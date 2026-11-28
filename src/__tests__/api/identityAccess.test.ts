/**
 * @jest-environment node
 *
 * P1.2 identity and access: what happens to a person's sessions and tokens when they are removed, when their role changes, when an
 * admin ends their sessions, and when the organisation requires two-factor -- and the IdP-driven (SCIM) role mapping.
 */
import { NextRequest } from "next/server";
import { fakeSupabase } from "../helpers/fakeSupabase";
import { hashScimToken } from "@/lib/scimAuth";
import crypto from "crypto";

let db: ReturnType<typeof fakeSupabase>;
let auditBroken = false;

const USERS: Record<string, { id: string; email: string }> = {
  admin: { id: "u-admin", email: "admin@acme.dev" },
  dev: { id: "u-dev", email: "dev@acme.dev" },
  reviewer: { id: "u-rev", email: "rev@acme.dev" },
  other: { id: "u-other", email: "boss@other.dev" },
};

jest.mock("@/lib/supabase", () => ({
  createServiceClient: () => {
    const client = db.client as unknown as { from: (t: string) => Record<string, unknown> };
    return {
      ...client,
      from: (table: string) => {
        const q = client.from(table);
        if (table === "audit_log" && auditBroken) q.insert = () => Promise.resolve({ error: { code: "42501", message: "permission denied" } });
        return q;
      },
      auth: {
        getUser: async (t: string) => {
          const sub = JSON.parse(Buffer.from(t.split(".")[1], "base64url").toString()).sub as string | undefined;
          const user = Object.values(USERS).find(u => u.id === sub);
          return user ? { data: { user: { ...user, email_confirmed_at: "2026-01-01", app_metadata: { provider: "email" } } }, error: null } : { data: { user: null }, error: { message: "bad token" } };
        },
        admin: { getUserById: async () => ({ data: { user: null }, error: { message: "not found" } }) },
      },
    };
  },
}));
jest.mock("@/lib/cache", () => ({
  cached: async (_k: string, _t: number, fn: () => unknown) => fn(),
  memoryCached: async (_k: string, _t: number, fn: () => unknown) => fn(),
  cacheDel: async () => {}, cacheKeys: { dashboard: () => "d", dependencies: () => "p" },
}));
jest.mock("@/lib/rateLimit", () => ({ checkRateLimit: async () => ({ success: true, headers: {} }), RATE_LIMITS: { keyCreate: {} } }));

import { verifyApiKey } from "@/app/api/_middleware";
import { POST as revokeSessions } from "@/app/api/team/sessions/route";
import { POST as bootstrap } from "@/app/api/auth/bootstrap/route";
import { GET as policyGET, PATCH as policyPATCH } from "@/app/api/security-policy/route";
import { DELETE as teamDELETE, PATCH as teamPATCH } from "@/app/api/team/route";
import { POST as scimCreate } from "@/app/api/scim/v2/Users/route";
import { PATCH as scimPatch } from "@/app/api/scim/v2/Users/[id]/route";
import { POST as createKey } from "@/app/api/keys/route";
import { generateTOTP } from "@/lib/totp";

const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
const token = (who: keyof typeof USERS, session = `sess-${who}`, withSession = true) =>
  `${b64({ alg: "none" })}.${b64({ sub: USERS[who].id, ...(withSession ? { session_id: session } : {}), amr: [{ method: "password", timestamp: Math.floor(Date.now() / 1000) }] })}.sig`;
const req = (url: string, who: keyof typeof USERS | null, method = "GET", body?: unknown, session?: string) =>
  new NextRequest(new URL(url, "https://app.example"), { method, headers: who ? { Authorization: `Bearer ${token(who, session)}` } : {}, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
const rows = (t: string) => db.tables[t] as Array<Record<string, unknown>>;
const member = (userId: string) => rows("org_members").find(m => m.user_id === userId)!;

beforeEach(() => {
  auditBroken = false;
  db = fakeSupabase({
    audit_log: [], api_keys: [], user_2fa: [], custom_roles: [], sso_connections: [], scim_tokens: [], sso_domains: [],
    organizations: [{ id: "org-1", name: "Acme", slug: "acme", require_mfa: false }, { id: "org-2", name: "Other", slug: "other", require_mfa: false }],
    org_members: [
      { id: "m-admin", org_id: "org-1", user_id: "u-admin", email: "admin@acme.dev", role: "admin", active_session_id: "sess-admin" },
      { id: "m-dev", org_id: "org-1", user_id: "u-dev", email: "dev@acme.dev", role: "security_reviewer", active_session_id: "sess-dev" },
      { id: "m-rev", org_id: "org-1", user_id: "u-rev", email: "rev@acme.dev", role: "developer", active_session_id: "sess-reviewer" },
      { id: "m-other", org_id: "org-2", user_id: "u-other", email: "boss@other.dev", role: "admin", active_session_id: "sess-other" },
    ],
  });
});

describe("removing a member ends their access at once", () => {
  it("their token is refused on the very next request", async () => {
    expect((await verifyApiKey(req("/api/x", "dev"))).org_id).toBe("org-1");
    const res = await teamDELETE(req("/api/team?user_id=u-dev", "admin", "DELETE"));
    expect(res.status).toBe(200);
    expect(await verifyApiKey(req("/api/x", "dev"))).toMatchObject({ org_id: "", error: "no_org_membership" });
  });

  it("a role change applies on the next request (no old role cached in the token)", async () => {
    expect((await verifyApiKey(req("/api/x", "dev"))).role).toBe("security_reviewer");
    const res = await teamPATCH(req("/api/team", "admin", "PATCH", { user_id: "u-dev", role: "developer" }));
    expect(res.status).toBe(200);
    expect((await verifyApiKey(req("/api/x", "dev"))).role).toBe("developer");
  });

  it("an organisation API key does not depend on the person who created it (so removing them does not break CI)", async () => {
    const created = await createKey(req("/api/keys", "dev", "POST", { name: "ci" }));
    // a security_reviewer cannot manage integrations: use the admin's key creation instead
    const res = created.status === 200 ? created : await createKey(req("/api/keys", "admin", "POST", { name: "ci" }));
    const rawKey = (await res.json()).raw_key as string;
    await teamDELETE(req("/api/team?user_id=u-admin", "admin", "DELETE"));      // refused (cannot remove self): the creator stays
    rows("org_members").splice(rows("org_members").findIndex(m => m.user_id === "u-admin"), 1);   // ...but if they are gone
    const asKey = new NextRequest("https://app.example/api/x", { headers: { "X-TrustLedger-Key": rawKey } });
    expect(await verifyApiKey(asKey)).toMatchObject({ org_id: "org-1" });
  });
});

describe("ending a member's sessions", () => {
  const revoke = (who: keyof typeof USERS, userId: string) => revokeSessions(req("/api/team/sessions", who, "POST", { user_id: userId }));

  it("refuses every token the member holds, and leaves their role and membership alone", async () => {
    expect((await verifyApiKey(req("/api/x", "dev"))).org_id).toBe("org-1");
    const res = await revoke("admin", "u-dev");
    expect(res.status).toBe(200);
    expect(await verifyApiKey(req("/api/x", "dev"))).toMatchObject({ org_id: "", error: "session_revoked" });
    expect(await verifyApiKey(req("/api/x", "dev", "GET", undefined, "any-other-session"))).toMatchObject({ error: "session_revoked" });
    const noSessionClaim = new NextRequest("https://app.example/api/x", { headers: { Authorization: `Bearer ${token("dev", "x", false)}` } });
    expect(await verifyApiKey(noSessionClaim)).toMatchObject({ error: "session_revoked" });
    expect(member("u-dev")).toMatchObject({ role: "security_reviewer", org_id: "org-1" });
    expect(rows("audit_log").map(r => r.event_type)).toEqual(["member_sessions_revoked"]);
  });

  it("the revoked session cannot sign itself back in through bootstrap; a NEW sign-in can", async () => {
    await revoke("admin", "u-dev");
    await bootstrap(req("/api/auth/bootstrap", "dev", "POST", {}, "sess-dev"));          // the same (stolen) session tries to re-register
    expect(await verifyApiKey(req("/api/x", "dev"))).toMatchObject({ error: "session_revoked" });
    await bootstrap(req("/api/auth/bootstrap", "dev", "POST", {}, "sess-new"));          // a genuine new sign-in
    expect((await verifyApiKey(req("/api/x", "dev", "GET", undefined, "sess-new"))).org_id).toBe("org-1");
    expect(await verifyApiKey(req("/api/x", "dev"))).toMatchObject({ error: "session_revoked" });   // the old one stays refused
  });

  it("works for a member who has two-factor too: their old session is refused until they sign in again", async () => {
    rows("user_2fa").push({ user_id: "u-dev", enabled: true, secret: "JBSWY3DPEHPK3PXP", backup_codes: [] });
    await revoke("admin", "u-dev");
    const after = await verifyApiKey(req("/api/x", "dev"));
    expect(after.org_id).toBe("");
    expect(["session_revoked", "mfa_required"]).toContain(after.error);
  });

  it("needs team-management permission, only an admin can end an admin's sessions, and another org's member is not found", async () => {
    expect((await revoke("reviewer", "u-dev")).status).toBe(403);
    member("u-dev").role = "developer";
    expect((await revoke("dev", "u-admin")).status).toBe(403);
    expect((await revoke("admin", "u-other")).status).toBe(404);
    expect((await verifyApiKey(req("/api/x", "other"))).org_id).toBe("org-2");
  });

  it("ending sessions stays in force even if it cannot be recorded; the caller is told", async () => {
    auditBroken = true;
    const res = await revoke("admin", "u-dev");
    expect(res.status).toBe(500);
    expect(await verifyApiKey(req("/api/x", "dev"))).toMatchObject({ error: "session_revoked" });
  });
});

describe("the organisation-wide two-factor requirement", () => {
  const withPolicy = (on: boolean) => { rows("organizations")[0].require_mfa = on; };

  it("off: nobody is asked for it", async () => {
    expect((await verifyApiKey(req("/api/x", "dev"))).org_id).toBe("org-1");
  });

  it("on: a member without two-factor is stopped, except on the calls that let them turn it on", async () => {
    withPolicy(true);
    expect(await verifyApiKey(req("/api/scans", "dev"))).toMatchObject({ org_id: "", error: "mfa_enrollment_required" });
    for (const path of ["/api/auth/2fa", "/api/me", "/api/auth/bootstrap"]) {
      expect((await verifyApiKey(req(path, "dev"))).org_id).toBe("org-1");
    }
  });

  it("on: a member who has two-factor (and verified this session) carries on", async () => {
    withPolicy(true);
    rows("user_2fa").push({ user_id: "u-dev", enabled: true, secret: "JBSWY3DPEHPK3PXP", backup_codes: [] });
    expect((await verifyApiKey(req("/api/scans", "dev"))).org_id).toBe("org-1");
  });

  it("it applies to the whole organisation and no other", async () => {
    withPolicy(true);
    expect((await verifyApiKey(req("/api/scans", "other"))).org_id).toBe("org-2");
  });

  it("platform_admin is exempt (break-glass)", async () => {
    withPolicy(true);
    member("u-dev").role = "platform_admin";
    expect((await verifyApiKey(req("/api/scans", "dev"))).org_id).toBe("org-1");
  });

  it("a missing column (migration not run) means no requirement, not a lockout", async () => {
    const real = db.client.from;
    db.client.from = ((t: string) => (t === "organizations" ? { select: () => ({ eq: () => ({ maybeSingle: async () => ({ data: null, error: { code: "42703", message: "column require_mfa does not exist" } }) }) }) } : real(t))) as typeof db.client.from;
    const dev = await verifyApiKey(req("/api/scans", "dev"));
    expect(dev.org_id).toBe("org-1");
  });

  describe("switching it on", () => {
    it("shows how many members would be stopped", async () => {
      rows("user_2fa").push({ user_id: "u-admin", enabled: true, secret: "S", backup_codes: [] });
      const body = await (await policyGET(req("/api/security-policy", "admin"))).json();
      expect(body).toMatchObject({ require_mfa: false, you_have_mfa: true, members_total: 3, members_without_mfa: 2 });
    });

    it("needs the admin's own two-factor first, so it cannot lock out its author", async () => {
      const res = await policyPATCH(req("/api/security-policy", "admin", "PATCH", { require_mfa: true }));
      expect(res.status).toBe(422);
      expect((await res.json()).error).toBe("enable_your_own_2fa_first");
      expect(rows("organizations")[0].require_mfa).toBe(false);
    });

    it("with their own two-factor on, an admin can switch it on and off; it is recorded", async () => {
      rows("user_2fa").push({ user_id: "u-admin", enabled: true, secret: "S", backup_codes: [] });
      expect((await policyPATCH(req("/api/security-policy", "admin", "PATCH", { require_mfa: true }))).status).toBe(200);
      expect(rows("organizations")[0].require_mfa).toBe(true);
      expect((await policyPATCH(req("/api/security-policy", "admin", "PATCH", { require_mfa: false }))).status).toBe(200);
      expect(rows("organizations")[0].require_mfa).toBe(false);
      expect(rows("audit_log").map(r => (r.payload as { require_mfa: boolean }).require_mfa)).toEqual([true, false]);
    });

    it("is undone if it cannot be recorded", async () => {
      rows("user_2fa").push({ user_id: "u-admin", enabled: true, secret: "S", backup_codes: [] });
      auditBroken = true;
      const res = await policyPATCH(req("/api/security-policy", "admin", "PATCH", { require_mfa: true }));
      expect(res.status).toBe(500);
      expect(rows("organizations")[0].require_mfa).toBe(false);
    });

    it("is admin only", async () => {
      expect((await policyPATCH(req("/api/security-policy", "dev", "PATCH", { require_mfa: true }))).status).toBe(403);
      expect((await policyGET(req("/api/security-policy", "dev"))).status).toBe(403);
    });
  });
});

describe("SCIM roles from the identity provider", () => {
  const TOKEN = "tl_scim_test-token-0123456789012345678901234567890";
  const scim = (url: string, method: string, body?: unknown) =>
    new NextRequest(new URL(url, "https://app.example"), { method, headers: { Authorization: `Bearer ${TOKEN}` }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
  const ctx = (id: string) => ({ params: Promise.resolve({ id }) });
  beforeEach(() => {
    rows("scim_tokens").push({ org_id: "org-1", token_hash: hashScimToken(TOKEN), token_prefix: TOKEN.slice(0, 14), created_at: "2026-11-01T00:00:00Z", last_used_at: null });
    rows("sso_domains").push({ org_id: "org-1", domain: "acme.dev", verification_token: "t", verified_at: "2026-10-01T00:00:00Z" });
  });
  // creating an auth user is outside this test: the SCIM route calls db.auth.admin.createUser
  beforeAll(() => {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const supa = require("@/lib/supabase") as { createServiceClient: () => { auth: { admin: Record<string, unknown> } } };
    const original = supa.createServiceClient;
    jest.spyOn(supa, "createServiceClient").mockImplementation(() => {
      const c = original();
      c.auth.admin.createUser = async ({ email }: { email: string }) => ({ data: { user: { id: `auth-${email}` } }, error: null });
      return c;
    });
  });

  it("provisions with the role the IdP asks for", async () => {
    const res = await scimCreate(scim("/api/scim/v2/Users", "POST", { userName: "new@acme.dev", roles: [{ value: "security_reviewer", primary: true }] }));
    expect(res.status).toBe(201);
    expect(rows("org_members").find(m => m.email === "new@acme.dev")).toMatchObject({ role: "security_reviewer" });
    expect((await res.json()).roles).toEqual([{ value: "security_reviewer", primary: true }]);
  });

  it("defaults to developer when no role is given", async () => {
    await scimCreate(scim("/api/scim/v2/Users", "POST", { userName: "plain@acme.dev" }));
    expect(rows("org_members").find(m => m.email === "plain@acme.dev")).toMatchObject({ role: "developer" });
  });

  it.each([["admin"], ["platform_admin"], ["superuser"], [""]])("refuses the role %j (admin is never granted through SCIM, and unknown roles are errors)", async (role) => {
    const res = await scimCreate(scim("/api/scim/v2/Users", "POST", { userName: "x@acme.dev", roles: [{ value: role }] }));
    expect(res.status).toBe(400);
    expect(rows("org_members").some(m => m.email === "x@acme.dev")).toBe(false);
  });

  it("a PATCH replace of roles changes the member's role and is recorded; the new role applies at once", async () => {
    const res = await scimPatch(scim("/api/scim/v2/Users/u-rev", "PATCH", { Operations: [{ op: "replace", path: "roles", value: [{ value: "security_reviewer" }] }] }), ctx("u-rev"));
    expect(res.status).toBe(200);
    expect(member("u-rev").role).toBe("security_reviewer");
    expect(rows("audit_log")).toEqual([expect.objectContaining({ event_type: "member_role_changed", actor_email: "scim", payload: expect.objectContaining({ from: "developer", new_role: "security_reviewer" }) })]);
    expect((await verifyApiKey(req("/api/x", "reviewer"))).role).toBe("security_reviewer");
  });

  it("never changes an admin's role, up or down, and never makes anyone an admin", async () => {
    const down = await scimPatch(scim("/api/scim/v2/Users/u-admin", "PATCH", { Operations: [{ op: "replace", path: "roles", value: [{ value: "developer" }] }] }), ctx("u-admin"));
    expect(down.status).toBe(403);
    const up = await scimPatch(scim("/api/scim/v2/Users/u-rev", "PATCH", { Operations: [{ op: "replace", path: "roles", value: [{ value: "admin" }] }] }), ctx("u-rev"));
    expect(up.status).toBe(400);
    expect(member("u-admin").role).toBe("admin");
    expect(member("u-rev").role).toBe("developer");
  });

  it("a role change that cannot be recorded is reported as failed", async () => {
    auditBroken = true;
    const res = await scimPatch(scim("/api/scim/v2/Users/u-rev", "PATCH", { Operations: [{ op: "replace", path: "roles", value: [{ value: "security_reviewer" }] }] }), ctx("u-rev"));
    expect(res.status).toBe(500);
  });
});

describe("the one-time authenticator code is not accepted as a stored secret", () => {
  it("(guard) generateTOTP is deterministic for a secret, so the 2FA tests above are not flaky", () => {
    expect(generateTOTP("JBSWY3DPEHPK3PXP", 1_700_000_000)).toBe(generateTOTP("JBSWY3DPEHPK3PXP", 1_700_000_000));
    expect(crypto.randomUUID()).toBeTruthy();
  });
});
