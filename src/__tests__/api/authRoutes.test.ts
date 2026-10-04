/**
 * @jest-environment node
 *
 * Sign-up / sign-in server routes, run through the real handlers against an in-memory database:
 *   - bootstrap never auto-creates or auto-joins an org (only invites + /create-org put users in an org)
 *   - 2FA is enforced at sign-in: no active session until the code step; codes and backup codes
 *   - creating an org records the creator's name and active session
 */
import { NextRequest } from "next/server";
import { fakeSupabase } from "../helpers/fakeSupabase";
import { generateTOTP, generateTOTPSecret } from "@/lib/totp";

let db: ReturnType<typeof fakeSupabase>;
const users: Record<string, Record<string, unknown>> = {};

jest.mock("@/lib/supabase", () => ({
  createServiceClient: () => ({
    ...db.client,
    auth: { getUser: async (token: string) => {
      const sid = JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString()).sub as string;
      return users[sid] ? { data: { user: users[sid] }, error: null } : { data: { user: null }, error: { message: "bad" } };
    } },
  }),
}));
jest.mock("@/lib/audit", () => ({ writeAuditLog: jest.fn(async () => {}) }));
const rateLimitOk = { current: true };
jest.mock("@/lib/rateLimit", () => ({ checkRateLimit: jest.fn(async () => ({ success: rateLimitOk.current, reset: Date.now() + 60_000, headers: {} })) }));

import { POST as bootstrap } from "@/app/api/auth/bootstrap/route";
import { GET as mfaStatus, POST as mfaVerify } from "@/app/api/auth/2fa/login/route";
import { POST as createOrg } from "@/app/api/orgs/create/route";
import { verifyApiKey } from "@/app/api/_middleware";

const token = (userId: string, sessionId: string) =>
  `h.${Buffer.from(JSON.stringify({ sub: userId, session_id: sessionId })).toString("base64url")}.s`;
const rowsOf = (table: string) => (db.client.from(table) as unknown as { rows: Record<string, unknown>[] }).rows;
const req = (url: string, tok: string, body?: unknown) => new NextRequest(new URL(url, "https://app.example"), {
  method: body === undefined ? "GET" : "POST",
  headers: { Authorization: `Bearer ${tok}`, "Content-Type": "application/json" },
  ...(body === undefined ? {} : { body: JSON.stringify(body) }),
});

beforeEach(() => {
  for (const k of Object.keys(users)) delete users[k];
  rateLimitOk.current = true;
  process.env.NEXT_PUBLIC_SKIP_AUTH = "false";
});

describe("bootstrap: no automatic org", () => {
  it("an uninvited email sign-up gets no org (no shared 'default' org) and nothing is written", async () => {
    db = fakeSupabase({ organizations: [{ id: "o-default", slug: "default" }], org_members: [{ id: "m0", org_id: "o-default", user_id: "first", email: "first@x.dev", role: "admin" }] });
    users.u2 = { id: "u2", email: "stranger@y.dev", email_confirmed_at: "2026-10-01", user_metadata: {} };
    const res = await (await bootstrap(req("/api/auth/bootstrap", token("u2", "s1"), {}))).json();
    expect(res).toEqual({ has_org: false, is_new_user: true, mfa_required: false });
    // Nothing created, nothing joined (the only write is the invite lookup, which matched no row).
    expect(db.writes.filter(w => w.op !== "update")).toEqual([]);
    expect(rowsOf("organizations")).toHaveLength(1);
    expect(rowsOf("org_members")).toEqual([{ id: "m0", org_id: "o-default", user_id: "first", email: "first@x.dev", role: "admin" }]);
  });

  it("a GitHub login equal to an existing org's slug does not join that org", async () => {
    db = fakeSupabase({ organizations: [{ id: "o-acme", slug: "acme" }], org_members: [] });
    users.g = { id: "g", email: "acme@users.noreply", email_confirmed_at: "2026-10-01", user_metadata: { user_name: "acme", preferred_username: "acme" } };
    const res = await (await bootstrap(req("/api/auth/bootstrap", token("g", "s1"), {}))).json();
    expect(res.has_org).toBe(false);
    expect(rowsOf("org_members")).toEqual([]);
    expect(db.writes.filter(w => w.op === "insert")).toEqual([]);
  });

  it("claims a pending invite by confirmed email — but not with an unconfirmed one", async () => {
    db = fakeSupabase({ org_members: [{ id: "inv", org_id: "o1", user_id: null, email: "new@acme.dev", role: "developer" }] });
    users.u = { id: "u", email: "new@acme.dev", email_confirmed_at: null, user_metadata: {} };
    expect((await (await bootstrap(req("/api/auth/bootstrap", token("u", "s1"), {}))).json()).has_org).toBe(false);
    users.u.email_confirmed_at = "2026-10-01";
    expect((await (await bootstrap(req("/api/auth/bootstrap", token("u", "s1"), {}))).json()).has_org).toBe(true);
    const tables = (db.client.from("org_members") as unknown as { rows: Record<string, unknown>[] }).rows;
    expect(tables[0]).toMatchObject({ user_id: "u", active_session_id: "s1" });
  });

  it("an existing member's sign-in becomes the active session", async () => {
    db = fakeSupabase({ org_members: [{ id: "m", org_id: "o1", user_id: "u", email: "a@acme.dev", active_session_id: "old" }] });
    users.u = { id: "u", email: "a@acme.dev", email_confirmed_at: "2026-10-01" };
    expect(await (await bootstrap(req("/api/auth/bootstrap", token("u", "new"), {}))).json()).toEqual({ has_org: true, is_new_user: false, mfa_required: false });
    expect(db.writes).toContainEqual(expect.objectContaining({ table: "org_members", op: "update", payload: expect.objectContaining({ active_session_id: "new" }) }));
  });
});

describe("2FA at sign-in", () => {
  const secret = generateTOTPSecret();
  const seed = (active: string | null = "old") => {
    db = fakeSupabase({
      org_members: [{ id: "m", org_id: "o1", user_id: "u", email: "a@acme.dev", role: "admin", active_session_id: active }],
      user_2fa: [{ user_id: "u", enabled: true, secret, backup_codes: ["AAAA1111", "BBBB2222"] }],
    });
    users.u = { id: "u", email: "a@acme.dev", email_confirmed_at: "2026-10-01" };
  };
  const member = () => (db.client.from("org_members") as unknown as { rows: Record<string, unknown>[] }).rows[0];

  it("a password sign-in alone does not activate the session, so the API refuses it", async () => {
    seed();
    expect(await (await bootstrap(req("/api/auth/bootstrap", token("u", "pw"), {}))).json()).toMatchObject({ mfa_required: true });
    expect(member().active_session_id).toBe("old");
    expect((await verifyApiKey(req("/api/x", token("u", "pw")))).error).toBe("mfa_required");
    expect(await (await mfaStatus(req("/api/auth/2fa/login", token("u", "pw")))).json()).toEqual({ required: true, verified: false });
  });

  it("a wrong code is rejected; the right code activates the session and the API lets it in", async () => {
    seed();
    const bad = await mfaVerify(req("/api/auth/2fa/login", token("u", "pw"), { code: "000000" === generateTOTP(secret) ? "111111" : "000000" }));
    expect(bad.status).toBe(400);
    expect(member().active_session_id).toBe("old");

    const ok = await mfaVerify(req("/api/auth/2fa/login", token("u", "pw"), { code: generateTOTP(secret) }));
    expect(ok.status).toBe(200);
    expect(member().active_session_id).toBe("pw");
    expect(await verifyApiKey(req("/api/x", token("u", "pw")))).toMatchObject({ org_id: "o1", user_id: "u" });
    expect(await (await mfaStatus(req("/api/auth/2fa/login", token("u", "pw")))).json()).toEqual({ required: true, verified: true });
  });

  it("a backup code works once and is then used up", async () => {
    seed();
    expect((await mfaVerify(req("/api/auth/2fa/login", token("u", "s2"), { code: "aaaa1111" }))).status).toBe(200);
    const codes = (db.client.from("user_2fa") as unknown as { rows: Record<string, unknown>[] }).rows[0].backup_codes;
    expect(codes).toEqual(["BBBB2222"]);
    expect((await mfaVerify(req("/api/auth/2fa/login", token("u", "s3"), { code: "AAAA1111" }))).status).toBe(400);
  });

  it("is rate limited", async () => {
    seed(); rateLimitOk.current = false;
    expect((await mfaVerify(req("/api/auth/2fa/login", token("u", "pw"), { code: generateTOTP(secret) }))).status).toBe(429);
    expect(member().active_session_id).toBe("old");
  });

  it("users without 2FA: no code step", async () => {
    db = fakeSupabase({ org_members: [{ id: "m", org_id: "o1", user_id: "u", email: "a@acme.dev" }], user_2fa: [] });
    users.u = { id: "u", email: "a@acme.dev" };
    expect(await (await mfaStatus(req("/api/auth/2fa/login", token("u", "pw")))).json()).toEqual({ required: false, verified: false });
    expect((await mfaVerify(req("/api/auth/2fa/login", token("u", "pw"), { code: "123456" }))).status).toBe(400);
  });
});

it("the API links an invite whose member row has no user yet (confirmed email only)", async () => {
  db = fakeSupabase({ org_members: [{ id: "inv", org_id: "o1", user_id: null, email: "inv@acme.dev", role: "developer", active_session_id: null }], user_2fa: [] });
  users.u = { id: "u", email: "inv@acme.dev", email_confirmed_at: "2026-10-01" };
  expect(await verifyApiKey(req("/api/x", token("u", "s1")))).toMatchObject({ org_id: "o1", user_id: "u", role: "developer" });
  expect(rowsOf("org_members")[0].user_id).toBe("u");
});

it("creating an org records the creator's name and makes this session the active one", async () => {
  db = fakeSupabase({ organizations: [], org_members: [] });
  users.u = { id: "u", email: "founder@new.dev", user_metadata: { full_name: "Fay Founder" } };
  // the fake insert returns no generated id; give the org row one
  const res = await createOrg(req("/api/orgs/create", token("u", "s-create"), { name: "New Co", slug: "new-co" }));
  const body = await res.json();
  if (res.status !== 201) throw new Error(JSON.stringify(body));
  const m = (db.client.from("org_members") as unknown as { rows: Record<string, unknown>[] }).rows[0];
  expect(m).toMatchObject({ user_id: "u", role: "admin", name: "Fay Founder", active_session_id: "s-create" });
});
