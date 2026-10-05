/**
 * @jest-environment node
 *
 * Server-side permission enforcement: built-in roles and custom roles decide what each API action allows,
 * attestation follows the file's risk, and nobody can hand out more access than they hold.
 */
import { NextRequest } from "next/server";
import { fakeSupabase } from "../helpers/fakeSupabase";

let db: ReturnType<typeof fakeSupabase>;
type Auth = { org_id: string; user_id?: string; actor_email?: string; role?: string };
let auth: Auth;
jest.mock("@/lib/supabase", () => ({ createServiceClient: () => db.client }));
jest.mock("@/app/api/_middleware", () => ({
  ...jest.requireActual("@/app/api/_middleware"),
  verifyApiKey: async () => ({ ...auth }),   // a fresh object per request, like the real one
}));
jest.mock("@/lib/audit", () => ({ writeAuditLog: jest.fn(async () => {}) }));
jest.mock("@/lib/cache", () => ({ cacheDel: async () => {}, cacheKeys: { dashboard: () => "d" }, invalidateViolationsCache: async () => {} }));
jest.mock("@/lib/rateLimit", () => ({ checkRateLimit: async () => ({ success: true, headers: {} }), RATE_LIMITS: {} }));
jest.mock("@/lib/scanner", () => ({ buildAttestationHash: () => "hash" }));
jest.mock("@/lib/github", () => ({ getInstallationToken: jest.fn(), updateCheckRun: jest.fn() }));
jest.mock("@/lib/repoViolations", () => ({ hasOpenRepoViolations: async () => true }));
jest.mock("@/lib/autoIncidents", () => ({ syncAutoIncidents: async () => {} }));
jest.mock("@/lib/outboundWebhook", () => ({ fireOrgWebhooks: async () => {}, deliverWebhook: async () => ({ success: true }) }));

import { POST as attestPOST } from "@/app/api/attest/route";
import { POST as bulkPOST } from "@/app/api/scans/bulk/route";
import { DELETE as retentionDELETE, POST as retentionPOST } from "@/app/api/retention/route";
import { DELETE as keysDELETE } from "@/app/api/keys/route";
import { POST as webhooksPOST } from "@/app/api/webhooks/route";
import { PATCH as violationsPATCH } from "@/app/api/violations/route";
import { GET as rolesGET, POST as rolesPOST, PATCH as rolesPATCH, DELETE as rolesDELETE } from "@/app/api/custom-roles/route";
import { PATCH as teamPATCH, DELETE as teamDELETE } from "@/app/api/team/route";
import { GET as meGET } from "@/app/api/me/route";
import { POST as alertsPOST } from "@/app/api/alerts/route";
import { POST as syncCheckRunPOST } from "@/app/api/sync-check-run/route";
import { POST as orgsPOST } from "@/app/api/orgs/route";
import { POST as riskSyncPOST } from "@/app/api/risk-register/sync/route";
import { PATCH as prefsPATCH } from "@/app/api/preferences/route";
import { BUILTIN_PERMISSIONS, permissionsFromRow } from "@/lib/permissions";

const ADMIN:    Auth = { org_id: "org-1", user_id: "u-admin", actor_email: "admin@a.test", role: "admin" };
const REVIEWER: Auth = { org_id: "org-1", user_id: "u-rev", actor_email: "rev@a.test", role: "security_reviewer" };
const DEV:      Auth = { org_id: "org-1", user_id: "u-dev", actor_email: "dev@a.test", role: "developer" };
const JUNIOR:   Auth = { org_id: "org-1", user_id: "u-junior", actor_email: "junior@a.test", role: "developer" };
const LEAD:     Auth = { org_id: "org-1", user_id: "u-lead", actor_email: "lead@a.test", role: "developer" };
const API_KEY:  Auth = { org_id: "org-1" };

const rows = (t: string) => (db.client.from(t) as unknown as { rows: Record<string, unknown>[] }).rows;
const req = (url: string, method: string, body?: unknown) =>
  new NextRequest(new URL(url, "https://app.example"), { method, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
const as = (a: Auth) => { auth = a; };

const VIOLATION  = "33333333-3333-4333-8333-333333333333";
const SCAN       = "44444444-4444-4444-8444-444444444444";
const CR_JUNIOR  = "55555555-5555-4555-8555-555555555555";
const CR_LEAD    = "66666666-6666-4666-8666-666666666666";
const CR_FOREIGN = "77777777-7777-4777-8777-777777777777";
const CR_BROAD   = "88888888-8888-4888-8888-888888888888";

beforeEach(() => {
  jest.clearAllMocks();
  db = fakeSupabase({
    org_members: [
      { id: "m-admin", org_id: "org-1", user_id: "u-admin", email: "admin@a.test", role: "admin", custom_role_id: null },
      { id: "m-admin2", org_id: "org-1", user_id: "u-admin2", email: "admin2@a.test", role: "admin", custom_role_id: null },
      { id: "m-rev", org_id: "org-1", user_id: "u-rev", email: "rev@a.test", role: "security_reviewer", custom_role_id: null },
      { id: "m-dev", org_id: "org-1", user_id: "u-dev", email: "dev@a.test", role: "developer", custom_role_id: null },
      { id: "m-junior", org_id: "org-1", user_id: "u-junior", email: "junior@a.test", role: "developer", custom_role_id: CR_JUNIOR },
      { id: "m-lead", org_id: "org-1", user_id: "u-lead", email: "lead@a.test", role: "developer", custom_role_id: CR_LEAD },
    ],
    custom_roles: [
      { id: CR_JUNIOR, org_id: "org-1", name: "Junior reviewer", can_attest_high: true, can_attest_medium: true },
      // a team lead: manages the team and attests HIGH, but isn't an admin
      { id: CR_LEAD, org_id: "org-1", name: "Team lead", can_manage_team: true, can_attest_high: true, can_attest_medium: true },
      { id: CR_FOREIGN, org_id: "org-2", name: "Foreign", can_manage_team: true },
      { id: CR_BROAD, org_id: "org-1", name: "Senior reviewer", can_attest_critical: true, can_attest_high: true },
    ],
    scans: [{ id: SCAN, org_id: "org-1", repo_full_name: "acme/api", overall_risk: "CRITICAL", check_run_id: null, installation_id: null }],
    scan_files: [
      { scan_id: SCAN, org_id: "org-1", file_path: "high.ts", risk_score: "HIGH" },
      { scan_id: SCAN, org_id: "org-1", file_path: "crit.ts", risk_score: "CRITICAL" },
    ],
    attestations: [],
    violations: [{ id: VIOLATION, org_id: "org-1", scan_id: SCAN, file_path: "high.ts", status: "open", risk_score: "HIGH", notes: [] }],
    api_keys: [{ id: "k1", org_id: "org-1", revoked: false }],
    webhook_configs: [],
  });
});

const attest = (file_path: string, reviewer_email = "someone@a.test") =>
  attestPOST(req("/api/attest", "POST", { scan_id: SCAN, file_path, reviewer_email }));

describe("attestation follows the file's risk and the caller's permissions", () => {
  it("a developer can't attest a HIGH file; nothing is recorded", async () => {
    as(DEV);
    const res = await attest("high.ts");
    expect(res.status).toBe(403);
    expect(await res.json()).toMatchObject({ error: "insufficient_permissions", risk_score: "HIGH" });
    expect(rows("attestations")).toHaveLength(0);
  });

  it("a security reviewer can, and the attestation is recorded as the signed-in reviewer, not the body's email", async () => {
    as(REVIEWER);
    expect((await attest("crit.ts", "ceo@a.test")).status).toBe(200);
    expect(rows("attestations")).toEqual([expect.objectContaining({ file_path: "crit.ts", reviewer_email: "rev@a.test", reviewer_id: "u-rev" })]);
  });

  it("a custom role that may attest HIGH but not CRITICAL gets exactly that", async () => {
    as(JUNIOR);
    expect((await attest("high.ts")).status).toBe(200);
    expect((await attest("crit.ts")).status).toBe(403);
    expect(rows("attestations").map(a => a.file_path)).toEqual(["high.ts"]);
  });

  it("an API key can't attest (attestation is a person's sign-off)", async () => {
    as(API_KEY);
    expect((await attest("high.ts")).status).toBe(403);
  });

  it("bulk attest signs off only what the role allows and reports the rest", async () => {
    as(JUNIOR);
    const res = await bulkPOST(req("/api/scans/bulk?op=attest", "POST", { scan_id: SCAN, reviewer_email: "x@a.test" }));
    expect(await res.json()).toMatchObject({ ok: true, attested: 1, not_permitted: 1 });
    expect(rows("attestations").map(a => [a.file_path, a.reviewer_email])).toEqual([["high.ts", "junior@a.test"]]);
  });

  it("bulk attest and bulk resolve are refused outright without any attest / triage permission", async () => {
    as(DEV);
    expect((await bulkPOST(req("/api/scans/bulk?op=attest", "POST", { scan_id: SCAN, reviewer_email: "x@a.test" }))).status).toBe(403);
    expect((await bulkPOST(req("/api/scans/bulk?op=resolve", "POST", { scan_id: SCAN }))).status).toBe(403);
    expect(rows("violations")[0].status).toBe("open");
  });
});

describe("management actions that used to be open to every member", () => {
  it("developers can't resolve violations, delete data, revoke API keys or add webhooks", async () => {
    as(DEV);
    expect((await violationsPATCH(req("/api/violations", "PATCH", { id: VIOLATION, status: "resolved" }))).status).toBe(403);
    expect((await retentionDELETE(req("/api/retention?scope=scans&before=2020-01-01", "DELETE"))).status).toBe(403);
    expect((await keysDELETE(req("/api/keys", "DELETE", { id: "k1" }))).status).toBe(403);
    expect((await webhooksPOST(req("/api/webhooks", "POST", { url: "https://hooks.example/x", events: ["scan.completed"] }))).status).toBe(403);
    expect(rows("violations")[0].status).toBe("open");
    expect(rows("api_keys")[0].revoked).toBe(false);
    expect(rows("webhook_configs")).toHaveLength(0);
  });

  it("erasing the whole org needs the built-in admin role -- not a reviewer, not an API key", async () => {
    for (const who of [REVIEWER, API_KEY, LEAD]) {
      as(who);
      expect((await retentionPOST(req("/api/retention?action=delete_account", "POST"))).status).toBe(403);
    }
    expect(rows("scans")).toHaveLength(1);
  });

  it("reviewers resolve violations; admins revoke keys", async () => {
    as(REVIEWER);
    expect((await violationsPATCH(req("/api/violations", "PATCH", { id: VIOLATION, status: "resolved" }))).status).toBe(200);
    as(ADMIN);
    expect((await keysDELETE(req("/api/keys", "DELETE", { id: "k1" }))).status).toBe(200);
    expect(rows("api_keys")[0].revoked).toBe(true);
  });
});

describe("routes that were open to every member", () => {
  it("a developer can't page people, force a PR's check to neutral, create orgs or rewrite the risk register", async () => {
    as(DEV);
    expect((await alertsPOST(req("/api/alerts", "POST", { alert_type: "x", severity: "P1", title: "t", body_text: "b", deliver: true }))).status).toBe(403);
    expect((await syncCheckRunPOST(req("/api/sync-check-run", "POST", { scan_id: SCAN, force_neutral: true }))).status).toBe(403);
    expect((await orgsPOST(req("/api/orgs", "POST", { slug: "mine", name: "Mine", plan: "enterprise" }))).status).toBe(403);
    expect((await riskSyncPOST(req("/api/risk-register/sync", "POST", { risks: [] }))).status).toBe(403);
    expect(rows("organizations")).toHaveLength(0);
  });

  it("even an org admin can't create orgs -- that's the platform-admin (MSP) feature", async () => {
    as(ADMIN);
    expect((await orgsPOST(req("/api/orgs", "POST", { slug: "mine", name: "Mine" }))).status).toBe(403);
  });

  it("a plain check-run sync (no force) stays open to every member", async () => {
    as(DEV);
    expect((await syncCheckRunPOST(req("/api/sync-check-run", "POST", { scan_id: SCAN }))).status).not.toBe(403);
  });

  it("preferences are always the caller's own, whatever the body says", async () => {
    as(DEV);
    await prefsPATCH(req("/api/preferences", "PATCH", { user_id: "u-admin", org_id: "org-2", email_digest: false }));
    expect(rows("notification_preferences")).toEqual([expect.objectContaining({ user_id: "u-dev", org_id: "org-1", email_digest: false })]);
  });
});

describe("custom roles API", () => {
  it("admins create a role with exactly the ticked permissions", async () => {
    as(ADMIN);
    const res = await rolesPOST(req("/api/custom-roles", "POST", { name: "Auditor", can_view_audit_log: true, can_export_data: true }));
    expect(res.status).toBe(201);
    const role = rows("custom_roles").find(r => r.name === "Auditor")!;
    expect(permissionsFromRow(role)).toEqual(permissionsFromRow({ can_view_audit_log: true, can_export_data: true }));
    expect(role.org_id).toBe("org-1");
  });

  it("rejects unknown flags and blank names", async () => {
    as(ADMIN);
    expect((await rolesPOST(req("/api/custom-roles", "POST", { name: "X", can_do_anything: true }))).status).toBe(400);
    expect((await rolesPOST(req("/api/custom-roles", "POST", { name: "  " }))).status).toBe(400);
  });

  it("only team managers may see or change roles", async () => {
    as(DEV);
    expect((await rolesGET(req("/api/custom-roles", "GET"))).status).toBe(403);
    expect((await rolesPOST(req("/api/custom-roles", "POST", { name: "Mine", can_manage_team: true }))).status).toBe(403);
  });

  it("lists this org's roles and who holds them -- never another org's", async () => {
    as(ADMIN);
    const body = await (await rolesGET(req("/api/custom-roles", "GET"))).json();
    expect(body.roles.map((r: { name: string }) => r.name).sort()).toEqual(["Junior reviewer", "Senior reviewer", "Team lead"]);
    expect(body.assignments).toEqual({ "u-junior": CR_JUNIOR, "u-lead": CR_LEAD });
  });

  it("a non-admin team manager can't create or widen a role beyond their own permissions", async () => {
    as(LEAD);
    expect((await rolesPOST(req("/api/custom-roles", "POST", { name: "Big", can_attest_critical: true }))).status).toBe(403);
    expect((await rolesPATCH(req("/api/custom-roles", "PATCH", { id: CR_JUNIOR, can_manage_billing: true }))).status).toBe(403);
    expect((await rolesPOST(req("/api/custom-roles", "POST", { name: "Small", can_attest_high: true }))).status).toBe(201);
  });

  it("...nor edit or delete a role that is already broader than they are", async () => {
    as(LEAD);
    expect((await rolesPATCH(req("/api/custom-roles", "PATCH", { id: CR_BROAD, name: "Renamed" }))).status).toBe(403);
    // even when the edit would bring it within their reach: a role they couldn't create isn't theirs to reshape
    expect((await rolesPATCH(req("/api/custom-roles", "PATCH", { id: CR_BROAD, can_attest_critical: false }))).status).toBe(403);
    expect(rows("custom_roles").find(r => r.id === CR_BROAD)!.can_attest_critical).toBe(true);
    expect((await rolesDELETE(req(`/api/custom-roles?id=${CR_BROAD}`, "DELETE"))).status).toBe(403);
    expect(rows("custom_roles").find(r => r.id === CR_BROAD)!.name).toBe("Senior reviewer");
  });

  it("can't touch another org's role", async () => {
    as(ADMIN);
    expect((await rolesPATCH(req("/api/custom-roles", "PATCH", { id: CR_FOREIGN, name: "Mine now" }))).status).toBe(404);
    expect((await rolesDELETE(req(`/api/custom-roles?id=${CR_FOREIGN}`, "DELETE"))).status).toBe(404);
    expect(rows("custom_roles").find(r => r.id === CR_FOREIGN)!.name).toBe("Foreign");
  });

  it("deleting a role sends its members back to their built-in role", async () => {
    as(ADMIN);
    expect((await rolesDELETE(req(`/api/custom-roles?id=${CR_JUNIOR}`, "DELETE"))).status).toBe(200);
    expect(rows("custom_roles").some(r => r.id === CR_JUNIOR)).toBe(false);
    expect(rows("org_members").find(m => m.user_id === "u-junior")!.custom_role_id).toBeNull();
    as(JUNIOR);
    expect((await attest("high.ts")).status).toBe(403);   // plain developer again
  });
});

describe("assigning roles through /api/team", () => {
  it("an admin assigns and clears a custom role", async () => {
    as(ADMIN);
    expect((await teamPATCH(req("/api/team", "PATCH", { user_id: "u-dev", custom_role_id: CR_JUNIOR }))).status).toBe(200);
    expect(rows("org_members").find(m => m.user_id === "u-dev")!.custom_role_id).toBe(CR_JUNIOR);
    as(DEV);
    expect((await attest("high.ts")).status).toBe(200);
    as(ADMIN);
    expect((await teamPATCH(req("/api/team", "PATCH", { user_id: "u-dev", custom_role_id: null }))).status).toBe(200);
    expect(rows("org_members").find(m => m.user_id === "u-dev")!.custom_role_id).toBeNull();
  });

  it("refuses another org's custom role, and changing your own", async () => {
    as(ADMIN);
    expect((await teamPATCH(req("/api/team", "PATCH", { user_id: "u-dev", custom_role_id: CR_FOREIGN }))).status).toBe(404);
    expect((await teamPATCH(req("/api/team", "PATCH", { user_id: "u-admin", custom_role_id: CR_JUNIOR }))).status).toBe(400);
    expect(rows("org_members").find(m => m.user_id === "u-dev")!.custom_role_id).toBeNull();
  });

  it("a non-admin team manager can't make anyone admin, give out broader roles, or remove an admin", async () => {
    as(LEAD);
    expect((await teamPATCH(req("/api/team", "PATCH", { user_id: "u-dev", role: "admin" }))).status).toBe(403);
    expect((await teamPATCH(req("/api/team", "PATCH", { user_id: "u-dev", role: "security_reviewer" }))).status).toBe(403);
    expect((await teamDELETE(req("/api/team?user_id=u-admin2", "DELETE"))).status).toBe(403);
    expect(rows("org_members").find(m => m.user_id === "u-dev")!.role).toBe("developer");
    expect(rows("org_members").some(m => m.user_id === "u-admin2")).toBe(true);
    // ...but can assign a role within their own reach
    expect((await teamPATCH(req("/api/team", "PATCH", { user_id: "u-dev", custom_role_id: CR_JUNIOR }))).status).toBe(200);
  });
});

describe("/api/me", () => {
  it("returns the effective permissions and the custom role's name for the UI", async () => {
    db.client.from("organizations");
    as(JUNIOR);
    const me = await (await meGET(req("/api/me", "GET"))).json();
    expect(me.permissions).toEqual(permissionsFromRow({ can_attest_high: true, can_attest_medium: true }));
    expect(me.custom_role_name).toBe("Junior reviewer");
    as(DEV);
    expect((await (await meGET(req("/api/me", "GET"))).json()).permissions).toEqual(BUILTIN_PERMISSIONS.developer);
  });
});
