/**
 * @jest-environment node
 *
 * Cross-tenant fixes from the isolation audit: an org admin can't grant platform_admin (which reads every
 * org), and record ids taken from a request body can't touch another org's rows.
 */
import { NextRequest } from "next/server";
import { fakeSupabase } from "../helpers/fakeSupabase";

let db: ReturnType<typeof fakeSupabase>;
jest.mock("@/lib/supabase", () => ({ createServiceClient: () => db.client }));
const audit = jest.fn(async (..._args: unknown[]) => {});
jest.mock("@/lib/audit", () => ({ writeAuditLog: (...a: unknown[]) => audit(...a) }));
jest.mock("@/lib/cache", () => ({
  cacheDel: async () => {}, invalidateViolationsCache: async () => {}, cached: async (_k: string, _t: number, f: () => unknown) => f(),
  cacheKeys: { dashboard: () => "d", violations: () => "v" }, TTL: {},
}));
jest.mock("@/lib/rateLimit", () => ({ checkRateLimit: async () => ({ success: true, headers: {} }) }));
jest.mock("@/app/api/_middleware", () => ({
  ...jest.requireActual("@/app/api/_middleware"),
  verifyApiKey: async () => ({ org_id: "org-1", user_id: "u-admin", actor_email: "admin@org1.test", role: "admin" }),
}));

import { POST as settingsPOST } from "@/app/api/settings/route";
import { PATCH as teamPATCH } from "@/app/api/team/route";
import { PATCH as violationsPATCH } from "@/app/api/violations/route";
import { POST as ticketPOST } from "@/app/api/integrations/ticket/route";

const rows = (t: string) => (db.client.from(t) as unknown as { rows: Record<string, unknown>[] }).rows;
const req = (url: string, method: string, body: unknown) =>
  new NextRequest(new URL(url, "https://app.example"), { method, body: JSON.stringify(body) });

const OWN_VIOLATION   = "11111111-1111-4111-8111-111111111111";
const OTHER_VIOLATION = "22222222-2222-4222-8222-222222222222";

beforeEach(() => {
  jest.clearAllMocks();
  db = fakeSupabase({
    org_members: [
      { id: "m1", org_id: "org-1", user_id: "u-admin", email: "admin@org1.test", role: "admin" },
      { id: "m2", org_id: "org-1", user_id: "u-dev", email: "dev@org1.test", role: "developer" },
    ],
    violations: [
      { id: OWN_VIOLATION, org_id: "org-1", status: "open", notes: [], file_path: "a.ts", risk_score: "HIGH", scan_id: "s1" },
      { id: OTHER_VIOLATION, org_id: "org-2", status: "open", notes: [], file_path: "b.ts", risk_score: "HIGH", scan_id: "s2" },
    ],
  });
});

describe("platform_admin can't be granted by an org admin", () => {
  it("settings: rejects platform_admin (self or others) and unknown roles, changing nothing", async () => {
    for (const [user_id, role] of [["u-admin", "platform_admin"], ["u-dev", "platform_admin"], ["u-dev", "owner"]]) {
      const res = await settingsPOST(req("/api/settings", "POST", { action: "update_member_role", user_id, role }));
      expect(res.status).toBe(400);
      expect((await res.json()).error).toBe("invalid_role");
    }
    expect(rows("org_members").map(m => m.role)).toEqual(["admin", "developer"]);
  });

  it("settings: rejects platform_admin on invite too", async () => {
    const res = await settingsPOST(req("/api/settings", "POST", { action: "invite_member", email: "x@y.test", role: "platform_admin" }));
    expect(res.status).toBe(400);
  });

  it("settings: a normal role change still works, and is audit-logged", async () => {
    const res = await settingsPOST(req("/api/settings", "POST", { action: "update_member_role", user_id: "u-dev", role: "security_reviewer" }));
    expect(res.status).toBe(200);
    expect(rows("org_members").find(m => m.user_id === "u-dev")!.role).toBe("security_reviewer");
    expect(audit).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({ event_type: "member_role_changed", payload: { new_role: "security_reviewer" } }));
  });

  it("team: rejects platform_admin", async () => {
    const res = await teamPATCH(req("/api/team", "PATCH", { user_id: "u-dev", role: "platform_admin" }));
    expect(res.status).toBe(400);
    expect(rows("org_members").find(m => m.user_id === "u-dev")!.role).toBe("developer");
  });
});

describe("request-body record ids stay inside the caller's org", () => {
  it("violations: a note lands on the caller's own violation", async () => {
    const res = await violationsPATCH(req("/api/violations", "PATCH", { id: OWN_VIOLATION, status: "in_review", note: "looking" }));
    expect(res.status).toBe(200);
    expect(rows("violations").find(v => v.id === OWN_VIOLATION)!.notes).toEqual([expect.objectContaining({ text: "looking" })]);
  });

  it("violations: another org's violation is neither updated nor noted", async () => {
    const res = await violationsPATCH(req("/api/violations", "PATCH", { id: OTHER_VIOLATION, status: "resolved", note: "pwned" }));
    expect(res.status).toBe(500);
    expect(rows("violations").find(v => v.id === OTHER_VIOLATION)).toMatchObject({ status: "open", notes: [] });
  });

  describe("integrations/ticket", () => {
    const realFetch = global.fetch;
    beforeEach(() => {
      process.env.LINEAR_API_KEY = "lin-test";
      process.env.LINEAR_TEAM_ID = "team-1";
      global.fetch = jest.fn(async () => new Response(JSON.stringify({
        data: { issueCreate: { success: true, issue: { id: "iss-1", identifier: "TL-1", url: "https://linear.app/tl/issue/TL-1" } } },
      }))) as unknown as typeof fetch;
    });
    afterEach(() => {
      global.fetch = realFetch;
      delete process.env.LINEAR_API_KEY;
      delete process.env.LINEAR_TEAM_ID;
    });

    it("records the ticket on the caller's own violation", async () => {
      const res = await ticketPOST(req("/api/integrations/ticket", "POST", { provider: "linear", title: "t", description: "d", violation_id: OWN_VIOLATION }));
      expect(res.status).toBe(200);
      expect(rows("violations").find(v => v.id === OWN_VIOLATION)!.notes).toEqual([expect.objectContaining({ text: expect.stringContaining("TL-1") })]);
    });

    it("never writes to another org's violation", async () => {
      const res = await ticketPOST(req("/api/integrations/ticket", "POST", { provider: "linear", title: "t", description: "d", violation_id: OTHER_VIOLATION }));
      expect(res.status).toBe(200);
      expect(rows("violations").find(v => v.id === OTHER_VIOLATION)!.notes).toEqual([]);
    });
  });
});
