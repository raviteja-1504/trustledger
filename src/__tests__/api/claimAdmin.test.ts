/**
 * @jest-environment node
 *
 * POST /api/claim-admin: the recovery path for an organisation with no admin. Before, ANY member of such an organisation
 * (a viewer, a developer) could make themselves admin; now only its oldest member, the one who created it, can.
 */
import { NextRequest } from "next/server";
import { fakeSupabase } from "../helpers/fakeSupabase";

let db = fakeSupabase({});
jest.mock("@/lib/supabase", () => ({ createServiceClient: () => db.client }));
let auth: { error?: string; org_id: string; user_id?: string; actor_email?: string } = { org_id: "org-1", user_id: "u-owner", actor_email: "owner@acme.test" };
jest.mock("@/app/api/_middleware", () => ({ verifyApiKey: async () => auth }));
let allowed = true;
jest.mock("@/lib/rateLimit", () => ({ ...jest.requireActual("@/lib/rateLimit"), checkRateLimit: async () => ({ success: allowed, headers: {} }) }));
const audit = jest.fn(async (..._a: unknown[]) => undefined);
jest.mock("@/lib/audit", () => ({ ...jest.requireActual("@/lib/audit"), writeAuditLog: (...a: unknown[]) => audit(...a) }));

import { POST } from "@/app/api/claim-admin/route";

const call = async () => { const res = await POST(new NextRequest(new URL("/api/claim-admin", "https://app.example"), { method: "POST" })); return { status: res.status, body: await res.json() as Record<string, unknown> }; };
const roleOf = async (user: string) => ((await db.client.from("org_members").select("role").eq("user_id", user).single()) as unknown as { data: { role: string } }).data.role;

const member = (id: number, user_id: string | null, role: string, created_at: string, org_id = "org-1") => ({ id, org_id, user_id, role, created_at });
beforeEach(() => {
  auth = { org_id: "org-1", user_id: "u-owner", actor_email: "owner@acme.test" };
  allowed = true; audit.mockClear();
  // an organisation whose admin is gone: the owner (oldest), a developer and a viewer who joined later
  db = fakeSupabase({
    org_members: [
      member(1, "u-owner", "developer", "2026-01-01T00:00:00Z"),
      member(2, "u-dev", "developer", "2026-02-01T00:00:00Z"),
      member(3, "u-view", "viewer", "2026-03-01T00:00:00Z"),
    ],
  });
});

describe("POST /api/claim-admin", () => {
  it("the organisation's oldest member becomes admin, and it is audit-logged", async () => {
    const r = await call();
    expect(r.status).toBe(200);
    expect(await roleOf("u-owner")).toBe("admin");
    expect(audit).toHaveBeenCalledTimes(1);
    expect(audit.mock.calls[0][1]).toMatchObject({ org_id: "org-1", event_type: "member_role_changed", actor_id: "u-owner", resource_id: "u-owner", payload: { via: "claim_admin", to: "admin" } });
  });

  it("any other member is refused with a reason, and nothing changes (this was open to every member)", async () => {
    for (const user of ["u-dev", "u-view"]) {
      auth = { org_id: "org-1", user_id: user };
      const r = await call();
      expect(r.status).toBe(403);
      expect(r.body.error).toBe("not_the_owner");
      expect(String(r.body.message)).toMatch(/first member/);
      expect(await roleOf(user)).not.toBe("admin");
    }
    expect(audit).not.toHaveBeenCalled();
  });

  it("an invitation nobody has accepted (no user yet) does not hold the ownership", async () => {
    db = fakeSupabase({ org_members: [member(1, null, "developer", "2025-12-01T00:00:00Z"), member(2, "u-owner", "developer", "2026-01-01T00:00:00Z"), member(3, "u-dev", "developer", "2026-02-01T00:00:00Z")] });
    expect((await call()).status).toBe(200);
    expect(await roleOf("u-owner")).toBe("admin");
  });

  it("an organisation that has an admin: refused, as before", async () => {
    db = fakeSupabase({ org_members: [member(1, "u-owner", "developer", "2026-01-01T00:00:00Z"), member(2, "u-admin", "admin", "2026-02-01T00:00:00Z")] });
    const r = await call();
    expect(r.status).toBe(403);
    expect(r.body.error).toBe("org_has_admin");
    expect(await roleOf("u-owner")).toBe("developer");
  });

  it("another organisation's members are not counted (an admin elsewhere does not block, an owner elsewhere does not qualify)", async () => {
    db = fakeSupabase({ org_members: [member(1, "u-other-admin", "admin", "2025-01-01T00:00:00Z", "org-2"), member(2, "u-early", "developer", "2025-06-01T00:00:00Z", "org-2"), member(3, "u-owner", "developer", "2026-01-01T00:00:00Z")] });
    expect((await call()).status).toBe(200);
    expect(await roleOf("u-owner")).toBe("admin");
  });

  it("an API key (no person) is refused; too many attempts are rate-limited", async () => {
    auth = { org_id: "org-1" };
    expect((await call()).status).toBe(400);
    auth = { org_id: "org-1", user_id: "u-owner" };
    allowed = false;
    expect((await call()).status).toBe(429);
    expect(await roleOf("u-owner")).toBe("developer");
  });

  it("not signed in: 401", async () => {
    auth = { error: "unauthorized", org_id: "" };
    expect((await call()).status).toBe(401);
  });
});
