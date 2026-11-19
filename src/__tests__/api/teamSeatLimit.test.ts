/**
 * @jest-environment node
 *
 * Team management (POST /api/team) must stop at the plan's member limit. It used to add the 3rd member to a 2-member plan and
 * the settings page then showed "Over the limit: 3 members against 2 on your plan": only the older /api/settings invite path
 * checked the limit.
 */
import { NextRequest } from "next/server";
import { fakeSupabase } from "../helpers/fakeSupabase";

let db: ReturnType<typeof fakeSupabase>;
const inviteUserByEmail = jest.fn();
jest.mock("@/lib/supabase", () => ({
  createServiceClient: () => ({ ...db.client, auth: { admin: { inviteUserByEmail, listUsers: async () => ({ data: { users: [] } }) } } }),
}));
jest.mock("@/app/api/_middleware", () => ({
  ...jest.requireActual("@/app/api/_middleware"),
  verifyApiKey: async () => ({ org_id: "org-1", user_id: "u-admin", actor_email: "admin@a.test", role: "admin" }),
}));
jest.mock("@/lib/audit", () => ({ writeAuditLog: jest.fn(async () => {}) }));

import { POST as teamPOST } from "@/app/api/team/route";

const member = (n: number) => ({ id: `m-${n}`, org_id: "org-1", user_id: `u-${n}`, email: `user${n}@a.test`, role: "developer", custom_role_id: null });
const post = (body: unknown) => teamPOST(new NextRequest(new URL("/api/team", "https://app.example"), { method: "POST", body: JSON.stringify(body) }));
const members = () => (db.client.from("org_members") as unknown as { rows: unknown[] }).rows;

beforeEach(() => {
  jest.clearAllMocks();
  inviteUserByEmail.mockImplementation(async () => ({ data: { user: { id: "u-new" } }, error: null }));
});

describe("POST /api/team respects the plan's member limit", () => {
  it("refuses a 3rd member on a 2-member plan: nothing is added and no invite email is sent", async () => {
    db = fakeSupabase({ organizations: [{ id: "org-1", plan: "free" }], org_members: [member(1), member(2)] });
    const res = await post({ email: "third@a.test", role: "developer" });
    expect(res.status).toBe(403);
    const body = await res.json();
    expect(body.error).toBe("plan_limit_members");
    expect(body.message).toMatch(/2 team members/);
    expect(inviteUserByEmail).not.toHaveBeenCalled();
    expect(members()).toHaveLength(2);
  });

  it("counts members who were invited but have not signed in yet (same table, no user activity needed)", async () => {
    db = fakeSupabase({ organizations: [{ id: "org-1", plan: "free" }], org_members: [member(1), { ...member(2), user_id: null }] });
    expect((await post({ email: "third@a.test", role: "developer" })).status).toBe(403);
    expect(members()).toHaveLength(2);
  });

  it("still adds a member while there is room", async () => {
    db = fakeSupabase({ organizations: [{ id: "org-1", plan: "free" }], org_members: [member(1)] });
    const res = await post({ email: "second@a.test", role: "developer" });
    expect(res.status).toBe(201);
    expect(inviteUserByEmail).toHaveBeenCalledTimes(1);
    expect(members()).toHaveLength(2);
  });

  it("an existing member is reported as already a member, not as a limit error", async () => {
    db = fakeSupabase({ organizations: [{ id: "org-1", plan: "free" }], org_members: [member(1), member(2)] });
    expect((await post({ email: "user1@a.test", role: "developer" })).status).toBe(409);
  });
});
