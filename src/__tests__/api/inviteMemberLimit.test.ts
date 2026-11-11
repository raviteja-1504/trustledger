/**
 * @jest-environment node
 *
 * The free trial has 2 team members: inviting a third is refused with a message, before any email is sent.
 */
import { NextRequest } from "next/server";
import { fakeSupabase } from "../helpers/fakeSupabase";

let db: ReturnType<typeof fakeSupabase>;
const invite = jest.fn(async () => ({ data: { user: { id: "u-new" } }, error: null }));
jest.mock("@/lib/supabase", () => ({ createServiceClient: () => ({ ...db.client, auth: { admin: { inviteUserByEmail: invite } } }) }));
jest.mock("@/lib/audit", () => ({ writeAuditLog: async () => {} }));
jest.mock("@/lib/cache", () => ({ cacheDel: async () => {}, invalidateViolationsCache: async () => {}, cached: async (_k: string, _t: number, f: () => unknown) => f(), cacheKeys: { dashboard: () => "d", violations: () => "v" }, TTL: {} }));
jest.mock("@/lib/rateLimit", () => ({ checkRateLimit: async () => ({ success: true, headers: {} }) }));
jest.mock("@/app/api/_middleware", () => ({ ...jest.requireActual("@/app/api/_middleware"), verifyApiKey: async () => ({ org_id: "org-1", user_id: "u1", actor_email: "a@x.test", role: "admin" }) }));

import { POST } from "@/app/api/settings/route";

const member = (i: number, org = "org-1") => ({ id: `m${i}`, org_id: org, user_id: `u${i}`, email: `m${i}@x.test`, role: "developer" });
const send = async () => { const r = await POST(new NextRequest(new URL("/api/settings", "https://app.example"), { method: "POST", body: JSON.stringify({ action: "invite_member", email: "new@x.test", role: "developer" }) })); return { status: r.status, body: await r.json() as Record<string, unknown> }; };
beforeEach(() => { invite.mockClear(); });

it("with room: the invitation is sent", async () => {
  db = fakeSupabase({ organizations: [{ id: "org-1", plan: "free" }], org_members: [member(1)] });
  expect((await send()).status).toBe(200);
  expect(invite).toHaveBeenCalledTimes(1);
});

it("a full team (2 members, counting people already invited): refused with a message, and no email is sent", async () => {
  db = fakeSupabase({ organizations: [{ id: "org-1", plan: "free" }], org_members: [member(1), member(2), member(3, "org-2")] });
  const r = await send();
  expect(r.status).toBe(403);
  expect(r.body.error).toBe("plan_limit_members");
  expect(String(r.body.message)).toMatch(/2 team members.*Contact us to upgrade/);
  expect(invite).not.toHaveBeenCalled();
});
