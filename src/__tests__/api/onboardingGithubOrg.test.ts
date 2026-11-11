/**
 * @jest-environment node
 *
 * A GitHub organisation belongs to one TrustLedger organisation (its pull requests are routed by that handle): saving a
 * handle another organisation already holds is refused with a clear error, not lost quietly.
 */
import { NextRequest } from "next/server";
import { fakeSupabase } from "../helpers/fakeSupabase";

let db = fakeSupabase({});
jest.mock("@/lib/supabase", () => ({ createServiceClient: () => db.client }));
jest.mock("@/app/api/_middleware", () => ({
  ...jest.requireActual("@/app/api/_middleware"),
  verifyApiKey: async () => ({ org_id: "org-1", user_id: "u1", role: "admin" }),
}));

import { POST } from "@/app/api/onboarding/route";

const save = async (github_org: string) => {
  const res = await POST(new NextRequest(new URL("/api/onboarding", "https://app.example"), { method: "POST", body: JSON.stringify({ action: "save_github_org", github_org }) }));
  return { status: res.status, body: await res.json() };
};
const handleOf = async (id: string) => ((await db.client.from("organizations").select("github_org").eq("id", id).single()) as unknown as { data: { github_org: string | null } }).data.github_org;

beforeEach(() => {
  db = fakeSupabase({ organizations: [{ id: "org-1", github_org: null }, { id: "org-2", github_org: "taken-corp" }] });
});

describe("POST /api/onboarding save_github_org", () => {
  it("links a free handle to the caller's organisation", async () => {
    expect((await save("acme-corp")).status).toBe(200);
    expect(await handleOf("org-1")).toBe("acme-corp");
  });
  it("refuses a handle another organisation already holds, and changes nothing", async () => {
    const r = await save("taken-corp");
    expect(r).toEqual({ status: 409, body: { error: "github_org_taken" } });
    expect(await handleOf("org-1")).toBeNull();
    expect(await handleOf("org-2")).toBe("taken-corp");
  });
  it("saving the organisation's own handle again is fine", async () => {
    await save("acme-corp");
    expect((await save("acme-corp")).status).toBe(200);
  });
  it("a missing handle is a 400", async () => {
    expect((await save("  ")).status).toBe(400);
  });
});
