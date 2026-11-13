/**
 * @jest-environment node
 *
 * GET /api/onboarding reports whether the organisation is already running (other members, or scans), so that only a
 * brand-new organisation's creator is sent to the setup wizard.
 */
import { NextRequest } from "next/server";
import { fakeSupabase } from "../helpers/fakeSupabase";

let db = fakeSupabase({});
jest.mock("@/lib/supabase", () => ({ createServiceClient: () => db.client }));
jest.mock("@/app/api/_middleware", () => ({
  ...jest.requireActual("@/app/api/_middleware"),
  verifyApiKey: async () => ({ org_id: "org-1", user_id: "u1", role: "admin" }),
}));

import { GET } from "@/app/api/onboarding/route";

const get = async () => (await GET(new NextRequest(new URL("/api/onboarding", "https://app.example")))).json() as Promise<{ complete: boolean; org_name: string; members: number; has_scans: boolean }>;

describe("GET /api/onboarding", () => {
  it("a brand-new organisation: one member, nothing scanned, not complete", async () => {
    db = fakeSupabase({
      organizations: [{ id: "org-1", name: "Acme", onboarding_complete: false }],
      org_members: [{ id: "m1", org_id: "org-1", user_id: "u1" }, { id: "m9", org_id: "org-2", user_id: "u9" }],
      scans: [{ id: "x", org_id: "org-2" }],
    });
    expect(await get()).toEqual({ complete: false, org_name: "Acme", github_org: null, members: 1, has_scans: false });
  });
  it("a running organisation: other members and scans (counted for this organisation only)", async () => {
    db = fakeSupabase({
      organizations: [{ id: "org-1", name: "Acme", onboarding_complete: false }],
      org_members: [{ id: "m1", org_id: "org-1" }, { id: "m2", org_id: "org-1" }, { id: "m3", org_id: "org-1" }],
      scans: [{ id: "s1", org_id: "org-1" }],
    });
    expect(await get()).toEqual({ complete: false, org_name: "Acme", github_org: null, members: 3, has_scans: true });
  });
});
