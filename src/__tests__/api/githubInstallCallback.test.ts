/**
 * @jest-environment node
 *
 * GET /api/auth/callback is where GitHub sends a person after they install the app. It links the installation to their
 * organisation, then returns them to the setup wizard while setup is unfinished (or the dashboard once it is done):
 * Settings has nothing about GitHub to show, and a new tab left behind is not where they should end up.
 */
import { NextRequest } from "next/server";
import { fakeSupabase } from "../helpers/fakeSupabase";

let db = fakeSupabase({});
jest.mock("@/lib/supabase", () => ({
  createServiceClient: () => ({ ...db.client, auth: { getUser: async () => ({ data: { user: { id: "u1" } }, error: null }) } }),
}));
const getInstallationAccount = jest.fn(async (_id: number) => "acme-corp");
jest.mock("@/lib/github", () => ({ getInstallationAccount: (...a: unknown[]) => getInstallationAccount(...(a as [number])) }));
jest.mock("@/lib/logger", () => ({ logger: { error: jest.fn(), info: jest.fn(), warn: jest.fn() } }));

import { GET } from "@/app/api/auth/callback/route";

process.env.NEXT_PUBLIC_SUPABASE_URL = "https://abcdef.supabase.co";
const COOKIE = `sb-abcdef-auth-token=${encodeURIComponent(JSON.stringify({ access_token: "tok" }))}`;
const call = async (qs: string, cookie: string | null = COOKIE) => {
  const res = await GET(new NextRequest(new URL(`/api/auth/callback${qs}`, "https://app.example"), { headers: cookie ? { cookie } : {} }));
  const loc = res.headers.get("location") ?? "";
  return { status: res.status, path: loc.replace("https://app.example", "") };
};
const seed = (complete: boolean) => {
  db = fakeSupabase({
    org_members: [{ org_id: "org-1", user_id: "u1" }],
    organizations: [{ id: "org-1", onboarding_complete: complete }],
    github_installations: [],
  });
};
beforeEach(() => { seed(false); getInstallationAccount.mockClear(); });

describe("GitHub App install callback", () => {
  it("setup unfinished: back into the wizard, with the installation, and the installation is linked to the organisation", async () => {
    const r = await call("?code=c&installation_id=777&setup_action=install");
    expect(r.path).toBe("/onboarding?github_app=connected&installation_id=777&setup_action=install");
    const rows = ((await db.client.from("github_installations").select("*")) as unknown as { data: Array<Record<string, unknown>> }).data;
    expect(rows).toEqual([expect.objectContaining({ org_id: "org-1", installation_id: 777, github_org: "acme-corp" })]);
  });

  it("setup already done: the dashboard, not Settings", async () => {
    seed(true);
    expect((await call("?installation_id=777&setup_action=install")).path).toBe("/dashboard?github_app=connected");
  });

  it("a request waiting for an organisation owner's approval (no installation id): the wizard says so", async () => {
    expect((await call("?setup_action=request")).path).toBe("/onboarding?setup_action=request");
  });

  it("no installation id and no request: back to the wizard with an error it shows", async () => {
    expect((await call("")).path).toBe("/onboarding?error=missing_installation_id");
  });

  it("not signed in: the login page", async () => {
    expect((await call("?installation_id=777&setup_action=install", null)).path).toBe("/login?error=not_signed_in");
  });
});
