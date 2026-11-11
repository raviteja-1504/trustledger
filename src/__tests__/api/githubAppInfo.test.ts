/**
 * @jest-environment node
 *
 * GET /api/github-app/info: is TrustLedger's GitHub App set up on this deployment, and where does a customer install it?
 */
import { NextRequest } from "next/server";

let auth: { error?: string; org_id?: string } = { org_id: "org-1" };
jest.mock("@/app/api/_middleware", () => ({ verifyApiKey: async () => auth }));
const getAppPublicInfo = jest.fn();
jest.mock("@/lib/github", () => ({ getAppPublicInfo: (...a: unknown[]) => getAppPublicInfo(...a) }));

import { GET } from "@/app/api/github-app/info/route";

const get = async () => { const res = await GET(new NextRequest(new URL("/api/github-app/info", "https://app.example"))); return { status: res.status, body: await res.json() }; };
const ENV = { id: process.env.GITHUB_APP_ID, key: process.env.GITHUB_APP_PRIVATE_KEY };

beforeEach(() => { auth = { org_id: "org-1" }; getAppPublicInfo.mockReset(); });
afterAll(() => { process.env.GITHUB_APP_ID = ENV.id; process.env.GITHUB_APP_PRIVATE_KEY = ENV.key; });

describe("GET /api/github-app/info", () => {
  it("needs a signed-in user", async () => {
    auth = { error: "unauthorized" };
    expect((await get()).status).toBe(401);
  });

  it("no app set up yet: not configured, no link (the wizard then shows the operator's creation guide)", async () => {
    delete process.env.GITHUB_APP_ID; delete process.env.GITHUB_APP_PRIVATE_KEY;
    expect((await get()).body).toEqual({ configured: false, install_url: null });
    expect(getAppPublicInfo).not.toHaveBeenCalled();
  });

  it("app set up: configured, with the link a customer clicks to install it", async () => {
    process.env.GITHUB_APP_ID = "123"; process.env.GITHUB_APP_PRIVATE_KEY = "pem";
    getAppPublicInfo.mockResolvedValue({ slug: "trustledger", html_url: "x", install_url: "https://github.com/apps/trustledger/installations/new" });
    expect((await get()).body).toEqual({ configured: true, install_url: "https://github.com/apps/trustledger/installations/new" });
  });

  it("app set up but GitHub can't be asked right now: configured, no link (the page offers a retry); no secret is returned", async () => {
    process.env.GITHUB_APP_ID = "123"; process.env.GITHUB_APP_PRIVATE_KEY = "super-secret-pem";
    getAppPublicInfo.mockRejectedValue(new Error("GitHub app lookup failed: 502"));
    const { body } = await get();
    expect(body).toEqual({ configured: true, install_url: null });
    expect(JSON.stringify(body)).not.toContain("super-secret-pem");
  });
});
