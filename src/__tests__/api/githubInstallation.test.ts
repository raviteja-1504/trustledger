/**
 * @jest-environment node
 *
 * After installing the GitHub App, GitHub sends the person back with ?installation_id=...; this asks GitHub which account
 * the installation is on, so the setup wizard can fill in the organisation handle.
 */
import { NextRequest } from "next/server";

let auth: { error?: string; org_id?: string } = { org_id: "org-1" };
jest.mock("@/app/api/_middleware", () => ({ verifyApiKey: async () => auth }));
const getInstallationAccount = jest.fn();
jest.mock("@/lib/github", () => ({ getInstallationAccount: (...a: unknown[]) => getInstallationAccount(...a) }));

import { GET } from "@/app/api/github-app/installation/route";

const get = async (qs: string) => { const res = await GET(new NextRequest(new URL(`/api/github-app/installation${qs}`, "https://app.example"))); return { status: res.status, body: await res.json() }; };
beforeEach(() => { auth = { org_id: "org-1" }; getInstallationAccount.mockReset(); });

describe("GET /api/github-app/installation", () => {
  it("needs a signed-in user", async () => {
    auth = { error: "unauthorized" };
    expect((await get("?id=1")).status).toBe(401);
  });
  it("returns the account's login for a numeric installation id", async () => {
    getInstallationAccount.mockResolvedValue("acme-corp");
    expect(await get("?id=12345")).toEqual({ status: 200, body: { login: "acme-corp" } });
    expect(getInstallationAccount).toHaveBeenCalledWith(12345);
  });
  it("rejects a missing or non-numeric id without asking GitHub", async () => {
    for (const qs of ["", "?id=", "?id=abc", "?id=1;drop", "?id=-5"]) expect((await get(qs)).status).toBe(400);
    expect(getInstallationAccount).not.toHaveBeenCalled();
  });
  it("an installation GitHub doesn't know is a 404, not a server error", async () => {
    getInstallationAccount.mockRejectedValue(new Error("GitHub installation lookup failed: 404"));
    expect((await get("?id=999")).status).toBe(404);
  });
});
