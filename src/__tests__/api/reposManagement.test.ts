/**
 * @jest-environment node
 *
 * Settings → Repositories server side: import from the GitHub App, switch on/off, add by name, App status.
 */
import { NextRequest } from "next/server";
import { fakeSupabase } from "../helpers/fakeSupabase";

let db: ReturnType<typeof fakeSupabase>;
let role = "admin";
jest.mock("@/lib/supabase", () => ({ createServiceClient: () => db.client }));
const cacheDel = jest.fn(async () => {});
jest.mock("@/lib/cache", () => ({ cacheDel: (k: string) => cacheDel(k as never), cacheKeys: { dashboard: (o: string, d: number) => `dash:${o}:${d}` } }));
jest.mock("@/app/api/_middleware", () => ({
  ...jest.requireActual("@/app/api/_middleware"),
  verifyApiKey: async () => ({ org_id: "org-1", user_id: "u1", role }),
}));
const gh = {
  getInstallationToken: jest.fn(async (id: number) => ({ token: `tok-${id}` })),
  listInstallationRepos: jest.fn(),
  getAppPublicInfo: jest.fn(async () => ({ slug: "trustledger-app", html_url: "https://github.com/apps/trustledger-app", install_url: "https://github.com/apps/trustledger-app/installations/new" })),
};
jest.mock("@/lib/github", () => ({
  getInstallationToken: (id: number) => gh.getInstallationToken(id),
  listInstallationRepos: (t: string) => gh.listInstallationRepos(t),
  getAppPublicInfo: () => gh.getAppPublicInfo(),
}));

import { GET, POST, PATCH } from "@/app/api/repos/route";
import { GET as githubStatus } from "@/app/api/repos/github/route";

const rows = (t: string) => (db.client.from(t) as unknown as { rows: Record<string, unknown>[] }).rows;
const req = (url: string, method = "GET", body?: unknown) =>
  new NextRequest(new URL(url, "https://app.example"), { method, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });

beforeEach(() => {
  jest.clearAllMocks();
  role = "admin";
  db = fakeSupabase({
    repositories: [
      { id: "r1", org_id: "org-1", repo_full_name: "raviteja-1504/trustledger", is_active: true, default_branch: "master" },
      { id: "r2", org_id: "org-1", repo_full_name: "acme/payments-api", is_active: false, default_branch: "main" },
      { id: "r3", org_id: "org-2", repo_full_name: "other/private", is_active: true, default_branch: "main" },
    ],
    github_installations: [
      { org_id: "org-1", installation_id: 11, github_org: "raviteja-1504" },
      { org_id: "org-1", installation_id: 22, github_org: "nama-corp" },
    ],
  });
  gh.listInstallationRepos.mockImplementation(async (token: string) => token === "tok-11"
    ? [{ full_name: "raviteja-1504/trustledger", default_branch: "master", private: false }, { full_name: "raviteja-1504/juiceshop-test", default_branch: "main", private: false }]
    : [{ full_name: "nama-corp/billing", default_branch: "develop", private: true }, { full_name: "acme/payments-api", default_branch: "main", private: false }]);
});

describe("import from GitHub", () => {
  it("adds only repositories that aren't connected yet, from every installation; switched-off repos stay off", async () => {
    const res = await POST(req("/api/repos?import=github", "POST"));
    expect(await res.json()).toEqual({ added: 2, already_connected: 2, total: 4 });
    const org = rows("repositories").filter(r => r.org_id === "org-1");
    expect(org.map(r => r.repo_full_name).sort()).toEqual(["acme/payments-api", "nama-corp/billing", "raviteja-1504/juiceshop-test", "raviteja-1504/trustledger"]);
    expect(org.find(r => r.repo_full_name === "acme/payments-api")!.is_active).toBe(false);
    expect(org.find(r => r.repo_full_name === "nama-corp/billing")).toMatchObject({ is_active: true, default_branch: "develop" });
    expect(gh.getInstallationToken).toHaveBeenCalledWith(11);
    expect(gh.getInstallationToken).toHaveBeenCalledWith(22);
  });

  it("explains a missing GitHub App, and an App that can see no repositories", async () => {
    db = fakeSupabase({ repositories: [], github_installations: [] });
    let res = await POST(req("/api/repos?import=github", "POST"));
    expect(res.status).toBe(422);
    expect((await res.json()).error).toBe("github_app_not_installed");
    db = fakeSupabase({ repositories: [], github_installations: [{ org_id: "org-1", installation_id: 11, github_org: "x" }] });
    gh.listInstallationRepos.mockResolvedValue([]);
    res = await POST(req("/api/repos?import=github", "POST"));
    expect((await res.json()).error).toBe("no_repos_found");
  });

  it("is admin-only", async () => {
    role = "developer";
    const res = await POST(req("/api/repos?import=github", "POST"));
    expect(res.status).toBe(403);
    expect(gh.listInstallationRepos).not.toHaveBeenCalled();
  });
});

it("switching a repository clears the cached dashboard numbers right away", async () => {
  await PATCH(req("/api/repos", "PATCH", { id: "r1", is_active: false }));
  expect(cacheDel.mock.calls.map(c => c[0]).sort()).toEqual(["dash:org-1:30", "dash:org-1:7", "dash:org-1:90"]);
  cacheDel.mockClear();
  await POST(req("/api/repos?import=github", "POST"));
  expect(cacheDel).toHaveBeenCalledTimes(3);
});

describe("switch on / off", () => {
  it("an admin switches a repository; another org's repository can't be touched", async () => {
    expect((await PATCH(req("/api/repos", "PATCH", { id: "r1", is_active: false }))).status).toBe(200);
    expect(rows("repositories").find(r => r.id === "r1")!.is_active).toBe(false);
    expect((await PATCH(req("/api/repos", "PATCH", { id: "r3", is_active: false }))).status).toBe(404);
    expect(rows("repositories").find(r => r.id === "r3")!.is_active).toBe(true);
  });

  it("needs a boolean, and is admin-only", async () => {
    expect((await PATCH(req("/api/repos", "PATCH", { id: "r1", is_active: "no" }))).status).toBe(400);
    role = "security_reviewer";
    expect((await PATCH(req("/api/repos", "PATCH", { id: "r1", is_active: false }))).status).toBe(403);
    expect(rows("repositories").find(r => r.id === "r1")!.is_active).toBe(true);
  });
});

it("adding one repo by name requires owner/name and admin", async () => {
  expect((await POST(req("/api/repos", "POST", { repo_full_name: "not a repo" }))).status).toBe(400);
  expect((await POST(req("/api/repos", "POST", { repo_full_name: "my-org/api" }))).status).toBe(200);
  role = "developer";
  expect((await POST(req("/api/repos", "POST", { repo_full_name: "my-org/other" }))).status).toBe(403);
});

it("lists only this org's repositories", async () => {
  const { repos } = await (await GET(req("/api/repos"))).json();
  expect(repos.map((r: { repo_full_name: string }) => r.repo_full_name)).toEqual(["acme/payments-api", "raviteja-1504/trustledger"]);
});

it("reports the GitHub App's installations and its install link", async () => {
  expect(await (await githubStatus(req("/api/repos/github"))).json()).toEqual({
    installed: true, accounts: ["raviteja-1504", "nama-corp"], install_url: "https://github.com/apps/trustledger-app/installations/new",
  });
  db = fakeSupabase({ github_installations: [] });
  gh.getAppPublicInfo.mockRejectedValueOnce(new Error("no key"));
  expect(await (await githubStatus(req("/api/repos/github"))).json()).toEqual({ installed: false, accounts: [], install_url: null });
});
