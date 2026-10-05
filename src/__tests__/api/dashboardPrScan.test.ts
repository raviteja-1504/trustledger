/**
 * @jest-environment node
 *
 * Dashboard "New Scan" server side: listing a connected repo's open PRs, and queueing a scan of one.
 */
import { NextRequest } from "next/server";
import { fakeSupabase } from "../helpers/fakeSupabase";

let db: ReturnType<typeof fakeSupabase>;
jest.mock("@/lib/supabase", () => ({ createServiceClient: () => db.client }));
jest.mock("@/app/api/_middleware", () => ({ ...jest.requireActual("@/app/api/_middleware"), verifyApiKey: async () => ({ org_id: "org-1", user_id: "u1", actor_email: "dev@acme.dev", role: "developer" }) }));
jest.mock("@/lib/audit", () => ({ writeAuditLog: jest.fn(async () => {}) }));
const enqueueScan = jest.fn(async () => {});
jest.mock("@/lib/queue", () => ({ enqueueScan: (...a: unknown[]) => enqueueScan(...(a as [])) }));
const gh = {
  getInstallationToken: jest.fn(async () => ({ token: "t" })),
  getPullRequest: jest.fn(),
  listOpenPullRequests: jest.fn(),
  createCheckRun: jest.fn(async () => ({ id: 77 })),
};
jest.mock("@/lib/github", () => ({
  getInstallationToken: (...a: unknown[]) => gh.getInstallationToken(...(a as [])),
  getPullRequest: (...a: unknown[]) => gh.getPullRequest(...(a as [])),
  listOpenPullRequests: (...a: unknown[]) => gh.listOpenPullRequests(...(a as [])),
  createCheckRun: (...a: unknown[]) => gh.createCheckRun(...(a as [])),
}));

import { GET as listPulls } from "@/app/api/repos/pulls/route";
import { POST as scanPr } from "@/app/api/scans/pr/route";

const pr = { number: 12, title: "Add refunds", author: "ana", branch: "feat/refunds", head_sha: "abc123def456", draft: false, state: "open", updated_at: "2026-10-03T10:00:00Z", additions: 40, deletions: 2, commits: 3, changed_files: 4, created_at: "2026-10-02T10:00:00Z" };

const seed = (extra: Record<string, Record<string, unknown>[]> = {}) => {
  db = fakeSupabase({
    repositories: [
      { org_id: "org-1", repo_full_name: "namacorp/billing", is_active: true },
      { org_id: "org-1", repo_full_name: "namacorp/old-thing", is_active: false },
      { org_id: "org-2", repo_full_name: "other/secret-repo", is_active: true },
    ],
    github_installations: [
      { org_id: "org-1", installation_id: 1001, github_org: "someone-else" },
      { org_id: "org-1", installation_id: 2002, github_org: "NamaCorp" },
    ],
    scans: [],
    ...extra,
  });
};
const get = (q: string) => listPulls(new NextRequest(new URL(`/api/repos/pulls?${q}`, "https://app.example")));
const post = (body: unknown) => scanPr(new NextRequest(new URL("/api/scans/pr", "https://app.example"), { method: "POST", body: JSON.stringify(body) }));

beforeEach(() => { jest.clearAllMocks(); seed(); gh.getPullRequest.mockResolvedValue(pr); gh.listOpenPullRequests.mockResolvedValue([pr]); });

describe("GET /api/repos/pulls", () => {
  it("lists a connected repo's open PRs using the installation that owns the repo", async () => {
    const res = await get("repo=namacorp/billing");
    expect(res.status).toBe(200);
    expect((await res.json()).pulls).toEqual([{ number: 12, title: "Add refunds", author: "ana", branch: "feat/refunds", head_sha: "abc123def456", draft: false, updated_at: "2026-10-03T10:00:00Z" }]);
    expect(gh.getInstallationToken).toHaveBeenCalledWith(2002);
  });

  it("refuses repos that aren't connected (inactive, another org's, or made up)", async () => {
    for (const repo of ["namacorp/old-thing", "other/secret-repo", "acme/payments-api"]) {
      const res = await get(`repo=${repo}`);
      expect(res.status).toBe(404);
      expect((await res.json()).error).toBe("repo_not_connected");
    }
    expect((await get("repo=not-a-repo")).status).toBe(400);
    expect(gh.listOpenPullRequests).not.toHaveBeenCalled();
  });

  it("explains when the GitHub App isn't installed", async () => {
    seed({ github_installations: [] });
    const res = await get("repo=namacorp/billing");
    expect(res.status).toBe(422);
    expect((await res.json()).error).toBe("github_app_not_installed");
  });
});

describe("POST /api/scans/pr", () => {
  it("queues the same GitHub-backed scan a webhook runs, at the PR's current head", async () => {
    const res = await post({ repo: "namacorp/billing", pr_number: 12 });
    expect(await res.json()).toEqual({ status: "queued", repo: "namacorp/billing", pr_number: 12, head_sha: "abc123def456" });
    expect(enqueueScan).toHaveBeenCalledWith(expect.objectContaining({
      org_id: "org-1", installation_id: 2002, repo_full_name: "namacorp/billing", pr_number: 12,
      head_sha: "abc123def456", branch: "feat/refunds", pr_author: "ana", action: "manual", check_run_id: 77, force: false,
    }));
  });

  it("returns the existing scan instead of queueing a duplicate when the head was already scanned", async () => {
    seed({ scans: [{ id: "scan-old", org_id: "org-1", repo_full_name: "namacorp/billing", pr_number: 12, commit_sha: "abc123def456", created_at: "2026-10-01T00:00:00Z" }] });
    const res = await post({ repo: "namacorp/billing", pr_number: 12 });
    expect(await res.json()).toMatchObject({ status: "already_scanned", scan_id: "scan-old" });
    expect(enqueueScan).not.toHaveBeenCalled();
  });

  it("'Scan again' forces a rescan of the same head; a new head needs no force", async () => {
    seed({ scans: [{ id: "scan-old", org_id: "org-1", repo_full_name: "namacorp/billing", pr_number: 12, commit_sha: "abc123def456", created_at: "2026-10-01T00:00:00Z" }] });
    await post({ repo: "namacorp/billing", pr_number: 12, force: true });
    expect(enqueueScan).toHaveBeenLastCalledWith(expect.objectContaining({ force: true }));
    gh.getPullRequest.mockResolvedValue({ ...pr, head_sha: "fff999" });
    await post({ repo: "namacorp/billing", pr_number: 12, force: true });
    expect(enqueueScan).toHaveBeenLastCalledWith(expect.objectContaining({ head_sha: "fff999", force: false }));
  });

  it("at most one scan a minute per PR", async () => {
    seed({ scans: [{ id: "s", org_id: "org-1", repo_full_name: "namacorp/billing", pr_number: 12, commit_sha: "older", created_at: new Date().toISOString() }] });
    const res = await post({ repo: "namacorp/billing", pr_number: 12 });
    expect(res.status).toBe(429);
    expect(enqueueScan).not.toHaveBeenCalled();
  });

  it("rejects bad input, unknown PRs and repos that aren't connected", async () => {
    expect((await post({ repo: "namacorp/billing", pr_number: 0 })).status).toBe(400);
    expect((await post({ repo: "namacorp/billing", pr_number: "x" })).status).toBe(400);
    expect((await post({ repo: "acme/payments-api", pr_number: 50 })).status).toBe(404);
    gh.getPullRequest.mockResolvedValue(null);
    const res = await post({ repo: "namacorp/billing", pr_number: 999 });
    expect(res.status).toBe(404);
    expect((await res.json()).error).toBe("pr_not_found");
    expect(enqueueScan).not.toHaveBeenCalled();
  });
});
