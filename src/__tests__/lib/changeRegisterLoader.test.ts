/**
 * @jest-environment node
 *
 * Loading the change register (lib/changeRegisterLoader.ts): merged pull requests and reviews from GitHub through the
 * installation that owns each repository, scans / HIGH-CRITICAL files / sign-offs from the database. A repository
 * GitHub won't list, or reviews that can't be read, make the population incomplete (stated, never shown as
 * approved); a failed database read fails the register rather than showing every change as unscanned.
 */
const ghCalls: string[] = [];
let failPullsFor: string | null = null;
let failReviewsFor: number | null = null;
jest.mock("@/lib/github", () => ({
  ...jest.requireActual("@/lib/github"),
  getInstallationToken: jest.fn(async (id: number) => ({ token: `tok-${id}` })),
  listMergedPullRequests: jest.fn(async (token: string, owner: string, repo: string) => {
    ghCalls.push(`pulls ${owner}/${repo} ${token}`);
    if (failPullsFor === `${owner}/${repo}`) throw new Error("GitHub GET closed pulls failed: 404");
    if (repo !== "api") return { pulls: [], truncated: false };
    return { pulls: [
      { number: 1, title: "Add login", author: "alice", merged_at: "2026-10-11T12:00:00Z", merged_by: "carol", head_sha: "sha1", url: "u1" },
      { number: 2, title: "Fix pay", author: "alice", merged_at: "2026-10-12T12:00:00Z", merged_by: "carol", head_sha: "sha2", url: "u2" },
    ], truncated: false };
  }),
  readBranchProtection: jest.fn(async (token: string, owner: string, repo: string) => {
    ghCalls.push(`protection ${owner}/${repo} ${token}`);
    return { repo: `${owner}/${repo}`, branch: "main", protected: true, rules: [{ type: "pull_request", parameters: { required_approving_review_count: 1 } }], classic: "none" };
  }),
  listPullReviews: jest.fn(async (token: string, owner: string, repo: string, n: number) => {
    ghCalls.push(`reviews ${owner}/${repo}#${n} ${token}`);
    if (failReviewsFor === n) throw new Error("GitHub GET reviews failed: 502");
    return [{ reviewer: "bob", state: "APPROVED", submitted_at: `2026-10-1${n}T10:00:00Z`, commit_id: `sha${n}` }];
  }),
}));

import { loadChangeRegister } from "@/lib/changeRegisterLoader";

type Row = Record<string, unknown>;
let tables: Record<string, Row[]>;
let failTable: string | null;

/** A small PostgREST stand-in: eq / in / gte / lte filters and range paging over in-memory rows. */
function fakeDb() {
  return {
    from(table: string) {
      const filters: Array<(r: Row) => boolean> = [];
      let range: [number, number] | null = null;
      const q = {
        select: () => q, order: () => q,
        eq: (c: string, v: unknown) => { filters.push(r => r[c] === v); return q; },
        not: (c: string, op: string, v: unknown) => { if (op === "is" && v === null) filters.push(r => r[c] != null); return q; },
        in: (c: string, vs: unknown[]) => { filters.push(r => vs.includes(r[c])); return q; },
        gte: (c: string, v: string) => { filters.push(r => String(r[c]) >= v); return q; },
        lte: (c: string, v: string) => { filters.push(r => String(r[c]) <= v); return q; },
        range: (f: number, t: number) => { range = [f, t]; return q; },
        limit: (n: number) => { range = [0, n - 1]; return q; },
        then: (res: (v: unknown) => unknown) => {
          if (failTable === table) return Promise.resolve({ data: null, error: { message: "boom" } }).then(res);
          const rows = (tables[table] ?? []).filter(r => filters.every(f => f(r)));
          return Promise.resolve({ data: range ? rows.slice(range[0], range[1] + 1) : rows, error: null }).then(res);
        },
      };
      return q;
    },
  };
}

beforeEach(() => {
  ghCalls.length = 0; failPullsFor = null; failReviewsFor = null; failTable = null;
  tables = {
    repositories: [
      { org_id: "org-1", repo_full_name: "acme/api", is_active: true },
      { org_id: "org-1", repo_full_name: "acme/web", is_active: true },
      { org_id: "org-2", repo_full_name: "other/secret", is_active: true },
    ],
    github_installations: [{ org_id: "org-1", installation_id: 7, github_org: "ACME" }],
    scans: [
      { id: "s1", org_id: "org-1", repo_full_name: "acme/api", pr_number: 1, commit_sha: "sha1", created_at: "2026-10-11T09:00:00Z", overall_risk: "HIGH" },
      { id: "sx", org_id: "org-2", repo_full_name: "acme/api", pr_number: 2, commit_sha: "sha2", created_at: "2026-10-12T09:00:00Z", overall_risk: "LOW" },
    ],
    scan_files: [{ org_id: "org-1", scan_id: "s1", file_path: "auth.ts", risk_score: "HIGH" }],
    attestations: [{ org_id: "org-1", scan_id: "s1", file_path: "auth.ts", reviewer_github: "bob", created_at: "2026-10-11T11:00:00Z" }],
  };
});

const load = () => loadChangeRegister(fakeDb() as never, "org-1", "2026-10-01T00:00:00.000Z", "2026-10-31T23:59:59.000Z");

describe("loadChangeRegister", () => {
  it("reads every active repository of the organisation through its installation and builds the register", async () => {
    const reg = await load();
    expect(ghCalls.filter(c => c.startsWith("pulls"))).toEqual(["pulls acme/api tok-7", "pulls acme/web tok-7"]);
    expect(reg.rows.map(r => [r.number, r.exceptions])).toEqual([[1, []], [2, ["not_scanned"]]]);
    expect(reg.rows[0]).toMatchObject({ scan: { scan_id: "s1" }, high_risk_files: 1, high_risk_signed_off: 1 });
    expect(reg.complete).toBe(true);
  });

  it("with several installations, each repository is read through the one on its own GitHub account", async () => {
    tables.github_installations = [
      { org_id: "org-1", installation_id: 3, github_org: "someone-else" },
      { org_id: "org-1", installation_id: 7, github_org: "acme" },
    ];
    await load();
    expect(ghCalls.filter(c => c.startsWith("pulls"))).toEqual(["pulls acme/api tok-7", "pulls acme/web tok-7"]);
  });

  it("another organisation's scan of the same pull request is not evidence", async () => {
    const reg = await load();
    expect(reg.rows[1].scan).toBeNull();
  });

  it("a repository GitHub won't list is recorded as not read, and the population is incomplete", async () => {
    failPullsFor = "acme/web";
    const reg = await load();
    expect(reg.coverage.find(c => c.repo === "acme/web")).toMatchObject({ read: false, reason: expect.stringContaining("404") });
    expect(reg.complete).toBe(false);
  });

  it("no installation row: a repository whose scans came through the App is read through that installation", async () => {
    tables.github_installations = [];
    tables.scans.push({ id: "s9", org_id: "org-1", repo_full_name: "acme/web", pr_number: 4, commit_sha: "x", created_at: "2026-09-01T00:00:00Z", overall_risk: "LOW", installation_id: 42 });
    const reg = await load();
    expect(ghCalls.filter(c => c.startsWith("pulls"))).toEqual(["pulls acme/web tok-42"]);
    expect(reg.coverage.find(c => c.repo === "acme/web")).toMatchObject({ read: true });
    expect(reg.coverage.find(c => c.repo === "acme/api")).toMatchObject({ read: false, reason: expect.stringContaining("not installed") });
  });

  it("no installation: every repository is not read, with the reason", async () => {
    tables.github_installations = [];
    const reg = await load();
    expect(reg.coverage.every(c => !c.read && /not installed/.test(c.reason ?? ""))).toBe(true);
    expect(reg.complete).toBe(false);
    // no snapshot is invented: each repository's protection is Unknown, with the same reason
    expect(reg.branch_protection!.map(p => [p.repo, p.approvals_required, p.limits[0]])).toEqual([
      ["acme/api", null, expect.stringContaining("not installed")], ["acme/web", null, expect.stringContaining("not installed")],
    ]);
  });

  it("snapshots each repository's branch protection through the same installation", async () => {
    const reg = await load();
    expect(ghCalls.filter(c => c.startsWith("protection")).sort()).toEqual(["protection acme/api tok-7", "protection acme/web tok-7"]);
    expect(reg.branch_protection!.map(p => [p.repo, p.approvals_required])).toEqual([["acme/api", 1], ["acme/web", 1]]);
  });

  it("reviews that couldn't be read leave the pull request unapproved and mark the repository incomplete", async () => {
    failReviewsFor = 2;
    const reg = await load();
    expect(reg.rows[1].exceptions).toContain("no_approval");
    expect(reg.coverage.find(c => c.repo === "acme/api")).toMatchObject({ truncated: true, reason: expect.stringContaining("1 pull request's reviews") });
    expect(reg.complete).toBe(false);
  });

  it.each(["repositories", "scans", "scan_files", "attestations"])("a failed read of %s fails the register", async t => {
    failTable = t;
    await expect(load()).rejects.toThrow(/change register/);
  });
});
