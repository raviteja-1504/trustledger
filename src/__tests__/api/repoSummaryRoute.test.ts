/**
 * @jest-environment node
 *
 * GET /api/repos/summary: one repository's real rows, scoped to the org (and a developer's own PRs), paged.
 */
import { NextRequest } from "next/server";
import { fakeSupabase } from "../helpers/fakeSupabase";

let db: ReturnType<typeof fakeSupabase>;
let auth: Record<string, unknown> = { org_id: "org-1", role: "admin", user_id: "u1" };
jest.mock("@/lib/supabase", () => ({ createServiceClient: () => db.client }));
jest.mock("@/app/api/_middleware", () => ({ verifyApiKey: async () => auth }));

import { GET } from "@/app/api/repos/summary/route";

const get = async (repo = "o/api") => {
  const res = await GET(new NextRequest(new URL(`/api/repos/summary?repo=${encodeURIComponent(repo)}`, "https://app.example")));
  return { status: res.status, body: await res.json() as Record<string, any> };   // eslint-disable-line @typescript-eslint/no-explicit-any
};
const scan = (id: string, pr: number, at: string, author = "dev1", o: Record<string, unknown> = {}) =>
  ({ id, org_id: "org-1", repo_full_name: "o/api", pr_number: pr, commit_sha: `${id}0000000`, branch: "b", overall_risk: "HIGH", total_ai_percentage: 0.5, file_count: 4, created_at: at, triggered_by: "webhook", pr_author: author, ...o });
const file = (scan_id: string, path: string, risk: string) => ({ org_id: "org-1", scan_id, file_path: path, language: "ts", risk_score: risk, ai_percentage: 0.5, risk_indicators: [] });

function seed(o: { scans?: unknown[]; files?: unknown[] } = {}, opts: Parameters<typeof fakeSupabase>[1] = {}) {
  db = fakeSupabase({
    repositories: [{ org_id: "org-1", repo_full_name: "o/api", default_branch: "main", is_active: true, created_at: "2026-08-01T00:00:00Z" }],
    org_members: [{ org_id: "org-1", user_id: "u-dev", github_login: "dev1" }],
    scans: (o.scans ?? [scan("s1", 7, "2026-10-01T00:00:00Z"), scan("s2", 8, "2026-10-05T00:00:00Z", "dev2"), { ...scan("x", 1, "2026-10-09T00:00:00Z"), org_id: "org-2" }]) as Record<string, unknown>[],
    scan_files: (o.files ?? [file("s2", "a.ts", "CRITICAL"), file("s2", "b.ts", "LOW"), file("s1", "c.ts", "HIGH")]) as Record<string, unknown>[],
    attestations: [{ org_id: "org-1", scan_id: "s2", file_path: "a.ts", reviewer_email: "rev@x", created_at: "2026-10-06T00:00:00Z" }],
    violations: [], violation_overrides: [],
    secret_findings: [{ org_id: "org-1", scan_id: "s2", status: "open" }, { org_id: "org-1", scan_id: "s2", status: "resolved" }],
  }, opts);
}

beforeEach(() => { auth = { org_id: "org-1", role: "admin", user_id: "u1" }; seed(); });

describe("GET /api/repos/summary", () => {
  it("the repo record, its latest scan's files with sign-off status, PRs and history", async () => {
    const { status, body } = await get();
    expect(status).toBe(200);
    expect(body.repo).toEqual({ name: "o/api", default_branch: "main", is_active: true, connected_at: "2026-08-01T00:00:00Z" });
    expect(body.latest_scan.scan_id).toBe("s2");
    expect(body.files.map((f: { file_path: string; status: string }) => [f.file_path, f.status])).toEqual([["a.ts", "attested"], ["b.ts", "not_required"]]);
    expect(body.prs.map((p: { pr_number: number }) => p.pr_number)).toEqual([8, 7]);
    expect(body.scans).toHaveLength(2);                 // not the other org's scan
    expect(body.open_secrets).toBe(1);
    expect(body.scope).toBe("org");
  });

  it("developers see their own pull requests only", async () => {
    auth = { org_id: "org-1", role: "developer", user_id: "u-dev" };
    const { body } = await get();
    expect(body.scope).toBe("own");
    expect(body.scans.map((s: { scan_id: string }) => s.scan_id)).toEqual(["s1"]);
    expect(body.latest_scan.scan_id).toBe("s1");
  });

  it("bad or unknown repositories are refused", async () => {
    expect((await get("nope")).status).toBe(400);
    expect((await get("o/unknown")).status).toBe(404);
  });

  it("reads past the 1000-row cap", async () => {
    const files = Array.from({ length: 1300 }, (_, i) => file("s9", `f${i}.ts`, "HIGH"));
    seed({ scans: [scan("s9", 9, "2026-10-10T00:00:00Z")], files }, { maxRows: 1000 });
    const { body } = await get();
    expect(body.files).toHaveLength(1300);
    expect(body.signoff.required).toBe(1300);
    expect(body.prs[0].high_crit).toBe(1300);
  });
});
