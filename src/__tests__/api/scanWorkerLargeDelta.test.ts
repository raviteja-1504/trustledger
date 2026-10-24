/**
 * @jest-environment node
 *
 * A push to a 1,242-file pull request rescans only the changed files and carries the rest over from the previous
 * scan. That carry-over read the previous scan's files with one plain select, which PostgREST cuts at 1000 rows:
 * every unchanged file past the first 1000 silently left the new scan. The fake database truncates the same way.
 */
import { NextRequest } from "next/server";
import { fakeSupabase } from "../helpers/fakeSupabase";

let db = fakeSupabase({});
jest.mock("@/lib/supabase", () => ({ createServiceClient: () => db.client }));
jest.mock("@/lib/opsEvents", () => ({ recordEvent: jest.fn(async () => {}) }));
jest.mock("@/lib/engineWarmup", () => ({ ensureTaintEngines: jest.fn(async () => ({ ready: true, ms: 0 })) }));
jest.mock("@/lib/audit", () => ({ writeAuditLog: async () => {} }));
jest.mock("@/lib/autoIncidents", () => ({ syncAutoIncidents: async () => {} }));
jest.mock("@/lib/policyAlerts", () => ({ ensurePolicyAlerts: async () => {} }));
jest.mock("@/lib/cache", () => {
  const actual = jest.requireActual("@/lib/cache");
  return { ...actual, cacheDel: async () => {}, invalidateSecretsCache: async () => {}, invalidateViolationsCache: async () => {} };
});

const N = 1242;
const path = (i: number) => `testcode/BenchmarkTest${String(i).padStart(5, "0")}.py`;
const CHANGED = path(0);
const updateCheckRun = jest.fn(async () => {});
jest.mock("@/lib/github", () => ({
  ...jest.requireActual("@/lib/github"),
  getInstallationToken: jest.fn(async () => ({ token: "t" })),
  getPRHeadSha: jest.fn(async () => "new-sha"),
  getPRFiles: jest.fn(async () => Array.from({ length: N }, (_, i) => ({ filename: path(i), status: "modified", additions: 1, deletions: 0 }))),
  getCommitDiff: jest.fn(async () => new Set([CHANGED])),
  fetchFileContents: jest.fn(async () => [{ path: CHANGED, content: "def f(x):\n    return x + 1\n" }]),
  updateCheckRun: (...a: unknown[]) => (updateCheckRun as (...x: unknown[]) => Promise<void>)(...a),
}));

import { POST } from "@/app/api/scan-worker/route";

const PREV = "22222222-2222-4222-8222-222222222222";
const JOB = { org_id: "org-1", installation_id: 1, repo_full_name: "acme/bench", pr_number: 1, head_sha: "new-sha", branch: "main",
  pr_author: null, before_sha: "old-sha", action: "synchronize", check_run_id: null, delivery_id: null };

const realFetch = global.fetch;
beforeEach(() => {
  delete process.env.VERCEL_ENV; delete process.env.INTERNAL_SECRET;
  global.fetch = (async () => new Response("", { status: 404 })) as typeof fetch;   // the PR-commits lookup
  db = fakeSupabase({
    scans: [{ id: PREV, org_id: "org-1", repo_full_name: "acme/bench", pr_number: 1, commit_sha: "old-sha", created_at: "2026-10-23T09:00:00Z" }],
    scan_files: Array.from({ length: N }, (_, i) => ({
      id: `p-${i}`, scan_id: PREV, org_id: "org-1", file_path: path(i), language: "python", ai_percentage: 0, risk_score: "LOW",
      risk_indicators: [], content_hash: `h${i}`, line_count: 2, content: null, attribution: null,
      indicators: [{ id: "weak-crypto", label: "Weak Cryptographic Hash", severity: "high", line: 1, fingerprint: `fp-${i}` }],
    })),
    repositories: [], attestations: [], violations: [], organizations: [{ id: "org-1", block_on_critical: true, block_on_high: true }],
  }, { maxRows: 1000 });
});
afterEach(() => { global.fetch = realFetch; });

it("a one-file push to a 1,242-file PR keeps every unchanged file in the new scan", async () => {
  const res = await POST(new NextRequest(new URL("https://app.example/api/scan-worker"), {
    method: "POST", headers: { "x-internal-secret": "dev" }, body: JSON.stringify(JOB),
  }));
  const body = await res.json() as { ok: boolean; scan_id: string; files_scanned: number; files_inherited: number };
  expect(body).toMatchObject({ ok: true, files_scanned: 1, files_inherited: N - 1 });
  const rows = db.writes.filter(w => w.table === "scan_files" && w.op === "insert")
    .flatMap(w => w.payload as Array<{ scan_id: string; file_path: string }>).filter(r => r.scan_id === body.scan_id);
  expect(rows.length).toBe(N);
  expect(new Set(rows.map(r => r.file_path)).size).toBe(N);
});

it("the check run's 'since the last push' compares with the whole previous scan", async () => {
  updateCheckRun.mockClear();
  await POST(new NextRequest(new URL("https://app.example/api/scan-worker"), {
    method: "POST", headers: { "x-internal-secret": "dev" }, body: JSON.stringify({ ...JOB, check_run_id: 5 }),
  }));
  const summary = ((updateCheckRun.mock.calls.at(-1) as unknown[])[4] as { output: { summary: string } }).output.summary;
  // the changed file's finding is gone; the 1,241 carried-over findings were all there before (cut at 1000 rows,
  // the last 242 of them read as new)
  expect(summary).toContain("✅ No new security findings.");
  expect(summary).toContain("✅ **1 fixed** since the last push.");
});
