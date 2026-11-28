/**
 * @jest-environment node
 *
 * The scan worker and the job ledger: a job is claimed once; a retry or duplicate that finds it already running or finished does
 * not run it again; a worker failure marks the job failed with the reason (dead after the last attempt); a clean run marks it done.
 */
import { NextRequest } from "next/server";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const chain: any = new Proxy({}, { get: (_t, k) => k === "then" ? (res: (v: unknown) => void) => res({ data: null, error: null }) : () => chain });
jest.mock("@/lib/supabase", () => ({ createServiceClient: () => chain }));
jest.mock("@/lib/opsEvents", () => ({ recordEvent: jest.fn(async () => {}) }));
jest.mock("@/lib/engineWarmup", () => ({ ensureTaintEngines: jest.fn(async () => ({ ready: true, ms: 0 })) }));

const claimJob = jest.fn();
const finishJob = jest.fn(async () => {});
jest.mock("@/lib/scanJobs", () => ({
  ...jest.requireActual("@/lib/scanJobs"),
  claimJob: (...a: unknown[]) => claimJob(...a),
  finishJob: (...a: unknown[]) => (finishJob as unknown as (...x: unknown[]) => unknown)(...a),
}));

const prFiles = jest.fn();
const fetchFileContents = jest.fn();
jest.mock("@/lib/github", () => ({
  ...jest.requireActual("@/lib/github"),
  getInstallationToken: jest.fn(async () => ({ token: "t" })),
  getPRHeadSha: jest.fn(async () => "abc"),
  getPRFiles: (...a: unknown[]) => prFiles(...a),
  fetchFileContents: (...a: unknown[]) => fetchFileContents(...a),
  updateCheckRun: jest.fn(async () => {}),
}));

import { POST } from "@/app/api/scan-worker/route";

const JOB = { org_id: "org-1", job_id: "job-1", installation_id: 1, repo_full_name: "acme/app", pr_number: 1, head_sha: "abc", branch: "main",
  pr_author: null, before_sha: null, action: "opened", check_run_id: 5, delivery_id: null };
const run = (job: Record<string, unknown> = JOB) => POST(new NextRequest(new URL("https://app.example/api/scan-worker"), {
  method: "POST", headers: { "x-internal-secret": "dev" }, body: JSON.stringify(job),
}));
const SRC = "export const add = (a, b) => a + b;\n";

const realFetch = global.fetch;
beforeEach(() => {
  delete process.env.VERCEL_ENV; delete process.env.INTERNAL_SECRET;
  jest.clearAllMocks();
  claimJob.mockResolvedValue({ claimed: true, attempts: 1, ledger: true });
  global.fetch = (async () => new Response("", { status: 404 })) as typeof fetch;
  prFiles.mockResolvedValue([{ filename: "src/a.js", status: "added", additions: 1, deletions: 0 }]);
});
afterEach(() => { global.fetch = realFetch; });

it("claims the job in the ledger before doing any work, and marks it done afterwards", async () => {
  fetchFileContents.mockResolvedValue([{ path: "src/a.js", content: SRC }]);
  const res = await run();
  expect(res.status).toBe(200);
  expect(claimJob.mock.calls[0].slice(1)).toEqual(["org-1", "job-1"]);
  expect(finishJob.mock.calls[0].slice(1)).toEqual(["org-1", "job-1", 1, expect.objectContaining({ ok: true, result: "scanned" })]);
});

it("a duplicate delivery that finds the job already running or finished does no work at all", async () => {
  claimJob.mockResolvedValue({ claimed: false, attempts: 1, ledger: true });
  const res = await run();
  expect(res.status).toBe(200);
  expect(await res.json()).toMatchObject({ skipped: true, reason: "job_already_handled" });
  expect(prFiles).not.toHaveBeenCalled();
  expect(fetchFileContents).not.toHaveBeenCalled();
  expect(finishJob).not.toHaveBeenCalled();                     // it never owned the job, so it must not rewrite its outcome
});

it("a failed run is marked failed with the reason, and the worker still answers 5xx so the queue retries it", async () => {
  fetchFileContents.mockResolvedValue([]);                       // nothing readable: the worker's 503
  const res = await run();
  expect(res.status).toBe(503);
  expect(finishJob.mock.calls[0].slice(1)).toEqual(["org-1", "job-1", 1, expect.objectContaining({ ok: false, error: expect.stringContaining("files_unreadable") })]);
});

it("the attempt number reaches the ledger, so the last attempt can make the job dead", async () => {
  claimJob.mockResolvedValue({ claimed: true, attempts: 4, ledger: true });
  fetchFileContents.mockResolvedValue([]);
  await run();
  expect(finishJob.mock.calls[0].slice(1)).toEqual(["org-1", "job-1", 4, expect.objectContaining({ ok: false })]);
});

it("a job with no ledger row (or no ledger) runs exactly as before and writes nothing to it", async () => {
  claimJob.mockResolvedValue({ claimed: true, attempts: 0, ledger: false });
  fetchFileContents.mockResolvedValue([{ path: "src/a.js", content: SRC }]);
  expect((await run()).status).toBe(200);
  expect(finishJob).not.toHaveBeenCalled();
});

it("a job queued before the ledger existed (no job_id) is not claimed at all", async () => {
  fetchFileContents.mockResolvedValue([{ path: "src/a.js", content: SRC }]);
  const { job_id: _unused, ...legacy } = JOB; void _unused;
  expect((await run(legacy)).status).toBe(200);
  expect(claimJob).not.toHaveBeenCalled();
  expect(finishJob).not.toHaveBeenCalled();
});
