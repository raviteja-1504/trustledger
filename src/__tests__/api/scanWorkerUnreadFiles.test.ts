/**
 * @jest-environment node
 *
 * The scan worker must never pass a PR whose files it couldn't read. A 2,800-file PR whose every read failed
 * (GitHub rate limit) completed as "No scannable files" / neutral -- an unscanned PR could merge.
 */
import { NextRequest } from "next/server";

// Any query resolves to "no rows": no earlier scan of this commit, nothing to inherit.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const chain: any = new Proxy({}, { get: (_t, k) => k === "then" ? (res: (v: unknown) => void) => res({ data: null, error: null }) : () => chain });
jest.mock("@/lib/supabase", () => ({ createServiceClient: () => chain }));
jest.mock("@/lib/opsEvents", () => ({ recordEvent: jest.fn(async () => {}) }));
jest.mock("@/lib/engineWarmup", () => ({ ensureTaintEngines: jest.fn(async () => ({ ready: true, ms: 0 })) }));

const prFiles = jest.fn();
const fetchFileContents = jest.fn();
const updateCheckRun = jest.fn(async () => {});
jest.mock("@/lib/github", () => ({
  ...jest.requireActual("@/lib/github"),
  getInstallationToken: jest.fn(async () => ({ token: "t" })),
  getPRHeadSha: jest.fn(async () => "abc"),
  getPRFiles: (...a: unknown[]) => prFiles(...a),
  fetchFileContents: (...a: unknown[]) => fetchFileContents(...a),
  updateCheckRun: (...a: unknown[]) => (updateCheckRun as (...x: unknown[]) => Promise<void>)(...a),
}));

import { POST } from "@/app/api/scan-worker/route";

const JOB = { org_id: null, installation_id: 1, repo_full_name: "acme/app", pr_number: 1, head_sha: "abc", branch: "main",
  pr_author: null, before_sha: null, action: "opened", check_run_id: 5, delivery_id: null };
const run = () => POST(new NextRequest(new URL("https://app.example/api/scan-worker"), {
  method: "POST", headers: { "x-internal-secret": "dev" }, body: JSON.stringify(JOB),
}));
const finalCheck = () => (updateCheckRun.mock.calls.at(-1) as unknown[])[4] as { conclusion: string; output: { title: string; summary: string } };

const realFetch = global.fetch;
beforeEach(() => {
  delete process.env.VERCEL_ENV; delete process.env.INTERNAL_SECRET;
  updateCheckRun.mockClear();
  global.fetch = (async () => new Response("", { status: 404 })) as typeof fetch;   // the PR-commits lookup
  prFiles.mockResolvedValue([
    { filename: "src/a.js", status: "added", additions: 1, deletions: 0 },
    { filename: "src/b.js", status: "added", additions: 1, deletions: 0 },
  ]);
});
afterEach(() => { global.fetch = realFetch; });

const SRC = "export const add = (a, b) => a + b;\n";

it("no file readable: a failing check (not 'No scannable files'), and a retryable response", async () => {
  fetchFileContents.mockResolvedValue([]);
  const res = await run();
  expect(res.status).toBe(503);
  expect(finalCheck().conclusion).toBe("failure");
  expect(finalCheck().output.title).toBe("Couldn't read this PR's files");
  expect(finalCheck().output.summary).toMatch(/couldn't read 2 of 2 files/);
});

it("some files unread: the check can't pass, and says so", async () => {
  fetchFileContents.mockResolvedValue([{ path: "src/a.js", content: SRC }]);
  const res = await run();
  expect(res.status).toBe(200);
  expect(finalCheck().conclusion).toBe("action_required");
  expect(finalCheck().output.summary).toMatch(/Not every file was scanned[\s\S]*couldn't read 1 of 2 files/);
});

it("every file read and clean: passes", async () => {
  fetchFileContents.mockResolvedValue([{ path: "src/a.js", content: SRC }, { path: "src/b.js", content: SRC }]);
  await run();
  expect(finalCheck().conclusion).toBe("success");
  expect(finalCheck().output.summary).not.toMatch(/Not every file was scanned/);
});

it("genuinely nothing to scan is still 'No scannable files'", async () => {
  prFiles.mockResolvedValue([{ filename: "docs/logo.png", status: "added", additions: 0, deletions: 0 }]);
  fetchFileContents.mockResolvedValue([]);
  const res = await run();
  expect(res.status).toBe(200);
  expect(finalCheck().output.title).toBe("No scannable files");
});
