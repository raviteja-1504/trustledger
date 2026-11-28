/**
 * @jest-environment node
 *
 * enqueueScan records the job in the ledger first: the same job is not queued twice, the queued job carries its ledger id, a job
 * that never reaches a worker is marked failed with the reason, and with no ledger at all the scan is queued exactly as before.
 */
import { fakeSupabase } from "../helpers/fakeSupabase";

let db: ReturnType<typeof fakeSupabase>;
let dbDown = false;
const publishJSON = jest.fn(async (_o: unknown) => ({ messageId: "m" }));

jest.mock("@/lib/supabase", () => ({
  createServiceClient: () => {
    if (dbDown) throw new Error("supabase_not_configured");
    const client = db.client as unknown as { from: (t: string) => Record<string, unknown> };
    return {
      ...client,
      from: (table: string) => {
        const q = client.from(table);
        if (table === "scan_jobs") {                       // the table's unique (org_id, dedupe_key) and defaults
          const insert = (q.insert as (p: Record<string, unknown>) => unknown).bind(q);
          let n = (db.tables.scan_jobs as unknown[]).length;
          q.insert = (p: Record<string, unknown>) => {
            if ((db.tables.scan_jobs as Array<Record<string, unknown>>).some(r => r.org_id === p.org_id && r.dedupe_key === p.dedupe_key)) {
              return { select: () => ({ single: async () => ({ data: null, error: { code: "23505", message: "duplicate" } }) }) };
            }
            return insert({ id: `job-${++n}`, updated_at: new Date().toISOString(), ...p });
          };
        }
        return q;
      },
    };
  },
}));
jest.mock("@upstash/qstash", () => ({ Client: class { publishJSON(o: unknown) { return publishJSON(o); } } }));
jest.mock("@/lib/alertDelivery", () => ({ sendSlackAlert: jest.fn(async () => {}) }));

import { enqueueScan, requeueJob, ScanNotQueuedError, type ScanJob } from "@/lib/queue";

const JOB: ScanJob = { org_id: "org-1", installation_id: 7, repo_full_name: "acme/app", pr_number: 4, head_sha: "abc", branch: "main", pr_author: null, before_sha: null, action: "opened", check_run_id: 5, delivery_id: "d-1" };
const jobs = () => db.tables.scan_jobs as Array<Record<string, unknown>>;
const ENV = ["QSTASH_TOKEN", "NEXT_PUBLIC_APP_URL", "INTERNAL_SECRET", "VERCEL_ENV"] as const;
const saved: Record<string, string | undefined> = {};
const realFetch = global.fetch;

beforeEach(() => {
  for (const k of ENV) saved[k] = process.env[k];
  process.env.QSTASH_TOKEN = "tok"; process.env.NEXT_PUBLIC_APP_URL = "https://app.example"; process.env.INTERNAL_SECRET = "secret";
  dbDown = false; publishJSON.mockClear(); publishJSON.mockResolvedValue({ messageId: "m" });
  db = fakeSupabase({ scan_jobs: [] });
  jest.spyOn(console, "log").mockImplementation(() => {}); jest.spyOn(console, "error").mockImplementation(() => {});
});
afterEach(() => { for (const k of ENV) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; } global.fetch = realFetch; jest.restoreAllMocks(); });

const body = () => (publishJSON.mock.calls[0][0] as { body: ScanJob }).body;

it("records the job, then queues it carrying its ledger id", async () => {
  await enqueueScan(JOB);
  expect(jobs()).toHaveLength(1);
  expect(jobs()[0]).toMatchObject({ status: "queued", repo_full_name: "acme/app", head_sha: "abc" });
  expect(publishJSON).toHaveBeenCalledTimes(1);
  expect(body()).toMatchObject({ job_id: "job-1", delivery_id: "d-1", head_sha: "abc" });
});

it("the same job arriving again while it is queued or running is not queued a second time", async () => {
  await enqueueScan(JOB);
  await enqueueScan({ ...JOB, action: "synchronize", delivery_id: "d-2" });
  expect(publishJSON).toHaveBeenCalledTimes(1);
  expect(jobs()).toHaveLength(1);
});

it("a finished job is queued again (a re-run check on an old commit still works)", async () => {
  await enqueueScan(JOB);
  jobs()[0].status = "succeeded";
  await enqueueScan(JOB);
  expect(publishJSON).toHaveBeenCalledTimes(2);
  expect(jobs()[0].status).toBe("queued");
});

it("a job that reaches no worker (the queue fails and the direct call cannot connect) is marked failed with the reason, and the caller still hears about it", async () => {
  publishJSON.mockRejectedValue(new Error("qstash down"));
  global.fetch = (async () => { throw new Error("connect ECONNREFUSED"); }) as typeof fetch;
  await expect(enqueueScan(JOB)).rejects.toThrow(/ECONNREFUSED/);
  expect(jobs()[0]).toMatchObject({ status: "failed", last_error: "connect ECONNREFUSED" });
});

it("with no queue and no internal secret, the job is marked failed (nothing could run it)", async () => {
  delete process.env.QSTASH_TOKEN; delete process.env.INTERNAL_SECRET; process.env.VERCEL_ENV = "production";
  await expect(enqueueScan(JOB)).rejects.toBeInstanceOf(ScanNotQueuedError);
  expect(jobs()[0]).toMatchObject({ status: "failed", last_error: "no queue configured and INTERNAL_SECRET is not set" });
});

it("when the worker itself ran and failed, the worker (not the queue) owns the job's outcome", async () => {
  publishJSON.mockRejectedValue(new Error("qstash down"));
  global.fetch = (async () => new Response("{}", { status: 503 })) as typeof fetch;
  await expect(enqueueScan(JOB)).rejects.toMatchObject({ workerResponded: true });
  expect(jobs()[0].status).toBe("queued");                       // untouched here: the worker settles it
});

it("with no ledger (no database), the scan is queued exactly as before", async () => {
  dbDown = true;
  await enqueueScan(JOB);
  expect(publishJSON).toHaveBeenCalledTimes(1);
  expect(body().job_id).toBeUndefined();
});

it("with no ledger table, the scan is queued exactly as before", async () => {
  const real = db.client.from;
  (db.client as unknown as { from: unknown }).from = ((t: string) => (t === "scan_jobs"
    ? { insert: () => ({ select: () => ({ single: async () => ({ data: null, error: { code: "42P01", message: 'relation "scan_jobs" does not exist' } }) }) }) }
    : (real as unknown as (x: string) => unknown)(t)));
  await enqueueScan(JOB);
  expect(publishJSON).toHaveBeenCalledTimes(1);
  expect(body().job_id).toBeUndefined();
});

it("a job with no organisation is not recorded and still queued", async () => {
  await enqueueScan({ ...JOB, org_id: null });
  expect(jobs()).toHaveLength(0);
  expect(publishJSON).toHaveBeenCalledTimes(1);
});

it("requeueJob (a replay) queues the stored job as it is, without registering it again", async () => {
  await enqueueScan(JOB);
  publishJSON.mockClear();
  await requeueJob({ ...JOB, job_id: "job-1" });
  expect(publishJSON).toHaveBeenCalledTimes(1);
  expect(jobs()).toHaveLength(1);
  expect(body().job_id).toBe("job-1");
});
