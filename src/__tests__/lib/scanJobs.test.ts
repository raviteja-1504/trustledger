/**
 * @jest-environment node
 *
 * The scan job ledger (lib/scanJobs.ts): duplicates do not queue twice, a job is claimed by one worker at a time, attempts are
 * bounded with a dead-letter state and a reason, and a failed job can be replayed from its original payload.
 */
import { fakeSupabase } from "../helpers/fakeSupabase";
import {
  MAX_ATTEMPTS, claimJob, failureReason, finishJob, jobKey, markNotQueued, queueOverview, registerJob, resetForReplay,
} from "@/lib/scanJobs";
import type { ScanJob } from "@/lib/queue";

const ORG = "org-1";
const job = (over: Partial<ScanJob> = {}): ScanJob => ({
  org_id: ORG, installation_id: 7, repo_full_name: "acme/app", pr_number: 4, head_sha: "abc123", branch: "main", pr_author: null,
  before_sha: null, action: "opened", check_run_id: 11, delivery_id: "d-1", ...over,
});

/** The in-memory database, plus the unique (org_id, dedupe_key) the real table has. */
function ledger(rows: Array<Record<string, unknown>> = []) {
  const db = fakeSupabase({ scan_jobs: rows });
  const real = db.client.from;
  let n = 0;
  (db.client as unknown as { from: unknown }).from = ((table: string) => {
    const q = (real as unknown as (t: string) => Record<string, unknown>)(table);
    if (table === "scan_jobs") {
      const insert = (q.insert as (p: Record<string, unknown>) => unknown).bind(q);
      q.insert = (payload: Record<string, unknown>) => {
        const clash = (db.tables.scan_jobs as Array<Record<string, unknown>>).some(r => r.org_id === payload.org_id && r.dedupe_key === payload.dedupe_key);
        if (clash) return { select: () => ({ single: async () => ({ data: null, error: { code: "23505", message: "duplicate key" } }) }) };
        return insert({ id: `job-${++n}`, created_at: new Date().toISOString(), updated_at: new Date().toISOString(), ...payload });   // the table's defaults
      };
    }
    return q;
  }) as unknown as typeof db.client.from;
  return db;
}
const rows = (db: ReturnType<typeof ledger>) => db.tables.scan_jobs as Array<Record<string, unknown>>;
const d = (db: ReturnType<typeof ledger>) => db.client as never;

describe("registerJob", () => {
  it("records a new job with its original payload", async () => {
    const db = ledger();
    const r = await registerJob(d(db), job());
    expect(r).toMatchObject({ id: "job-1", duplicate: false });
    expect(rows(db)[0]).toMatchObject({ status: "queued", attempts: 0, max_attempts: MAX_ATTEMPTS, repo_full_name: "acme/app", pr_number: 4, head_sha: "abc123", forced: false });
    expect((rows(db)[0].job as ScanJob).delivery_id).toBe("d-1");
  });

  it("the same webhook arriving twice does not queue a second job (it is still queued or running)", async () => {
    const db = ledger();
    await registerJob(d(db), job());
    expect(await registerJob(d(db), job({ delivery_id: "d-2", action: "synchronize" }))).toMatchObject({ id: "job-1", duplicate: true });
    expect(rows(db)).toHaveLength(1);
    rows(db)[0].status = "running";
    expect(await registerJob(d(db), job())).toMatchObject({ duplicate: true });
  });

  it("a job that has finished is queued again (a re-run check on an old commit must still work), with fresh attempts and the latest payload", async () => {
    const db = ledger();
    await registerJob(d(db), job());
    Object.assign(rows(db)[0], { status: "succeeded", attempts: 2, last_error: "old", scan_id: "s1", result: "scanned" });
    const again = await registerJob(d(db), job({ check_run_id: 99 }));
    expect(again).toMatchObject({ id: "job-1", duplicate: false });
    expect(rows(db)[0]).toMatchObject({ status: "queued", attempts: 0, last_error: null, scan_id: null });
    expect((rows(db)[0].job as ScanJob).check_run_id).toBe(99);
  });

  it("a job stuck queued or running for too long is presumed lost and queued again", async () => {
    const db = ledger();
    await registerJob(d(db), job());
    rows(db)[0].updated_at = new Date(Date.now() - 2 * 3600_000).toISOString();
    expect(await registerJob(d(db), job())).toMatchObject({ duplicate: false });
  });

  it("a different commit or PR is a different job; every forced rescan is its own job", async () => {
    const db = ledger();
    await registerJob(d(db), job());
    await registerJob(d(db), job({ head_sha: "def456" }));
    await registerJob(d(db), job({ pr_number: 5 }));
    await registerJob(d(db), job({ force: true, delivery_id: null }));
    await registerJob(d(db), job({ force: true, delivery_id: null }));
    expect(rows(db)).toHaveLength(5);
    expect(jobKey(job({ force: true, delivery_id: null }))).not.toBe(jobKey(job({ force: true, delivery_id: null })));
    expect(jobKey(job())).toBe("acme/app#4@abc123");
  });

  it("another organisation's identical job is separate", async () => {
    const db = ledger();
    await registerJob(d(db), job());
    expect(await registerJob(d(db), job({ org_id: "org-2" }))).toMatchObject({ duplicate: false });
  });

  it("no organisation, or no ledger table, means no ledger (the scan runs as before)", async () => {
    expect(await registerJob(d(ledger()), job({ org_id: null }))).toBeNull();
    const db = ledger();
    const real = db.client.from;
    db.client.from = ((t: string) => (t === "scan_jobs" ? { insert: () => ({ select: () => ({ single: async () => ({ data: null, error: { code: "42P01", message: 'relation "scan_jobs" does not exist' } }) }) }) } : real(t))) as typeof db.client.from;
    expect(await registerJob(d(db), job())).toBeNull();
  });
});

describe("claimJob", () => {
  const seeded = async (patch: Record<string, unknown> = {}) => { const db = ledger(); await registerJob(d(db), job()); Object.assign(rows(db)[0], patch); return db; };

  it("a queued job is claimed once: attempts go up and it is running", async () => {
    const db = await seeded();
    expect(await claimJob(d(db), ORG, "job-1")).toEqual({ claimed: true, attempts: 1, ledger: true });
    expect(rows(db)[0]).toMatchObject({ status: "running", attempts: 1 });
  });

  it("two deliveries at the same moment: exactly one gets the job", async () => {
    const db = await seeded();
    const [a, b] = await Promise.all([claimJob(d(db), ORG, "job-1"), claimJob(d(db), ORG, "job-1")]);
    expect([a.claimed, b.claimed].sort()).toEqual([false, true]);
    expect(rows(db)[0].attempts).toBe(1);
  });

  it("a job that is running, or done, is not taken again", async () => {
    const running = await seeded({ status: "running", started_at: new Date().toISOString() });
    expect((await claimJob(d(running), ORG, "job-1")).claimed).toBe(false);
    const done = await seeded({ status: "succeeded" });
    expect((await claimJob(d(done), ORG, "job-1")).claimed).toBe(false);
    const dead = await seeded({ status: "dead" });
    expect((await claimJob(d(dead), ORG, "job-1")).claimed).toBe(false);
  });

  it("a failed job is claimed by the queue's retry", async () => {
    const db = await seeded({ status: "failed", attempts: 1 });
    expect(await claimJob(d(db), ORG, "job-1")).toMatchObject({ claimed: true, attempts: 2 });
  });

  it("a claim abandoned by a killed worker is taken over after a while, not before", async () => {
    const fresh = await seeded({ status: "running", attempts: 1, started_at: new Date().toISOString() });
    expect((await claimJob(d(fresh), ORG, "job-1")).claimed).toBe(false);
    const stale = await seeded({ status: "running", attempts: 1, started_at: new Date(Date.now() - 30 * 60_000).toISOString() });
    expect(await claimJob(d(stale), ORG, "job-1")).toMatchObject({ claimed: true, attempts: 2 });
  });

  it("no row for the id, or another organisation's job, means no ledger: run as before, never block", async () => {
    const db = await seeded();
    expect(await claimJob(d(db), ORG, "nope")).toEqual({ claimed: true, attempts: 0, ledger: false });
    expect(await claimJob(d(db), "org-2", "job-1")).toMatchObject({ ledger: false });
  });
});

describe("finishJob", () => {
  const running = async (attempts: number) => { const db = ledger(); await registerJob(d(db), job()); Object.assign(rows(db)[0], { status: "running", attempts }); return db; };

  it("success: done, with how it ended and the scan", async () => {
    const db = await running(1);
    await finishJob(d(db), ORG, "job-1", 1, { ok: true, result: "scanned", scan_id: "s-9" });
    expect(rows(db)[0]).toMatchObject({ status: "succeeded", result: "scanned", scan_id: "s-9", last_error: null });
  });

  it("failure with attempts left: failed (will be retried), with the reason", async () => {
    const db = await running(2);
    await finishJob(d(db), ORG, "job-1", 2, { ok: false, error: "files_unreadable" });
    expect(rows(db)[0]).toMatchObject({ status: "failed", last_error: "files_unreadable" });
  });

  it("failure on the last attempt: dead (the dead-letter state), with the reason", async () => {
    const db = await running(MAX_ATTEMPTS);
    await finishJob(d(db), ORG, "job-1", MAX_ATTEMPTS, { ok: false, error: "scan_failed: boom" });
    expect(rows(db)[0]).toMatchObject({ status: "dead", last_error: "scan_failed: boom" });
  });

  it("only a running job is settled: a late, stale worker cannot overwrite a job that was re-queued", async () => {
    const db = await running(1);
    rows(db)[0].status = "queued";
    await finishJob(d(db), ORG, "job-1", 1, { ok: true, result: "scanned" });
    expect(rows(db)[0].status).toBe("queued");
  });
});

describe("a job that never reached a worker", () => {
  it("is marked failed with the reason so it is visible and replayable", async () => {
    const db = ledger(); await registerJob(d(db), job());
    await markNotQueued(d(db), ORG, "job-1", "no queue configured and INTERNAL_SECRET is not set");
    expect(rows(db)[0]).toMatchObject({ status: "failed", last_error: "no queue configured and INTERNAL_SECRET is not set" });
  });
});

describe("replay", () => {
  it("puts a dead job back in the queue with fresh attempts and returns the ORIGINAL job", async () => {
    const db = ledger(); await registerJob(d(db), job({ delivery_id: "orig-delivery", check_run_id: 77 }));
    Object.assign(rows(db)[0], { status: "dead", attempts: 4, last_error: "x" });
    const r = await resetForReplay(d(db), ORG, "job-1");
    expect(r).toMatchObject({ job: { job_id: "job-1", delivery_id: "orig-delivery", check_run_id: 77, head_sha: "abc123" } });
    expect(rows(db)[0]).toMatchObject({ status: "queued", attempts: 0, last_error: null });
  });

  it("only failed or dead jobs can be replayed (a running or finished one would only be a duplicate)", async () => {
    for (const status of ["queued", "running", "succeeded"]) {
      const db = ledger(); await registerJob(d(db), job()); rows(db)[0].status = status;
      expect(await resetForReplay(d(db), ORG, "job-1")).toEqual({ error: "not_replayable" });
    }
  });

  it("another organisation's job cannot be replayed", async () => {
    const db = ledger(); await registerJob(d(db), job()); rows(db)[0].status = "dead";
    expect(await resetForReplay(d(db), "org-2", "job-1")).toEqual({ error: "not_found" });
    expect(rows(db)[0].status).toBe("dead");
  });
});

describe("what the organisation sees", () => {
  it("counts the last 7 days, and lists failed, dead and stuck jobs with their reasons", async () => {
    const db = ledger();
    const mk = (i: number, status: string, extra: Record<string, unknown> = {}) => rows(db).push({
      id: `j${i}`, org_id: ORG, dedupe_key: `k${i}`, repo_full_name: "acme/app", pr_number: i, head_sha: "abc", action: "opened", forced: false,
      status, attempts: 1, max_attempts: 4, last_error: null, result: null, scan_id: null, created_at: new Date().toISOString(), updated_at: new Date().toISOString(), finished_at: null, ...extra,
    });
    mk(1, "succeeded"); mk(2, "succeeded"); mk(3, "failed", { last_error: "files_unreadable" }); mk(4, "dead", { last_error: "scan_failed: boom" });
    mk(5, "queued"); mk(6, "queued", { updated_at: new Date(Date.now() - 2 * 3600_000).toISOString() });    // stuck
    mk(7, "succeeded", { updated_at: new Date(Date.now() - 10 * 86400_000).toISOString() });                // older than a week
    mk(8, "dead", { org_id: "org-2", last_error: "someone else's" });
    const o = await queueOverview(d(db), ORG);
    expect(o.counts).toEqual({ queued: 2, running: 0, succeeded: 2, failed: 1, dead: 1 });
    expect(o.attention.map(j => j.id).sort()).toEqual(["j3", "j4", "j6"]);
    expect(JSON.stringify(o)).not.toContain("someone else's");
    expect(JSON.stringify(o)).not.toContain('"job"');                       // the stored payload is not sent to the browser
  });

  it("with no table yet it says so instead of failing", async () => {
    const db = fakeSupabase({}, { errorFor: () => ({ code: "42P01", message: 'relation "scan_jobs" does not exist' }) });
    expect(await queueOverview(db.client as never, ORG)).toMatchObject({ set_up: false, attention: [] });
  });
});

describe("failureReason", () => {
  it("is the worker's code and safe message, short; or the HTTP status when there is none", () => {
    expect(failureReason({ error: "scan_failed", message: "The scan could not be completed." }, 500)).toBe("scan_failed: The scan could not be completed.");
    expect(failureReason({ error: "files_unreadable", requested: 3 }, 503)).toBe("files_unreadable");
    expect(failureReason(null, 502)).toBe("http_502");
    expect(failureReason({ error: "x", message: "y".repeat(1000) }, 500).length).toBe(300);
  });
});
