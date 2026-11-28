/**
 * The scan job ledger (migration 20261129_scan_jobs.sql): idempotent job registration, an atomic claim so a job runs once at a
 * time, bounded attempts, a dead-letter state with a reason, and replay of the original payload.
 *
 * Everything here is best-effort around scanning: if the table is missing or the database errors, the functions answer "no ledger"
 * and the scan carries on exactly as it did before the ledger existed. The ledger never decides whether a scan runs unless it can
 * positively say another delivery of the same job is already running or queued.
 */
import crypto from "crypto";
import type { SupabaseClient } from "@supabase/supabase-js";
import type { ScanJob } from "@/lib/queue";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Db = SupabaseClient<any>;

export const MAX_ATTEMPTS = 4;                 // the first run plus QStash's 3 retries (lib/queue.ts)
const IN_FLIGHT_FRESH_MS = 30 * 60_000;        // a queued/running job older than this is presumed lost and may be re-queued
const RUNNING_STALE_MS = 15 * 60_000;          // a "running" claim older than this (a worker killed mid-run) may be taken over

export type JobStatus = "queued" | "running" | "succeeded" | "failed" | "dead";
export interface JobRow {
  id: string; org_id: string; repo_full_name: string; pr_number: number | null; head_sha: string | null; action: string | null; forced: boolean;
  status: JobStatus; attempts: number; max_attempts: number; last_error: string | null; result: string | null; scan_id: string | null;
  created_at: string; updated_at: string; started_at: string | null; finished_at: string | null; job: ScanJob;
}

/** One key per repo + PR + commit; a forced rescan is its own job each time. */
export function jobKey(job: ScanJob): string {
  const base = `${job.repo_full_name}#${job.pr_number}@${job.head_sha}`;
  return job.force ? `${base}:force:${job.delivery_id ?? crypto.randomUUID()}` : base;
}

const missingTable = (e: { code?: string; message?: string } | null | undefined) =>
  !!e && (e.code === "42P01" || e.code === "PGRST205" || /scan_jobs/.test(e.message ?? "") && /does not exist|schema cache/i.test(e.message ?? ""));

/**
 * Record a job before it is queued. Returns the job id to put on the queued job, or `duplicate` when the same job is already queued
 * or running (so the caller does not queue it again), or null when there is no ledger.
 */
export async function registerJob(db: Db, job: ScanJob): Promise<{ id: string; duplicate: false } | { id: string; duplicate: true } | null> {
  if (!job.org_id) return null;
  try {
    const key = jobKey(job);
    const fresh = { org_id: job.org_id, dedupe_key: key, repo_full_name: job.repo_full_name, pr_number: job.pr_number, head_sha: job.head_sha, action: job.action, forced: !!job.force, job, status: "queued", attempts: 0, max_attempts: MAX_ATTEMPTS };
    const { data: inserted, error } = await db.from("scan_jobs").insert({ ...fresh, org_id: job.org_id }).select("id").single() as { data: { id: string } | null; error: { code?: string; message?: string } | null };
    if (inserted) return { id: inserted.id, duplicate: false };
    if (error?.code !== "23505") return null;                       // a missing table or any other problem: no ledger

    const { data: existing } = await db.from("scan_jobs").select("id, status, updated_at").eq("org_id", job.org_id).eq("dedupe_key", key).maybeSingle() as { data: { id: string; status: JobStatus; updated_at: string } | null };
    if (!existing) return null;
    const inFlight = existing.status === "queued" || existing.status === "running";
    if (inFlight && Date.now() - Date.parse(existing.updated_at) < IN_FLIGHT_FRESH_MS) return { id: existing.id, duplicate: true };

    // Finished (or lost): run it again -- a re-run check on an old commit must still work. Same row, fresh attempts, latest payload.
    const { error: upErr } = await db.from("scan_jobs").update({
      job, action: job.action, status: "queued", attempts: 0, last_error: null, result: null, scan_id: null, started_at: null, finished_at: null, updated_at: new Date().toISOString(),
    }).eq("id", existing.id).eq("org_id", job.org_id);
    return upErr ? null : { id: existing.id, duplicate: false };
  } catch { return null; }
}

/** The worker takes the job. False means another delivery already has it (or it already finished): do not run it again. */
export async function claimJob(db: Db, orgId: string, jobId: string): Promise<{ claimed: boolean; attempts: number; ledger: boolean }> {
  try {
    const staleBefore = new Date(Date.now() - RUNNING_STALE_MS).toISOString();
    const { data: row, error } = await db.from("scan_jobs").select("status, attempts, started_at").eq("id", jobId).eq("org_id", orgId).maybeSingle() as { data: { status: JobStatus; attempts: number; started_at: string | null } | null; error: { code?: string; message?: string } | null };
    if (error || !row) return { claimed: true, attempts: 0, ledger: false };     // no ledger entry: run as before
    const takeable = row.status === "queued" || row.status === "failed" || (row.status === "running" && (row.started_at ?? "") < staleBefore);
    if (!takeable) return { claimed: false, attempts: row.attempts, ledger: true };
    // The claim is the conditional update: only one of two concurrent deliveries gets a row back.
    const seenStatus = row.status, seenAttempts = row.attempts, next = seenAttempts + 1;
    const { data: won } = await db.from("scan_jobs")
      .update({ status: "running", attempts: next, started_at: new Date().toISOString(), updated_at: new Date().toISOString() })
      .eq("id", jobId).eq("org_id", orgId).eq("status", seenStatus).eq("attempts", seenAttempts).select("id") as { data: Array<{ id: string }> | null };
    return won && won.length > 0 ? { claimed: true, attempts: next, ledger: true } : { claimed: false, attempts: seenAttempts, ledger: true };
  } catch { return { claimed: true, attempts: 0, ledger: false }; }
}

/** A short, customer-safe reason from the worker's JSON error body. */
export function failureReason(body: unknown, status: number): string {
  const b = (body && typeof body === "object" ? body : {}) as { error?: unknown; message?: unknown };
  const code = typeof b.error === "string" ? b.error : `http_${status}`;
  const message = typeof b.message === "string" ? b.message : "";
  return (message ? `${code}: ${message}` : code).slice(0, 300);
}

/** The worker finished: succeeded (including a no-op), or failed / dead when it ran out of attempts. */
export async function finishJob(db: Db, orgId: string, jobId: string, attempts: number, outcome: { ok: true; result: string; scan_id?: string | null } | { ok: false; error: string }): Promise<void> {
  try {
    const now = new Date().toISOString();
    const patch = outcome.ok
      ? { status: "succeeded", result: outcome.result, scan_id: outcome.scan_id ?? null, last_error: null, finished_at: now, updated_at: now }
      : { status: attempts >= MAX_ATTEMPTS ? "dead" : "failed", last_error: outcome.error, finished_at: now, updated_at: now };
    await db.from("scan_jobs").update(patch).eq("id", jobId).eq("org_id", orgId).eq("status", "running");
  } catch { /* the ledger must never break a scan */ }
}

/** The job never reached a worker (no queue, or the direct call failed): visible as failed, with the reason, and replayable. */
export async function markNotQueued(db: Db, orgId: string, jobId: string, error: string): Promise<void> {
  try {
    const now = new Date().toISOString();
    await db.from("scan_jobs").update({ status: "failed", last_error: error.slice(0, 300), finished_at: now, updated_at: now }).eq("id", jobId).eq("org_id", orgId).eq("status", "queued");
  } catch { /* best effort */ }
}

/** Put a failed / dead job back in the queue with fresh attempts. Returns the stored original job, or null if it cannot be replayed. */
export async function resetForReplay(db: Db, orgId: string, jobId: string): Promise<{ job: ScanJob } | { error: "not_found" | "not_replayable" | "unavailable" }> {
  try {
    const { data: row, error } = await db.from("scan_jobs").select("id, status, job").eq("id", jobId).eq("org_id", orgId).maybeSingle() as { data: { id: string; status: JobStatus; job: ScanJob } | null; error: { code?: string; message?: string } | null };
    if (error) return { error: missingTable(error) ? "unavailable" : "unavailable" };
    if (!row) return { error: "not_found" };
    if (row.status !== "failed" && row.status !== "dead") return { error: "not_replayable" };
    const { data: reset } = await db.from("scan_jobs")
      .update({ status: "queued", attempts: 0, last_error: null, finished_at: null, updated_at: new Date().toISOString() })
      .eq("id", jobId).eq("org_id", orgId).eq("status", row.status).select("id") as { data: Array<{ id: string }> | null };
    if (!reset || reset.length === 0) return { error: "not_replayable" };
    return { job: { ...row.job, job_id: jobId } };
  } catch { return { error: "unavailable" }; }
}

/** What a customer sees of the queue: counts over the last 7 days, and the jobs that need attention. */
export async function queueOverview(db: Db, orgId: string) {
  const since = new Date(Date.now() - 7 * 86400_000).toISOString();
  const cols = "id, repo_full_name, pr_number, head_sha, action, forced, status, attempts, max_attempts, last_error, result, scan_id, created_at, updated_at, finished_at";
  const { data, error } = await db.from("scan_jobs").select(cols).eq("org_id", orgId).gte("updated_at", since).order("updated_at", { ascending: false }).limit(200) as { data: Array<Omit<JobRow, "job" | "started_at">> | null; error: { code?: string; message?: string } | null };
  if (error) return { set_up: !missingTable(error), counts: { queued: 0, running: 0, succeeded: 0, failed: 0, dead: 0 }, attention: [] as Array<Omit<JobRow, "job" | "started_at">>, recent: [] as Array<Omit<JobRow, "job" | "started_at">> };
  // Only these fields leave the server: never the stored payload (installation, check run, delivery ids), whatever the query returned.
  const rows = (data ?? []).map(r => ({
    id: r.id, repo_full_name: r.repo_full_name, pr_number: r.pr_number, head_sha: r.head_sha, action: r.action, forced: r.forced, status: r.status,
    attempts: r.attempts, max_attempts: r.max_attempts, last_error: r.last_error, result: r.result, scan_id: r.scan_id,
    created_at: r.created_at, updated_at: r.updated_at, finished_at: r.finished_at,
  }));
  const counts = { queued: 0, running: 0, succeeded: 0, failed: 0, dead: 0 };
  for (const r of rows) counts[r.status]++;
  const stuckBefore = new Date(Date.now() - IN_FLIGHT_FRESH_MS).toISOString();
  return {
    set_up: true, counts,
    // dead and failed jobs, and anything queued or running far longer than a scan takes
    attention: rows.filter(r => r.status === "dead" || r.status === "failed" || ((r.status === "queued" || r.status === "running") && r.updated_at < stuckBefore)),
    recent: rows.slice(0, 20),
  };
}
