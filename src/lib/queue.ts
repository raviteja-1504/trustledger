import { Client } from "@upstash/qstash";
import { sendSlackAlert } from "@/lib/alertDelivery";
import { internalSecret } from "@/lib/internalSecret";
import { createServiceClient } from "@/lib/supabase";
import { registerJob, markNotQueued } from "@/lib/scanJobs";

export interface ScanJob {
  org_id:           string | null;
  installation_id:  number;
  repo_full_name:   string;
  pr_number:        number;
  head_sha:         string;
  branch:           string;
  pr_author:        string | null;
  before_sha:       string | null;
  action:           string;
  check_run_id:     number | null;
  delivery_id:      string | null;
  // PR behavior metadata for multi-signal evidence scoring
  pr_additions?:    number;
  pr_deletions?:    number;
  pr_commits?:      number;
  pr_changed_files?: number;
  pr_created_at?:   string;
  // A user-requested rescan (api/scans/[id]/rescan): run even though this commit was already scanned,
  // as a full (non-delta) scan with the current engine.
  force?:           boolean;
  // Follows the job from webhook / dashboard request through the worker (lib/trace.ts, Trace page).
  trace_id?:        string;
  // The job's row in the scan job ledger (lib/scanJobs.ts): lets the worker claim it once, and the organisation see and replay it.
  job_id?:          string;
}

/** The scan did not get queued or run. `workerResponded` means the worker did run and reported its own failure (it has already updated the check run). */
export class ScanNotQueuedError extends Error {
  constructor(message: string, readonly workerResponded = false) { super(message); this.name = "ScanNotQueuedError"; }
}

/** Strip UTF-8 BOM and whitespace that Windows CLI piping adds to env vars. */
function cleanEnv(val: string | undefined, fallback = ""): string {
  return (val ?? fallback).replace(/^﻿/, "").trim();
}

let _client: Client | null = null;

function client(): Client {
  if (!_client) {
    // Without an explicit baseUrl, the SDK defaults to the global
    // qstash.upstash.io endpoint, which 404s for region-pinned accounts
    // (e.g. us-east-1) — QSTASH_URL must be passed explicitly.
    _client = new Client({
      token:   cleanEnv(process.env.QSTASH_TOKEN),
      baseUrl: cleanEnv(process.env.QSTASH_URL) || undefined,
    });
  }
  return _client;
}

async function directFetch(workerUrl: string, job: ScanJob): Promise<void> {
  const secret = internalSecret();
  if (!secret) {
    // The worker would refuse the call (production without INTERNAL_SECRET accepts only QStash signatures).
    console.error("[queue] cannot run the scan directly: INTERNAL_SECRET is not set in production");
    throw new ScanNotQueuedError("no queue configured and INTERNAL_SECRET is not set");
  }
  console.log("[queue] calling scan-worker at", workerUrl, "secret len:", secret.length);
  const res = await fetch(workerUrl, {
    method:  "POST",
    headers: { "Content-Type": "application/json", "x-internal-secret": secret },
    body:    JSON.stringify(job),
  });
  const body = await res.json().catch(() => ({}));
  console.log("[queue] scan-worker response:", res.status, JSON.stringify(body).slice(0, 300));
  // The direct path has no QStash retry behind it: a non-2xx here means the scan did not run, and the caller must know.
  if (!res.ok) throw new ScanNotQueuedError(`scan-worker answered ${res.status}`, true);
}

/**
 * Queue a scan. The job is recorded in the ledger first (its original payload, for retries and replay); a second delivery of a job
 * that is already queued or running is dropped here instead of becoming a second scan. If the job never reaches a worker it is
 * marked failed, with the reason, so it shows up -- and can be replayed -- instead of vanishing.
 */
export async function enqueueScan(job: ScanJob): Promise<void> {
  let db: ReturnType<typeof createServiceClient> | null = null;
  try { db = createServiceClient(); } catch { db = null; }
  const registered = db ? await registerJob(db, job) : null;
  if (registered?.duplicate) {
    console.log("[queue] the same job is already queued or running; not queuing it again", registered.id);
    return;
  }
  const queued = registered ? { ...job, job_id: registered.id } : job;
  try {
    await enqueueNow(queued);
  } catch (err) {
    // Anything that stopped the job before a worker took it (no queue, no secret, the call itself failing). When the worker answered with
    // its own failure it has already settled the job in the ledger.
    if (db && registered && job.org_id && !(err instanceof ScanNotQueuedError && err.workerResponded)) {
      await markNotQueued(db, job.org_id, registered.id, err instanceof Error ? err.message : String(err));
    }
    throw err;
  }
}

/** Queue a job that already has its ledger row (a replay): no second registration, same failure bookkeeping. */
export async function requeueJob(job: ScanJob): Promise<void> {
  try {
    await enqueueNow(job);
  } catch (err) {
    if (job.job_id && job.org_id && !(err instanceof ScanNotQueuedError && err.workerResponded)) {
      try { await markNotQueued(createServiceClient(), job.org_id, job.job_id, err instanceof Error ? err.message : String(err)); } catch { /* best effort */ }
    }
    throw err;
  }
}

async function enqueueNow(job: ScanJob): Promise<void> {
  const appUrl = cleanEnv(process.env.NEXT_PUBLIC_APP_URL)
    || cleanEnv(process.env.VERCEL_URL ? `https://${process.env.VERCEL_URL}` : "");
  const workerUrl = `${appUrl}/api/scan-worker`;
  console.log("[queue] workerUrl:", workerUrl, "qstash token set:", !!process.env.QSTASH_TOKEN);

  if (!cleanEnv(process.env.QSTASH_TOKEN)) {
    await directFetch(workerUrl, job);
    return;
  }

  try {
    await client().publishJSON({
      url: workerUrl,
      body: job,
      retries: 3,
      // Caps concurrent scan-worker runs sharing the same GitHub App
      // installation token -- without this, a burst of PR activity in one
      // org (mass rebase, a bot force-pushing many open PRs at once) fires
      // every scan fully concurrently, all racing for the same shared
      // GitHub API rate-limit budget (5000 req/hour per installation) and
      // hammering the database simultaneously. Keyed per-installation, not
      // globally, so different orgs still scan fully in parallel with each
      // other -- this only throttles bursts *within* one org.
      // QStash rejects flow-control keys containing anything but
      // alphanumeric/hyphen/underscore/period -- a colon here was silently
      // failing every single publish call ("flowControlKey must be
      // alphanumeric, hyphen, underscore, or period"), which is why every
      // scan since this feature was added actually ran through the
      // synchronous directFetch() fallback below instead of through QStash,
      // and why GitHub webhook deliveries were timing out (that fallback
      // blocks the webhook response on the full scan duration).
      flowControl: { key: `installation-${job.installation_id}`, parallelism: 5 },
    });
    console.log("[queue] job enqueued to QStash successfully");
  } catch (err) {
    const detail = String(err).slice(0, 200);
    console.error("[queue] QStash failed, running scan directly:", detail);

    // QStash failing silently (wrong region endpoint, bad signing key, quota
    // exhausted) previously went unnoticed until a user complained that PR
    // checks weren't running -- nothing paged anyone. This is a real
    // degraded-mode fallback (synchronous scan, no retries, no flow-control
    // concurrency cap), so it should be loud, not just a log line nobody is
    // tailing.
    const webhook = cleanEnv(process.env.SLACK_WEBHOOK_URL);
    if (webhook) {
      sendSlackAlert(webhook, {
        alert_id:  `qstash-fallback-${job.installation_id}-${Date.now()}`,
        severity:  "P2",
        title:     "QStash enqueue failed -- scan ran synchronously without retries/concurrency limits",
        body:      `Scan for \`${job.repo_full_name}\` PR #${job.pr_number} fell back to direct execution.\nError: \`${detail}\``,
        repo:      job.repo_full_name,
        pr_number: job.pr_number,
        org_name:  job.repo_full_name.split("/")[0] ?? "unknown",
        app_url:   cleanEnv(process.env.NEXT_PUBLIC_APP_URL, "https://app.trustledger.dev"),
      }).catch(() => { /* best-effort */ });
    }

    await directFetch(workerUrl, job);
  }
}
