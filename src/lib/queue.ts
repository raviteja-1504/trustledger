import { Client } from "@upstash/qstash";
import { sendSlackAlert } from "@/lib/alertDelivery";

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
  // PR behavior metadata for multi-signal evidence scoring
  pr_additions?:    number;
  pr_deletions?:    number;
  pr_commits?:      number;
  pr_changed_files?: number;
  pr_created_at?:   string;
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
  const secret = cleanEnv(process.env.INTERNAL_SECRET, "dev");
  console.log("[queue] calling scan-worker at", workerUrl, "secret len:", secret.length);
  const res = await fetch(workerUrl, {
    method:  "POST",
    headers: { "Content-Type": "application/json", "x-internal-secret": secret },
    body:    JSON.stringify(job),
  });
  const body = await res.json().catch(() => ({}));
  console.log("[queue] scan-worker response:", res.status, JSON.stringify(body).slice(0, 300));
}

export async function enqueueScan(job: ScanJob): Promise<void> {
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
