import { Client } from "@upstash/qstash";

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
    await client().publishJSON({ url: workerUrl, body: job, retries: 3 });
    console.log("[queue] job enqueued to QStash successfully");
  } catch (err) {
    console.error("[queue] QStash failed, running scan directly:", String(err).slice(0, 200));
    await directFetch(workerUrl, job);
  }
}
