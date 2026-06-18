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
}

let _client: Client | null = null;

function client(): Client {
  if (!_client) {
    // baseUrl is NOT a valid option in @upstash/qstash — token alone is sufficient
    _client = new Client({ token: process.env.QSTASH_TOKEN! });
  }
  return _client;
}

/**
 * Enqueue a scan job via Upstash QStash.
 * Falls back to a direct POST to the worker when QSTASH_TOKEN is not set
 * (local dev / environments without QStash configured).
 */
async function directFetch(workerUrl: string, job: ScanJob): Promise<void> {
  const res = await fetch(workerUrl, {
    method:  "POST",
    headers: { "Content-Type": "application/json", "x-internal-secret": process.env.INTERNAL_SECRET ?? "dev" },
    body:    JSON.stringify(job),
  });
  const body = await res.json().catch(() => ({}));
  console.log("[queue] scan-worker response:", res.status, JSON.stringify(body).slice(0, 200));
}

export async function enqueueScan(job: ScanJob): Promise<void> {
  const workerUrl = `${process.env.NEXT_PUBLIC_APP_URL}/api/scan-worker`;

  if (!process.env.QSTASH_TOKEN) {
    // No QStash — run scan synchronously so it completes before the caller returns
    await directFetch(workerUrl, job);
    return;
  }

  try {
    await client().publishJSON({ url: workerUrl, body: job, retries: 3 });
    console.log("[queue] job enqueued to QStash");
  } catch (err) {
    // QStash unavailable — run scan synchronously as fallback
    console.error("[queue] QStash failed, running scan directly:", err);
    await directFetch(workerUrl, job);
  }
}
