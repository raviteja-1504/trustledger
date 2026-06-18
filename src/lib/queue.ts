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
    _client = new Client({
      token:   process.env.QSTASH_TOKEN!,
      ...(process.env.QSTASH_URL ? { baseUrl: process.env.QSTASH_URL } : {}),
    });
  }
  return _client;
}

/**
 * Enqueue a scan job via Upstash QStash.
 * Falls back to a direct POST to the worker when QSTASH_TOKEN is not set
 * (local dev / environments without QStash configured).
 */
export async function enqueueScan(job: ScanJob): Promise<void> {
  const workerUrl = `${process.env.NEXT_PUBLIC_APP_URL}/api/scan-worker`;

  if (!process.env.QSTASH_TOKEN) {
    // Local dev fallback: fire-and-forget direct fetch so the webhook still
    // returns quickly without blocking on the scan.
    fetch(workerUrl, {
      method:  "POST",
      headers: { "Content-Type": "application/json", "x-internal-secret": process.env.INTERNAL_SECRET ?? "dev" },
      body:    JSON.stringify(job),
    }).catch(() => {});
    return;
  }

  await client().publishJSON({
    url:     workerUrl,
    body:    job,
    retries: 3,
  });
}
