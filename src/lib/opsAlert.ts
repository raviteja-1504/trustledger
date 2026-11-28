/**
 * Alerts to whoever runs the platform (not to customers): a scan job that ran out of attempts, an audit entry that could not be
 * written, an outbound integration that gave up. They go to OPS_ALERT_WEBHOOK_URL (a Slack-compatible incoming webhook, https only,
 * checked like any outbound address) when it is set, and are a no-op when it is not -- the same facts are always logged and recorded
 * as ops events either way.
 *
 * Nothing here is scheduled: an alert is sent at the moment the thing happens. What a monitor polls on a schedule is
 * GET /api/ops/status (lib/opsStatus.ts), which an external uptime service can watch.
 *
 * What an alert may contain: a fixed sentence per kind, counts, and opaque ids (organisation id, job id). Never a repository name,
 * a person's email, a file path, a payload or an error message from customer code.
 */
import { safeFetch } from "@/lib/safeFetch";
import { logger } from "@/lib/logger";

export type OpsAlertKind = "scan_job_dead" | "audit_write_failed" | "integration_gave_up" | "queue_delayed" | "database_unavailable";

const SENTENCE: Record<OpsAlertKind, string> = {
  scan_job_dead:        "A scan job ran out of attempts and needs replaying",
  audit_write_failed:   "A required audit entry could not be written",
  integration_gave_up:  "An outbound webhook was given up on after its last retry",
  queue_delayed:        "Scans are waiting in the queue longer than expected",
  database_unavailable: "The database did not answer",
};
const SEVERITY: Record<OpsAlertKind, "P1" | "P2"> = { scan_job_dead: "P2", audit_write_failed: "P1", integration_gave_up: "P2", queue_delayed: "P2", database_unavailable: "P1" };

const WINDOW_MS = 15 * 60_000;     // the same alert (kind + organisation) is sent at most once in this long
const MAX_PER_WINDOW = 20;         // and at most this many alerts of any kind per instance, so a bad hour cannot flood the channel
const sent = new Map<string, number>();

/** Only these keys of `data` are ever put in a message, and only simple values. */
const SAFE_KEYS = ["org_id", "job_id", "webhook_id", "event_type", "count", "oldest_minutes", "attempts"] as const;

/** Forget what was sent (tests). */
export function resetOpsAlertState(): void { sent.clear(); }

export function opsAlertText(kind: OpsAlertKind, data: Record<string, unknown> = {}): string {
  const facts = SAFE_KEYS.filter(k => data[k] !== undefined && (typeof data[k] === "string" || typeof data[k] === "number"))
    .map(k => `${k}=${String(data[k]).slice(0, 64)}`);
  return `[${SEVERITY[kind]}] TrustLedger: ${SENTENCE[kind]}${facts.length ? ` (${facts.join(", ")})` : ""}`;
}

/** Send an alert. Never throws, never waits long: it must not be the thing that slows or breaks the work that triggered it. */
export async function notifyOps(kind: OpsAlertKind, data: Record<string, unknown> = {}, now = Date.now()): Promise<boolean> {
  try {
    const url = (process.env.OPS_ALERT_WEBHOOK_URL ?? "").trim();
    if (!url) return false;
    for (const [k, at] of sent) if (now - at > WINDOW_MS) sent.delete(k);
    const key = `${kind}:${typeof data.org_id === "string" ? data.org_id : ""}`;
    if (sent.has(key) || sent.size >= MAX_PER_WINDOW) return false;
    sent.set(key, now);
    const res = await safeFetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ text: opsAlertText(kind, data) }), timeoutMs: 4000 });
    if (!res.ok) logger.warn("Ops alert webhook refused the alert", { event: "ops_alert_failed", kind, status: res.status });
    return res.ok;
  } catch (e) {
    logger.warn("Ops alert could not be sent", { event: "ops_alert_failed", kind, detail: e instanceof Error ? e.message : String(e) });
    return false;
  }
}
