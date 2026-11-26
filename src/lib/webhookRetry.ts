/**
 * Retry policy for failed outbound webhook deliveries. After the first failure the event is retried after 5 min, 15 min,
 * 1 h, 6 h and 24 h (5 retries); a failed 5th retry is final. Each retry re-sends the ORIGINAL event stored in
 * webhook_failed_deliveries (migration 20261127_webhook_failed_deliveries.sql).
 */
import type { WebhookEvent } from "@/lib/outboundWebhook";

export const RETRY_DELAYS_MS = [5 * 60_000, 15 * 60_000, 60 * 60_000, 6 * 3600_000, 24 * 3600_000];
export const MAX_RETRIES = RETRY_DELAYS_MS.length;

/** When the next retry is due, given how many retries have been attempted so far; null when the retries are used up. */
export function nextRetryAt(retriesDone: number, now: Date): Date | null {
  const delay = RETRY_DELAYS_MS[retriesDone];
  return delay === undefined ? null : new Date(now.getTime() + delay);
}

/** Failures worth retrying: not a disabled webhook or a blocked URL, which no amount of waiting fixes. */
export function isRetryable(error: string | undefined): boolean {
  return error !== "webhook_disabled" && error !== "webhook_url_not_allowed";
}

/** Store a failed delivery for retry. Never throws: if the table is missing the delivery is simply not retried. */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export async function enqueueFailedDelivery(db: any, webhookId: string, event: WebhookEvent, status: number | null, error?: string): Promise<void> {
  try {
    await db.from("webhook_failed_deliveries").upsert({
      webhook_id: webhookId, org_id: event.org_id, event_id: event.id, event_type: event.type, payload: event,
      retry_count: 0, next_retry_at: nextRetryAt(0, new Date())!.toISOString(), permanently_failed: false,
      last_status: status, last_error: error ?? null,
    }, { onConflict: "webhook_id,event_id", ignoreDuplicates: true });
  } catch { /* non-fatal */ }
}
