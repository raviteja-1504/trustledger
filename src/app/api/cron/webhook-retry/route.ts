/**
 * Webhook Delivery Retry
 * Re-sends the ORIGINAL event of every failed delivery that is due (webhook_failed_deliveries), with backoff
 * 5 min, 15 min, 1 h, 6 h, 24 h; after the 5th failed retry the delivery is marked permanently failed.
 * See lib/webhookRetry.ts for the policy.
 *
 * Nothing schedules this route: it runs only when something calls it with the CRON_SECRET.
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { deliverWebhook, type WebhookEvent, type WebhookEventType } from "@/lib/outboundWebhook";
import { cronAuthorized } from "@/lib/cronAuth";
import { isRetryable, nextRetryAt } from "@/lib/webhookRetry";
import { notifyOps } from "@/lib/opsAlert";

const BATCH = 50;
const CLAIM_MS = 10 * 60_000;   // a claimed row is not picked up again for this long, so overlapping runs do not double-send

interface Row {
  id: string; webhook_id: string; org_id: string; payload: WebhookEvent;
  retry_count: number; next_retry_at: string;
}
interface Hook { id: string; url: string; secret: string | null; events: string[]; enabled: boolean }

export async function GET(req: NextRequest) {
  if (!cronAuthorized(req)) return NextResponse.json({ error: "unauthorized" }, { status: 401 });   // also when CRON_SECRET is unset

  const db  = createServiceClient();
  const now = new Date();
  let retried = 0, succeeded = 0, gaveUp = 0;

  const { data: due, error } = await db.from("webhook_failed_deliveries")
    .select("id, webhook_id, org_id, payload, retry_count, next_retry_at")
    .eq("permanently_failed", false)
    .lte("next_retry_at", now.toISOString())
    .order("next_retry_at", { ascending: true })
    .limit(BATCH) as { data: Row[] | null; error: { message?: string } | null };
  if (error) return NextResponse.json({ error: "retry_queue_unavailable" }, { status: 500 });
  if (!due || due.length === 0) return NextResponse.json({ ok: true, retried: 0, succeeded: 0, gave_up: 0 });

  for (const row of due) {
    // Claim the row (compare-and-set on next_retry_at); skip it if another run got there first.
    const { data: claimed } = await db.from("webhook_failed_deliveries")
      .update({ next_retry_at: new Date(now.getTime() + CLAIM_MS).toISOString() })
      .eq("id", row.id).eq("next_retry_at", row.next_retry_at).select("id");
    if (!claimed || claimed.length === 0) continue;

    const { data: hook } = await db.from("webhook_configs")
      .select("id, url, secret, events, enabled").eq("id", row.webhook_id).eq("org_id", row.org_id).maybeSingle() as { data: Hook | null };

    // Webhook deleted or switched off since the failure: nothing left to retry.
    if (!hook || !hook.enabled) {
      await db.from("webhook_failed_deliveries")
        .update({ permanently_failed: true, next_retry_at: null, last_error: hook ? "webhook_disabled" : "webhook_deleted" }).eq("id", row.id);
      gaveUp++;
      continue;
    }

    retried++;
    const result = await deliverWebhook(
      { url: hook.url, secret: hook.secret ?? undefined, events: hook.events as WebhookEventType[], enabled: true },
      row.payload,   // the original event: same id and body as the first attempt
    );

    await db.from("webhook_configs").update({
      last_delivery_status: result.status_code ?? (result.success ? 200 : 0),
      last_delivery_at:     new Date().toISOString(),
    }).eq("id", hook.id);
    try {
      await db.from("webhook_delivery_log").insert({
        webhook_id: hook.id, org_id: row.org_id, event_type: row.payload.type, status_code: result.status_code,
        duration_ms: result.duration_ms, success: result.success, error_msg: result.error,
      });
    } catch { /* non-fatal */ }

    if (result.success) {
      succeeded++;
      await db.from("webhook_failed_deliveries").delete().eq("id", row.id);
      continue;
    }

    const retriesDone = row.retry_count + 1;
    const next = isRetryable(result.error) ? nextRetryAt(retriesDone, new Date()) : null;
    if (!next) {
      gaveUp++;
      void notifyOps("integration_gave_up", { org_id: row.org_id, webhook_id: row.webhook_id });
    }
    await db.from("webhook_failed_deliveries").update({
      retry_count: retriesDone, last_status: result.status_code, last_error: result.error ?? null,
      next_retry_at: next ? next.toISOString() : null, permanently_failed: !next,
    }).eq("id", row.id);
  }

  return NextResponse.json({ ok: true, retried, succeeded, gave_up: gaveUp, ran_at: now.toISOString() });
}
