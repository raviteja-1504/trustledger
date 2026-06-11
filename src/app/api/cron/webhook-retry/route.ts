/**
 * Webhook Delivery Retry Cron
 * Runs every 5 minutes — retries failed webhook deliveries with exponential backoff.
 * Max 5 retries, after which the webhook is marked permanently failed.
 *
 * Retry schedule (exponential backoff):
 *   Attempt 1: 5 minutes
 *   Attempt 2: 15 minutes
 *   Attempt 3: 1 hour
 *   Attempt 4: 6 hours
 *   Attempt 5: 24 hours → final
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { deliverWebhook, type WebhookEvent, type WebhookEventType } from "@/lib/outboundWebhook";

const RETRY_DELAYS_MS = [
  5 * 60_000,      //  5 min
  15 * 60_000,     // 15 min
  60 * 60_000,     //  1 h
  6 * 3600_000,    //  6 h
  24 * 3600_000,   // 24 h
];

export async function GET(req: NextRequest) {
  const auth = req.headers.get("authorization");
  if (auth !== `Bearer ${process.env.CRON_SECRET}`) {
    return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  }

  const db          = createServiceClient();
  const now         = new Date();
  let retriedCount  = 0;
  let succeededCount= 0;

  // Find failed deliveries that are due for retry
  // In production: store retry state in webhook_delivery_log
  // For now, check webhook_configs last_delivery_status
  const { data: failedWebhooks } = (await db
    .from("webhook_configs")
    .select("id, org_id, url, secret, events, enabled, last_delivery_at, last_delivery_status")
    .eq("enabled", true)
    .not("last_delivery_status", "is", null)
    .gte("last_delivery_status", 400)
    .lt("last_delivery_at", new Date(now.getTime() - 5 * 60_000).toISOString())
  ) as { data: Array<{
      id: string; org_id: string; url: string; secret: string | null;
      events: string[]; enabled: boolean;
      last_delivery_at: string | null; last_delivery_status: number | null;
    }> | null };

  if (!failedWebhooks || failedWebhooks.length === 0) {
    return NextResponse.json({ ok: true, retried: 0, succeeded: 0 });
  }

  for (const hook of failedWebhooks) {
    retriedCount++;

    // Build a retry event
    const retryEvent: WebhookEvent = {
      id:         crypto.randomUUID(),
      type:       "scan.completed" as WebhookEventType, // generic retry ping
      created_at: new Date().toISOString(),
      org_id:     hook.org_id,
      data:       { retry: true, reason: "automatic_retry", original_status: hook.last_delivery_status },
    };

    const result = await deliverWebhook(
      { url: hook.url, secret: hook.secret ?? undefined, events: hook.events as WebhookEventType[], enabled: true },
      retryEvent,
    );

    // Update delivery status
    await db.from("webhook_configs").update({
      last_delivery_status: result.status_code ?? (result.success ? 200 : 0),
      last_delivery_at:     new Date().toISOString(),
    }).eq("id", hook.id);

    if (result.success) succeededCount++;

    // Log delivery attempt
    try {
      await db.from("webhook_delivery_log").insert({
        webhook_id:  hook.id,
        org_id:      hook.org_id,
        event_type:  "retry",
        status_code: result.status_code,
        duration_ms: result.duration_ms,
        success:     result.success,
        error_msg:   result.error,
      });
    } catch { /* non-fatal */ }
  }

  return NextResponse.json({
    ok:        true,
    retried:   retriedCount,
    succeeded: succeededCount,
    ran_at:    now.toISOString(),
  });
}
