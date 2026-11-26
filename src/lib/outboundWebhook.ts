/**
 * Outbound Webhook Delivery
 * Sends signed event payloads to customer-configured URLs when key events occur.
 * Supports HMAC-SHA256 signatures so customers can verify delivery authenticity.
 *
 * Events:
 *   scan.completed       — every scan result
 *   violation.opened     — new CRITICAL/HIGH violation
 *   violation.resolved   — violation marked resolved
 *   alert.fired          — P1/P2 alert created
 *   attestation.created  — file attested
 *   sla.breached         — attestation SLA exceeded
 */

import crypto from "crypto";
import { isPublicHttpUrl } from "./outboundUrl";
import { safeFetch } from "./safeFetch";
import { enqueueFailedDelivery, isRetryable } from "./webhookRetry";

export type WebhookEventType =
  | "scan.completed"
  | "violation.opened"
  | "violation.resolved"
  | "alert.fired"
  | "attestation.created"
  | "sla.breached"
  | "secret.detected"
  | "incident.created";

export interface WebhookEvent {
  id:          string;            // UUID of this delivery
  type:        WebhookEventType;
  created_at:  string;            // ISO timestamp
  org_id:      string;
  data:        Record<string, unknown>;
}

interface WebhookConfig {
  id?:     string;
  url:     string;
  secret?: string;         // HMAC secret for signature verification
  events:  WebhookEventType[];
  enabled: boolean;
}

interface DeliveryResult {
  success:     boolean;
  status_code: number | null;
  duration_ms: number;
  error?:      string;
}

// ── Deliver a webhook ─────────────────────────────────────────────────────────

export async function deliverWebhook(
  config: WebhookConfig,
  event: WebhookEvent,
): Promise<DeliveryResult> {
  if (!config.enabled || !config.url) {
    return { success: false, status_code: null, duration_ms: 0, error: "webhook_disabled" };
  }

  // A user-typed URL: never the server's own network (cloud metadata, localhost, private ranges)
  if (!isPublicHttpUrl(config.url)) {
    return { success: false, status_code: null, duration_ms: 0, error: "webhook_url_not_allowed" };
  }

  if (!config.events.includes(event.type)) {
    return { success: true, status_code: null, duration_ms: 0 }; // Not subscribed to this event
  }

  const body      = JSON.stringify(event);
  const timestamp = Math.floor(Date.now() / 1000);

  // Build HMAC signature: sha256=HMAC(secret, timestamp.body)
  const headers: Record<string, string> = {
    "Content-Type":          "application/json",
    "X-TrustLedger-Event":   event.type,
    "X-TrustLedger-Delivery":event.id,
    "X-TrustLedger-Timestamp": String(timestamp),
    "User-Agent":             "TrustLedger-Webhook/1.0",
  };

  if (config.secret) {
    const sig = crypto
      .createHmac("sha256", config.secret)
      .update(`${timestamp}.${body}`)
      .digest("hex");
    headers["X-TrustLedger-Signature"] = `sha256=${sig}`;
  }

  const start = Date.now();
  try {
    // safeFetch vets the address the connection really goes to (no DNS rebinding), never follows a redirect (a 3xx is a
    // failed delivery), and times out after 10 s.
    const res = await safeFetch(config.url, { method: "POST", headers, body, timeoutMs: 10_000 });
    return {
      success:     res.ok,
      status_code: res.status,
      duration_ms: Date.now() - start,
    };
  } catch (e) {
    return {
      success:     false,
      status_code: null,
      duration_ms: Date.now() - start,
      error:       e instanceof Error ? e.message : "network_error",
    };
  }
}

// ── Load webhook configs for an org ──────────────────────────────────────────

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export async function getOrgWebhooks(db: any, orgId: string): Promise<WebhookConfig[]> {
  const { data: org } = await db
    .from("organizations")
    .select("id")
    .eq("id", orgId)
    .single() as { data: { id: string } | null };

  if (!org) return [];

  // Load from webhook_configs table (created in migration below)
  const { data: configs } = await db
    .from("webhook_configs")
    .select("id, url, secret, events, enabled")
    .eq("org_id", orgId) as { data: WebhookConfig[] | null };

  return configs ?? [];
}

// ── Fan-out to all configured webhooks ───────────────────────────────────────

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export async function fireOrgWebhooks(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  db: any,
  orgId: string,
  event: Omit<WebhookEvent, "id" | "created_at" | "org_id">,
): Promise<void> {
  const configs = await getOrgWebhooks(db, orgId);
  if (configs.length === 0) return;

  const fullEvent: WebhookEvent = {
    id:         crypto.randomUUID(),
    created_at: new Date().toISOString(),
    org_id:     orgId,
    ...event,
  };

  // Deliver to all hooks in parallel (non-blocking)
  await Promise.allSettled(configs.map(async cfg => {
    const result = await deliverWebhook(cfg, fullEvent);
    // A failed delivery is kept, with this exact event, for the retry job (lib/webhookRetry.ts).
    if (!result.success && cfg.id && isRetryable(result.error)) {
      await enqueueFailedDelivery(db, cfg.id, fullEvent, result.status_code, result.error);
    }
  }));
}
