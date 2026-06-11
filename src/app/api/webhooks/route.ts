/**
 * Customer Webhook Config API
 * Manage outbound webhook endpoints per org.
 * GET    /api/webhooks          → list configured webhooks
 * POST   /api/webhooks          → add a webhook
 * PATCH  /api/webhooks          → update a webhook
 * DELETE /api/webhooks?id=...   → delete a webhook
 * POST   /api/webhooks/test     → send a test payload
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey } from "../_middleware";
import { deliverWebhook, type WebhookEventType } from "@/lib/outboundWebhook";
import crypto from "crypto";

const ALL_EVENTS: WebhookEventType[] = [
  "scan.completed","violation.opened","violation.resolved",
  "alert.fired","attestation.created","sla.breached",
  "secret.detected","incident.created",
];

export async function GET(req: NextRequest) {
  const { org_id, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  const db = createServiceClient();
  const { data } = await db
    .from("webhook_configs")
    .select("id, url, events, enabled, created_at, last_delivery_at, last_delivery_status")
    .eq("org_id", org_id)
    .order("created_at") as { data: unknown[] | null };

  return NextResponse.json({ webhooks: data ?? [] });
}

export async function POST(req: NextRequest) {
  const { org_id, user_id, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  const url  = new URL(req.url);
  const body = await req.json() as {
    action?: "test";
    url?:    string;
    events?: WebhookEventType[];
    secret?: string;
    id?:     string;
  };

  const db = createServiceClient();

  // ── Test an existing webhook ──────────────────────────────────────────────
  if (body.action === "test") {
    const webhookUrl = body.url ?? "";
    if (!webhookUrl) return NextResponse.json({ error:"missing_url" }, { status:400 });

    const result = await deliverWebhook(
      { url: webhookUrl, secret: body.secret, events: ALL_EVENTS, enabled: true },
      {
        id:         crypto.randomUUID(),
        type:       "scan.completed",
        created_at: new Date().toISOString(),
        org_id,
        data: {
          test:        true,
          message:     "This is a test delivery from TrustLedger.",
          scan_id:     "test-scan-id",
          overall_risk:"LOW",
          file_count:  0,
        },
      },
    );

    return NextResponse.json({ ok: result.success, result });
  }

  // ── Create new webhook ────────────────────────────────────────────────────
  if (!body.url) return NextResponse.json({ error:"missing_url" }, { status:400 });

  let parsedUrl: URL;
  try { parsedUrl = new URL(body.url); } catch {
    return NextResponse.json({ error:"invalid_url" }, { status:400 });
  }
  // Block SSRF — reject private/internal IP ranges and non-HTTPS
  const PRIVATE = /^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|0\.0\.0\.0|::1|fc00:|fe80:)/i;
  if (parsedUrl.protocol !== "https:" || PRIVATE.test(parsedUrl.hostname)) {
    return NextResponse.json({ error:"url_not_allowed" }, { status:400 });
  }

  const { data, error: insErr } = await db
    .from("webhook_configs")
    .insert({
      org_id,
      url:        body.url,
      secret:     body.secret ?? null,
      events:     body.events ?? ALL_EVENTS,
      enabled:    true,
      created_by: user_id ?? null,
    })
    .select("id, url, events, enabled, created_at")
    .single() as { data: unknown; error: unknown };

  if (insErr) return NextResponse.json({ error:"insert_failed" }, { status:500 });
  return NextResponse.json({ webhook: data });
}

export async function PATCH(req: NextRequest) {
  const { org_id, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  const body = await req.json() as { id:string; url?:string; events?:WebhookEventType[]; enabled?:boolean; secret?:string };
  if (!body.id) return NextResponse.json({ error:"missing_id" }, { status:400 });

  const db = createServiceClient();
  const updates: Record<string, unknown> = {};
  if (body.url     !== undefined) updates.url     = body.url;
  if (body.events  !== undefined) updates.events  = body.events;
  if (body.enabled !== undefined) updates.enabled = body.enabled;
  if (body.secret  !== undefined) updates.secret  = body.secret;

  await db.from("webhook_configs").update(updates).eq("id", body.id).eq("org_id", org_id);
  return NextResponse.json({ ok: true });
}

export async function DELETE(req: NextRequest) {
  const { org_id, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  const id = new URL(req.url).searchParams.get("id");
  if (!id) return NextResponse.json({ error:"missing_id" }, { status:400 });

  const db = createServiceClient();
  await db.from("webhook_configs").delete().eq("id", id).eq("org_id", org_id);
  return NextResponse.json({ ok: true });
}
