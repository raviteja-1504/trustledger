import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey } from "../_middleware";
import { writeAuditLog } from "@/lib/audit";
import { deliverAlert, type AlertPayload } from "@/lib/alertDelivery";

// ── GET — list alerts ──────────────────────────────────────────────────────────

// Alert sources recognised by the dashboard UI (src/app/alerts/page.tsx AlertSource)
const KNOWN_SOURCES = new Set(["scan", "policy", "secret", "dependency", "sla", "anomaly", "exploit"]);

interface AlertRow {
  id: string;
  alert_type: string | null;
  severity: string;
  status: string;
  title: string;
  body: string;
  repo: string | null;
  scan_id: string | null;
  runbook_url: string | null;
  escalation_emails: string[] | null;
  fired_at: string;
  acknowledged_by: string | null;
  snooze_until: string | null;
  resolved_at: string | null;
}

// Normalise a raw `alerts` table row into the shape the alerts page UI expects
// (Alert interface in src/app/alerts/page.tsx) — DB rows lack notes/history/
// channel/pr_number/group_id and use different column names for runbook/escalation.
function toUiAlert(row: AlertRow) {
  return {
    id:               row.id,
    title:            row.title,
    body:             row.body,
    severity:         row.severity,
    source:           row.alert_type && KNOWN_SOURCES.has(row.alert_type) ? row.alert_type : "policy",
    status:           row.status,
    repo:             row.repo ?? undefined,
    scan_id:          row.scan_id ?? undefined,
    fired_at:         row.fired_at,
    acknowledged_by:  row.acknowledged_by ?? undefined,
    snooze_until:     row.snooze_until ?? undefined,
    resolved_at:      row.resolved_at ?? undefined,
    channel:          "in-app",
    runbook:          row.runbook_url ?? undefined,
    escalation:       row.escalation_emails ?? undefined,
    notes:            [] as string[],
    history:          [{ action: "Alert created", at: row.fired_at }],
  };
}

export async function GET(req: NextRequest) {
  const { org_id, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  const url    = new URL(req.url);
  const status = url.searchParams.get("status");
  const sev    = url.searchParams.get("severity");
  const limit  = parseInt(url.searchParams.get("limit") ?? "50");

  const db = createServiceClient();
  let query = db
    .from("alerts")
    .select("*")
    .eq("org_id", org_id)
    .order("fired_at", { ascending: false })
    .limit(limit);

  if (status) query = query.eq("status", status);
  if (sev)    query = query.eq("severity", sev);

  const { data, error: qErr } = await query;
  if (qErr) return NextResponse.json({ error: qErr.message }, { status: 500 });

  return NextResponse.json({ alerts: (data ?? []).map(row => toUiAlert(row as AlertRow)) });
}

// ── POST — fire a new alert + deliver it ──────────────────────────────────────

export async function POST(req: NextRequest) {
  const { org_id, user_id, actor_email, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  const body = await req.json() as {
    alert_type:       string;
    severity:         "P1" | "P2" | "P3" | "P4";
    title:            string;
    body_text:        string;
    repo?:            string;
    scan_id?:         string;
    runbook_url?:     string;
    escalation_emails?: string[];
    deliver:          boolean;  // if true, send Slack/email/PD now
  };

  if (!body.title || !body.severity) {
    return NextResponse.json({ error: "missing_fields" }, { status: 400 });
  }

  const db = createServiceClient();

  // Insert alert record
  const { data: alert, error: insErr } = await db
    .from("alerts")
    .insert({
      org_id,
      alert_type:        body.alert_type ?? "manual",
      severity:          body.severity,
      status:            "firing",
      title:             body.title,
      body:              body.body_text ?? "",
      repo:              body.repo ?? null,
      scan_id:           body.scan_id ?? null,
      runbook_url:       body.runbook_url ?? null,
      escalation_emails: body.escalation_emails ?? [],
      fired_at:          new Date().toISOString(),
    })
    .select("id")
    .single() as { data: { id: string } | null; error: unknown };

  if (insErr || !alert) {
    return NextResponse.json({ error: "insert_failed" }, { status: 500 });
  }

  // Fetch org config for delivery
  let deliveryResult = { slack: false, email: false, pagerduty: false };

  if (body.deliver && (body.severity === "P1" || body.severity === "P2")) {
    const { data: org } = await db
      .from("organizations")
      .select("name, slug")
      .eq("id", org_id)
      .single() as { data: { name: string; slug: string } | null };

    const slackWebhook  = process.env.SLACK_WEBHOOK_URL ?? "";
    const sendgridKey   = process.env.SENDGRID_API_KEY ?? "";
    const pagerdutyKey  = process.env.PAGERDUTY_KEY ?? "";
    const fromEmail     = process.env.ALERT_FROM_EMAIL ?? "alerts@trustledger.dev";
    const appUrl        = process.env.NEXT_PUBLIC_APP_URL ?? "https://app.trustledger.dev";

    const payload: AlertPayload = {
      alert_id:   alert.id,
      severity:   body.severity,
      title:      body.title,
      body:       body.body_text ?? "",
      repo:       body.repo,
      scan_id:    body.scan_id,
      runbook:    body.runbook_url,
      org_name:   org?.name ?? org_id,
      app_url:    appUrl,
    };

    deliveryResult = await deliverAlert(
      {
        slack_webhook:    slackWebhook || undefined,
        sendgrid_api_key: sendgridKey || undefined,
        alert_from_email: fromEmail,
        pagerduty_key:    pagerdutyKey || undefined,
        alert_emails:     body.escalation_emails ?? [],
      },
      payload,
    );
  }

  await writeAuditLog(db, {
    org_id,
    event_type:    "alert_fired",
    actor_id:      user_id ?? null,
    actor_email:   actor_email ?? null,
    resource_type: "alert",
    resource_id:   alert.id,
    payload: { title: body.title, severity: body.severity, delivery: deliveryResult },
  });

  return NextResponse.json({ alert_id: alert.id, delivered: deliveryResult });
}

// ── PATCH — acknowledge / snooze / resolve ────────────────────────────────────

export async function PATCH(req: NextRequest) {
  const { org_id, user_id, actor_email, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  const body = await req.json() as {
    id:           string;
    status:       string;
    snooze_hours?: number;
    note?:        string;
  };

  if (!body.id || !body.status) {
    return NextResponse.json({ error: "missing_fields" }, { status: 400 });
  }

  const db  = createServiceClient();
  const now = new Date().toISOString();

  const updates: Record<string, unknown> = { status: body.status };
  if (body.status === "acknowledged") {
    updates.acknowledged_by = user_id ?? null;
    updates.acknowledged_at = now;
  }
  if (body.status === "snoozed" && body.snooze_hours) {
    updates.snooze_until = new Date(Date.now() + body.snooze_hours * 3600_000).toISOString();
  }
  if (body.status === "resolved") {
    updates.resolved_at = now;
  }

  const { data, error: upErr } = await db
    .from("alerts")
    .update(updates)
    .eq("id", body.id)
    .eq("org_id", org_id)
    .select("id, title, severity")
    .single() as { data: { id: string; title: string; severity: string } | null; error: unknown };

  if (upErr || !data) return NextResponse.json({ error: "update_failed" }, { status: 500 });

  await writeAuditLog(db, {
    org_id,
    event_type:    body.status === "resolved" ? "alert_resolved" : "alert_fired",
    actor_id:      user_id ?? null,
    actor_email:   actor_email ?? null,
    resource_type: "alert",
    resource_id:   body.id,
    payload: { status: body.status, title: data.title },
  });

  return NextResponse.json({ ok: true });
}
