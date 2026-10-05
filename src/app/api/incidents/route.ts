import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey } from "../_middleware";
import { writeAuditLog } from "@/lib/audit";
import { deliverAlert } from "@/lib/alertDelivery";
import { PLAYBOOK_TEMPLATES, type IncidentType } from "@/lib/incidentPlaybooks";

export async function GET(req: NextRequest) {
  const { org_id, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  const url    = new URL(req.url);
  const status = url.searchParams.get("status");
  const sev    = url.searchParams.get("severity");

  const db = createServiceClient();

  // ?count=open -- just the number of open (active + contained) incidents, for badges. Rows carry their
  // whole playbook and timeline (~9 KB each), so a badge must never download the list to count it.
  if (url.searchParams.get("count") === "open") {
    const { count } = await db
      .from("incidents")
      .select("id", { count: "exact", head: true })
      .eq("org_id", org_id)
      .in("status", OPEN_STATUSES);
    return NextResponse.json({ count: count ?? 0 });
  }

  const base = () => {
    let q = db.from("incidents").select("*").eq("org_id", org_id).order("detected_at", { ascending: false });
    if (sev) q = q.eq("severity", sev);
    return q;
  };

  if (status) {
    const { data } = await base().eq("status", status).limit(MAX_INCIDENTS);
    return NextResponse.json({ incidents: data ?? [] });
  }

  // Unfiltered: every open incident, plus the most recent closed ones -- not the org's entire history
  // on every page load and poll.
  const [open, closed] = await Promise.all([
    base().in("status", OPEN_STATUSES).limit(MAX_INCIDENTS),
    base().not("status", "in", `(${OPEN_STATUSES.join(",")})`).limit(RECENT_CLOSED_INCIDENTS),
  ]);
  const incidents = [...(open.data ?? []), ...(closed.data ?? [])]
    .sort((a, b) => String(b.detected_at).localeCompare(String(a.detected_at)));
  return NextResponse.json({ incidents });
}

const OPEN_STATUSES = ["active", "contained"];
const MAX_INCIDENTS = 1000;
const RECENT_CLOSED_INCIDENTS = 200;

export async function POST(req: NextRequest) {
  const { org_id, user_id, actor_email, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  const body = await req.json() as {
    title:          string;
    description?:   string;
    severity:       string;
    incident_type:  string;
    affected_repo?: string;
    affected_file?: string;
    stakeholders?:  string[];
  };

  if (!body.title || !body.severity) {
    return NextResponse.json({ error: "missing_fields" }, { status: 400 });
  }

  const db = createServiceClient();
  const now = new Date().toISOString();

  const template = PLAYBOOK_TEMPLATES[body.incident_type as IncidentType];

  const { data: incident, error: insErr } = await db
    .from("incidents")
    .insert({
      org_id,
      title:          body.title,
      description:    body.description ?? null,
      severity:       body.severity,
      status:         "active",
      incident_type:  body.incident_type ?? "unknown",
      affected_repo:  body.affected_repo ?? null,
      affected_file:  body.affected_file ?? null,
      stakeholders:   body.stakeholders ?? [],
      timeline:       [{ time: now, action: "Incident created", actor: actor_email ?? "system" }],
      // Populate the playbook checklist from the matching template so a real
      // incident has the same checklist the old client-only version always
      // showed but never actually persisted (playbook was hardcoded to []
      // here before). Unknown/custom types get an empty checklist.
      playbook:       template ? template.steps.map(s => ({ ...s, completed: false })) : [],
      detected_at:    now,
      created_by:     user_id ?? null,
    })
    .select("id")
    .single() as { data: { id: string } | null; error: unknown };

  if (insErr || !incident) return NextResponse.json({ error: "insert_failed" }, { status: 500 });

  // Auto-fire alert for P1/P2 incidents
  if (body.severity === "P1" || body.severity === "P2") {
    const { data: org } = await db
      .from("organizations")
      .select("name, slack_webhook, teams_webhook")
      .eq("id", org_id)
      .single() as { data: { name: string; slack_webhook: string | null; teams_webhook: string | null } | null };

    await deliverAlert(
      {
        slack_webhook:    org?.slack_webhook || process.env.SLACK_WEBHOOK_URL,
        teams_webhook:    org?.teams_webhook || undefined,
        sendgrid_api_key: process.env.SENDGRID_API_KEY,
        alert_from_email: process.env.ALERT_FROM_EMAIL ?? "alerts@trustledger.dev",
        alert_emails:     body.stakeholders ?? [],
      },
      {
        alert_id:  incident.id,
        severity:  body.severity as "P1" | "P2",
        title:     `Incident: ${body.title}`,
        body:      body.description ?? body.title,
        repo:      body.affected_repo,
        org_name:  org?.name ?? "",
        app_url:   process.env.NEXT_PUBLIC_APP_URL ?? "https://app.trustledger.dev",
      },
    );
  }

  await writeAuditLog(db, {
    org_id,
    event_type:    "incident_created",
    actor_id:      user_id ?? null,
    actor_email:   actor_email ?? null,
    resource_type: "incident",
    resource_id:   incident.id,
    payload: { title: body.title, severity: body.severity },
  });

  return NextResponse.json({ incident_id: incident.id });
}

export async function PATCH(req: NextRequest) {
  const { org_id, user_id, actor_email, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  const body = await req.json() as {
    id:               string;
    status?:          string;
    root_cause?:      string;
    lesson_learned?:  string;
    impact?:          string;
    timeline_entry?:  { action: string };
  };

  if (!body.id) return NextResponse.json({ error: "missing_id" }, { status: 400 });

  const db  = createServiceClient();
  const now = new Date().toISOString();

  const updates: Record<string, unknown> = {};
  if (body.status)         updates.status         = body.status;
  if (body.root_cause)     updates.root_cause     = body.root_cause;
  if (body.lesson_learned) updates.lesson_learned = body.lesson_learned;
  if (body.impact)         updates.impact         = body.impact;
  if (body.status === "contained") updates.contained_at = now;
  if (body.status === "resolved")  updates.resolved_at  = now;

  // Append timeline entry
  if (body.timeline_entry) {
    const { data: current } = await db
      .from("incidents")
      .select("timeline")
      .eq("id", body.id)
      .eq("org_id", org_id)
      .single() as { data: { timeline: unknown[] } | null };

    const timeline = (Array.isArray(current?.timeline) ? current.timeline : []) as unknown[];
    timeline.push({ time: now, action: body.timeline_entry.action, actor: actor_email ?? "system" });
    updates.timeline = timeline;
  }

  await db.from("incidents").update(updates).eq("id", body.id).eq("org_id", org_id);

  if (body.status === "resolved") {
    await writeAuditLog(db, {
      org_id, event_type: "incident_resolved",
      actor_id: user_id ?? null, actor_email: actor_email ?? null,
      resource_type: "incident", resource_id: body.id, payload: {},
    });
  }

  return NextResponse.json({ ok: true });
}
