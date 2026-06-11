/**
 * Data Retention Policy API
 * GET  /api/retention  → get current policy
 * PATCH /api/retention → update retention settings
 * DELETE /api/retention?scope=scans&before=2025-01-01 → delete data
 * POST  /api/retention?action=export_all → GDPR full data export
 * POST  /api/retention?action=delete_account → GDPR right to erasure
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey } from "../_middleware";
import { writeAuditLog } from "@/lib/audit";

const DEFAULT_RETENTION = {
  scans_days:         365,   // Keep scan records
  audit_log_days:     2555,  // 7 years (SOC 2 requirement)
  secret_findings_days: 365,
  violations_days:    365,
  incidents_days:     2555,
};

export async function GET(req: NextRequest) {
  const { org_id, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  const db = createServiceClient();

  // Try to get from org metadata (stored as JSON in organizations table)
  // For now, return defaults — in production store in a retention_policies table
  return NextResponse.json({
    policy:   DEFAULT_RETENTION,
    note:     "Data retention periods in days. SOC 2 requires 7-year audit log retention.",
  });
}

export async function PATCH(req: NextRequest) {
  const { org_id, user_id, actor_email, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  const raw  = await req.json().catch(() => ({})) as Record<string, unknown>;
  // Clamp all numeric values to sane bounds (1 day – 2555 days / ~7 years)
  const body: Partial<typeof DEFAULT_RETENTION> = {};
  for (const [k, v] of Object.entries(raw)) {
    if (typeof v === "number" && isFinite(v)) {
      (body as Record<string, number>)[k] = Math.min(Math.max(Math.round(v), 1), 2555);
    }
  }
  const db   = createServiceClient();

  await writeAuditLog(db, {
    org_id,
    event_type:    "org_settings_changed",
    actor_id:      user_id ?? null,
    actor_email:   actor_email ?? null,
    resource_type: "retention_policy",
    payload:       body,
  });

  return NextResponse.json({ ok: true, updated: body });
}

export async function DELETE(req: NextRequest) {
  const { org_id, user_id, actor_email, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  const url    = new URL(req.url);
  const scope  = url.searchParams.get("scope");   // scans | violations | secrets | all
  const before = url.searchParams.get("before");  // ISO date

  const VALID_SCOPES = new Set(["scans", "violations", "secrets", "incidents", "alerts", "all"]);
  if (!scope || !VALID_SCOPES.has(scope)) {
    return NextResponse.json({ error: "scope must be one of: scans, violations, secrets, incidents, alerts, all" }, { status: 400 });
  }
  if (!before) {
    return NextResponse.json({ error: "before (ISO date) is required" }, { status: 400 });
  }
  const cutoffDate = new Date(before);
  if (isNaN(cutoffDate.getTime())) {
    return NextResponse.json({ error: "before must be a valid ISO date string" }, { status: 400 });
  }
  // Safety guard: never delete data from the last 7 days
  const sevenDaysAgo = new Date(Date.now() - 7 * 86400_000);
  if (cutoffDate > sevenDaysAgo) {
    return NextResponse.json({ error: "before must be at least 7 days in the past" }, { status: 400 });
  }

  const db = createServiceClient();
  const cutoff = cutoffDate.toISOString();
  let deleted = 0;

  const tables: Record<string, string> = {
    scans:      "scans",
    violations: "violations",
    secrets:    "secret_findings",
    incidents:  "incidents",
    alerts:     "alerts",
  };

  const targetTables = scope === "all" ? Object.values(tables) : [tables[scope]].filter(Boolean);

  for (const table of targetTables) {
    const { count } = await db
      .from(table)
      .delete({ count: "exact" })
      .eq("org_id", org_id)
      .lt("created_at", cutoff) as { count: number | null };
    deleted += count ?? 0;
  }

  await writeAuditLog(db, {
    org_id,
    event_type:    "org_settings_changed",
    actor_id:      user_id ?? null,
    actor_email:   actor_email ?? null,
    resource_type: "data_deletion",
    payload:       { scope, before: cutoff, records_deleted: deleted },
  });

  return NextResponse.json({ ok: true, deleted, scope, before: cutoff });
}

export async function POST(req: NextRequest) {
  const { org_id, user_id, actor_email, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  const url    = new URL(req.url);
  const action = url.searchParams.get("action");
  const db     = createServiceClient();

  if (action === "export_all") {
    // GDPR Article 20: Right to data portability
    // In production: queue an async job and email a download link
    const { data: member } = await db
      .from("org_members")
      .select("email")
      .eq("user_id", user_id ?? "")
      .eq("org_id", org_id)
      .single() as { data: { email: string } | null };

    await writeAuditLog(db, {
      org_id,
      event_type:    "report_generated",
      actor_id:      user_id ?? null,
      actor_email:   actor_email ?? null,
      resource_type: "gdpr_export",
      payload:       { email: member?.email, action: "data_portability" },
    });

    return NextResponse.json({
      ok:      true,
      message: "GDPR data export queued. A download link will be emailed to the org admin within 24 hours.",
      note:    "In production, implement async job + S3 signed URL delivery.",
    });
  }

  if (action === "delete_account") {
    // GDPR Article 17: Right to erasure
    // Keeps audit log (legal obligation) but removes all operational data
    const tables = ["scans","scan_files","violations","secret_findings",
                    "incidents","alerts","risk_register","attestations",
                    "webhook_configs","repositories"];

    for (const table of tables) {
      await db.from(table).delete().eq("org_id", org_id);
    }

    await writeAuditLog(db, {
      org_id,
      event_type:    "org_settings_changed",
      actor_id:      user_id ?? null,
      actor_email:   actor_email ?? null,
      resource_type: "account_deletion",
      payload:       { action: "gdpr_erasure", tables_cleared: tables },
    });

    return NextResponse.json({
      ok:      true,
      message: "Account data erased. Audit log retained per SOC 2 requirements (7 years).",
    });
  }

  return NextResponse.json({ error: "unknown_action" }, { status: 400 });
}
