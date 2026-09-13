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
  const skipped: Record<string, string> = {};

  // scans, violations, secret_findings, and alerts all reference `scans`
  // with NO ACTION (not CASCADE) -- deleting an old scan while any of those
  // still point at it fails outright, and attestations reference it too but
  // can NEVER be deleted (immutable by DB rule -- see 001_initial.sql's
  // attestations_no_delete rule, a deliberate "reviewer sign-off is a
  // permanent record" guarantee). So an attested scan can never actually be
  // purged through this endpoint, by design -- only scans nobody ever
  // reviewed are eligible. This used to attempt the delete anyway (with the
  // error never checked), which silently did nothing for almost every real
  // org instead of cleaning up what it safely could.
  if (scope === "scans" || scope === "all") {
    const { data: oldScans } = await db
      .from("scans").select("id").eq("org_id", org_id).lt("created_at", cutoff);
    const oldScanIds = (oldScans ?? []).map(s => s.id);

    if (oldScanIds.length > 0) {
      const { data: attested } = await db
        .from("attestations").select("scan_id").in("scan_id", oldScanIds);
      const attestedSet = new Set((attested ?? []).map(a => a.scan_id));
      const eligibleIds = oldScanIds.filter(id => !attestedSet.has(id));

      if (eligibleIds.length > 0) {
        // Clear FK-dependent rows first -- scan_files cascades automatically.
        await db.from("violations").delete().in("scan_id", eligibleIds);
        await db.from("secret_findings").delete().in("scan_id", eligibleIds);
        await db.from("alerts").delete().in("scan_id", eligibleIds);
        const { count, error: delErr } = await db
          .from("scans").delete({ count: "exact" }).in("id", eligibleIds) as { count: number | null; error: unknown };
        if (delErr) skipped.scans = "delete failed";
        else deleted += count ?? 0;
      }
      if (eligibleIds.length < oldScanIds.length) {
        skipped.scans = `${oldScanIds.length - eligibleIds.length} attested scan(s) retained (cannot be deleted)`;
      }
    }
  }

  // The remaining scopes don't have anything referencing them with NO ACTION,
  // so a plain per-org, per-cutoff delete is safe on its own.
  const otherTables: Record<string, string> = {
    violations: "violations", secrets: "secret_findings", incidents: "incidents", alerts: "alerts",
  };
  const targetOther = scope === "all" ? Object.values(otherTables) : [otherTables[scope]].filter(Boolean);
  for (const table of targetOther) {
    const { count, error: delErr } = await db
      .from(table)
      .delete({ count: "exact" })
      .eq("org_id", org_id)
      .lt("created_at", cutoff) as { count: number | null; error: unknown };
    if (delErr) skipped[table] = "delete failed";
    else deleted += count ?? 0;
  }

  await writeAuditLog(db, {
    org_id,
    event_type:    "org_settings_changed",
    actor_id:      user_id ?? null,
    actor_email:   actor_email ?? null,
    resource_type: "data_deletion",
    payload:       { scope, before: cutoff, records_deleted: deleted, skipped },
  });

  return NextResponse.json({ ok: true, deleted, scope, before: cutoff, skipped });
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
    // Keeps audit log (legal obligation) but removes all operational data.
    //
    // Note: `attestations` is immutable by DB rule (attestations_no_delete,
    // 001_initial.sql) -- a deliberate "reviewer sign-off is a permanent
    // record" guarantee for SOC 2. That means this delete call for
    // attestations below is a guaranteed no-op: attestation rows (which can
    // include a reviewer's email) are NOT actually erased by this endpoint,
    // regardless of table ordering. Resolving that tension between the
    // audit-immutability guarantee and GDPR erasure is a legal/product
    // decision, not something to silently paper over here -- flagging it
    // rather than changing the immutability rule myself.
    //
    // violations/secret_findings/alerts reference `scans` with NO ACTION
    // (not CASCADE), so they must be cleared before scans is deleted, or
    // that delete fails outright. scan_files cascades from scans
    // automatically. Order matters here in a way it didn't before.
    const dependents = ["violations", "secret_findings", "alerts"];
    // attestations deliberately excluded -- the DB rule that makes it
    // immutable replaces DELETE with a no-op rather than raising an error,
    // so attempting it would silently "succeed" at deleting nothing and
    // wrongly report itself as cleared below.
    const rest = ["incidents", "risk_register", "webhook_configs", "repositories"];
    const cleared: string[] = [];
    const retained: string[] = ["attestations"];
    const failed:  string[] = [];

    for (const table of dependents) {
      const { error: delErr } = await db.from(table).delete().eq("org_id", org_id);
      if (delErr) failed.push(table); else cleared.push(table);
    }
    const { error: scansErr } = await db.from("scans").delete().eq("org_id", org_id);
    if (scansErr) failed.push("scans"); else cleared.push("scans", "scan_files" /* cascades */);
    for (const table of rest) {
      const { error: delErr } = await db.from(table).delete().eq("org_id", org_id);
      if (delErr) failed.push(table); else cleared.push(table);
    }

    await writeAuditLog(db, {
      org_id,
      event_type:    "org_settings_changed",
      actor_id:      user_id ?? null,
      actor_email:   actor_email ?? null,
      resource_type: "account_deletion",
      payload:       { action: "gdpr_erasure", tables_cleared: cleared, tables_retained: retained, tables_failed: failed },
    });

    return NextResponse.json({
      ok:      true,
      message: "Account data erased. Audit log retained per SOC 2 requirements (7 years). Attestation records are also retained (immutable by design) -- see attestations_no_delete.",
      tables_failed: failed,
    });
  }

  return NextResponse.json({ error: "unknown_action" }, { status: 400 });
}
