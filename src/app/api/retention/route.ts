/**
 * Data Retention Policy API
 * GET  /api/retention  → the org's policy (lib/retention.ts), with the last automatic run
 * PATCH /api/retention → update periods / switch automatic enforcement on or off
 * DELETE /api/retention?scope=scans&before=2025-01-01 → delete data now (manual; includes open records)
 * POST  /api/retention?action=export_all → GDPR full data export
 * POST  /api/retention?action=delete_account → GDPR right to erasure
 *
 * Automatic enforcement runs daily from /api/cron/pipeline-health for orgs that switched it on.
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey, requirePermission, requireRole } from "../_middleware";
import { writeAuditLog } from "@/lib/audit";
import { safeError } from "@/lib/errors";
import { loadRetention, normalizeRetention, purgeScansBefore, purgeTableBefore, MIN_DAYS, MAX_DAYS } from "@/lib/retention";

export async function GET(req: NextRequest) {
  const { org_id, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });
  const policy = await loadRetention(createServiceClient(), org_id);
  return NextResponse.json({
    policy,
    bounds: { min_days: MIN_DAYS, max_days: MAX_DAYS },
    note:   "Retention periods in days. Automatic enforcement never deletes attested scans, open items, or the audit log.",
  });
}

export async function PATCH(req: NextRequest) {
  const auth = await verifyApiKey(req);
  const { org_id, user_id, actor_email, error } = auth;
  if (error) return NextResponse.json({ error }, { status: 401 });
  const permErr = await requirePermission(auth, "can_manage_policies");
  if (permErr) return NextResponse.json({ error: permErr }, { status: 403 });

  const raw = await req.json().catch(() => ({})) as Record<string, unknown>;
  const db  = createServiceClient();
  const current = await loadRetention(db, org_id);
  // Only the periods and the switch are settable; the last-run fields are written by the cron alone.
  const { last_enforced_at: _a, last_result: _b, ...settable } = raw;
  const next = normalizeRetention({ ...current, ...settable }, current);
  next.last_enforced_at = current.last_enforced_at ?? null;
  next.last_result = current.last_result ?? null;

  const { error: saveErr } = await db.from("organizations").update({ retention_policy: next }).eq("id", org_id);
  if (saveErr) return safeError(saveErr, { code: "retention_save_failed", message: "We couldn't save the retention policy. Please try again." });

  await writeAuditLog(db, {
    org_id,
    event_type:    "org_settings_changed",
    actor_id:      user_id ?? null,
    actor_email:   actor_email ?? null,
    resource_type: "retention_policy",
    payload:       { from: { ...current, last_result: undefined }, to: { ...next, last_result: undefined } },
  });

  return NextResponse.json({ ok: true, policy: next });
}

export async function DELETE(req: NextRequest) {
  const auth = await verifyApiKey(req);
  const { org_id, user_id, actor_email, error } = auth;
  if (error) return NextResponse.json({ error }, { status: 401 });
  const permErr = await requirePermission(auth, "can_manage_policies");
  if (permErr) return NextResponse.json({ error: permErr }, { status: 403 });

  const url    = new URL(req.url);
  const scope  = url.searchParams.get("scope");   // scans | violations | secrets | incidents | alerts | all
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

  // Attested scans can never be deleted (attestations are immutable by DB rule): only unreviewed scans go.
  if (scope === "scans" || scope === "all") {
    const r = await purgeScansBefore(db, org_id, cutoff, 1000);
    deleted += r.deleted;
    if (r.failed) skipped.scans = "delete failed";
    else if (r.retained_attested > 0) skipped.scans = `${r.retained_attested} attested scan(s) retained (cannot be deleted)`;
  }

  // A manual delete is an explicit decision, so it includes records that are still open.
  const otherTables: Record<string, string> = {
    violations: "violations", secrets: "secret_findings", incidents: "incidents", alerts: "alerts",
  };
  const targetOther = scope === "all" ? Object.values(otherTables) : [otherTables[scope]].filter(Boolean);
  for (const table of targetOther) {
    const r = await purgeTableBefore(db, org_id, table, cutoff, true);
    if (r.failed) skipped[table] = "delete failed";
    else deleted += r.deleted;
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
  const auth = await verifyApiKey(req);
  const { org_id, user_id, actor_email, error } = auth;
  if (error) return NextResponse.json({ error }, { status: 401 });

  const url    = new URL(req.url);
  const action = url.searchParams.get("action");
  // Erasing the whole org's data is an admin decision no permission flag can grant; a full export needs export rights.
  const permErr = action === "delete_account" ? requireRole(auth, "admin")
    : action === "export_all" ? await requirePermission(auth, "can_export_data") : null;
  if (permErr) return NextResponse.json({ error: permErr }, { status: 403 });
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
