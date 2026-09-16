/**
 * Real Evidence Auto-Collection
 * Maps TrustLedger scan data to each framework's control set.
 *
 * POST /api/evidence/collect → collect evidence for a specific control
 * GET  /api/evidence/collect?framework=soc2&period_start=...&period_end=...
 *       → generate a full evidence package for the audit period
 *
 * `framework` accepts soc2 | euai | pcidss | iso27001 (case-insensitive,
 * defaults to soc2). Every framework's controls are computed from the
 * same real signals -- no framework gets a fabricated number. The actual
 * computation lives in lib/evidenceEngine.ts so /api/report can reuse the
 * exact same real per-control scores in the generated PDF instead of a
 * third, independently-invented formula.
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey, requireRole } from "../../_middleware";
import { writeAuditLog } from "@/lib/audit";
import { safeError } from "@/lib/errors";
import { collectEvidence } from "@/lib/evidenceEngine";

export async function GET(req: NextRequest) {
  const { org_id, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  const url          = new URL(req.url);
  const framework    = url.searchParams.get("framework") ?? "soc2";
  const periodStart  = url.searchParams.get("period_start") ?? new Date(Date.now() - 90 * 86400_000).toISOString();
  const periodEnd    = url.searchParams.get("period_end")   ?? new Date().toISOString();

  const pkg = await collectEvidence(org_id, framework, periodStart, periodEnd);
  return NextResponse.json(pkg);
}

export async function POST(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });
  const roleErr = requireRole(auth, "security_reviewer");
  if (roleErr) return NextResponse.json({ error: roleErr }, { status: 403 });

  const body = await req.json() as {
    control_id:   string;
    framework_id: string;
    notes?:       string;
    url?:         string;
  };

  if (!body.control_id) return NextResponse.json({ error:"missing_control_id" }, { status:400 });

  const db = createServiceClient();

  // Append-only evidence log entry -- previously this wrote a fake
  // "resolved" row into compliance_exceptions (a table meant for tracked
  // control gaps, not evidence), which also had no unique constraint
  // matching the upsert's onConflict target and would error. Real table,
  // real record: who collected what evidence for which control, when.
  const { data, error } = await db
    .from("evidence_log")
    .insert({
      org_id:             auth.org_id,
      framework_id:       body.framework_id ?? "soc2",
      control_id:         body.control_id,
      note:               body.notes ?? null,
      file_url:           body.url ?? null,
      collected_by:       auth.user_id ?? null,
      collected_by_email: auth.actor_email ?? null,
    })
    .select("id, created_at")
    .single() as { data: { id: string; created_at: string } | null; error: unknown };

  if (error || !data) return safeError(error, { code: "evidence_collect_failed", message: "We couldn't record that evidence. Please try again." });

  await writeAuditLog(db, {
    org_id: auth.org_id!, event_type: "evidence_collected",
    actor_id: auth.user_id ?? null, actor_email: auth.actor_email ?? null,
    resource_type: "evidence_log", resource_id: data.id,
    payload: { control_id: body.control_id, framework_id: body.framework_id ?? "soc2" },
  });

  return NextResponse.json({ ok: true, control_id: body.control_id, collected_at: data.created_at });
}
