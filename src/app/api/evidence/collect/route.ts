/**
 * Control evidence (lib/controlEvidence.ts, loaded by lib/evidenceEngine.ts)
 *
 * POST /api/evidence/collect → record manually collected evidence for a control
 * GET  /api/evidence/collect?framework=soc2&period_start=...&period_end=...
 *       → the evidence package for the audit period
 * GET  /api/evidence/collect?overview=1 → every applicable framework's control statuses and the distinct gaps
 *
 * `framework` accepts soc2 | iso27001 | pcidss | aigov (case-insensitive, defaults to soc2; the old "euai"
 * maps to aigov). /api/report uses the same engine for the PDF.
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey, requirePermission } from "../../_middleware";
import { writeAuditLog } from "@/lib/audit";
import { safeError } from "@/lib/errors";
import { collectEvidence, collectEvidenceOverview } from "@/lib/evidenceEngine";

export async function GET(req: NextRequest) {
  const { org_id, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  const params       = req.nextUrl.searchParams;
  const framework    = params.get("framework") ?? "soc2";
  const periodStart  = params.get("period_start") ?? new Date(Date.now() - 90 * 86400_000).toISOString();
  const periodEnd    = params.get("period_end")   ?? new Date().toISOString();

  try {
    if (params.get("overview") === "1") return NextResponse.json(await collectEvidenceOverview(org_id, periodStart, periodEnd));
    return NextResponse.json(await collectEvidence(org_id, framework, periodStart, periodEnd));
  } catch (err) {
    return safeError(err, { code: "evidence_failed", message: "We couldn't collect the evidence right now. Please try again." });
  }
}

export async function POST(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });
  const roleErr = await requirePermission(auth, "can_export_data");
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
