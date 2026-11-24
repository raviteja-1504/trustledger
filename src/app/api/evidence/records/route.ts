/**
 * GET  /api/evidence/records
 *   Returns evidence records for the caller's org.
 *   Query params:
 *     framework   – filter by framework_id (e.g. "soc2")
 *     control_id  – filter by control_id
 *     status      – filter by verification_status
 *     limit       – max rows (default 100, max 500)
 *     offset      – pagination offset (default 0)
 *
 * POST /api/evidence/records
 *   Collect a new evidence record.
 *   Requires can_export_data permission.
 *   Body: { framework, control_id, evidence_type, evidence_source, repository_id?,
 *           commit_sha?, scan_id?, attestation_id?, note? }
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey, requirePermission } from "../../_middleware";
import { writeAuditLog } from "@/lib/audit";
import { safeError } from "@/lib/errors";
import {
  buildEvidenceRecord,
  evidenceRecordToRow,
  rowToEvidenceRecord,
  type EvidenceType,
} from "@/lib/evidenceRecord";
import { getFrameworkMapping } from "@/lib/controlMapping";
import crypto from "crypto";

export async function GET(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });

  const p = req.nextUrl.searchParams;
  const framework  = p.get("framework");
  const control_id = p.get("control_id");
  const status     = p.get("status");
  const limit      = Math.min(500, Math.max(1, parseInt(p.get("limit") ?? "100", 10)));
  const offset     = Math.max(0, parseInt(p.get("offset") ?? "0", 10));

  const db = createServiceClient();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let q = (db as any)
    .from("evidence_log")
    .select("id, org_id, framework_id, control_id, note, file_url, collected_by, collected_by_email, created_at")
    .eq("org_id", auth.org_id)
    .order("created_at", { ascending: false })
    .range(offset, offset + limit - 1);

  if (framework)  q = q.eq("framework_id", framework);
  if (control_id) q = q.eq("control_id", control_id);

  const { data, error } = await q as { data: Array<Record<string, unknown>> | null; error: unknown };
  if (error) return safeError(error, { code: "records_fetch_failed", message: "Could not fetch evidence records." });

  const records = (data ?? [])
    .map(row => rowToEvidenceRecord(row as Parameters<typeof rowToEvidenceRecord>[0]))
    .filter(r => r !== null)
    .filter(r => !status || r!.verification_status === status);

  return NextResponse.json({ records, total: records.length, offset, limit });
}

export async function POST(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });
  const roleErr = await requirePermission(auth, "can_export_data");
  if (roleErr) return NextResponse.json({ error: roleErr }, { status: 403 });

  type Body = {
    framework:      string;
    control_id:     string;
    evidence_type:  EvidenceType;
    evidence_source: string;
    repository_id?: string;
    commit_sha?:    string;
    scan_id?:       string;
    attestation_id?: string;
    note?:          string;
  };

  let body: Body;
  try {
    body = await req.json() as Body;
  } catch {
    return NextResponse.json({ error: "invalid_json" }, { status: 400 });
  }

  if (!body.framework || !body.control_id || !body.evidence_type || !body.evidence_source) {
    return NextResponse.json({ error: "missing_required_fields", required: ["framework", "control_id", "evidence_type", "evidence_source"] }, { status: 400 });
  }

  // Validate that the control exists in the framework mapping.
  const fw = getFrameworkMapping(body.framework);
  if (!fw) {
    return NextResponse.json({ error: "unknown_framework", supported: ["soc2", "iso27001", "pcidss", "aigov"] }, { status: 400 });
  }
  const ctrl = fw.controls.find(c => c.control_id === body.control_id);
  if (!ctrl) {
    return NextResponse.json({ error: "unknown_control_id", framework: fw.framework_id, valid_controls: fw.controls.map(c => c.control_id) }, { status: 400 });
  }

  const now = new Date();
  const record = buildEvidenceRecord({
    evidence_id:         crypto.randomUUID(),
    org_id:              auth.org_id,
    framework:           fw.framework_id,
    control_id:          body.control_id,
    evidence_type:       body.evidence_type,
    evidence_source:     body.evidence_source,
    repository_id:       body.repository_id,
    commit_sha:          body.commit_sha,
    scan_id:             body.scan_id,
    attestation_id:      body.attestation_id,
    collection_timestamp: now.toISOString(),
    collector_identity:  auth.user_id ?? "system",
    note:                body.note,
  });

  const row = evidenceRecordToRow(record);
  const db = createServiceClient();

  const { data: inserted, error } = await db
    .from("evidence_log")
    .insert(row)
    .select("id, created_at")
    .single() as { data: { id: string; created_at: string } | null; error: unknown };

  if (error || !inserted) {
    return safeError(error, { code: "evidence_insert_failed", message: "Could not store the evidence record." });
  }

  await writeAuditLog(db, {
    org_id:        auth.org_id,
    event_type:    "evidence_collected",
    actor_id:      auth.user_id ?? null,
    actor_email:   auth.actor_email ?? null,
    resource_type: "evidence_log",
    resource_id:   inserted.id,
    payload: {
      framework:    fw.framework_id,
      control_id:   body.control_id,
      evidence_type: body.evidence_type,
      content_hash:  record.content_hash,
    },
  });

  return NextResponse.json({
    ok:              true,
    evidence_id:     inserted.id,
    content_hash:    record.content_hash,
    expiration_date: record.expiration_date,
    collected_at:    inserted.created_at,
    scope_disclaimer: fw.scope_disclaimer,
  }, { status: 201 });
}
