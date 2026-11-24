/**
 * GET   /api/evidence/[id]  — fetch a single evidence record
 * PATCH /api/evidence/[id]  — lifecycle transition: verify | revoke | refresh
 *
 * Actions (body.action):
 *   "verify"  — recompute the content hash from body.payload and update status
 *   "revoke"  — mark the record revoked; body.reason is required
 *   "refresh" — collect a new record superseding this one; returns the new id
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey, requirePermission } from "../../_middleware";
import { writeAuditLog } from "@/lib/audit";
import { safeError } from "@/lib/errors";
import {
  rowToEvidenceRecord,
  evidenceRecordToRow,
  buildEvidenceRecord,
  verifyRecord,
  markVerified,
  markRevoked,
  canonicalPayload,
} from "@/lib/evidenceRecord";
import crypto from "crypto";

type Params = { params: Promise<{ id: string }> };

async function fetchRow(db: ReturnType<typeof createServiceClient>, id: string, orgId: string) {
  return db
    .from("evidence_log")
    .select("id, org_id, framework_id, control_id, note, file_url, collected_by, collected_by_email, created_at")
    .eq("id", id)
    .eq("org_id", orgId)
    .single() as unknown as Promise<{ data: Record<string, unknown> | null; error: unknown }>;
}

export async function GET(req: NextRequest, { params }: Params) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });

  const { id } = await params;
  const db = createServiceClient();
  const { data: row, error } = await fetchRow(db, id, auth.org_id);
  if (error || !row) return NextResponse.json({ error: "not_found" }, { status: 404 });

  const record = rowToEvidenceRecord(row as unknown as Parameters<typeof rowToEvidenceRecord>[0]);
  if (!record) return NextResponse.json({ error: "legacy_record_format" }, { status: 422 });

  return NextResponse.json({ record });
}

export async function PATCH(req: NextRequest, { params }: Params) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });
  const roleErr = await requirePermission(auth, "can_export_data");
  if (roleErr) return NextResponse.json({ error: roleErr }, { status: 403 });

  const { id } = await params;
  const db = createServiceClient();
  const { data: row, error: fetchErr } = await fetchRow(db, id, auth.org_id);
  if (fetchErr || !row) return NextResponse.json({ error: "not_found" }, { status: 404 });

  const record = rowToEvidenceRecord(row as unknown as Parameters<typeof rowToEvidenceRecord>[0]);
  if (!record) return NextResponse.json({ error: "legacy_record_format" }, { status: 422 });

  type Body = { action: "verify" | "revoke" | "refresh"; payload?: string; reason?: string };
  let body: Body;
  try {
    body = await req.json() as Body;
  } catch {
    return NextResponse.json({ error: "invalid_json" }, { status: 400 });
  }

  // ── verify ────────────────────────────────────────────────────────────────
  if (body.action === "verify") {
    if (!body.payload) return NextResponse.json({ error: "missing_payload" }, { status: 400 });
    const valid = verifyRecord(record, body.payload);
    const updated = markVerified(record);
    const updatedRow = evidenceRecordToRow(updated);

    await db.from("evidence_log").update({ note: updatedRow.note }).eq("id", id).eq("org_id", auth.org_id);

    await writeAuditLog(db, {
      org_id: auth.org_id, event_type: "evidence_collected",
      actor_id: auth.user_id ?? null, actor_email: auth.actor_email ?? null,
      resource_type: "evidence_log", resource_id: id,
      payload: { action: "verify", hash_match: valid, status: updated.verification_status },
    });

    return NextResponse.json({ ok: true, hash_match: valid, verification_status: updated.verification_status });
  }

  // ── revoke ────────────────────────────────────────────────────────────────
  if (body.action === "revoke") {
    if (!body.reason) return NextResponse.json({ error: "missing_reason" }, { status: 400 });
    const updated = markRevoked(record, body.reason);
    const updatedRow = evidenceRecordToRow(updated);

    await db.from("evidence_log").update({ note: updatedRow.note }).eq("id", id).eq("org_id", auth.org_id);

    await writeAuditLog(db, {
      org_id: auth.org_id, event_type: "evidence_deleted",
      actor_id: auth.user_id ?? null, actor_email: auth.actor_email ?? null,
      resource_type: "evidence_log", resource_id: id,
      payload: { action: "revoke", reason: body.reason },
    });

    return NextResponse.json({ ok: true, verification_status: "revoked" });
  }

  // ── refresh ───────────────────────────────────────────────────────────────
  if (body.action === "refresh") {
    // Revoke the old record first (superseded).
    const revoked = markRevoked(record, `superseded by refresh at ${new Date().toISOString()}`);
    await db.from("evidence_log").update({ note: evidenceRecordToRow(revoked).note }).eq("id", id).eq("org_id", auth.org_id);

    // Collect a fresh record with the same identity fields.
    const now = new Date();
    const fresh = buildEvidenceRecord({
      evidence_id:         crypto.randomUUID(),
      org_id:              record.org_id,
      framework:           record.framework,
      control_id:          record.control_id,
      evidence_type:       record.evidence_type,
      evidence_source:     record.evidence_source,
      repository_id:       record.repository_id,
      commit_sha:          record.commit_sha,
      scan_id:             record.scan_id,
      attestation_id:      record.attestation_id,
      collection_timestamp: now.toISOString(),
      collector_identity:  auth.user_id ?? "system",
      note:                `Refreshed from ${id}`,
    });

    const { data: inserted, error: insertErr } = await db
      .from("evidence_log")
      .insert(evidenceRecordToRow(fresh))
      .select("id, created_at")
      .single() as { data: { id: string; created_at: string } | null; error: unknown };

    if (insertErr || !inserted) return safeError(insertErr, { code: "refresh_failed", message: "Could not create a refreshed record." });

    await writeAuditLog(db, {
      org_id: auth.org_id, event_type: "evidence_collected",
      actor_id: auth.user_id ?? null, actor_email: auth.actor_email ?? null,
      resource_type: "evidence_log", resource_id: inserted.id,
      payload: { action: "refresh", supersedes: id, content_hash: fresh.content_hash },
    });

    return NextResponse.json({ ok: true, new_evidence_id: inserted.id, content_hash: fresh.content_hash, expiration_date: fresh.expiration_date }, { status: 201 });
  }

  return NextResponse.json({ error: "unknown_action", valid_actions: ["verify", "revoke", "refresh"] }, { status: 400 });
}
