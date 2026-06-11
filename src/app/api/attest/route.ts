import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey } from "../_middleware";
import { buildAttestationHash } from "@/lib/scanner";
import { writeAuditLog } from "@/lib/audit";
import { cacheDel, cacheKeys } from "@/lib/cache";
import { validateBody, AttestSchema } from "@/lib/validation";

export async function POST(req: NextRequest) {
  const { org_id, user_id, actor_email, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  const validation = await validateBody(req, AttestSchema);
  if (!validation.ok) return validation.response;
  const body = validation.data;

  const db = createServiceClient();
  const now = new Date().toISOString();

  // Verify scan belongs to this org
  const { data: scan } = await db
    .from("scans")
    .select("id, repo_full_name, overall_risk")
    .eq("id", body.scan_id)
    .eq("org_id", org_id)
    .single();

  if (!scan) return NextResponse.json({ error: "scan_not_found" }, { status: 404 });

  // Get file risk level
  const { data: file } = await db
    .from("scan_files")
    .select("risk_score")
    .eq("scan_id", body.scan_id)
    .eq("file_path", body.file_path)
    .single();

  // Build cryptographic payload hash
  const payloadHash = buildAttestationHash(
    body.scan_id, body.file_path, body.reviewer_email, now,
  );

  // Insert immutable attestation record
  const { data: attestation, error: attErr } = await db
    .from("attestations")
    .insert({
      org_id,
      scan_id:         body.scan_id,
      file_path:       body.file_path,
      risk_score:      file?.risk_score ?? "UNKNOWN",
      reviewer_id:     user_id ?? null,
      reviewer_email:  body.reviewer_email,
      reviewer_github: body.reviewer_github ?? null,
      payload_hash:    payloadHash,
    })
    .select("id, created_at")
    .single();

  if (attErr || !attestation) {
    return NextResponse.json({ error: "attestation_failed", detail: attErr?.message }, { status: 500 });
  }

  // Update violation status to resolved
  await db
    .from("violations")
    .update({ status: "resolved", resolved_at: now, resolved_by: user_id ?? null })
    .eq("scan_id", body.scan_id)
    .eq("file_path", body.file_path);

  // Audit log
  await writeAuditLog(db, {
    org_id,
    event_type:    "attestation",
    actor_id:      user_id ?? null,
    actor_email:   body.reviewer_email,
    resource_type: "attestation",
    resource_id:   attestation.id,
    payload: {
      scan_id:     body.scan_id,
      file_path:   body.file_path,
      repo:        scan.repo_full_name,
      risk_score:  file?.risk_score ?? "UNKNOWN",
      payload_hash: payloadHash,
    },
  });

  // Invalidate dashboard cache so new attestation is reflected immediately
  await cacheDel(cacheKeys.dashboard(org_id, 90));
  await cacheDel(cacheKeys.dashboard(org_id, 30));

  return NextResponse.json({
    attestation_id: attestation.id,
    payload_hash:   payloadHash,
    attested_at:    attestation.created_at,
    file_path:      body.file_path,
    reviewer_email: body.reviewer_email,
  });
}
