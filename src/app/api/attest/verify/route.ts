/**
 * GET /api/attest/verify?id=<attestation-uuid>
 *
 * Independent verification endpoint (task spec D): loads the attestation record,
 * verifies the Ed25519 signature against the stored canonical payload, and reports
 * the result without trusting application-layer state beyond what the DB record holds.
 *
 * The attestation must belong to the caller's org (enforced by the .eq("org_id", …)
 * filter — the signing_keys lookup that follows is then "parent-verified" because
 * signing_key_id came from that org-scoped row).
 *
 * Possible verify_result values:
 *   "valid"         — signature OK, payload intact
 *   "no_signature"  — pre-signing attestation (hash-only record, created before
 *                     ATTESTATION_SIGNING_KEY was set in the deployment environment)
 *   "invalid"       — signature present but cryptographically invalid (payload tampered)
 *   "key_not_found" — signing_key_id references a deleted key row
 *   "key_revoked"   — signing key was explicitly revoked (treat as untrusted)
 *   "key_retired"   — signing key retired (rotation); signature is still cryptographically
 *                     valid but the key is no longer in active use
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey } from "../../_middleware";
import {
  verifyAttestation,
  validatePayloadSchema,
  checkPayloadDbBinding,
  type CanonicalAttestationPayload,
} from "@/lib/attestationSigning";

export async function GET(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });

  const id = req.nextUrl.searchParams.get("id");
  if (!id) return NextResponse.json({ error: "missing parameter: id" }, { status: 400 });

  const db = createServiceClient();

  const { data: att } = await db
    .from("attestations")
    .select("id, scan_id, file_path, reviewer_email, payload_hash, payload_json, signature, signing_key_id, created_at")
    .eq("id", id)
    .eq("org_id", auth.org_id)
    .single();

  if (!att) return NextResponse.json({ error: "not_found" }, { status: 404 });

  const attTyped = att as {
    signature:      string | null;
    signing_key_id: string | null;
    payload_json:   CanonicalAttestationPayload | null;
  };

  const { result: cryptoResult } = await verifyAttestation(db, {
    signature:      attTyped.signature,
    signing_key_id: attTyped.signing_key_id,
    payload_json:   attTyped.payload_json,
  });

  // For records with a valid (or key_retired) cryptographic signature, additionally
  // verify that every signed payload field matches the corresponding database column.
  // A valid signature only proves the payload was not altered after signing; it does
  // not prove the payload actually describes THIS attestation row — an attacker with
  // DB write access could substitute a legitimately-signed payload from a different record.
  let verifyResult = cryptoResult;
  if (cryptoResult === "valid" || cryptoResult === "key_retired") {
    const payload = attTyped.payload_json!;

    if (!validatePayloadSchema(payload)) {
      verifyResult = "payload_schema_invalid";
    } else {
      // Load the scan to verify repo and commit_sha (fields not stored on the attestation row).
      const { data: scan } = await db
        .from("scans")
        .select("repo_full_name, commit_sha")
        .eq("id", att.scan_id)
        .eq("org_id", auth.org_id)
        .maybeSingle();

      const binding = checkPayloadDbBinding(
        payload,
        {
          scan_id:        att.scan_id,
          file_path:      att.file_path,
          reviewer_email: att.reviewer_email,
          signing_key_id: attTyped.signing_key_id,
        },
        auth.org_id,
        scan ? { repo_full_name: scan.repo_full_name as string, commit_sha: scan.commit_sha as string | null } : undefined,
      );

      if (binding !== "ok") verifyResult = "payload_db_mismatch";
    }
  }

  return NextResponse.json({
    id:             att.id,
    scan_id:        att.scan_id,
    file_path:      att.file_path,
    reviewer_email: att.reviewer_email,
    created_at:     att.created_at,
    payload_hash:   att.payload_hash,
    has_signature:  !!attTyped.signature,
    verify_result:  verifyResult,
  });
}
