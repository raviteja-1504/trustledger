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
import { verifyAttestation, type CanonicalAttestationPayload } from "@/lib/attestationSigning";

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

  const { result } = await verifyAttestation(db, {
    signature:      (att as { signature: string | null }).signature,
    signing_key_id: (att as { signing_key_id: string | null }).signing_key_id,
    payload_json:   (att as { payload_json: CanonicalAttestationPayload | null }).payload_json,
  });

  return NextResponse.json({
    id:             att.id,
    scan_id:        att.scan_id,
    file_path:      att.file_path,
    reviewer_email: att.reviewer_email,
    created_at:     att.created_at,
    payload_hash:   att.payload_hash,
    has_signature:  !!(att as { signature: string | null }).signature,
    verify_result:  result,
  });
}
