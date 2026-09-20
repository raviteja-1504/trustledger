import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey } from "../_middleware";
import { validateBody, AttestSchema } from "@/lib/validation";
import { checkRateLimit, RATE_LIMITS } from "@/lib/rateLimit";
import { safeError } from "@/lib/errors";
import { performAttestation } from "@/lib/attestation";

export async function POST(req: NextRequest) {
  const { org_id, user_id, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  const rl = await checkRateLimit(org_id, RATE_LIMITS.attest);
  if (!rl.success) {
    return NextResponse.json({ error: "rate_limited" }, { status: 429, headers: rl.headers });
  }

  const validation = await validateBody(req, AttestSchema);
  if (!validation.ok) return validation.response;
  const body = validation.data;

  const db = createServiceClient();
  const result = await performAttestation(db, {
    org_id,
    user_id,
    scan_id:         body.scan_id,
    file_path:       body.file_path,
    reviewer_email:  body.reviewer_email,
    reviewer_github: body.reviewer_github,
  });

  if (!result.ok) {
    if (result.reason === "scan_not_found") {
      return NextResponse.json({ error: "scan_not_found" }, { status: 404 });
    }
    return safeError(result.detail, { code: "attestation_failed", message: "We couldn't record this attestation. Please try again." });
  }

  return NextResponse.json({
    attestation_id: result.attestation_id,
    payload_hash:   result.payload_hash,
    attested_at:    result.attested_at,
    file_path:      body.file_path,
    reviewer_email: body.reviewer_email,
  });
}
