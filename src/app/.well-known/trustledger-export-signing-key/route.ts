/**
 * GET /.well-known/trustledger-export-signing-key
 *
 * Publishes this deployment's Ed25519 PUBLIC key, so anyone can verify a signed Trust Record or audit-log
 * export without a shared secret and without trusting us. Returns the key id, the PEM, the algorithm, and a
 * pointer to the offline verifier. Public and unauthenticated by design -- a public key reveals nothing.
 *
 * 404 when no signing key is configured (documents are then HMAC-signed or unsigned).
 */
import { NextResponse } from "next/server";
import { exportPublicKey } from "@/lib/exportSigning";

export function GET() {
  const pub = exportPublicKey();
  if (!pub) return NextResponse.json({ error: "no_signing_key", message: "This deployment has no public signing key configured." }, { status: 404 });
  return NextResponse.json({
    algorithm: pub.algorithm,
    key_id: pub.key_id,
    public_key_pem: pub.public_key_pem,
    signed_content: "canonical JSON of the document's `record`: object keys sorted at every level, no whitespace",
    verify: "Reconstruct the canonical JSON of `record`, base64-decode signature.value, and Ed25519-verify with this public key. Check signature.key_id equals key_id above. See scripts/verify-trust-record.mjs.",
  }, { headers: { "Cache-Control": "public, max-age=3600" } });
}
