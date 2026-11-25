/**
 * Ed25519 signing and verification for attestation payloads.
 *
 * Trust model and production deployment notes
 * -------------------------------------------
 * - Private signing key: loaded from ATTESTATION_SIGNING_KEY env var (PEM, PKCS#8).
 *   In production this env var should reference a secrets-manager entry (Doppler,
 *   AWS Secrets Manager, GCP Secret Manager) rather than a literal PEM value.
 *   KMS/HSM-backed key management requires a signing proxy outside this codebase.
 * - Public keys: stored in the signing_keys table (service-role only; RLS enabled).
 * - Verification is independent: given payload_json + signature any party with the
 *   public key can verify an attestation without trusting this application.
 * - Database-level immutability (Postgres RULE blocks UPDATE/DELETE on attestations)
 *   is best-effort. It does not replace the cryptographic chain: a Supabase project
 *   owner with direct DB access can drop the rules. The cryptographic signature is
 *   the authoritative tamper-evidence record.
 * - Key rotation: generate a new pair, set ATTESTATION_SIGNING_KEY to the new PEM,
 *   then: UPDATE signing_keys SET status = 'retired', retired_at = now() WHERE id = '<old>';
 *   Historical attestations stay verifiable via the retired key's public_key_pem.
 * - Key revocation: same, but status = 'revoked'. The verify endpoint returns "key_revoked"
 *   for any attestation signed with that key.
 */

import crypto from "crypto";
import type { SupabaseClient } from "@supabase/supabase-js";
import { canonicalJson } from "@/lib/audit";

// ── Schema ────────────────────────────────────────────────────────────────────

export const PAYLOAD_SCHEMA_VERSION = 1 as const;

/**
 * All 11 required fields (task spec A) plus schema_version for forward compatibility (spec B).
 * Never reorder or rename fields: canonicalPayloadBytes sorts keys, so the layout is stable,
 * but the field set defines the schema_version boundary.
 */
export interface CanonicalAttestationPayload {
  /** Increment when any field is added, removed, or its semantics change. */
  schema_version:  typeof PAYLOAD_SCHEMA_VERSION;
  /** A.1 — reviewer identity (from org_members, never client-supplied freeform). */
  reviewer_email:  string;
  reviewer_id:     string | null;
  /** A.2 — organisation identity. */
  org_id:          string;
  /** A.3 — repo identifier: "{owner}/{repo}". */
  repo:            string;
  /** A.4 — full 40-hex SHA of the reviewed commit. */
  commit_sha:      string;
  file_path:       string;
  /** A.5 — SHA-256 of the file's content at this commit, or null for deleted/unavailable. */
  content_hash:    string | null;
  /** A.6 — scan identifier. */
  scan_id:         string;
  /** A.7 — SHA-256 of the canonical JSON of the file's finding indicators at sign time. */
  findings_digest: string;
  /** A.8 — review decision. */
  decision:        "attested";
  /** A.9 — fingerprint of the org's merge-gate policy in force at sign time. */
  policy_version:  string;
  /** A.10 — ISO-8601 UTC timestamp. */
  timestamp:       string;
  /** A.11 — UUID of the signing_keys row used. */
  key_id:          string;
}

// ── Pure cryptographic helpers ────────────────────────────────────────────────

/** SHA-256 of the canonical (sorted-key) JSON of an indicators array (spec A.7). */
export function buildFindingsDigest(findings: unknown): string {
  return crypto.createHash("sha256")
    .update(canonicalJson(findings))
    .digest("hex");
}

/**
 * Fingerprint of the org's merge-gate policy (spec A.9).
 * Changes whenever block_on_critical or block_on_high change.
 */
export function buildPolicyVersion(gate: { block_on_critical: boolean; block_on_high: boolean }): string {
  const h = crypto.createHash("sha256")
    .update(canonicalJson(gate))
    .digest("hex")
    .slice(0, 16);
  return `v${PAYLOAD_SCHEMA_VERSION}:${h}`;
}

/** Deterministic UTF-8 bytes for signing: canonical JSON with recursively sorted keys (spec B). */
export function canonicalPayloadBytes(payload: CanonicalAttestationPayload): Buffer {
  return Buffer.from(canonicalJson(payload), "utf8");
}

/** Ed25519 signature over the canonical payload bytes, base64-encoded (spec A). */
export function signCanonicalPayload(payload: CanonicalAttestationPayload, privateKeyPem: string): string {
  const data = canonicalPayloadBytes(payload);
  return crypto.sign(null, data, { key: privateKeyPem, format: "pem" }).toString("base64");
}

/**
 * Verify an Ed25519 signature against a canonical payload (spec D).
 * Returns false for any error (malformed key, bad base64, wrong payload).
 */
export function verifyCanonicalPayload(
  payload:         CanonicalAttestationPayload,
  signatureBase64: string,
  publicKeyPem:    string,
): boolean {
  try {
    return crypto.verify(
      null,
      canonicalPayloadBytes(payload),
      { key: publicKeyPem, format: "pem" },
      Buffer.from(signatureBase64, "base64"),
    );
  } catch {
    return false;
  }
}

/** Generate a fresh Ed25519 key pair (PKCS#8 / SPKI PEM). Useful for key rotation and tests. */
export function generateSigningKeyPair(): { privateKeyPem: string; publicKeyPem: string } {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519", {
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding:  { type: "spki",  format: "pem" },
  });
  return { privateKeyPem: privateKey as string, publicKeyPem: publicKey as string };
}

// ── DB-backed key management (spec C) ─────────────────────────────────────────

export interface SigningKeyRow {
  id:             string;
  public_key_pem: string;
  status:         "active" | "retired" | "revoked";
}

/**
 * Load the platform signing key from ATTESTATION_SIGNING_KEY and ensure its public key
 * is registered in signing_keys. Returns null when:
 *   - the env var is absent (falls back to hash-only attestation mode)
 *   - the PEM is invalid
 *   - the key's signing_keys row is 'revoked'
 *
 * On first call with a new key the row is inserted; on subsequent calls the existing row
 * is returned (unique constraint on public_key_pem prevents duplicates).
 */
export async function ensureSigningKey(
  db: SupabaseClient,
): Promise<{ id: string; privateKeyPem: string } | null> {
  const privateKeyPem = (process.env.ATTESTATION_SIGNING_KEY ?? "").trim();
  if (!privateKeyPem) return null;

  let privateKey: crypto.KeyObject;
  try {
    privateKey = crypto.createPrivateKey(privateKeyPem);
  } catch {
    console.error("ATTESTATION_SIGNING_KEY contains an invalid PEM — attestations will be hash-only");
    return null;
  }

  const publicKeyPem = (
    crypto.createPublicKey(privateKey).export({ type: "spki", format: "pem" }) as string
  ).trim();

  // Look for the key's existing row first; insert only if absent.
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let { data: key } = await (db.from("signing_keys") as any)
    .select("id, status")
    .is("org_id", null)
    .eq("public_key_pem", publicKeyPem)
    .maybeSingle() as { data: Pick<SigningKeyRow, "id" | "status"> | null };

  if (!key) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const { data: inserted } = await (db.from("signing_keys") as any)
      .insert({ org_id: null, algorithm: "ed25519", public_key_pem: publicKeyPem, status: "active" })
      .select("id, status")
      .single() as { data: Pick<SigningKeyRow, "id" | "status"> | null };
    // If the insert races with another instance and hits the unique constraint, fall back to select.
    if (!inserted) {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const { data: raced } = await (db.from("signing_keys") as any)
        .select("id, status")
        .is("org_id", null)
        .eq("public_key_pem", publicKeyPem)
        .single() as { data: Pick<SigningKeyRow, "id" | "status"> | null };
      key = raced;
    } else {
      key = inserted;
    }
  }

  // Retired keys must not sign new attestations (they remain verifiable for historical records,
  // but only the currently-configured key — marked active — may produce new signatures).
  if (!key || key.status === "revoked" || key.status === "retired") return null;
  return { id: key.id, privateKeyPem };
}

// ── Verification (spec D) ─────────────────────────────────────────────────────

export type VerifyResult =
  | "valid"                      // signature OK and payload matches DB record
  | "no_signature"               // pre-signing attestation (payload_json or signature is null)
  | "invalid"                    // signature present but cryptographically invalid
  | "key_not_found"              // signing_key_id references a row that no longer exists
  | "key_revoked"                // key was explicitly revoked (spec C: revocation)
  | "key_retired"                // key was retired (historical attestations still valid: "key_retired" ≠ invalid)
  | "payload_db_mismatch"        // signature OK but payload fields disagree with the DB record
  | "payload_schema_invalid"     // payload_json is missing required fields or has wrong types
  | "inherited_source_not_found" // the referenced source attestation was deleted or belongs to another org
  | "inherited_content_changed"; // the file's content hash in this scan differs from the source scan

// ── Payload schema validation ─────────────────────────────────────────────────

/**
 * Returns true when payload_json has all required fields with correct types.
 * A missing or wrongly-typed field indicates schema drift or tampering.
 */
export function validatePayloadSchema(p: unknown): p is CanonicalAttestationPayload {
  if (!p || typeof p !== "object") return false;
  const o = p as Record<string, unknown>;
  return (
    o.schema_version === PAYLOAD_SCHEMA_VERSION &&
    typeof o.reviewer_email  === "string" && o.reviewer_email.length > 0 &&
    (o.reviewer_id === null || typeof o.reviewer_id === "string") &&
    typeof o.org_id          === "string" && o.org_id.length > 0 &&
    typeof o.repo            === "string" && o.repo.length > 0 &&
    typeof o.commit_sha      === "string" && o.commit_sha.length > 0 &&
    typeof o.file_path       === "string" && o.file_path.length > 0 &&
    (o.content_hash === null || typeof o.content_hash === "string") &&
    typeof o.scan_id         === "string" && o.scan_id.length > 0 &&
    typeof o.findings_digest === "string" && o.findings_digest.length > 0 &&
    o.decision === "attested" &&
    typeof o.policy_version  === "string" && o.policy_version.length > 0 &&
    typeof o.timestamp       === "string" && o.timestamp.length > 0 &&
    typeof o.key_id          === "string" && o.key_id.length > 0
  );
}

// ── DB binding check ─────────────────────────────────────────────────────────

export interface AttestationBindingRow {
  scan_id:        string;
  file_path:      string;
  reviewer_email: string;
  signing_key_id: string | null;
}

export interface ScanBindingRow {
  repo_full_name: string;
  commit_sha:     string | null;
}

/**
 * Cross-checks every signed payload field against the corresponding DB columns.
 * A cryptographically valid signature only proves the payload was not tampered with;
 * this check proves the payload actually describes this attestation row, not a different one.
 *
 * Returns "payload_db_mismatch" if any field disagrees.
 */
export function checkPayloadDbBinding(
  payload:   CanonicalAttestationPayload,
  att:       AttestationBindingRow,
  authOrgId: string,
  scan?:     ScanBindingRow,
): "ok" | "payload_db_mismatch" {
  if (
    payload.org_id          !== authOrgId       ||
    payload.scan_id         !== att.scan_id     ||
    payload.file_path       !== att.file_path   ||
    payload.reviewer_email  !== att.reviewer_email ||
    payload.key_id          !== att.signing_key_id
  ) return "payload_db_mismatch";

  if (scan) {
    if (payload.repo !== scan.repo_full_name) return "payload_db_mismatch";
    // commit_sha: compare against scan record; treat null as empty string (pre-migration rows).
    const dbCommit = scan.commit_sha ?? "";
    if (payload.commit_sha !== dbCommit) return "payload_db_mismatch";
  }

  return "ok";
}

/**
 * Look up the signing key and cryptographically verify an attestation's signature (spec D).
 * A "key_retired" result means the key is no longer in active use but historical attestations
 * signed with it remain cryptographically valid; the caller decides whether to treat this as
 * a warning rather than an error.
 */
export async function verifyAttestation(
  db: SupabaseClient,
  attestation: {
    signature:      string | null;
    signing_key_id: string | null;
    payload_json:   CanonicalAttestationPayload | null;
  },
): Promise<{ result: VerifyResult }> {
  if (!attestation.signature || !attestation.signing_key_id || !attestation.payload_json) {
    return { result: "no_signature" };
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const { data: key } = await (db.from("signing_keys") as any)
    .select("public_key_pem, status")
    .eq("id", attestation.signing_key_id)
    .single() as { data: Pick<SigningKeyRow, "public_key_pem" | "status"> | null };

  if (!key)                     return { result: "key_not_found" };
  if (key.status === "revoked") return { result: "key_revoked" };
  if (key.status === "retired") {
    // Still verify the signature — a tampered payload is "invalid" even on a retired key.
    const valid = verifyCanonicalPayload(attestation.payload_json, attestation.signature, key.public_key_pem);
    return { result: valid ? "key_retired" : "invalid" };
  }

  const valid = verifyCanonicalPayload(attestation.payload_json, attestation.signature, key.public_key_pem);
  return { result: valid ? "valid" : "invalid" };
}
