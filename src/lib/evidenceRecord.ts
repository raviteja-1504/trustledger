/**
 * Evidence record: a single piece of evidence for a compliance control.
 *
 * Each record captures exactly one artifact — a scan result, an approval, a
 * reviewer attestation, a secret-detection run — and ties it to a specific
 * framework control at collection time.
 *
 * Key design constraints:
 *   - A technical scan alone does NOT establish compliance. Records are raw
 *     evidence; human review, policy documentation, and control testing by an
 *     independent assessor are always required on top.
 *   - Records are append-only. Revocation creates a new "revoked" lifecycle
 *     entry; it never deletes the original.
 *   - Content hashes are SHA-256 over the canonical evidence payload so a
 *     verifier can confirm the record hasn't changed after collection.
 *
 * Server-only (uses node:crypto). Do not import into client components.
 */

import crypto from "crypto";

// ── Evidence types (sources) ──────────────────────────────────────────────────

export type EvidenceType =
  | "security_scan"           // automated scan result (vuln, secret, compliance rule)
  | "pr_approval"             // GitHub/GitLab PR approval event
  | "reviewer_attestation"    // TrustLedger reviewer sign-off
  | "repository_change"       // commit or merge event in a connected repo
  | "secret_detection"        // secret/credential finding or resolution
  | "dependency_analysis"     // dependency manifest scan (npm, Maven, pip…)
  | "risk_assessment"         // manual risk register entry
  | "vulnerability_remediation" // closing / resolving a vulnerability finding
  | "access_control_event";   // role assignment, permission change, member add/remove

export const EVIDENCE_TYPE_LABELS: Record<EvidenceType, string> = {
  security_scan:              "Security scan",
  pr_approval:                "PR approval",
  reviewer_attestation:       "Reviewer attestation",
  repository_change:          "Repository change",
  secret_detection:           "Secret detection",
  dependency_analysis:        "Dependency analysis",
  risk_assessment:            "Risk assessment",
  vulnerability_remediation:  "Vulnerability remediation",
  access_control_event:       "Access-control event",
};

// ── Evidence lifecycle ────────────────────────────────────────────────────────

export type EvidenceLifecycleStatus =
  | "pending_verification"  // just collected; content hash not yet checked against source
  | "verified"              // content hash confirmed against source
  | "active"                // in-use, within its expiration window
  | "expired"               // past its expiration_date; needs refresh
  | "revoked";              // explicitly invalidated (superseded, found incorrect, etc.)

/** Default TTL in days for each evidence type. Expressed as calendar days. */
export const EVIDENCE_TTL_DAYS: Record<EvidenceType, number> = {
  security_scan:              90,   // scan results age quickly; rescan quarterly
  pr_approval:                365,  // approval records are durable audit artifacts
  reviewer_attestation:       365,
  repository_change:          365,
  secret_detection:           90,   // secret state changes; refresh if status changes
  dependency_analysis:        90,
  risk_assessment:            180,  // risk posture should be re-evaluated every 6 months
  vulnerability_remediation:  365,
  access_control_event:       365,
};

// ── Core record type ──────────────────────────────────────────────────────────

/**
 * A single compliance evidence record.
 *
 * Maps to the `evidence_log` DB table (server-serialised via
 * evidenceRecordToRow / rowToEvidenceRecord).  Extended fields are stored in
 * the `note` column as a canonical JSON object; this avoids requiring a
 * migration while keeping the type fully specified.
 */
export interface EvidenceRecord {
  /** Unique record identifier (UUID from the DB row). */
  evidence_id: string;
  org_id: string;
  /** Normalised framework id: "soc2" | "iso27001" | "pcidss" | "aigov". */
  framework: string;
  control_id: string;
  evidence_type: EvidenceType;
  /**
   * Where the evidence came from: a URL to the scan result, the PR, the
   * audit-log entry, or a human-readable description.
   */
  evidence_source: string;
  repository_id?: string;
  commit_sha?: string;
  scan_id?: string;
  attestation_id?: string;
  /** ISO 8601 UTC timestamp when the record was collected. */
  collection_timestamp: string;
  /** User ID, service account name, or "system" for automated collection. */
  collector_identity: string;
  /**
   * SHA-256 hex digest of the canonical evidence payload (see
   * canonicalPayload). Used by verifyRecord() to detect post-collection
   * mutation.
   */
  content_hash: string;
  verification_status: EvidenceLifecycleStatus;
  /** ISO 8601 UTC date after which this record must be refreshed. */
  expiration_date: string;
  /** Free-text note (shown in the audit trail and auditor export). */
  note?: string;
}

// ── Content hashing ───────────────────────────────────────────────────────────

/**
 * Canonical payload for hashing: an alphabetically sorted JSON representation
 * of the stable identity fields.  Excludes mutable fields (verification_status,
 * note) so the hash survives a verification-status update.
 */
export function canonicalPayload(r: Omit<EvidenceRecord, "content_hash" | "verification_status" | "note">): string {
  const stable: Record<string, unknown> = {
    evidence_id:         r.evidence_id,
    org_id:              r.org_id,
    framework:           r.framework,
    control_id:          r.control_id,
    evidence_type:       r.evidence_type,
    evidence_source:     r.evidence_source,
    collection_timestamp: r.collection_timestamp,
    collector_identity:  r.collector_identity,
    expiration_date:     r.expiration_date,
  };
  if (r.repository_id)  stable.repository_id  = r.repository_id;
  if (r.commit_sha)     stable.commit_sha     = r.commit_sha;
  if (r.scan_id)        stable.scan_id        = r.scan_id;
  if (r.attestation_id) stable.attestation_id = r.attestation_id;
  return JSON.stringify(stable, Object.keys(stable).sort());
}

/** SHA-256 hex over the canonical payload string. */
export function computeContentHash(payload: string): string {
  return crypto.createHash("sha256").update(payload, "utf8").digest("hex");
}

// ── Expiration ────────────────────────────────────────────────────────────────

/**
 * Compute the expiration date for a new record of the given evidence type,
 * relative to `collectedAt`.
 */
export function computeExpirationDate(evidenceType: EvidenceType, collectedAt: Date): Date {
  const ttl = EVIDENCE_TTL_DAYS[evidenceType];
  const exp = new Date(collectedAt);
  exp.setUTCDate(exp.getUTCDate() + ttl);
  return exp;
}

/** True when the record is past its expiration_date. */
export function isExpired(record: EvidenceRecord, now = new Date()): boolean {
  return new Date(record.expiration_date) <= now;
}

/** Days until the record expires (negative if already expired). */
export function daysUntilExpiry(record: EvidenceRecord, now = new Date()): number {
  const msPerDay = 86_400_000;
  return Math.round((new Date(record.expiration_date).getTime() - now.getTime()) / msPerDay);
}

// ── Lifecycle transitions ─────────────────────────────────────────────────────

/**
 * Build a new EvidenceRecord from raw inputs; computes the content hash and
 * expiration date.  Does not write to the DB.
 */
export function buildEvidenceRecord(
  input: Omit<EvidenceRecord, "content_hash" | "verification_status" | "expiration_date">,
): EvidenceRecord {
  const collectedAt = new Date(input.collection_timestamp);
  const expiration_date = computeExpirationDate(input.evidence_type, collectedAt).toISOString();
  const withExpiry = { ...input, expiration_date };
  const payload = canonicalPayload(withExpiry);
  const content_hash = computeContentHash(payload);
  return {
    ...withExpiry,
    content_hash,
    verification_status: "pending_verification",
  };
}

/**
 * Verify a record by recomputing its content hash from the given payload.
 * Returns true when the record is unmodified.
 */
export function verifyRecord(record: EvidenceRecord, payload: string): boolean {
  return computeContentHash(payload) === record.content_hash;
}

/**
 * Returns an updated record marked "verified" or "expired" based on current
 * time.  Does NOT write to the DB.
 */
export function markVerified(record: EvidenceRecord, now = new Date()): EvidenceRecord {
  const verification_status: EvidenceLifecycleStatus = isExpired(record, now)
    ? "expired"
    : "verified";
  return { ...record, verification_status };
}

/** Returns an updated record marked "expired".  Does NOT write to the DB. */
export function markExpired(record: EvidenceRecord): EvidenceRecord {
  return { ...record, verification_status: "expired" };
}

/** Returns an updated record marked "revoked".  Does NOT write to the DB. */
export function markRevoked(record: EvidenceRecord, reason: string): EvidenceRecord {
  return { ...record, verification_status: "revoked", note: reason };
}

// ── DB row serialisation ──────────────────────────────────────────────────────

/**
 * Fields stored in the `evidence_log` table's native columns.
 * Extended evidence fields are packed into `note` as JSON.
 */
export interface EvidenceLogRow {
  id?:                string;
  org_id:             string;
  framework_id:       string;
  control_id:         string;
  note:               string;
  file_url:           string | null;
  collected_by:       string | null;
  collected_by_email: string | null;
  created_at?:        string;
}

interface NotePayload {
  v:                   1;
  evidence_type:       EvidenceType;
  content_hash:        string;
  verification_status: EvidenceLifecycleStatus;
  expiration_date:     string;
  collector_identity:  string;
  repository_id?:      string;
  commit_sha?:         string;
  scan_id?:            string;
  attestation_id?:     string;
  user_note?:          string;
}

/** Serialise an EvidenceRecord to a row ready for `evidence_log.insert()`. */
export function evidenceRecordToRow(r: EvidenceRecord): EvidenceLogRow {
  const notePayload: NotePayload = {
    v:                   1,
    evidence_type:       r.evidence_type,
    content_hash:        r.content_hash,
    verification_status: r.verification_status,
    expiration_date:     r.expiration_date,
    collector_identity:  r.collector_identity,
  };
  if (r.repository_id)  notePayload.repository_id  = r.repository_id;
  if (r.commit_sha)     notePayload.commit_sha     = r.commit_sha;
  if (r.scan_id)        notePayload.scan_id        = r.scan_id;
  if (r.attestation_id) notePayload.attestation_id = r.attestation_id;
  if (r.note)           notePayload.user_note      = r.note;

  return {
    org_id:             r.org_id,
    framework_id:       r.framework,
    control_id:         r.control_id,
    note:               JSON.stringify(notePayload),
    file_url:           r.evidence_source || null,
    collected_by:       r.collector_identity,
    collected_by_email: null,
  };
}

/** Deserialise a DB row back to an EvidenceRecord. Returns null for legacy rows without the v:1 payload. */
export function rowToEvidenceRecord(row: EvidenceLogRow & { id: string; created_at: string }): EvidenceRecord | null {
  let n: Partial<NotePayload>;
  try {
    n = JSON.parse(row.note ?? "{}");
  } catch {
    return null;
  }
  if (n.v !== 1) return null;

  return {
    evidence_id:         row.id,
    org_id:              row.org_id,
    framework:           row.framework_id,
    control_id:          row.control_id,
    evidence_type:       n.evidence_type!,
    evidence_source:     row.file_url ?? "",
    repository_id:       n.repository_id,
    commit_sha:          n.commit_sha,
    scan_id:             n.scan_id,
    attestation_id:      n.attestation_id,
    collection_timestamp: row.created_at,
    collector_identity:  n.collector_identity ?? row.collected_by ?? "unknown",
    content_hash:        n.content_hash ?? "",
    verification_status: n.verification_status ?? "pending_verification",
    expiration_date:     n.expiration_date ?? row.created_at,
    note:                n.user_note,
  };
}

// ── Freshness helpers ─────────────────────────────────────────────────────────

export type FreshnessLabel = "fresh" | "aging" | "stale" | "expired";

/**
 * Classify how fresh a record is relative to its TTL:
 *   fresh   = > 50% of TTL remaining
 *   aging   = 10–50% remaining
 *   stale   = 0–10% remaining
 *   expired = past expiration
 */
export function freshnessLabel(record: EvidenceRecord, now = new Date()): FreshnessLabel {
  if (isExpired(record, now)) return "expired";
  const ttlDays = EVIDENCE_TTL_DAYS[record.evidence_type];
  const remaining = daysUntilExpiry(record, now);
  const pct = remaining / ttlDays;
  if (pct > 0.5) return "fresh";
  if (pct > 0.1) return "aging";
  return "stale";
}
