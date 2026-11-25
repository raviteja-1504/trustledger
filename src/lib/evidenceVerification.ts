/**
 * Verifying a stored evidence record (Task 12, cryptographic evidence verification).
 *
 * Two independent checks:
 *  1. integrity  - the record's content_hash recomputes from the fields stored with it (hash_version 2), or from a
 *                  payload the caller supplies (older records, whose hashed values were never stored).
 *  2. anchor     - the hash the record had when it was collected was also written into the audit log
 *                  (evidence_collected, payload.content_hash), which is hash-chained and covered by signed
 *                  checkpoints. Someone who edits both the record and its hash in evidence_log still disagrees with it.
 *
 * A record is "verified" only when the first check passes and the second does not contradict it. A mismatch in
 * either marks it "verification_failed": untrusted, and not counted toward any control.
 *
 * What this does not do: prove the evidence's SOURCE is genuine (the scan, the PR, the document it points to).
 * It shows the record has not changed since TrustLedger collected it.
 */
import type { SupabaseClient } from "@supabase/supabase-js";
import {
  checkIntegrity, verifyRecord, markVerified, markVerificationFailed, type EvidenceRecord, type IntegrityResult,
} from "./evidenceRecord";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Db = SupabaseClient<any>;

export type AnchorStatus =
  | "anchored"         // the audit log holds the same hash
  | "anchor_mismatch"  // the audit log holds a different hash for this record
  | "no_anchor";       // no audit entry with a hash (older record, or its audit write failed)

/** Compare a record's hash with the hashes recorded for it in audit-log payloads. */
export function anchorStatus(auditPayloads: readonly unknown[], contentHash: string): AnchorStatus {
  const hashes = auditPayloads
    .map(p => (p && typeof p === "object" ? (p as { content_hash?: unknown }).content_hash : undefined))
    .filter((h): h is string => typeof h === "string" && h.length > 0);
  if (hashes.length === 0) return "no_anchor";
  return hashes.includes(contentHash) ? "anchored" : "anchor_mismatch";
}

export async function loadAnchor(db: Db, orgId: string, evidenceId: string, contentHash: string): Promise<AnchorStatus> {
  const { data } = await db.from("audit_log").select("payload")
    .eq("org_id", orgId).eq("resource_type", "evidence_log").eq("resource_id", evidenceId) as { data: Array<{ payload: unknown }> | null };
  return anchorStatus((data ?? []).map(r => r.payload), contentHash);
}

export interface VerificationOutcome {
  integrity: IntegrityResult;
  anchor:    AnchorStatus;
  /** "unchanged" when nothing could be checked (a legacy record with no payload supplied). */
  result:    "verified" | "failed" | "unchanged";
  record:    EvidenceRecord;
}

/** Pure decision: no database access. */
export function decideVerification(record: EvidenceRecord, anchor: AnchorStatus, suppliedPayload?: string, now = new Date()): VerificationOutcome {
  const integrity: IntegrityResult = suppliedPayload !== undefined
    ? (verifyRecord(record, suppliedPayload) ? "intact" : "mismatch")
    : checkIntegrity(record);
  if (integrity === "legacy_unverifiable") return { integrity, anchor, result: "unchanged", record };
  if (integrity === "mismatch" || anchor === "anchor_mismatch") return { integrity, anchor, result: "failed", record: markVerificationFailed(record) };
  return { integrity, anchor, result: "verified", record: markVerified(record, now) };
}

export async function verifyStoredEvidence(db: Db, orgId: string, record: EvidenceRecord, suppliedPayload?: string): Promise<VerificationOutcome> {
  const anchor = await loadAnchor(db, orgId, record.evidence_id, record.content_hash);
  return decideVerification(record, anchor, suppliedPayload);
}

/**
 * Whether a record may count toward a control's coverage. Failed or revoked records never do. A record whose hash
 * can be recomputed must still match it; a legacy record (hash cannot be recomputed) counts only once someone has
 * verified it with the original payload.
 */
export function isTrustedEvidence(record: EvidenceRecord, anchor?: AnchorStatus): boolean {
  if (record.verification_status === "revoked" || record.verification_status === "verification_failed") return false;
  if (anchor === "anchor_mismatch") return false;
  const integrity = checkIntegrity(record);
  if (integrity === "mismatch") return false;
  if (integrity === "legacy_unverifiable") return record.verification_status === "verified";
  return true;
}
