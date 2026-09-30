/**
 * Trust Record: one signed, self-contained document answering "what did TrustLedger know about this change,
 * and who signed off?" for a single scan -- the commit, the engine and how complete the analysis was, every
 * security finding with its confidence, whether the PR introduced it and any triage decision on it, the AI
 * share per file, the reviewer attestations, and the merge-gate outcome.
 *
 * Signed with HMAC-SHA256 over the canonical JSON of `record` (keys sorted, no whitespace), with the same
 * export signing key as the signed audit-log export. verifyTrustRecord() recomputes it.
 * Server-only (node:crypto).
 */
import crypto from "crypto";
import type { FileIndicator } from "@/types";
import type { ScanHealth } from "./scanHealth";
import { isActive, type TriageDecision } from "./findingLifecycle";
import { confidenceLevel } from "./confidence";
import { findingMeta } from "./findingCatalog";

export const TRUST_RECORD_SCHEMA = "trustledger.trust-record/v1";

export interface TrustRecordInput {
  org_name: string | null;
  scan: {
    id: string; repo: string; pr_number: number; commit_sha: string; created_at: string;
    overall_risk: string; total_ai_percentage: number; triggered_by: string | null; duration_ms: number | null;
  };
  engine_version: string | null;
  health: ScanHealth | null;
  files: Array<{ file_path: string; risk_score: string; ai_percentage: number; indicators: FileIndicator[] }>;
  attestations: Array<{ file_path: string; reviewer_email: string | null; reviewer_github: string | null; payload_hash: string | null; created_at: string | null }>;
  triage: ReadonlyMap<string, TriageDecision>;
  open_blocking_violations: number;
  generated_at: string;
}

const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export function buildTrustRecord(input: TrustRecordInput) {
  const now = new Date(input.generated_at);
  const findings = input.files.flatMap(f => f.indicators
    .filter(i => !!(i.cwe ?? findingMeta(i.id, i.label).cwe))
    .map(i => {
      const decision = i.fingerprint ? input.triage.get(i.fingerprint) : undefined;
      const active = isActive(decision, now);
      return {
        fingerprint: i.fingerprint ?? null,
        rule: i.id,
        title: findingMeta(i.id, i.label).title,
        severity: i.severity,
        cwe: i.cwe ?? findingMeta(i.id, i.label).cwe ?? null,
        file: f.file_path,
        line: i.line ?? null,
        confidence: confidenceLevel({ confidence: i.confidence, sourceExpr: i.sourceExpr, sourceAssumed: i.flow?.source.assumed }),
        analysis: i.sourceExpr ? "data-flow" : "pattern",
        introduced_by_pr: i.introduced ?? null,
        decision: active && decision ? { status: decision.status, reason: decision.reason, by: decision.set_by_email, at: decision.set_at, expires_at: decision.expires_at } : null,
      };
    }))
    .sort((a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9) || a.file.localeCompare(b.file) || (a.line ?? 0) - (b.line ?? 0));

  const count = (pred: (f: typeof findings[number]) => boolean) => findings.filter(pred).length;
  return {
    schema: TRUST_RECORD_SCHEMA,
    generated_at: input.generated_at,
    organization: input.org_name,
    change: { repository: input.scan.repo, pull_request: input.scan.pr_number, commit: input.scan.commit_sha },
    scan: {
      id: input.scan.id, scanned_at: input.scan.created_at, triggered_by: input.scan.triggered_by,
      engine_version: input.engine_version, duration_ms: input.scan.duration_ms,
      coverage: input.health ? { status: input.health.status, gaps: input.health.gap_counts } : null,
    },
    verdict: {
      overall_risk: input.scan.overall_risk,
      ai_share_percent: Math.round(input.scan.total_ai_percentage * 10) / 10,
      merge_gate: input.open_blocking_violations > 0 ? "blocked" : "clear",
      open_blocking_violations: input.open_blocking_violations,
    },
    summary: {
      findings: findings.length,
      critical: count(f => f.severity === "critical"), high: count(f => f.severity === "high"),
      introduced_by_pr: count(f => f.introduced_by_pr === true),
      accepted_or_false_positive: count(f => f.decision !== null),
      files: input.files.length,
      files_attested: new Set(input.attestations.map(a => a.file_path)).size,
    },
    files: input.files.map(f => ({ path: f.file_path, risk: f.risk_score, ai_share_percent: Math.round(f.ai_percentage * 10) / 10 }))
      .sort((a, b) => a.path.localeCompare(b.path)),
    findings,
    attestations: input.attestations
      .map(a => ({ file: a.file_path, reviewer: a.reviewer_email, reviewer_github: a.reviewer_github, at: a.created_at, payload_hash: a.payload_hash }))
      .sort((a, b) => a.file.localeCompare(b.file)),
  };
}

export type TrustRecord = ReturnType<typeof buildTrustRecord>;

/** JSON with object keys sorted at every level and no whitespace -- the exact bytes that are signed. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const obj = value as Record<string, unknown>;
  return `{${Object.keys(obj).filter(k => obj[k] !== undefined).sort().map(k => `${JSON.stringify(k)}:${canonicalJson(obj[k])}`).join(",")}}`;
}

export function signTrustRecord(record: TrustRecord, key: string): string {
  return crypto.createHmac("sha256", key).update(canonicalJson(record)).digest("hex");
}

export function verifyTrustRecord(doc: { record: TrustRecord; signature: { algorithm: string; value: string } }, key: string): boolean {
  if (doc.signature?.algorithm !== "HMAC-SHA256") return false;
  const expected = Buffer.from(signTrustRecord(doc.record, key), "hex");
  const given = Buffer.from(doc.signature.value ?? "", "hex");
  return expected.length === given.length && crypto.timingSafeEqual(expected, given);
}

/** Identifies a signing key without revealing it: the first 16 hex chars of SHA-256(key). Lets a verifier tell
 * "tampered" apart from "signed with a key this server doesn't have" (e.g. after key rotation). */
export function signingKeyId(key: string): string {
  return crypto.createHash("sha256").update(key).digest("hex").slice(0, 16);
}

export type TrustRecordCheck =
  | "valid"            // signed with this server's key, unchanged since
  | "tampered"         // signed with this server's key, but the record was changed afterwards
  | "unknown_key"      // signed with a different key (another deployment, or a rotated key)
  | "unsigned"         // exported without a signature
  | "malformed"        // not a Trust Record
  | "not_configured";  // this server has no signing key to verify against

export const CHECK_MESSAGE: Record<TrustRecordCheck, string> = {
  valid: "Valid. This record was produced by TrustLedger with this server's key and hasn't been changed since.",
  tampered: "Tampered. The signature doesn't match the content: the record was edited after it was exported.",
  unknown_key: "Unknown key. The record was signed with a key this server doesn't have (another deployment, or a key that has since been rotated), so it can't be checked here.",
  unsigned: "Unsigned. This record was exported without a signature, so its integrity can't be checked.",
  malformed: "Not a Trust Record. The file isn't in the trustledger.trust-record format.",
  not_configured: "Can't verify. This server has no export signing key configured.",
};

/** Check an uploaded Trust Record document against `key` (this server's signing key, if any). */
export function checkTrustRecord(doc: unknown, key: string | undefined): TrustRecordCheck {
  const d = doc as { record?: { schema?: unknown }; signature?: { algorithm?: string; value?: string; key_id?: string } | null } | null;
  if (!d || typeof d !== "object" || !d.record || typeof d.record !== "object" || d.record.schema !== TRUST_RECORD_SCHEMA) return "malformed";
  if (!d.signature) return "unsigned";
  if (!key) return "not_configured";
  if (d.signature.key_id && d.signature.key_id !== signingKeyId(key)) return "unknown_key";
  if (typeof d.signature.value !== "string" || !/^[0-9a-f]{64}$/.test(d.signature.value)) return "tampered";
  return verifyTrustRecord(d as { record: TrustRecord; signature: { algorithm: string; value: string } }, key) ? "valid" : "tampered";
}
