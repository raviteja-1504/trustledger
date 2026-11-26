/**
 * Append-only, tamper-evident audit log writer.
 * Every entry includes the SHA-256 of the previous entry (hash chain).
 * Stored in the audit_log table which has no UPDATE/DELETE rules.
 *
 * What is hashed: previous entry hash, event type, actor, the payload as canonical JSON (keys sorted -- Postgres
 * jsonb reorders keys, so insertion-order JSON could never be recomputed from the stored row), and the entry's time,
 * which is now written explicitly as created_at so the stored row carries exactly the time that was hashed.
 * Entries written before that (the database chose created_at, a few ms off the hashed time) can't be recomputed;
 * verification still checks their links and reports them as such, rather than calling them tampered.
 */

import { buildAuditHash } from "./scanner";
import type { SupabaseClient } from "@supabase/supabase-js";
import type { Database } from "@/types/supabase";

/**
 * Serialises writeAuditLog calls per org within a single process.
 *
 * This prevents in-process concurrent writers from forking the chain. It does NOT protect against
 * forks across separate server instances. The proper distributed fix requires a PostgreSQL advisory
 * lock (pg_advisory_xact_lock(org_id_hash)) held inside a transaction that spans the SELECT and
 * INSERT. That requires a database function and a migration, which is a future hardening step.
 *
 * Threat model: a fork creates two valid branches from the same parent hash. Neither branch is
 * "wrong" in terms of content integrity, but chain verification will return FORK_DETECTED,
 * allowing operators to investigate and resolve the split. Hash chaining alone does not prevent a
 * privileged administrator from rewriting the entire chain — it only makes rewrites detectable by
 * independent observers who have cached prior hashes.
 */
const _writeLocks = new Map<string, Promise<void>>();

export type AuditEventType =
  | "scan_complete" | "attestation" | "merge_blocked" | "merge_allowed"
  | "policy_violation" | "policy_change" | "secret_detected" | "secret_resolved"
  | "integration_connected" | "user_added" | "user_removed"
  | "sla_breach" | "alert_fired" | "alert_resolved"
  | "incident_created" | "incident_resolved"
  | "api_key_created" | "api_key_revoked"
  | "violation_resolved" | "violation_escalated" | "violation_assigned"
  | "report_generated" | "org_settings_changed"
  | "member_invited" | "member_role_changed" | "member_removed"
  | "exception_created" | "exception_resolved"
  | "risk_updated" | "evidence_collected"
  | "finding_triaged" | "finding_reopened" | "findings_baselined" | "scan_rescan_requested"
  | "user_login"
  | "repo_connected" | "repo_enabled" | "repo_disabled"
  | "data_exported"
  | "evidence_uploaded" | "evidence_deleted"
  | "ai_tool_policy_changed" | "shadow_ai_triaged"
  | "org_deletion_requested" | "org_deleted";

interface AuditEntry {
  org_id:        string;
  event_type:    AuditEventType;
  actor_id?:     string | null;
  actor_email?:  string | null;
  resource_type?: string;
  resource_id?:  string;
  payload:       Record<string, unknown>;
}

/** JSON with object keys sorted at every level, so the same value always gives the same text. */
export function canonicalJson(v: unknown): string {
  if (v === null || typeof v !== "object") return JSON.stringify(v) ?? "null";
  if (Array.isArray(v)) return `[${v.map(x => (x === undefined ? "null" : canonicalJson(x))).join(",")}]`;
  const o = v as Record<string, unknown>;
  return `{${Object.keys(o).filter(k => o[k] !== undefined).sort().map(k => `${JSON.stringify(k)}:${canonicalJson(o[k])}`).join(",")}}`;
}

/** An entry's hash, as written. */
export function auditEntryHash(prevHash: string | null, eventType: string, actorEmail: string | null, payload: unknown, createdAtIso: string): string {
  return buildAuditHash(prevHash, eventType, actorEmail ?? "system", canonicalJson(payload ?? {}), createdAtIso);
}

export async function writeAuditLog(
  db: SupabaseClient<Database>,
  entry: AuditEntry,
  opts: { strict?: boolean } = {},
): Promise<void> {
  // Serialise writes for this org within this process (best-effort; not distributed-safe).
  const prev = _writeLocks.get(entry.org_id) ?? Promise.resolve();
  let releaseLock!: () => void;
  const lock = new Promise<void>(r => { releaseLock = r; });
  _writeLocks.set(entry.org_id, lock);

  try {
    await prev;
    await _writeAuditLogInner(db, entry, !!opts.strict);
  } finally {
    releaseLock();
    // Clean up once the slot is no longer the latest promise for this org.
    if (_writeLocks.get(entry.org_id) === lock) _writeLocks.delete(entry.org_id);
  }
}

async function _writeAuditLogInner(
  db: SupabaseClient<Database>,
  entry: AuditEntry,
  strict: boolean,
): Promise<void> {
  // Read the most recent entry hash inside the (best-effort) lock.
  const { data: prev } = await db
    .from("audit_log")
    .select("entry_hash")
    .eq("org_id", entry.org_id)
    .order("id", { ascending: false })
    .limit(1)
    .single() as { data: { entry_hash: string } | null };

  const now       = new Date().toISOString();
  const prevHash  = prev?.entry_hash ?? null;
  const entryHash = auditEntryHash(prevHash, entry.event_type, entry.actor_email ?? null, entry.payload, now);

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const { error } = await (db.from("audit_log") as any).insert({
    org_id:        entry.org_id,
    event_type:    entry.event_type,
    actor_id:      entry.actor_id ?? null,
    actor_email:   entry.actor_email ?? null,
    resource_type: entry.resource_type ?? null,
    resource_id:   entry.resource_id ?? null,
    payload:       entry.payload,
    prev_hash:     prevHash,
    entry_hash:    entryHash,
    created_at:    now,
  });
  // Best-effort by default (existing callers log events after the fact); strict callers -- those that must not
  // proceed without the record, e.g. organisation deletion -- get the failure.
  if (error && strict) throw new Error(`audit_write_failed: ${error.message ?? "unknown"}`);
}

export interface ChainRow { id: number; event_type: string; actor_email: string | null; payload: unknown; prev_hash: string | null; entry_hash: string; created_at: string }

/**
 * Explicit verification outcome, returned alongside the boolean `valid` for callers that need
 * finer-grained reporting.
 *
 * - VALID:           every entry verified, no forks.
 * - FORK_DETECTED:   two or more entries share the same parent hash (concurrent writers created
 *                    a branch). The chain content is not corrupted, but ordering is ambiguous.
 * - MISSING_RECORDS: an entry points at a prev_hash that is not in the loaded rows — a record
 *                    was deleted or the chain was truncated.
 * - INVALID:         an entry's contents no longer hash to their stored entry_hash — the row was
 *                    modified in place.
 * - INCOMPLETE:      verification could not run (e.g. a database error was thrown before all
 *                    rows were loaded).
 */
export type VerificationStatus = "VALID" | "FORK_DETECTED" | "MISSING_RECORDS" | "INVALID" | "INCOMPLETE";

export interface ChainVerification {
  /** Explicit status (see VerificationStatus). Use this instead of `valid` where possible. */
  status: VerificationStatus;
  /** Backward-compatible boolean summary: true only when status is VALID or FORK_DETECTED. */
  valid: boolean;
  total: number;
  /** Entries whose contents were recomputed and matched. */
  verified: number;
  /** Older entries (before the first recomputable one) whose contents can't be recomputed; their links were checked. */
  legacy: number;
  /** Entries where two (or more) entries share the same prev_hash. FORK_DETECTED is set when this is > 0. */
  concurrent: number;
  /** id of the first entry that fails: its link points nowhere, or its recomputable contents changed. */
  broken_at?: number;
  reason?: "missing_link" | "content_changed";
  first_at: string | null;
  last_at: string | null;
}

/**
 * Check a chain (rows in id order). Valid when every entry links to an existing earlier entry and every entry from
 * the first recomputable one on recomputes to its stored hash.
 */
export function checkAuditChain(rows: readonly ChainRow[]): ChainVerification {
  const base = { total: rows.length, verified: 0, legacy: 0, concurrent: 0, first_at: rows[0]?.created_at ?? null, last_at: rows[rows.length - 1]?.created_at ?? null };
  const seenHashes = new Set<string>();
  const linkedFrom = new Set<string>();
  let recomputable = false;
  let verified = 0, legacy = 0, concurrent = 0;
  for (let i = 0; i < rows.length; i++) {
    const r = rows[i];
    // Links: the first entry starts the chain; every other must point at an earlier entry's hash.
    if (i > 0 || r.prev_hash != null) {
      if (r.prev_hash == null || !seenHashes.has(r.prev_hash)) {
        return { ...base, verified, legacy, concurrent, status: "MISSING_RECORDS", valid: false, broken_at: r.id, reason: "missing_link" };
      }
      if (linkedFrom.has(r.prev_hash)) concurrent++;
      linkedFrom.add(r.prev_hash);
    }
    // Contents: recompute from the stored row.
    const at = Number.isNaN(Date.parse(r.created_at)) ? r.created_at : new Date(r.created_at).toISOString();
    const ok = auditEntryHash(r.prev_hash, r.event_type, r.actor_email, r.payload, at) === r.entry_hash;
    if (ok) { recomputable = true; verified++; }
    else if (!recomputable) legacy++;
    else return { ...base, verified, legacy, concurrent, status: "INVALID", valid: false, broken_at: r.id, reason: "content_changed" };
    seenHashes.add(r.entry_hash);
  }
  const status: VerificationStatus = concurrent > 0 ? "FORK_DETECTED" : "VALID";
  return { ...base, verified, legacy, concurrent, status, valid: true };
}

const PAGE = 1000;
const MAX_ROWS = 200_000;

/** Every audit entry of an org in id order, paged past the 1000-row cap. `complete` is false when a read failed part-way. */
export async function loadAuditRows(db: SupabaseClient<Database>, org_id: string): Promise<{ rows: ChainRow[]; complete: boolean }> {
  const rows: ChainRow[] = [];
  try {
    for (let from = 0; from < MAX_ROWS; from += PAGE) {
      const { data, error } = await db
        .from("audit_log")
        .select("id, event_type, actor_email, payload, prev_hash, entry_hash, created_at")
        .eq("org_id", org_id)
        .order("id", { ascending: true })
        .range(from, from + PAGE - 1) as { data: ChainRow[] | null; error: unknown };
      if (error) throw error;
      rows.push(...(data ?? []));
      if (!data || data.length < PAGE) break;
    }
  } catch {
    return { rows, complete: false };
  }
  return { rows, complete: true };
}

/** Verify the integrity of the audit log chain for an org (every entry, paged past the 1000-row cap). */
export async function verifyAuditChain(
  db: SupabaseClient<Database>,
  org_id: string,
): Promise<ChainVerification> {
  const { rows, complete } = await loadAuditRows(db, org_id);
  if (!complete) {
    return {
      status: "INCOMPLETE",
      valid: false,
      total: rows.length,
      verified: 0,
      legacy: 0,
      concurrent: 0,
      first_at: rows[0]?.created_at ?? null,
      last_at: rows[rows.length - 1]?.created_at ?? null,
    };
  }
  return checkAuditChain(rows);
}
