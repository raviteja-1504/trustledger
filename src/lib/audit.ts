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

import crypto from "crypto";
import { buildAuditHash } from "./scanner";
import { logger } from "./logger";
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
  | "member_sessions_revoked"
  | "org_deletion_requested" | "org_deletion_cancelled" | "org_deletion_started" | "org_deleted"
  | "audit_forks_reviewed";

/**
 * Events that must be on record: an action that changes who can do what, how the product is configured, what leaves it, or
 * what is destroyed. A route that writes one of these uses requireAudit() (lib/auditRequired.ts) -- the action is reported as
 * failed (or undone) when its audit entry cannot be written -- and never the best-effort writeAuditLog() alone.
 * src/__tests__/lib/auditRequired.test.ts fails the build when a route writes one of them any other way.
 * `org_settings_changed` covers configuration of every kind; a call that is genuinely system housekeeping (billing sync, health
 * cron, checkpoint bookkeeping) is marked `audit: best-effort` in a comment where it is written.
 */
export const REQUIRED_AUDIT_EVENTS: ReadonlySet<AuditEventType> = new Set<AuditEventType>([
  "attestation",
  "member_invited", "member_role_changed", "member_removed", "member_sessions_revoked", "user_added", "user_removed",
  "api_key_created", "api_key_revoked",
  "policy_change", "ai_tool_policy_changed", "org_settings_changed", "exception_created", "exception_resolved",
  "data_exported",
  "evidence_deleted", "repo_disabled", "org_deletion_requested", "org_deletion_cancelled", "org_deletion_started", "org_deleted", "audit_forks_reviewed",
]);

export interface AuditEntry {
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

/** What an entry's v2 hash covers: everything that identifies it. (v1 covered only prev, type, actor email, payload, time.) */
export interface AuditHashInput {
  prev_hash: string | null; org_id: string; event_type: string; actor_id: string | null; actor_email: string | null;
  resource_type: string | null; resource_id: string | null; payload: unknown; created_at: string;
}

/**
 * Hash format v2: SHA-256 over "tl-audit-v2:" + the canonical JSON of an ARRAY of the fields (not a delimiter-joined
 * string, so no value can shift into its neighbour). It covers org_id, actor_id, resource_type and resource_id, which v1
 * left unprotected: changing who did something, or what it was done to, now breaks the hash. v2 needs no new column: a
 * v2 entry is recognised by recomputing it (a v1 entry's stored hash cannot match a v2 preimage, nor the reverse), and
 * once a chain has a v2 entry every later one must be v2 (checkAuditChain), so an entry cannot be re-hashed as v1 to
 * dodge the metadata check.
 */
export function auditEntryHashV2(e: AuditHashInput): string {
  return crypto.createHash("sha256").update("tl-audit-v2:" + canonicalJson([
    e.prev_hash, e.org_id, e.event_type, e.actor_id, e.actor_email ?? "system", e.resource_type, e.resource_id, e.payload ?? {}, e.created_at,
  ])).digest("hex");
}

const MAX_APPEND_ATTEMPTS = 6;

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
  let lastError = "unknown";
  for (let attempt = 0; attempt < MAX_APPEND_ATTEMPTS; attempt++) {
    // The newest entry is the parent. A failed read must NOT be treated as "no entries": that would append a second
    // genesis entry and fork the chain.
    const { data: prevRows, error: readError } = await db
      .from("audit_log").select("entry_hash").eq("org_id", entry.org_id).order("id", { ascending: false }).limit(1) as
      { data: Array<{ entry_hash: string }> | null; error: { message?: string } | null };
    if (readError) { lastError = `read: ${readError.message ?? "unknown"}`; break; }

    const now       = new Date().toISOString();
    const prevHash  = prevRows?.[0]?.entry_hash ?? null;
    const row = {
      org_id: entry.org_id, event_type: entry.event_type, actor_id: entry.actor_id ?? null, actor_email: entry.actor_email ?? null,
      resource_type: entry.resource_type ?? null, resource_id: entry.resource_id ?? null, payload: entry.payload,
    };
    const entryHash = auditEntryHashV2({ ...row, prev_hash: prevHash, created_at: now });

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const { error } = await (db.from("audit_log") as any).insert({ ...row, org_id: entry.org_id, prev_hash: prevHash, entry_hash: entryHash, created_at: now });
    if (!error) return;
    lastError = error.message ?? "unknown";
    // 23505 = another writer (another server instance) appended after our read: the database allows one child per parent
    // (migration 20261128_audit_one_child_per_parent.sql). Read the new tail and try again instead of forking.
    if (error.code !== "23505") break;
  }
  // Best-effort by default (callers log events after the fact), but never silent; strict callers -- those that must not
  // proceed without the record, e.g. organisation deletion -- get the failure.
  logger.error("Audit entry not written", { event: "audit_write_failed", org_id: entry.org_id, event_type: entry.event_type, error: lastError });
  if (strict) throw new Error(`audit_write_failed: ${lastError}`);
}

export interface ChainRow {
  id: number; event_type: string; actor_email: string | null; payload: unknown; prev_hash: string | null; entry_hash: string; created_at: string;
  /** Covered by hash v2. loadAuditRows fills them in; a row without org_id can only be checked as v1. */
  org_id?: string; actor_id?: string | null; resource_type?: string | null; resource_id?: string | null;
}

/**
 * Explicit verification outcome, returned alongside the boolean `valid` for callers that need
 * finer-grained reporting.
 *
 * - VALID:           every entry verified, no forks.
 * - FORK_DETECTED:   two or more entries share the same parent hash (concurrent writers created
 *                    a branch). Contents may all check out, but the history has two branches, so it is
 *                    NOT a clean history: ordering is ambiguous and an entry could hide on the other branch.
 * - MISSING_RECORDS: an entry points at a prev_hash that is not in the loaded rows — a record
 *                    was deleted or the chain was truncated.
 * - INVALID:         an entry's contents no longer hash to their stored entry_hash — the row was
 *                    modified in place.
 * - INCOMPLETE:      verification could not run (a database error before all rows were loaded, or the
 *                    database returned fewer rows than it holds). Says nothing either way about the log.
 * - INCOMPLETE_LIMIT_REACHED: the log is longer than the number of entries this check reads (MAX_AUDIT_ROWS), so
 *                    only a prefix was seen. A clean prefix is not a clean log: nothing is reported as verified.
 */
export type VerificationStatus = "VALID" | "FORK_DETECTED" | "MISSING_RECORDS" | "INVALID" | "INCOMPLETE" | "INCOMPLETE_LIMIT_REACHED";

export interface ChainVerification {
  /** Explicit status (see VerificationStatus). Use this instead of `valid` where possible. */
  status: VerificationStatus;
  /** True only when status is VALID. A fork is not clean. */
  valid: boolean;
  total: number;
  /** Entries whose contents were recomputed and matched. */
  verified: number;
  /** Of those, entries checked with hash v2 -- their org, actor and resource fields are covered too. The rest are v1 (contents only). */
  metadata_verified: number;
  /** Older entries (before the first recomputable one) whose contents can't be recomputed; their links were checked. */
  legacy: number;
  /** Entries where two (or more) entries share the same prev_hash. FORK_DETECTED is set when this is > 0. */
  concurrent: number;
  /** id of the first UNREVIEWED entry that shares its parent with an earlier one (set with FORK_DETECTED). */
  fork_at?: number;
  /** Every entry that shares a parent with an earlier one, how many of them an admin has recorded as reviewed (an
   *  "audit_forks_reviewed" entry later in the chain names them), and how many are still unreviewed. A fork is a fact of
   *  the history and stays in the chain; reviewing it records, inside the chain itself, that someone looked. */
  fork_ids?: number[];
  reviewed_forks?: number;
  unreviewed_forks?: number;
  unreviewed_fork_ids?: number[];
  /** id of the first entry that fails: its link points nowhere, or its recomputable contents changed. */
  broken_at?: number;
  reason?: "missing_link" | "content_changed" | "downgraded";
  first_at: string | null;
  last_at: string | null;
}

/**
 * Check a chain (rows in id order). Valid when every entry links to an existing earlier entry and every entry from
 * the first recomputable one on recomputes to its stored hash.
 */
export function checkAuditChain(rows: readonly ChainRow[]): ChainVerification {
  const base = { total: rows.length, verified: 0, metadata_verified: 0, legacy: 0, concurrent: 0, first_at: rows[0]?.created_at ?? null, last_at: rows[rows.length - 1]?.created_at ?? null };
  const seenHashes = new Set<string>();
  const linkedFrom = new Set<string>();
  let recomputable = false, seenV2 = false;
  let verified = 0, metadata = 0, legacy = 0, concurrent = 0;
  const forkIds: number[] = [];
  const forkIdSet = new Set<number>();
  const reviewed = new Set<number>();
  const so_far = () => ({ ...base, verified, metadata_verified: metadata, legacy, concurrent });
  for (let i = 0; i < rows.length; i++) {
    const r = rows[i];
    // Links: the first entry starts the chain; every other must point at an earlier entry's hash.
    if (i > 0 || r.prev_hash != null) {
      if (r.prev_hash == null || !seenHashes.has(r.prev_hash)) {
        return { ...so_far(), status: "MISSING_RECORDS", valid: false, broken_at: r.id, reason: "missing_link" };
      }
      if (linkedFrom.has(r.prev_hash)) { concurrent++; forkIds.push(r.id); forkIdSet.add(r.id); }
      linkedFrom.add(r.prev_hash);
    }
    // Contents: recompute from the stored row -- v2 (covers org / actor / resource too) first, then v1.
    const at = Number.isNaN(Date.parse(r.created_at)) ? r.created_at : new Date(r.created_at).toISOString();
    const v2 = r.org_id !== undefined && auditEntryHashV2({
      prev_hash: r.prev_hash, org_id: r.org_id, event_type: r.event_type, actor_id: r.actor_id ?? null, actor_email: r.actor_email,
      resource_type: r.resource_type ?? null, resource_id: r.resource_id ?? null, payload: r.payload, created_at: at,
    }) === r.entry_hash;
    if (v2) { recomputable = true; seenV2 = true; verified++; metadata++; }
    else if (auditEntryHash(r.prev_hash, r.event_type, r.actor_email, r.payload, at) === r.entry_hash) {
      // A v1 entry after a v2 one cannot be genuine: the writer has produced only v2 since the first. Otherwise a v2 entry
      // could be re-hashed as v1 to make its metadata editable.
      if (seenV2) return { ...so_far(), status: "INVALID", valid: false, broken_at: r.id, reason: "downgraded" };
      recomputable = true; verified++;
    }
    else if (!recomputable) legacy++;
    else return { ...so_far(), status: "INVALID", valid: false, broken_at: r.id, reason: "content_changed" };
    // A review entry covers the forks it names that came BEFORE it (it cannot vouch for entries that did not exist yet).
    if (r.event_type === "audit_forks_reviewed") {
      const named = (r.payload as { fork_entry_ids?: unknown } | null)?.fork_entry_ids;
      if (Array.isArray(named)) for (const id of named) if (typeof id === "number" && id < r.id && forkIdSet.has(id)) reviewed.add(id);
    }
    seenHashes.add(r.entry_hash);
  }
  const unreviewed = forkIds.filter(id => !reviewed.has(id));
  const status: VerificationStatus = unreviewed.length > 0 ? "FORK_DETECTED" : "VALID";
  return {
    ...so_far(), status, valid: status === "VALID",
    ...(forkIds.length > 0 ? { fork_ids: forkIds, reviewed_forks: forkIds.length - unreviewed.length, unreviewed_forks: unreviewed.length, unreviewed_fork_ids: unreviewed } : {}),
    ...(unreviewed.length > 0 ? { fork_at: unreviewed[0] } : {}),
  };
}

const PAGE = 1000;
/** The most entries one verification reads. A longer log is reported as INCOMPLETE_LIMIT_REACHED, never as verified. */
export const MAX_AUDIT_ROWS = 200_000;

export type AuditLoadIncomplete = "read_failed" | "limit_reached" | "count_mismatch";

/**
 * Every audit entry of an org in id order, paged past the 1000-row cap. `complete` is true only when what was read is the
 * WHOLE log: false (with the reason) when a read failed part-way, when the log is longer than `maxRows`, or when the
 * database holds a different number of entries than came back (a server that shortens pages makes a short page look like
 * the last one, and silently drops the rest).
 */
export async function loadAuditRows(
  db: SupabaseClient<Database>, org_id: string, opts: { maxRows?: number } = {},
): Promise<{ rows: ChainRow[]; complete: boolean; reason?: AuditLoadIncomplete }> {
  const maxRows = opts.maxRows ?? MAX_AUDIT_ROWS;
  const rows: ChainRow[] = [];
  let ranToLimit = true;
  try {
    for (let from = 0; from < maxRows; from += PAGE) {
      const { data, error } = await db
        .from("audit_log")
        .select("id, event_type, actor_id, actor_email, resource_type, resource_id, payload, prev_hash, entry_hash, created_at")
        .eq("org_id", org_id)
        .order("id", { ascending: true })
        .range(from, from + PAGE - 1) as { data: ChainRow[] | null; error: unknown };
      if (error) throw error;
      rows.push(...(data ?? []).map(r => ({ ...r, org_id })));
      if (!data || data.length < PAGE) { ranToLimit = false; break; }
    }
    // The loop ended on its limit, or on a page that merely looked short: ask the database how many entries there are.
    const { count, error: countError } = await db.from("audit_log").select("id", { count: "exact", head: true }).eq("org_id", org_id);
    if (countError || count == null) return { rows, complete: false, reason: "read_failed" };
    if (count > rows.length) return { rows, complete: false, reason: ranToLimit ? "limit_reached" : "count_mismatch" };
    if (count < rows.length) return { rows, complete: false, reason: "count_mismatch" };
  } catch {
    return { rows, complete: false, reason: "read_failed" };
  }
  return { rows, complete: true };
}

/** Verify the integrity of the audit log chain for an org (every entry, paged past the 1000-row cap). */
export async function verifyAuditChain(
  db: SupabaseClient<Database>,
  org_id: string,
): Promise<ChainVerification> {
  const { rows, complete, reason } = await loadAuditRows(db, org_id);
  if (!complete) {
    return {
      status: reason === "limit_reached" ? "INCOMPLETE_LIMIT_REACHED" : "INCOMPLETE",
      valid: false,
      total: rows.length,
      verified: 0,
      metadata_verified: 0,
      legacy: 0,
      concurrent: 0,
      first_at: rows[0]?.created_at ?? null,
      last_at: rows[rows.length - 1]?.created_at ?? null,
    };
  }
  return checkAuditChain(rows);
}
