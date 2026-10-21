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
  | "ai_tool_policy_changed" | "shadow_ai_triaged";

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
): Promise<void> {
  // Get the most recent entry hash for this org (to build the chain)
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
  await (db.from("audit_log") as any).insert({
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
}

export interface ChainRow { id: number; event_type: string; actor_email: string | null; payload: unknown; prev_hash: string | null; entry_hash: string; created_at: string }

export interface ChainVerification {
  valid: boolean;
  total: number;
  /** Entries whose contents were recomputed and matched. */
  verified: number;
  /** Older entries (before the first recomputable one) whose contents can't be recomputed; their links were checked. */
  legacy: number;
  /** Entries written at the same moment as another, both pointing at the same previous entry (not tampering). */
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
        return { ...base, verified, legacy, concurrent, valid: false, broken_at: r.id, reason: "missing_link" };
      }
      if (linkedFrom.has(r.prev_hash)) concurrent++;
      linkedFrom.add(r.prev_hash);
    }
    // Contents: recompute from the stored row.
    const at = Number.isNaN(Date.parse(r.created_at)) ? r.created_at : new Date(r.created_at).toISOString();
    const ok = auditEntryHash(r.prev_hash, r.event_type, r.actor_email, r.payload, at) === r.entry_hash;
    if (ok) { recomputable = true; verified++; }
    else if (!recomputable) legacy++;
    else return { ...base, verified, legacy, concurrent, valid: false, broken_at: r.id, reason: "content_changed" };
    seenHashes.add(r.entry_hash);
  }
  return { ...base, verified, legacy, concurrent, valid: true };
}

const PAGE = 1000;
const MAX_ROWS = 200_000;

/** Verify the integrity of the audit log chain for an org (every entry, paged past the 1000-row cap). */
export async function verifyAuditChain(
  db: SupabaseClient<Database>,
  org_id: string,
): Promise<ChainVerification> {
  const rows: ChainRow[] = [];
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
  return checkAuditChain(rows);
}
