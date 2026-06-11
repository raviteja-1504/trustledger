/**
 * Append-only, tamper-evident audit log writer.
 * Every entry includes the SHA-256 of the previous entry (hash chain).
 * Stored in the audit_log table which has no UPDATE/DELETE rules.
 */

import { buildAuditHash } from "./scanner";
import type { SupabaseClient } from "@supabase/supabase-js";
import type { Database } from "@/types/supabase";

export type AuditEventType =
  | "scan_complete" | "attestation" | "merge_blocked" | "merge_allowed"
  | "policy_violation" | "policy_change" | "secret_detected"
  | "integration_connected" | "user_added" | "user_removed"
  | "sla_breach" | "alert_fired" | "alert_resolved"
  | "incident_created" | "incident_resolved"
  | "api_key_created" | "api_key_revoked"
  | "violation_resolved" | "violation_escalated"
  | "report_generated" | "org_settings_changed";

interface AuditEntry {
  org_id:        string;
  event_type:    AuditEventType;
  actor_id?:     string | null;
  actor_email?:  string | null;
  resource_type?: string;
  resource_id?:  string;
  payload:       Record<string, unknown>;
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
  const entryHash = buildAuditHash(
    prevHash,
    entry.event_type,
    entry.actor_email ?? "system",
    JSON.stringify(entry.payload),
    now,
  );

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
  });
}

/** Verify the integrity of the audit log chain for an org. */
export async function verifyAuditChain(
  db: SupabaseClient<Database>,
  org_id: string,
): Promise<{ valid: boolean; broken_at?: number; total: number }> {
  const { data: rows } = await db
    .from("audit_log")
    .select("id, event_type, actor_email, payload, prev_hash, entry_hash, created_at")
    .eq("org_id", org_id)
    .order("id", { ascending: true }) as {
      data: Array<{ id: number; event_type: string; actor_email: string | null; payload: unknown; prev_hash: string | null; entry_hash: string; created_at: string }> | null
    };

  if (!rows || rows.length === 0) return { valid: true, total: 0 };

  for (let i = 0; i < rows.length; i++) {
    const row      = rows[i];
    const prevHash = i === 0 ? null : rows[i - 1].entry_hash;

    const expected = buildAuditHash(
      prevHash,
      row.event_type,
      row.actor_email ?? "system",
      JSON.stringify(row.payload),
      row.created_at,
    );

    if (expected !== row.entry_hash) {
      return { valid: false, broken_at: row.id, total: rows.length };
    }
  }

  return { valid: true, total: rows.length };
}
