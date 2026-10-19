/**
 * An organisation's data version: when it last attested, scanned or changed a violation's status. Put it in cache
 * keys for anything derived from those tables, so a copy computed before a change is never used after it -- on any
 * server instance. (Deleting keys on write isn't enough: without Redis each instance has its own in-memory cache, and
 * a request in flight during the write can store the old result right after the delete.)
 *
 * Returns null when it can't be read: callers must then not cache.
 */
import type { SupabaseClient } from "@supabase/supabase-js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Db = SupabaseClient<any>;

export async function orgDataVersion(db: Db, orgId: string): Promise<string | null> {
  const latest = (table: string, column: string) =>
    db.from(table).select(column).eq("org_id", orgId).order(column, { ascending: false }).limit(1).maybeSingle() as unknown as
      Promise<{ data: Record<string, string> | null; error: unknown }>;
  try {
    // violations rows have no updated_at, so a status change there (PATCH /api/violations, incl. reopening) is seen
    // through the audit entry that route writes for every change.
    const statusChange = db.from("audit_log").select("created_at").eq("org_id", orgId).eq("event_type", "violation_resolved")
      .order("created_at", { ascending: false }).limit(1).maybeSingle() as unknown as Promise<{ data: Record<string, string> | null; error: unknown }>;
    const rows = await Promise.all([latest("attestations", "created_at"), latest("scans", "created_at"), latest("violation_overrides", "updated_at"), statusChange]);
    // A table that doesn't exist yet (older database) just contributes nothing; any other error means "unknown".
    if (rows.slice(0, 2).some(r => r.error)) return null;
    return [rows[0].data?.created_at, rows[1].data?.created_at, rows[2].error ? "" : rows[2].data?.updated_at, rows[3].error ? "" : rows[3].data?.created_at]
      .map(v => v ?? "").join("|");
  } catch { return null; }
}

export const versionedKey = (key: string, version: string) => `${key}:v:${version}`;
