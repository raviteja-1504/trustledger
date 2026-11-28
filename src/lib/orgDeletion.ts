/**
 * Organisation deletion workflow (supabase/migrations/20261129_org_deletion_requests.sql): what would be deleted, how long the
 * waiting period is, and the request's state. The route (app/api/orgs/delete) is the only caller.
 */
import type { SupabaseClient } from "@supabase/supabase-js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Db = SupabaseClient<any>;

export interface DeletionRequest {
  id: string; org_id: string; requested_by_email: string | null; requested_at: string; execute_after: string;
  status: "pending" | "executing" | "completed" | "failed" | "cancelled";
  preview: Record<string, unknown>; cancelled_at: string | null; completed_at: string | null; error: string | null;
}

/** Hours between the request and the earliest execution. ORG_DELETION_DELAY_HOURS, default 24, at most 30 days; at least 1 in production. */
export function deletionDelayHours(): number {
  const n = parseInt(process.env.ORG_DELETION_DELAY_HOURS ?? "24", 10);
  const hours = Number.isFinite(n) ? Math.min(720, Math.max(0, n)) : 24;
  return process.env.NODE_ENV === "production" || process.env.VERCEL_ENV === "production" ? Math.max(1, hours) : hours;
}

/** Customer data that is deleted, by what an admin would call it. */
const DELETED: Array<{ key: string; label: string; table: string }> = [
  { key: "members", label: "Members", table: "org_members" },
  { key: "repositories", label: "Repositories", table: "repositories" },
  { key: "scans", label: "Scans", table: "scans" },
  { key: "violations", label: "Violations", table: "violations" },
  { key: "secret_findings", label: "Secret findings", table: "secret_findings" },
  { key: "incidents", label: "Incidents", table: "incidents" },
  { key: "api_keys", label: "API keys", table: "api_keys" },
  { key: "webhooks", label: "Webhooks", table: "webhook_configs" },
  { key: "evidence", label: "Evidence records", table: "evidence_log" },
];
/** Evidence that is kept, against an anonymised organisation record (see delete_org_cascade). */
const RETAINED: Array<{ key: string; label: string; table: string }> = [
  { key: "audit_log", label: "Audit log entries", table: "audit_log" },
  { key: "attestations", label: "Attestations", table: "attestations" },
  { key: "audit_checkpoints", label: "Signed audit checkpoints", table: "audit_checkpoints" },
];

async function count(db: Db, table: string, orgId: string): Promise<number | null> {
  const { count: n, error } = await db.from(table).select("id", { count: "exact", head: true }).eq("org_id", orgId);
  return error ? null : (n ?? 0);
}

export async function deletionPreview(db: Db, orgId: string) {
  const [deleted, retained] = await Promise.all([
    Promise.all(DELETED.map(async d => ({ key: d.key, label: d.label, count: await count(db, d.table, orgId) }))),
    Promise.all(RETAINED.map(async d => ({ key: d.key, label: d.label, count: await count(db, d.table, orgId) }))),
  ]);
  return {
    deleted, retained,
    // where an admin takes a copy first: the exports are audited and need their own sign-in, so they are pages, not links to files
    exports: [
      { label: "Audit log (signed export)", href: "/audit" },
      { label: "Reports and evidence", href: "/reports" },
    ],
  };
}

export async function openRequest(db: Db, orgId: string): Promise<DeletionRequest | null> {
  const { data } = await db.from("org_deletion_requests").select("*").eq("org_id", orgId).in("status", ["pending", "executing", "failed"]).maybeSingle() as { data: DeletionRequest | null };
  return data;
}
