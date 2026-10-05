/**
 * Data retention: each org's policy (organizations.retention_policy) and the deletes that apply it -- by hand
 * (DELETE /api/retention) or every day when the org has switched on automatic enforcement (the daily cron).
 *
 * What automatic enforcement never deletes:
 *   - attested scans (attestations are immutable by DB rule -- a reviewer's sign-off is a permanent record);
 *   - anything still open (violations, secrets, incidents, alerts are removed only once closed);
 *   - the audit log (append-only and hash-chained: removing its oldest entries would break verification).
 */
import type { SupabaseClient } from "@supabase/supabase-js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Db = SupabaseClient<any>;

export const DATA_KEYS = ["scans_days", "violations_days", "secret_findings_days", "incidents_days", "alerts_days"] as const;
export type DataKey = typeof DATA_KEYS[number];

export interface RetentionPolicy extends Record<DataKey, number> {
  audit_log_days: number;
  /** Off by default: switching it on deletes history, so an org must choose it. */
  auto_enforce:   boolean;
  last_enforced_at?: string | null;
  last_result?:      RetentionRunSummary | null;
}

export const RETENTION_DEFAULTS: RetentionPolicy = {
  scans_days:           365,
  violations_days:      365,
  secret_findings_days: 365,
  incidents_days:       2555,
  alerts_days:          365,
  audit_log_days:       2555,   // 7 years (SOC 2 practice); never purged automatically
  auto_enforce:         false,
};

/** Bounds: nothing younger than 30 days is ever deleted automatically; 7 years max. */
export const MIN_DAYS = 30;
export const MAX_DAYS = 2555;

const clamp = (v: unknown, fallback: number, min = MIN_DAYS, max = MAX_DAYS) =>
  typeof v === "number" && Number.isFinite(v) ? Math.min(Math.max(Math.round(v), min), max) : fallback;

/** Any stored or submitted value → a complete, in-bounds policy. Unknown keys are dropped. */
export function normalizeRetention(raw: unknown, base: RetentionPolicy = RETENTION_DEFAULTS): RetentionPolicy {
  const r = (raw && typeof raw === "object" ? raw : {}) as Record<string, unknown>;
  const out = { ...base } as RetentionPolicy;
  for (const k of DATA_KEYS) out[k] = clamp(r[k], base[k]);
  out.audit_log_days = clamp(r.audit_log_days, base.audit_log_days, 365, 3650);
  out.auto_enforce = typeof r.auto_enforce === "boolean" ? r.auto_enforce : base.auto_enforce;
  if ("last_enforced_at" in r) out.last_enforced_at = (r.last_enforced_at as string | null) ?? null;
  if ("last_result" in r) out.last_result = (r.last_result as RetentionRunSummary | null) ?? null;
  return out;
}

export async function loadRetention(db: Db, orgId: string): Promise<RetentionPolicy> {
  const { data } = await db.from("organizations").select("retention_policy").eq("id", orgId).maybeSingle() as { data: { retention_policy?: unknown } | null };
  return normalizeRetention(data?.retention_policy);
}

/** Statuses after which a record may be removed by age. */
export const CLOSED_STATUSES: Record<string, string[]> = {
  violations:      ["resolved", "accepted"],
  secret_findings: ["resolved"],
  incidents:       ["resolved", "closed"],
  alerts:          ["resolved"],
};

/** Old scans are processed in batches so one run can't time out on a large backlog. */
export const SCAN_BATCH = 500;

export interface PurgeResult { deleted: number; retained_attested: number; failed: boolean }

/** Deletes this org's scans created before `cutoff` that nobody attested, with the rows that reference them
 * (scan_files cascade). Attested scans are reported, never deleted. */
export async function purgeScansBefore(db: Db, orgId: string, cutoff: string, limit = SCAN_BATCH): Promise<PurgeResult> {
  const { data: oldScans } = await db.from("scans").select("id").eq("org_id", orgId).lt("created_at", cutoff).limit(limit);
  const oldIds = ((oldScans ?? []) as Array<{ id: string }>).map(s => s.id);
  if (oldIds.length === 0) return { deleted: 0, retained_attested: 0, failed: false };

  const { data: attested } = await db.from("attestations").select("scan_id").eq("org_id", orgId).in("scan_id", oldIds);
  const attestedSet = new Set(((attested ?? []) as Array<{ scan_id: string }>).map(a => a.scan_id));
  const eligible = oldIds.filter(id => !attestedSet.has(id));
  const retained = oldIds.length - eligible.length;
  if (eligible.length === 0) return { deleted: 0, retained_attested: retained, failed: false };

  // violations / secret_findings / alerts reference scans with NO ACTION: clear them first.
  for (const t of ["violations", "secret_findings", "alerts"]) {
    await db.from(t).delete().eq("org_id", orgId).in("scan_id", eligible);
  }
  const { count, error } = await db.from("scans").delete({ count: "exact" }).eq("org_id", orgId).in("id", eligible) as
    { count: number | null; error: unknown };
  return { deleted: error ? 0 : (count ?? eligible.length), retained_attested: retained, failed: !!error };
}

/** Deletes this org's rows in `table` created before `cutoff` -- only closed ones unless `includeOpen`. */
export async function purgeTableBefore(db: Db, orgId: string, table: string, cutoff: string, includeOpen = false): Promise<{ deleted: number; failed: boolean }> {
  let q = db.from(table).delete({ count: "exact" }).eq("org_id", orgId).lt("created_at", cutoff);
  if (!includeOpen) q = q.in("status", CLOSED_STATUSES[table] ?? []);
  const { count, error } = await q as { count: number | null; error: unknown };
  return { deleted: error ? 0 : (count ?? 0), failed: !!error };
}

export interface RetentionRunSummary {
  at: string;
  deleted: Record<string, number>;
  attested_scans_kept: number;
  failed: string[];
}

const TABLE_FOR: Record<Exclude<DataKey, "scans_days">, string> = {
  violations_days: "violations", secret_findings_days: "secret_findings", incidents_days: "incidents", alerts_days: "alerts",
};

export const cutoffFor = (days: number, now: number) => new Date(now - days * 86_400_000).toISOString();

/** Applies the policy once. Deletes only closed records (and unattested scans) older than each period. */
export async function enforceRetention(db: Db, orgId: string, policy: RetentionPolicy, now = Date.now()): Promise<RetentionRunSummary> {
  const summary: RetentionRunSummary = { at: new Date(now).toISOString(), deleted: {}, attested_scans_kept: 0, failed: [] };
  const scans = await purgeScansBefore(db, orgId, cutoffFor(policy.scans_days, now));
  summary.deleted.scans = scans.deleted;
  summary.attested_scans_kept = scans.retained_attested;
  if (scans.failed) summary.failed.push("scans");
  for (const [key, table] of Object.entries(TABLE_FOR) as Array<[DataKey, string]>) {
    const r = await purgeTableBefore(db, orgId, table, cutoffFor(policy[key], now));
    summary.deleted[table] = r.deleted;
    if (r.failed) summary.failed.push(table);
  }
  return summary;
}

export const totalDeleted = (s: RetentionRunSummary) => Object.values(s.deleted).reduce((a, b) => a + b, 0);
