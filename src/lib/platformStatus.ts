/**
 * What the public status page shows: coarse component states derived from the real signals (lib/opsStatus.ts), and the operator's
 * notices (platform_notices). No counts, no organisation ids, nothing about any customer: a state per component and the notices.
 */
import type { SupabaseClient } from "@supabase/supabase-js";
import { opsStatus, type OpsCheck } from "@/lib/opsStatus";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Db = SupabaseClient<any>;

export type ComponentState = "operational" | "degraded" | "down";
export interface PublicComponent { key: "database" | "scans" | "audit_log" | "webhooks"; name: string; state: ComponentState }
export interface PublicNotice { id: string; severity: "info" | "degraded" | "outage"; title: string; body: string; started_at: string; updated_at: string; resolved_at: string | null }
export interface PublicStatus { components: PublicComponent[]; notices: PublicNotice[]; checked_at: string }

const failing = (checks: OpsCheck[], ...names: string[]) => checks.some(c => names.includes(c.name) && !c.ok);

/** Component states from the checks: a failing check degrades its component; no database answer is "down". */
export function componentsFrom(checks: OpsCheck[]): PublicComponent[] {
  const db = checks.find(c => c.name === "database");
  return [
    { key: "database", name: "Database", state: !db || db.value === null ? "down" : db.ok ? "operational" : "degraded" },
    { key: "scans", name: "Scanning", state: failing(checks, "queue_oldest_waiting", "scans_stuck_running", "scan_jobs_dead_24h") ? "degraded" : "operational" },
    { key: "audit_log", name: "Audit log", state: failing(checks, "audit_write_failures_1h", "audit_checkpoints_refused_24h") ? "degraded" : "operational" },
    { key: "webhooks", name: "Outbound webhooks", state: failing(checks, "webhooks_given_up_24h") ? "degraded" : "operational" },
  ];
}

export async function loadNotices(db: Db, now = Date.now()): Promise<PublicNotice[]> {
  const { data, error } = await db.from("platform_notices").select("id, severity, title, body, started_at, updated_at, resolved_at").order("started_at", { ascending: false }).limit(30) as { data: PublicNotice[] | null; error: unknown };
  if (error || !data) return [];
  const cutoff = now - 14 * 86400_000;
  // open ones, and resolved ones from the last two weeks; only the fields the page shows
  return data.filter(n => !n.resolved_at || Date.parse(n.resolved_at) >= cutoff).slice(0, 10)
    .map(n => ({ id: n.id, severity: n.severity, title: String(n.title).slice(0, 200), body: String(n.body ?? "").slice(0, 2000), started_at: n.started_at, updated_at: n.updated_at, resolved_at: n.resolved_at }));
}

export async function publicStatus(db: Db, now = Date.now()): Promise<PublicStatus> {
  const [status, notices] = await Promise.all([opsStatus(db, now), loadNotices(db, now)]);
  return { components: componentsFrom(status.checks), notices, checked_at: status.checked_at };
}
