/**
 * The platform's own health, for an external monitor to poll (GET /api/ops/status). Platform-wide numbers only: counts and ages,
 * and at most the opaque ids of the organisations with the most failures -- never an organisation's name, repository, person or
 * payload -- so it is safe to look at, paste into an incident channel, or hand to support.
 *
 * Nothing here is scheduled by the app. An uptime service (or anyone with the token) asks; each check says whether it passes and what
 * it measured. A check whose table does not exist yet is skipped, not failed.
 */
import type { SupabaseClient } from "@supabase/supabase-js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Db = SupabaseClient<any>;

export interface OpsCheck { name: string; ok: boolean; value: number | null; limit: number; unit: string; skipped?: boolean; note: string }
export interface OpsStatus { status: "ok" | "degraded"; checked_at: string; checks: OpsCheck[]; failing_orgs: Array<{ org_id: string; dead: number; failed: number }> }

/** What "too slow" or "too many" means. A check passes while its value is at most the limit. */
export const LIMITS = {
  databaseMs: 2000,
  oldestWaitingMinutes: 10,
  stuckRunning: 0,
  deadJobs24h: 0,
  auditFailures1h: 0,
  checkpointsRefused24h: 0,
  webhooksGivenUp24h: 10,
} as const;
const RUNNING_STALE_MIN = 15;

type DbError = { code?: string; message?: string } | null;
const minutes = (iso: string, now: number) => Math.max(0, Math.round((now - Date.parse(iso)) / 60_000));
const missing = (e: DbError) => !!e && (e.code === "42P01" || e.code === "PGRST205" || /does not exist|schema cache/i.test(e.message ?? ""));

export async function opsStatus(db: Db, now = Date.now()): Promise<OpsStatus> {
  const iso = (msAgo: number) => new Date(now - msAgo).toISOString();
  const checks: OpsCheck[] = [];

  // the database answers, and how fast
  const t0 = Date.now();
  const ping = await db.from("organizations").select("id").limit(1) as { error: DbError };
  const pingMs = Date.now() - t0;
  checks.push({ name: "database", value: ping.error ? null : pingMs, limit: LIMITS.databaseMs, unit: "ms", ok: !ping.error && pingMs <= LIMITS.databaseMs, note: "A simple query answers within the limit" });

  // a counted check: passes while the count is within the limit; a missing table is skipped
  const counted = async (name: string, limit: number, unit: string, note: string, q: PromiseLike<{ count: number | null; error: DbError }>) => {
    const r = await q;
    if (r.error) { checks.push({ name, value: null, limit, unit, skipped: missing(r.error), ok: missing(r.error), note }); return; }
    const value = r.count ?? 0;
    checks.push({ name, value, limit, unit, ok: value <= limit, note });
  };

  // the oldest scan still waiting in the queue
  const oldest = await db.from("scan_jobs").select("created_at").eq("status", "queued").order("created_at", { ascending: true }).limit(1) as { data: Array<{ created_at: string }> | null; error: DbError };
  const waitNote = "The oldest scan waiting in the queue";
  if (oldest.error) checks.push({ name: "queue_oldest_waiting", value: null, limit: LIMITS.oldestWaitingMinutes, unit: "min", skipped: missing(oldest.error), ok: missing(oldest.error), note: waitNote });
  else {
    const value = oldest.data?.[0] ? minutes(oldest.data[0].created_at, now) : 0;
    checks.push({ name: "queue_oldest_waiting", value, limit: LIMITS.oldestWaitingMinutes, unit: "min", ok: value <= LIMITS.oldestWaitingMinutes, note: waitNote });
  }

  await counted("scans_stuck_running", LIMITS.stuckRunning, "jobs", `Scans running for more than ${RUNNING_STALE_MIN} minutes`,
    db.from("scan_jobs").select("id", { count: "exact", head: true }).eq("status", "running").lt("started_at", iso(RUNNING_STALE_MIN * 60_000)));
  await counted("scan_jobs_dead_24h", LIMITS.deadJobs24h, "jobs", "Scans that ran out of attempts and wait to be replayed",
    db.from("scan_jobs").select("id", { count: "exact", head: true }).eq("status", "dead").gte("updated_at", iso(24 * 3600_000)));
  await counted("audit_write_failures_1h", LIMITS.auditFailures1h, "events", "Required audit entries that could not be written",
    db.from("ops_events").select("id", { count: "exact", head: true }).eq("kind", "audit.write_failed").gte("created_at", iso(3600_000)));
  await counted("audit_checkpoints_refused_24h", LIMITS.checkpointsRefused24h, "events", "An audit log failed verification, so no checkpoint was signed",
    db.from("ops_events").select("id", { count: "exact", head: true }).eq("kind", "audit.checkpoint_refused").gte("created_at", iso(24 * 3600_000)));
  await counted("webhooks_given_up_24h", LIMITS.webhooksGivenUp24h, "deliveries", "Outbound webhook deliveries given up on",
    db.from("webhook_failed_deliveries").select("id", { count: "exact", head: true }).eq("permanently_failed", true).gte("created_at", iso(24 * 3600_000)));

  // which organisations have the most failed scans: opaque ids and counts, nothing else
  const bad = await db.from("scan_jobs").select("org_id, status").in("status", ["dead", "failed"]).gte("updated_at", iso(24 * 3600_000)).limit(1000) as { data: Array<{ org_id: string; status: string }> | null };
  const perOrg = new Map<string, { dead: number; failed: number }>();
  for (const r of bad.data ?? []) {
    const e = perOrg.get(r.org_id) ?? { dead: 0, failed: 0 };
    if (r.status === "dead") e.dead++; else e.failed++;
    perOrg.set(r.org_id, e);
  }
  const failing_orgs = [...perOrg.entries()].map(([org_id, c]) => ({ org_id, ...c })).sort((a, b) => (b.dead * 10 + b.failed) - (a.dead * 10 + a.failed)).slice(0, 5);

  return { status: checks.every(c => c.ok) ? "ok" : "degraded", checked_at: new Date(now).toISOString(), checks, failing_orgs };
}
