/**
 * Is the scan pipeline healthy? Finds work that should have finished but didn't, plus recent failure counts.
 * Used live by the Trace page and once a day by the pipeline-health job (which raises alerts).
 *
 *  - Undelivered webhooks: GitHub/GitLab/Bitbucket deliveries still unprocessed 10+ minutes after arriving
 *    (works without the ops_events table).
 *  - Stuck scans: a scan.queued event with nothing after it (completed / failed / skipped / superseded) for 15+
 *    minutes.
 */
import type { SupabaseClient } from "@supabase/supabase-js";

export const UNDELIVERED_AFTER_MIN = 10;
export const STUCK_AFTER_MIN = 15;
const FINISHED = ["scan.completed", "scan.failed", "scan.skipped", "scan.superseded"];

export interface StuckScan { trace_id: string; repo: string | null; pr_number: number | null; queued_at: string; minutes: number }
export interface UndeliveredWebhook { id: string; repo: string | null; event_type: string; received_at: string; minutes: number; error: string | null }
export interface PipelineHealth {
  stuck_scans: StuckScan[];
  undelivered_webhooks: UndeliveredWebhook[];
  failed_scans_24h: number;
  api_errors_24h: number;
  completed_scans_24h: number;
  events_available: boolean;          // false until the ops_events migration has run
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export async function pipelineHealth(db: SupabaseClient<any>, orgId: string, now = Date.now()): Promise<PipelineHealth> {
  const dayAgo = new Date(now - 24 * 3600_000).toISOString();
  const minutesSince = (iso: string) => Math.floor((now - Date.parse(iso)) / 60_000);

  const { data: deliveries } = await db
    .from("webhook_deliveries")
    .select("id, repo_full_name, event_type, created_at, error, processed")
    .eq("org_id", orgId)
    .eq("processed", false)
    .gte("created_at", dayAgo)
    .lt("created_at", new Date(now - UNDELIVERED_AFTER_MIN * 60_000).toISOString())
    .order("created_at", { ascending: false })
    .limit(50) as { data: Array<{ id: string; repo_full_name: string | null; event_type: string; created_at: string; error: string | null }> | null };
  const undelivered_webhooks = (deliveries ?? []).map(d => ({
    id: d.id, repo: d.repo_full_name, event_type: d.event_type, received_at: d.created_at, minutes: minutesSince(d.created_at), error: d.error,
  }));

  const { data: events, error } = await db
    .from("ops_events")
    .select("trace_id, kind, repo, pr_number, created_at")
    .eq("org_id", orgId)
    .gte("created_at", dayAgo)
    .in("kind", ["scan.queued", "scan.failed", "api.error", ...FINISHED])
    .order("created_at", { ascending: true })
    .limit(5000) as { data: Array<{ trace_id: string; kind: string; repo: string | null; pr_number: number | null; created_at: string }> | null; error: unknown };

  if (error || !events) {
    return { stuck_scans: [], undelivered_webhooks, failed_scans_24h: 0, api_errors_24h: 0, completed_scans_24h: 0, events_available: false };
  }

  const finishedTraces = new Set(events.filter(e => FINISHED.includes(e.kind)).map(e => e.trace_id));
  const queued = new Map<string, (typeof events)[number]>();
  for (const e of events) if (e.kind === "scan.queued") queued.set(e.trace_id, e);   // latest queue per trace
  const stuck_scans = [...queued.values()]
    .filter(q => !finishedTraces.has(q.trace_id) && minutesSince(q.created_at) >= STUCK_AFTER_MIN)
    .map(q => ({ trace_id: q.trace_id, repo: q.repo, pr_number: q.pr_number, queued_at: q.created_at, minutes: minutesSince(q.created_at) }))
    .sort((a, b) => b.minutes - a.minutes);

  return {
    stuck_scans,
    undelivered_webhooks,
    failed_scans_24h:    events.filter(e => e.kind === "scan.failed").length,
    api_errors_24h:      events.filter(e => e.kind === "api.error").length,
    completed_scans_24h: events.filter(e => e.kind === "scan.completed").length,
    events_available:    true,
  };
}
