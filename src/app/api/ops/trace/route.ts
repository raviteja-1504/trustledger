/**
 * Trace lookup for admins and security reviewers (the Trace page).
 *
 * GET /api/ops/trace                 → pipeline health + the most recent traces (last 24 h)
 * GET /api/ops/trace?q=<anything>    → the traces matching q, each as a full timeline:
 *     owner/repo#42   a pull request          3f9a1c22   an error reference (ref_id) shown to a user
 *     <uuid>          a scan id, webhook delivery id, or GitHub delivery GUID
 *     <other>         a trace id (also returned in X-Trace-Id / x-request-id headers)
 */
import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey, requireRole } from "../../_middleware";
import { pipelineHealth } from "@/lib/pipelineHealth";

type EventRow = {
  id: number; created_at: string; trace_id: string; kind: string; level: string; message: string | null;
  scan_id: string | null; delivery_id: string | null; repo: string | null; pr_number: number | null;
  ref_id: string | null; duration_ms: number | null; data: Record<string, unknown>;
};
const COLS = "id, created_at, trace_id, kind, level, message, scan_id, delivery_id, repo, pr_number, ref_id, duration_ms, data";
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export async function GET(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });
  const roleErr = requireRole(auth, "security_reviewer");
  if (roleErr) return NextResponse.json({ error: roleErr, message: "Tracing is available to admins and security reviewers." }, { status: 403 });

  const db = createServiceClient();
  const q = (req.nextUrl.searchParams.get("q") ?? "").trim().slice(0, 200);
  const health = await pipelineHealth(db, auth.org_id);

  const scoped = () => db.from("ops_events").select(COLS).eq("org_id", auth.org_id);
  let seeds: EventRow[] = [];
  if (!q) {
    const { data } = await scoped().gte("created_at", new Date(Date.now() - 24 * 3600_000).toISOString())
      .order("created_at", { ascending: false }).limit(300) as { data: EventRow[] | null };
    seeds = data ?? [];
  } else {
    const pr = q.match(/^([\w.-]+\/[\w.-]+)#(\d+)$/);
    const query = pr ? scoped().eq("repo", pr[1]).eq("pr_number", Number(pr[2]))
      : /^[0-9a-f]{8}$/i.test(q) ? scoped().eq("ref_id", q.toLowerCase())
      : UUID.test(q) ? scoped().or(`scan_id.eq.${q},delivery_id.eq.${q},trace_id.eq.${q}`)
      : /^[A-Za-z0-9-]{8,64}$/.test(q) ? scoped().eq("trace_id", q)
      : null;
    if (!query) return NextResponse.json({ error: "invalid_query", message: "Search by owner/repo#PR, an error reference, a scan or delivery ID, or a trace ID." }, { status: 400 });
    const { data } = await query.order("created_at", { ascending: false }).limit(200) as { data: EventRow[] | null };
    seeds = data ?? [];
  }

  // Expand to whole traces, newest first, at most 25.
  const traceIds = [...new Set(seeds.map(e => e.trace_id))].slice(0, 25);
  let events: EventRow[] = [];
  if (traceIds.length > 0) {
    const { data } = await scoped().in("trace_id", traceIds).order("created_at", { ascending: true }).limit(2000) as { data: EventRow[] | null };
    events = data ?? [];
  }
  const stuck = new Set(health.stuck_scans.map(s => s.trace_id));
  const traces = traceIds.map(id => {
    const ev = events.filter(e => e.trace_id === id);
    const kinds = new Set(ev.map(e => e.kind));
    const status = kinds.has("scan.failed") || kinds.has("scan.enqueue_failed") ? "failed"
      : kinds.has("scan.completed") ? "completed"
      : kinds.has("scan.superseded") ? "superseded"
      : kinds.has("scan.skipped") ? "skipped"
      : stuck.has(id) ? "stuck"
      : kinds.has("api.error") ? "error"
      : kinds.has("scan.queued") || kinds.has("scan.started") ? "running"
      : "info";
    const first = ev[0], last = ev[ev.length - 1];
    return {
      trace_id: id, status,
      repo: ev.find(e => e.repo)?.repo ?? null, pr_number: ev.find(e => e.pr_number != null)?.pr_number ?? null,
      scan_id: ev.find(e => e.scan_id)?.scan_id ?? null,
      started_at: first?.created_at ?? null, last_at: last?.created_at ?? null,
      events: ev,
    };
  });

  return NextResponse.json({ health, traces });
}
