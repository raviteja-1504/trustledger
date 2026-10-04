"use client";

/**
 * Trace — what happened to a scan or a request, step by step (admins and security reviewers).
 * Search by owner/repo#PR, an error reference a user was shown, a scan / delivery ID, or a trace ID.
 */
import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import AuthGuard from "@/components/AuthGuard";
import { authedFetch } from "@/lib/useRealData";

interface TraceEvent {
  id: number; created_at: string; trace_id: string; kind: string; level: string; message: string | null;
  scan_id: string | null; delivery_id: string | null; repo: string | null; pr_number: number | null;
  ref_id: string | null; duration_ms: number | null; data: Record<string, unknown>;
}
interface Trace {
  trace_id: string; status: string; repo: string | null; pr_number: number | null; scan_id: string | null;
  started_at: string | null; last_at: string | null; events: TraceEvent[];
}
interface Health {
  stuck_scans: Array<{ trace_id: string; repo: string | null; pr_number: number | null; minutes: number }>;
  undelivered_webhooks: Array<{ id: string; repo: string | null; event_type: string; minutes: number; error: string | null }>;
  failed_scans_24h: number; api_errors_24h: number; completed_scans_24h: number; events_available: boolean;
}

const KIND_LABEL: Record<string, string> = {
  "webhook.received": "Webhook received", "webhook.ignored": "Webhook ignored",
  "scan.queued": "Scan queued", "scan.enqueue_failed": "Couldn't queue scan", "scan.started": "Scan started",
  "scan.files_fetched": "Files fetched from GitHub", "scan.completed": "Scan completed", "scan.failed": "Scan failed",
  "scan.skipped": "Skipped (already scanned)", "scan.superseded": "Superseded by a newer push",
  "checkrun.updated": "Check run updated", "checkrun.failed": "Check run update failed",
  "api.error": "Request failed", "pipeline.stuck": "Pipeline alert raised",
};
const STATUS_STYLE: Record<string, string> = {
  completed: "bg-emerald-50 text-emerald-700 ring-emerald-200", failed: "bg-rose-50 text-rose-700 ring-rose-200",
  stuck: "bg-amber-50 text-amber-800 ring-amber-200", running: "bg-sky-50 text-sky-700 ring-sky-200",
  error: "bg-rose-50 text-rose-700 ring-rose-200", superseded: "bg-gray-100 text-gray-600 ring-gray-200",
  skipped: "bg-gray-100 text-gray-600 ring-gray-200", info: "bg-gray-100 text-gray-600 ring-gray-200",
};
const DOT: Record<string, string> = { error: "bg-rose-500", warn: "bg-amber-400", info: "bg-indigo-400" };

const time = (iso: string) => new Date(iso).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" });
const dur = (ms: number | null) => ms == null ? null : ms < 1000 ? `${ms} ms` : `${(ms / 1000).toFixed(1)} s`;

function HealthTile({ label, value, hint, tone }: { label: string; value: number | string; hint: string; tone: "ok" | "warn" | "bad" }) {
  const c = tone === "ok" ? "text-emerald-700" : tone === "warn" ? "text-amber-700" : "text-rose-700";
  return (
    <div className="section-card p-4">
      <p className="text-[11px] font-bold uppercase tracking-wider text-gray-400">{label}</p>
      <p className={`text-2xl font-black tabular-nums mt-1 ${c}`}>{value}</p>
      <p className="text-xs text-gray-400 mt-0.5">{hint}</p>
    </div>
  );
}

function TraceCard({ t, open, onToggle }: { t: Trace; open: boolean; onToggle: () => void }) {
  return (
    <div className="section-card overflow-hidden">
      <button type="button" onClick={onToggle} aria-expanded={open}
        className="w-full text-left px-4 sm:px-5 py-3 flex items-center gap-3 flex-wrap hover:bg-gray-50/70">
        <span className={`text-[11px] font-bold uppercase tracking-wide px-2 py-0.5 rounded-full ring-1 ${STATUS_STYLE[t.status] ?? STATUS_STYLE.info}`}>{t.status}</span>
        <span className="text-sm font-semibold text-gray-900 font-mono truncate">{t.repo ? `${t.repo}${t.pr_number ? ` #${t.pr_number}` : ""}` : KIND_LABEL[t.events[0]?.kind] ?? "Request"}</span>
        <span className="text-xs text-gray-400">{t.started_at ? time(t.started_at) : ""} · {t.events.length} step{t.events.length !== 1 ? "s" : ""}</span>
        <span className="ml-auto text-[11px] font-mono text-gray-400">trace {t.trace_id}</span>
      </button>
      {open && (
        <div className="border-t border-gray-100">
          <ol className="divide-y divide-gray-50">
            {t.events.map(e => (
              <li key={e.id} className="px-4 sm:px-5 py-2.5 flex items-start gap-3">
                <span className={`mt-1.5 w-2 h-2 rounded-full shrink-0 ${DOT[e.level] ?? DOT.info}`} />
                <div className="min-w-0 flex-1">
                  <p className="text-sm text-gray-900">
                    <span className="font-semibold">{KIND_LABEL[e.kind] ?? e.kind}</span>
                    {e.message && e.message !== e.kind && <span className="text-gray-500"> — {e.message}</span>}
                  </p>
                  <p className="text-[11px] text-gray-400 font-mono flex flex-wrap gap-x-3">
                    <span>{time(e.created_at)}</span>
                    {dur(e.duration_ms) && <span>{dur(e.duration_ms)}</span>}
                    {e.ref_id && <span>ref {e.ref_id}</span>}
                    {e.scan_id && <Link href={`/pr/${e.scan_id}`} className="text-indigo-500 hover:underline">scan {e.scan_id.slice(0, 8)}</Link>}
                  </p>
                  {Object.keys(e.data ?? {}).length > 0 && (
                    <details className="mt-1">
                      <summary className="text-[11px] text-gray-400 cursor-pointer select-none">details</summary>
                      <pre className="mt-1 text-[11px] bg-gray-50 border border-gray-100 rounded-lg p-2 overflow-x-auto whitespace-pre-wrap break-all">{JSON.stringify(e.data, null, 2)}</pre>
                    </details>
                  )}
                </div>
              </li>
            ))}
          </ol>
        </div>
      )}
    </div>
  );
}

export default function TracePage() {
  const [query, setQuery] = useState("");
  const [submitted, setSubmitted] = useState("");
  const [health, setHealth] = useState<Health | null>(null);
  const [traces, setTraces] = useState<Trace[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState<Set<string>>(new Set());

  const load = useCallback(async (q: string) => {
    setError(null); setTraces(null);
    try {
      const res = await authedFetch<{ health: Health; traces: Trace[] }>(`/api/ops/trace${q ? `?q=${encodeURIComponent(q)}` : ""}`);
      setHealth(res.health); setTraces(res.traces);
      setOpen(new Set(q && res.traces[0] ? [res.traces[0].trace_id] : []));
    } catch (e) {
      setTraces([]); setError(e instanceof Error ? e.message : "Couldn't load traces.");
    }
  }, []);
  useEffect(() => { load(""); }, [load]);

  const toggle = (id: string) => setOpen(s => { const n = new Set(s); n.has(id) ? n.delete(id) : n.add(id); return n; });

  return (
    <AuthGuard>
      <div className="max-w-5xl mx-auto space-y-5 pb-12">
        <div>
          <h1 className="text-xl font-extrabold text-gray-900 tracking-tight">Trace</h1>
          <p className="text-sm text-gray-500 mt-0.5">What happened to a scan or a request, step by step. Events are kept for 30 days.</p>
        </div>

        {health && (
          <section aria-label="Pipeline health" className="grid grid-cols-2 lg:grid-cols-4 gap-3">
            <HealthTile label="Stuck scans" value={health.stuck_scans.length} hint="queued 15+ min, not finished" tone={health.stuck_scans.length ? "bad" : "ok"} />
            <HealthTile label="Failed scans" value={health.failed_scans_24h} hint={`last 24 h · ${health.completed_scans_24h} completed`} tone={health.failed_scans_24h ? "bad" : "ok"} />
            <HealthTile label="Request errors" value={health.api_errors_24h} hint="last 24 h" tone={health.api_errors_24h ? "warn" : "ok"} />
            <HealthTile label="Unprocessed webhooks" value={health.undelivered_webhooks.length} hint="10+ min old" tone={health.undelivered_webhooks.length ? "bad" : "ok"} />
          </section>
        )}
        {health && !health.events_available && (
          <p role="status" className="text-xs text-amber-800 bg-amber-50 border border-amber-200 rounded-xl px-3.5 py-2.5">
            Step-by-step events aren&apos;t being stored yet — run the <span className="font-mono">20261004_ops_events.sql</span> migration in Supabase. Webhook checks still work.
          </p>
        )}

        <form onSubmit={e => { e.preventDefault(); setSubmitted(query.trim()); load(query.trim()); }} className="flex gap-2">
          <input value={query} onChange={e => setQuery(e.target.value)} aria-label="Search traces"
            placeholder="owner/repo#42 · error reference (e.g. 3f9a1c22) · scan, delivery or trace ID"
            className="flex-1 min-w-0 text-sm border border-gray-200 rounded-xl px-3.5 py-2.5 focus:outline-none focus:ring-2 focus:ring-indigo-400 bg-white" />
          <button type="submit" className="px-4 py-2.5 text-sm font-bold rounded-xl bg-indigo-600 text-white hover:bg-indigo-700">Search</button>
          {submitted && <button type="button" onClick={() => { setQuery(""); setSubmitted(""); load(""); }} className="px-3 py-2.5 text-sm font-semibold text-gray-500 hover:text-gray-800">Clear</button>}
        </form>

        {error && <p role="alert" className="text-sm text-rose-600">{error}</p>}

        {health && health.undelivered_webhooks.length > 0 && !submitted && (
          <section className="section-card p-4 space-y-2" aria-label="Unprocessed webhooks">
            <p className="text-sm font-bold text-gray-900">Webhooks not processed</p>
            <ul className="space-y-1">
              {health.undelivered_webhooks.slice(0, 8).map(w => (
                <li key={w.id} className="text-xs text-gray-600 font-mono flex flex-wrap gap-x-3">
                  <span>{w.repo ?? "?"}</span><span>{w.event_type}</span><span>{w.minutes} min ago</span>
                  <button type="button" className="text-indigo-500 hover:underline" onClick={() => { setQuery(w.id); setSubmitted(w.id); load(w.id); }}>trace</button>
                  {w.error && <span className="text-rose-600">{w.error}</span>}
                </li>
              ))}
            </ul>
          </section>
        )}

        <section aria-label="Traces" className="space-y-3">
          <p className="text-xs font-bold uppercase tracking-wider text-gray-400">{submitted ? `Results for “${submitted}”` : "Last 24 hours"}</p>
          {traces === null ? <p className="text-sm text-gray-400">Loading…</p>
            : traces.length === 0 ? <p className="text-sm text-gray-400">{submitted ? "Nothing found for that search in the last 30 days." : "No activity recorded in the last 24 hours."}</p>
            : traces.map(t => <TraceCard key={t.trace_id} t={t} open={open.has(t.trace_id)} onToggle={() => toggle(t.trace_id)} />)}
        </section>
      </div>
    </AuthGuard>
  );
}
