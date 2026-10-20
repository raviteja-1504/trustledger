"use client";

/**
 * Audit Trail: the organisation's audit log exactly as stored (/api/audit) -- every entry with its real event type,
 * who did it, what it was about (lib/auditEvents.ts), and the hash it was stored with. Nothing from this browser is
 * mixed in, and the chain check is the server's (lib/audit.ts), which says plainly what it could and couldn't check.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import AuthGuard from "@/components/AuthGuard";
import { authedFetch, getAuthHeader, isSeedMode } from "@/lib/useRealData";
import { useAuth } from "@/lib/auth";
import {
  CATEGORY_LABEL, CATEGORY_SOC2, describeAuditRow, sinceFor, typesByCategory,
  type AuditCategory, type AuditRow, type AuditView,
} from "@/lib/auditEvents";
import type { ChainVerification } from "@/lib/audit";

const PAGE_SIZE = 200;
const PERIODS = [["7", "Last 7 days"], ["30", "Last 30 days"], ["90", "Last 90 days"], ["365", "Last 12 months"], ["all", "All time"]] as const;
type Period = (typeof PERIODS)[number][0];
const SEV_DOT: Record<AuditView["severity"], string> = { critical: "bg-rose-500", warning: "bg-amber-400", info: "bg-indigo-400" };
const CAT_CLS: Record<AuditCategory, string> = {
  scans: "bg-sky-50 text-sky-700", reviews: "bg-emerald-50 text-emerald-700", findings: "bg-rose-50 text-rose-700", incidents: "bg-orange-50 text-orange-700",
  access: "bg-violet-50 text-violet-700", settings: "bg-amber-50 text-amber-800", integrations: "bg-indigo-50 text-indigo-700", evidence: "bg-gray-100 text-gray-700",
};

interface AuditResponse { events: AuditRow[]; total: number; counts: Record<string, number>; period_total: number; page: number }

const pad = (n: number) => String(n).padStart(2, "0");
const utcTime = (iso: string) => { const d = new Date(iso); return `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())} UTC`; };
const utcDay = (iso: string) => new Date(iso).toLocaleDateString("en-GB", { weekday: "long", day: "numeric", month: "long", year: "numeric", timeZone: "UTC" });
const fmtDay = (iso: string) => new Date(iso).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric", timeZone: "UTC" });
const plural = (n: number, one: string, many = `${one}s`) => `${n.toLocaleString()} ${n === 1 ? one : many}`;
const csvCell = (v: unknown) => { const s = String(v ?? ""); return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s; };

export default function AuditPage() {
  const { profile } = useAuth();
  const demo = isSeedMode() && !profile?.org_id;
  const [period, setPeriod] = useState<Period>("30");
  const [category, setCategory] = useState<AuditCategory | "all">("all");
  const [type, setType] = useState("all");
  const [actor, setActor] = useState("all");
  const [search, setSearch] = useState("");
  const [rows, setRows] = useState<AuditRow[] | null>(null);
  const [meta, setMeta] = useState<{ total: number; counts: Record<string, number>; period_total: number } | null>(null);
  const [page, setPage] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [loadingMore, setLoadingMore] = useState(false);
  const [expanded, setExpanded] = useState<number | null>(null);
  const [verify, setVerify] = useState<{ state: "idle" | "checking" | "done" | "error"; result?: ChainVerification }>({ state: "idle" });
  const [updatedAt, setUpdatedAt] = useState<Date | null>(null);

  const groups = useMemo(() => typesByCategory(), []);
  const typeFilter = type !== "all" ? [type] : category !== "all" ? groups.find(([c]) => c === category)?.[1].map(([t]) => t) ?? [] : [];

  const query = useCallback((p: number) => {
    const q = new URLSearchParams({ limit: String(PAGE_SIZE), page: String(p) });
    const since = sinceFor(period);
    if (since) q.set("since", since);
    if (typeFilter.length) q.set("type", typeFilter.join(","));
    if (actor !== "all") q.set("actor", actor);
    return `/api/audit?${q}`;
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [period, typeFilter.join(","), actor]);

  const load = useCallback(async () => {
    if (demo || !profile?.org_id) return;
    try {
      const r = await authedFetch<AuditResponse>(query(0));
      setRows(r.events); setMeta({ total: r.total, counts: r.counts ?? {}, period_total: r.period_total ?? r.total }); setPage(0); setError(null); setUpdatedAt(new Date());
    } catch (e) { setError(e instanceof Error ? e.message : "Couldn't load the audit log."); }
  }, [demo, profile?.org_id, query]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    const tick = () => { if (!document.hidden) load(); };
    const id = setInterval(tick, 120_000);
    window.addEventListener("focus", tick);
    return () => { clearInterval(id); window.removeEventListener("focus", tick); };
  }, [load]);

  async function loadMore() {
    setLoadingMore(true);
    try {
      const r = await authedFetch<AuditResponse>(query(page + 1));
      setRows(prev => [...(prev ?? []), ...r.events.filter(e => !(prev ?? []).some(x => x.id === e.id))]);
      setPage(page + 1);
    } catch (e) { setError(e instanceof Error ? e.message : "Couldn't load older entries."); }
    setLoadingMore(false);
  }

  async function runVerify() {
    setVerify({ state: "checking" });
    try { setVerify({ state: "done", result: await authedFetch<ChainVerification>("/api/audit", { method: "POST" }) }); }
    catch { setVerify({ state: "error" }); }
  }

  const views = useMemo(() => (rows ?? []).map(describeAuditRow), [rows]);
  const actors = useMemo(() => [...new Set(views.map(v => v.actor).filter((a): a is string => !!a))].sort(), [views]);
  const shown = useMemo(() => {
    const q = search.trim().toLowerCase();
    return q ? views.filter(v => [v.title, v.label, v.actor ?? "", v.repo ?? "", ...v.facts.map(f => f[1])].join(" ").toLowerCase().includes(q)) : views;
  }, [views, search]);
  const byDay = useMemo(() => {
    const m = new Map<string, AuditView[]>();
    for (const v of shown) { const k = v.at.slice(0, 10); m.set(k, [...(m.get(k) ?? []), v]); }
    return [...m];
  }, [shown]);
  const catCounts = useMemo(() => {
    const c: Partial<Record<AuditCategory, number>> = {};
    for (const [cat, types] of groups) c[cat] = types.reduce((s, [t]) => s + (meta?.counts[t] ?? 0), 0);
    return c;
  }, [groups, meta]);
  const knownTypes = new Set(groups.flatMap(([, t]) => t.map(([x]) => x)));
  const otherCount = Object.entries(meta?.counts ?? {}).filter(([t]) => !knownTypes.has(t)).reduce((s, [, n]) => s + n, 0);
  const narrowed = category !== "all" || type !== "all" || actor !== "all" || search !== "";

  function exportLoaded(fmt: "csv" | "json") {
    const data = shown.map(v => ({ id: v.id, time: v.at, event: v.type, label: v.label, title: v.title, actor: v.actor, repo: v.repo, facts: Object.fromEntries(v.facts), entry_hash: v.entry_hash, prev_hash: v.prev_hash }));
    const body = fmt === "json" ? JSON.stringify(data, null, 2)
      : [["id", "time_utc", "event", "title", "actor", "repo", "details", "entry_hash", "prev_hash"], ...data.map(d => [d.id, d.time, d.event, d.title, d.actor, d.repo, Object.entries(d.facts).map(([k, v]) => `${k}: ${v}`).join("; "), d.entry_hash, d.prev_hash])]
        .map(r => r.map(csvCell).join(",")).join("\r\n");
    const url = URL.createObjectURL(new Blob([body], { type: fmt === "json" ? "application/json" : "text/csv" }));
    Object.assign(document.createElement("a"), { href: url, download: `audit-trail.${fmt}` }).click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }
  async function exportSigned() {
    try {
      const res = await fetch("/api/export/signed", { headers: await getAuthHeader() });
      if (!res.ok) throw new Error();
      const url = URL.createObjectURL(await res.blob());
      Object.assign(document.createElement("a"), { href: url, download: "audit-log-signed.json" }).click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch { setError("The signed export failed. Please try again."); }
  }

  const v = verify.result;
  return (
    <AuthGuard>
      <div className="max-w-5xl mx-auto space-y-5 pb-10">
        <header className="flex flex-wrap items-start justify-between gap-4">
          <div>
            <h1 className="text-xl font-black text-gray-900 tracking-tight">Audit Trail</h1>
            <p className="text-sm text-gray-500 mt-0.5 max-w-2xl">
              Everything that happened in your organisation, as stored: scans, sign-offs, finding changes, sign-ins, settings and exports.
              Entries can&apos;t be edited or deleted, and each carries the hash of the one before it.
            </p>
            {updatedAt && <p className="text-[11px] text-gray-400 mt-1">Updated {updatedAt.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })} · times in UTC</p>}
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <button onClick={load} className="px-3 py-2 text-xs font-semibold text-gray-600 bg-white border border-gray-200 rounded-xl hover:bg-gray-50">Refresh</button>
            <button onClick={() => exportLoaded("csv")} disabled={!shown.length} className="px-3 py-2 text-xs font-semibold text-gray-600 bg-white border border-gray-200 rounded-xl hover:bg-gray-50 disabled:opacity-40">Export shown (CSV)</button>
            <button onClick={() => exportLoaded("json")} disabled={!shown.length} className="px-3 py-2 text-xs font-semibold text-gray-600 bg-white border border-gray-200 rounded-xl hover:bg-gray-50 disabled:opacity-40">JSON</button>
            <button onClick={exportSigned} className="px-3 py-2 text-xs font-semibold text-indigo-700 bg-indigo-50 border border-indigo-100 rounded-xl hover:bg-indigo-100" title="The full log, signed by the server">Signed export</button>
          </div>
        </header>

        {demo && <div className="section-card p-6 text-sm text-gray-600">The audit trail is your organisation&apos;s stored log. Connect a repository to see it.</div>}
        {error && <div role="alert" className="flex items-center justify-between gap-3 bg-rose-50 border border-rose-200 text-rose-800 px-4 py-3 rounded-xl text-sm"><span>Couldn&apos;t load the audit log. {error}</span><button onClick={load} className="font-bold text-xs">Retry</button></div>}

        {!demo && (
          <section aria-label="Integrity" className="section-card px-5 py-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <p className="text-sm font-bold text-gray-900">Has anything been changed or removed?</p>
                <p className="text-xs text-gray-500 mt-0.5">Checks every stored entry: that each one links to the entry before it, and that its contents still match its hash.</p>
              </div>
              <button onClick={runVerify} disabled={verify.state === "checking"} className="px-3 py-2 text-xs font-bold text-white bg-indigo-600 rounded-xl hover:bg-indigo-700 disabled:opacity-50">
                {verify.state === "checking" ? "Checking…" : "Check the whole log"}
              </button>
            </div>
            {verify.state === "error" && <p className="mt-3 text-xs text-rose-600">The check couldn&apos;t run. Please try again.</p>}
            {verify.state === "done" && v && (
              <div role="status" className={`mt-3 rounded-xl px-4 py-3 text-xs ${v.valid ? "bg-emerald-50 text-emerald-800" : "bg-rose-50 text-rose-800"}`}>
                {v.valid ? (
                  <p><strong>Intact.</strong> {plural(v.total, "entry", "entries")}{v.first_at ? ` from ${fmtDay(v.first_at)} to ${fmtDay(v.last_at!)}` : ""}: every link is in place
                    {v.verified ? `, and ${plural(v.verified, "entry's", "entries'")} contents match their hashes` : ""}.</p>
                ) : (
                  <p><strong>Problem at entry #{v.broken_at}.</strong> {v.reason === "missing_link" ? "It doesn't link to any earlier entry — an entry before it may have been removed." : "Its contents no longer match its hash — it may have been changed."}</p>
                )}
                {v.legacy > 0 && <p className="mt-1 text-gray-600">{plural(v.legacy, "older entry", "older entries")} (written before contents were stored in a checkable form) can only be link-checked.</p>}
                {v.concurrent > 0 && <p className="mt-1 text-gray-600">{plural(v.concurrent, "entry", "entries")} were written at the same moment as another and share its link — expected, not tampering.</p>}
              </div>
            )}
          </section>
        )}

        {meta && (
          <section aria-label="Summary" className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <div className="section-card px-4 py-3 col-span-2 sm:col-span-1">
              <p className="text-[10px] font-black uppercase tracking-widest text-gray-400">Entries</p>
              <p className="text-2xl font-black tabular-nums text-gray-900 mt-1">{meta.period_total.toLocaleString()}</p>
              <p className="text-[11px] text-gray-500">{PERIODS.find(([k]) => k === period)?.[1]}</p>
            </div>
            {(["reviews", "findings", "access"] as const).map(c => (
              <button key={c} onClick={() => { setCategory(category === c ? "all" : c); setType("all"); }} aria-pressed={category === c}
                className={`section-card px-4 py-3 text-left hover:ring-2 hover:ring-indigo-100 ${category === c ? "ring-2 ring-indigo-300" : ""}`}>
                <p className="text-[10px] font-black uppercase tracking-widest text-gray-400">{CATEGORY_LABEL[c]}</p>
                <p className="text-2xl font-black tabular-nums text-gray-900 mt-1">{(catCounts[c] ?? 0).toLocaleString()}</p>
                <p className="text-[11px] text-gray-500">SOC 2 {CATEGORY_SOC2[c].join(", ")}</p>
              </button>
            ))}
          </section>
        )}

        {meta && (
          <div className="flex flex-wrap items-center gap-2">
            <select aria-label="Period" value={period} onChange={e => setPeriod(e.target.value as Period)} className="text-xs font-semibold text-gray-700 bg-white border border-gray-200 rounded-lg px-2.5 py-1.5">
              {PERIODS.map(([k, l]) => <option key={k} value={k}>{l}</option>)}
            </select>
            <select aria-label="Category" value={category} onChange={e => { setCategory(e.target.value as AuditCategory | "all"); setType("all"); }} className="text-xs font-semibold text-gray-700 bg-white border border-gray-200 rounded-lg px-2.5 py-1.5">
              <option value="all">All categories</option>
              {groups.map(([c]) => <option key={c} value={c}>{CATEGORY_LABEL[c]} ({(catCounts[c] ?? 0).toLocaleString()})</option>)}
            </select>
            <select aria-label="Event" value={type} onChange={e => setType(e.target.value)} className="text-xs font-semibold text-gray-700 bg-white border border-gray-200 rounded-lg px-2.5 py-1.5 max-w-[14rem]">
              <option value="all">All events</option>
              {groups.filter(([c]) => category === "all" || c === category).map(([c, types]) => (
                <optgroup key={c} label={CATEGORY_LABEL[c]}>
                  {types.map(([t, l]) => <option key={t} value={t}>{l} ({(meta.counts[t] ?? 0).toLocaleString()})</option>)}
                </optgroup>
              ))}
            </select>
            <select aria-label="Who" value={actor} onChange={e => setActor(e.target.value)} className="text-xs font-semibold text-gray-700 bg-white border border-gray-200 rounded-lg px-2.5 py-1.5 max-w-[14rem]">
              <option value="all">Anyone</option>
              {[...new Set([...(actor !== "all" ? [actor] : []), ...actors])].map(a => <option key={a} value={a}>{a}</option>)}
            </select>
            <input aria-label="Search loaded entries" value={search} onChange={e => setSearch(e.target.value)} placeholder="Search file, repo, person…"
              className="text-xs border border-gray-200 rounded-lg px-2.5 py-1.5 w-48 focus:outline-none focus:ring-2 focus:ring-indigo-200" />
            {narrowed && <button onClick={() => { setCategory("all"); setType("all"); setActor("all"); setSearch(""); }} className="text-xs font-bold text-rose-600 hover:text-rose-800 px-2 py-1 rounded-lg hover:bg-rose-50">Clear filters</button>}
            <span className="text-xs text-gray-400 ml-auto">{shown.length.toLocaleString()} shown of {meta.total.toLocaleString()} matching{otherCount ? ` · ${otherCount} uncategorised` : ""}</span>
          </div>
        )}

        {!demo && !rows && !error && <div className="h-40 rounded-2xl bg-white border border-gray-100 animate-pulse" aria-label="Loading audit log" />}

        {rows && (shown.length === 0 ? (
          <div className="section-card py-14 text-center text-sm text-gray-500">{rows.length === 0 ? "No audit entries in this period." : "No loaded entries match your search."}</div>
        ) : (
          <div className="space-y-5">
            {byDay.map(([day, items]) => (
              <section key={day} aria-label={utcDay(`${day}T00:00:00Z`)}>
                <div className="flex items-center gap-3 mb-2">
                  <p className="text-xs font-black text-gray-700 uppercase tracking-widest">{utcDay(`${day}T00:00:00Z`)}</p>
                  <div className="flex-1 h-px bg-gray-100" />
                  <p className="text-[10px] text-gray-400">{plural(items.length, "entry", "entries")}</p>
                </div>
                <ul className="section-card divide-y divide-gray-50 overflow-hidden">
                  {items.map(e => <EntryRow key={e.id} e={e} open={expanded === e.id} onToggle={() => setExpanded(expanded === e.id ? null : e.id)} />)}
                </ul>
              </section>
            ))}
            {meta && rows.length < meta.total && (
              <button onClick={loadMore} disabled={loadingMore} className="w-full py-2.5 text-xs font-semibold text-indigo-600 bg-white border border-gray-200 rounded-xl hover:bg-indigo-50 disabled:opacity-50">
                {loadingMore ? "Loading…" : `Load older entries (${(meta.total - rows.length).toLocaleString()} more)`}
              </button>
            )}
          </div>
        ))}
      </div>
    </AuthGuard>
  );
}

function EntryRow({ e, open, onToggle }: { e: AuditView; open: boolean; onToggle: () => void }) {
  return (
    <li>
      <button onClick={onToggle} aria-expanded={open} className="w-full text-left flex items-start gap-3 px-5 py-3 hover:bg-gray-50/60">
        <span className={`mt-1.5 w-2 h-2 rounded-full shrink-0 ${SEV_DOT[e.severity]}`} aria-label={e.severity} />
        <div className="flex-1 min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${CAT_CLS[e.category]}`}>{e.label}</span>
            <span className="text-xs font-semibold text-gray-800 break-words">{e.title}</span>
          </div>
          <p className="text-[11px] text-gray-500 mt-0.5">{e.actor ?? "System"}{e.repo ? ` · ${e.repo}` : ""}</p>
        </div>
        <span className="text-[10px] font-mono text-gray-500 tabular-nums shrink-0">{utcTime(e.at)}</span>
      </button>
      {open && (
        <div className="px-5 pb-4 pl-10 space-y-3">
          {e.facts.length > 0 && (
            <dl className="grid grid-cols-1 sm:grid-cols-3 gap-2">
              {e.facts.map(([k, v]) => (
                <div key={k} className="bg-gray-50 rounded-lg px-3 py-2 border border-gray-100 min-w-0">
                  <dt className="text-[9px] font-bold text-gray-400 uppercase tracking-wide">{k}</dt>
                  <dd className="text-[11px] font-semibold text-gray-700 mt-0.5 break-all">{v}</dd>
                </div>
              ))}
            </dl>
          )}
          <div className="flex flex-wrap items-center gap-2 text-[10px]">
            <span className="font-black uppercase tracking-widest text-indigo-400">SOC 2 evidence</span>
            {CATEGORY_SOC2[e.category].map(c => <span key={c} className="font-mono font-bold text-indigo-700 bg-indigo-50 px-1.5 py-0.5 rounded border border-indigo-100">{c}</span>)}
          </div>
          <div className="text-[10px] font-mono text-gray-500 space-y-0.5 break-all">
            <p>Entry #{e.id} · {e.at}</p>
            <p>Hash: {e.entry_hash ?? "—"}</p>
            <p>Previous: {e.prev_hash ?? "start of the log"}</p>
          </div>
          {e.link && <Link href={e.link.href} className="inline-block text-xs font-bold text-indigo-600 hover:text-indigo-800">{e.link.label} →</Link>}
        </div>
      )}
    </li>
  );
}
