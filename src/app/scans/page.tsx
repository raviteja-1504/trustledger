"use client";

/**
 * Scan history: every pull request and push scan for the period, newest first, with what each found and whether its
 * high-risk files have been signed off. Stats are for the selected period; older scans of the same pull request are
 * marked superseded (their review status lives on the latest scan). Loads every scan in the period (up to MAX), and
 * refreshes when a scan lands or a file is signed off. No demo data is ever shown in place of a failed load.
 */

import { Suspense, useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import AuthGuard from "@/components/AuthGuard";
import RiskBadge from "@/components/RiskBadge";
import { authedFetch, isSeedMode } from "@/lib/useRealData";
import { useAuth } from "@/lib/auth";
import { useScansRealtime } from "@/lib/realtime";
import { dailyActivity, historyStats, reviewedCount, supersededIds, type ScanRow } from "@/lib/scanHistory";
import type { RiskLevel } from "@/types";
import { LoadingBlock } from "@/components/Loading";

const PERIODS = [{ k: "7", l: "7 days" }, { k: "30", l: "30 days" }, { k: "90", l: "90 days" }] as const;
type Period = (typeof PERIODS)[number]["k"];
const PAGE = 200;
const MAX = 1000;

const BAR: Record<string, string> = { CRITICAL: "bg-rose-600", HIGH: "bg-orange-500", MEDIUM: "bg-amber-400", LOW: "bg-emerald-500" };

function ago(iso: string) {
  const m = Math.floor((Date.now() - new Date(iso).getTime()) / 60000);
  if (m < 1) return "just now";
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  return d === 1 ? "yesterday" : d < 7 ? `${d}d ago` : new Date(iso).toLocaleDateString("en-GB", { day: "numeric", month: "short" });
}
function groupLabel(iso: string) {
  const d = new Date(iso), today = new Date();
  const days = Math.round((new Date(today.toDateString()).getTime() - new Date(d.toDateString()).getTime()) / 86400000);
  return days === 0 ? "Today" : days === 1 ? "Yesterday" : days < 7 ? d.toLocaleDateString("en", { weekday: "long" }) : d.toLocaleDateString("en-GB", { day: "numeric", month: "long", year: "numeric" });
}

function Stat({ label, value, sub, tone }: { label: string; value: string | number; sub?: string; tone?: "bad" | "good" }) {
  return (
    <div className="bg-white rounded-2xl border border-gray-100 p-5 shadow-[0_1px_2px_rgba(15,23,42,0.05)]">
      <p className="text-[11px] font-semibold uppercase tracking-wide text-gray-500">{label}</p>
      <p className={`mt-2 text-3xl font-black tabular-nums leading-none ${tone === "bad" ? "text-rose-600" : tone === "good" ? "text-emerald-600" : "text-gray-900"}`}>{value}</p>
      {sub && <p className="mt-2 text-xs text-gray-500 leading-snug">{sub}</p>}
    </div>
  );
}

function ScansContent() {
  const { profile } = useAuth();
  const searchParams = useSearchParams();
  const offline = isSeedMode() && !profile?.org_id;
  const [period, setPeriod] = useState<Period>("30");
  const [scans, setScans] = useState<ScanRow[] | null>(null);
  const [truncated, setTruncated] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [resolved, setResolved] = useState<Set<string>>(new Set());
  const [repoFilter, setRepoFilter] = useState(() => searchParams?.get("repo") ?? "all");
  const [riskFilter, setRiskFilter] = useState<RiskLevel | "all">("all");
  const [reviewFilter, setReviewFilter] = useState<"all" | "pending">("all");
  const [search, setSearch] = useState("");
  const [updatedAt, setUpdatedAt] = useState<Date | null>(null);

  const load = useCallback(async () => {
    if (offline) return;
    const since = new Date(Date.now() - Number(period) * 86400_000).toISOString();
    try {
      const all: ScanRow[] = [];
      let before: string | null = null;
      do {
        const q = new URLSearchParams({ limit: String(PAGE), since });
        if (before) q.set("before", before);
        const r: { scans: ScanRow[]; next_before?: string | null } = await authedFetch(`/api/scans?${q}`);
        all.push(...(r.scans ?? []));
        before = r.next_before ?? null;
      } while (before && all.length < MAX);
      setScans(all); setTruncated(!!before); setError(null); setUpdatedAt(new Date());
    } catch (e) {
      setError(e instanceof Error ? e.message : "Couldn't load scans");
    }
    try {
      const o = await authedFetch<{ overrides: Record<string, { status: string }> }>("/api/violation-status");
      setResolved(new Set(Object.entries(o.overrides ?? {}).filter(([, v]) => v.status === "resolved").map(([k]) => k)));
    } catch { /* keep previous */ }
  }, [offline, period]);

  useEffect(() => { setScans(null); load(); }, [load]);
  useScansRealtime(profile?.org_id, () => { load(); });
  useEffect(() => {
    const tick = () => { if (!document.hidden) load(); };
    window.addEventListener("tl:attestation", tick);
    window.addEventListener("tl:attest-complete", tick);
    window.addEventListener("focus", tick);
    return () => { window.removeEventListener("tl:attestation", tick); window.removeEventListener("tl:attest-complete", tick); window.removeEventListener("focus", tick); };
  }, [load]);

  const superseded = useMemo(() => supersededIds(scans ?? []), [scans]);
  const repos = useMemo(() => [...new Set((scans ?? []).map(s => s.repo))].sort(), [scans]);
  const filtered = useMemo(() => (scans ?? []).filter(s => {
    if (repoFilter !== "all" && s.repo !== repoFilter) return false;
    if (riskFilter !== "all" && s.overall_risk !== riskFilter) return false;
    if (reviewFilter === "pending" && (superseded.has(s.scan_id) || (s.high_crit_count ?? 0) === 0 || reviewedCount(s, resolved) >= (s.high_crit_count ?? 0))) return false;
    if (search) {
      const q = search.toLowerCase();
      if (![s.repo, s.branch, s.commit_sha, s.pr_number > 0 ? `#${s.pr_number}` : ""].join(" ").toLowerCase().includes(q)) return false;
    }
    return true;
  }), [scans, repoFilter, riskFilter, reviewFilter, search, superseded, resolved]);
  const stats = useMemo(() => historyStats(filtered, resolved), [filtered, resolved]);
  const days = useMemo(() => dailyActivity(filtered, new Date(Date.now() - (Number(period) - 1) * 86400_000), new Date()), [filtered, period]);
  const maxDay = Math.max(1, ...days.map(d => d.total));
  const groups = useMemo(() => {
    const out: Array<{ label: string; items: ScanRow[] }> = [];
    for (const s of filtered) {
      const label = groupLabel(s.created_at);
      if (out[out.length - 1]?.label !== label) out.push({ label, items: [] });
      out[out.length - 1].items.push(s);
    }
    return out;
  }, [filtered]);
  const filteredOut = (scans?.length ?? 0) - filtered.length;

  return (
    <AuthGuard>
      <div className="max-w-[1400px] mx-auto space-y-8 pb-16">
        <header className="animate-fade-up flex flex-wrap items-end justify-between gap-4">
          <div>
            <h1 className="text-2xl font-black text-gray-900 tracking-tight">Scan history</h1>
            <p className="text-sm text-gray-500 mt-0.5">
              Every pull request and push scan · open one to see its files and sign off
              {updatedAt && <span className="text-gray-400"> · live, updated {updatedAt.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</span>}
            </p>
          </div>
          <div className="flex items-center gap-0.5 bg-gray-100 p-1 rounded-xl" role="group" aria-label="Period">
            {PERIODS.map(p => (
              <button key={p.k} onClick={() => setPeriod(p.k)} aria-pressed={period === p.k}
                className={`px-3 py-1.5 text-xs font-semibold rounded-lg transition-all ${period === p.k ? "bg-white text-gray-900 shadow-sm" : "text-gray-500 hover:text-gray-700"}`}>
                {p.l}
              </button>
            ))}
          </div>
        </header>

        {offline && <div className="section-card p-6 text-sm text-gray-600">Connect a repository to start scanning pull requests.</div>}
        {error && !scans && (
          <div role="alert" className="flex items-center justify-between gap-3 bg-rose-50 border border-rose-200 text-rose-800 px-4 py-3 rounded-xl text-sm">
            <span>Couldn&apos;t load scans. {error}</span>
            <button onClick={load} className="font-bold text-xs">Retry</button>
          </div>
        )}
        {!offline && !scans && !error && <LoadingBlock label="scans" rows={6} />}

        {scans && (
          <>
            <div className="animate-fade-up grid grid-cols-1 min-[420px]:grid-cols-2 lg:grid-cols-3 2xl:grid-cols-6 gap-4">
              <Stat label="Scans" value={stats.scans} sub={`${stats.prs} pull request${stats.prs === 1 ? "" : "s"} · ${stats.repos} repo${stats.repos === 1 ? "" : "s"}`} />
              <Stat label="Critical scans" value={stats.critical} sub="Overall risk CRITICAL" tone={stats.critical ? "bad" : undefined} />
              <Stat label="High-risk scans" value={stats.high} sub="Overall risk HIGH" />
              <Stat label="Fully signed off" value={stats.needsReview ? `${stats.fullyReviewed}/${stats.needsReview}` : "—"} sub="Latest scans with HIGH/CRITICAL files" tone={stats.needsReview && stats.fullyReviewed === stats.needsReview ? "good" : undefined} />
              <Stat label="Files scanned" value={stats.files.toLocaleString()} />
              <Stat label="AI content" value={stats.ai_share == null ? "—" : `${Math.round(stats.ai_share * 100)}%`} sub="Files-weighted" />
            </div>

            <section aria-label="Daily scans" className="animate-fade-up section-card p-6">
              <div className="flex flex-wrap items-start justify-between gap-3 mb-4">
                <div>
                  <h2 className="text-sm font-bold text-gray-900">Scans per day</h2>
                  <p className="text-xs text-gray-400 mt-0.5">Last {period} days to today · coloured by the day&apos;s worst result</p>
                </div>
                <div className="flex flex-wrap gap-3 text-[11px] text-gray-500">
                  {(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map(r => <span key={r} className="flex items-center gap-1.5"><span className={`w-2.5 h-2.5 rounded-sm ${BAR[r]}`} />{r[0] + r.slice(1).toLowerCase()}</span>)}
                </div>
              </div>
              <div className="flex items-end gap-[3px] h-28" role="img" aria-label={`${stats.scans} scans over ${period} days`}>
                {days.map(d => (
                  <div key={d.day} className="flex-1 h-full flex flex-col justify-end" title={`${d.day}: ${d.total} scan${d.total === 1 ? "" : "s"}`}>
                    <div className={`w-full rounded-t ${d.worst && d.worst !== "UNKNOWN" ? BAR[d.worst] : "bg-gray-200"}`}
                      style={{ height: d.total ? `${Math.max(6, (d.total / maxDay) * 100)}%` : "2px", opacity: d.total ? 1 : 0.6 }} />
                  </div>
                ))}
              </div>
              <div className="flex justify-between mt-2 text-[11px] text-gray-400">
                <span>{new Date(`${days[0].day}T00:00:00Z`).toLocaleDateString("en-GB", { day: "numeric", month: "short", timeZone: "UTC" })}</span>
                <span>Today</span>
              </div>
            </section>

            <section aria-label="Scans" className="animate-fade-up section-card overflow-hidden">
              <div className="flex flex-wrap items-center gap-3 px-6 pt-5 pb-4 border-b border-gray-100">
                <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search repo, branch, commit, #PR" aria-label="Search scans"
                  className="flex-1 min-w-[200px] text-sm border border-gray-200 rounded-lg px-3 py-2 focus:outline-none focus:ring-2 focus:ring-indigo-200" />
                <select value={repoFilter} onChange={e => setRepoFilter(e.target.value)} aria-label="Repository" className="text-sm border border-gray-200 rounded-lg px-2.5 py-2 bg-white">
                  <option value="all">All repositories</option>
                  {repos.map(r => <option key={r} value={r}>{r}</option>)}
                </select>
                <select value={riskFilter} onChange={e => setRiskFilter(e.target.value as RiskLevel | "all")} aria-label="Risk" className="text-sm border border-gray-200 rounded-lg px-2.5 py-2 bg-white">
                  <option value="all">All results</option>
                  {(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map(r => <option key={r} value={r}>{r}</option>)}
                </select>
                <select value={reviewFilter} onChange={e => setReviewFilter(e.target.value as "all" | "pending")} aria-label="Review" className="text-sm border border-gray-200 rounded-lg px-2.5 py-2 bg-white">
                  <option value="all">Any review status</option>
                  <option value="pending">Waiting for sign-off</option>
                </select>
              </div>

              {filtered.length === 0 ? (
                <p className="px-6 py-14 text-center text-sm text-gray-500">{scans.length ? "No scans match these filters." : `No scans in the last ${period} days.`}</p>
              ) : groups.map(g => (
                <div key={g.label}>
                  <div className="px-6 py-2 bg-gray-50/80 border-y border-gray-100 text-xs font-bold text-gray-500">{g.label} <span className="font-normal text-gray-400">· {g.items.length} scan{g.items.length === 1 ? "" : "s"}</span></div>
                  <ul className="divide-y divide-gray-50">
                    {g.items.map(s => {
                      const old = superseded.has(s.scan_id);
                      const total = s.high_crit_count ?? 0;
                      const done = reviewedCount(s, resolved);
                      return (
                        <li key={s.scan_id}>
                          <Link href={`/pr/${s.scan_id}`} className={`flex flex-wrap items-center gap-x-5 gap-y-2 px-6 py-4 hover:bg-indigo-50/30 transition-colors ${old ? "opacity-60" : ""}`}>
                            <div className="w-20 shrink-0"><RiskBadge level={s.overall_risk} /></div>
                            <div className="min-w-[200px] flex-1">
                              <p className="text-sm font-bold text-gray-900 break-words">{s.repo}</p>
                              <p className="mt-0.5 text-xs text-gray-500 break-words">
                                {s.pr_number > 0 ? <span className="font-semibold text-indigo-600">PR #{s.pr_number}</span> : <span>Direct push</span>}
                                <span> · {s.branch} · <span className="font-mono">{s.commit_sha.slice(0, 7)}</span></span>
                              </p>
                            </div>
                            <div className="shrink-0 w-40">
                              {old ? <span className="text-xs font-semibold text-gray-500 bg-gray-100 px-2 py-1 rounded-lg">Superseded by a newer push</span>
                                : total === 0 ? <span className="text-xs text-gray-400">No high-risk files</span>
                                : <span className={`text-xs font-bold px-2 py-1 rounded-lg ${done >= total ? "bg-emerald-50 text-emerald-700" : done ? "bg-amber-50 text-amber-800" : "bg-rose-50 text-rose-700"}`}>
                                    {done}/{total} high-risk signed off
                                  </span>}
                            </div>
                            <div className="shrink-0 w-20 text-right">
                              <p className="text-sm font-bold tabular-nums text-gray-800">{Math.round(s.total_ai_percentage * 100)}%</p>
                              <p className="text-[11px] text-gray-400">AI</p>
                            </div>
                            <div className="shrink-0 w-16 text-right">
                              <p className="text-sm font-bold tabular-nums text-gray-800">{s.file_count}</p>
                              <p className="text-[11px] text-gray-400">files</p>
                            </div>
                            <div className="shrink-0 w-24 text-right">
                              <p className="text-sm text-gray-700">{ago(s.created_at)}</p>
                              <p className="text-[11px] text-gray-400">{s.triggered_by}</p>
                            </div>
                          </Link>
                        </li>
                      );
                    })}
                  </ul>
                </div>
              ))}
            </section>

            <p className="text-center text-xs text-gray-400">
              {filtered.length} of {scans.length} scans in the last {period} days{truncated ? ` (the first ${MAX} — narrow the period to see older ones)` : ""}
              {filteredOut > 0 && (
                <button onClick={() => { setSearch(""); setRepoFilter("all"); setRiskFilter("all"); setReviewFilter("all"); }} className="ml-2 font-semibold text-indigo-600 hover:text-indigo-800">Clear filters</button>
              )}
            </p>
          </>
        )}
      </div>
    </AuthGuard>
  );
}

export default function ScansPage() {
  return (
    <Suspense fallback={<div className="h-64" />}>
      <ScansContent />
    </Suspense>
  );
}
