"use client";

/**
 * Analytics: measured activity for the period -- scans, findings opened vs closed, how long high-risk files waited for
 * a reviewer, the backlog's age, AI content over time, reviewers and repositories. Every number comes from
 * /api/analytics (lib/orgAnalytics.ts); nothing is estimated or projected beyond the measured pace.
 *
 * Live: refetches every minute while visible, when a scan lands, after a sign-off, and on returning to the tab.
 */

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import dynamic from "next/dynamic";
import AuthGuard from "@/components/AuthGuard";
import { authedFetch, isSeedMode } from "@/lib/useRealData";
import { useAuth } from "@/lib/auth";
import { useScansRealtime } from "@/lib/realtime";
import type { Analytics } from "@/lib/orgAnalytics";
import { backlogSentence, clearSentence, reviewSentence, shortDuration } from "@/lib/analyticsWords";

const WeeklyChart = dynamic(() => import("@/components/analytics/WeeklyChart"), { ssr: false, loading: () => <div className="h-[260px] rounded-xl bg-gray-50 animate-pulse" /> });

const PERIODS = [7, 30, 90] as const;
const POLL_MS = 60_000;

const pct = (n: number | null | undefined) => n == null ? "—" : `${Math.round(n * 100)}%`;

function Stat({ label, value, sub, tone = "default" }: { label: string; value: string; sub: string; tone?: "default" | "good" | "bad" }) {
  return (
    <div className="bg-white rounded-2xl border border-gray-100 p-5 shadow-[0_1px_2px_rgba(15,23,42,0.05)]">
      <p className="text-[11px] font-semibold uppercase tracking-wide text-gray-500">{label}</p>
      <p className={`mt-2 text-3xl font-black tabular-nums leading-none ${tone === "bad" ? "text-rose-600" : tone === "good" ? "text-emerald-600" : "text-gray-900"}`}>{value}</p>
      <p className="mt-2 text-xs text-gray-500 leading-snug">{sub}</p>
    </div>
  );
}

function Card({ title, sub, children, aside }: { title: string; sub?: string; children: React.ReactNode; aside?: React.ReactNode }) {
  return (
    <section aria-label={title} className="section-card p-6 min-w-0">
      <div className="flex flex-wrap items-start justify-between gap-3 mb-5">
        <div>
          <h2 className="text-sm font-bold text-gray-900">{title}</h2>
          {sub && <p className="text-xs text-gray-400 mt-0.5">{sub}</p>}
        </div>
        {aside}
      </div>
      {children}
    </section>
  );
}

export default function AnalyticsPage() {
  const { profile } = useAuth();
  const [days, setDays] = useState<(typeof PERIODS)[number]>(30);
  const [data, setData] = useState<(Analytics & { scope?: "own" | "org" }) | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [updatedAt, setUpdatedAt] = useState<Date | null>(null);
  const offline = isSeedMode() && !profile?.org_id;

  const load = useCallback(async () => {
    if (offline) return;
    try {
      const d = await authedFetch<Analytics & { scope?: "own" | "org" }>(`/api/analytics?days=${days}`);
      setData(d); setError(null); setUpdatedAt(new Date());
    } catch (e) {
      setError(e instanceof Error ? e.message : "Couldn't load analytics");
    }
  }, [days, offline]);

  useEffect(() => { setData(null); load(); }, [load]);
  useScansRealtime(profile?.org_id, () => { load(); });
  useEffect(() => {
    const tick = () => { if (!document.hidden) load(); };
    const id = setInterval(tick, POLL_MS);
    window.addEventListener("focus", tick);
    window.addEventListener("tl:attestation", tick);
    document.addEventListener("visibilitychange", tick);
    return () => { clearInterval(id); window.removeEventListener("focus", tick); window.removeEventListener("tl:attestation", tick); document.removeEventListener("visibilitychange", tick); };
  }, [load]);

  const crit = data?.review_time.find(r => r.severity === "CRITICAL");
  const high = data?.review_time.find(r => r.severity === "HIGH");
  const allDeadline = (crit?.with_deadline ?? 0) + (high?.with_deadline ?? 0);
  const allOnTime = (crit?.on_time ?? 0) + (high?.on_time ?? 0);
  const net = data ? data.totals.opened - data.totals.closed : 0;
  const maxAge = Math.max(1, ...(data?.backlog.by_age.map(b => b.count) ?? [0]));
  const maxReviewer = Math.max(1, ...(data?.reviewers.map(r => r.signoffs) ?? [0]));

  return (
    <AuthGuard>
      <div className="max-w-[1400px] mx-auto space-y-8 pb-16">
        <header className="animate-fade-up flex flex-wrap items-end justify-between gap-4">
          <div>
            <h1 className="text-2xl font-black text-gray-900 tracking-tight">Analytics</h1>
            <p className="text-sm text-gray-500 mt-0.5">
              Measured from your scans, findings and sign-offs{data?.scope === "own" ? " · your pull requests" : ""}
              {updatedAt && <span className="text-gray-400"> · live, updated {updatedAt.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</span>}
            </p>
          </div>
          <div className="flex items-center gap-2">
            <div className="flex items-center gap-0.5 bg-gray-100 p-1 rounded-xl" role="group" aria-label="Period">
              {PERIODS.map(p => (
                <button key={p} onClick={() => setDays(p)} aria-pressed={days === p}
                  className={`px-3 py-1.5 text-xs font-semibold rounded-lg transition-all ${days === p ? "bg-white text-gray-900 shadow-sm" : "text-gray-500 hover:text-gray-700"}`}>
                  {p}d
                </button>
              ))}
            </div>
            <button onClick={load} className="px-3 py-2 text-xs font-semibold text-gray-600 bg-white border border-gray-200 rounded-xl hover:bg-gray-50 shadow-sm">Refresh</button>
          </div>
        </header>

        {offline && <div className="section-card p-6 text-sm text-gray-600">Connect a repository to see analytics. Nothing is shown in demo mode rather than invented numbers.</div>}
        {error && !data && (
          <div role="alert" className="flex items-center justify-between gap-3 bg-rose-50 border border-rose-200 text-rose-800 px-4 py-3 rounded-xl text-sm">
            <span>Couldn&apos;t load analytics. {error}</span>
            <button onClick={load} className="font-bold text-xs">Retry</button>
          </div>
        )}
        {!offline && !data && !error && (
          <div className="grid grid-cols-2 lg:grid-cols-3 2xl:grid-cols-6 gap-4" aria-label="Loading analytics">
            {[0, 1, 2, 3, 4, 5].map(i => <div key={i} className="h-32 rounded-2xl bg-white border border-gray-100 animate-pulse" />)}
          </div>
        )}

        {data && (
          <>
            {/* ── Headline ── */}
            <div className="animate-fade-up grid grid-cols-1 min-[420px]:grid-cols-2 lg:grid-cols-3 2xl:grid-cols-6 gap-4">
              <Stat label="Scans" value={String(data.totals.scans)} sub={`${data.totals.prs} pull requests · ${(data.totals.scans / Math.max(days / 7, 1)).toFixed(1)} per week`} />
              <Stat label="Findings found" value={String(data.totals.opened)} sub={`${data.totals.closed} fixed or closed in the same period`} />
              <Stat label="Open work" value={`${net > 0 ? "+" : ""}${net}`} sub={backlogSentence(data.totals.opened, data.totals.closed)} tone={net > 0 ? "bad" : net < 0 ? "good" : "default"} />
              <Stat label="Typical wait for sign-off" value={shortDuration(crit?.median_hours ?? null)}
                sub={crit?.count ? `Half of CRITICAL files were signed off faster than this. HIGH: ${shortDuration(high?.median_hours ?? null)}` : `No CRITICAL sign-offs yet. HIGH: ${shortDuration(high?.median_hours ?? null)}`} />
              <Stat label="Signed off on time" value={allDeadline ? pct(allOnTime / allDeadline) : "—"} sub={allDeadline ? `${allOnTime} of ${allDeadline} sign-offs beat their fix deadline` : "No sign-offs had a fix deadline"} tone={allDeadline && allOnTime / allDeadline < 0.8 ? "bad" : "default"} />
              <Stat label="Waiting now" value={String(data.backlog.open)} sub={data.backlog.overdue ? `${data.backlog.overdue} already past their fix deadline` : "None past their fix deadline"} tone={data.backlog.overdue ? "bad" : "default"} />
            </div>

            {/* ── Weekly activity ── */}
            <div className="animate-fade-up">
              <Card title="Weekly activity" sub={`Each week: findings found, findings fixed or closed, and files signed off · last ${days} days to today`}>
                <WeeklyChart weeks={data.weeks} />
              </Card>
            </div>

            {/* ── Review time + backlog ── */}
            <div className="animate-fade-up grid grid-cols-1 xl:grid-cols-2 gap-6">
              <Card title="How long files wait for a sign-off" sub="From the scan that flagged a file to the moment a reviewer signed it off">
                <div className="space-y-4">
                  {data.review_time.map(r => (
                    <div key={r.severity} className="rounded-2xl bg-gray-50/60 ring-1 ring-gray-100 p-4">
                      <div className="flex items-center justify-between gap-3">
                        <span className={`text-[11px] font-black px-2 py-0.5 rounded ${r.severity === "CRITICAL" ? "bg-violet-100 text-violet-700" : "bg-orange-100 text-orange-700"}`}>{r.severity}</span>
                        <span className="text-xs text-gray-500">{r.count} sign-off{r.count === 1 ? "" : "s"}</span>
                      </div>
                      <p className="mt-2 text-xs text-gray-700 leading-relaxed">{reviewSentence(r)}</p>
                      <div className="mt-3 grid grid-cols-3 gap-3">
                        <div title="Half of the sign-offs were faster than this, half slower">
                          <p className="text-xl font-black tabular-nums text-gray-900">{shortDuration(r.median_hours)}</p><p className="text-[11px] text-gray-500">typical wait</p>
                        </div>
                        <div title="9 in 10 sign-offs were faster than this; only the slowest 1 in 10 took longer">
                          <p className="text-xl font-black tabular-nums text-gray-900">{shortDuration(r.p90_hours)}</p><p className="text-[11px] text-gray-500">9 in 10 within</p>
                        </div>
                        <div title="Of the sign-offs that had a fix deadline, the share that came before it">
                          <p className={`text-xl font-black tabular-nums ${r.with_deadline && r.on_time / r.with_deadline < 0.8 ? "text-rose-600" : "text-gray-900"}`}>{r.with_deadline ? pct(r.on_time / r.with_deadline) : "—"}</p>
                          <p className="text-[11px] text-gray-500">on time</p>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </Card>

              <Card title="Waiting for review" sub="Findings still open, by how long they've been waiting"
                aside={<Link href="/sla" className="text-xs font-semibold text-indigo-600 hover:text-indigo-800">SLA tracker →</Link>}>
                <div className="space-y-3">
                  {data.backlog.by_age.map(b => (
                    <div key={b.key} className="flex items-center gap-3">
                      <span className="w-24 shrink-0 text-xs font-semibold text-gray-600">{b.label}</span>
                      <div className="flex-1 h-7 rounded-lg bg-gray-100 overflow-hidden">
                        <div className={`h-full rounded-lg ${b.key === "gt7d" ? "bg-rose-400" : b.key === "d2_7" ? "bg-orange-300" : b.key === "d1_2" ? "bg-amber-300" : "bg-emerald-300"}`}
                          style={{ width: `${b.count ? Math.max(4, (b.count / maxAge) * 100) : 0}%` }} />
                      </div>
                      <span className="w-10 text-right text-sm font-black tabular-nums text-gray-900">{b.count}</span>
                    </div>
                  ))}
                </div>
                <p className="mt-5 rounded-xl bg-gray-50 p-3 text-xs text-gray-700 leading-relaxed">
                  {clearSentence(data.backlog.open, data.totals.closed, days, data.backlog.days_to_clear)}
                </p>
              </Card>
            </div>

            {/* ── AI content + reviewers ── */}
            <div className="animate-fade-up grid grid-cols-1 xl:grid-cols-2 gap-6">
              <Card title="AI-written code" sub="Share of each week's scanned code written by AI (bigger scans count for more)"
                aside={<span className="text-xs text-gray-500">Period: <strong className="text-gray-900">{pct(data.totals.ai_share)}</strong></span>}>
                <ul className="space-y-2">
                  {data.weeks.map(w => (
                    <li key={w.week} className="flex items-center gap-3" title={w.range}>
                      <span className="w-20 shrink-0 text-xs text-gray-500">{w.label}</span>
                      <div className="flex-1 h-3 rounded-full bg-gray-100 overflow-hidden">
                        {w.ai_share != null && <div className="h-full rounded-full bg-indigo-400" style={{ width: `${Math.round(w.ai_share * 100)}%` }} />}
                      </div>
                      <span className="w-12 text-right text-xs font-bold tabular-nums text-gray-700">{w.ai_share == null ? "—" : pct(w.ai_share)}</span>
                    </li>
                  ))}
                </ul>
                <p className="mt-4 text-xs text-gray-400">Using AI isn&apos;t a problem in itself; unreviewed risky AI code is. Weeks without scans show “—”.</p>
              </Card>

              <Card title="Reviewers" sub="Who signed off files this period, and how quickly they usually did"
                aside={data.self_approvals > 0 ? <span title="The pull request's author signed off their own change" className="text-xs font-bold text-rose-600 bg-rose-50 px-2 py-1 rounded-lg">{data.self_approvals} signed off their own change{data.self_approvals === 1 ? "" : "s"}</span> : undefined}>
                {data.reviewers.length === 0 ? <p className="text-sm text-gray-400">No sign-offs in this period.</p> : (
                  <ul className="space-y-3">
                    {data.reviewers.slice(0, 8).map(r => (
                      <li key={r.reviewer}>
                        <div className="flex items-center justify-between gap-3 text-sm">
                          <span className="min-w-0 font-semibold text-gray-800 break-all">{r.reviewer}</span>
                          <span className="shrink-0 text-xs text-gray-500 tabular-nums"><strong className="text-gray-900">{r.signoffs}</strong> sign-off{r.signoffs === 1 ? "" : "s"} · usually within {shortDuration(r.median_hours)}</span>
                        </div>
                        <div className="mt-1 h-1.5 rounded-full bg-gray-100 overflow-hidden">
                          <div className="h-full rounded-full bg-emerald-400" style={{ width: `${(r.signoffs / maxReviewer) * 100}%` }} />
                        </div>
                      </li>
                    ))}
                  </ul>
                )}
              </Card>
            </div>

            {/* ── Repositories ── */}
            <div className="animate-fade-up">
              <Card title="Repositories" sub="What happened in each repository this period. “Waiting now” is what's still open today.">
                {data.repos.length === 0 ? <p className="text-sm text-gray-400">No scans in this period.</p> : (
                  <div className="overflow-x-auto -mx-6">
                    <table className="w-full min-w-[640px]">
                      <thead>
                        <tr className="text-left text-[10px] font-bold uppercase tracking-wider text-gray-400 border-b border-gray-100">
                          <th className="px-6 py-3">Repository</th>
                          <th className="px-4 py-3 text-right">Scans</th>
                          <th className="px-4 py-3 text-right">PRs</th>
                          <th className="px-4 py-3 text-right">Found</th>
                          <th className="px-4 py-3 text-right">Fixed / closed</th>
                          <th className="px-4 py-3 text-right">Waiting now</th>
                          <th className="px-6 py-3 text-right">AI-written</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-gray-50">
                        {data.repos.map(r => (
                          <tr key={r.repo} className="hover:bg-gray-50/60">
                            <td className="px-6 py-3"><Link href={`/repo/${r.repo}`} className="text-sm font-bold text-gray-800 hover:text-indigo-600 break-words">{r.repo}</Link></td>
                            <td className="px-4 py-3 text-right text-sm tabular-nums text-gray-700">{r.scans}</td>
                            <td className="px-4 py-3 text-right text-sm tabular-nums text-gray-700">{r.prs}</td>
                            <td className="px-4 py-3 text-right text-sm tabular-nums text-gray-700">{r.opened}</td>
                            <td className="px-4 py-3 text-right text-sm tabular-nums text-gray-700">{r.closed}</td>
                            <td className={`px-4 py-3 text-right text-sm font-bold tabular-nums ${r.open ? "text-rose-600" : "text-emerald-600"}`}>{r.open}</td>
                            <td className="px-6 py-3 text-right text-sm tabular-nums text-gray-700">{pct(r.ai_share)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </Card>
            </div>
          </>
        )}
      </div>
    </AuthGuard>
  );
}
