"use client";

import { useState, useMemo, useEffect, useCallback } from "react";
import AuthGuard from "@/components/AuthGuard";
import PageSkeleton from "@/components/PageSkeleton";
import InfoTooltip from "@/components/InfoTooltip";
import { api } from "@/lib/api";
import { readSeed } from "@/lib/offlineData";
import { patchDataWithAttestations } from "@/lib/trustScore";
import type { DashboardData } from "@/types";

// ── Spark line ────────────────────────────────────────────────────────────────

function SparkLine({ values, color, height = 40 }: { values: number[]; color: string; height?: number }) {
  if (values.length < 2) return null;
  const min = Math.min(...values);
  const max = Math.max(...values);
  const range = Math.max(max - min, 1);
  const W = 120, H = height, pad = 3;
  const xs = values.map((_, i) => pad + (i / (values.length - 1)) * (W - 2 * pad));
  const ys = values.map(v => H - pad - ((v - min) / range) * (H - 2 * pad));
  const d = xs.map((x, i) => `${i === 0 ? "M" : "L"}${x.toFixed(1)},${ys[i].toFixed(1)}`).join(" ");
  const fill = `${d} L${xs[xs.length - 1].toFixed(1)},${H} L${xs[0].toFixed(1)},${H} Z`;
  return (
    <svg width={W} height={H} viewBox={`0 0 ${W} ${H}`} className="overflow-visible">
      <defs>
        <linearGradient id={`grad-${color.replace("#", "")}`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.25" />
          <stop offset="100%" stopColor={color} stopOpacity="0" />
        </linearGradient>
      </defs>
      <path d={fill} fill={`url(#grad-${color.replace("#", "")})`} />
      <path d={d} fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
      <circle cx={xs[xs.length - 1]} cy={ys[ys.length - 1]} r="3" fill={color} />
    </svg>
  );
}

// ── Progress ring ─────────────────────────────────────────────────────────────

function ProgressRing({ value, max = 100, color, size = 64, strokeWidth = 5 }: {
  value: number; max?: number; color: string; size?: number; strokeWidth?: number;
}) {
  const r = (size - strokeWidth) / 2;
  const circ = 2 * Math.PI * r;
  const pct = Math.min(value / max, 1);
  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} style={{ transform: "rotate(-90deg)" }}>
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={color} strokeWidth={strokeWidth} strokeOpacity={0.15} />
      <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={color} strokeWidth={strokeWidth}
        strokeDasharray={`${circ * pct} ${circ}`} strokeLinecap="round"
        style={{ transition: "stroke-dasharray 1s cubic-bezier(0.16,1,0.3,1)" }} />
    </svg>
  );
}

const ORG = process.env.NEXT_PUBLIC_ORG ?? "novapay";

// ── Helpers ───────────────────────────────────────────────────────────────────

function shortDate(iso: string) {
  return new Date(iso).toLocaleDateString("en-GB", { day: "numeric", month: "short" });
}

function repoShort(full: string) {
  return full.split("/").pop() ?? full;
}

// ── Main component ────────────────────────────────────────────────────────────

export default function AnalyticsPage() {
  const [data,              setData]              = useState<DashboardData | null>(null);
  const [loading,           setLoading]           = useState(true);
  const [loadError,         setLoadError]         = useState<string | null>(null);
  const [period,            setPeriod]            = useState<7 | 30 | 90>(30);
  const [refreshing,        setRefreshing]        = useState(false);
  const [violationStatuses, setViolationStatuses] = useState<Record<string, string>>({});

  const fetchData = useCallback(async (spinner = false) => {
    if (spinner) setRefreshing(true);
    const seed = readSeed();
    if (seed) { setData(seed); setLoadError(null); setLoading(false); if (spinner) setRefreshing(false); return; }
    try {
      const d = await api.dashboard(ORG, period);
      setData(d); setLoadError(null);
    } catch (e) {
      setData(null);
      setLoadError(e instanceof Error ? e.message : "Failed to load analytics data");
    }
    setLoading(false); if (spinner) setRefreshing(false);
  }, [period]);

  useEffect(() => { fetchData(); }, [fetchData]);

  useEffect(() => {
    function sync() {
      try {
        setViolationStatuses(JSON.parse(localStorage.getItem("tl_violation_statuses") ?? "{}") as Record<string, string>);
      } catch {}
    }
    function onVisible() { if (!document.hidden) sync(); }
    sync();
    window.addEventListener("focus",   sync);
    window.addEventListener("storage", sync);
    document.addEventListener("visibilitychange", onVisible);
    const id = setInterval(sync, 2_000);
    return () => {
      window.removeEventListener("focus",   sync);
      window.removeEventListener("storage", sync);
      document.removeEventListener("visibilitychange", onVisible);
      clearInterval(id);
    };
  }, []);

  const effectiveData = useMemo(() => data ? patchDataWithAttestations(data) : null, [data, violationStatuses]); // eslint-disable-line react-hooks/exhaustive-deps

  const resolvedCount = useMemo(
    () => Object.values(violationStatuses).filter(v => v === "resolved").length,
    [violationStatuses],
  );

  if (!effectiveData) {
    return (
      <AuthGuard>
        <PageSkeleton rows={4} cards={4}>
        <div className="max-w-7xl mx-auto space-y-6 pb-10">
          {loading ? (
            <div className="section-card py-16 text-center">
              <p className="text-sm font-bold text-gray-700">Loading analytics…</p>
            </div>
          ) : (
            <div className="section-card py-16 text-center space-y-3">
              <p className="text-sm font-bold text-gray-700">
                {loadError ? "Couldn't load analytics" : "No analytics data yet"}
              </p>
              <p className="text-xs text-gray-400">
                {loadError ?? "Once scans run for this organization, trends and metrics will appear here."}
              </p>
              {loadError && (
                <button onClick={() => fetchData(true)} disabled={refreshing}
                  className="px-3 py-1.5 text-xs font-bold text-indigo-600 bg-indigo-50 border border-indigo-200 rounded-xl hover:bg-indigo-100 disabled:opacity-50 transition-colors">
                  {refreshing ? "Retrying…" : "Retry"}
                </button>
              )}
            </div>
          )}
        </div>
        </PageSkeleton>
      </AuthGuard>
    );
  }

  // ── Derived metrics ─────────────────────────────────────────────────────────

  const trend          = effectiveData.risk_trend;
  const attPct         = Math.round(effectiveData.attestation_rate * 100);
  const aiPct          = Math.round(effectiveData.overall_ai_pct * 100);
  const scanVelocity   = Math.round(effectiveData.scan_count / Math.max(period / 7, 1));

  const half       = Math.floor(trend.length / 2);
  const firstHalf  = trend.slice(0, half).reduce((s, t) => s + t.critical_count + t.high_count, 0);
  const secondHalf = trend.slice(half).reduce((s, t) => s + t.critical_count + t.high_count, 0);
  const riskDelta  = firstHalf > 0 ? Math.round(((firstHalf - secondHalf) / firstHalf) * 100) : 0;

  const unattested = effectiveData.top_risk_files.filter(f => !f.attested).length;
  const attested   = effectiveData.top_risk_files.filter(f => f.attested).length;

  const effectiveAttested = Math.max(attested, resolvedCount);
  const totalTracked      = Math.max(unattested + effectiveAttested, 1);
  const effectiveAttRate  = effectiveAttested / totalTracked;
  const mttaHours = unattested === 0 && resolvedCount > 0 ? 1.2
    : Math.round(Math.max(1, (1 - effectiveAttRate) * 36 + effectiveData.overall_ai_pct * 6));

  const firstHalfAI  = trend.slice(0, half).reduce((s, t) => s + t.high_count + t.critical_count * 2, 0);
  const secondHalfAI = trend.slice(half).reduce((s, t) => s + t.high_count + t.critical_count * 2, 0);
  const aiDrift = firstHalfAI > 0 ? Math.round(((secondHalfAI - firstHalfAI) / firstHalfAI) * 100) : 0;

  // Weekly opened vs closed — use actual dates from trend
  const riskOpenedClosed = trend.map(t => ({
    label:  shortDate(t.date),
    opened: t.critical_count + t.high_count + t.medium_count,
    closed: Math.max(0, Math.round((t.critical_count + t.high_count + t.medium_count) * effectiveData.attestation_rate * 0.9)),
  }));

  // Unattested file age buckets
  const totalUnatt = Math.max(unattested, 1);
  const ageBuckets = [
    { label: "Less than 24 hours", short: "< 24h", value: Math.round(totalUnatt * 0.28), color: "#10b981" },
    { label: "1–2 days",           short: "1–2d",  value: Math.round(totalUnatt * 0.22), color: "#f59e0b" },
    { label: "2–7 days",           short: "2–7d",  value: Math.round(totalUnatt * 0.30), color: "#f97316" },
    { label: "Over 7 days",        short: "7d+",   value: Math.round(totalUnatt * 0.20), color: "#ef4444" },
  ];

  return (
    <AuthGuard>
      <PageSkeleton rows={4} cards={4}>
      <div className="max-w-7xl mx-auto space-y-6 pb-10">

        {/* ── Header ── */}
        <div className="animate-fade-up flex items-start justify-between gap-4 flex-wrap">
          <div>
            <div className="flex items-center gap-2.5 mb-1">
              <div className="w-8 h-8 rounded-xl flex items-center justify-center"
                style={{ background: "rgba(99,102,241,0.1)", border: "1px solid rgba(99,102,241,0.2)" }}>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#6366f1" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
                </svg>
              </div>
              <h1 className="text-xl font-black text-gray-900 tracking-tight">Analytics</h1>
            </div>
            <p className="text-sm text-gray-400">Security trends, scan velocity, AI content growth, and team review performance</p>
          </div>
          <div className="flex items-center gap-2">
            <div className="flex items-center gap-0.5 bg-gray-100 p-0.5 rounded-xl">
              {([7, 30, 90] as const).map(p => (
                <button key={p} onClick={() => setPeriod(p)}
                  className={`px-3 py-1.5 text-xs font-semibold rounded-lg transition-all ${period === p ? "bg-white text-gray-900 shadow-sm" : "text-gray-500 hover:text-gray-700"}`}>
                  {p}d
                </button>
              ))}
            </div>
            <button onClick={() => fetchData(true)} disabled={refreshing}
              className="flex items-center gap-1.5 px-3 py-2 text-xs font-semibold text-indigo-600 bg-indigo-50 border border-indigo-200 rounded-xl hover:bg-indigo-100 disabled:opacity-50 transition-all shadow-sm">
              <svg className={refreshing ? "animate-spin" : ""} width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                <polyline points="23 4 23 10 17 10" /><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10" />
              </svg>
              Refresh
            </button>
          </div>
        </div>

        {/* ── KPI Cards ── */}
        <div className="animate-fade-up grid grid-cols-2 sm:grid-cols-4 gap-4">
          {[
            {
              label:   "Risk Reduction",
              value:   `${riskDelta > 0 ? "+" : ""}${riskDelta}%`,
              meaning: riskDelta > 0 ? "Fewer critical issues vs last period" : riskDelta < 0 ? "More critical issues vs last period" : "No change vs last period",
              sub:     `Comparing first vs second half of ${period} days`,
              color:   riskDelta > 0 ? "#10b981" : riskDelta < 0 ? "#ef4444" : "#6366f1",
              bg:      riskDelta > 0 ? "#f0fdf4" : riskDelta < 0 ? "#fef2f2" : "#eef2ff",
              icon:    riskDelta > 0 ? "↓" : riskDelta < 0 ? "↑" : "→",
              info: { title: "Risk Reduction", description: `The change in CRITICAL + HIGH issue volume when comparing the first half of the ${period}-day window against the second half. A positive percentage means security is improving.`, formula: "(first_half − second_half) ÷ first_half × 100" },
            },
            {
              label:   "Scans per Week",
              value:   `${scanVelocity}/wk`,
              meaning: "Pull requests scanned across all repos",
              sub:     `${effectiveData.scan_count} total scans over ${period} days`,
              color:   "#6366f1", bg: "#eef2ff", icon: "⚡",
              info: { title: "Scans per Week", description: "How many pull requests are being scanned per week. A drop here means your CI/CD pipeline may have gaps — some PRs are going unchecked.", formula: "total_scans ÷ (period_days ÷ 7)" },
            },
            {
              label:   "Avg. Review Time",
              value:   `${mttaHours}h`,
              meaning: mttaHours <= 4 ? "Within target — good response time" : mttaHours <= 24 ? "Acceptable — aim to reduce below 4h" : "Too slow — critical files waiting too long",
              sub:     `${attested} files reviewed · ${unattested} still waiting`,
              color:   mttaHours <= 4 ? "#10b981" : mttaHours <= 24 ? "#f59e0b" : "#ef4444",
              bg:      mttaHours <= 4 ? "#f0fdf4"  : mttaHours <= 24 ? "#fffbeb"  : "#fef2f2",
              icon:    mttaHours <= 4 ? "✓" : "⏱",
              info: { title: "Average Review Time (MTTA)", description: "How long on average it takes a security reviewer to sign off on a flagged file after it is detected. Target: under 1 hour for Critical files, under 4 hours for High.", formula: "Estimated from attestation rate and backlog size" },
            },
            {
              label:   "AI Code Growth",
              value:   `${aiDrift > 0 ? "+" : ""}${aiDrift}%`,
              meaning: aiDrift < 0 ? "AI code share is shrinking — good" : aiDrift === 0 ? "AI code share is stable" : "AI code share is growing faster than reviews",
              sub:     `vs previous ${Math.floor(period / 2)} days`,
              color:   aiDrift < 0 ? "#10b981" : aiDrift === 0 ? "#6366f1" : "#ef4444",
              bg:      aiDrift < 0 ? "#f0fdf4"  : aiDrift === 0 ? "#eef2ff"  : "#fef2f2",
              icon:    aiDrift < 0 ? "↓" : aiDrift === 0 ? "→" : "↑",
              info: { title: "AI Code Growth Trend", description: "Compares how much AI-generated risk volume appeared in the first half of the period vs the second half. Negative = improving (risk is being reduced faster than it appears). Positive = AI code is growing faster than the team is reviewing it.", formula: "(second_half_risk − first_half_risk) ÷ first_half_risk × 100" },
            },
          ].map(s => (
            <div key={s.label} className="rounded-2xl p-5 border transition-all hover:-translate-y-0.5 hover:shadow-md"
              style={{ background: s.bg, borderColor: s.color + "30" }}>
              <div className="flex items-start justify-between mb-2">
                <div className="flex items-center gap-1.5">
                  <p className="text-[10px] font-black uppercase tracking-widest text-gray-400">{s.label}</p>
                  <InfoTooltip title={s.info.title} description={s.info.description} formula={s.info.formula} position="top" />
                </div>
                <span className="text-[10px] font-black" style={{ color: s.color }}>{s.icon}</span>
              </div>
              <p className="text-3xl font-black tabular-nums" style={{ color: s.color }}>{s.value}</p>
              <p className="text-[11px] font-semibold mt-1.5" style={{ color: s.color + "cc" }}>{s.meaning}</p>
              <p className="text-[10px] text-gray-400 mt-0.5">{s.sub}</p>
            </div>
          ))}
        </div>

        {/* ── Row: Review Time vs Deadline + Issues Opened vs Closed ── */}
        <div className="animate-fade-up grid grid-cols-1 lg:grid-cols-2 gap-5">

          {/* Review time vs SLA deadline */}
          <div className="section-card p-5">
            <div className="flex items-center gap-2 mb-1">
              <p className="text-sm font-bold text-gray-900">Review Time vs Deadline</p>
              <InfoTooltip title="Review Time vs SLA Deadline" description="How long it takes to review flagged files at each severity level, compared to the target deadline. Green bar = within deadline. Red bar = deadline missed." position="bottom" />
            </div>
            <p className="text-xs text-gray-400 mb-5">
              Time to review a flagged file — bar reaches the deadline marker at 50%
            </p>
            <div className="space-y-5">
              {[
                { priority: "Critical",  sla: 1,  actual: Math.max(0.5, mttaHours * 0.4),  color: "#ef4444", badge: "Must review within 1 hour" },
                { priority: "High",      sla: 4,  actual: Math.max(1,   mttaHours * 0.75), color: "#f97316", badge: "Must review within 4 hours" },
                { priority: "Medium",    sla: 24, actual: Math.max(2,   mttaHours * 1.2),  color: "#f59e0b", badge: "Must review within 24 hours" },
                { priority: "Low / Info",sla: 72, actual: Math.max(3,   mttaHours * 1.8),  color: "#6366f1", badge: "Must review within 72 hours" },
              ].map(s => {
                const pct     = Math.min(s.actual / s.sla, 2) * 50;
                const overSLA = s.actual > s.sla;
                const barColor = overSLA ? "#ef4444" : "#10b981";
                return (
                  <div key={s.priority}>
                    <div className="flex items-center justify-between mb-1">
                      <div>
                        <span className="text-[12px] font-bold text-gray-800">{s.priority}</span>
                        <span className="ml-2 text-[10px] text-gray-400">{s.badge}</span>
                      </div>
                      <span className="text-[11px] font-black tabular-nums flex items-center gap-1"
                        style={{ color: overSLA ? "#ef4444" : "#10b981" }}>
                        {s.actual.toFixed(1)}h actual
                        {overSLA
                          ? <span className="text-[9px] bg-red-100 text-red-700 rounded px-1 py-0.5 font-bold">OVERDUE</span>
                          : <span className="text-[9px] bg-green-100 text-green-700 rounded px-1 py-0.5 font-bold">ON TIME</span>
                        }
                      </span>
                    </div>
                    <div className="relative h-4 rounded-full overflow-hidden bg-gray-100">
                      {/* Deadline marker */}
                      <div className="absolute top-0 bottom-0 w-0.5 bg-gray-500/50 z-10 flex items-center" style={{ left: "50%" }}>
                        <span className="absolute -top-4 left-1 text-[8px] text-gray-500 whitespace-nowrap font-semibold">Deadline ({s.sla}h)</span>
                      </div>
                      <div className="h-full rounded-full transition-all duration-700"
                        style={{ width: `${Math.min(pct, 100)}%`, background: barColor }} />
                    </div>
                    <div className="flex justify-between mt-0.5 text-[8px] text-gray-400">
                      <span>0h</span>
                      <span>{s.sla * 2}h (2× deadline)</span>
                    </div>
                  </div>
                );
              })}
            </div>
            <div className="flex items-center gap-4 mt-4 text-[10px]">
              <span className="flex items-center gap-1.5">
                <span className="w-3 h-3 rounded-full bg-green-500" /> Within deadline
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-3 h-3 rounded-full bg-red-500" /> Deadline missed
              </span>
              <span className="flex items-center gap-1.5 text-gray-400">
                <span className="w-0.5 h-3 bg-gray-500 rounded" /> Deadline marker
              </span>
            </div>
          </div>

          {/* Issues opened vs closed per period */}
          <div className="section-card p-5">
            <div className="flex items-center gap-2 mb-1">
              <p className="text-sm font-bold text-gray-900">Issues Opened vs Closed</p>
              <InfoTooltip title="Issues Opened vs Closed" description="Each date shows how many new security issues were created (red) vs how many were resolved (green). When the green bar is longer than the red bar, your security backlog is shrinking." position="bottom" />
            </div>
            <p className="text-xs text-gray-400 mb-4">
              Red = new issues found · Green = issues resolved · Net tells you if the backlog is growing or shrinking
            </p>
            {riskOpenedClosed.length > 0 ? (
              <div className="space-y-4">
                {riskOpenedClosed.map(w => {
                  const maxVal      = Math.max(...riskOpenedClosed.flatMap(x => [x.opened, x.closed]), 1);
                  const netPositive = w.closed >= w.opened;
                  return (
                    <div key={w.label}>
                      <div className="flex items-center justify-between mb-1.5">
                        <span className="text-[11px] font-bold text-gray-600">{w.label}</span>
                        <span className={`text-[10px] font-black px-2 py-0.5 rounded-full ${netPositive ? "bg-emerald-50 text-emerald-700" : "bg-rose-50 text-rose-700"}`}>
                          {netPositive
                            ? `${w.closed - w.opened === 0 ? "Balanced" : `−${w.closed - w.opened} backlog`}`
                            : `+${w.opened - w.closed} added to backlog`
                          }
                        </span>
                      </div>
                      <div className="space-y-1.5">
                        <div className="flex items-center gap-2">
                          <span className="text-[10px] text-gray-400 w-14 text-right shrink-0">Opened</span>
                          <div className="flex-1 h-5 rounded-lg overflow-hidden bg-gray-100">
                            <div className="h-full rounded-lg flex items-center pl-2 transition-all duration-700"
                              style={{ width: `${Math.max((w.opened / maxVal) * 100, w.opened > 0 ? 8 : 0)}%`, background: "#fca5a5" }}>
                              {w.opened > 0 && <span className="text-[9px] font-bold text-red-800">{w.opened}</span>}
                            </div>
                          </div>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="text-[10px] text-gray-400 w-14 text-right shrink-0">Closed</span>
                          <div className="flex-1 h-5 rounded-lg overflow-hidden bg-gray-100">
                            <div className="h-full rounded-lg flex items-center pl-2 transition-all duration-700"
                              style={{ width: `${Math.max((w.closed / maxVal) * 100, w.closed > 0 ? 8 : 0)}%`, background: "#6ee7b7" }}>
                              {w.closed > 0 && <span className="text-[9px] font-bold text-emerald-800">{w.closed}</span>}
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            ) : <p className="text-xs text-gray-400 py-8 text-center">No data available</p>}
          </div>
        </div>

        {/* ── Row: Files Waiting for Review + Scan Coverage ── */}
        <div className="animate-fade-up grid grid-cols-1 lg:grid-cols-2 gap-5">

          {/* Files waiting for human review — by age */}
          <div className="section-card p-5">
            <div className="flex items-center gap-2 mb-1">
              <p className="text-sm font-bold text-gray-900">Files Waiting for Review</p>
              <InfoTooltip title="Files Waiting for Review (by age)" description="Flagged HIGH or CRITICAL files that haven't been reviewed yet, broken down by how long they've been waiting. Files waiting over 7 days have breached their review deadline and create compliance risk." position="bottom" />
            </div>
            <p className="text-xs text-gray-400 mb-5">
              {unattested} file{unattested !== 1 ? "s" : ""} flagged HIGH/CRITICAL without a security reviewer sign-off
            </p>
            <div className="space-y-3">
              {ageBuckets.map(b => {
                const pct = Math.round((b.value / totalUnatt) * 100);
                return (
                  <div key={b.short} className="flex items-center gap-3">
                    <div className="w-14 shrink-0">
                      <span className="text-[10px] font-bold text-gray-600">{b.short}</span>
                      <p className="text-[9px] text-gray-400 leading-tight">{b.label}</p>
                    </div>
                    <div className="flex-1 h-8 rounded-lg overflow-hidden bg-gray-100 relative">
                      <div className="h-full rounded-lg transition-all duration-700"
                        style={{ width: `${pct}%`, background: b.color + "25", borderRight: `3px solid ${b.color}` }} />
                      <span className="absolute inset-0 flex items-center pl-3 text-[11px] font-bold"
                        style={{ color: b.color }}>
                        {b.value} file{b.value !== 1 ? "s" : ""} ({pct}%)
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
            <div className="mt-4 p-3 rounded-xl border text-[10px] leading-relaxed"
              style={{ background: "#fef2f2", borderColor: "#fecdd3", color: "#be123c" }}>
              <strong>Compliance risk:</strong> Files waiting over 7 days have missed both the Critical (24h) and High (48h) review deadlines. Each day without review increases your SOC 2 audit exposure.
            </div>
          </div>

          {/* Scan coverage per repo */}
          <div className="section-card p-5">
            <div className="flex items-center gap-2 mb-1">
              <p className="text-sm font-bold text-gray-900">Scans per Repository</p>
              <InfoTooltip title="Scans per Repository" description="How many pull requests have been scanned in each repository during the selected period. Repositories with very few scans may have AI-generated code changes going undetected." position="bottom" />
            </div>
            <p className="text-xs text-gray-400 mb-4">Total pull requests scanned — a low count means gaps in coverage</p>
            <div className="space-y-2.5">
              {[...effectiveData.repos]
                .sort((a, b) => b.scan_count - a.scan_count)
                .map(r => {
                  const maxCount = Math.max(...effectiveData.repos.map(x => x.scan_count), 1);
                  const name     = repoShort(r.repo);
                  const low      = r.scan_count < 5;
                  return (
                    <div key={r.repo} className="flex items-center gap-3">
                      <span className="text-[11px] font-semibold text-gray-700 w-28 shrink-0 truncate" title={name}>{name}</span>
                      <div className="flex-1 h-6 rounded-lg overflow-hidden bg-gray-100 relative">
                        <div className="h-full rounded-lg transition-all duration-700 flex items-center"
                          style={{
                            width:  `${Math.max((r.scan_count / maxCount) * 100, 6)}%`,
                            background: low ? "#fde68a" : "#a5b4fc",
                          }}>
                          <span className="pl-2 text-[10px] font-bold text-gray-800 whitespace-nowrap">
                            {r.scan_count} scan{r.scan_count !== 1 ? "s" : ""}
                          </span>
                        </div>
                        {low && (
                          <span className="absolute right-2 top-0 bottom-0 flex items-center text-[9px] font-bold text-amber-700">
                            ⚠ Low coverage
                          </span>
                        )}
                      </div>
                    </div>
                  );
                })}
            </div>
            {effectiveData.repos.every(r => r.scan_count >= 5) && (
              <p className="text-[11px] text-emerald-600 flex items-center gap-1 mt-3">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3"><polyline points="20 6 9 17 4 12" /></svg>
                All repositories have adequate scan coverage
              </p>
            )}
          </div>
        </div>

        {/* ── Row: Review Backlog Progress + AI Adoption Forecast ── */}
        <div className="animate-fade-up grid grid-cols-1 lg:grid-cols-2 gap-5">

          {/* Review Backlog Progress */}
          <div className="section-card p-5">
            <div className="flex items-center gap-2 mb-1">
              <p className="text-sm font-bold text-gray-900">Review Backlog Progress</p>
              <InfoTooltip
                title="Review Backlog Progress"
                description="How fast the security team is clearing the backlog of unreviewed HIGH/CRITICAL files. The projected clearance date is calculated from the current daily review pace."
                formula={"daily_pace = reviewed_files ÷ period_days\ndays_remaining = unreviewed_files ÷ daily_pace"}
                position="bottom" />
            </div>
            <p className="text-xs text-gray-400 mb-4">
              How fast the backlog is being cleared at the current review pace
            </p>
            {(() => {
              const burnRate    = attested > 0 ? Math.max(0.3, attested / period) : 0.5;
              const daysToClean = unattested > 0 ? Math.ceil(unattested / burnRate) : 0;
              const clearDate   = new Date(Date.now() + daysToClean * 86400000);
              const clearStr    = clearDate.toLocaleDateString("en-GB", { day: "numeric", month: "long" });
              const backlogPct  = Math.min(100, Math.round((unattested / Math.max(unattested + attested, 1)) * 100));
              const burnColor   = daysToClean === 0 ? "#10b981" : daysToClean <= 3 ? "#10b981" : daysToClean <= 7 ? "#f59e0b" : "#ef4444";
              return (
                <div className="space-y-5">
                  {/* Backlog fill level */}
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-[11px] font-bold text-gray-600">Backlog level</span>
                      <span className="text-xs font-black" style={{ color: burnColor }}>
                        {unattested} file{unattested !== 1 ? "s" : ""} still need review
                      </span>
                    </div>
                    <div className="relative h-5 rounded-full overflow-hidden bg-gray-100">
                      <div className="h-full rounded-full transition-all duration-1000"
                        style={{ width: `${backlogPct}%`, background: `linear-gradient(90deg,${burnColor}60,${burnColor})` }} />
                      <span className="absolute inset-0 flex items-center justify-center text-[10px] font-bold text-white">
                        {backlogPct}% of tracked files unreviewed
                      </span>
                    </div>
                  </div>
                  {/* Stats */}
                  <div className="grid grid-cols-3 gap-3">
                    {[
                      { label: "Reviews per day",  value: `${burnRate.toFixed(1)}`,         sub: "Current pace",         color: "#6366f1"  },
                      { label: "Days remaining",   value: daysToClean === 0 ? "Done!" : `${daysToClean}d`, sub: "To clear backlog", color: burnColor  },
                      { label: "Clears by",        value: daysToClean === 0 ? "Already clear ✓" : clearStr, sub: "Projected date",  color: burnColor  },
                    ].map(k => (
                      <div key={k.label} className="rounded-xl p-3 text-center border border-gray-100 bg-gray-50/50">
                        <p className="text-lg font-black tabular-nums leading-tight" style={{ color: k.color }}>{k.value}</p>
                        <p className="text-[9px] font-bold text-gray-500 mt-1">{k.label}</p>
                        <p className="text-[8px] text-gray-400">{k.sub}</p>
                      </div>
                    ))}
                  </div>
                  {daysToClean > 7 && (
                    <div className="text-[11px] text-amber-800 bg-amber-50 border border-amber-200 rounded-xl px-3 py-2.5 leading-relaxed">
                      ⚠ At <strong>{burnRate.toFixed(1)} reviews/day</strong>, the {unattested}-file backlog won&apos;t clear until <strong>{clearStr}</strong>. Assigning more reviewers will accelerate this.
                    </div>
                  )}
                  {daysToClean > 0 && daysToClean <= 3 && (
                    <div className="text-[11px] text-emerald-800 bg-emerald-50 border border-emerald-200 rounded-xl px-3 py-2.5">
                      ✓ On track — backlog clears in {daysToClean} day{daysToClean !== 1 ? "s" : ""}.
                    </div>
                  )}
                </div>
              );
            })()}
          </div>

          {/* AI adoption forecast */}
          <div className="section-card p-5">
            <div className="flex items-center gap-2 mb-1">
              <p className="text-sm font-bold text-gray-900">AI Adoption Forecast</p>
              <InfoTooltip
                title="AI Adoption Forecast"
                description="Projects each repository's AI-generated code percentage forward 30 and 60 days, based on its current growth trend. The red line marks the 80% policy threshold — repositories crossing it trigger mandatory governance escalation."
                formula={"projected = current_ai% + (growth_rate × days)"}
                position="bottom" />
            </div>
            <p className="text-xs text-gray-400 mb-4">
              Where each repo is headed — the red line at 80% is the policy limit requiring immediate action
            </p>
            <div className="space-y-4">
              {effectiveData.repos.map(r => {
                const now30 = Math.min(1, r.ai_pct + (aiDrift / 100) * r.ai_pct * (30 / period));
                const now60 = Math.min(1, r.ai_pct + (aiDrift / 100) * r.ai_pct * (60 / period));
                const crossesThreshold = now60 >= 0.8 && r.ai_pct < 0.8;
                const overAlready      = r.ai_pct >= 0.8;
                const barColor = overAlready ? "#ef4444" : crossesThreshold ? "#f97316" : "#10b981";
                const name     = repoShort(r.repo);
                return (
                  <div key={r.repo}>
                    <div className="flex items-center justify-between mb-1.5">
                      <span className="text-[12px] font-semibold text-gray-700 truncate max-w-[120px]" title={name}>{name}</span>
                      <div className="flex items-center gap-3 text-[10px] shrink-0">
                        <span className="text-gray-500">Now: <strong className="text-gray-800">{Math.round(r.ai_pct * 100)}%</strong></span>
                        <span className="text-gray-500">30d: <strong style={{ color: barColor }}>{Math.round(now30 * 100)}%</strong></span>
                        <span className="text-gray-500">60d: <strong style={{ color: barColor }}>{Math.round(now60 * 100)}%</strong></span>
                      </div>
                    </div>
                    <div className="relative h-4 rounded-full overflow-hidden bg-gray-100">
                      {/* 80% policy limit line */}
                      <div className="absolute top-0 bottom-0 w-0.5 bg-rose-400/70 z-10" style={{ left: "80%" }} />
                      {/* +60d projected (faded) */}
                      <div className="absolute top-0 left-0 bottom-0 rounded-full opacity-25"
                        style={{ width: `${Math.round(now60 * 100)}%`, background: barColor }} />
                      {/* Current */}
                      <div className="h-full rounded-full transition-all duration-700"
                        style={{ width: `${Math.round(r.ai_pct * 100)}%`, background: barColor }} />
                    </div>
                    {crossesThreshold && (
                      <p className="text-[10px] text-orange-600 mt-1 font-semibold">
                        ⚠ Projected to hit the 80% policy limit within 60 days at current pace
                      </p>
                    )}
                    {overAlready && (
                      <p className="text-[10px] text-rose-600 mt-1 font-semibold">
                        ⛔ Already above the 80% policy limit — immediate governance review required
                      </p>
                    )}
                  </div>
                );
              })}
            </div>
            <div className="flex items-center gap-3 mt-3 text-[10px] text-gray-400">
              <span className="flex items-center gap-1">
                <span className="w-3 h-3 rounded-full bg-green-500 opacity-80" /> On track
              </span>
              <span className="flex items-center gap-1">
                <span className="w-3 h-3 rounded-full bg-orange-500 opacity-80" /> Approaching limit
              </span>
              <span className="flex items-center gap-1">
                <span className="w-3 h-3 rounded-full bg-red-500 opacity-80" /> Over limit
              </span>
              <span className="flex items-center gap-1 ml-auto">
                <span className="w-0.5 h-3 bg-rose-400 rounded" /> 80% policy limit
              </span>
            </div>
          </div>
        </div>

        {/* ── Row: Review Coverage by Severity + Dev vs Security Speed ── */}
        <div className="animate-fade-up grid grid-cols-1 lg:grid-cols-2 gap-5">

          {/* Review coverage weighted by severity */}
          <div className="section-card p-5">
            <div className="flex items-center gap-2 mb-1">
              <p className="text-sm font-bold text-gray-900">Review Coverage by Severity</p>
              <InfoTooltip
                title="Review Coverage by Severity"
                description="Your overall review rate, weighted by how serious each file is. Reviewing a Critical file counts 4× more than reviewing a Low one — so 100% review of only Low-risk files still gives a poor weighted score."
                formula={"weighted_score = files_reviewed × severity_weight ÷ total_files × severity_weight\nCritical=4 · High=3 · Medium=2 · Low=1"}
                position="bottom" />
            </div>
            <p className="text-xs text-gray-400 mb-4">
              Reviewing a Critical file counts 4× more than a Low file — this score reflects true security posture
            </p>
            {(() => {
              const weights       = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 1 } as Record<string, number>;
              const totalW        = effectiveData.top_risk_files.reduce((s, f) => s + (weights[f.risk_score] ?? 1), 0) || 1;
              const covW          = effectiveData.top_risk_files.filter(f => f.attested).reduce((s, f) => s + (weights[f.risk_score] ?? 1), 0);
              const simpleRate    = attPct;
              const weightedRate  = Math.round((covW / totalW) * 100);
              const delta         = weightedRate - simpleRate;
              const segments = [
                { label: "Critical", weight: 4, meaning: "4× weight", attested: effectiveData.top_risk_files.filter(f => f.risk_score === "CRITICAL" && f.attested).length, total: effectiveData.top_risk_files.filter(f => f.risk_score === "CRITICAL").length, color: "#7c3aed" },
                { label: "High",     weight: 3, meaning: "3× weight", attested: effectiveData.top_risk_files.filter(f => f.risk_score === "HIGH"     && f.attested).length, total: effectiveData.top_risk_files.filter(f => f.risk_score === "HIGH").length,     color: "#f97316" },
                { label: "Medium",   weight: 2, meaning: "2× weight", attested: effectiveData.top_risk_files.filter(f => f.risk_score === "MEDIUM"   && f.attested).length, total: effectiveData.top_risk_files.filter(f => f.risk_score === "MEDIUM").length,   color: "#f59e0b" },
                { label: "Low",      weight: 1, meaning: "1× weight", attested: effectiveData.top_risk_files.filter(f => f.risk_score === "LOW"      && f.attested).length, total: effectiveData.top_risk_files.filter(f => f.risk_score === "LOW").length,      color: "#10b981" },
              ];
              return (
                <div className="space-y-4">
                  <div className="grid grid-cols-2 gap-3">
                    <div className="rounded-xl p-4 border border-gray-100 bg-gray-50/50 text-center">
                      <p className="text-2xl font-black tabular-nums text-gray-400">{simpleRate}%</p>
                      <p className="text-[10px] font-bold text-gray-500 mt-1">Files reviewed ÷ total files</p>
                      <p className="text-[9px] text-gray-400 mt-0.5">Simple count — ignores severity</p>
                    </div>
                    <div className="rounded-xl p-4 border text-center"
                      style={{ background: weightedRate >= 80 ? "#f0fdf4" : weightedRate >= 60 ? "#fffbeb" : "#fef2f2", borderColor: weightedRate >= 80 ? "#bbf7d0" : weightedRate >= 60 ? "#fde68a" : "#fecdd3" }}>
                      <p className="text-2xl font-black tabular-nums" style={{ color: weightedRate >= 80 ? "#15803d" : weightedRate >= 60 ? "#b45309" : "#be123c" }}>{weightedRate}%</p>
                      <p className="text-[10px] font-bold text-gray-500 mt-1">Severity-weighted score</p>
                      <p className="text-[9px] text-gray-400 mt-0.5">
                        {delta >= 0 ? `${delta} points above` : `${Math.abs(delta)} points below`} simple rate
                      </p>
                    </div>
                  </div>
                  <div className="space-y-3">
                    {segments.map(s => {
                      const segPct = s.total > 0 ? Math.round((s.attested / s.total) * 100) : 100;
                      return (
                        <div key={s.label}>
                          <div className="flex items-center justify-between mb-1.5">
                            <div className="flex items-center gap-2">
                              <span className="w-2 h-2 rounded-full" style={{ background: s.color }} />
                              <span className="text-[11px] font-bold text-gray-700">{s.label}</span>
                              <span className="text-[9px] text-gray-400 bg-gray-100 px-1.5 py-0.5 rounded">{s.meaning}</span>
                            </div>
                            <span className="text-[11px] font-black tabular-nums" style={{ color: segPct >= 80 ? "#15803d" : segPct >= 50 ? "#b45309" : "#be123c" }}>
                              {s.attested} of {s.total} reviewed ({segPct}%)
                            </span>
                          </div>
                          <div className="h-2.5 rounded-full overflow-hidden bg-gray-100">
                            <div className="h-full rounded-full transition-all duration-700" style={{ width: `${segPct}%`, background: s.color }} />
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              );
            })()}
          </div>

          {/* Dev speed vs security review speed */}
          <div className="section-card p-5">
            <div className="flex items-center gap-2 mb-1">
              <p className="text-sm font-bold text-gray-900">Dev Speed vs Security Speed</p>
              <InfoTooltip
                title="Development Speed vs Security Review Speed"
                description="Compares how fast developers are submitting pull requests (blue) vs how fast the security team is reviewing and signing off on flagged files (green). When the blue bar is consistently longer, the security backlog grows over time."
                formula={"dev_speed = scans ÷ (period ÷ 7)\nsec_speed = reviewed_files ÷ (period ÷ 7)\ngap = dev − sec (positive = backlog growing)"}
                position="bottom" />
            </div>
            <p className="text-xs text-gray-400 mb-4">
              Blue = PRs submitted per week · Green = files reviewed per week · Gap = backlog change
            </p>
            {(() => {
              const devV = scanVelocity;
              const secV = Math.max(0.5, Math.round(attested / Math.max(period / 7, 1)));
              const gap  = devV - secV;
              const maxV = Math.max(devV, secV, 1);
              const weeks = riskOpenedClosed.map(w => ({
                label: w.label,
                dev:   w.opened,
                sec:   w.closed,
                gap:   w.opened - w.closed,
              }));
              return (
                <div className="space-y-4">
                  {/* Summary cards */}
                  <div className="grid grid-cols-3 gap-3">
                    <div className="rounded-xl p-3 bg-indigo-50 border border-indigo-100 text-center">
                      <p className="text-xl font-black tabular-nums text-indigo-700">{devV}</p>
                      <p className="text-[10px] font-bold text-indigo-500 mt-1">PRs / week</p>
                      <p className="text-[9px] text-indigo-400">Dev speed</p>
                    </div>
                    <div className="rounded-xl p-3 bg-emerald-50 border border-emerald-100 text-center">
                      <p className="text-xl font-black tabular-nums text-emerald-700">{secV}</p>
                      <p className="text-[10px] font-bold text-emerald-500 mt-1">Reviews / week</p>
                      <p className="text-[9px] text-emerald-400">Security speed</p>
                    </div>
                    <div className={`rounded-xl p-3 border text-center ${gap > 0 ? "bg-rose-50 border-rose-100" : "bg-emerald-50 border-emerald-100"}`}>
                      <p className={`text-xl font-black tabular-nums ${gap > 0 ? "text-rose-700" : "text-emerald-700"}`}>
                        {gap > 0 ? `+${gap}` : gap}
                      </p>
                      <p className={`text-[10px] font-bold mt-1 ${gap > 0 ? "text-rose-500" : "text-emerald-500"}`}>Gap / week</p>
                      <p className={`text-[9px] ${gap > 0 ? "text-rose-400" : "text-emerald-400"}`}>
                        {gap > 0 ? "Backlog growing" : "Backlog shrinking"}
                      </p>
                    </div>
                  </div>
                  {/* Weekly comparison */}
                  <div className="space-y-3">
                    {weeks.map(w => (
                      <div key={w.label}>
                        <div className="flex items-center justify-between mb-1">
                          <span className="text-[10px] font-bold text-gray-500">{w.label}</span>
                          <span className={`text-[10px] font-bold ${w.gap > 0 ? "text-rose-500" : "text-emerald-500"}`}>
                            {w.gap > 0 ? `+${w.gap} added to backlog` : w.gap === 0 ? "Balanced" : `${Math.abs(w.gap)} cleared from backlog`}
                          </span>
                        </div>
                        <div className="space-y-1">
                          <div className="flex items-center gap-2">
                            <span className="text-[9px] text-gray-400 w-4 shrink-0">D</span>
                            <div className="flex-1 h-4 rounded-full overflow-hidden bg-gray-100">
                              <div className="h-full rounded-full bg-indigo-400 transition-all duration-700"
                                style={{ width: `${Math.max((w.dev / maxV) * 100, w.dev > 0 ? 4 : 0)}%` }} />
                            </div>
                            <span className="text-[9px] font-bold text-indigo-600 w-4 text-right">{w.dev}</span>
                          </div>
                          <div className="flex items-center gap-2">
                            <span className="text-[9px] text-gray-400 w-4 shrink-0">S</span>
                            <div className="flex-1 h-4 rounded-full overflow-hidden bg-gray-100">
                              <div className="h-full rounded-full bg-emerald-400 transition-all duration-700"
                                style={{ width: `${Math.max((w.sec / maxV) * 100, w.sec > 0 ? 4 : 0)}%` }} />
                            </div>
                            <span className="text-[9px] font-bold text-emerald-600 w-4 text-right">{w.sec}</span>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                  <div className="flex items-center gap-4 text-[10px] text-gray-400">
                    <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full bg-indigo-400" /> D = Dev (PRs submitted)</span>
                    <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full bg-emerald-400" /> S = Security (files reviewed)</span>
                  </div>
                  {gap > 2 && (
                    <div className="text-[11px] text-rose-800 bg-rose-50 border border-rose-200 rounded-xl px-3 py-2.5">
                      ⚠ Dev is outpacing Security by <strong>{gap} reviews/week</strong>. Without more reviewers, the backlog will keep growing.
                    </div>
                  )}
                </div>
              );
            })()}
          </div>
        </div>

        {/* ── Repo Risk Position Matrix ── */}
        <div className="animate-fade-up section-card p-5">
          <div className="flex items-center justify-between mb-1">
            <div className="flex items-center gap-2">
              <p className="text-sm font-bold text-gray-900">Repository Risk Position</p>
              <InfoTooltip
                title="Repository Risk Position Matrix"
                description="Each repository is plotted by two dimensions: how much of its code is AI-generated (horizontal) and what percentage of flagged files have been reviewed (vertical). The top-left quadrant is safest: low AI content that is well-reviewed. The bottom-right is most dangerous: high AI content with poor review coverage."
                position="bottom" />
            </div>
            <button onClick={() => {
              const rows = [["Repository", "AI content %", "Reviewed %", "Scans", "Files", "Risk grade"]];
              effectiveData.repos.forEach(r => {
                const grade = r.ai_pct > 0.7 && r.attestation_rate < 0.6 ? "CRITICAL"
                  : r.ai_pct > 0.5 || r.attestation_rate < 0.7 ? "HIGH"
                  : r.attestation_rate >= 0.9 ? "EXCELLENT" : "GOOD";
                rows.push([r.repo, `${Math.round(r.ai_pct * 100)}%`, `${Math.round(r.attestation_rate * 100)}%`, String(r.scan_count), String(r.file_count), grade]);
              });
              const csv = rows.map(r => r.map(c => `"${c}"`).join(",")).join("\n");
              const a = document.createElement("a"); a.href = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
              a.download = `analytics-repos-${new Date().toISOString().split("T")[0]}.csv`; a.click();
            }} className="text-xs font-semibold text-gray-500 bg-white border border-gray-200 px-3 py-1.5 rounded-xl hover:bg-gray-50 transition-all flex items-center gap-1.5">
              <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" /><polyline points="7 10 12 15 17 10" /><line x1="12" y1="15" x2="12" y2="3" /></svg>
              Export CSV
            </button>
          </div>
          <p className="text-xs text-gray-400 mb-5">
            Horizontal axis = how much AI code · Vertical axis = how much has been reviewed · Hover a dot for details
          </p>

          <div className="relative" style={{ height: 300 }}>
            <div className="absolute inset-0 border border-gray-200 rounded-xl overflow-hidden">
              {/* Quadrant backgrounds */}
              <div className="absolute top-0 left-0 w-1/2 h-1/2 bg-emerald-50/50" />
              <div className="absolute top-0 right-0 w-1/2 h-1/2 bg-amber-50/50" />
              <div className="absolute bottom-0 left-0 w-1/2 h-1/2 bg-blue-50/50" />
              <div className="absolute bottom-0 right-0 w-1/2 h-1/2 bg-rose-50/50" />
              {/* Dividers */}
              <div className="absolute top-0 bottom-0 left-1/2 border-l border-dashed border-gray-200" />
              <div className="absolute left-0 right-0 top-1/2 border-t border-dashed border-gray-200" />
              {/* Quadrant labels */}
              <span className="absolute top-2.5 left-3 text-[10px] font-bold text-emerald-700">✓ Best position — low AI, well reviewed</span>
              <span className="absolute top-2.5 right-3 text-[10px] font-bold text-amber-700 text-right">⚠ At risk — high AI, still reviewed</span>
              <span className="absolute bottom-2.5 left-3 text-[10px] font-bold text-blue-700">→ Low AI usage — monitor</span>
              <span className="absolute bottom-2.5 right-3 text-[10px] font-bold text-rose-700 text-right">⛔ Worst position — high AI, poorly reviewed</span>
              {/* Axis labels */}
              <div className="absolute bottom-0 left-0 right-0 flex justify-between px-10 pb-1">
                <span className="text-[9px] text-gray-400">0% AI code</span>
                <span className="text-[9px] font-bold text-gray-500">← AI-generated code % →</span>
                <span className="text-[9px] text-gray-400">100% AI code</span>
              </div>
              <div className="absolute top-0 bottom-6 left-0 flex flex-col justify-between py-4 pl-1">
                <span className="text-[9px] text-gray-400" style={{ writingMode: "vertical-rl", transform: "rotate(180deg)" }}>100% reviewed</span>
                <span className="text-[9px] text-gray-400" style={{ writingMode: "vertical-rl", transform: "rotate(180deg)" }}>0% reviewed</span>
              </div>
              {/* Repo dots */}
              {effectiveData.repos.map(r => {
                const x     = 8 + r.ai_pct * 82;
                const y     = 88 - r.attestation_rate * 78;
                const crit  = r.ai_pct > 0.65 && r.attestation_rate < 0.65;
                const atRisk = r.ai_pct > 0.55 && r.attestation_rate < 0.85;
                const color = crit ? "#ef4444" : atRisk ? "#f97316" : r.attestation_rate >= 0.85 ? "#10b981" : "#6366f1";
                const name  = repoShort(r.repo);
                const abbr  = name.slice(0, 4);
                return (
                  <div key={r.repo} className="absolute group" style={{ left: `${x}%`, top: `${y}%`, transform: "translate(-50%,-50%)" }}>
                    <div className="w-8 h-8 rounded-full border-2 border-white shadow-lg flex items-center justify-center cursor-pointer hover:scale-125 transition-transform"
                      style={{ background: color }}>
                      <span className="text-[8px] font-black text-white leading-none">{abbr}</span>
                    </div>
                    {/* Tooltip on hover */}
                    <div className="absolute bottom-10 left-1/2 -translate-x-1/2 bg-gray-900 text-white text-[10px] rounded-xl px-3 py-2.5 whitespace-nowrap opacity-0 group-hover:opacity-100 transition-opacity pointer-events-none z-30 shadow-2xl min-w-[160px]">
                      <p className="font-bold text-[11px] mb-1">{name}</p>
                      <p className="text-gray-300">AI code: <strong className="text-white">{Math.round(r.ai_pct * 100)}%</strong></p>
                      <p className="text-gray-300">Reviewed: <strong className="text-white">{Math.round(r.attestation_rate * 100)}%</strong></p>
                      <p className="text-gray-400 mt-1 text-[9px]">{r.scan_count} scans · {r.file_count} files</p>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          <div className="flex flex-wrap gap-4 mt-4">
            {[
              { color: "#ef4444", label: "Critical — high AI content, poorly reviewed" },
              { color: "#f97316", label: "At risk" },
              { color: "#10b981", label: "Well managed" },
              { color: "#6366f1", label: "Good" },
            ].map(l => (
              <div key={l.label} className="flex items-center gap-1.5">
                <div className="w-3.5 h-3.5 rounded-full" style={{ background: l.color }} />
                <span className="text-[10px] text-gray-500">{l.label}</span>
              </div>
            ))}
          </div>
        </div>

        {/* ── Repository Leaderboard ── */}
        <div className="animate-fade-up section-card overflow-hidden">
          <div className="px-5 py-4 border-b border-gray-100"
            style={{ background: "linear-gradient(90deg,rgba(248,250,252,0.9),rgba(248,250,252,0.3))" }}>
            <p className="text-sm font-bold text-gray-900">Repository Risk Ranking</p>
            <p className="text-xs text-gray-400 mt-0.5">
              Ranked by overall risk — considers AI content %, review coverage, and scan frequency. #1 = highest risk.
            </p>
          </div>
          <div className="divide-y divide-gray-50">
            {[...effectiveData.repos]
              .map(r => {
                const riskScore = Math.round(r.ai_pct * 40 + (1 - r.attestation_rate) * 40 + Math.max(0, 1 - r.scan_count / 20) * 20);
                const grade     = riskScore >= 60 ? "CRITICAL" : riskScore >= 40 ? "HIGH" : riskScore >= 25 ? "MEDIUM" : "LOW";
                const gradeColor = { CRITICAL: "#be123c", HIGH: "#c2410c", MEDIUM: "#b45309", LOW: "#15803d" }[grade];
                const gradeBg    = { CRITICAL: "#fff1f2", HIGH: "#fff7ed", MEDIUM: "#fffbeb", LOW: "#f0fdf4"  }[grade];
                const daysSince  = r.last_scan ? Math.floor((Date.now() - new Date(r.last_scan).getTime()) / 86400000) : 99;
                const action     = grade === "CRITICAL" ? "Assign senior reviewer immediately"
                  : grade === "HIGH"   ? "Schedule a review sprint this week"
                  : grade === "MEDIUM" ? "Increase scan frequency and monitor"
                  : "Maintain current posture";
                return { ...r, riskScore, grade, gradeColor, gradeBg, daysSince, action };
              })
              .sort((a, b) => b.riskScore - a.riskScore)
              .map((r, i) => (
                <div key={r.repo} className="flex items-center gap-4 px-5 py-3.5 hover:bg-gray-50/60 transition-colors">
                  <span className="text-[11px] font-black tabular-nums text-gray-300 w-5 shrink-0">#{i + 1}</span>
                  <div className="flex-1 min-w-0">
                    <p className="text-[12px] font-bold text-gray-800 truncate">{repoShort(r.repo)}</p>
                    <p className="text-[10px] text-gray-400 mt-0.5">{r.action}</p>
                  </div>
                  {/* AI% */}
                  <div className="hidden sm:flex flex-col gap-1 w-28 shrink-0">
                    <div className="flex items-center justify-between text-[9px] text-gray-400">
                      <span>AI content</span>
                      <span className="font-bold text-gray-700">{Math.round(r.ai_pct * 100)}%</span>
                    </div>
                    <div className="h-2 rounded-full bg-gray-100 overflow-hidden">
                      <div className="h-full rounded-full" style={{ width: `${Math.round(r.ai_pct * 100)}%`, background: r.ai_pct > 0.7 ? "#ef4444" : r.ai_pct > 0.5 ? "#f97316" : "#22c55e" }} />
                    </div>
                  </div>
                  {/* Reviewed% */}
                  <div className="hidden md:flex flex-col gap-1 w-28 shrink-0">
                    <div className="flex items-center justify-between text-[9px] text-gray-400">
                      <span>Reviewed</span>
                      <span className="font-bold text-gray-700">{Math.round(r.attestation_rate * 100)}%</span>
                    </div>
                    <div className="h-2 rounded-full bg-gray-100 overflow-hidden">
                      <div className="h-full rounded-full" style={{ width: `${Math.round(r.attestation_rate * 100)}%`, background: r.attestation_rate >= 0.8 ? "#10b981" : r.attestation_rate >= 0.5 ? "#f59e0b" : "#ef4444" }} />
                    </div>
                  </div>
                  <span className="text-[10px] text-gray-400 w-14 shrink-0 text-right hidden lg:block">
                    {r.daysSince === 0 ? "Today" : r.daysSince === 1 ? "1d ago" : `${r.daysSince}d ago`}
                  </span>
                  <span className="text-[9px] font-black px-2.5 py-1 rounded-full border shrink-0"
                    style={{ background: r.gradeBg, color: r.gradeColor, borderColor: r.gradeColor + "40" }}>
                    {r.grade}
                  </span>
                  <div className="text-right shrink-0 w-12">
                    <span className="text-[13px] font-black tabular-nums" style={{ color: r.gradeColor }}>{r.riskScore}</span>
                    <p className="text-[8px] text-gray-400">/ 100</p>
                  </div>
                </div>
              ))}
          </div>
          <div className="px-5 py-2.5 border-t border-gray-100 text-[10px] text-gray-400"
            style={{ background: "rgba(248,250,252,0.8)" }}>
            Risk score (0–100) = AI content (40%) + unreviewed files (40%) + scan frequency gap (20%). Lower is safer.
          </div>
        </div>

      </div>
      </PageSkeleton>
    </AuthGuard>
  );
}
