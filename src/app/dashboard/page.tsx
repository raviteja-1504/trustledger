"use client";

/**
 * Dashboard: one screen that answers "how governed is our code right now, and what should we do next?" before
 * anyone opens a specific page.
 *
 *   1. Trust Score hero: score, 30-day trend, the six dimensions, the actions worth the most points.
 *   2. Six headline numbers, each linking to where it's handled.
 *   3. Risk trend for the period, next to the review queue.
 *   4. Governance: AI tool usage, leaked secrets, audit evidence.
 *   5. Repositories, next to recent activity.
 *
 * Every number comes from real data: the dashboard payload (api.dashboard), /api/trust-score, /api/shadow-ai,
 * /api/secrets and /api/evidence/collect?overview=1. Panels whose data can't load say so instead of guessing.
 */

import { useEffect, useState, useMemo } from "react";
import Link from "next/link";
import AuthGuard from "@/components/AuthGuard";
import { api } from "@/lib/api";
import { loadPolicy } from "@/lib/policy";
import { computeTrustScore } from "@/lib/trustScore";
import { useScansRealtime } from "@/lib/realtime";
import { useAuth } from "@/lib/auth";
import SetupGuide from "@/components/setup/SetupGuide";
import { useRole, ROLE_LABELS, ROLE_COLORS } from "@/lib/roles";
import RoleGate from "@/components/RoleGate";
import NewScanPanel from "@/components/NewScanPanel";
import type { DashboardData, ActivityEvent } from "@/types";
import type { GovernanceScore } from "@/lib/governanceScore";
import type { ShadowSummary } from "@/lib/shadowAi";
import type { EvidenceOverview } from "@/lib/evidenceEngine";
import { applyLiveReviewState } from "@/lib/dashboardLiveState";
import { deriveActivity } from "@/lib/dashboardActivity";
import { authedFetch, isSeedMode } from "@/lib/useRealData";
import TrustHero, { type TrustHistoryPoint } from "@/components/dashboard/TrustHero";
import KpiStrip, { buildKpis } from "@/components/dashboard/KpiStrip";
import ReviewQueue, { buildQueue } from "@/components/dashboard/ReviewQueue";
import RiskPanel from "@/components/dashboard/RiskPanel";
import RepoTable, { buildRepoRows } from "@/components/dashboard/RepoTable";
import ActivityList from "@/components/dashboard/ActivityList";
import { EvidencePanel, SecretsPanel, ShadowAiPanel, countSecrets, type Loadable, type SecretCounts } from "@/components/dashboard/GovernancePanels";

const DAYS_OPTIONS = [7, 30, 90] as const;
type DaysOption = (typeof DAYS_OPTIONS)[number];
type RangeMode = DaysOption | "custom";
const ORG = process.env.NEXT_PUBLIC_ORG ?? "acme";

const riskPrefix = (r: string) => r === "CRITICAL" ? "crit" : r === "HIGH" ? "high" : r === "MEDIUM" ? "med" : "low";

function KeyboardIcon() {
  return (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="2" y="7" width="20" height="14" rx="2"/><path d="M7 21V7"/><path d="M17 21V7"/><path d="M2 11h20"/><path d="M2 15h20"/>
    </svg>
  );
}

function ShortcutsToast({ onClose }: { onClose: () => void }) {
  const shortcuts = [
    { key: "N", desc: "New scan" }, { key: "E", desc: "Export CSV" },
    { key: "7", desc: "Last 7 days" }, { key: "3", desc: "Last 30 days" }, { key: "9", desc: "Last 90 days" },
    { key: "?", desc: "This menu" },
  ];
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm" onClick={onClose}>
      <div className="bg-white rounded-2xl shadow-2xl p-6 w-80 mx-4 animate-fade-up" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-4">
          <p className="font-bold text-gray-900 flex items-center gap-2"><KeyboardIcon /> Keyboard shortcuts</p>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600 text-lg leading-none" aria-label="Close">×</button>
        </div>
        <ul className="space-y-2">
          {shortcuts.map(s => (
            <li key={s.key} className="flex items-center justify-between">
              <span className="text-sm text-gray-600">{s.desc}</span>
              <kbd className="text-xs font-bold bg-gray-100 text-gray-700 px-2 py-0.5 rounded-lg border border-gray-200">{s.key}</kbd>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}

function greeting(name?: string | null) {
  const h = new Date().getHours();
  const part = h < 12 ? "Good morning" : h < 18 ? "Good afternoon" : "Good evening";
  return name ? `${part}, ${name}` : part;
}

export default function DashboardPage() {
  const [rangeMode,     setRangeMode]     = useState<RangeMode>(90);
  const [days,          setDays]          = useState<DaysOption>(90);
  const [startDate,     setStartDate]     = useState("");
  const [endDate,       setEndDate]       = useState("");
  const [pendingStart,  setPendingStart]  = useState("");
  const [pendingEnd,    setPendingEnd]    = useState("");
  const [data,          setData]          = useState<DashboardData | null>(null);
  const [error,         setError]         = useState<string | null>(null);
  const [loading,       setLoading]       = useState(true);
  const [lastRefreshed, setLastRefreshed] = useState<Date | null>(null);
  const [refreshAgo,    setRefreshAgo]    = useState("");
  const [refreshing,    setRefreshing]    = useState(false);
  const [activity,      setActivity]      = useState<ActivityEvent[]>([]);
  const [localActivity, setLocalActivity] = useState<ActivityEvent[]>([]); // sign-offs made on the PR page
  const [policyName,    setPolicyName]    = useState("Standard");
  const [scanPanelOpen, setScanPanelOpen] = useState(false);
  const [showShortcuts, setShowShortcuts] = useState(false);
  const [reloadKey,     setReloadKey]     = useState(0);
  const [violationStatuses, setViolationStatuses] = useState<Record<string, string>>({});
  const [secretCounts,  setSecretCounts]  = useState<Loadable<SecretCounts>>(null);
  const [trust,         setTrust]         = useState<Loadable<{ score: GovernanceScore; history: TrustHistoryPoint[] }>>(null);
  const [shadow,        setShadow]        = useState<Loadable<ShadowSummary>>(null);
  const [evidence,      setEvidence]      = useState<Loadable<EvidenceOverview>>(null);

  const { role, permissions } = useRole();
  const roleColor = ROLE_COLORS[role];
  const { profile } = useAuth();
  const isDeveloperView = role === "developer";
  const seed = isSeedMode();
  const orgLabel = profile?.org_id ? (profile.org_name || profile.org_slug || ORG) : ORG;

  // A new scan landed: reload the dashboard payload.
  useScansRealtime(profile?.org_id, () => setReloadKey(k => k + 1));

  useEffect(() => { setPolicyName(loadPolicy().name); }, []);

  // Review state and open secrets live server-side, so this agrees with the sidebar badges and their pages.
  useEffect(() => {
    async function sync() {
      if (!profile?.org_id) return;
      if (isSeedMode()) {
        const total = parseInt(localStorage.getItem("tl_secret_total") ?? "0", 10);
        setSecretCounts({ CRITICAL: 0, HIGH: 0, MEDIUM: isNaN(total) ? 0 : total });
        return;
      }
      try {
        const [overridesRes, secretsRes] = await Promise.all([
          authedFetch<{ overrides: Record<string, { status: string }> }>("/api/violation-status"),
          authedFetch<{ findings: { status: string; severity?: string }[] }>("/api/secrets?status=open"),
        ]);
        const next: Record<string, string> = {};
        for (const [id, o] of Object.entries(overridesRes.overrides ?? {})) next[id] = o.status;
        setViolationStatuses(next);
        setSecretCounts(countSecrets(secretsRes.findings ?? []));
      } catch { setSecretCounts(prev => prev ?? "unavailable"); }
    }
    function onVisible() { if (!document.hidden) sync(); }
    sync();
    window.addEventListener("focus", sync);
    window.addEventListener("tl:badge", sync);
    document.addEventListener("visibilitychange", onVisible);
    const id = setInterval(() => { if (!document.hidden) sync(); }, 30_000);
    return () => {
      window.removeEventListener("focus", sync);
      window.removeEventListener("tl:badge", sync);
      document.removeEventListener("visibilitychange", onVisible);
      clearInterval(id);
    };
  }, [profile?.org_id]);

  // Trust Score, AI tool usage and audit evidence: server-computed, independent of the date range.
  useEffect(() => {
    if (seed) return;
    let live = true;
    authedFetch<{ score: GovernanceScore; history: TrustHistoryPoint[] }>("/api/trust-score?history=30")
      .then(r => { if (live) setTrust(r?.score ? { score: r.score, history: r.history ?? [] } : "unavailable"); })
      .catch(() => { if (live) setTrust("unavailable"); });
    authedFetch<{ summary: ShadowSummary }>("/api/shadow-ai?days=30")
      .then(r => { if (live) setShadow(r?.summary ?? "unavailable"); })
      .catch(() => { if (live) setShadow("unavailable"); });
    if (!isDeveloperView) {
      authedFetch<EvidenceOverview>("/api/evidence/collect?overview=1")
        .then(o => { if (live) setEvidence(Array.isArray(o?.frameworks) ? o : "unavailable"); })
        .catch(() => { if (live) setEvidence("unavailable"); });
    }
    return () => { live = false; };
  }, [seed, isDeveloperView, reloadKey]);

  // Sign-offs made on the PR page show up in activity straight away.
  useEffect(() => {
    function syncLocal() {
      try { setLocalActivity((JSON.parse(localStorage.getItem("tl_local_activity") ?? "[]") as ActivityEvent[]).slice(0, 15)); } catch {}
    }
    syncLocal();
    window.addEventListener("focus", syncLocal);
    const id = setInterval(syncLocal, 5_000);
    return () => { window.removeEventListener("focus", syncLocal); clearInterval(id); };
  }, []);

  // Dashboard payload for the selected range.
  useEffect(() => {
    // Opt-in dev seed, only without a real org.
    const seedRaw = typeof window !== "undefined" && localStorage.getItem("tl_force_seed") === "1" && !profile?.org_id
      ? localStorage.getItem("tl_notif_snapshot") : null;
    if (seedRaw) {
      try {
        const s = JSON.parse(seedRaw) as DashboardData;
        if (Array.isArray(s?.repos) && s.repos.length > 0) {
          setData(s); setLastRefreshed(new Date()); setLoading(false); setActivity(deriveActivity(s));
          return;
        }
      } catch {}
    }
    let live = true;
    setError(null); setLoading(true);
    const sd = rangeMode === "custom" ? startDate : undefined;
    const ed = rangeMode === "custom" ? endDate : undefined;
    api.dashboard(ORG, typeof rangeMode === "number" ? rangeMode : days, sd, ed)
      .then(d => { if (!live) return; setData(d); setLastRefreshed(new Date()); setActivity(d.repos.length > 0 ? deriveActivity(d) : []); })
      .catch((e: Error) => { if (live) { setData(null); setError(e?.message || "Failed to load dashboard data"); } })
      .finally(() => { if (live) setLoading(false); });
    return () => { live = false; };
  }, [days, rangeMode, startDate, endDate, profile?.org_id, reloadKey]);

  useEffect(() => {
    function tick() {
      if (!lastRefreshed) { setRefreshAgo(""); return; }
      const s = Math.floor((Date.now() - lastRefreshed.getTime()) / 1000);
      setRefreshAgo(s < 60 ? "just now" : s < 3600 ? `${Math.floor(s / 60)}m ago` : `${Math.floor(s / 3600)}h ago`);
    }
    tick();
    const id = setInterval(tick, 30_000);
    return () => clearInterval(id);
  }, [lastRefreshed]);

  const { effectiveData } = useMemo(() => applyLiveReviewState(data, violationStatuses), [data, violationStatuses]);

  const displayActivity = useMemo(() => {
    const seen = new Set<string>();
    return [...localActivity, ...activity]
      .filter(e => { const k = `${e.scan_id}::${e.file_path}::${e.timestamp}`; if (seen.has(k)) return false; seen.add(k); return true; })
      .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
      .slice(0, 15);
  }, [localActivity, activity]);

  const queue = useMemo(() => effectiveData
    ? buildQueue(effectiveData, Date.now(), f => violationStatuses[`${riskPrefix(f.risk_score)}::${f.scan_id}::${f.file_path}`] === "in_review")
    : [], [effectiveData, violationStatuses]);

  const kpis = useMemo(() => {
    if (!effectiveData) return [];
    const d = effectiveData;
    const sevenDaysAgo = new Date(Date.now() - 7 * 86400000).toISOString().split("T")[0];
    const scanned7d = d.repos.filter(r => r.last_scan && r.last_scan >= sevenDaysAgo).length;
    const connected = Math.max(d.connected_repo_count ?? 0, d.repos.length);
    const totalHigh = d.total_high_crit ?? null;
    const reviewed = d.attested_high_crit ?? null;
    const unreviewed = d.top_risk_files.filter(f => !f.attested && (f.risk_score === "CRITICAL" || f.risk_score === "HIGH"));
    const sla = (d.sla_breach_critical_count ?? 0) + (d.sla_breach_high_count ?? 0);
    const secrets = secretCounts === null || secretCounts === "unavailable" ? null : secretCounts;
    return buildKpis({
      unreviewedHighRisk: unreviewed.length,
      unreviewedCritical: unreviewed.filter(f => f.risk_score === "CRITICAL").length,
      awaitingSignoffRepos: d.unattested_deploy_count,
      slaBreaches: sla,
      openSecrets: secrets ? secrets.CRITICAL + secrets.HIGH + secrets.MEDIUM : null,
      openCriticalSecrets: secrets ? secrets.CRITICAL : null,
      reviewCoverage: totalHigh ? d.attestation_rate : null,
      reviewedFiles: reviewed, totalHighRiskFiles: totalHigh,
      scanCoverage: connected ? scanned7d / connected : 0,
      reposScanned7d: scanned7d, reposConnected: connected,
    });
  }, [effectiveData, secretCounts]);

  const repoRows = useMemo(() => effectiveData
    ? buildRepoRows(effectiveData.repos, trust && trust !== "unavailable" ? trust.score.repos : null)
    : [], [effectiveData, trust]);

  const demoTotal = useMemo(() => seed && effectiveData ? computeTrustScore(effectiveData).total : null, [seed, effectiveData]);

  function exportCSV() {
    if (!effectiveData) return;
    const rows = [
      ["Repository", "Trust Score", "Open CRITICAL", "Open HIGH", "High-risk reviewed %", "AI %", "Scans", "Last scan"],
      ...repoRows.map(r => [r.repo, r.score ?? "", r.openCritical ?? "", r.openHigh ?? r.highCrit, Math.round(r.review * 100), (r.ai * 100).toFixed(1), r.scans, r.lastScan ?? ""]),
    ];
    const csv = rows.map(r => r.map(v => `"${String(v).replace(/"/g, '""')}"`).join(",")).join("\n");
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
    a.download = `trustledger-repositories-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(a.href);
  }

  async function refresh() {
    setRefreshing(true);
    try {
      const sd = rangeMode === "custom" ? startDate : undefined;
      const ed = rangeMode === "custom" ? endDate : undefined;
      const d = await api.dashboard(ORG, typeof rangeMode === "number" ? rangeMode : days, sd, ed, true);
      setData(d); setLastRefreshed(new Date()); setActivity(d.repos.length > 0 ? deriveActivity(d) : []);
      setReloadKey(k => k + 1);
    } catch {}
    setRefreshing(false);
  }

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      const tag = (e.target as HTMLElement).tagName;
      if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return;
      if (e.key === "?" || e.key === "/") { setShowShortcuts(s => !s); return; }
      if (e.key === "n" || e.key === "N") { if (permissions.canScan) setScanPanelOpen(true); }
      if (e.key === "e" || e.key === "E") { if (permissions.canExportData) exportCSV(); }
      if (e.key === "7") { setDays(7); setRangeMode(7); }
      if (e.key === "3") { setDays(30); setRangeMode(30); }
      if (e.key === "9") { setDays(90); setRangeMode(90); }
      if (e.key === "Escape") setShowShortcuts(false);
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [permissions, repoRows]); // eslint-disable-line react-hooks/exhaustive-deps

  const hasData = !!effectiveData && effectiveData.repos.length > 0;
  const periodLabel = rangeMode === "custom"
    ? (startDate && endDate ? `${startDate} → ${endDate}` : "custom range")
    : `last ${rangeMode} days`;
  const firstName = profile?.name?.split(" ")[0] ?? null;

  return (
    <AuthGuard>
      <div className="max-w-[1400px] mx-auto space-y-5 pb-12">

        {/* ── Header ── */}
        <header className="animate-fade-up flex flex-wrap items-end justify-between gap-4">
          <div className="min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="flex items-center gap-1.5 text-[11px] font-semibold text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded-full ring-1 ring-emerald-200">
                <span className="relative flex w-1.5 h-1.5">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                  <span className="relative inline-flex rounded-full w-1.5 h-1.5 bg-emerald-500" />
                </span>
                Live
              </span>
              <span className="text-xs font-semibold text-gray-500 truncate">{orgLabel}</span>
              <span className={`inline-flex items-center gap-1 text-[11px] font-semibold px-2 py-0.5 rounded-full ring-1 ${roleColor.bg} ${roleColor.text} ${roleColor.ring}`}>
                <span className={`w-1.5 h-1.5 rounded-full ${roleColor.dot}`} />{ROLE_LABELS[role]}
              </span>
              <Link href="/settings" className="text-[11px] font-semibold text-gray-500 hover:text-indigo-600">
                {/policy/i.test(policyName) ? policyName : `${policyName} policy`}
              </Link>
            </div>
            <h1 className="mt-1.5 text-2xl font-black text-gray-900 tracking-tight">{greeting(firstName)}</h1>
            <p className="text-sm text-gray-500 mt-0.5">
              {isDeveloperView ? "Your pull requests" : "Code governance across your organisation"} · {periodLabel}
              {refreshAgo && <span className="text-gray-400"> · updated {refreshAgo}</span>}
            </p>
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            <div className="flex items-center gap-0.5 bg-gray-100 p-1 rounded-xl" role="group" aria-label="Period">
              {DAYS_OPTIONS.map(d => (
                <button key={d} onClick={() => { setDays(d); setRangeMode(d); }} aria-pressed={rangeMode === d}
                  className={`px-3 py-1.5 text-xs font-semibold rounded-lg transition-all ${rangeMode === d ? "bg-white text-gray-900 shadow-sm" : "text-gray-500 hover:text-gray-700"}`}>
                  {d}d
                </button>
              ))}
              <button onClick={() => { setRangeMode("custom"); setPendingStart(""); setPendingEnd(""); }} aria-pressed={rangeMode === "custom"}
                className={`px-3 py-1.5 text-xs font-semibold rounded-lg transition-all ${rangeMode === "custom" ? "bg-white text-gray-900 shadow-sm" : "text-gray-500 hover:text-gray-700"}`}>
                Custom
              </button>
            </div>
            <button onClick={refresh} disabled={refreshing} aria-label="Refresh data" title="Refresh"
              className="w-9 h-9 flex items-center justify-center text-gray-500 bg-white border border-gray-200 rounded-xl hover:bg-gray-50 disabled:opacity-50 shadow-sm">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round" className={refreshing ? "animate-spin" : ""}>
                <polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>
              </svg>
            </button>
            <button onClick={() => setShowShortcuts(true)} title="Keyboard shortcuts (?)" aria-label="Keyboard shortcuts"
              className="hidden lg:flex w-9 h-9 items-center justify-center text-gray-400 bg-white border border-gray-200 rounded-xl hover:bg-gray-50 shadow-sm">
              <KeyboardIcon />
            </button>
            <RoleGate requires="canScan">
              <button onClick={() => setScanPanelOpen(true)} title="New scan (N)"
                className="flex items-center gap-1.5 px-4 py-2 text-sm font-bold bg-indigo-600 text-white rounded-xl hover:bg-indigo-700 active:scale-[0.98] transition-all shadow-sm shadow-indigo-200">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
                New scan
              </button>
            </RoleGate>
          </div>
        </header>

        {rangeMode === "custom" && (
          <div className="flex flex-wrap items-center gap-3 bg-white border border-gray-200 rounded-xl px-4 py-3 shadow-sm">
            <span className="text-xs font-bold text-gray-500 uppercase tracking-wider">Custom range</span>
            <label className="flex items-center gap-2 text-[10px] font-bold text-gray-400 uppercase tracking-wider">From
              <input type="date" value={pendingStart} onChange={e => setPendingStart(e.target.value)}
                className="text-sm text-gray-700 border border-gray-200 rounded-lg px-3 py-1.5 focus:outline-none focus:ring-2 focus:ring-indigo-400" />
            </label>
            <label className="flex items-center gap-2 text-[10px] font-bold text-gray-400 uppercase tracking-wider">To
              <input type="date" value={pendingEnd} onChange={e => setPendingEnd(e.target.value)}
                className="text-sm text-gray-700 border border-gray-200 rounded-lg px-3 py-1.5 focus:outline-none focus:ring-2 focus:ring-indigo-400" />
            </label>
            <div className="flex items-center gap-2 ml-auto">
              <button disabled={!pendingStart || !pendingEnd} onClick={() => { setStartDate(pendingStart); setEndDate(pendingEnd); }}
                className="px-4 py-1.5 text-sm font-bold bg-indigo-600 text-white rounded-lg disabled:opacity-40 hover:bg-indigo-700">Apply</button>
              <button onClick={() => { setRangeMode(90); setDays(90); }} className="px-3 py-1.5 text-sm font-semibold text-gray-400 hover:text-gray-600">Cancel</button>
            </div>
          </div>
        )}

        {!loading && !error && data && data.repos.length === 0 && <SetupGuide />}

        {error && !loading && (
          <div role="alert" className="flex items-center justify-between gap-3 bg-rose-50 border border-rose-200 text-rose-800 px-4 py-3 rounded-xl text-sm">
            <span><span className="font-bold">Couldn&apos;t load the dashboard.</span> {error}</span>
            <button onClick={() => setReloadKey(k => k + 1)} className="shrink-0 font-bold text-xs text-rose-600 hover:text-rose-900">Retry</button>
          </div>
        )}

        {isDeveloperView && (
          <div className="flex items-center gap-3 bg-indigo-50 border border-indigo-100 rounded-xl px-4 py-2.5 text-xs text-indigo-700">
            <span className="font-bold">My PRs</span>
            Showing repositories and files from pull requests opened by @{profile?.github_login ?? profile?.email?.split("@")[0] ?? "you"}. The Trust Score is your organisation&apos;s.
          </div>
        )}

        {/* ── 1. Trust Score ── */}
        <div className="animate-fade-up">
          <TrustHero
            score={trust && trust !== "unavailable" ? trust.score : null}
            history={trust && trust !== "unavailable" ? trust.history : []}
            demoTotal={demoTotal}
            loading={!seed && trust === null} />
        </div>

        {loading && !effectiveData && (
          <div className="space-y-5" aria-label="Loading dashboard">
            <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-3">
              {[0, 1, 2, 3, 4, 5].map(i => <div key={i} className="h-[118px] rounded-2xl bg-white border border-gray-100 animate-pulse" />)}
            </div>
            <div className="grid grid-cols-1 xl:grid-cols-3 gap-5">
              <div className="section-card h-72 animate-pulse xl:col-span-2" />
              <div className="section-card h-72 animate-pulse" />
            </div>
          </div>
        )}

        {effectiveData && hasData && (
          <>
            {/* ── 2. Headline numbers ── */}
            <div className="animate-fade-up"><KpiStrip kpis={kpis} /></div>

            {/* ── 3. Risk + review queue ── */}
            <div className="animate-fade-up grid grid-cols-1 xl:grid-cols-3 gap-5 items-stretch">
              <div className="xl:col-span-2 min-w-0"><RiskPanel data={effectiveData} periodLabel={periodLabel} /></div>
              <ReviewQueue items={queue} />
            </div>

            {/* ── 4. Governance ── */}
            <div className={`animate-fade-up grid grid-cols-1 md:grid-cols-2 gap-5 ${isDeveloperView ? "" : "xl:grid-cols-3"}`}>
              <ShadowAiPanel summary={seed ? "unavailable" : shadow} />
              <SecretsPanel counts={secretCounts} />
              {!isDeveloperView && <EvidencePanel overview={seed ? "unavailable" : evidence} />}
            </div>

            {/* ── 5. Repositories + activity ── */}
            <div className="animate-fade-up grid grid-cols-1 xl:grid-cols-3 gap-5 items-start">
              <div className="xl:col-span-2 min-w-0">
                <RepoTable rows={repoRows} onExport={permissions.canExportData ? exportCSV : undefined} />
              </div>
              <ActivityList events={displayActivity} />
            </div>
          </>
        )}
      </div>

      <NewScanPanel open={scanPanelOpen} onClose={() => setScanPanelOpen(false)} />
      {showShortcuts && <ShortcutsToast onClose={() => setShowShortcuts(false)} />}
    </AuthGuard>
  );
}
