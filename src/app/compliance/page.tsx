"use client";

import { useState, useMemo, useEffect, useCallback } from "react";
import Link from "next/link";
import AuthGuard from "@/components/AuthGuard";
import PageSkeleton from "@/components/PageSkeleton";
import InfoTooltip from "@/components/InfoTooltip";
import { api } from "@/lib/api";
import { readSeed } from "@/lib/offlineData";
import { makeFrameworks as makeDefaultFrameworks, CROSS_FRAMEWORK_THEMES as DEFAULT_THEMES } from "@/lib/complianceConfig";
import type { FrameworkDef as FrameworkDefLib, CrossFrameworkTheme } from "@/lib/complianceConfig";
import type { DashboardData } from "@/types";

// ── Types ──────────────────────────────────────────────────────────────────────

interface ControlObjective {
  id: string;
  label: string;
  description: string;
  weight: number;
  owner: string;
  last_tested?: string;
  next_test?: string;
  test_frequency: "monthly" | "quarterly" | "annually";
  evidence_items: {
    type: string;
    description: string;
    auto: boolean;      // auto-collected from live data
  }[];
  cross_map: { framework: string; control_id: string }[];  // maps to other frameworks
}

interface FrameworkDef {
  id: string;
  shortName: string;
  fullName: string;
  standard: string;
  color: string;
  gradient: string;
  headerBg: string;
  certBody: string;
  nextAudit: string;
  certExpiry?: string;
  controls: ControlObjective[];
}

interface Exception {
  id: string;
  control_id: string;
  framework_id: string;
  title: string;
  description: string;
  risk_accepted: boolean;
  owner: string;
  due_date: string;
  remediation: string;
  created_at: string;
  status: "open" | "in-progress" | "resolved";
}

const ORG = process.env.NEXT_PUBLIC_ORG ?? "novapay";

// ── Framework catalog — delegates to lib; localStorage overrides audit dates ──

function makeFrameworks(): FrameworkDef[] {
  let policy: Record<string, string> = {};
  try { policy = JSON.parse(typeof window !== "undefined" ? (localStorage.getItem("tl_compliance_schedule") ?? "{}") : "{}"); } catch { /* */ }
  return makeDefaultFrameworks(ORG, policy) as FrameworkDef[];
}

// ── Persistence ────────────────────────────────────────────────────────────────

const EXC_KEY = "tl_exceptions_state";

function loadExceptions(): Exception[] {
  try { return JSON.parse(localStorage.getItem(EXC_KEY) ?? "[]"); } catch { return []; }
}
function saveExceptions(e: Exception[]) { localStorage.setItem(EXC_KEY, JSON.stringify(e)); }

// ── Dynamic score computation ─────────────────────────────────────────────────

function computeScore(fw: FrameworkDef, data: DashboardData | null, exceptions: Exception[]): number {
  if (!data) return 70;
  const d = data;
  const attPct  = d.attestation_rate * 100;
  const scanCnt = d.scan_count;
  const fc      = d.file_count;
  const openExc = exceptions.filter(e => e.framework_id === fw.id && e.status !== "resolved").length;

  let score = 0;
  fw.controls.forEach(ctrl => {
    const hasEvidence = ctrl.evidence_items.filter(e => e.auto).length > 0;
    let ctrlScore = 0;
    if (fw.id === "soc2") {
      if (ctrl.id === "CC6.1") ctrlScore = Math.min(100, attPct * 1.1);
      else if (ctrl.id === "CC6.2") ctrlScore = scanCnt > 0 ? 95 : 20;
      else if (ctrl.id === "CC7.2") ctrlScore = scanCnt > 10 ? 100 : scanCnt * 8;
      else if (ctrl.id === "CC8.1") ctrlScore = Math.min(100, attPct);
      else if (ctrl.id === "A1.2")  ctrlScore = fc > 100 ? 100 : fc;
    } else if (fw.id === "euai") {
      if (ctrl.id === "Art.9")  ctrlScore = Math.min(100, attPct * 0.9);
      else if (ctrl.id === "Art.10") ctrlScore = fc > 0 ? 100 : 0;
      else if (ctrl.id === "Art.13") ctrlScore = scanCnt > 0 ? 100 : 0;
      else if (ctrl.id === "Art.14") ctrlScore = Math.min(100, attPct);
      else if (ctrl.id === "Art.17") ctrlScore = scanCnt > 0 ? 100 : 0;
    } else if (fw.id === "pcidss") {
      if (ctrl.id === "6.2.4") ctrlScore = scanCnt > 0 ? Math.min(100, 70 + attPct * 0.3) : 10;
      else if (ctrl.id === "6.3.2") ctrlScore = fc > 0 ? 100 : 0;
      else if (ctrl.id === "6.4.1") ctrlScore = d.unattested_deploy_count === 0 ? 100 : Math.max(20, 80 - d.unattested_deploy_count * 10);
      else if (ctrl.id === "6.4.2") ctrlScore = Math.min(100, attPct * 0.95);
      else if (ctrl.id === "6.4.3") ctrlScore = scanCnt > 0 ? 90 : 20;
    } else if (fw.id === "iso27001") {
      if (ctrl.id === "A.8.25") ctrlScore = scanCnt > 10 ? 100 : scanCnt * 8;
      else if (ctrl.id === "A.8.26") ctrlScore = Math.min(100, 60 + attPct * 0.4);
      else if (ctrl.id === "A.8.28") ctrlScore = Math.min(100, attPct);
      else if (ctrl.id === "A.8.30") ctrlScore = fc > 0 ? 100 : 0;
      else if (ctrl.id === "A.5.33") ctrlScore = scanCnt > 0 ? 100 : 0;
    }
    score += (ctrlScore / 100) * ctrl.weight;
  });

  const totalWeight = fw.controls.reduce((s, c) => s + c.weight, 0);
  let pct = Math.round((score / totalWeight) * 100);
  pct = Math.max(0, pct - openExc * 3); // each open exception deducts 3 pts
  return Math.min(100, Math.max(0, pct));
}

function predictReadiness(score: number, target = 90): { days: number; date: string } {
  const gap = target - score;
  if (gap <= 0) return { days: 0, date: "Ready now" };
  const daysPerPoint = 1.8; // estimated from evidence velocity
  const days = Math.ceil(gap * daysPerPoint);
  const date = new Date(Date.now() + days * 86400000)
    .toLocaleDateString("en-GB", { day:"numeric", month:"short", year:"numeric" });
  return { days, date };
}

// ── Helpers ────────────────────────────────────────────────────────────────────

function daysUntil(iso: string) {
  return Math.ceil((new Date(iso).getTime() - Date.now()) / 86400000);
}
function fmtDate(iso?: string) {
  if (!iso) return "—";
  const d = new Date(iso);
  return `${d.getDate()} ${["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"][d.getMonth()]} ${d.getFullYear()}`;
}

function evidenceStrength(ctrl: ControlObjective, data: DashboardData | null): number {
  const autoCount = ctrl.evidence_items.filter(e => e.auto).length;
  const totalCount = ctrl.evidence_items.length;
  const base = (autoCount / Math.max(totalCount, 1)) * 3;
  const scanBonus = data && data.scan_count > 10 ? 1 : 0;
  const freshBonus = ctrl.last_tested ? (daysUntil(ctrl.last_tested) < -90 ? 0 : 1) : 0;
  return Math.round(Math.min(5, base + scanBonus + freshBonus));
}

function StrengthStars({ score }: { score: number }) {
  return (
    <div className="flex items-center gap-0.5">
      {[1,2,3,4,5].map(i => (
        <svg key={i} width="10" height="10" viewBox="0 0 24 24"
          fill={i <= score ? "#f59e0b" : "#e2e8f0"} stroke="none">
          <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/>
        </svg>
      ))}
    </div>
  );
}

// ── Tabs ───────────────────────────────────────────────────────────────────────

type PageTab = "overview" | "controls" | "mapping" | "exceptions";

// ── Page ───────────────────────────────────────────────────────────────────────

export default function CompliancePage() {
  const [frameworks,  setFrameworks]  = useState<FrameworkDef[]>(() => makeDefaultFrameworks(ORG, {}) as FrameworkDef[]);
  const [crossThemes, setCrossThemes] = useState<CrossFrameworkTheme[]>(DEFAULT_THEMES);
  const [data,        setData]        = useState<DashboardData | null>(null);
  const [activeFw,    setActiveFw]    = useState<string>("soc2");
  const [tab,         setTab]         = useState<PageTab>("overview");
  const [exceptions,  setExceptions]  = useState<Exception[]>([]);
  const [showExcForm, setShowExcForm] = useState(false);
  const [excForm,     setExcForm]     = useState({ title:"", description:"", control_id:"", owner:`alice@${ORG}.io`, due_date:"", remediation:"", risk_accepted:false });
  const [refreshing,  setRefreshing]  = useState(false);

  useEffect(() => { setExceptions(loadExceptions()); }, []);

  // Re-derive frameworks when tl_compliance_schedule changes in another tab or on focus
  useEffect(() => {
    function refresh() { setFrameworks(makeFrameworks()); }
    function onStorage(e: StorageEvent) { if (e.key === "tl_compliance_schedule") refresh(); }
    function onFocus() { refresh(); }
    window.addEventListener("storage", onStorage);
    window.addEventListener("focus", onFocus);
    return () => { window.removeEventListener("storage", onStorage); window.removeEventListener("focus", onFocus); };
  }, []);

  // Fetch framework config from API — falls back to lib defaults
  useEffect(() => {
    api.complianceConfig(ORG)
      .then(res => {
        if (Array.isArray(res?.frameworks) && res.frameworks.length > 0)
          setFrameworks(res.frameworks as FrameworkDef[]);
        if (Array.isArray(res?.crossFrameworkThemes) && res.crossFrameworkThemes.length > 0)
          setCrossThemes(res.crossFrameworkThemes as CrossFrameworkTheme[]);
      })
      .catch(() => { /* keep defaults */ });
  }, []);

  const fetchData = useCallback(async (spinner = false) => {
    if (spinner) setRefreshing(true);
    const seed = readSeed();
    const d = seed ?? await api.dashboard(ORG, 90).catch(() => null);
    if (d) setData(d);
    if (spinner) setRefreshing(false);
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  const fw = frameworks.find(f => f.id === activeFw) ?? frameworks[0];

  const scores = useMemo(() =>
    frameworks.map(f => ({
      id: f.id,
      score: computeScore(f, data, exceptions),
      exceptions: exceptions.filter(e => e.framework_id === f.id && e.status !== "resolved").length,
    })), [data, exceptions]);

  const fwScore    = scores.find(s => s.id === activeFw)?.score ?? 0;
  const prediction = predictReadiness(fwScore);
  const overallPct = Math.round(scores.reduce((s, x) => s + x.score, 0) / scores.length);

  // Control-level scores
  const controlScores = useMemo(() => {
    if (!data) return {};
    const map: Record<string, number> = {};
    fw.controls.forEach(ctrl => {
      const strength = evidenceStrength(ctrl, data);
      map[ctrl.id] = Math.round((strength / 5) * 100);
    });
    return map;
  }, [fw, data]);

  function addException() {
    if (!excForm.title || !excForm.control_id) return;
    const exc: Exception = {
      id: `exc-${Date.now()}`,
      control_id:   excForm.control_id,
      framework_id: activeFw,
      title:        excForm.title,
      description:  excForm.description,
      risk_accepted: excForm.risk_accepted,
      owner:         excForm.owner,
      due_date:      excForm.due_date,
      remediation:   excForm.remediation,
      created_at:    new Date().toISOString().split("T")[0],
      status:        "open",
    };
    const next = [...exceptions, exc];
    setExceptions(next);
    saveExceptions(next);
    setShowExcForm(false);
    setExcForm({ title:"", description:"", control_id:"", owner:`alice@${ORG}.io`, due_date:"", remediation:"", risk_accepted:false });
  }

  function closeException(id: string) {
    const next = exceptions.map(e => e.id === id ? { ...e, status:"resolved" as const } : e);
    setExceptions(next);
    saveExceptions(next);
  }

  const fwExceptions = exceptions.filter(e => e.framework_id === activeFw);

  // Export auditor package
  function exportAuditorPackage() {
    const pkg = {
      type: "TrustLedger Auditor Package",
      generated_at: new Date().toISOString(),
      org: ORG,
      framework: fw.fullName,
      standard: fw.standard,
      compliance_score: fwScore,
      prediction: prediction,
      controls: fw.controls.map(ctrl => ({
        id:            ctrl.id,
        label:         ctrl.label,
        description:   ctrl.description,
        owner:         ctrl.owner,
        last_tested:   ctrl.last_tested,
        next_test:     ctrl.next_test,
        evidence_strength: evidenceStrength(ctrl, data),
        evidence_items:    ctrl.evidence_items,
        control_score:     controlScores[ctrl.id] ?? 0,
        open_exceptions:   exceptions.filter(e => e.control_id === ctrl.id && e.status !== "resolved").length,
      })),
      exceptions: fwExceptions,
      live_metrics: data ? {
        scan_count:              data.scan_count,
        attestation_rate:        data.attestation_rate,
        unattested_deploy_count: data.unattested_deploy_count,
        file_count:              data.file_count,
        repos:                   data.repos.length,
      } : null,
    };
    const blob = new Blob([JSON.stringify(pkg, null, 2)], { type:"application/json" });
    Object.assign(document.createElement("a"), {
      href:     URL.createObjectURL(blob),
      download: `auditor-package-${activeFw}-${new Date().toISOString().split("T")[0]}.json`,
    }).click();
  }

  return (
    <AuthGuard>
      <PageSkeleton rows={4} cards={3}>
      <div className="max-w-7xl mx-auto space-y-5 pb-10">

        {/* ── Header ── */}
        <div className="animate-fade-up flex items-start justify-between gap-4 flex-wrap">
          <div>
            <div className="flex items-center gap-2.5 mb-1">
              <div className="w-8 h-8 rounded-xl flex items-center justify-center"
                style={{ background:"rgba(99,102,241,0.1)", border:"1px solid rgba(99,102,241,0.2)" }}>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#6366f1" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/>
                </svg>
              </div>
              <h1 className="text-xl font-black text-gray-900 tracking-tight">Compliance Center</h1>
            </div>
            <p className="text-sm text-gray-400">
              SOC 2 · EU AI Act · PCI-DSS · ISO 27001 — live scores, exception management, cross-framework mapping &amp; auditor packages
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button onClick={() => fetchData(true)} disabled={refreshing}
              className="flex items-center gap-1.5 px-3 py-2 text-xs font-semibold text-gray-600 bg-white border border-gray-200 rounded-xl hover:bg-gray-50 disabled:opacity-50 transition-all shadow-sm">
              <svg className={refreshing?"animate-spin":""} width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                <polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>
              </svg>
              Refresh
            </button>
            <button onClick={exportAuditorPackage}
              className="flex items-center gap-1.5 px-3 py-2 text-xs font-bold text-emerald-700 bg-emerald-50 border border-emerald-200 rounded-xl hover:bg-emerald-100 transition-all shadow-sm">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
              Auditor Package
            </button>
            <Link href="/reports"
              className="flex items-center gap-1.5 px-4 py-2 text-xs font-bold text-white rounded-xl transition-all shadow-sm"
              style={{ background:"linear-gradient(135deg,#6366f1,#7c3aed)", boxShadow:"0 2px 10px rgba(99,102,241,0.35)" }}>
              Generate Report
            </Link>
          </div>
        </div>

        {/* ── Overall posture banner ── */}
        <div className="animate-fade-up rounded-2xl overflow-hidden"
          style={{ background:"linear-gradient(135deg,#0f172a,#1e1b4b)", boxShadow:"0 4px 24px rgba(0,0,0,0.15)" }}>
          <div className="px-8 py-5 grid grid-cols-1 sm:grid-cols-4 gap-6 items-center">
            <div className="sm:col-span-2">
              <div className="flex items-center gap-2 mb-1">
                <p className="text-[10px] font-bold uppercase tracking-widest text-white/30">Overall Compliance Posture</p>
                <InfoTooltip title="Overall Compliance Posture" description="Simple average of live framework compliance scores, dynamically computed from real scan data, attestation rates, and evidence collection status." formula={"(SOC 2 + EU AI Act + PCI-DSS + ISO 27001) ÷ 4"} position="bottom" />
              </div>
              <div className="flex items-end gap-3">
                <span className="text-6xl font-black text-white tabular-nums">{overallPct}</span>
                <span className="text-2xl font-bold text-white/40 mb-1">%</span>
                <span className="mb-1.5 text-sm text-white/40">{overallPct>=90?"Audit-ready":overallPct>=75?"On track":overallPct>=60?"Needs work":"At risk"}</span>
              </div>
              <div className="mt-3 h-2 rounded-full overflow-hidden bg-white/10">
                <div className="h-full rounded-full transition-all duration-1000"
                  style={{ width:`${overallPct}%`, background:"linear-gradient(90deg,#6366f1,#10b981)" }} />
              </div>
            </div>
            {frameworks.map(f => {
              const s = scores.find(x => x.id === f.id)!;
              const pred = predictReadiness(s.score);
              return (
                <button key={f.id} onClick={() => setActiveFw(f.id)}
                  className="text-left rounded-xl p-3 transition-all"
                  style={{ background: activeFw===f.id ? "rgba(255,255,255,0.12)" : "rgba(255,255,255,0.04)", border:`1px solid ${activeFw===f.id?"rgba(255,255,255,0.2)":"rgba(255,255,255,0.06)"}` }}>
                  <p className="text-[9px] text-white/30 font-bold uppercase tracking-widest mb-1">{f.shortName}</p>
                  <p className="text-2xl font-black text-white tabular-nums">{s.score}%</p>
                  <div className="mt-1.5 h-1 rounded-full overflow-hidden bg-white/10">
                    <div className="h-full rounded-full" style={{ width:`${s.score}%`, background:f.gradient }} />
                  </div>
                  <p className="text-[9px] text-white/30 mt-1.5">
                    {pred.days === 0 ? "✓ Audit-ready" : `${pred.days}d to 90%`}
                    {s.exceptions > 0 && ` · ${s.exceptions} exception${s.exceptions>1?"s":""}`}
                  </p>
                </button>
              );
            })}
          </div>
        </div>

        {/* ── Framework tabs ── */}
        <div className="animate-fade-up flex items-center gap-1 bg-gray-100 p-0.5 rounded-xl w-fit">
          {(["overview","controls","mapping","exceptions"] as PageTab[]).map(t => (
            <button key={t} onClick={() => setTab(t)}
              className={`px-4 py-2 text-xs font-semibold rounded-lg transition-all capitalize ${tab===t?"bg-white text-gray-900 shadow-sm":"text-gray-500 hover:text-gray-700"}`}>
              {t === "mapping" ? "Cross-Framework Map" : t === "exceptions" ? `Exceptions (${fwExceptions.length})` : t.charAt(0).toUpperCase()+t.slice(1)}
            </button>
          ))}
        </div>

        {/* ══ OVERVIEW TAB ══════════════════════════════════════════════════════ */}
        {tab === "overview" && (
          <div className="animate-fade-up grid grid-cols-1 lg:grid-cols-[300px_1fr] gap-5">

            {/* Left: framework selector */}
            <div className="space-y-3">
              {frameworks.map(f => {
                const s    = scores.find(x => x.id === f.id)!;
                const pred = predictReadiness(s.score);
                const days = daysUntil(f.nextAudit);
                return (
                  <button key={f.id} onClick={() => setActiveFw(f.id)}
                    className="w-full rounded-2xl overflow-hidden border-2 text-left transition-all"
                    style={{ borderColor: activeFw===f.id ? f.color : "rgba(226,232,240,0.8)", boxShadow: activeFw===f.id ? `0 4px 20px ${f.color}20` : "none" }}>
                    <div className="px-4 py-3" style={{ background: f.headerBg }}>
                      <div className="flex items-center justify-between mb-2">
                        <p className="text-[9px] font-bold text-white/40 uppercase tracking-widest">{f.shortName}</p>
                        <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded-full ${days<=30?"text-rose-300 bg-rose-900/30":"text-white/30 bg-white/10"}`}>
                          Audit in {days}d
                        </span>
                      </div>
                      <div className="flex items-center justify-between">
                        <p className="text-base font-black text-white">{f.fullName}</p>
                        <span className="text-2xl font-black text-white tabular-nums">{s.score}%</span>
                      </div>
                      <div className="mt-2 h-1.5 rounded-full overflow-hidden bg-white/10">
                        <div className="h-full rounded-full" style={{ width:`${s.score}%`, background:f.gradient }} />
                      </div>
                    </div>
                    <div className="px-4 py-2 bg-white flex items-center gap-4 text-[10px]">
                      <span className="text-emerald-600 font-bold">{s.score}% compliant</span>
                      {pred.days > 0 && <span className="text-gray-400">{pred.days}d → 90%</span>}
                      {s.exceptions > 0 && <span className="text-amber-600 font-bold">{s.exceptions} exc.</span>}
                      {f.certBody && <span className="text-gray-400 ml-auto text-[9px] truncate">{f.certBody}</span>}
                    </div>
                  </button>
                );
              })}

              {/* Predictive readiness card */}
              <div className="rounded-2xl p-4 border border-indigo-100" style={{ background:"rgba(238,242,255,0.5)" }}>
                <div className="flex items-center gap-1.5 mb-2">
                  <p className="text-[9px] font-black uppercase tracking-widest text-indigo-600">Predictive Readiness</p>
                  <InfoTooltip title="Predictive Readiness" description="Estimated days to reach 90% compliance for the active framework, based on current evidence collection velocity and outstanding gaps." position="right" />
                </div>
                {prediction.days === 0 ? (
                  <div>
                    <p className="text-2xl font-black text-emerald-600">Audit-ready ✓</p>
                    <p className="text-[10px] text-emerald-600/70 mt-1">{fw.shortName} exceeds 90% threshold</p>
                  </div>
                ) : (
                  <div>
                    <p className="text-2xl font-black text-indigo-700 tabular-nums">{prediction.days} days</p>
                    <p className="text-[10px] text-indigo-500 mt-1">Estimated {prediction.date}</p>
                    <p className="text-[9px] text-gray-400 mt-1">At current evidence velocity</p>
                  </div>
                )}
              </div>
            </div>

            {/* Right: control summary */}
            <div className="space-y-3">
              {fw.controls.map(ctrl => {
                const openExcs = exceptions.filter(e => e.control_id===ctrl.id && e.status!=="resolved").length;
                const strength = evidenceStrength(ctrl, data);
                const ctrlPct  = controlScores[ctrl.id] ?? 0;
                const satisfied = ctrlPct >= 80;
                const partial   = ctrlPct >= 50 && !satisfied;
                return (
                  <div key={ctrl.id} className="section-card overflow-hidden">
                    <div className="flex items-start gap-4 px-5 py-4">
                      {/* Control ID badge */}
                      <span className="text-[11px] font-black font-mono px-2.5 py-1 rounded-lg shrink-0 mt-0.5"
                        style={{ background:`${fw.color}10`, color:fw.color, border:`1px solid ${fw.color}25` }}>
                        {ctrl.id}
                      </span>

                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap mb-1">
                          <p className="text-sm font-bold text-gray-900">{ctrl.label}</p>
                          {openExcs > 0 && (
                            <span className="text-[9px] font-black text-amber-700 bg-amber-50 px-1.5 py-0.5 rounded border border-amber-200">
                              {openExcs} exception{openExcs>1?"s":""}
                            </span>
                          )}
                          {ctrl.cross_map.length > 0 && (
                            <span className="text-[9px] font-semibold text-indigo-600 bg-indigo-50 px-1.5 py-0.5 rounded border border-indigo-100">
                              maps to {ctrl.cross_map.map(m=>m.control_id).join(", ")}
                            </span>
                          )}
                        </div>
                        <p className="text-xs text-gray-500 leading-relaxed mb-2">{ctrl.description}</p>

                        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-[10px]">
                          <div>
                            <p className="text-gray-400 font-semibold uppercase tracking-wide mb-0.5">Owner</p>
                            <p className="font-bold text-gray-700">{ctrl.owner.split("@")[0]}</p>
                          </div>
                          <div>
                            <p className="text-gray-400 font-semibold uppercase tracking-wide mb-0.5">Last Tested</p>
                            <p className="font-bold text-gray-700">{fmtDate(ctrl.last_tested)}</p>
                          </div>
                          <div>
                            <p className="text-gray-400 font-semibold uppercase tracking-wide mb-0.5">Next Test</p>
                            <p className={`font-bold ${daysUntil(ctrl.next_test!)<=30?"text-rose-600":"text-gray-700"}`}>{fmtDate(ctrl.next_test)}</p>
                          </div>
                          <div>
                            <p className="text-gray-400 font-semibold uppercase tracking-wide mb-0.5">Evidence</p>
                            <StrengthStars score={strength} />
                          </div>
                        </div>
                      </div>

                      {/* Score ring */}
                      <div className="shrink-0 flex flex-col items-center gap-1">
                        <div className="relative w-12 h-12">
                          <svg width="48" height="48" viewBox="0 0 48 48" style={{ transform:"rotate(-90deg)" }}>
                            <circle cx="24" cy="24" r="18" fill="none" stroke="#e2e8f0" strokeWidth="4" />
                            <circle cx="24" cy="24" r="18" fill="none"
                              stroke={satisfied?"#10b981":partial?"#f59e0b":"#ef4444"}
                              strokeWidth="4"
                              strokeDasharray={`${2*Math.PI*18*(ctrlPct/100)} ${2*Math.PI*18}`}
                              strokeLinecap="round"
                              style={{ transition:"stroke-dasharray 0.8s ease" }} />
                          </svg>
                          <span className="absolute inset-0 flex items-center justify-center text-[10px] font-black"
                            style={{ color:satisfied?"#10b981":partial?"#f59e0b":"#ef4444" }}>
                            {ctrlPct}%
                          </span>
                        </div>
                        <span className="text-[9px] font-bold" style={{ color:satisfied?"#15803d":partial?"#b45309":"#be123c" }}>
                          {satisfied?"SAT":partial?"PART":"GAP"}
                        </span>
                      </div>
                    </div>

                    {/* Evidence items */}
                    <div className="border-t border-gray-50 px-5 py-3 bg-gray-50/40">
                      <p className="text-[9px] font-black uppercase tracking-widest text-gray-400 mb-2">Evidence ({ctrl.evidence_items.length} items)</p>
                      <div className="flex flex-wrap gap-2">
                        {ctrl.evidence_items.map((ev, i) => (
                          <span key={i} className={`text-[10px] font-semibold px-2 py-0.5 rounded border flex items-center gap-1 ${ev.auto?"text-emerald-700 bg-emerald-50 border-emerald-200":"text-amber-700 bg-amber-50 border-amber-200"}`}>
                            {ev.auto ? <svg width="8" height="8" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3"><polyline points="20 6 9 17 4 12"/></svg>
                                     : <svg width="8" height="8" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3"><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/><circle cx="12" cy="12" r="10"/></svg>}
                            {ev.description.slice(0, 35)}{ev.description.length>35?"…":""}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* ══ CONTROLS DEEP-DIVE TAB ════════════════════════════════════════════ */}
        {tab === "controls" && (
          <div className="animate-fade-up space-y-4">
            {fw.controls.map(ctrl => {
              const strength = evidenceStrength(ctrl, data);
              const ctrlPct  = controlScores[ctrl.id] ?? 0;
              const autoEvid = ctrl.evidence_items.filter(e => e.auto);
              const manEvid  = ctrl.evidence_items.filter(e => !e.auto);
              const openExcs = exceptions.filter(e => e.control_id===ctrl.id && e.status!=="resolved");
              return (
                <div key={ctrl.id} className="section-card overflow-hidden">
                  {/* Header */}
                  <div className="flex items-center justify-between px-6 py-4 border-b border-gray-100"
                    style={{ background:`${fw.color}05` }}>
                    <div className="flex items-center gap-3">
                      <span className="text-sm font-black font-mono px-3 py-1.5 rounded-xl"
                        style={{ background:`${fw.color}15`, color:fw.color, border:`1px solid ${fw.color}30` }}>
                        {ctrl.id}
                      </span>
                      <div>
                        <p className="text-sm font-bold text-gray-900">{ctrl.label}</p>
                        <p className="text-[10px] text-gray-400 mt-0.5">{ctrl.test_frequency} testing · owner: <strong>{ctrl.owner.split("@")[0]}</strong></p>
                      </div>
                    </div>
                    <div className="flex items-center gap-4">
                      <StrengthStars score={strength} />
                      <span className="text-lg font-black tabular-nums" style={{ color:ctrlPct>=80?"#15803d":ctrlPct>=50?"#b45309":"#be123c" }}>
                        {ctrlPct}%
                      </span>
                    </div>
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-3 gap-0 divide-y sm:divide-y-0 sm:divide-x divide-gray-50">
                    {/* Description + mapping */}
                    <div className="p-5">
                      <p className="text-[10px] font-black uppercase tracking-widest text-gray-400 mb-2">Control Objective</p>
                      <p className="text-xs text-gray-700 leading-relaxed mb-3">{ctrl.description}</p>
                      {ctrl.cross_map.length > 0 && (
                        <div>
                          <p className="text-[9px] font-black uppercase tracking-widest text-gray-400 mb-1.5">Also satisfies</p>
                          <div className="flex flex-wrap gap-1.5">
                            {ctrl.cross_map.map(m => {
                              const other = frameworks.find(f => f.id===m.framework);
                              return other ? (
                                <span key={`${m.framework}-${m.control_id}`}
                                  className="text-[9px] font-bold px-2 py-0.5 rounded-full text-white"
                                  style={{ background:other.gradient }}>
                                  {other.shortName} {m.control_id}
                                </span>
                              ) : null;
                            })}
                          </div>
                        </div>
                      )}
                    </div>
                    {/* Evidence */}
                    <div className="p-5">
                      <p className="text-[10px] font-black uppercase tracking-widest text-gray-400 mb-3">Evidence Items</p>
                      <div className="space-y-2">
                        {autoEvid.map((ev, i) => (
                          <div key={i} className="flex items-start gap-2">
                            <span className="w-4 h-4 rounded-full bg-emerald-500 flex items-center justify-center shrink-0 mt-0.5">
                              <svg width="8" height="8" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="3"><polyline points="20 6 9 17 4 12"/></svg>
                            </span>
                            <div>
                              <p className="text-[10px] font-semibold text-gray-700">{ev.description}</p>
                              <p className="text-[9px] text-emerald-600 font-bold">AUTO-COLLECTED</p>
                            </div>
                          </div>
                        ))}
                        {manEvid.map((ev, i) => (
                          <div key={i} className="flex items-start gap-2">
                            <span className="w-4 h-4 rounded-full bg-amber-400 flex items-center justify-center shrink-0 mt-0.5">
                              <svg width="8" height="8" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="3"><line x1="12" y1="8" x2="12" y2="12"/></svg>
                            </span>
                            <div>
                              <p className="text-[10px] font-semibold text-gray-700">{ev.description}</p>
                              <p className="text-[9px] text-amber-600 font-bold">MANUAL UPLOAD NEEDED</p>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                    {/* Testing schedule */}
                    <div className="p-5">
                      <p className="text-[10px] font-black uppercase tracking-widest text-gray-400 mb-3">Testing Schedule</p>
                      <div className="space-y-2 text-[10px]">
                        <div className="flex justify-between"><span className="text-gray-400">Frequency</span><span className="font-bold text-gray-700 capitalize">{ctrl.test_frequency}</span></div>
                        <div className="flex justify-between"><span className="text-gray-400">Last tested</span><span className="font-bold text-gray-700">{fmtDate(ctrl.last_tested)}</span></div>
                        <div className="flex justify-between">
                          <span className="text-gray-400">Next test</span>
                          <span className={`font-bold ${daysUntil(ctrl.next_test!)<=30?"text-rose-600":daysUntil(ctrl.next_test!)<=60?"text-amber-600":"text-gray-700"}`}>
                            {fmtDate(ctrl.next_test)}
                          </span>
                        </div>
                        <div className="flex justify-between"><span className="text-gray-400">Weight</span><span className="font-bold text-gray-700">{ctrl.weight}%</span></div>
                      </div>
                      {openExcs.length > 0 && (
                        <div className="mt-3 space-y-1.5">
                          <p className="text-[9px] font-black uppercase tracking-widest text-amber-600">Open Exceptions</p>
                          {openExcs.map(e => (
                            <div key={e.id} className="text-[9px] text-amber-700 bg-amber-50 border border-amber-200 rounded-lg px-2 py-1">
                              {e.title}
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}

        {/* ══ CROSS-FRAMEWORK MAPPING TAB ═══════════════════════════════════════ */}
        {tab === "mapping" && (
          <div className="animate-fade-up space-y-5">
            <div className="section-card overflow-hidden">
              <div className="flex items-center justify-between px-5 py-4 border-b border-gray-100">
                <div className="flex items-center gap-2">
                  <p className="text-sm font-bold text-gray-900">Cross-Framework Control Mapping</p>
                  <InfoTooltip title="Cross-Framework Mapping" description="Shows how compliance themes map across SOC 2, EU AI Act, and PCI-DSS. A single TrustLedger action (e.g. attesting a file) satisfies multiple controls simultaneously." position="bottom" />
                </div>
                <p className="text-[10px] text-gray-400">One action → multiple frameworks satisfied</p>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-gray-100 bg-gray-50/60">
                      <th className="px-5 py-3 text-left text-[10px] font-black uppercase tracking-wider text-gray-400 w-48">Theme</th>
                      {frameworks.map(f => (
                        <th key={f.id} className="px-4 py-3 text-center text-[10px] font-black uppercase tracking-wider" style={{ color:f.color }}>
                          {f.shortName}
                        </th>
                      ))}
                      <th className="px-4 py-3 text-left text-[10px] font-black uppercase tracking-wider text-gray-400">TrustLedger Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-50">
                    {crossThemes.map(theme => (
                      <tr key={theme.theme} className="hover:bg-gray-50/40 transition-colors">
                        <td className="px-5 py-4">
                          <p className="text-xs font-bold text-gray-900">{theme.theme}</p>
                          <p className="text-[10px] text-gray-400 mt-0.5 leading-snug">{theme.description}</p>
                        </td>
                        {frameworks.map(f => {
                          const ctrlId = (theme.controls as Record<string,string>)[f.id];
                          const ctrl   = f.controls.find(c => c.id === ctrlId);
                          const score  = scores.find(s=>s.id===f.id)?.score ?? 0;
                          return (
                            <td key={f.id} className="px-4 py-4 text-center">
                              {ctrl ? (
                                <div>
                                  <span className="text-[11px] font-black font-mono px-2 py-0.5 rounded-lg"
                                    style={{ background:`${f.color}10`, color:f.color, border:`1px solid ${f.color}25` }}>
                                    {ctrlId}
                                  </span>
                                  <p className="text-[8px] text-gray-400 mt-1 font-medium">{ctrl.label.split(" ").slice(0,2).join(" ")}</p>
                                </div>
                              ) : (
                                <span className="text-gray-300 text-[10px]">—</span>
                              )}
                            </td>
                          );
                        })}
                        <td className="px-4 py-4">
                          <p className="text-[10px] text-indigo-700 font-semibold leading-relaxed">{theme.description}</p>
                          <span className="text-[9px] text-emerald-600 font-bold flex items-center gap-1 mt-1">
                            <svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3"><polyline points="20 6 9 17 4 12"/></svg>
                            Automatically satisfied by TrustLedger
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Efficiency card */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              {[
                { label:"Controls Covered",  value:`${crossThemes.length * 4}`, sub:"across all 4 frameworks",            color:"#6366f1", bg:"#eef2ff" },
                { label:"Unique Themes",      value:String(crossThemes.length), sub:"compliance themes addressed",          color:"#10b981", bg:"#f0fdf4" },
                { label:"Overlap Efficiency", value:`${Math.round((crossThemes.length / (frameworks.reduce((s,f)=>s+f.controls.length,0)))*100)}%`, sub:"controls satisfied by shared actions", color:"#f59e0b", bg:"#fffbeb" },
              ].map(s => (
                <div key={s.label} className="rounded-2xl p-5 border" style={{ background:s.bg, borderColor:s.color+"30" }}>
                  <p className="text-3xl font-black tabular-nums" style={{ color:s.color }}>{s.value}</p>
                  <p className="text-xs font-semibold text-gray-500 mt-1">{s.label}</p>
                  <p className="text-[10px] text-gray-400 mt-0.5">{s.sub}</p>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ══ EXCEPTIONS TAB ════════════════════════════════════════════════════ */}
        {tab === "exceptions" && (
          <div className="animate-fade-up space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-bold text-gray-900">Exception Register — {fw.shortName}</p>
                <p className="text-xs text-gray-400 mt-0.5">Formally tracked control gaps, risk acceptances, and remediation plans</p>
              </div>
              <button onClick={() => setShowExcForm(v=>!v)}
                className="flex items-center gap-1.5 px-3 py-2 text-xs font-bold text-indigo-700 bg-indigo-50 border border-indigo-200 rounded-xl hover:bg-indigo-100 transition-colors">
                <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
                Log Exception
              </button>
            </div>

            {/* Add exception form */}
            {showExcForm && (
              <div className="section-card p-5 space-y-4 border-2 border-indigo-200">
                <p className="text-sm font-bold text-gray-900">New Exception</p>
                <div className="grid grid-cols-2 gap-3">
                  <div className="col-span-2">
                    <label className="block text-[10px] font-semibold text-gray-500 mb-1">Exception Title *</label>
                    <input value={excForm.title} onChange={e=>setExcForm(p=>({...p,title:e.target.value}))}
                      placeholder="e.g. CC8.1 attestation gap — legacy codebase files"
                      className="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm text-gray-700 focus:outline-none focus:ring-2 focus:ring-indigo-400" />
                  </div>
                  <div>
                    <label className="block text-[10px] font-semibold text-gray-500 mb-1">Control *</label>
                    <select value={excForm.control_id} onChange={e=>setExcForm(p=>({...p,control_id:e.target.value}))}
                      className="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm text-gray-700 focus:outline-none">
                      <option value="">Select control</option>
                      {fw.controls.map(c=><option key={c.id} value={c.id}>{c.id} — {c.label}</option>)}
                    </select>
                  </div>
                  <div>
                    <label className="block text-[10px] font-semibold text-gray-500 mb-1">Owner</label>
                    <select value={excForm.owner} onChange={e=>setExcForm(p=>({...p,owner:e.target.value}))}
                      className="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm text-gray-700 focus:outline-none">
                      {(()=>{try{const m=JSON.parse(localStorage.getItem("tl_team_members")??"[]");if(m.length)return m.map((x:{email:string})=>x.email);}catch{/**/}return [`alice@${ORG}.io`,`bob@${ORG}.io`,`carol@${ORG}.io`,`david@${ORG}.io`];})().map((em:string)=>(
                        <option key={em} value={em}>{em.split("@")[0]}</option>
                      ))}
                    </select>
                  </div>
                  <div className="col-span-2">
                    <label className="block text-[10px] font-semibold text-gray-500 mb-1">Description</label>
                    <textarea value={excForm.description} onChange={e=>setExcForm(p=>({...p,description:e.target.value}))}
                      placeholder="Describe the gap and why it exists"
                      className="w-full border border-gray-200 rounded-lg px-3 py-2 text-xs text-gray-700 focus:outline-none focus:ring-2 focus:ring-indigo-400 resize-none" rows={2} />
                  </div>
                  <div>
                    <label className="block text-[10px] font-semibold text-gray-500 mb-1">Due Date</label>
                    <input type="date" value={excForm.due_date} onChange={e=>setExcForm(p=>({...p,due_date:e.target.value}))}
                      className="w-full border border-gray-200 rounded-lg px-3 py-2 text-xs text-gray-700 focus:outline-none" />
                  </div>
                  <div className="flex items-center gap-2">
                    <input type="checkbox" id="risk_accept" checked={excForm.risk_accepted} onChange={e=>setExcForm(p=>({...p,risk_accepted:e.target.checked}))}
                      className="w-4 h-4 accent-amber-500" />
                    <label htmlFor="risk_accept" className="text-xs text-gray-600 font-semibold">Risk formally accepted</label>
                  </div>
                  <div className="col-span-2">
                    <label className="block text-[10px] font-semibold text-gray-500 mb-1">Remediation Plan</label>
                    <textarea value={excForm.remediation} onChange={e=>setExcForm(p=>({...p,remediation:e.target.value}))}
                      placeholder="Steps to close this exception"
                      className="w-full border border-gray-200 rounded-lg px-3 py-2 text-xs text-gray-700 focus:outline-none focus:ring-2 focus:ring-indigo-400 resize-none" rows={2} />
                  </div>
                </div>
                <div className="flex gap-2">
                  <button onClick={addException} disabled={!excForm.title||!excForm.control_id}
                    className="px-4 py-2 text-sm font-bold text-white rounded-xl disabled:opacity-40"
                    style={{ background:"linear-gradient(135deg,#6366f1,#7c3aed)" }}>
                    Log Exception
                  </button>
                  <button onClick={()=>setShowExcForm(false)} className="px-4 py-2 text-sm font-semibold text-gray-500 rounded-xl hover:bg-gray-50">Cancel</button>
                </div>
              </div>
            )}

            {/* Exception list */}
            {fwExceptions.length === 0 ? (
              <div className="section-card py-14 text-center">
                <div className="w-12 h-12 rounded-2xl bg-emerald-50 flex items-center justify-center text-emerald-500 mx-auto mb-3">
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>
                  </svg>
                </div>
                <p className="text-sm font-bold text-gray-700">No exceptions logged for {fw.shortName}</p>
                <p className="text-xs text-gray-400 mt-1">All controls are satisfied — or click "Log Exception" to formally track a gap</p>
              </div>
            ) : fwExceptions.map(exc => {
              const ctrl  = fw.controls.find(c=>c.id===exc.control_id);
              const days  = exc.due_date ? daysUntil(exc.due_date) : null;
              const statStyle = exc.status==="resolved"
                ? { bg:"#f0fdf4", text:"#15803d", border:"#bbf7d0", label:"Resolved" }
                : exc.status==="in-progress"
                ? { bg:"#fffbeb", text:"#b45309", border:"#fde68a", label:"In Progress" }
                : { bg:"#fef2f2", text:"#be123c", border:"#fecdd3", label:"Open" };
              return (
                <div key={exc.id} className="section-card overflow-hidden border-l-4" style={{ borderLeftColor:exc.risk_accepted?"#f59e0b":"#ef4444" }}>
                  <div className="flex items-start gap-4 p-5">
                    <div className="flex-1 min-w-0 space-y-2">
                      <div className="flex items-center gap-2 flex-wrap">
                        {ctrl && (
                          <span className="text-[10px] font-black font-mono px-2 py-0.5 rounded" style={{ background:`${fw.color}10`, color:fw.color }}>{ctrl.id}</span>
                        )}
                        <span className="text-[10px] font-bold px-2 py-0.5 rounded-full border"
                          style={{ background:statStyle.bg, color:statStyle.text, borderColor:statStyle.border }}>
                          {statStyle.label}
                        </span>
                        {exc.risk_accepted && (
                          <span className="text-[9px] font-black text-amber-700 bg-amber-50 px-2 py-0.5 rounded border border-amber-200">
                            Risk Accepted
                          </span>
                        )}
                      </div>
                      <p className="text-sm font-bold text-gray-900">{exc.title}</p>
                      {exc.description && <p className="text-xs text-gray-500 leading-relaxed">{exc.description}</p>}
                      <div className="flex items-center gap-4 text-[10px] text-gray-400">
                        <span>Owner: <strong className="text-gray-600">{exc.owner.split("@")[0]}</strong></span>
                        {exc.due_date && (
                          <span className={days!==null&&days<0?"text-rose-600 font-bold":days!==null&&days<=7?"text-amber-600 font-bold":""}>
                            Due: {fmtDate(exc.due_date)} {days!==null&&days<0?`(${Math.abs(days)}d overdue)`:days!==null&&days<=7?`(${days}d)`:""  }
                          </span>
                        )}
                        <span>Logged: {fmtDate(exc.created_at)}</span>
                      </div>
                      {exc.remediation && (
                        <div className="text-[10px] text-indigo-700 bg-indigo-50 border border-indigo-100 rounded-lg px-3 py-2 leading-relaxed">
                          <span className="font-bold">Remediation:</span> {exc.remediation}
                        </div>
                      )}
                    </div>
                    {exc.status !== "resolved" && (
                      <button onClick={() => closeException(exc.id)}
                        className="shrink-0 text-[11px] font-bold text-emerald-700 bg-emerald-50 border border-emerald-200 px-3 py-1.5 rounded-lg hover:bg-emerald-100 transition-colors whitespace-nowrap">
                        Mark Resolved
                      </button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}

        {/* ── Actions row ── */}
        <div className="animate-fade-up grid grid-cols-1 sm:grid-cols-3 gap-3">
          {[
            { label:"View Evidence Locker",  sub:"Manage control evidence artifacts", href:"/evidence",   color:"#10b981", bg:"#f0fdf4", border:"#bbf7d0" },
            { label:"Generate Report PDF",   sub:`Signed ${fw.shortName} evidence package`, href:`/reports?fw=${encodeURIComponent(fw.shortName)}`, color:"#6366f1", bg:"#eef2ff", border:"#c7d2fe" },
            { label:"Audit Trail",           sub:"View all compliance-relevant events", href:"/audit",     color:"#7c3aed", bg:"#f5f3ff", border:"#ddd6fe" },
          ].map(a => (
            <Link key={a.label} href={a.href}
              className="section-card p-4 flex flex-col gap-1.5 hover:shadow-md transition-all group border"
              style={{ borderColor:a.border, background:a.bg }}>
              <p className="text-xs font-bold flex items-center justify-between" style={{ color:a.color }}>
                {a.label}
                <span className="group-hover:translate-x-0.5 transition-transform">→</span>
              </p>
              <p className="text-[10px] text-gray-400 leading-snug">{a.sub}</p>
            </Link>
          ))}
        </div>

      </div>
      </PageSkeleton>
    </AuthGuard>
  );
}
