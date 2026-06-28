"use client";

import { useState, useEffect, useCallback, useMemo } from "react";
import Link from "next/link";
import AuthGuard from "@/components/AuthGuard";
import { formatDateTime, formatDateOnly, relativeTime, useTimezone } from "@/lib/timezone";
import PageSkeleton from "@/components/PageSkeleton";
import InfoTooltip from "@/components/InfoTooltip";
import { api } from "@/lib/api";
import type { DashboardData } from "@/types";
import { readSeed } from "@/lib/offlineData";

const ORG = process.env.NEXT_PUBLIC_ORG ?? "novapay";

// ── Types ──────────────────────────────────────────────────────────────────────

type ScoreBand = "A" | "B" | "C" | "D" | "F";
type Domain = "ai_risk" | "secrets" | "compliance" | "dependencies" | "attestation" | "response";

interface DomainScore {
  id: Domain;
  label: string;
  score: number;       // 0–100
  weight: number;      // contribution weight
  trend: number;       // delta vs last period (±)
  issues: number;
  description: string;
  link: string;
  color: string;
  bg: string;
}

interface PostureHistoryPoint {
  date: string;
  score: number;
}

interface Recommendation {
  id: string;
  priority: "critical" | "high" | "medium";
  title: string;
  impact: number;     // estimated score gain
  effort: "low" | "medium" | "high";
  domain: Domain;
  link: string;
  action: string;
}

// ── Score computation ──────────────────────────────────────────────────────────

function scoreGrade(s: number): ScoreBand {
  if (s >= 90) return "A";
  if (s >= 80) return "B";
  if (s >= 70) return "C";
  if (s >= 55) return "D";
  return "F";
}

function gradeMeta(g: ScoreBand): { color: string; bg: string; ring: string; label: string } {
  return {
    A: { color:"#15803d", bg:"#f0fdf4", ring:"#22c55e", label:"Excellent" },
    B: { color:"#1d4ed8", bg:"#eff6ff", ring:"#3b82f6", label:"Good"      },
    C: { color:"#b45309", bg:"#fffbeb", ring:"#f59e0b", label:"Fair"       },
    D: { color:"#c2410c", bg:"#fff7ed", ring:"#f97316", label:"Poor"       },
    F: { color:"#be123c", bg:"#fff1f2", ring:"#f43f5e", label:"Critical"   },
  }[g];
}

function clamp(n: number): number { return Math.min(100, Math.max(0, Math.round(n))); }

function computeDomains(data: DashboardData): DomainScore[] {
  const attest   = data.attestation_rate;
  const aiPct    = data.overall_ai_pct;
  const totalFiles = data.top_risk_files.length || 1;

  // Unattested critical/high files — use violation statuses for accuracy
  let resolvedViolations = 0;
  const violationStatuses: Record<string, string> = {};
  try {
    const vs = JSON.parse(localStorage.getItem("tl_violation_statuses") ?? "{}") as Record<string,string>;
    Object.assign(violationStatuses, vs);
    resolvedViolations = Object.values(vs).filter(v => v === "resolved").length;
  } catch {}
  const riskPfx = (r: string) => r === "CRITICAL" ? "crit" : r === "HIGH" ? "high" : "med";
  const unresolvedCrit = data.top_risk_files.filter(f => {
    if (f.attested || f.risk_score !== "CRITICAL") return false;
    return violationStatuses[`crit::${f.scan_id}::${f.file_path}`] !== "resolved";
  }).length;
  const unresolvedHigh = data.top_risk_files.filter(f => {
    if (f.attested || f.risk_score !== "HIGH") return false;
    return violationStatuses[`${riskPfx(f.risk_score)}::${f.scan_id}::${f.file_path}`] !== "resolved";
  }).length;

  // AI Risk — penalise high AI%, unresolved critical/high, weight by repo count
  const aiPenalty  = (aiPct - 0.3) * 40;   // no penalty below 30%, max ~28pt at 100%
  const critPenalty = unresolvedCrit * 15;
  const highPenalty = unresolvedHigh * 6;
  const aiRawScore  = Math.max(0, 100 - Math.max(0, aiPenalty) - critPenalty - highPenalty);
  const aiTrend     = -((unresolvedCrit + unresolvedHigh) - resolvedViolations) * 2;

  // Attestation — properly normalised: base rate + deploy penalty
  const unattested    = data.unattested_deploy_count;
  const deployPenalty = Math.min(30, unattested * 5);   // cap at -30 pts
  const attestScore   = clamp(attest * 100 - deployPenalty);
  const attestTrend   = Math.round((attest - 0.75) * 20);

  // Secrets — weight CRITICAL higher than HIGH/MEDIUM
  let secretScore = 90;
  let secretIssues = 0;
  try {
    const ss = JSON.parse(localStorage.getItem("tl_secret_status") ?? "{}") as Record<string, string>;
    // Read full finding severity from MOCK_FINDINGS IDs (sec_001=CRITICAL, sec_002=CRITICAL, sec_003=CRITICAL, sec_004-006=HIGH, sec_007-008=MEDIUM)
    const criticalIds = new Set(["sec_001","sec_002","sec_003"]);
    const highIds     = new Set(["sec_004","sec_005","sec_006"]);
    let penalty = 0;
    Object.entries(ss).forEach(([id, status]) => {
      if (status !== "open") return;
      if (criticalIds.has(id))    penalty += 20;
      else if (highIds.has(id))   penalty += 10;
      else                        penalty += 5;
    });
    // Also count live findings (sec_live_*, sec_ri_*) as HIGH
    Object.entries(ss).filter(([id]) => !id.startsWith("sec_0")).forEach(([,v]) => {
      if (v === "open") penalty += 10;
    });
    secretScore  = clamp(100 - penalty);
    secretIssues = Object.values(ss).filter(v => v === "open").length;
  } catch {}

  // Compliance — factor in exceptions AND evidence coverage
  let complianceScore = 72;
  let compIssues = 0;
  try {
    const ex = JSON.parse(localStorage.getItem("tl_exceptions_state") ?? "[]") as { status?: string }[];
    const activeExceptions = ex.filter(e => e.status !== "resolved").length;
    // Evidence coverage: collected / total from tl_evidence_state
    // evidence/page.tsx writes { status: EvidenceStatus, collected_at?, note? } — check .status, not .collected
    const ev = JSON.parse(localStorage.getItem("tl_evidence_state") ?? "{}") as Record<string, { status?: string }>;
    const evVals = Object.values(ev);
    const evCoverage = evVals.length > 0 ? evVals.filter(v => v.status === "collected").length / evVals.length : 0.5;
    complianceScore = clamp(70 + evCoverage * 25 - activeExceptions * 6);
    compIssues = activeExceptions;
  } catch {}

  // Dependencies — fixed: tl_dep_vuln_count is stored as a string, not a number
  let depsScore = 75;
  let depsIssues = 0;
  try {
    const raw = localStorage.getItem("tl_dep_vuln_count");
    const count = raw ? parseInt(raw, 10) : 0;
    if (!isNaN(count)) {
      depsScore  = clamp(100 - count * 7);
      depsIssues = count;
    }
  } catch {}

  // Response — velocity: risk trend direction + incident resolution rate
  const latestTrend = data.risk_trend.slice(-1)[0];
  const prevTrend   = data.risk_trend.slice(-2)[0];
  let responseScore = 70;
  if (latestTrend && prevTrend) {
    const nowTotal  = latestTrend.critical_count + latestTrend.high_count;
    const prevTotal = prevTrend.critical_count   + prevTrend.high_count;
    const deltaPercentage = prevTotal > 0 ? ((prevTotal - nowTotal) / prevTotal) * 100 : 0;
    // Improving trend (negative delta = fewer issues) → higher score
    responseScore = clamp(65 + deltaPercentage * 0.5);
  }
  // Bonus: resolved violations shows active remediation effort
  responseScore = clamp(responseScore + Math.min(15, resolvedViolations * 2));

  const latestCritH = latestTrend ? latestTrend.critical_count + latestTrend.high_count : 6;
  const prevCritH   = prevTrend   ? prevTrend.critical_count   + prevTrend.high_count   : 8;

  return [
    {
      id:"ai_risk",     label:"AI Code Risk",
      score:clamp(aiRawScore),
      weight:0.25, trend: clamp(aiTrend + 50) - 50,   // center around 0
      issues: unresolvedCrit + unresolvedHigh,
      description:`${unresolvedCrit} CRITICAL + ${unresolvedHigh} HIGH unattested files across ${data.repos.length} repos`,
      link:"/violations", color:"#7c3aed", bg:"#f5f3ff",
    },
    {
      id:"attestation", label:"Attestation",
      score:attestScore,
      weight:0.20, trend: attestTrend,
      issues: unattested,
      description:`${Math.round(attest*100)}% coverage · ${unattested} deploy${unattested!==1?"s":""} blocked`,
      link:"/violations", color:"#1d4ed8", bg:"#eff6ff",
    },
    {
      id:"secrets",     label:"Secrets",
      score:secretScore,
      weight:0.20, trend: secretIssues === 0 ? 5 : -secretIssues * 3,
      issues: secretIssues,
      description:`${secretIssues} open secret${secretIssues!==1?"s":""} — API keys, passwords, tokens`,
      link:"/secrets",   color:"#be123c", bg:"#fff1f2",
    },
    {
      id:"compliance",  label:"Compliance",
      score:complianceScore,
      weight:0.15, trend: 1,
      issues: compIssues,
      description:`${compIssues} active exception${compIssues!==1?"s":""} · Evidence coverage from locker`,
      link:"/compliance",color:"#0369a1", bg:"#f0f9ff",
    },
    {
      id:"dependencies",label:"Dependencies",
      score:depsScore,
      weight:0.10, trend: depsIssues === 0 ? 3 : -2,
      issues: depsIssues,
      description:`${depsIssues} vulnerable/hallucinated package${depsIssues!==1?"s":""}`,
      link:"/dependencies",color:"#b45309", bg:"#fffbeb",
    },
    {
      id:"response",    label:"Incident Response",
      score:clamp(responseScore),
      weight:0.10, trend: Math.round((prevCritH - latestCritH) * 3),
      issues: latestCritH,
      description:`${resolvedViolations} violation${resolvedViolations!==1?"s":""} resolved · Trend: ${latestCritH < prevCritH ? "↓ improving" : latestCritH > prevCritH ? "↑ worsening" : "→ stable"}`,
      link:"/incidents", color:"#15803d", bg:"#f0fdf4",
    },
  ];
}

function computeOverall(domains: DomainScore[]): number {
  const total = domains.reduce((acc, d) => acc + d.score * d.weight, 0);
  const wSum  = domains.reduce((acc, d) => acc + d.weight, 0);
  return Math.round(total / wSum);
}

function buildHistory(data: DashboardData): PostureHistoryPoint[] {
  // Reconstruct a posture score for each historical data point using the same domain weights
  // Domains weighted: ai_risk(0.25) attestation(0.20) secrets(0.20) compliance(0.15) deps(0.10) response(0.10)
  return data.risk_trend.map((p, i) => {
    const critH = p.critical_count + p.high_count;
    // AI risk: worse when more critical/high issues existed
    const aiScore    = clamp(100 - p.critical_count * 15 - p.high_count * 6 - p.medium_count * 1.5);
    // Attestation: estimate from trend (improving repos over time)
    const attEst     = Math.min(0.95, data.attestation_rate + (data.risk_trend.length - 1 - i) * (-0.015));
    const attScore   = clamp(attEst * 100);
    // Secrets/compliance/deps: use current values (we don't have historical localStorage data)
    const secScore   = 80;
    const compScore  = 70;
    const depsScore  = 75;
    // Response: velocity from adjacent trend points
    const prev = data.risk_trend[i - 1];
    const prevCH = prev ? prev.critical_count + prev.high_count : critH + 2;
    const respScore = clamp(65 + (prevCH > critH ? 15 : prevCH < critH ? -10 : 0));

    const combined = Math.round(
      aiScore   * 0.25 +
      attScore  * 0.20 +
      secScore  * 0.20 +
      compScore * 0.15 +
      depsScore * 0.10 +
      respScore * 0.10
    );
    return { date: p.date, score: clamp(combined) };
  });
}

function buildRecommendations(domains: DomainScore[], data: DashboardData): Recommendation[] {
  const recs: Recommendation[] = [];
  const aiD   = domains.find(d => d.id === "ai_risk")!;
  const attD  = domains.find(d => d.id === "attestation")!;
  const secD  = domains.find(d => d.id === "secrets")!;
  const compD = domains.find(d => d.id === "compliance")!;
  const depsD = domains.find(d => d.id === "dependencies")!;
  const respD = domains.find(d => d.id === "response")!;

  // Pull specific files for context
  const critUnatt = data.top_risk_files.filter(f => f.risk_score === "CRITICAL" && !f.attested);
  const highUnatt = data.top_risk_files.filter(f => f.risk_score === "HIGH"     && !f.attested);
  const topCrit   = critUnatt[0];
  const worstRepo = [...data.repos].sort((a, b) => a.attestation_rate - b.attestation_rate)[0];

  if (critUnatt.length > 0) {
    recs.push({
      id:"r1", priority:"critical",
      title:`Attest ${critUnatt.length} CRITICAL file${critUnatt.length>1?"s":""} — ${topCrit ? topCrit.file_path.split("/").pop() : ""} is highest risk`,
      impact: Math.min(15, 8 + critUnatt.length), effort:"low",
      domain:"ai_risk", link:`/pr/${topCrit?.scan_id ?? ""}`, action:"Review files",
    });
  }
  if (data.unattested_deploy_count > 0) {
    recs.push({
      id:"r2", priority:"critical",
      title:`Unblock ${data.unattested_deploy_count} deployment${data.unattested_deploy_count>1?"s":""} — ${highUnatt.length} HIGH files still pending review`,
      impact:6, effort:"low",
      domain:"attestation", link:"/violations", action:"View violations",
    });
  }
  if (secD.score < 70) {
    recs.push({
      id:"r3", priority:"high",
      title:`Rotate ${secD.issues} exposed credential${secD.issues>1?"s":""} — treat as compromised until rotated`,
      impact:7, effort:"medium",
      domain:"secrets", link:"/secrets", action:"Open secrets",
    });
  }
  if (attD.score < 80 && worstRepo) {
    recs.push({
      id:"r4", priority:"high",
      title:`${worstRepo.repo.split("/").pop()} at ${Math.round(worstRepo.attestation_rate*100)}% — raise to 90%+ attestation`,
      impact:5, effort:"medium",
      domain:"attestation", link:"/violations", action:"Start reviews",
    });
  }
  if (aiD.score < 75 && data.overall_ai_pct > 0.5) {
    recs.push({
      id:"r5", priority:"high",
      title:`${Math.round(data.overall_ai_pct*100)}% avg AI content — enable block-on-critical gate before next deploy`,
      impact:6, effort:"low",
      domain:"ai_risk", link:"/settings", action:"Configure policy",
    });
  }
  if (compD.score < 80) {
    recs.push({
      id:"r6", priority:"medium",
      title:`${compD.issues} compliance exception${compD.issues>1?"s":""} active — review or remediate before audit window`,
      impact:4, effort:"high",
      domain:"compliance", link:"/evidence", action:"Collect evidence",
    });
  }
  if (depsD.score < 80 && depsD.issues > 0) {
    recs.push({
      id:"r7", priority:"medium",
      title:`${depsD.issues} vulnerable package${depsD.issues>1?"s":""} — patch or lock to safe versions`,
      impact:4, effort:"medium",
      domain:"dependencies", link:"/dependencies", action:"View deps",
    });
  }
  if (respD.score < 65) {
    recs.push({
      id:"r8", priority:"medium",
      title:"Risk trend is worsening — activate incident response playbooks for open P1/P2 items",
      impact:3, effort:"medium",
      domain:"response", link:"/incidents", action:"View incidents",
    });
  }
  if (data.overall_ai_pct > 0.6 && attD.score > 80) {
    recs.push({
      id:"r9", priority:"medium",
      title:`Mandate dual-reviewer for ${Math.round(data.overall_ai_pct*100)}% AI repos to prevent SLA breaches`,
      impact:3, effort:"low",
      domain:"attestation", link:"/settings", action:"Update policy",
    });
  }

  return recs.sort((a, b) => {
    const p = { critical:0, high:1, medium:2 };
    return p[a.priority] - p[b.priority] || b.impact - a.impact;
  }).slice(0, 6);
}

// ── Helpers ────────────────────────────────────────────────────────────────────

const MONTHS = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
function fmtDate(iso: string) {
  const d = new Date(iso);
  return `${d.getDate()} ${MONTHS[d.getMonth()]}`;
}

function ScoreRing({ score, grade, size = 120 }: { score: number; grade: ScoreBand; size?: number }) {
  const meta = gradeMeta(grade);
  const r = size * 0.4;
  const circ = 2 * Math.PI * r;
  const fill = (score / 100) * circ;
  const cx = size / 2;
  return (
    <div className="relative flex items-center justify-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} style={{ transform:"rotate(-90deg)" }}>
        <circle cx={cx} cy={cx} r={r} fill="none" stroke="#e2e8f0" strokeWidth={size * 0.08} />
        <circle cx={cx} cy={cx} r={r} fill="none" stroke={meta.ring} strokeWidth={size * 0.08}
          strokeDasharray={`${fill} ${circ}`} strokeLinecap="round"
          style={{ transition:"stroke-dasharray 1.2s cubic-bezier(0.4,0,0.2,1)" }} />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="font-black tabular-nums leading-none" style={{ fontSize: size * 0.26, color: meta.color }}>{score}</span>
        <span className="font-black tracking-tight" style={{ fontSize: size * 0.13, color: meta.color }}>{grade}</span>
      </div>
    </div>
  );
}

function MiniBar({ value, max, color }: { value: number; max: number; color: string }) {
  return (
    <div className="h-1.5 rounded-full bg-gray-100 overflow-hidden">
      <div className="h-full rounded-full transition-all duration-700" style={{ width:`${Math.min(100,(value/max)*100)}%`, background: color }} />
    </div>
  );
}

function TrendArrow({ delta }: { delta: number }) {
  if (Math.abs(delta) < 1) return <span className="text-[10px] text-gray-400">—</span>;
  return delta > 0
    ? <span className="text-[10px] font-bold text-emerald-600">↑ +{delta}</span>
    : <span className="text-[10px] font-bold text-rose-600">↓ {delta}</span>;
}

const PRIORITY_STYLE = {
  critical: { bg:"#fef2f2", text:"#be123c", border:"#fecdd3", dot:"#ef4444" },
  high:     { bg:"#fff7ed", text:"#c2410c", border:"#fed7aa", dot:"#f97316" },
  medium:   { bg:"#fffbeb", text:"#b45309", border:"#fde68a", dot:"#f59e0b" },
};

const EFFORT_STYLE = {
  low:    { label:"Quick win", color:"#15803d" },
  medium: { label:"Some work", color:"#b45309" },
  high:   { label:"Big lift",  color:"#be123c" },
};

// ── Benchmark data (industry averages) ─────────────────────────────────────────

const INDUSTRY_BENCHMARKS = [
  { label:"Top 10%",   score:88, color:"#15803d" },
  { label:"Median",    score:68, color:"#b45309" },
  { label:"Bottom 25%",score:48, color:"#be123c" },
];

// ── Page ───────────────────────────────────────────────────────────────────────

export default function PosturePage() {
    const tz = useTimezone();
  const [data,              setData]              = useState<DashboardData | null>(null);
  const [loading,           setLoading]           = useState(true);
  const [loadError,         setLoadError]         = useState<string | null>(null);
  const [lastSync,          setLastSync]          = useState<Date | null>(null);
  const [activeTab,         setActiveTab]         = useState<"overview" | "domains" | "recommendations" | "history">("overview");
  const [violationStatuses, setViolationStatuses] = useState<Record<string,string>>({});

  const fetchData = useCallback(async () => {
    const seed = readSeed();
    if (seed) {
      setData(seed);
      setLoadError(null);
      setLastSync(new Date());
      setLoading(false);
      return;
    }
    try {
      const d = await api.dashboard(ORG, 90);
      setData(d);
      setLoadError(null);
    } catch (e) {
      setData(null);
      setLoadError(e instanceof Error ? e.message : "Failed to load posture data");
    } finally {
      setLastSync(new Date());
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    const id = setInterval(fetchData, 30_000);
    return () => clearInterval(id);
  }, [fetchData]);

  useEffect(() => {
    function sync() {
      try {
        setViolationStatuses(JSON.parse(localStorage.getItem("tl_violation_statuses") ?? "{}") as Record<string,string>);
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

  // Patch top_risk_files with locally-resolved violations so recommendations reflect current state
  const patchedData = useMemo<DashboardData | null>(() => {
    if (!data) return null;
    const riskPfx = (r: string) => r === "CRITICAL" ? "crit" : r === "HIGH" ? "high" : r === "MEDIUM" ? "med" : "low";
    try {
      const vs = JSON.parse(localStorage.getItem("tl_violation_statuses") ?? "{}") as Record<string,string>;
      // Patch top_risk_files: mark file as attested when its violation is resolved/in_review
      const patchedFiles = data.top_risk_files.map(f => {
        if (f.attested) return f;
        const key    = `${riskPfx(f.risk_score)}::${f.scan_id}::${f.file_path}`;
        const status = vs[key];
        return (status === "resolved" || status === "in_review") ? { ...f, attested: true } : f;
      });
      // Recompute unattested_deploy_count from patched files
      const unresolvedRepos = new Set(
        patchedFiles.filter(f => !f.attested && (f.risk_score === "CRITICAL" || f.risk_score === "HIGH")).map(f => f.repo)
      );
      return {
        ...data,
        top_risk_files: patchedFiles,
        unattested_deploy_count: Math.min(data.unattested_deploy_count, unresolvedRepos.size),
      };
    } catch { return data; }
  }, [data, violationStatuses]); // eslint-disable-line react-hooks/exhaustive-deps

  const domains   = useMemo(() => patchedData ? computeDomains(patchedData) : [], [patchedData, violationStatuses]); // eslint-disable-line react-hooks/exhaustive-deps
  const overall   = useMemo(() => computeOverall(domains),        [domains]);
  const grade     = useMemo(() => scoreGrade(overall),            [overall]);
  const gradeMeta_ = gradeMeta(grade);
  const history   = useMemo(() => data ? buildHistory(data) : [], [data]);
  const recs      = useMemo(() => patchedData ? buildRecommendations(domains, patchedData) : [], [domains, patchedData]);

  const criticalRecs = recs.filter(r => r.priority === "critical").length;
  const highRecs     = recs.filter(r => r.priority === "high").length;

  if (!data || !patchedData) {
    return (
      <AuthGuard>
        <PageSkeleton rows={4} cards={6}>
        <div className="max-w-7xl mx-auto space-y-6 pb-10">
          {loading ? (
            <div className="section-card py-16 text-center">
              <p className="text-sm font-bold text-gray-700">Loading security posture…</p>
            </div>
          ) : (
            <div className="section-card py-16 text-center space-y-3">
              <p className="text-sm font-bold text-gray-700">
                {loadError ? "Couldn't load security posture" : "No posture data yet"}
              </p>
              <p className="text-xs text-gray-400">
                {loadError ?? "Once scans run for this organization, your security posture score will appear here."}
              </p>
              {loadError && (
                <button onClick={fetchData}
                  className="px-3 py-1.5 text-xs font-bold text-indigo-600 bg-indigo-50 border border-indigo-200 rounded-xl hover:bg-indigo-100 transition-colors">
                  Retry
                </button>
              )}
            </div>
          )}
        </div>
        </PageSkeleton>
      </AuthGuard>
    );
  }

  // Score chart points
  const histMax = Math.max(...history.map(p => p.score), overall);
  const histMin = Math.min(...history.map(p => p.score), overall - 5);
  const chartH = 64;
  const chartW = 320;
  const pts = history.map((p, i) => {
    const x = (i / Math.max(history.length - 1, 1)) * chartW;
    const y = chartH - ((p.score - histMin) / Math.max(histMax - histMin, 1)) * chartH;
    return `${x},${y}`;
  }).join(" ");

  return (
    <AuthGuard>
      <PageSkeleton rows={4} cards={6}>
      <div className="max-w-7xl mx-auto space-y-5 pb-10">

        {/* Header */}
        <div className="animate-fade-up flex items-start justify-between gap-4 flex-wrap">
          <div>
            <div className="flex items-center gap-2.5 mb-1">
              <div className="w-8 h-8 rounded-xl flex items-center justify-center"
                style={{ background:"rgba(99,102,241,0.1)", border:"1px solid rgba(99,102,241,0.2)" }}>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#6366f1" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M12 2a10 10 0 1 0 10 10"/><path d="M12 6v6l4 2"/><circle cx="18" cy="6" r="3" fill="#6366f1" stroke="none"/>
                </svg>
              </div>
              <h1 className="text-xl font-black text-gray-900 tracking-tight">Security Posture</h1>
              {criticalRecs > 0 && (
                <span className="text-xs font-black text-white bg-rose-600 px-2 py-0.5 rounded-full animate-pulse">
                  {criticalRecs} critical action{criticalRecs > 1 ? "s" : ""}
                </span>
              )}
            </div>
            <p className="text-sm text-gray-400">
              Real-time security health score across all repos · auto-refreshes every 30s
            </p>
          </div>
          <div className="flex items-center gap-2">
            {lastSync && <span className="text-xs text-gray-400">Synced {Math.floor((Date.now()-lastSync.getTime())/60000)}m ago</span>}
            <button onClick={fetchData} className="flex items-center gap-1.5 px-3 py-2 text-xs font-semibold text-gray-600 bg-white border border-gray-200 rounded-xl hover:bg-gray-50 transition-all shadow-sm">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"/><path d="M8 16H3v5"/></svg>
              Refresh
            </button>
          </div>
        </div>

        {/* Hero — score + summary */}
        <div className="animate-fade-up rounded-2xl overflow-hidden border border-gray-100 shadow-sm"
          style={{ background:`linear-gradient(135deg, ${gradeMeta_.bg}, white)` }}>
          <div className="flex items-center gap-6 flex-wrap p-6">

            {/* Score ring */}
            {!loading && <ScoreRing score={overall} grade={grade} size={128} />}
            {loading && <div className="w-32 h-32 rounded-full bg-gray-100 animate-pulse" />}

            {/* Score breakdown */}
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-3 mb-1">
                <p className="text-2xl font-black text-gray-900">
                  {gradeMeta_.label} Security Posture
                </p>
              </div>
              <p className="text-sm text-gray-500 mb-4">
                Based on {data.repos.length} repos · {data.scan_count} scans · {data.file_count.toLocaleString()} files
              </p>
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                {[
                  { label:"AI Code Coverage",  value:`${(patchedData.attestation_rate*100).toFixed(0)}%`, good: patchedData.attestation_rate > 0.85,
                    info:{ title:"Attestation Rate", description:"Percentage of AI-generated files that have been reviewed and attested by a security engineer." } },
                  { label:"Unreviewed Deploys", value:String(patchedData.unattested_deploy_count), good: patchedData.unattested_deploy_count === 0,
                    info:{ title:"Unattested Deploys", description:"Deployments that went live without full attestation coverage — each represents a policy violation." } },
                  { label:"Critical Issues",   value:String(patchedData.top_risk_files.filter(f=>f.risk_score==="CRITICAL"&&!f.attested).length), good: patchedData.top_risk_files.filter(f=>f.risk_score==="CRITICAL"&&!f.attested).length === 0,
                    info:{ title:"Critical Unattested Files", description:"Files with CRITICAL risk score that have not yet been reviewed by a security engineer." } },
                  { label:"AI % of Codebase",  value:`${(data.overall_ai_pct*100).toFixed(0)}%`, good: data.overall_ai_pct < 0.5,
                    info:{ title:"AI Code Percentage", description:"What fraction of your scanned codebase was identified as AI-generated. Higher values mean more exposure." } },
                  { label:"Repos Scanned",     value:String(data.repos.length), good: true,
                    info:{ title:"Repos Scanned", description:"Number of repositories currently monitored by TrustLedger." } },
                  { label:"Action Required",   value:String(criticalRecs + highRecs), good: (criticalRecs + highRecs) === 0,
                    info:{ title:"Actions Required", description:"Total count of critical and high-priority recommendations that improve your posture score." } },
                ].map(m => (
                  <div key={m.label} className="flex items-center gap-2 bg-white/70 rounded-xl px-3 py-2 border border-white/80">
                    <div className="w-2 h-2 rounded-full flex-shrink-0" style={{ background: m.good ? "#22c55e" : "#ef4444" }} />
                    <div className="flex-1 min-w-0">
                      <p className="text-[10px] text-gray-400 font-medium truncate flex items-center gap-1">
                        {m.label}
                        <InfoTooltip title={m.info.title} description={m.info.description} position="top" />
                      </p>
                      <p className="text-sm font-black text-gray-800 tabular-nums">{m.value}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Benchmark */}
            <div className="hidden lg:flex flex-col gap-2 min-w-[140px]">
              <p className="text-xs font-bold text-gray-500 mb-1">Industry Benchmark</p>
              {INDUSTRY_BENCHMARKS.map(b => (
                <div key={b.label} className="flex items-center gap-2">
                  <div className="text-[10px] text-gray-400 w-20">{b.label}</div>
                  <div className="flex-1 h-1.5 rounded-full bg-gray-100 relative overflow-visible">
                    <div className="h-full rounded-full" style={{ width:`${b.score}%`, background:b.color }} />
                    {overall > 0 && (
                      <div className="absolute top-1/2 -translate-y-1/2 w-2.5 h-2.5 rounded-full border-2 border-white shadow"
                        style={{ left:`${Math.min(overall,98)}%`, background:"#6366f1" }} />
                    )}
                  </div>
                  <div className="text-[10px] font-bold w-6 tabular-nums" style={{ color:b.color }}>{b.score}</div>
                </div>
              ))}
              <p className="text-[10px] text-indigo-600 font-bold mt-1">
                Your score: <span className="font-black">{overall}</span>
              </p>
            </div>
          </div>
        </div>

        {/* Tabs */}
        <div className="animate-fade-up flex gap-1 bg-gray-50 rounded-xl p-1 w-fit border border-gray-100">
          {(["overview","domains","recommendations","history"] as const).map(t => (
            <button key={t} onClick={() => setActiveTab(t)}
              className="px-4 py-1.5 rounded-lg text-xs font-semibold capitalize transition-all"
              style={activeTab === t ? { background:"white", color:"#1e293b", boxShadow:"0 1px 4px rgba(0,0,0,0.08)" } : { color:"#64748b" }}>
              {t === "recommendations" ? `Actions (${recs.length})` : t.charAt(0).toUpperCase()+t.slice(1)}
            </button>
          ))}
        </div>

        {/* ── Overview tab ──────────────────────────────────────────────────── */}
        {activeTab === "overview" && (
          <div className="space-y-4">

            {/* Domain summary grid */}
            <div className="animate-fade-up grid grid-cols-2 sm:grid-cols-3 gap-3">
              {domains.map(d => (
                <Link href={d.link} key={d.id}
                  className="group rounded-2xl p-4 border transition-all hover:shadow-md hover:-translate-y-0.5"
                  style={{ background:d.bg, borderColor:d.color+"25" }}>
                  <div className="flex items-start justify-between gap-2 mb-3">
                    <div>
                      <p className="text-xs font-semibold text-gray-500">{d.label}</p>
                      <div className="flex items-center gap-2 mt-0.5">
                        <p className="text-2xl font-black tabular-nums" style={{ color:d.color }}>{d.score}</p>
                        <span className="text-xs font-black px-1.5 py-0.5 rounded-lg" style={{ background:d.color+"18", color:d.color }}>
                          {scoreGrade(d.score)}
                        </span>
                      </div>
                    </div>
                    <TrendArrow delta={d.trend} />
                  </div>
                  <MiniBar value={d.score} max={100} color={d.color} />
                  <p className="text-[10px] text-gray-400 mt-2">
                    {d.issues > 0 ? `${d.issues} issue${d.issues>1?"s":""} open` : "No open issues"}
                    <span className="ml-1 opacity-0 group-hover:opacity-100 transition-opacity">↗</span>
                  </p>
                </Link>
              ))}
            </div>

            {/* Score trend sparkline */}
            {history.length >= 2 && (
              <div className="animate-fade-up rounded-2xl p-5 border border-gray-100 bg-white shadow-sm">
                <div className="flex items-center justify-between mb-4">
                  <div>
                    <p className="text-sm font-black text-gray-800">Posture Trend</p>
                    <p className="text-xs text-gray-400">Rolling 90-day security posture score</p>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <div className="w-2 h-2 rounded-full bg-indigo-500" />
                    <span className="text-xs text-gray-500">Overall score</span>
                  </div>
                </div>
                <div className="relative" style={{ height: chartH + 24 }}>
                  <svg width="100%" height={chartH} viewBox={`0 0 ${chartW} ${chartH}`} preserveAspectRatio="none">
                    {/* Area fill */}
                    <defs>
                      <linearGradient id="sparkGrad" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#6366f1" stopOpacity="0.15"/>
                        <stop offset="100%" stopColor="#6366f1" stopOpacity="0"/>
                      </linearGradient>
                    </defs>
                    <polyline fill="url(#sparkGrad)" stroke="none" points={`0,${chartH} ${pts} ${chartW},${chartH}`} />
                    <polyline fill="none" stroke="#6366f1" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" points={pts} />
                    {history.map((p, i) => {
                      const x = (i / Math.max(history.length - 1, 1)) * chartW;
                      const y = chartH - ((p.score - histMin) / Math.max(histMax - histMin, 1)) * chartH;
                      return <circle key={i} cx={x} cy={y} r="3" fill="white" stroke="#6366f1" strokeWidth="2" />;
                    })}
                  </svg>
                  {/* x-axis labels */}
                  <div className="flex justify-between pt-1">
                    {history.map((p, i) => (
                      <span key={i} className="text-[9px] text-gray-400">{fmtDate(p.date)}</span>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {/* Top 3 urgent recommendations — rich cards */}
            {recs.slice(0, 3).length > 0 && (
              <div className="animate-fade-up space-y-3">
                {/* Header row */}
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <div className="w-1.5 h-4 rounded-full bg-rose-500" />
                    <p className="text-sm font-black text-gray-900">Top Priority Actions</p>
                    <span className="text-[10px] font-bold text-rose-600 bg-rose-50 border border-rose-200 px-2 py-0.5 rounded-full">
                      {recs.filter(r=>r.priority==="critical").length} critical · {recs.filter(r=>r.priority==="high").length} high
                    </span>
                  </div>
                  <p className="text-[10px] text-gray-400">
                    Complete all → +{recs.reduce((a,r)=>a+r.impact,0)} pts · target score {Math.min(100, overall + recs.reduce((a,r)=>a+r.impact,0))}
                  </p>
                </div>

                {recs.slice(0, 3).map((r, idx) => {
                  const ps      = PRIORITY_STYLE[r.priority];
                  const domainD = domains.find(d => d.id === r.domain);
                  const effortStyle = {
                    low:    { label:"Quick win",  color:"#15803d", bg:"#f0fdf4", border:"#bbf7d0" },
                    medium: { label:"Some work",  color:"#b45309", bg:"#fffbeb", border:"#fde68a" },
                    high:   { label:"Big lift",   color:"#be123c", bg:"#fff1f2", border:"#fecdd3" },
                  }[r.effort];
                  const impactBarWidth = Math.min(100, r.impact * 7); // 0-15pts → 0-100%

                  return (
                    <div key={r.id}
                      className="rounded-2xl border bg-white shadow-sm overflow-hidden transition-all hover:shadow-md"
                      style={{ borderLeftWidth:3, borderLeftColor:ps.dot, borderColor:idx===0?ps.border:"#e2e8f0" }}>
                      {/* Main row */}
                      <div className="flex items-start gap-4 px-4 py-4">
                        {/* Number */}
                        <div className="w-7 h-7 rounded-xl flex items-center justify-center shrink-0 text-white text-[11px] font-black mt-0.5"
                          style={{ background: ps.dot }}>
                          {idx + 1}
                        </div>

                        {/* Content */}
                        <div className="flex-1 min-w-0">
                          {/* Badges row */}
                          <div className="flex items-center gap-2 flex-wrap mb-1.5">
                            <span className="text-[9px] font-black uppercase px-2 py-0.5 rounded-full"
                              style={{ background:ps.bg, color:ps.text, border:`1px solid ${ps.border}` }}>
                              {r.priority}
                            </span>
                            {domainD && (
                              <span className="text-[9px] font-semibold px-2 py-0.5 rounded-full border"
                                style={{ background:domainD.bg, color:domainD.color, borderColor:domainD.color+"30" }}>
                                {domainD.label}
                              </span>
                            )}
                            <span className="text-[9px] font-semibold px-2 py-0.5 rounded-full border"
                              style={{ background:effortStyle.bg, color:effortStyle.color, borderColor:effortStyle.border }}>
                              {effortStyle.label}
                            </span>
                          </div>

                          {/* Title */}
                          <p className="text-sm font-bold text-gray-900 leading-snug">{r.title}</p>

                          {/* Impact bar */}
                          <div className="flex items-center gap-2 mt-2">
                            <span className="text-[9px] text-gray-400 shrink-0">Score impact</span>
                            <div className="flex-1 h-1.5 rounded-full bg-gray-100 overflow-hidden">
                              <div className="h-full rounded-full transition-all duration-700"
                                style={{ width:`${impactBarWidth}%`, background:"linear-gradient(90deg,#10b981,#059669)" }} />
                            </div>
                            <span className="text-[10px] font-black text-emerald-600 shrink-0">+{r.impact} pts</span>
                          </div>
                        </div>

                        {/* CTA */}
                        <Link href={r.link}
                          className="shrink-0 flex items-center gap-1.5 px-3 py-2 text-xs font-black text-white rounded-xl hover:opacity-90 transition-all active:scale-95 shadow-sm mt-0.5"
                          style={{ background:`linear-gradient(135deg,${ps.dot},${ps.dot}cc)` }}>
                          {r.action}
                          <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><path d="M5 12h14"/><path d="m12 5 7 7-7 7"/></svg>
                        </Link>
                      </div>

                      {/* Bottom context bar */}
                      {idx === 0 && (
                        <div className="px-4 py-2 border-t border-gray-50 flex items-center gap-2"
                          style={{ background:"rgba(248,250,252,0.8)" }}>
                          <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="#94a3b8" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                          <p className="text-[9px] text-gray-400">
                            <span className="font-bold text-gray-600">Highest impact action available.</span> Completing this raises your posture score by {r.impact} points — the single biggest gain you can make right now.
                          </p>
                        </div>
                      )}
                    </div>
                  );
                })}

                {/* See all link */}
                {recs.length > 3 && (
                  <button onClick={() => setActiveTab("recommendations")}
                    className="w-full text-[11px] font-bold text-indigo-600 bg-indigo-50 border border-indigo-100 py-2.5 rounded-xl hover:bg-indigo-100 transition-colors">
                    View all {recs.length} recommendations →
                  </button>
                )}
              </div>
            )}
          </div>
        )}

        {/* ── Domains tab ───────────────────────────────────────────────────── */}
        {activeTab === "domains" && (
          <div className="space-y-3">
            {domains.map(d => {
              const g = scoreGrade(d.score);
              const gm = gradeMeta(g);
              return (
                <div key={d.id} className="animate-fade-up rounded-2xl border bg-white shadow-sm overflow-hidden">
                  <div className="flex items-center gap-4 p-5">
                    <div className="w-16 h-16 rounded-2xl flex flex-col items-center justify-center shrink-0 border-2"
                      style={{ background:gm.bg, borderColor:gm.ring+"60" }}>
                      <span className="text-xl font-black tabular-nums leading-none" style={{ color:gm.color }}>{d.score}</span>
                      <span className="text-[10px] font-black" style={{ color:gm.color }}>{g}</span>
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-0.5">
                        <p className="text-sm font-black text-gray-800">{d.label}</p>
                        <TrendArrow delta={d.trend} />
                      </div>
                      <p className="text-xs text-gray-400 mb-2">{d.description}</p>
                      <div className="flex items-center gap-3">
                        <div className="flex-1 h-2 rounded-full bg-gray-100 overflow-hidden">
                          <div className="h-full rounded-full transition-all duration-700" style={{ width:`${d.score}%`, background:d.color }} />
                        </div>
                        <span className="text-[10px] font-semibold text-gray-400 w-16 text-right">
                          {d.issues > 0 ? `${d.issues} issue${d.issues>1?"s":""}` : "Clean"}
                        </span>
                      </div>
                    </div>
                    <Link href={d.link}
                      className="shrink-0 text-xs font-semibold px-3 py-1.5 rounded-xl border transition-all hover:shadow-sm"
                      style={{ borderColor:d.color+"40", color:d.color, background:d.bg }}>
                      View details ↗
                    </Link>
                  </div>
                  {/* Weight bar */}
                  <div className="px-5 pb-4">
                    <div className="flex items-center justify-between text-[10px] text-gray-400 mb-1">
                      <span>Weight in overall score: {Math.round(d.weight * 100)}%</span>
                      <span>Contributing {Math.round(d.score * d.weight)} pts</span>
                    </div>
                    <div className="h-1 rounded-full bg-gray-100 overflow-hidden">
                      <div className="h-full rounded-full bg-gray-300" style={{ width:`${d.weight * 100}%` }} />
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}

        {/* ── Recommendations tab ───────────────────────────────────────────── */}
        {activeTab === "recommendations" && (
          <div className="space-y-3">
            <div className="animate-fade-up rounded-2xl bg-indigo-50 border border-indigo-100 px-5 py-4">
              <p className="text-sm font-black text-indigo-800 mb-1">Score Improvement Roadmap</p>
              <p className="text-xs text-indigo-600">
                Complete all actions below to gain an estimated
                <span className="font-black"> +{recs.reduce((acc,r)=>acc+r.impact,0)} points</span> — bringing your score to {Math.min(100, overall + recs.reduce((acc,r)=>acc+r.impact,0))}.
              </p>
            </div>
            {recs.map(r => {
              const ps   = PRIORITY_STYLE[r.priority];
              const ef   = EFFORT_STYLE[r.effort];
              const domainLabel = domains.find(d => d.id === r.domain)?.label ?? r.domain;
              return (
                <div key={r.id} className="animate-fade-up rounded-2xl border bg-white shadow-sm p-5">
                  <div className="flex items-start gap-4">
                    <div className="w-8 h-8 rounded-xl flex items-center justify-center shrink-0 mt-0.5"
                      style={{ background:ps.bg, border:`1px solid ${ps.border}` }}>
                      <div className="w-2.5 h-2.5 rounded-full" style={{ background:ps.dot }} />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-start justify-between gap-3 flex-wrap">
                        <p className="text-sm font-bold text-gray-800">{r.title}</p>
                        <div className="flex items-center gap-2 shrink-0">
                          <span className="text-[10px] font-black text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded-full border border-emerald-100">+{r.impact} pts</span>
                          <span className="text-[10px] font-semibold px-2 py-0.5 rounded-full border" style={{ color:ps.text, background:ps.bg, borderColor:ps.border }}>
                            {r.priority.charAt(0).toUpperCase()+r.priority.slice(1)}
                          </span>
                        </div>
                      </div>
                      <div className="flex items-center gap-3 mt-2 flex-wrap">
                        <span className="text-[10px] text-gray-400">Domain: <span className="font-semibold text-gray-600">{domainLabel}</span></span>
                        <span className="text-[10px]" style={{ color:ef.color }}>● {ef.label}</span>
                      </div>
                    </div>
                    <Link href={r.link}
                      className="shrink-0 text-xs font-semibold text-white px-3 py-1.5 rounded-xl hover:opacity-90 transition-opacity"
                      style={{ background:`linear-gradient(135deg,${ps.dot},${ps.dot}cc)` }}>
                      {r.action}
                    </Link>
                  </div>
                </div>
              );
            })}
          </div>
        )}

        {/* ── History tab ───────────────────────────────────────────────────── */}
        {activeTab === "history" && (
          <div className="space-y-4">
            {/* Full chart */}
            <div className="animate-fade-up rounded-2xl border bg-white shadow-sm p-5">
              <p className="text-sm font-black text-gray-800 mb-4">90-Day Posture History</p>
              {history.length >= 2 ? (
                <div className="space-y-4">
                  {history.map((p, i) => {
                    const g    = scoreGrade(p.score);
                    const gm   = gradeMeta(g);
                    const prev = i > 0 ? history[i-1].score : p.score;
                    const delta = p.score - prev;
                    return (
                      <div key={p.date} className="flex items-center gap-4">
                        <span className="text-xs text-gray-400 w-16 shrink-0">{fmtDate(p.date)}</span>
                        <div className="flex-1 h-5 rounded-full bg-gray-50 overflow-hidden relative border border-gray-100">
                          <div className="h-full rounded-full transition-all duration-700"
                            style={{ width:`${p.score}%`, background:`linear-gradient(90deg,${gm.ring}88,${gm.ring})` }} />
                          <span className="absolute inset-0 flex items-center px-3 text-[10px] font-black" style={{ color:gm.color }}>
                            {p.score} — {gm.label}
                          </span>
                        </div>
                        <div className="w-12 text-right">
                          {i === 0 ? <span className="text-[10px] text-gray-400">—</span> : <TrendArrow delta={delta} />}
                        </div>
                      </div>
                    );
                  })}
                </div>
              ) : (
                <p className="text-sm text-gray-400 text-center py-8">Not enough data to show history yet.</p>
              )}
            </div>

            {/* Risk counts table */}
            <div className="animate-fade-up rounded-2xl border bg-white shadow-sm overflow-hidden">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-gray-100">
                    <th className="text-left px-5 py-3 font-semibold text-gray-500">Date</th>
                    <th className="text-right px-5 py-3 font-semibold text-gray-500">Critical</th>
                    <th className="text-right px-5 py-3 font-semibold text-gray-500">High</th>
                    <th className="text-right px-5 py-3 font-semibold text-gray-500">Medium</th>
                    <th className="text-right px-5 py-3 font-semibold text-gray-500">Posture</th>
                  </tr>
                </thead>
                <tbody>
                  {data.risk_trend.map((p, i) => {
                    const s = history[i]?.score ?? 0;
                    const g = scoreGrade(s);
                    const gm = gradeMeta(g);
                    return (
                      <tr key={p.date} className="border-b border-gray-50 hover:bg-gray-50/50 transition-colors">
                        <td className="px-5 py-2.5 font-medium text-gray-700">{fmtDate(p.date)}</td>
                        <td className="px-5 py-2.5 text-right font-bold text-rose-600">{p.critical_count}</td>
                        <td className="px-5 py-2.5 text-right font-bold text-orange-600">{p.high_count}</td>
                        <td className="px-5 py-2.5 text-right font-semibold text-yellow-600">{p.medium_count}</td>
                        <td className="px-5 py-2.5 text-right">
                          <span className="font-black tabular-nums px-2 py-0.5 rounded-lg text-[10px]"
                            style={{ color:gm.color, background:gm.bg }}>
                            {s} {g}
                          </span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}

      </div>
      </PageSkeleton>
    </AuthGuard>
  );
}
