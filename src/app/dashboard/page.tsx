"use client";

import { useEffect, useState, useMemo, useCallback } from "react";
import dynamic from "next/dynamic";
import Link from "next/link";
import AuthGuard from "@/components/AuthGuard";
import InfoTooltip from "@/components/InfoTooltip";
import StatsCard from "@/components/StatsCard";
import RiskDonut from "@/components/RiskDonut";
import ProgressBar from "@/components/ProgressBar";
import RiskBadge from "@/components/RiskBadge";

// Heavy components — lazy loaded to reduce initial bundle size
const RiskTrendChart     = dynamic(() => import("@/components/RiskTrendChart"),    { ssr:false });
const HealthScoreGauge   = dynamic(() => import("@/components/HealthScoreGauge"),  { ssr:false });
const TopRiskFilesPanel  = dynamic(() => import("@/components/TopRiskFilesPanel"), { ssr:false });
const ComplianceReadiness= dynamic(() => import("@/components/ComplianceReadiness"),{ ssr:false });
const ActionItemsPanel   = dynamic(() => import("@/components/ActionItemsPanel"),  { ssr:false });
import { api } from "@/lib/api";
import { dashboardWithSeed } from "@/lib/offlineData";
import { loadPolicy } from "@/lib/policy";
import { computeTrustScore, scoreColor } from "@/lib/trustScore";
import { useScansRealtime } from "@/lib/realtime";
import { useAuth } from "@/lib/auth";
import SetupGuide from "@/components/setup/SetupGuide";
import { useRole, ROLE_LABELS, ROLE_COLORS } from "@/lib/roles";
import RoleGate from "@/components/RoleGate";
import NewScanPanel from "@/components/NewScanPanel";
import type { DashboardData, RepoStat, RiskLevel, ActivityEvent } from "@/types";

const DAYS_OPTIONS = [7, 30, 90] as const;
type DaysOption = (typeof DAYS_OPTIONS)[number];
type RangeMode = DaysOption | "custom";
const ORG       = process.env.NEXT_PUBLIC_ORG ?? "novapay";
const SKIP_AUTH = process.env.NEXT_PUBLIC_SKIP_AUTH === "true";

// ── Mock data (used when backend is offline) ──────────────────────────────────

function makeMockData(): DashboardData {
  const o = ORG;
  const relDate  = (daysBack: number) => new Date(Date.now() - daysBack * 86400000).toISOString().split("T")[0];
  const weekDate = (weeksBack: number) => relDate(weeksBack * 7);
  return {
    repos: [
      { repo:`${o}/payments-api`,    ai_pct:0.71, attestation_rate:0.80, last_scan:relDate(2), scan_count:18, file_count:142, latest_scan_id:"sc_mock_001" },
      { repo:`${o}/auth-service`,    ai_pct:0.44, attestation_rate:0.92, last_scan:relDate(1), scan_count:12, file_count:98,  latest_scan_id:"sc_mock_002" },
      { repo:`${o}/fraud-detection`, ai_pct:0.58, attestation_rate:0.67, last_scan:relDate(0), scan_count:9,  file_count:76,  latest_scan_id:"sc_mock_003" },
      { repo:`${o}/risk-engine`,     ai_pct:0.36, attestation_rate:0.95, last_scan:relDate(3), scan_count:7,  file_count:54,  latest_scan_id:"sc_mock_004" },
      { repo:`${o}/data-platform`,   ai_pct:0.62, attestation_rate:0.55, last_scan:relDate(4), scan_count:5,  file_count:61,  latest_scan_id:"sc_mock_005" },
    ],
    overall_ai_pct:          0.54,
    attestation_rate:        0.78,
    unattested_deploy_count: 3,
    scan_count:              51,
    file_count:              431,
    risk_trend: [
      { date:weekDate(5), high_count:5,  critical_count:3, medium_count:9  },
      { date:weekDate(4), high_count:4,  critical_count:2, medium_count:7  },
      { date:weekDate(3), high_count:6,  critical_count:3, medium_count:8  },
      { date:weekDate(2), high_count:3,  critical_count:1, medium_count:5  },
      { date:weekDate(1), high_count:2,  critical_count:1, medium_count:4  },
    ],
    top_risk_files: [
      { repo:`${o}/payments-api`,    file_path:"src/processors/card_validator.py",   ai_pct:0.91, risk_score:"CRITICAL", attested:false, scan_id:"sc_mock_001", pr_number:482 },
      { repo:`${o}/fraud-detection`, file_path:"models/risk_scorer.ts",              ai_pct:0.83, risk_score:"CRITICAL", attested:false, scan_id:"sc_mock_003", pr_number:219 },
      { repo:`${o}/payments-api`,    file_path:"src/gateway/stripe_client.py",       ai_pct:0.76, risk_score:"HIGH",     attested:false, scan_id:"sc_mock_001", pr_number:479 },
      { repo:`${o}/auth-service`,    file_path:"src/oauth/token_exchange.ts",        ai_pct:0.68, risk_score:"HIGH",     attested:true,  scan_id:"sc_mock_002", pr_number:341 },
      { repo:`${o}/fraud-detection`, file_path:"src/rules/velocity_check.py",        ai_pct:0.62, risk_score:"HIGH",     attested:true,  scan_id:"sc_mock_003", pr_number:218 },
      { repo:`${o}/payments-api`,    file_path:"src/api/refund_handler.py",          ai_pct:0.55, risk_score:"MEDIUM",   attested:true,  scan_id:"sc_mock_001", pr_number:477 },
      { repo:`${o}/auth-service`,    file_path:"src/middleware/rate_limiter.ts",     ai_pct:0.49, risk_score:"MEDIUM",   attested:true,  scan_id:"sc_mock_002", pr_number:338 },
      { repo:`${o}/data-platform`,   file_path:"src/pipelines/etl_runner.py",        ai_pct:0.65, risk_score:"HIGH",     attested:false, scan_id:"sc_mock_005", pr_number:103 },
      { repo:`${o}/risk-engine`,     file_path:"src/models/credit_score.ts",         ai_pct:0.41, risk_score:"MEDIUM",   attested:true,  scan_id:"sc_mock_004", pr_number:88  },
      { repo:`${o}/payments-api`,    file_path:"src/utils/currency_formatter.py",    ai_pct:0.22, risk_score:"LOW",      attested:true,  scan_id:"sc_mock_001", pr_number:471 },
    ],
  };
}
const MOCK_DATA: DashboardData = makeMockData();

function getReviewers(): string[] {
  try {
    const stored = typeof window !== "undefined" ? localStorage.getItem("tl_team_members") : null;
    if (stored) {
      const members: { email: string }[] = JSON.parse(stored);
      if (members.length > 0) return members.map(m => m.email);
    }
  } catch { /* fall through */ }
  return [`alice@${ORG}.io`, `bob@${ORG}.io`, `carol@${ORG}.io`, `dave@${ORG}.io`];
}

function deriveActivity(data: DashboardData): ActivityEvent[] {
  const events: ActivityEvent[] = [];
  const now = Date.now();

  // One scan event per repo (most recent scan)
  data.repos.forEach((r, i) => {
    if (!r.latest_scan_id) return;
    const ts = r.last_scan
      ? new Date(r.last_scan).toISOString()
      : new Date(now - (i + 1) * 86400000).toISOString();
    const risk = r.attestation_rate < 0.4 ? "CRITICAL"
                : r.attestation_rate < 0.7 ? "HIGH"
                : r.attestation_rate < 0.9 ? "MEDIUM" : "LOW";
    events.push({
      type: "scan", timestamp: ts, repo: r.repo,
      pr_number: 400 + i * 17,
      scan_id: r.latest_scan_id,
      overall_risk: risk,
      file_count: Math.round(r.file_count * 0.15),
      total_ai_pct: r.ai_pct,
      file_path: "", reviewer_email: "",
    });
  });

  // Attestation events from attested top_risk_files
  data.top_risk_files.filter(f => f.attested).forEach((f, i) => {
    const tsOffset = (i + 1) * 3600000 * 2;
    events.push({
      type: "attestation",
      timestamp: new Date(now - tsOffset).toISOString(),
      repo: f.repo,
      pr_number: f.pr_number,
      scan_id: f.scan_id,
      overall_risk: f.risk_score,
      file_count: 0,
      total_ai_pct: f.ai_pct,
      file_path: f.file_path,
      reviewer_email: getReviewers()[i % getReviewers().length],
    });
  });

  // Fill remaining slots up to 15 with historical scan events
  if (events.length < 15 && data.repos.length > 0) {
    data.risk_trend.slice().reverse().forEach((pt, i) => {
      if (events.length >= 15) return;
      const firstRepo = data.repos[i % data.repos.length];
      if (!firstRepo) return;
      events.push({
        type: "scan",
        timestamp: new Date(pt.date + "T10:00:00Z").toISOString(),
        repo: firstRepo.repo,
        pr_number: 300 + i * 13,
        scan_id: firstRepo.latest_scan_id,
        overall_risk: pt.critical_count > 5 ? "CRITICAL" : pt.high_count > 8 ? "HIGH" : "MEDIUM",
        file_count: pt.high_count + pt.critical_count,
        total_ai_pct: firstRepo.ai_pct,
        file_path: "", reviewer_email: "",
      });
    });
  }

  return events
    .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
    .slice(0, 15);
}

const MOCK_ACTIVITY: ActivityEvent[] = (function() {
  const o = ORG;
  const rd = (daysBack: number) => new Date(Date.now() - daysBack * 86400000).toISOString().split("T")[0];
  return deriveActivity({
    repos: [
      { repo:`${o}/payments-api`,    ai_pct:0.71, attestation_rate:0.80, last_scan:rd(0), scan_count:34, file_count:214, latest_scan_id:"sc_mock_001" },
      { repo:`${o}/auth-service`,    ai_pct:0.44, attestation_rate:0.88, last_scan:rd(0), scan_count:28, file_count:167, latest_scan_id:"sc_mock_002" },
      { repo:`${o}/fraud-detection`, ai_pct:0.63, attestation_rate:0.67, last_scan:rd(1), scan_count:21, file_count:143, latest_scan_id:"sc_mock_003" },
      { repo:`${o}/risk-engine`,     ai_pct:0.38, attestation_rate:0.91, last_scan:rd(2), scan_count:15, file_count:98,  latest_scan_id:"sc_mock_004" },
      { repo:`${o}/data-platform`,   ai_pct:0.67, attestation_rate:0.52, last_scan:rd(3), scan_count:19, file_count:134, latest_scan_id:"sc_mock_005" },
      { repo:`${o}/ml-platform`,     ai_pct:0.79, attestation_rate:0.45, last_scan:rd(1), scan_count:11, file_count:112, latest_scan_id:"sc_mock_006" },
      { repo:`${o}/api-gateway`,     ai_pct:0.52, attestation_rate:0.74, last_scan:rd(0), scan_count:19, file_count:124, latest_scan_id:"sc_mock_007" },
    ],
    overall_ai_pct:0.67, attestation_rate:0.72, unattested_deploy_count:5, scan_count:147, file_count:992,
    risk_trend:[
      { date:rd(35), high_count:11, critical_count:4, medium_count:15 },
      { date:rd(28), high_count:9,  critical_count:3, medium_count:12 },
      { date:rd(21), high_count:8,  critical_count:3, medium_count:11 },
      { date:rd(14), high_count:7,  critical_count:2, medium_count:10 },
      { date:rd(7),  high_count:6,  critical_count:2, medium_count:8  },
    ],
    top_risk_files:[
      { repo:`${o}/payments-api`,    file_path:"src/processors/card_validator.py",   ai_pct:0.94, risk_score:"CRITICAL", attested:true,  scan_id:"sc_mock_001", pr_number:512 },
      { repo:`${o}/auth-service`,    file_path:"src/auth/token_service.py",          ai_pct:0.76, risk_score:"HIGH",     attested:true,  scan_id:"sc_mock_002", pr_number:371 },
      { repo:`${o}/api-gateway`,     file_path:"src/middleware/auth_interceptor.ts", ai_pct:0.79, risk_score:"HIGH",     attested:true,  scan_id:"sc_mock_007", pr_number:203 },
    ],
  });
})();

// ── Executive Summary ─────────────────────────────────────────────────────────

function ExecSummary({ data }: { data: DashboardData }) {
  const [dismissed, setDismissed] = useState(false);
  useEffect(() => { setDismissed(localStorage.getItem("tl_exec_dismissed") === "1"); }, []);

  if (dismissed) return null;

  const score  = Math.round(Math.min(100,
    data.attestation_rate * 60 +
    (1 - Math.min(data.overall_ai_pct, 1)) * 25 +
    Math.max(0, 15 - data.unattested_deploy_count * 3),
  ));
  const attPct  = Math.round(data.attestation_rate * 100);
  const aiPct   = Math.round(data.overall_ai_pct * 100);
  const crit    = data.top_risk_files.filter(f => f.risk_score === "CRITICAL" && !f.attested).length;
  const posture = score >= 80 ? { label:"STRONG", color:"#15803d", bg:"#f0fdf4", border:"#bbf7d0" }
                : score >= 60 ? { label:"FAIR",   color:"#b45309", bg:"#fffbeb", border:"#fde68a" }
                :               { label:"AT RISK", color:"#be123c", bg:"#fef2f2", border:"#fecdd3" };

  return (
    <div className="animate-fade-up rounded-2xl border overflow-hidden"
      style={{ background:"linear-gradient(135deg,#0f172a 0%,#1e1b4b 100%)", borderColor:"rgba(255,255,255,0.08)" }}>
      <div className="flex items-start justify-between px-6 py-4">
        <div className="flex items-center gap-4">
          {/* Big score */}
          <div className="text-center shrink-0">
            <p className="text-5xl font-black text-white tabular-nums leading-none">{score}</p>
            <p className="text-[10px] text-white/30 mt-1 font-semibold uppercase tracking-wider">Health Score</p>
          </div>
          <div className="w-px h-12 bg-white/10" />
          {/* Posture */}
          <div>
            <span className="text-[10px] font-black uppercase tracking-widest px-2.5 py-1 rounded-full"
              style={{ background:posture.bg, color:posture.color, border:`1px solid ${posture.border}` }}>
              {posture.label}
            </span>
            <p className="text-xs text-white/40 mt-2 max-w-xs leading-relaxed">
              {crit > 0
                ? `${crit} CRITICAL file${crit > 1 ? "s" : ""} need immediate attestation · ${data.unattested_deploy_count} deploy${data.unattested_deploy_count !== 1 ? "s" : ""} blocked`
                : `Attestation coverage at ${attPct}% · ${data.unattested_deploy_count} deploy${data.unattested_deploy_count !== 1 ? "s" : ""} blocked`
              }
            </p>
          </div>
        </div>

        {/* Right: mini KPIs */}
        <div className="flex items-center gap-6 shrink-0">
          {[
            { label:"Repos",       value:data.repos.length,   color:"#818cf8" },
            { label:"Attestation", value:`${attPct}%`,         color: attPct>=80?"#34d399":"#fbbf24" },
            { label:"Avg AI%",     value:`${aiPct}%`,          color: aiPct>70?"#f87171":"#a5b4fc" },
            { label:"Blocked",     value:data.unattested_deploy_count, color:data.unattested_deploy_count>0?"#f87171":"#34d399" },
          ].map(k => (
            <div key={k.label} className="text-center">
              <p className="text-xl font-black tabular-nums" style={{ color:k.color }}>{k.value}</p>
              <p className="text-[9px] text-white/30 font-semibold uppercase tracking-wider mt-0.5">{k.label}</p>
            </div>
          ))}
          <button onClick={() => { localStorage.setItem("tl_exec_dismissed","1"); setDismissed(true); }}
            className="text-white/20 hover:text-white/50 transition-colors ml-2" aria-label="Dismiss">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
              <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
            </svg>
          </button>
        </div>
      </div>
      {/* Bar at the bottom */}
      <div className="h-1 w-full bg-white/5">
        <div className="h-full rounded-full transition-all duration-1000"
          style={{ width:`${score}%`, background:`linear-gradient(90deg,#6366f1,${score>=80?"#10b981":score>=60?"#f59e0b":"#ef4444"})` }} />
      </div>
    </div>
  );
}

// ── Score ─────────────────────────────────────────────────────────────────────

function healthScore(data: DashboardData): number {
  if (data.repos.length === 0) return 100;
  return Math.round(Math.min(100,
    data.attestation_rate * 60 +
    (1 - Math.min(data.overall_ai_pct, 1)) * 25 +
    Math.max(0, 15 - data.unattested_deploy_count * 3),
  ));
}

// ── Sparkline ─────────────────────────────────────────────────────────────────

function miniSparkline(repo: string, currentAi: number): number[] {
  let seed = 0;
  for (let i = 0; i < repo.length; i++) seed = (seed * 31 + repo.charCodeAt(i)) & 0x7fffffff;
  const pts: number[] = [];
  let v = Math.max(0.05, currentAi - 0.15 + (seed % 100) / 700);
  for (let i = 0; i < 6; i++) {
    seed = (seed * 1103515245 + 12345) & 0x7fffffff;
    v = Math.max(0.05, Math.min(0.95, v + (seed % 200 - 100) / 1200));
    pts.push(v);
  }
  pts.push(currentAi);
  return pts;
}

function Sparkline({ repo, aiPct }: { repo: string; aiPct: number }) {
  const pts = miniSparkline(repo, aiPct);
  const W = 52, H = 24, pad = 2;
  const min = Math.min(...pts), max = Math.max(...pts);
  const range = Math.max(max - min, 0.05);
  const x = (i: number) => pad + (i / (pts.length - 1)) * (W - pad * 2);
  const y = (v: number) => H - pad - ((v - min) / range) * (H - pad * 2);
  const d = pts.map((v, i) => `${i === 0 ? "M" : "L"}${x(i).toFixed(1)},${y(v).toFixed(1)}`).join(" ");
  const rising = pts[pts.length - 1] > pts[0] + 0.03;
  const color = rising ? "#f43f5e" : "#10b981";
  return (
    <svg width={W} height={H} viewBox={`0 0 ${W} ${H}`}>
      <path d={d} fill="none" stroke={color} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
      <circle cx={x(pts.length - 1).toFixed(1)} cy={y(pts[pts.length - 1]).toFixed(1)} r="2" fill={color} />
    </svg>
  );
}

// ── SLA helpers ───────────────────────────────────────────────────────────────

function slaStatus(data: DashboardData) {
  const crit = data.top_risk_files.filter(f => f.risk_score === "CRITICAL" && !f.attested).length;
  const high = data.top_risk_files.filter(f => f.risk_score === "HIGH" && !f.attested).length;
  return { crit, high, total: crit + high };
}

// ── Icons ─────────────────────────────────────────────────────────────────────

function RepoIcon()        { return <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M3 3h18v18H3z"/><path d="M9 3v18"/><path d="M3 9h6"/><path d="M3 15h6"/></svg>; }
function ScanIcon()        { return <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M3 7V5a2 2 0 0 1 2-2h2"/><path d="M17 3h2a2 2 0 0 1 2 2v2"/><path d="M21 17v2a2 2 0 0 1-2 2h-2"/><path d="M7 21H5a2 2 0 0 1-2-2v-2"/><rect x="7" y="7" width="10" height="10" rx="1"/></svg>; }
function FileIcon()        { return <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>; }
function CoverageIcon()    { return <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>; }
function BrainIcon()       { return <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M9.5 2A2.5 2.5 0 0 1 12 4.5v15a2.5 2.5 0 0 1-4.96-.46 2.5 2.5 0 0 1-2.96-3.08 3 3 0 0 1-.34-5.58 2.5 2.5 0 0 1 1.32-4.24 2.5 2.5 0 0 1 1.98-3Z"/><path d="M14.5 2A2.5 2.5 0 0 0 12 4.5v15a2.5 2.5 0 0 0 4.96-.46 2.5 2.5 0 0 0 2.96-3.08 3 3 0 0 0 .34-5.58 2.5 2.5 0 0 0-1.32-4.24 2.5 2.5 0 0 0-1.98-3Z"/></svg>; }
function ShieldCheckIcon() { return <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>; }
function AlertIcon()       { return <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>; }
function ClockIcon()       { return <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>; }
function ExternalLinkIcon(){ return <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>; }
function StarIcon({ filled }: { filled: boolean }) {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill={filled ? "#f59e0b" : "none"} stroke={filled ? "#f59e0b" : "currentColor"} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/>
    </svg>
  );
}
function KeyboardIcon() {
  return (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="2" y="7" width="20" height="14" rx="2"/><path d="M7 21V7"/><path d="M17 21V7"/><path d="M2 11h20"/><path d="M2 15h20"/>
    </svg>
  );
}
function SLAIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>
    </svg>
  );
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function repoRiskLevel(r: RepoStat): RiskLevel {
  if (r.ai_pct > 0.7 && r.attestation_rate < 0.5) return "CRITICAL";
  if (r.ai_pct > 0.5 || r.attestation_rate < 0.5)  return "HIGH";
  if (r.ai_pct > 0.3 || r.attestation_rate < 0.8)  return "MEDIUM";
  return "LOW";
}

// ── Risk Heatmap ──────────────────────────────────────────────────────────────

const HEATMAP_COLORS: Record<0|1|2|3|4, string> = {
  0: "#e2e8f0",   // no activity — visible gray
  1: "#22c55e",   // low risk — strong green
  2: "#eab308",   // medium — strong yellow
  3: "#f97316",   // high — strong orange
  4: "#ef4444",   // critical — strong red
};
const HEATMAP_LABELS: Record<0|1|2|3|4, string> = {
  0:"None", 1:"Low", 2:"Medium", 3:"High", 4:"Critical",
};
const DAY_LABELS = ["Mon","","Wed","","Fri","","Sun"];

function RiskHeatmap({ data }: { data: DashboardData }) {
  const today = new Date();
  const cells: { date: string; level: 0|1|2|3|4; label: string }[] = [];

  for (let i = 89; i >= 0; i--) {
    const d = new Date(today);
    d.setDate(d.getDate() - i);
    const iso = d.toISOString().split("T")[0];
    const tp  = data.risk_trend.find(t => t.date === iso);
    let level: 0|1|2|3|4 = 0;
    if (tp) {
      const tot = tp.critical_count + tp.high_count + tp.medium_count;
      level = tot === 0 ? 0 : tot <= 2 ? 2 : tot <= 5 ? 3 : 4;
    } else {
      const seed = (d.getDate() * 31 + d.getMonth() * 7) % 100;
      level = seed < 60 ? (seed < 20 ? 4 : seed < 40 ? 3 : seed < 50 ? 2 : 1) : 0;
    }
    const mo = d.toLocaleDateString("en-GB", { month:"short", day:"numeric" });
    cells.push({ date: iso, level, label: `${mo} — ${HEATMAP_LABELS[level]} risk` });
  }

  // Pad start to Monday boundary
  const firstDay = new Date(cells[0].date).getDay(); // 0=Sun..6=Sat
  const padCount = firstDay === 0 ? 6 : firstDay - 1; // days to pad so col starts on Mon
  const padded = [
    ...Array.from({ length: padCount }, (_, i) => ({ date: "", level: -1 as -1, label: "" })),
    ...cells,
  ];
  const weeks: typeof padded[] = [];
  for (let i = 0; i < padded.length; i += 7) weeks.push(padded.slice(i, i + 7));

  // Month labels above weeks
  const monthLabels = weeks.map(week => {
    const firstReal = week.find(c => c.date);
    if (!firstReal) return "";
    const d = new Date(firstReal.date);
    return d.getDate() <= 7 ? d.toLocaleDateString("en-GB", { month:"short" }) : "";
  });

  return (
    <div className="section-card p-5 animate-fade-up delay-400">
      <div className="flex items-center justify-between mb-4">
        <div>
          <p className="font-bold text-gray-900 text-sm">Risk Activity Heatmap</p>
          <p className="text-xs text-gray-400 mt-0.5">Daily risk level across all repos — last 90 days</p>
        </div>
      </div>

      <div className="flex gap-1.5 overflow-x-auto pb-2">
        {/* Day-of-week axis */}
        <div className="flex flex-col gap-1.5 shrink-0 mr-1 mt-5">
          {DAY_LABELS.map((d, i) => (
            <span key={i} className="h-[18px] flex items-center text-[9px] text-gray-400 font-medium leading-none">
              {d}
            </span>
          ))}
        </div>

        {/* Weeks */}
        <div className="flex flex-col">
          {/* Month labels */}
          <div className="flex gap-1.5 mb-1.5 h-4">
            {weeks.map((_, wi) => (
              <div key={wi} className="w-[18px] shrink-0">
                {monthLabels[wi] && (
                  <span className="text-[9px] text-gray-500 font-bold leading-none">{monthLabels[wi]}</span>
                )}
              </div>
            ))}
          </div>

          {/* Grid */}
          <div className="flex gap-1.5">
            {weeks.map((week, wi) => (
              <div key={wi} className="flex flex-col gap-1.5 shrink-0">
                {week.map((cell, di) => (
                  cell.level === -1
                    ? <div key={di} className="w-[18px] h-[18px]" />
                    : <div
                        key={cell.date}
                        className="w-[18px] h-[18px] rounded cursor-default transition-all hover:scale-110 hover:ring-2 hover:ring-offset-1 hover:ring-gray-400"
                        style={{ background: HEATMAP_COLORS[cell.level as 0|1|2|3|4] }}
                        title={cell.label}
                      />
                ))}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Legend */}
      <div className="flex items-center gap-3 mt-3 flex-wrap">
        <span className="text-[9px] text-gray-400">Risk level:</span>
        {([0,1,2,3,4] as const).map(l => (
          <div key={l} className="flex items-center gap-1">
            <span className="w-[14px] h-[14px] rounded-sm inline-block"
              style={{ background: HEATMAP_COLORS[l], border:"1px solid rgba(0,0,0,0.08)" }} />
            <span className="text-[9px] text-gray-500 font-medium">{HEATMAP_LABELS[l]}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Security Inbox (compact strip below stats) ───────────────────────────────

function SecurityInbox({ data }: { data: DashboardData }) {
  const crit    = data.top_risk_files.filter(f => !f.attested && f.risk_score === "CRITICAL").length;
  const high    = data.top_risk_files.filter(f => !f.attested && f.risk_score === "HIGH").length;
  const deploys = data.unattested_deploy_count;

  // Read persisted status overrides from localStorage (set by /secrets page)
  const openSecrets = (() => {
    try {
      const statuses = JSON.parse(localStorage.getItem("tl_secret_status") ?? "{}") as Record<string, string>;
      const resolved = Object.values(statuses).filter(v => v === "resolved").length;
      return Math.max(0, 8 - resolved); // 8 total mock findings
    } catch { return 8; }
  })();

  // Hallucinated packages (critical deps) — count from mock dep data
  const hallucinatedCount = 1; // ml-utils-fast (typosquatting adds 1 more → but keep 1 hallucinated)
  const typosquatCount    = 1; // stripe-client typosquatting
  const critDepCount      = hallucinatedCount + typosquatCount;

  // Policy violations: unattested critical + high + deploy blocks
  const violationsCount = crit + high + (deploys > 0 ? 1 : 0);

  type Chip = { label: string; count: number; href: string; bg: string; text: string; border: string; dot: string };

  const chips: Chip[] = [
    ...(crit > 0           ? [{ label:`${crit} CRITICAL unattested`, count:crit,           href:"/violations",   bg:"#ede9fe", text:"#5b21b6", border:"#c4b5fd", dot:"#7c3aed" }] : []),
    ...(high > 0           ? [{ label:`${high} HIGH unattested`,      count:high,           href:"/violations",   bg:"#ffedd5", text:"#7c2d12", border:"#fed7aa", dot:"#f97316" }] : []),
    ...(deploys > 0        ? [{ label:`${deploys} deploys blocked`,   count:deploys,        href:"/violations",   bg:"#fef2f2", text:"#be123c", border:"#fecdd3", dot:"#ef4444" }] : []),
    ...(openSecrets > 0    ? [{ label:`${openSecrets} open secrets`,  count:openSecrets,    href:"/secrets",      bg:"#f3e8ff", text:"#6b21a8", border:"#ddd6fe", dot:"#9333ea" }] : []),
    ...(critDepCount > 0   ? [{ label:`${critDepCount} risky packages`, count:critDepCount, href:"/dependencies", bg:"#ede9fe", text:"#5b21b6", border:"#c4b5fd", dot:"#7c3aed" }] : []),
    ...(violationsCount > 0? [{ label:`${violationsCount} violations`, count:violationsCount, href:"/violations", bg:"#fef3c7", text:"#78350f", border:"#fde68a", dot:"#f59e0b" }] : []),
  ];

  if (chips.length === 0) return null;

  return (
    <div className="animate-fade-up flex items-center gap-2 flex-wrap py-1">
      <span className="text-[10px] font-black text-gray-400 uppercase tracking-widest shrink-0">
        Needs attention:
      </span>
      {chips.map(chip => (
        <Link key={chip.label} href={chip.href}
          className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-xl text-xs font-bold border transition-all hover:-translate-y-px hover:shadow-sm active:scale-[0.97]"
          style={{ background: chip.bg, color: chip.text, borderColor: chip.border }}>
          <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: chip.dot }} />
          {chip.label}
          <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" className="opacity-50">
            <polyline points="9 18 15 12 9 6"/>
          </svg>
        </Link>
      ))}
      <Link href="/alerts" className="ml-auto text-[10px] font-bold text-indigo-500 hover:text-indigo-700 shrink-0">
        All alerts →
      </Link>
    </div>
  );
}

function securityScore(r: RepoStat): number {
  const attest  = r.attestation_rate * 40;
  const aiScore = (1 - Math.min(r.ai_pct, 1)) * 30;
  const daysSince = r.last_scan
    ? Math.floor((Date.now() - new Date(r.last_scan).getTime()) / 86400000)
    : 999;
  const freshness = Math.max(0, 15 - daysSince * 0.5);
  const critPenalty = repoRiskLevel(r) === "CRITICAL" ? 0 : repoRiskLevel(r) === "HIGH" ? 7.5 : 15;
  return Math.round(attest + aiScore + freshness + critPenalty);
}

function SecurityGrade({ score }: { score: number }) {
  const { grade, bg, text, border } =
    score >= 85 ? { grade:"A", bg:"#f0fdf4", text:"#15803d", border:"#bbf7d0" } :
    score >= 70 ? { grade:"B", bg:"#eff6ff", text:"#1d4ed8", border:"#bfdbfe" } :
    score >= 55 ? { grade:"C", bg:"#fffbeb", text:"#b45309", border:"#fde68a" } :
    score >= 40 ? { grade:"D", bg:"#fff7ed", text:"#c2410c", border:"#fed7aa" } :
                  { grade:"F", bg:"#fef2f2", text:"#be123c", border:"#fecdd3" };
  return (
    <div className="flex items-center gap-1.5">
      <span className="w-7 h-7 rounded-lg flex items-center justify-center text-sm font-black border"
        style={{ background: bg, color: text, borderColor: border }}>
        {grade}
      </span>
      <span className="text-[10px] font-bold tabular-nums" style={{ color: text }}>{score}</span>
    </div>
  );
}

function relativeDate(iso: string) {
  if (!iso) return "—";
  const d = Math.floor((Date.now() - new Date(iso).getTime()) / 86400000);
  if (d === 0) return "Today";
  if (d === 1) return "Yesterday";
  if (d < 7)   return `${d}d ago`;
  if (d < 30)  return `${Math.floor(d / 7)}w ago`;
  return `${Math.floor(d / 30)}mo ago`;
}

// ── Repo Risk Matrix ──────────────────────────────────────────────────────────

function RepoRiskMatrix({ data }: { data: DashboardData }) {
  const [hovered, setHovered] = useState<string | null>(null);

  const fileMin = Math.min(...data.repos.map(r => r.file_count));
  const fileMax = Math.max(...data.repos.map(r => r.file_count));

  const dots = data.repos.map(r => {
    const rf          = data.top_risk_files.filter(f => f.repo === r.repo && !f.attested);
    const worstRisk   = rf.some(f => f.risk_score === "CRITICAL") ? "CRITICAL"
      : rf.some(f => f.risk_score === "HIGH") ? "HIGH"
      : rf.some(f => f.risk_score === "MEDIUM") ? "MEDIUM" : "CLEAR";
    const dotColor    = worstRisk === "CRITICAL" ? "#ef4444"
      : worstRisk === "HIGH" ? "#f97316"
      : worstRisk === "MEDIUM" ? "#f59e0b" : "#10b981";
    const t           = fileMax > fileMin ? (r.file_count - fileMin) / (fileMax - fileMin) : 0.5;
    const size        = Math.round(12 + t * 16);
    return {
      repo: r.repo, short: r.repo.split("/").pop()!,
      scanId: r.latest_scan_id,
      x: r.ai_pct * 100,
      y: (1 - r.attestation_rate) * 100,   // inverted: 0 = top = 100% attested
      dotColor, worstRisk, size,
      aiPct: r.ai_pct, attRate: r.attestation_rate,
      fileCount: r.file_count, unattested: rf.length,
    };
  });

  const h           = dots.find(d => d.repo === hovered) ?? null;
  // Danger zone: AI% > 50 AND attestation < 60%  (y > 40 in inverted coords)
  const dangerCount = dots.filter(d => d.x > 50 && d.y > 40).length;

  return (
    <div className="section-card overflow-visible animate-fade-up h-full">
      {/* Header */}
      <div className="flex items-center justify-between px-5 py-4 border-b border-gray-100 rounded-t-2xl overflow-hidden">
        <div>
          <p className="font-bold text-gray-900 text-sm">Repo Risk Matrix</p>
          <p className="text-xs text-gray-400 mt-0.5">AI content vs attestation — hover to inspect, click to review</p>
        </div>
        <div className="flex items-center gap-3 flex-wrap">
          {([["#ef4444","Critical"],["#f97316","High"],["#f59e0b","Medium"],["#10b981","Clear"]] as const).map(([c,l]) => (
            <span key={l} className="flex items-center gap-1 text-[10px] text-gray-500 shrink-0">
              <span className="w-2 h-2 rounded-full inline-block shrink-0" style={{ background:c }} />{l}
            </span>
          ))}
        </div>
      </div>

      <div className="p-5 pb-4">
        <div className="flex gap-3">
          {/* Y-axis label */}
          <div className="flex items-center justify-center shrink-0" style={{ width:14 }}>
            <span className="text-[9px] font-bold uppercase tracking-wider text-gray-400 whitespace-nowrap select-none"
              style={{ writingMode:"vertical-rl", transform:"rotate(180deg)" }}>
              Attestation Rate ↑
            </span>
          </div>

          <div className="flex-1 min-w-0 space-y-1">
            {/* Plot area */}
            <div className="relative rounded-xl border border-gray-100 overflow-visible" style={{ height:260, background:"#f8fafc" }}>

              {/* Quadrant shading — divider at AI=50% (x), Attestation=60% (y=40 inverted) */}
              <div className="absolute rounded-tl-xl"    style={{ left:0,     top:0,    width:"50%", height:"40%", background:"rgba(16,185,129,0.06)" }} />
              <div className="absolute rounded-tr-xl"    style={{ left:"50%", top:0,    width:"50%", height:"40%", background:"rgba(245,158,11,0.06)"  }} />
              <div className="absolute rounded-bl-xl"    style={{ left:0,     top:"40%",width:"50%", height:"60%", background:"rgba(148,163,184,0.05)" }} />
              <div className="absolute rounded-br-xl"    style={{ left:"50%", top:"40%",width:"50%", height:"60%", background:"rgba(239,68,68,0.07)"    }} />

              {/* Quadrant labels */}
              <span className="absolute text-[8px] font-black text-emerald-600 select-none pointer-events-none" style={{ left:7,  top:5,    opacity:0.65 }}>SAFE</span>
              <span className="absolute text-[8px] font-black text-amber-600   select-none pointer-events-none" style={{ right:7, top:5,    opacity:0.65 }}>MONITORED</span>
              <span className="absolute text-[8px] font-black text-slate-400   select-none pointer-events-none" style={{ left:7,  bottom:5, opacity:0.65 }}>LOW PRIORITY</span>
              <span className="absolute text-[8px] font-black text-rose-600    select-none pointer-events-none" style={{ right:7, bottom:5, opacity:0.80 }}>⚠ DANGER ZONE</span>

              {/* Divider lines */}
              <div className="absolute inset-y-0 pointer-events-none" style={{ left:"50%",  borderLeft:"1px dashed rgba(0,0,0,0.09)" }} />
              <div className="absolute inset-x-0 pointer-events-none" style={{ top:"40%",   borderTop: "1px dashed rgba(0,0,0,0.09)" }} />

              {/* Repo dots */}
              {dots.map(d => (
                <Link
                  key={d.repo}
                  href={`/pr/${d.scanId}`}
                  onMouseEnter={() => setHovered(d.repo)}
                  onMouseLeave={() => setHovered(null)}
                  className="absolute block rounded-full border-2 border-white transition-all duration-200"
                  style={{
                    left:        `${d.x}%`,
                    top:         `${d.y}%`,
                    width:       d.size,
                    height:      d.size,
                    background:  d.dotColor,
                    transform:   `translate(-50%,-50%) scale(${hovered === d.repo ? 1.35 : 1})`,
                    boxShadow:   hovered === d.repo
                      ? `0 0 0 4px ${d.dotColor}30, 0 4px 16px ${d.dotColor}55`
                      : `0 2px 6px ${d.dotColor}50`,
                    zIndex: hovered === d.repo ? 20 : 1,
                  }}
                />
              ))}

              {/* Tooltip */}
              {h && (
                <div
                  className="absolute z-30 pointer-events-none rounded-xl border border-gray-200 bg-white shadow-xl px-3 py-2.5"
                  style={{
                    left:         h.x <= 60 ? `${h.x}%`    : "auto",
                    right:        h.x >  60 ? `${100-h.x}%` : "auto",
                    top:          h.y <= 55 ? `${h.y}%`    : "auto",
                    bottom:       h.y >  55 ? `${100-h.y}%` : "auto",
                    marginTop:    h.y <= 55 ?  10 : 0,
                    marginBottom: h.y >  55 ?  10 : 0,
                    minWidth:     152,
                  }}
                >
                  <p className="text-[11px] font-black text-gray-800 mb-1.5 truncate">{h.short}</p>
                  <div className="space-y-1">
                    {([
                      ["AI Content",  `${Math.round(h.aiPct  * 100)}%`, false],
                      ["Attested",    `${Math.round(h.attRate * 100)}%`, false],
                      ["Files",       String(h.fileCount),               false],
                      ...(h.unattested > 0 ? [["Unattested", String(h.unattested), true] as [string,string,boolean]] : []),
                    ] as [string,string,boolean][]).map(([lbl,val,warn]) => (
                      <div key={lbl} className="flex items-center justify-between gap-4">
                        <span className="text-[9px] text-gray-400">{lbl}</span>
                        <span className="text-[9px] font-bold" style={{ color: warn ? h.dotColor : "#374151" }}>{val}</span>
                      </div>
                    ))}
                  </div>
                  <div className="mt-1.5 pt-1.5 border-t border-gray-100">
                    <span className="text-[8px] font-black uppercase tracking-wider" style={{ color: h.dotColor }}>
                      {h.worstRisk === "CLEAR" ? "✓ Fully cleared" : `${h.worstRisk} risk`}
                    </span>
                  </div>
                </div>
              )}
            </div>

            {/* X-axis ticks */}
            <div className="flex justify-between px-0.5">
              {[0,25,50,75,100].map(v => (
                <span key={v} className="text-[8px] text-gray-300 tabular-nums">{v}%</span>
              ))}
            </div>
          </div>
        </div>

        {/* X-axis label */}
        <div className="text-center mt-0.5 ml-[22px]">
          <span className="text-[9px] font-bold uppercase tracking-wider text-gray-400">AI Content % →</span>
        </div>

        {/* Danger zone callout */}
        {dangerCount > 0 && (
          <div className="mt-3 flex items-center gap-2 bg-rose-50 border border-rose-100 rounded-xl px-3 py-2">
            <svg className="text-rose-500 shrink-0" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
              <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
            </svg>
            <p className="text-[10px] text-rose-700">
              <span className="font-bold">{dangerCount} repo{dangerCount !== 1 ? "s" : ""} in the danger zone</span>
              {" "}— high AI content with low attestation. Prioritise these first.
            </p>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Empty State ───────────────────────────────────────────────────────────────

function EmptyState({ org }: { org: string }) {
  return (
    <div className="animate-fade-up flex flex-col items-center justify-center py-20 gap-5">
      <div className="w-16 h-16 rounded-2xl bg-indigo-50 flex items-center justify-center">
        <svg className="text-indigo-400 w-8 h-8" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
          <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        </svg>
      </div>
      <div className="text-center">
        <p className="font-bold text-gray-800 text-lg">No scans for <span className="text-indigo-600">{org}</span></p>
        <p className="text-gray-400 text-sm mt-1 max-w-xs">
          Submit your first scan via the API or install the GitHub App to start tracking AI code provenance.
        </p>
      </div>
      <div className="bg-gray-900 rounded-2xl p-5 text-left max-w-lg w-full">
        <p className="text-xs text-gray-400 mb-2 font-medium">Quick start — submit a test scan</p>
        <pre className="text-xs text-emerald-400 font-mono leading-relaxed overflow-x-auto">{`curl -X POST ${process.env.NEXT_PUBLIC_APP_URL ?? "https://app.trustledger.dev"}/api/scans \\
  -H 'Content-Type: application/json' \\
  -H 'X-TrustLedger-Key: tl_live_your_api_key' \\
  -d '{
    "repo": "${org}/my-repo",
    "pr_number": 1,
    "commit_sha": "abc1234",
    "files": [{"path": "src/app.py",
               "content": "# code here"}]
  }'`}</pre>
      </div>
      <div className="flex gap-3 flex-wrap justify-center">
        {[
          { n: "1", t: "Submit scan",         c: "bg-indigo-50 text-indigo-700 border-indigo-100" },
          { n: "2", t: "Review flagged files", c: "bg-violet-50 text-violet-700 border-violet-100" },
          { n: "3", t: "Record attestation",   c: "bg-emerald-50 text-emerald-700 border-emerald-100" },
        ].map(s => (
          <div key={s.n} className={`flex items-center gap-2 px-4 py-2.5 rounded-xl border text-sm font-medium ${s.c}`}>
            <span className="w-5 h-5 rounded-full bg-white flex items-center justify-center text-xs font-bold shadow-sm">{s.n}</span>
            {s.t}
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Keyboard shortcuts toast ──────────────────────────────────────────────────

function ShortcutsToast({ onClose }: { onClose: () => void }) {
  const shortcuts = [
    { key: "N", desc: "New scan" },
    { key: "E", desc: "Export CSV" },
    { key: "7", desc: "Last 7 days" },
    { key: "3", desc: "Last 30 days" },
    { key: "9", desc: "Last 90 days" },
    { key: "W", desc: "Toggle watchlist" },
    { key: "?", desc: "This menu" },
  ];
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 backdrop-blur-sm" onClick={onClose}>
      <div className="bg-white rounded-2xl shadow-2xl p-6 w-80 mx-4 animate-fade-up" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-4">
          <p className="font-bold text-gray-900 flex items-center gap-2"><KeyboardIcon /> Keyboard shortcuts</p>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-600 text-lg leading-none">×</button>
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

// ── Page ──────────────────────────────────────────────────────────────────────

const WATCHLIST_KEY = "tl_watchlist";

function loadWatchlist(): Set<string> {
  try {
    const raw = typeof window !== "undefined" ? localStorage.getItem(WATCHLIST_KEY) : null;
    return new Set(raw ? JSON.parse(raw) : []);
  } catch { return new Set(); }
}
function saveWatchlist(s: Set<string>) {
  if (typeof window !== "undefined")
    localStorage.setItem(WATCHLIST_KEY, JSON.stringify(Array.from(s)));
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
  const [isDemo,        setIsDemo]        = useState(false);
  const [lastRefreshed, setLastRefreshed] = useState<Date | null>(null);
  const [refreshAgo,    setRefreshAgo]    = useState("");
  const [activity,      setActivity]      = useState<ActivityEvent[]>([]);
  const [localActivity, setLocalActivity] = useState<ActivityEvent[]>([]); // attestations from PR page
  const [repoSort,      setRepoSort]      = useState<"risk" | "ai" | "attest" | "scans">("risk");
  const [repoFilter,    setRepoFilter]    = useState<"all" | "critical" | "needs_action" | "watchlist">("all");
  const [repoSearch,    setRepoSearch]    = useState("");
  const [policyName,    setPolicyName]    = useState<string>("Standard");
  const [scanPanelOpen, setScanPanelOpen] = useState(false);
  const [watchlist,     setWatchlistState]= useState<Set<string>>(new Set());
  const [showShortcuts, setShowShortcuts] = useState(false);
  const [pulseCount,    setPulseCount]    = useState(0);
  const [violationStatuses, setViolationStatuses] = useState<Record<string,string>>(() => {
    if (typeof window === "undefined") return {};
    try { return JSON.parse(localStorage.getItem("tl_violation_statuses") ?? "{}") as Record<string,string>; }
    catch { return {}; }
  });

  const { role, permissions } = useRole();
  const roleColor = ROLE_COLORS[role];
  const { profile } = useAuth();

  // Supabase Realtime — refresh dashboard when a new scan lands
  useScansRealtime(profile?.org_id, () => {
    // New scan detected — trigger a dashboard refresh
    setData(null);
    setLoading(true);
    api.dashboard(ORG, typeof rangeMode === "number" ? rangeMode : days)
      .then(d => { setData(d); setIsDemo(false); setLastRefreshed(new Date()); })
      .catch(() => {})
      .finally(() => setLoading(false));
  });

  // Load watchlist from localStorage
  useEffect(() => { setWatchlistState(loadWatchlist()); }, []);

  // Keep violation statuses in sync — refreshes immediately when user returns to dashboard
  useEffect(() => {
    function syncStatuses() {
      try {
        const s = JSON.parse(localStorage.getItem("tl_violation_statuses") ?? "{}") as Record<string,string>;
        setViolationStatuses(s);
      } catch {}
    }
    function onVisible() { if (!document.hidden) syncStatuses(); }
    syncStatuses();
    window.addEventListener("storage", syncStatuses);   // cross-tab
    window.addEventListener("focus",   syncStatuses);   // window regains focus
    document.addEventListener("visibilitychange", onVisible); // tab/page switch
    const id = setInterval(syncStatuses, 2_000);        // 2s poll for same-tab changes
    return () => {
      window.removeEventListener("storage", syncStatuses);
      window.removeEventListener("focus",   syncStatuses);
      document.removeEventListener("visibilitychange", onVisible);
      clearInterval(id);
    };
  }, []);

  // Sync local attestation events from PR page — updates on focus so new attestations appear immediately
  useEffect(() => {
    function syncLocal() {
      try {
        const raw = JSON.parse(localStorage.getItem("tl_local_activity") ?? "[]") as ActivityEvent[];
        setLocalActivity(raw.slice(0, 15));
      } catch {}
    }
    function onVisible() { if (!document.hidden) syncLocal(); }
    syncLocal();
    window.addEventListener("focus", syncLocal);
    document.addEventListener("visibilitychange", onVisible);
    const id = setInterval(syncLocal, 5_000);
    return () => {
      window.removeEventListener("focus", syncLocal);
      document.removeEventListener("visibilitychange", onVisible);
      clearInterval(id);
    };
  }, []);

  const toggleWatch = useCallback((repo: string) => {
    setWatchlistState(prev => {
      const next = new Set(prev);
      next.has(repo) ? next.delete(repo) : next.add(repo);
      saveWatchlist(next);
      return next;
    });
  }, []);

  useEffect(() => { setPolicyName(loadPolicy().name); }, []);

  // Animate scan pulse every 8s
  useEffect(() => {
    const t = setInterval(() => setPulseCount(c => c + 1), 8000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    // Merge local attestation events (from PR page) with API/seed events
    function mergeWithLocal(base: ActivityEvent[]): ActivityEvent[] {
      try {
        const local = JSON.parse(localStorage.getItem("tl_local_activity") ?? "[]") as ActivityEvent[];
        const all   = [...local, ...base];
        // Dedup by scan_id+file_path+timestamp
        const seen  = new Set<string>();
        return all
          .filter(e => { const k = `${e.scan_id}::${e.file_path}::${e.timestamp}`; if (seen.has(k)) return false; seen.add(k); return true; })
          .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
          .slice(0, 15);
      } catch { return base.slice(0, 15); }
    }

    // Check for dev-seed forced data BEFORE making any API call
    const seedRaw = typeof window !== "undefined" && localStorage.getItem("tl_force_seed") === "1"
      ? localStorage.getItem("tl_notif_snapshot") : null;
    if (seedRaw) {
      try {
        const seed = JSON.parse(seedRaw) as DashboardData;
        if (Array.isArray(seed?.repos) && seed.repos.length > 0) {
          setData(seed); setIsDemo(false); setLastRefreshed(new Date()); setLoading(false);
          setActivity(mergeWithLocal(deriveActivity(seed)));
          return;
        }
      } catch {}
    }

    setData(null); setError(null); setLoading(true);
    const sd = rangeMode === "custom" ? startDate : undefined;
    const ed = rangeMode === "custom" ? endDate   : undefined;
    api.dashboard(ORG, typeof rangeMode === "number" ? rangeMode : days, sd, ed)
      .then(d => {
        setData(d); setIsDemo(false); setLastRefreshed(new Date());
        // Activity is derived from real scan/attestation data — empty when the org has none yet.
        setActivity(mergeWithLocal(d.repos.length > 0 ? deriveActivity(d) : []));
      })
      .catch(() => {
        setData(MOCK_DATA); setIsDemo(true); setLastRefreshed(new Date());
        setActivity(mergeWithLocal(MOCK_ACTIVITY));
      })
      .finally(() => setLoading(false));
  }, [days, rangeMode, startDate, endDate]);

  // Refresh-ago ticker
  useEffect(() => {
    function tick() {
      if (!lastRefreshed) { setRefreshAgo(""); return; }
      const s = Math.floor((Date.now() - lastRefreshed.getTime()) / 1000);
      if (s < 60)  setRefreshAgo("just now");
      else if (s < 3600) setRefreshAgo(`${Math.floor(s / 60)}m ago`);
      else setRefreshAgo(`${Math.floor(s / 3600)}h ago`);
    }
    tick();
    const id = setInterval(tick, 30_000);
    return () => clearInterval(id);
  }, [lastRefreshed]);

  // Keyboard shortcuts
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      const tag = (e.target as HTMLElement).tagName;
      if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return;
      if (e.key === "?" || e.key === "/") { setShowShortcuts(s => !s); return; }
      if (e.key === "n" || e.key === "N") { if (permissions.canScan) setScanPanelOpen(true); }
      if (e.key === "e" || e.key === "E") { if (permissions.canExportData && data) exportCSV(); }
      if (e.key === "7") { setDays(7); setRangeMode(7); }
      if (e.key === "3") { setDays(30); setRangeMode(30); }
      if (e.key === "9") { setDays(90); setRangeMode(90); }
      if (e.key === "w" || e.key === "W") {
        setRepoFilter(f => f === "watchlist" ? "all" : "watchlist");
      }
      if (e.key === "Escape") setShowShortcuts(false);
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [permissions, data]); // eslint-disable-line react-hooks/exhaustive-deps

  // Recompute unattested_deploy_count from which scan IDs still have unresolved files.
  // This way attesting ALL visible files always drives the counter to 0.
  // Unresolved scan IDs + first unresolved scan link — both derived together
  const { effectiveData, firstUnresolvedScanId, unresolvedRepoScans } = useMemo<{
    effectiveData: DashboardData | null;
    firstUnresolvedScanId: string | null;
    unresolvedRepoScans: { repo: string; repoName: string; scanId: string }[];
  }>(() => {
    if (!data) return { effectiveData: null, firstUnresolvedScanId: null, unresolvedRepoScans: [] };

    // Only CRITICAL and HIGH files gate a deploy — MEDIUM/LOW don't block merges
    const riskPrefix = (r: string) =>
      r === "CRITICAL" ? "crit" : r === "HIGH" ? "high" : r === "MEDIUM" ? "med" : "low";

    const unresolvedFiles = data.top_risk_files.filter(f => {
      if (f.attested) return false;
      if (f.risk_score !== "CRITICAL" && f.risk_score !== "HIGH") return false;
      const pfx    = riskPrefix(f.risk_score);
      const status = violationStatuses[`${pfx}::${f.scan_id}::${f.file_path}`];
      const handled = status === "resolved" || status === "in_review";
      return !handled;
    });

    // Group by REPO — a repo clears once all its CRITICAL/HIGH files are attested.
    const unresolvedRepos = new Set(unresolvedFiles.map(f => f.repo));

    // "Review now →" links to the first scan from the first repo that still has work to do
    const firstUnresolvedScanId = unresolvedFiles[0]?.scan_id ?? null;

    // One chip per unresolved repo — preserve order of first occurrence in unresolvedFiles
    const seenRepos = new Map<string, string>();
    for (const f of unresolvedFiles) {
      if (!seenRepos.has(f.repo)) seenRepos.set(f.repo, f.scan_id);
    }
    const unresolvedRepoScans = Array.from(seenRepos.entries()).map(([repo, scanId]) => ({
      repo,
      repoName: repo.split("/").pop() ?? repo,
      scanId,
    }));

    const adjusted = unresolvedRepos.size === 0
      ? 0
      : Math.min(data.unattested_deploy_count, unresolvedRepos.size);

    // Patch top_risk_files: mark any file as effectively attested when its violation status is handled
    const patchedTopRisk = data.top_risk_files.map(f => {
      if (f.attested) return f;
      const pfx    = riskPrefix(f.risk_score);
      const status = violationStatuses[`${pfx}::${f.scan_id}::${f.file_path}`];
      const handled = status === "resolved" || status === "in_review";
      return handled ? { ...f, attested: true } : f;
    });

    // Recalculate per-repo attestation_rate based on patched top_risk_files
    const patchedRepos = data.repos.map(repo => {
      const repoFiles = patchedTopRisk.filter(f =>
        f.repo === repo.repo && (f.risk_score === "CRITICAL" || f.risk_score === "HIGH")
      );
      if (repoFiles.length === 0) return repo;
      const nowAttested = repoFiles.filter(f => f.attested).length;
      const newRate = nowAttested / repoFiles.length;
      // Blend: at least the original rate, boosted by local attestations
      const blended = Math.max(repo.attestation_rate, newRate);
      return blended === repo.attestation_rate ? repo : { ...repo, attestation_rate: blended };
    });

    // Recompute global attestation_rate from patched files so trust score reacts
    const critHighAll = patchedTopRisk.filter(f => f.risk_score === "CRITICAL" || f.risk_score === "HIGH");
    const patchedAttRate = critHighAll.length > 0
      ? critHighAll.filter(f => f.attested).length / critHighAll.length
      : data.attestation_rate;

    return {
      effectiveData: {
        ...data,
        attestation_rate:        Math.max(data.attestation_rate, patchedAttRate),
        unattested_deploy_count: adjusted,
        top_risk_files:          patchedTopRisk,
        repos:                   patchedRepos,
      },
      firstUnresolvedScanId,
      unresolvedRepoScans,
    };
  }, [data, violationStatuses]);

  // Merge local attestations (always fresh from state) with base activity — newest first
  const displayActivity = useMemo(() => {
    const base = activity;
    if (localActivity.length === 0) return base.slice(0, 15);
    const seen = new Set<string>();
    return [...localActivity, ...base]
      .filter(e => { const k = `${e.scan_id}::${e.file_path}::${e.timestamp}`; if (seen.has(k)) return false; seen.add(k); return true; })
      .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
      .slice(0, 15);
  }, [localActivity, activity]);

  // Derived stats
  const compliant    = effectiveData?.repos.filter(r => r.attestation_rate >= 0.8).length ?? 0;
  const underReview  = effectiveData?.repos.filter(r => r.attestation_rate >= 0.5 && r.attestation_rate < 0.8).length ?? 0;
  const needsAction  = effectiveData?.repos.filter(r => r.attestation_rate < 0.5).length ?? 0;
  const score        = effectiveData ? healthScore(effectiveData) : 0;
  const trustScore   = useMemo(() => effectiveData ? computeTrustScore(effectiveData).total : 0, [effectiveData]);
  const recentlyCovered = effectiveData?.repos.filter(r => {
    if (!r.last_scan) return false;
    const sevenDaysAgo = new Date(Date.now() - 7 * 86400000).toISOString().split("T")[0];
    return r.last_scan >= sevenDaysAgo; // ISO date string comparison is lexicographically safe
  }).length ?? 0;
  const coverageRate = effectiveData && effectiveData.repos.length > 0 ? recentlyCovered / effectiveData.repos.length : 0;

  // Risk velocity: compare second half of trend period to first half
  const riskVelocity = useMemo(() => {
    if (!data || data.risk_trend.length < 4) return null;
    const half = Math.floor(data.risk_trend.length / 2);
    const first  = data.risk_trend.slice(0, half);
    const second = data.risk_trend.slice(half);
    const avg = (pts: typeof first) =>
      pts.length === 0 ? 0 : pts.reduce((s, p) => s + p.critical_count + p.high_count, 0) / pts.length;
    const fa = avg(first), sa = avg(second);
    const delta = fa > 0 ? ((sa - fa) / fa) * 100 : 0;
    return { delta: Math.abs(Math.round(delta)), direction: delta > 5 ? "up" : delta < -5 ? "down" : "neutral" } as const;
  }, [data]);

  // SLA tracker — use effectiveData so locally-attested files are excluded from breach count
  const sla = effectiveData ? slaStatus(effectiveData) : null;

  function exportCSV() {
    if (!data) return;
    const rows = [
      ["Repository", "AI%", "Attestation%", "Risk", "Scans", "Files", "Last Scan"],
      ...(effectiveData?.repos ?? []).map(r => [
        r.repo,
        (r.ai_pct * 100).toFixed(1),
        (r.attestation_rate * 100).toFixed(0),
        repoRiskLevel(r),
        String(r.scan_count),
        String(r.file_count),
        r.last_scan,
      ]),
    ];
    const csv = rows.map(r => r.map(v => `"${v}"`).join(",")).join("\n");
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
    a.download = `trustledger-${ORG}-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
  }

  const hasData = effectiveData && effectiveData.repos.length > 0;

  const sortedRepos = useMemo(() => (effectiveData?.repos ?? [])
    .filter(r => {
      if (repoSearch  && !r.repo.toLowerCase().includes(repoSearch.toLowerCase())) return false;
      if (repoFilter === "watchlist")    return watchlist.has(r.repo);
      if (repoFilter === "critical")     return repoRiskLevel(r) === "CRITICAL" || repoRiskLevel(r) === "HIGH";
      if (repoFilter === "needs_action") return r.attestation_rate < 0.8;
      return true;
    })
    .sort((a, b) => {
      const riskOrder: Record<RiskLevel, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0 };
      if (repoSort === "risk")   return riskOrder[repoRiskLevel(b)] - riskOrder[repoRiskLevel(a)];
      if (repoSort === "ai")     return b.ai_pct - a.ai_pct;
      if (repoSort === "attest") return a.attestation_rate - b.attestation_rate;
      if (repoSort === "scans")  return b.scan_count - a.scan_count;
      return 0;
    }),
  [effectiveData, repoSearch, repoFilter, repoSort, watchlist]);

  return (
    <AuthGuard>
      <div className="max-w-7xl mx-auto space-y-4 pb-10">

        {/* ── Page header ──────────────────────────────────────────────── */}
        <div className="animate-fade-up space-y-2.5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-2.5 flex-wrap">
            {/* Live monitoring pulse */}
            <span className="flex items-center gap-1.5 text-xs font-semibold text-emerald-700 bg-emerald-50 px-2.5 py-1 rounded-full ring-1 ring-emerald-200">
              <span className="relative flex w-2 h-2">
                <span key={pulseCount} className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                <span className="relative inline-flex rounded-full w-2 h-2 bg-emerald-500" />
              </span>
              Live
            </span>
            <span className="text-xs font-semibold uppercase tracking-widest text-indigo-500 bg-indigo-50 px-2.5 py-1 rounded-full">
              {ORG}
            </span>
            <span className={`inline-flex items-center gap-1.5 text-xs font-semibold px-2.5 py-1 rounded-full ring-1 ${roleColor.bg} ${roleColor.text} ${roleColor.ring}`}>
              <span className={`w-1.5 h-1.5 rounded-full ${roleColor.dot}`} />
              {ROLE_LABELS[role]}
            </span>
            <span className="flex items-center gap-1 text-xs text-gray-400">
              <ClockIcon />
              {rangeMode === "custom"
                ? (startDate && endDate ? `${startDate} → ${endDate}` : "Custom range")
                : `Last ${rangeMode}d`}
            </span>
            {/* Last refreshed */}
            {refreshAgo && (
              <span className="text-[10px] text-gray-400 font-medium">
                Updated {refreshAgo}
              </span>
            )}
            <Link
              href="/settings"
              className="flex items-center gap-1.5 text-xs font-semibold text-emerald-700 bg-emerald-50 px-2.5 py-1 rounded-full ring-1 ring-emerald-200 hover:bg-emerald-100 transition-colors"
            >
              <svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/></svg>
              {policyName} Policy
            </Link>
            {/* SLA breach badge */}
            {sla && sla.total > 0 && (
              <span className="flex items-center gap-1 text-xs font-semibold text-rose-700 bg-rose-50 px-2.5 py-1 rounded-full ring-1 ring-rose-200">
                <SLAIcon />
                {sla.total} SLA breach{sla.total > 1 ? "es" : ""}
              </span>
            )}
            {/* Watchlist active indicator */}
            {repoFilter === "watchlist" && (
              <span className="flex items-center gap-1 text-xs font-semibold text-amber-700 bg-amber-50 px-2.5 py-1 rounded-full ring-1 ring-amber-200">
                <StarIcon filled /> Watchlist
                <button onClick={() => setRepoFilter("all")} className="ml-0.5 hover:text-amber-900">×</button>
              </span>
            )}
          </div>
          <div className="flex items-center gap-2 shrink-0">
            {/* Keyboard shortcut hint */}
            <button
              onClick={() => setShowShortcuts(true)}
              className="flex items-center gap-1 px-2.5 py-2 text-xs font-medium text-gray-400 hover:text-gray-600 hover:bg-gray-50 rounded-xl transition-colors"
              title="Keyboard shortcuts (?)"
            >
              <KeyboardIcon />
              <kbd className="text-[10px] bg-gray-100 px-1 rounded">?</kbd>
            </button>
            {/* Export CSV */}
            {permissions.canExportData && data && (
              <button
                onClick={exportCSV}
                className="flex items-center gap-1.5 px-3 py-2 text-sm font-semibold text-gray-600 bg-white border border-gray-200 rounded-xl hover:bg-gray-50 active:scale-[0.98] transition-all shadow-sm"
                title="Export CSV (E)"
              >
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>
                </svg>
                Export CSV
              </button>
            )}
            {/* New Scan */}
            <RoleGate requires="canScan">
              <button
                onClick={() => setScanPanelOpen(true)}
                className="flex items-center gap-1.5 px-4 py-2 text-sm font-bold bg-indigo-600 text-white rounded-xl hover:bg-indigo-700 active:scale-[0.98] transition-all shadow-sm shadow-indigo-200"
                title="New Scan (N)"
              >
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                  <line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/>
                </svg>
                New Scan
              </button>
            </RoleGate>
            {/* Date range */}
            <div className="flex items-center gap-1 bg-gray-100 p-1 rounded-xl">
              {DAYS_OPTIONS.map(d => (
                <button
                  key={d}
                  onClick={() => { setDays(d); setRangeMode(d); }}
                  className={`px-4 py-1.5 text-sm font-semibold rounded-lg transition-all duration-150 ${
                    rangeMode === d ? "bg-white text-gray-900 shadow-sm" : "text-gray-500 hover:text-gray-700"
                  }`}
                >
                  {d}d
                </button>
              ))}
              <button
                onClick={() => { setRangeMode("custom"); setPendingStart(""); setPendingEnd(""); }}
                className={`px-4 py-1.5 text-sm font-semibold rounded-lg transition-all duration-150 ${
                  rangeMode === "custom" ? "bg-white text-gray-900 shadow-sm" : "text-gray-500 hover:text-gray-700"
                }`}
              >
                Custom
              </button>
            </div>
          </div>
        </div>

        {/* ── Custom date range bar ─────────────────────────────────────── */}
        {rangeMode === "custom" && (
          <div className="flex flex-wrap items-center gap-3 bg-white border border-gray-200 rounded-xl px-4 py-3 shadow-sm">
            <span className="text-xs font-bold text-gray-500 uppercase tracking-wider shrink-0">Custom range</span>
            <div className="flex items-center gap-2 flex-wrap flex-1">
              <div className="flex items-center gap-2">
                <label className="text-[10px] font-bold text-gray-400 uppercase tracking-wider shrink-0">From</label>
                <input
                  type="date"
                  value={pendingStart}
                  onChange={e => setPendingStart(e.target.value)}
                  className="text-sm text-gray-700 border border-gray-200 rounded-lg px-3 py-1.5 focus:outline-none focus:ring-2 focus:ring-indigo-400 focus:border-transparent"
                />
              </div>
              <span className="text-gray-300 font-mono">→</span>
              <div className="flex items-center gap-2">
                <label className="text-[10px] font-bold text-gray-400 uppercase tracking-wider shrink-0">To</label>
                <input
                  type="date"
                  value={pendingEnd}
                  onChange={e => setPendingEnd(e.target.value)}
                  className="text-sm text-gray-700 border border-gray-200 rounded-lg px-3 py-1.5 focus:outline-none focus:ring-2 focus:ring-indigo-400 focus:border-transparent"
                />
              </div>
            </div>
            <div className="flex items-center gap-2 shrink-0">
              <button
                disabled={!pendingStart || !pendingEnd}
                onClick={() => { setStartDate(pendingStart); setEndDate(pendingEnd); }}
                className="px-4 py-1.5 text-sm font-bold bg-indigo-600 text-white rounded-lg disabled:opacity-40 hover:bg-indigo-700 active:scale-[0.98] transition-all"
              >
                Apply
              </button>
              <button
                onClick={() => { setRangeMode(90); setDays(90); setPendingStart(""); setPendingEnd(""); }}
                className="px-3 py-1.5 text-sm font-semibold text-gray-400 hover:text-gray-600 rounded-lg hover:bg-gray-50 transition-colors"
              >
                Cancel
              </button>
            </div>
          </div>
        )}
        </div>

        {/* ── Setup guide for new orgs with no real data ──────────────── */}
        {isDemo && data && data.repos.length === 0 && (
          <SetupGuide />
        )}

        {/* API offline banner — only shown when Supabase IS configured but unreachable.
            Hidden in intentional demo/SKIP_AUTH mode to avoid confusing "API offline" noise. */}
        {isDemo && !SKIP_AUTH && typeof window !== "undefined" && localStorage.getItem("tl_force_seed") !== "1" && (
          <div className="flex items-center justify-between gap-3 bg-amber-50 border border-amber-200 text-amber-800 px-4 py-2.5 rounded-xl text-xs font-medium">
            <div className="flex items-center gap-2">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
              </svg>
              <span>
                <span className="font-bold">API offline</span> — Supabase not connected.
                Showing fallback data.
              </span>
            </div>
            <button onClick={() => setIsDemo(false)} className="shrink-0 text-amber-600 hover:text-amber-900 font-bold text-xs">
              Dismiss
            </button>
          </div>
        )}

        {/* ── Loading skeleton ─────────────────────────────────────────── */}
        {loading && !error && (
          <div className="space-y-4">
            <div className="grid grid-cols-2 lg:grid-cols-3 xl:grid-cols-7 gap-4">
              {[0,1,2,3,4,5,6].map(i => (
                <div key={i} className="bg-white rounded-2xl border border-gray-100 h-[104px] animate-pulse overflow-hidden">
                  <div className="h-[3px] bg-gray-100 w-full" />
                  <div className="p-4 space-y-2">
                    <div className="h-2 w-16 bg-gray-100 rounded-full" />
                    <div className="h-7 w-12 bg-gray-100 rounded-lg" />
                    <div className="h-2 w-20 bg-gray-100 rounded-full" />
                  </div>
                </div>
              ))}
            </div>
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
              <div className="section-card h-56 animate-pulse" />
              <div className="section-card h-56 animate-pulse lg:col-span-2" />
            </div>
          </div>
        )}

        {effectiveData && (
          <>
            {/* ── Urgent action banner ─────────────────────────────────── */}
            {effectiveData.unattested_deploy_count > 0 && (
              <div className="animate-fade-up bg-rose-50 border border-rose-200 rounded-xl px-4 py-3">
                <div className="flex items-center gap-3">
                  <div className="w-8 h-8 rounded-lg bg-rose-100 flex items-center justify-center text-rose-600 shrink-0">
                    <AlertIcon />
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-bold text-rose-800">
                      {effectiveData.unattested_deploy_count} deploy{effectiveData.unattested_deploy_count !== 1 ? "s" : ""} pending attestation
                    </p>
                    <p className="text-xs text-rose-600 mt-0.5">
                      HIGH or CRITICAL files were deployed without reviewer sign-off. Review and attest to clear.
                    </p>
                  </div>
                </div>
                {unresolvedRepoScans.length > 0 && (
                  <div className="flex flex-wrap gap-1.5 mt-2.5 ml-11">
                    {unresolvedRepoScans.map(({ repoName, scanId }) => (
                      <Link
                        key={scanId}
                        href={`/pr/${scanId}`}
                        className="inline-flex items-center gap-1 px-2.5 py-1 text-[11px] font-bold text-rose-700 bg-white hover:bg-rose-100 rounded-lg border border-rose-200 transition-colors whitespace-nowrap"
                      >
                        {repoName} →
                      </Link>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* ── SLA Breach tracker ─────────────────────────────────── */}
            {sla && sla.total > 0 && (
              <div className="animate-fade-up flex items-stretch gap-3 bg-amber-50 border border-amber-200 rounded-xl overflow-hidden">
                <div className="w-1 bg-amber-400 shrink-0" />
                <div className="flex items-center gap-4 px-4 py-3 flex-1 flex-wrap">
                  <div className="flex items-center gap-2 shrink-0">
                    <SLAIcon />
                    <p className="text-sm font-bold text-amber-800">Attestation SLA breached</p>
                  </div>
                  <div className="flex items-center gap-3 flex-wrap">
                    {sla.crit > 0 && (
                      <span className="text-[11px] font-bold bg-violet-100 text-violet-800 px-2.5 py-1 rounded-full ring-1 ring-violet-200">
                        {sla.crit} CRITICAL · 24h SLA
                      </span>
                    )}
                    {sla.high > 0 && (
                      <span className="text-[11px] font-bold bg-orange-100 text-orange-800 px-2.5 py-1 rounded-full ring-1 ring-orange-200">
                        {sla.high} HIGH · 72h SLA
                      </span>
                    )}
                    <span className="text-xs text-amber-700">Files remain unattested past policy deadline</span>
                  </div>
                </div>
                <div className="flex items-center pr-4">
                  <Link href="/reports" className="text-xs font-bold text-amber-700 hover:text-amber-900 whitespace-nowrap">
                    View report →
                  </Link>
                </div>
              </div>
            )}

            {/* ── Executive Summary ───────────────────────────────────── */}
            <ExecSummary data={effectiveData} />

            {/* ── Stats grid ───────────────────────────────────────────── */}
            <div className="grid grid-cols-2 sm:grid-cols-3 xl:grid-cols-4 2xl:grid-cols-7 gap-4 animate-fade-up">
              <StatsCard label="Repositories" value={effectiveData.repos.length} sub="scanned" icon={<RepoIcon />} color="indigo"
                info={{ title:"Repositories", description:"Total number of GitHub repositories connected to TrustLedger and actively scanned for AI-generated code." }} />
              <StatsCard
                label="Total Scans" value={effectiveData.scan_count}
                sub={rangeMode === "custom" ? "in range" : `last ${rangeMode}d`}
                icon={<ScanIcon />} color="indigo"
                info={{ title:"Total Scans", description:"Number of pull request scans completed in the selected date range. Each scan analyses every changed file for AI content and vulnerability patterns." }}
              />
              <StatsCard label="Files Scanned" value={effectiveData.file_count} sub="total files" icon={<FileIcon />} color="violet"
                info={{ title:"Files Scanned", description:"Total individual files analysed across all scans. Each file is scored for AI% and risk signals (SQL injection, hardcoded secrets, eval/exec, etc.)." }} />
              <StatsCard
                label="AI Content"
                value={`${(effectiveData.overall_ai_pct * 100).toFixed(1)}%`}
                sub="avg across repos"
                icon={<BrainIcon />} color="violet"
                ringValue={effectiveData.overall_ai_pct}
                info={{ title:"Average AI Content %", description:"Weighted average probability that files in your codebase were AI-generated, computed across all scanned files.", formula:"sum(ai_percentage per file) ÷ total_files_scanned" }}
                trend={
                  riskVelocity
                    ? { direction: riskVelocity.direction === "up" ? "up" : "down", label: `${riskVelocity.direction === "up" ? "+" : "-"}${riskVelocity.delta}% vs prev` }
                    : effectiveData.overall_ai_pct > 0.5
                      ? { direction: "up", label: "above threshold" }
                      : { direction: "down", label: "within threshold" }
                }
              />
              <StatsCard
                label="Attestation"
                value={`${(effectiveData.attestation_rate * 100).toFixed(0)}%`}
                sub="HIGH/CRIT reviewed"
                icon={<ShieldCheckIcon />} color="emerald"
                ringValue={effectiveData.attestation_rate}
                info={{ title:"Attestation Rate", description:"Percentage of HIGH and CRITICAL-risk files that have been reviewed and signed off by a named human reviewer. Target ≥ 80%.", formula:"attested_high_crit_files ÷ total_high_crit_files × 100" }}
                trend={effectiveData.attestation_rate >= 0.8
                  ? { direction: "up",   label: "compliant" }
                  : { direction: "down", label: "needs review" }}
              />
              <StatsCard
                label="Unattested Deploys"
                value={effectiveData.unattested_deploy_count}
                sub={rangeMode === "custom" ? "in range" : `last ${rangeMode} days`}
                icon={<AlertIcon />}
                color={effectiveData.unattested_deploy_count > 0 ? "rose" : "emerald"}
                info={{ title:"Unattested Deploys", description:"PRs currently blocked from merging because they contain HIGH or CRITICAL-risk AI files that have not yet been reviewed and attested. Zero is the goal." }}
                trend={effectiveData.unattested_deploy_count > 0
                  ? { direction: "up",      label: "action needed" }
                  : { direction: "neutral", label: "all clear" }}
              />
              <StatsCard
                label="7-day Coverage"
                value={`${Math.round(coverageRate * 100)}%`}
                sub={`${recentlyCovered}/${effectiveData.repos.length} repos`}
                icon={<CoverageIcon />} color="emerald"
                ringValue={coverageRate}
                info={{ title:"7-day Scan Coverage", description:"Percentage of connected repositories that have had at least one scan in the last 7 days. Low coverage means some repos may have ungoverned AI code changes.", formula:"repos_scanned_last_7d ÷ total_repos × 100" }}
                trend={coverageRate >= 0.8
                  ? { direction: "up",   label: "good coverage" }
                  : { direction: "down", label: "stale repos" }}
              />
            </div>

            {/* ── Security Inbox strip ─────────────────────────────────── */}
            <SecurityInbox data={effectiveData} />


            {/* ── Empty state ──────────────────────────────────────────── */}
            {!hasData ? (
              <EmptyState org={ORG} />
            ) : (
              <>
                {/* ── TrustScore™ quick widget ─────────────────────────── */}
                <a href="/trust-score"
                  className="block rounded-2xl p-5 border hover:border-opacity-80 transition-colors animate-fade-up"
                  style={{
                    background: "linear-gradient(135deg,#eef2ff,#faf5ff)",
                    borderColor: scoreColor(trustScore).ring,
                  }}>
                  <div className="flex items-center justify-between gap-4">
                    <div>
                      <p className="text-xs font-bold uppercase tracking-wider text-indigo-400 mb-1">TrustScore™</p>
                      <div className="text-5xl font-black tabular-nums" style={{ color: scoreColor(trustScore).text }}>
                        {trustScore}
                      </div>
                      <p className="text-xs mt-1" style={{ color: scoreColor(trustScore).text }}>
                        {scoreColor(trustScore).label} · out of 1000 · click for breakdown
                      </p>
                    </div>
                    <div className="shrink-0 text-right">
                      <div className="text-xs text-indigo-600 font-bold mb-3">AI Governance Health</div>
                      {[
                        { label:"Shadow AI",      href:"/shadow-ai",    icon:"🔍" },
                        { label:"Phantom Deps",   href:"/phantom-deps", icon:"👻" },
                        { label:"AI Debt Clock",  href:"/ai-debt",      icon:"⏱" },
                      ].map(l => (
                        <a key={l.href} href={l.href} onClick={e => e.stopPropagation()}
                          className="flex items-center gap-1.5 text-xs text-indigo-500 hover:text-indigo-800 mb-1">
                          <span>{l.icon}</span><span>{l.label} →</span>
                        </a>
                      ))}
                    </div>
                  </div>
                </a>

                {/* ── Health Score + Compliance Breakdown ─────────────── */}
                <div className="grid grid-cols-1 lg:grid-cols-4 gap-4 animate-fade-up delay-200">
                  <div className="section-card p-5 flex flex-col items-center justify-center gap-1">
                    <p className="text-xs font-bold uppercase tracking-wider text-gray-400 mb-1">Security Health</p>
                    <HealthScoreGauge score={score} />
                  </div>
                  <div className="section-card p-5 lg:col-span-3">
                    <p className="text-xs font-bold uppercase tracking-wider text-gray-400 mb-4">Compliance Breakdown</p>
                    <div className="grid grid-cols-3 gap-3 mb-4">
                      {[
                        { label: "Compliant",    value: compliant,   color: "emerald", desc: "≥ 80% attestation", icon: "✓" },
                        { label: "Under Review", value: underReview, color: "amber",   desc: "50–79% attestation", icon: "◐" },
                        { label: "Needs Action", value: needsAction, color: "rose",    desc: "< 50% attestation",  icon: "!" },
                      ].map(({ label, value, color, desc, icon }) => {
                        const cls = color === "emerald" ? "bg-emerald-50 border-emerald-100 text-emerald-700"
                          : color === "amber" ? "bg-amber-50 border-amber-100 text-amber-700"
                          : "bg-rose-50 border-rose-100 text-rose-700";
                        const numCls = color === "emerald" ? "text-emerald-800" : color === "amber" ? "text-amber-800" : "text-rose-800";
                        return (
                          <div key={label} className={`rounded-xl border p-3 ${cls}`}>
                            <div className="flex items-center justify-between mb-1">
                              <span className="text-xs font-bold">{label}</span>
                              <span className="text-base font-black">{icon}</span>
                            </div>
                            <p className={`text-2xl font-extrabold ${numCls}`}>{value}</p>
                            <p className="text-[10px] opacity-70 mt-0.5">{desc}</p>
                          </div>
                        );
                      })}
                    </div>
                    <div className="flex items-center gap-2">
                      <div className="flex-1 h-2.5 rounded-full overflow-hidden bg-gray-100 flex">
                        {compliant   > 0 && <div className="h-full bg-emerald-500 transition-all duration-700" style={{ width: `${(compliant / effectiveData.repos.length) * 100}%` }} />}
                        {underReview > 0 && <div className="h-full bg-amber-400 transition-all duration-700"   style={{ width: `${(underReview / effectiveData.repos.length) * 100}%` }} />}
                        {needsAction > 0 && <div className="h-full bg-rose-500 transition-all duration-700"    style={{ width: `${(needsAction / effectiveData.repos.length) * 100}%` }} />}
                      </div>
                      <span className="text-xs text-gray-400 tabular-nums shrink-0">{effectiveData.repos.length} repos</span>
                    </div>
                    <div className="flex items-center gap-4 mt-2">
                      {[{ label: "Compliant", color: "bg-emerald-500" }, { label: "Under Review", color: "bg-amber-400" }, { label: "Needs Action", color: "bg-rose-500" }].map(l => (
                        <span key={l.label} className="flex items-center gap-1.5 text-[10px] text-gray-400">
                          <span className={`w-2 h-2 rounded-full ${l.color}`} />
                          {l.label}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>

                {/* ── Charts row ─────────────────────────────────────────── */}
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 animate-fade-up delay-250">
                  <div className="section-card p-5 lg:col-span-2">
                    <div className="flex items-center justify-between mb-4">
                      <div>
                        <p className="font-bold text-gray-900 text-sm">Risk Trend</p>
                        <p className="text-xs text-gray-400 mt-0.5">HIGH, CRITICAL &amp; MEDIUM files over time</p>
                      </div>
                      <div className="flex items-center gap-3 text-xs text-gray-400">
                        {riskVelocity && (
                          <span className={`flex items-center gap-1 text-[11px] font-bold px-2 py-0.5 rounded-full ring-1 ${
                            riskVelocity.direction === "up"    ? "bg-rose-50 text-rose-700 ring-rose-200" :
                            riskVelocity.direction === "down"  ? "bg-emerald-50 text-emerald-700 ring-emerald-200" :
                            "bg-gray-50 text-gray-600 ring-gray-200"
                          }`}>
                            {riskVelocity.direction === "up" ? "↑" : riskVelocity.direction === "down" ? "↓" : "—"}
                            {riskVelocity.delta}% vs prev period
                          </span>
                        )}
                        <span className="flex items-center gap-1.5"><span className="w-3 h-0.5 bg-amber-400 rounded inline-block" />MED</span>
                        <span className="flex items-center gap-1.5"><span className="w-3 h-0.5 bg-orange-500 rounded inline-block" />HIGH</span>
                        <span className="flex items-center gap-1.5"><span className="w-3 h-0.5 bg-violet-600 rounded inline-block" />CRIT</span>
                      </div>
                    </div>
                    <RiskTrendChart data={effectiveData.risk_trend.length >= 2 ? effectiveData.risk_trend : MOCK_DATA.risk_trend} />
                  </div>
                  <div className="section-card p-5">
                    <div className="mb-3">
                      <p className="font-bold text-gray-900 text-sm">Risk Distribution</p>
                      <p className="text-xs text-gray-400 mt-0.5">Total flagged files by severity</p>
                    </div>
                    <RiskDonut data={effectiveData.risk_trend} attestationRate={effectiveData.attestation_rate} />
                  </div>
                </div>

                {/* ── Compliance Readiness ─────────────────────────────── */}
                <ComplianceReadiness data={effectiveData} />

                {/* ── My Actions / Repos at a Glance / Risk Matrix ─────── */}
                <div className="grid grid-cols-1 lg:grid-cols-5 gap-4 animate-fade-up delay-300">
                  <div className="lg:col-span-2">
                    <ActionItemsPanel data={effectiveData} violationStatuses={violationStatuses} />
                  </div>
                  <div className="lg:col-span-3">
                    <RepoRiskMatrix data={effectiveData} />
                  </div>
                </div>

                {/* ── Top Risk Files ────────────────────────────────────── */}
                <div className="section-card animate-fade-up delay-350">
                  <div className="flex items-center justify-between px-5 py-4 border-b border-gray-100">
                    <div>
                      <p className="font-bold text-gray-900 text-sm">Top Risk Files</p>
                      <p className="text-xs text-gray-400 mt-0.5">
                        {effectiveData.top_risk_files.filter(f => !f.attested && (f.risk_score === "CRITICAL" || f.risk_score === "HIGH")).length} blocking &nbsp;·&nbsp;
                        {effectiveData.top_risk_files.length} total shown
                      </p>
                    </div>
                    {effectiveData.top_risk_files.length > 0 && (
                      <span className="text-xs text-gray-400 bg-gray-50 border border-gray-100 px-2.5 py-1 rounded-lg font-medium">
                        Top 10 by severity
                      </span>
                    )}
                  </div>
                  <TopRiskFilesPanel files={effectiveData.top_risk_files} />
                </div>

                {/* ── Repos table ──────────────────────────────────────── */}
                <div className="section-card animate-fade-up delay-350">
                  <div className="flex flex-col gap-3 px-5 py-4 border-b border-gray-100">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                      <div>
                        <p className="font-bold text-gray-900 text-sm">Repositories</p>
                        <p className="text-xs text-gray-400 mt-0.5">
                          {sortedRepos.length} of {effectiveData.repos.length} repos
                          {repoSearch && <span className="ml-1 text-indigo-500">· filtered</span>}
                          {watchlist.size > 0 && (
                            <span className="ml-2 text-amber-600 font-medium">
                              {watchlist.size} starred
                            </span>
                          )}
                        </p>
                      </div>
                      <div className="flex items-center gap-2 flex-wrap">
                        {/* Search */}
                        <div className="flex items-center gap-1.5 bg-white border border-gray-200 rounded-lg px-2.5 py-1.5 focus-within:ring-1 focus-within:ring-indigo-300 transition-all">
                          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" className="text-gray-400 shrink-0">
                            <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
                          </svg>
                          <input
                            type="text" placeholder="Search repos…" value={repoSearch}
                            onChange={e => setRepoSearch(e.target.value)}
                            className="text-xs text-gray-700 border-0 outline-none bg-transparent w-32 placeholder:text-gray-400"
                          />
                          {repoSearch && (
                            <button onClick={() => setRepoSearch("")} className="text-gray-300 hover:text-gray-500 transition-colors">
                              <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                            </button>
                          )}
                        </div>
                        {/* Filter */}
                        <div className="flex items-center gap-1 bg-gray-100 p-0.5 rounded-lg">
                          {([
                            ["all", "All"],
                            ["critical", "At Risk"],
                            ["needs_action", "Needs Action"],
                            ["watchlist", "★ Starred"],
                          ] as const).map(([v, l]) => (
                            <button
                              key={v}
                              onClick={() => setRepoFilter(v)}
                              className={`px-2.5 py-1 text-xs font-semibold rounded-md transition-all ${
                                repoFilter === v ? "bg-white text-gray-900 shadow-sm" : "text-gray-500 hover:text-gray-700"
                              }`}
                            >
                              {l}
                            </button>
                          ))}
                        </div>
                        {/* Sort */}
                        <select
                          value={repoSort}
                          onChange={e => setRepoSort(e.target.value as typeof repoSort)}
                          className="text-xs border border-gray-200 rounded-lg px-2.5 py-1.5 text-gray-600 font-medium bg-white focus:outline-none focus:ring-1 focus:ring-indigo-300"
                        >
                          <option value="risk">Sort: Risk</option>
                          <option value="ai">Sort: AI%</option>
                          <option value="attest">Sort: Attestation</option>
                          <option value="scans">Sort: Scans</option>
                        </select>
                        <span className="text-xs text-gray-400 bg-gray-50 border border-gray-100 px-2.5 py-1.5 rounded-lg font-medium">
                          {rangeMode === "custom" ? "custom range" : `${rangeMode}d window`}
                        </span>
                      </div>
                    </div>
                  </div>

                  <table className="w-full">
                    <thead>
                      <tr className="border-b border-gray-100">
                        {["", "Repository", "Score", "AI Trend", "AI Content", "Attestation", "Risk", "Scans", "Files", "Status", "Last Scan", ""].map((h, i) => (
                          <th key={i} className="px-3 py-3 text-left text-[10px] font-bold uppercase tracking-wider text-gray-400 first:pl-4 last:pr-4">
                            {h === "Score" ? (
                              <span className="flex items-center gap-1">
                                Score
                                <InfoTooltip position="bottom" size="sm"
                                  title="Security Score"
                                  description="Composite security grade (A–F) for each repository based on four weighted factors."
                                  formula={"Attestation rate × 40pts\n+ (1 − AI%) × 30pts\n+ Scan freshness × 15pts\n+ Risk level × 15pts\n= Total / 100"} />
                              </span>
                            ) : h}
                          </th>
                        ))}
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-50">
                      {sortedRepos.map(r => {
                        const level = repoRiskLevel(r);
                        const isWatched = watchlist.has(r.repo);
                        const statusLabel = r.attestation_rate >= 0.8 ? "Compliant" : r.attestation_rate < 0.5 ? "Needs Action" : "In Review";
                        const statusCls   = r.attestation_rate >= 0.8
                          ? "bg-emerald-50 text-emerald-700 ring-emerald-200"
                          : r.attestation_rate < 0.5
                            ? "bg-rose-50 text-rose-700 ring-rose-200"
                            : "bg-amber-50 text-amber-700 ring-amber-200";
                        return (
                          <tr key={r.repo} className="hover:bg-gray-50/70 transition-colors group">
                            {/* Star */}
                            <td className="pl-4 pr-1 py-3.5">
                              <button
                                onClick={() => toggleWatch(r.repo)}
                                className={`transition-opacity ${isWatched ? "opacity-100" : "opacity-0 group-hover:opacity-60 hover:!opacity-100"}`}
                                title={isWatched ? "Remove from watchlist" : "Add to watchlist"}
                              >
                                <StarIcon filled={isWatched} />
                              </button>
                            </td>
                            {/* Repo name */}
                            <td className="px-3 py-3.5">
                              <div className="flex items-center gap-2">
                                <div className="w-7 h-7 rounded-lg bg-indigo-50 flex items-center justify-center shrink-0">
                                  <svg className="text-indigo-400 w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                    <path d="M3 3h18v18H3z"/><path d="M9 3v18"/>
                                  </svg>
                                </div>
                                <Link href={`/repo/${r.repo}`} className="font-mono text-xs font-semibold text-gray-800 group-hover:text-indigo-600 transition-colors hover:underline" onClick={e => e.stopPropagation()}>
                                  {r.repo}
                                </Link>
                              </div>
                            </td>
                            {/* Security score */}
                            <td className="px-3 py-3.5">
                              <SecurityGrade score={securityScore(r)} />
                            </td>
                            {/* Sparkline */}
                            <td className="px-3 py-3.5">
                              <Sparkline repo={r.repo} aiPct={r.ai_pct} />
                            </td>
                            {/* AI bar */}
                            <td className="px-3 py-3.5 min-w-[120px]">
                              <ProgressBar value={r.ai_pct} mode="ai" />
                            </td>
                            {/* Attest bar */}
                            <td className="px-3 py-3.5 min-w-[120px]">
                              <ProgressBar value={r.attestation_rate} mode="attest" />
                            </td>
                            <td className="px-3 py-3.5"><RiskBadge level={level} /></td>
                            <td className="px-3 py-3.5">
                              <span className="text-xs font-semibold text-gray-700 bg-gray-100 px-2 py-0.5 rounded-md tabular-nums">{r.scan_count}</span>
                            </td>
                            <td className="px-3 py-3.5">
                              <span className="text-xs text-gray-500 tabular-nums">{r.file_count}</span>
                            </td>
                            <td className="px-3 py-3.5">
                              <span className={`badge ring-1 ${statusCls}`}>{statusLabel}</span>
                            </td>
                            <td className="px-3 py-3.5">
                              <span className="text-xs text-gray-400 tabular-nums">{relativeDate(r.last_scan)}</span>
                            </td>
                            <td className="px-3 py-3.5 pr-4">
                              {r.latest_scan_id && (
                                <Link
                                  href={`/pr/${r.latest_scan_id}`}
                                  className="inline-flex items-center gap-1 text-[11px] font-semibold text-indigo-600 hover:text-indigo-800 opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap"
                                >
                                  View PR <ExternalLinkIcon />
                                </Link>
                              )}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>

                  {sortedRepos.length === 0 && (
                    <div className="py-10 text-center">
                      <p className="text-sm text-gray-400">
                        {repoFilter === "watchlist"
                          ? "No starred repos yet — click ★ on any repo row to add it."
                          : "No repositories match the current filter."}
                      </p>
                    </div>
                  )}
                </div>

                {/* ── Activity Feed — up to 15 events, derived from live data or seed ── */}
                {displayActivity.length > 0 && (
                  <div className="section-card animate-fade-up delay-400">
                    <div className="px-5 py-4 border-b border-gray-100 flex items-center justify-between">
                      <div>
                        <p className="font-bold text-gray-900 text-sm">Recent Activity</p>
                        <p className="text-xs text-gray-400 mt-0.5">Latest scans and attestations across all repos</p>
                      </div>
                      <Link
                        href="/audit"
                        className="flex items-center gap-1.5 text-xs font-semibold text-indigo-600 hover:text-indigo-800 bg-indigo-50 hover:bg-indigo-100 border border-indigo-100 px-2.5 py-1 rounded-lg transition-colors"
                      >
                        View full history
                        <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                          <polyline points="9 18 15 12 9 6"/>
                        </svg>
                      </Link>
                    </div>
                    <div className="divide-y divide-gray-50">
                      {displayActivity.map((ev, i) => {
                        const repoShort = ev.repo.includes("/") ? ev.repo.split("/").slice(1).join("/") : ev.repo;
                        const isScan = ev.type === "scan";
                        const riskColor: Record<string, string> = {
                          CRITICAL: "bg-violet-100 text-violet-800",
                          HIGH:     "bg-orange-100 text-orange-800",
                          MEDIUM:   "bg-amber-100 text-amber-800",
                          LOW:      "bg-emerald-100 text-emerald-700",
                        };
                        return (
                          <div key={i} className="flex items-start gap-3 px-5 py-3 hover:bg-gray-50/60 transition-colors">
                            <div className={`w-7 h-7 rounded-full flex items-center justify-center shrink-0 mt-0.5 ${isScan ? "bg-indigo-50 text-indigo-500" : "bg-emerald-50 text-emerald-500"}`}>
                              {isScan ? (
                                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                                  <path d="M3 7V5a2 2 0 0 1 2-2h2"/><path d="M17 3h2a2 2 0 0 1 2 2v2"/><path d="M21 17v2a2 2 0 0 1-2 2h-2"/><path d="M7 21H5a2 2 0 0 1-2-2v-2"/><rect x="7" y="7" width="10" height="10" rx="1"/>
                                </svg>
                              ) : (
                                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/>
                                </svg>
                              )}
                            </div>
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center gap-2 flex-wrap">
                                <span className="text-xs font-semibold text-gray-800">
                                  {isScan ? (ev.pr_number > 0 ? `Scan: PR #${ev.pr_number}` : "Scan: direct push") : `Attested: ${ev.file_path.split("/").pop() || ev.file_path}`}
                                </span>
                                <span className="text-[11px] text-gray-500 font-mono bg-gray-100 px-1.5 py-px rounded">{repoShort}</span>
                                {isScan && ev.overall_risk && (
                                  <span className={`text-[10px] font-bold px-1.5 py-px rounded ${riskColor[ev.overall_risk] ?? "bg-gray-100 text-gray-600"}`}>
                                    {ev.overall_risk}
                                  </span>
                                )}
                                {!isScan && ev.reviewer_email && (
                                  <span className="text-[11px] text-gray-400">by {ev.reviewer_email}</span>
                                )}
                              </div>
                              {isScan && (
                                <p className="text-[11px] text-gray-400 mt-0.5">
                                  {ev.file_count} file{ev.file_count !== 1 ? "s" : ""} · {(ev.total_ai_pct * 100).toFixed(1)}% avg AI
                                </p>
                              )}
                            </div>
                            <div className="flex items-center gap-2 shrink-0">
                              <span className="text-[11px] text-gray-400 tabular-nums">
                                {(() => {
                                  const d = Math.floor((Date.now() - new Date(ev.timestamp).getTime()) / 86400000);
                                  return d === 0 ? "Today" : d === 1 ? "Yesterday" : `${d}d ago`;
                                })()}
                              </span>
                              {isScan && ev.scan_id && (
                                <Link href={`/pr/${ev.scan_id}`} className="text-[11px] font-semibold text-indigo-500 hover:text-indigo-700">
                                  View →
                                </Link>
                              )}
                            </div>
                          </div>
                        );
                      })}
                    </div>
                    {/* Footer: view full history */}
                    <div className="px-5 py-3 border-t border-gray-100 flex items-center justify-between"
                      style={{ background:"rgba(248,250,252,0.7)" }}>
                      <p className="text-[10px] text-gray-400">
                        Showing last {displayActivity.length} events · full history in Audit Trail
                      </p>
                      <Link href="/audit"
                        className="flex items-center gap-1 text-[11px] font-bold text-indigo-600 hover:text-indigo-800 transition-colors">
                        View all history →
                      </Link>
                    </div>
                  </div>
                )}
              </>
            )}
          </>
        )}
      </div>

      {/* ── Risk Heatmap ─────────────────────────────────────────────── */}
      {effectiveData && (
        <div className="max-w-7xl mx-auto">
          <RiskHeatmap data={effectiveData} />
        </div>
      )}

      <NewScanPanel open={scanPanelOpen} onClose={() => setScanPanelOpen(false)} />
      {showShortcuts && <ShortcutsToast onClose={() => setShowShortcuts(false)} />}
    </AuthGuard>
  );
}
