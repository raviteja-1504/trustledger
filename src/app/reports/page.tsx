"use client";

import { useState, useEffect, useCallback, useMemo, Suspense } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import type { ReactNode, CSSProperties } from "react";
import Link from "next/link";
import AuthGuard from "@/components/AuthGuard";
import { formatDateTime, formatDateOnly, relativeTime, useTimezone, getSavedTimezone } from "@/lib/timezone";
import type { DashboardData } from "@/types";
import { api } from "@/lib/api";
import { authedFetch } from "@/lib/useRealData";
import { readLocalStatuses } from "@/lib/localStatuses";
import { loadStatuses } from "@/lib/violationStatuses";
import { useAuth } from "@/lib/auth";
import { BrandWordmark } from "@/components/BrandLogo";
import {
  STATUS_LABEL, frameworkById, normalizeFrameworkId,
  type CheckResult, type ComplianceFacts, type EvidenceStatus, type FrameworkDef as EvidenceFramework,
} from "@/lib/controlEvidence";

type EvidenceFrameworkId = EvidenceFramework["id"];

// ─── Constants ────────────────────────────────────────────────────────────────

const BASE_URL = "";

const FRAMEWORKS = ["SOC 2", "ISO 27001", "PCI DSS", "AI governance"] as const;
type Framework = (typeof FRAMEWORKS)[number];

// /api/report and /api/evidence/collect ids (lib/controlEvidence.ts normalizeFrameworkId).
const API_FRAMEWORK_ID: Record<Framework, string> = {
  "SOC 2": "SOC2", "ISO 27001": "ISO27001", "PCI DSS": "PCIDSS", "AI governance": "AIGOV",
};
const EVIDENCE_ID: Record<Framework, EvidenceFrameworkId> = {
  "SOC 2": "soc2", "ISO 27001": "iso27001", "PCI DSS": "pcidss", "AI governance": "aigov",
};

/** ?fw= values, including the old labels ("SOC2", "PCI-DSS", "EU AI Act") that links elsewhere still use. */
function frameworkFromParam(p: string | null | undefined): Framework {
  if (!p) return "SOC 2";
  const id = normalizeFrameworkId(p);
  return (Object.keys(EVIDENCE_ID) as Framework[]).find(k => EVIDENCE_ID[k] === id) ?? "SOC 2";
}

// ─── Framework presentation (names, scope and controls come from lib/controlEvidence.ts) ─────────

interface FwDef {
  shortName:   string;
  fullName:    string;
  standard:    string;
  tagline:     string;
  scopeNote:   string;          // explicit "what this does / doesn't cover" disclaimer
  color:       string;          // primary hex
  colorDark:   string;
  gradientCss: string;
  headerBg:    string;
  accentBg:    string;
  icon:        ReactNode;
}

const FW_STYLE: Record<Framework, Omit<FwDef, "shortName" | "fullName" | "standard" | "scopeNote">> = {
  "SOC 2": {
    tagline:     "Change management & vulnerability management evidence",
    color:       "#6366f1",
    colorDark:   "#4338ca",
    gradientCss: "linear-gradient(135deg,#6366f1,#7c3aed)",
    headerBg:    "linear-gradient(135deg,#0f172a 0%,#1e1b4b 60%,#0f172a 100%)",
    accentBg:    "rgba(99,102,241,0.07)",
    icon: (
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
        <polyline points="9 12 11 14 15 10"/>
      </svg>
    ),
  },
  "ISO 27001": {
    tagline:     "Secure development & logging evidence (Annex A)",
    color:       "#8b5cf6",
    colorDark:   "#6d28d9",
    gradientCss: "linear-gradient(135deg,#8b5cf6,#6366f1)",
    headerBg:    "linear-gradient(135deg,#0f172a 0%,#2e1065 60%,#0f172a 100%)",
    accentBg:    "rgba(139,92,246,0.07)",
    icon: (
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
      </svg>
    ),
  },
  "PCI DSS": {
    tagline:     "Code review & secure development evidence (Req. 6 and 10)",
    color:       "#10b981",
    colorDark:   "#047857",
    gradientCss: "linear-gradient(135deg,#10b981,#0d9488)",
    headerBg:    "linear-gradient(135deg,#0f172a 0%,#042f2e 60%,#0f172a 100%)",
    accentBg:    "rgba(16,185,129,0.07)",
    icon: (
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <rect x="1" y="4" width="22" height="16" rx="2" ry="2"/>
        <line x1="1" y1="10" x2="23" y2="10"/>
      </svg>
    ),
  },
  "AI governance": {
    tagline:     "Approved AI tools, human review & provenance of AI-written code",
    color:       "#0ea5e9",
    colorDark:   "#0369a1",
    gradientCss: "linear-gradient(135deg,#0ea5e9,#6366f1)",
    headerBg:    "linear-gradient(135deg,#0f172a 0%,#0c2340 60%,#0f172a 100%)",
    accentBg:    "rgba(14,165,233,0.07)",
    icon: (
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/>
        <line x1="9" y1="1" x2="9" y2="4"/><line x1="15" y1="1" x2="15" y2="4"/><line x1="9" y1="20" x2="9" y2="23"/><line x1="15" y1="20" x2="15" y2="23"/>
        <line x1="20" y1="9" x2="23" y2="9"/><line x1="20" y1="14" x2="23" y2="14"/><line x1="1" y1="9" x2="4" y2="9"/><line x1="1" y1="14" x2="4" y2="14"/>
      </svg>
    ),
  },
};

const FW: Record<Framework, FwDef> = Object.fromEntries(FRAMEWORKS.map(k => {
  const def = frameworkById(EVIDENCE_ID[k])!;
  return [k, { ...FW_STYLE[k], shortName: k, fullName: def.name, standard: def.standard, scopeNote: def.scope }];
})) as Record<Framework, FwDef>;

// ─── Helpers ──────────────────────────────────────────────────────────────────

function offsetDate(months: number) {
  const d = new Date();
  d.setMonth(d.getMonth() - months);
  return d.toISOString().split("T")[0];
}
const todayStr = () => new Date().toISOString().split("T")[0];

function fmtDate(iso: string) {
  return formatDateOnly(new Date(iso), getSavedTimezone());
}

// ─── Data builders ────────────────────────────────────────────────────────────

interface Metric { label: string; value: string; sub: string; status: "good" | "warn" | "bad" | "info" }

interface ReportHistoryItem {
  id: string;
  framework: string;
  period_start: string;
  period_end: string;
  generated_by_email: string | null;
  signature: string;
  created_at: string;
}

/** Headline numbers, measured by the evidence engine for the selected period. */
function buildMetrics(fw: Framework, ev: EvidencePackageView | null): Metric[] {
  if (!ev) return ["High-risk files reviewed", "Independent reviews", "Findings past deadline", "Repositories scanned"]
    .map(label => ({ label, value: "—", sub: "Loading evidence…", status: "info" as const }));
  const f = ev.facts;
  const ratio = (n: number, d: number) => d > 0 ? n / d : 1;
  const comparable = f.reviews.independent + f.reviews.self;

  if (fw === "AI governance") return [
    { label:"Approved AI tools policy", value: f.ai.policy_configured ? "Set" : "Not set",
      sub: f.ai.policy_configured ? `${f.ai.open_violations} open unapproved-tool detection${f.ai.open_violations === 1 ? "" : "s"}` : "Choose approved tools in Shadow AI",
      status: !f.ai.policy_configured ? "bad" : f.ai.open_violations ? "warn" : "good" },
    { label:"AI-written risky code reviewed", value: f.risky.ai_heavy_total ? `${f.risky.ai_heavy_reviewed} / ${f.risky.ai_heavy_total}` : "—",
      sub:"High-risk files that are mostly AI-written", status: !f.risky.ai_heavy_total ? "info" : ratio(f.risky.ai_heavy_reviewed, f.risky.ai_heavy_total) >= 0.9 ? "good" : "warn" },
    { label:"Self-approvals", value: String(f.reviews.self), sub:"Author signed off their own change", status: f.reviews.self ? "bad" : "good" },
    { label:"Files with provenance", value: String(f.ai.files_analyzed), sub:"AI estimate and tool evidence stored per commit", status:"info" },
  ];

  return [
    { label:"High-risk files reviewed", value: f.risky.total ? `${f.risky.reviewed} / ${f.risky.total}` : "—",
      sub:"Latest scan of each pull request", status: !f.risky.total ? "info" : ratio(f.risky.reviewed, f.risky.total) >= 0.9 ? "good" : ratio(f.risky.reviewed, f.risky.total) >= 0.5 ? "warn" : "bad" },
    { label:"Independent reviews", value: comparable ? `${f.reviews.independent} / ${comparable}` : "—",
      sub: f.reviews.self ? `${f.reviews.self} self-approval${f.reviews.self === 1 ? "" : "s"}` : f.reviews.unknown ? `${f.reviews.unknown} couldn't be checked` : "Reviewer is not the author",
      status: f.reviews.self ? "bad" : comparable ? "good" : "info" },
    { label:"Findings past deadline", value: String(f.findings.overdue), sub:`${f.findings.open} open finding${f.findings.open === 1 ? "" : "s"}`, status: f.findings.overdue ? "bad" : "good" },
    { label:"Repositories scanned", value: `${f.repos.scanned} / ${f.repos.active}`, sub:`${f.prs_scanned} pull request${f.prs_scanned === 1 ? "" : "s"} scanned`,
      status: f.repos.active && f.repos.scanned < f.repos.active ? "warn" : "good" },
  ];
}

function buildRiskBars(d: DashboardData) {
  const crit = d.top_risk_files.filter(f => f.risk_score === "CRITICAL").length;
  const high = d.top_risk_files.filter(f => f.risk_score === "HIGH").length;
  const med  = d.top_risk_files.filter(f => f.risk_score === "MEDIUM").length;
  const low  = d.top_risk_files.filter(f => f.risk_score === "LOW").length;
  const total = crit + high + med + low || 1;
  return [
    { label:"CRITICAL", count:crit, color:"#7c3aed", pct:(crit/total)*100 },
    { label:"HIGH",     count:high, color:"#f97316", pct:(high/total)*100 },
    { label:"MEDIUM",   count:med,  color:"#f59e0b", pct:(med/total)*100  },
    { label:"LOW",      count:low,  color:"#10b981", pct:(low/total)*100  },
  ];
}

// ─── Attestation + compliance helpers ────────────────────────────────────────

const AVATAR_PALETTE = [
  { bg:"#ede9fe", text:"#6d28d9" }, { bg:"#dbeafe", text:"#1d4ed8" },
  { bg:"#d1fae5", text:"#065f46" }, { bg:"#fef3c7", text:"#92400e" },
  { bg:"#ffedd5", text:"#9a3412" }, { bg:"#fce7f3", text:"#9d174d" },
];

function ReviewerAvatar({ email, idx }: { email: string; idx: number }) {
  const initials = email.split("@")[0].slice(0, 2).toUpperCase();
  const p = AVATAR_PALETTE[idx % AVATAR_PALETTE.length];
  return (
    <div className="w-7 h-7 rounded-full flex items-center justify-center text-[9px] font-black shrink-0"
      style={{ background: p.bg, color: p.text, border: `1.5px solid ${p.text}30` }}>
      {initials}
    </div>
  );
}

function AIPctBar({ raw }: { raw: number }) {
  const color = raw > 0.7 ? "#ef4444" : raw > 0.4 ? "#f59e0b" : "#10b981";
  return (
    <div className="flex items-center gap-1.5">
      <div className="w-12 h-1.5 rounded-full overflow-hidden shrink-0" style={{ background:"rgba(0,0,0,0.07)" }}>
        <div className="h-full rounded-full" style={{ width:`${Math.min(raw*100,100)}%`, background:color }} />
      </div>
      <span className="text-[10px] font-bold tabular-nums w-11 text-right shrink-0" style={{ color }}>
        {(raw*100).toFixed(1)}%
      </span>
    </div>
  );
}

/** The parts of /api/evidence/collect's EvidencePackage this page shows. */
interface EvidencePackageView {
  framework: string;
  status_counts: Record<EvidenceStatus, number>;
  controls: Array<{ control_id: string; control_name: string; status: EvidenceStatus; checks: CheckResult[] }>;
  facts: ComplianceFacts;
}

const STATUS_STYLE: Record<EvidenceStatus, { textColor: string; bg: string; border: string }> = {
  pass:       { textColor:"#065f46", bg:"#d1fae5", border:"#6ee7b7" },
  partial:    { textColor:"#78350f", bg:"#fef3c7", border:"#fcd34d" },
  fail:       { textColor:"#7c2d12", bg:"#fee2e2", border:"#fca5a5" },
  not_tested: { textColor:"#475569", bg:"#f1f5f9", border:"#e2e8f0" },
};

// ─── StatusPill ───────────────────────────────────────────────────────────────

const PILL_STYLES: Record<string, CSSProperties> = {
  ATTESTED:   { background:"#d1fae5", color:"#065f46", border:"1px solid #a7f3d0" },
  YES:        { background:"#d1fae5", color:"#065f46", border:"1px solid #a7f3d0" },
  PASS:       { background:"#d1fae5", color:"#065f46", border:"1px solid #a7f3d0" },
  COMPLETE:   { background:"#d1fae5", color:"#065f46", border:"1px solid #a7f3d0" },
  REVIEWED:   { background:"#d1fae5", color:"#065f46", border:"1px solid #a7f3d0" },
  PENDING:    { background:"#fef3c7", color:"#78350f", border:"1px solid #fde68a" },
  INCOMPLETE: { background:"#fef3c7", color:"#78350f", border:"1px solid #fde68a" },
  REQUIRED:   { background:"#fef3c7", color:"#78350f", border:"1px solid #fde68a" },
  PARTIAL:    { background:"#fef3c7", color:"#78350f", border:"1px solid #fde68a" },
  CRITICAL:   { background:"#ede9fe", color:"#4c1d95", border:"1px solid #c4b5fd" },
  HIGH:       { background:"#ffedd5", color:"#7c2d12", border:"1px solid #fed7aa" },
  MEDIUM:     { background:"#fef3c7", color:"#78350f", border:"1px solid #fde68a" },
  LOW:        { background:"#f0fdf4", color:"#14532d", border:"1px solid #bbf7d0" },
};

function StatusPill({ v }: { v: string }) {
  const key = v.toUpperCase();
  const style = PILL_STYLES[key] ?? { background:"#f8fafc", color:"#475569", border:"1px solid #e2e8f0" };
  if (v === "—") return <span className="text-gray-300 font-mono text-xs">—</span>;
  return (
    <span className="inline-block px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wide whitespace-nowrap" style={style}>
      {v}
    </span>
  );
}

// ─── Document sections ────────────────────────────────────────────────────────

function SectionHead({ num, title, color }: { num: number; title: string; color: string }) {
  return (
    <div className="flex items-center gap-3 mb-4">
      <span className="w-6 h-6 rounded-full flex items-center justify-center text-white text-[10px] font-black shrink-0"
        style={{ background: color }}>
        {num}
      </span>
      <h3 className="text-[11px] font-black uppercase tracking-widest text-gray-500">{title}</h3>
      <div className="flex-1 h-px bg-gray-100" />
    </div>
  );
}

function MetricGrid({ metrics, color }: { metrics: Metric[]; color: string }) {
  const STATUS_COLORS: Record<string, { text: string; bg: string; border: string }> = {
    good: { text:"#065f46", bg:"#d1fae5", border:"#a7f3d0" },
    warn: { text:"#78350f", bg:"#fef3c7", border:"#fde68a" },
    bad:  { text:"#7c2d12", bg:"#fee2e2", border:"#fca5a5" },
    info: { text:"#1e40af", bg:"#dbeafe", border:"#bfdbfe" },
  };

  return (
    <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
      {metrics.map(m => {
        const c = STATUS_COLORS[m.status];
        return (
          <div key={m.label} className="rounded-xl p-4" style={{ background:c.bg, border:`1px solid ${c.border}` }}>
            <p className="text-[9px] font-bold uppercase tracking-widest mb-2" style={{ color:c.text, opacity:0.7 }}>{m.label}</p>
            <p className="text-2xl font-black leading-none tabular-nums" style={{ color:c.text }}>{m.value}</p>
            <p className="text-[10px] mt-1.5 leading-snug" style={{ color:c.text, opacity:0.65 }}>{m.sub}</p>
          </div>
        );
      })}
    </div>
  );
}

function RiskOverview({ data, color }: { data: DashboardData; color: string }) {
  const bars = buildRiskBars(data);
  const total = bars.reduce((s, b) => s + b.count, 0);
  const attPct = Math.round(data.attestation_rate * 100);

  return (
    <div className="grid grid-cols-2 gap-6">
      {/* Risk distribution */}
      <div>
        <p className="text-[10px] font-bold text-gray-400 uppercase tracking-wider mb-3">Risk Distribution</p>
        <div className="space-y-2.5">
          {bars.map(b => (
            <div key={b.label} className="space-y-1">
              <div className="flex items-center justify-between">
                <span className="text-[10px] font-bold" style={{ color:b.color }}>{b.label}</span>
                <span className="text-[10px] font-black text-gray-600 tabular-nums">{b.count}</span>
              </div>
              <div className="h-2 rounded-full overflow-hidden" style={{ background:"rgba(0,0,0,0.06)" }}>
                <div className="h-full rounded-full transition-all duration-700"
                  style={{ width:`${b.pct}%`, background:b.color }} />
              </div>
            </div>
          ))}
        </div>
        <p className="text-[10px] text-gray-400 mt-3">{total} total files scanned</p>
      </div>

      {/* Attestation coverage */}
      <div>
        <p className="text-[10px] font-bold text-gray-400 uppercase tracking-wider mb-3">Attestation Coverage</p>
        <div className="flex items-end gap-3">
          {/* Big number */}
          <div>
            <span className="text-5xl font-black tabular-nums" style={{ color }}>{attPct}</span>
            <span className="text-xl font-bold text-gray-400">%</span>
          </div>
          <div className="pb-1.5">
            <p className="text-xs font-semibold text-gray-600">
              {data.top_risk_files.filter(f => f.attested).length} of {data.top_risk_files.length} files attested
            </p>
            <p className="text-[10px] text-gray-400">{data.unattested_deploy_count} HIGH/CRITICAL file{data.unattested_deploy_count !== 1 ? "s" : ""} awaiting sign-off</p>
          </div>
        </div>
        <div className="mt-3 h-3 rounded-full overflow-hidden" style={{ background:"rgba(0,0,0,0.06)" }}>
          <div className="h-full rounded-full transition-all duration-700"
            style={{ width:`${attPct}%`, background: attPct>=80?"#10b981":attPct>=50?"#f59e0b":"#ef4444" }} />
        </div>
        <div className="flex justify-between mt-1">
          <span className="text-[9px] text-gray-400">0%</span>
          <span className="text-[9px] text-gray-400">Target ≥ 80%</span>
          <span className="text-[9px] text-gray-400">100%</span>
        </div>
      </div>
    </div>
  );
}

const riskPfx = (r: string) =>
  r === "CRITICAL" ? "crit" : r === "HIGH" ? "high" : r === "MEDIUM" ? "med" : "low";

function AttestationRecords({ data, fw, start, color, violationStatuses }: {
  data: DashboardData; fw: Framework; start: string; color: string;
  violationStatuses: Record<string, string>;
}) {
  const router = useRouter();

  // Optimistic local set — keeps instant feedback when Attest is clicked in-page
  const [localAttested, setLocalAttested] = useState<Set<string>>(() => {
    if (typeof window === "undefined") return new Set<string>();
    return new Set(Object.entries(readLocalStatuses()).filter(([,v]) => v === "resolved").map(([k]) => k));
  });

  // Keep localAttested in sync whenever the parent violationStatuses updates
  // (captures attestations made on the PR page or in other tabs)
  useEffect(() => {
    const resolvedKeys = Object.entries(violationStatuses)
      .filter(([, v]) => v === "resolved")
      .map(([k]) => k);
    setLocalAttested(prev => {
      const merged = new Set([...Array.from(prev), ...resolvedKeys]);
      return merged;
    });
  }, [violationStatuses]);

  const isAttested = (f: { scan_id: string; file_path: string; risk_score: string; attested: boolean }) =>
    f.attested || localAttested.has(`${riskPfx(f.risk_score)}::${f.scan_id}::${f.file_path}`);

  // Show all files — sort unattested HIGH/CRIT first so pending work is visible
  const riskOrder = (r: string) => r === "CRITICAL" ? 0 : r === "HIGH" ? 1 : r === "MEDIUM" ? 2 : 3;
  const files = [...data.top_risk_files].sort((a, b) => {
    const aAtt = isAttested(a), bAtt = isAttested(b);
    if (aAtt !== bAtt) return aAtt ? 1 : -1;
    return riskOrder(a.risk_score) - riskOrder(b.risk_score);
  });
  const attFiles      = files.filter(f => isAttested(f));
  const pendFiles     = files.filter(f => !isAttested(f));
  const blockingFiles = pendFiles.filter(f => f.risk_score === "CRITICAL" || f.risk_score === "HIGH");
  const infoFiles     = pendFiles.filter(f => f.risk_score !== "CRITICAL" && f.risk_score !== "HIGH");
  const total         = files.length || 1;
  const attPct        = Math.round((attFiles.length / total) * 100);

  function FileRow({ f, idx }: { f: (typeof files)[0]; idx: number }) {
    const attested  = isAttested(f);
    const rev       = f.attested_by;
    const fileShort = f.file_path.split("/").pop() ?? f.file_path;
    const fileDir   = f.file_path.includes("/") ? f.file_path.split("/").slice(0,-1).join("/")+"/": "";
    const localKey  = `${riskPfx(f.risk_score)}::${f.scan_id}::${f.file_path}`;
    const date      = attested
      ? (localAttested.has(localKey) ? new Date().toISOString().split("T")[0] : f.attested_at?.split("T")[0] ?? null)
      : null;
    const lbColor   = attested ? "#10b981"
                    : f.risk_score==="CRITICAL" ? "#ef4444"
                    : f.risk_score==="HIGH" ? "#f97316" : "#f59e0b";
    const displayRisk = f.risk_score;

    const inner = (
      <>
        {/* PR */}
        <span className="font-mono text-[10px] font-bold text-gray-400 shrink-0 w-9">#{f.pr_number}</span>

        {/* File */}
        <div className="flex-1 min-w-[90px]">
          {fileDir && <p className="text-[9px] text-gray-400 font-mono truncate leading-none mb-0.5">{fileDir}</p>}
          <p className="text-[11px] font-semibold font-mono text-gray-800 truncate leading-snug">{fileShort}</p>
          <p className="text-[9px] text-gray-400 mt-0.5">{f.repo.split("/").pop()}</p>
        </div>

        {/* Risk */}
        <div className="shrink-0 w-20"><StatusPill v={displayRisk} /></div>

        {/* Attestation status — Review & Attest opens the PR review modal so the
            reviewer always sees the source code before confirming attestation.
            Placed right after Risk (before Reviewer/AI Content) so the primary
            action stays visible without horizontal scrolling on narrow panels. */}
        <div className="shrink-0 w-28 flex items-center gap-2">
          {attested ? (
            <>
              <div className="w-6 h-6 rounded-full flex items-center justify-center shrink-0"
                style={{ background:"#d1fae5", border:"1.5px solid #6ee7b7" }}>
                <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="#10b981" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">
                  <polyline points="20 6 9 17 4 12"/>
                </svg>
              </div>
              <div className="min-w-0">
                <p className="text-[10px] font-bold text-emerald-700 leading-none">Attested</p>
                <p className="text-[9px] text-gray-400 font-mono mt-0.5 truncate">{date}</p>
              </div>
            </>
          ) : (
            <button
              onClick={e => {
                e.preventDefault(); e.stopPropagation();
                router.push(`/pr/${f.scan_id}?attest=${encodeURIComponent(f.file_path)}`);
              }}
              title="Review the source code before attesting"
              className="inline-flex items-center gap-1 text-[10px] font-bold text-white px-2 py-1.5 rounded-lg whitespace-nowrap transition-opacity hover:opacity-90 active:scale-95 w-full justify-center"
              style={{
                background: f.risk_score==="CRITICAL"
                  ? "linear-gradient(135deg,#ef4444,#dc2626)"
                  : "linear-gradient(135deg,#f97316,#ea580c)",
                boxShadow: f.risk_score==="CRITICAL"
                  ? "0 2px 8px rgba(239,68,68,0.35)"
                  : "0 2px 8px rgba(249,115,22,0.30)",
              }}>
              <svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" className="shrink-0">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
              </svg>
              Attest
            </button>
          )}
        </div>

        {/* Reviewer */}
        <div className="flex items-center gap-1.5 shrink-0 w-28">
          {rev ? (
            <>
              <ReviewerAvatar email={rev} idx={idx} />
              <span className="text-[10px] text-gray-500 truncate font-medium">{rev.split("@")[0]}</span>
            </>
          ) : (
            <span className="text-[10px] text-gray-400">—</span>
          )}
        </div>

        {/* AI% bar */}
        <div className="shrink-0"><AIPctBar raw={f.ai_pct} /></div>
      </>
    );

    const rowClass = "group/row flex items-center gap-2 px-4 py-3 transition-colors";
    const rowStyle: CSSProperties = { borderLeft:`3px solid ${lbColor}`, borderBottom:"1px solid #f8fafc" };

    if (!attested) {
      return (
        <Link href={`/pr/${f.scan_id}`}
          className={rowClass}
          style={{ ...rowStyle, cursor:"pointer" }}
          onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = f.risk_score==="CRITICAL" ? "rgba(254,226,226,0.4)" : "rgba(255,237,213,0.35)"; }}
          onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = ""; }}
        >
          {inner}
        </Link>
      );
    }

    return (
      <Link href={`/pr/${f.scan_id}`}
        className={rowClass}
        style={rowStyle}
        onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background="#f8fafc"; }}
        onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background=""; }}
      >
        {inner}
      </Link>
    );
  }

  if (!files.length) {
    return (
      <div className="rounded-xl border border-gray-200 py-12 text-center">
        <p className="text-sm font-semibold text-emerald-600">All files attested</p>
        <p className="text-xs text-gray-400 mt-1">No pending attestations in this period</p>
      </div>
    );
  }

  return (
    <div className="overflow-x-hidden rounded-xl border border-gray-200"
      style={{ boxShadow:"0 1px 8px rgba(0,0,0,0.05)" }}>

      {/* ── Summary banner ── */}
      <div className="px-5 py-4" style={{ background:"#f8fafc", borderBottom:"1px solid #e2e8f0" }}>
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-baseline gap-2">
            <span className="text-2xl font-black tabular-nums" style={{ color }}>{attFiles.length}</span>
            <span className="text-sm text-gray-500 font-medium">of {files.length} files attested</span>
          </div>
          <div className="flex items-center gap-3 flex-wrap justify-end">
            <span className="flex items-center gap-1.5 text-[10px] font-semibold text-emerald-700">
              <span className="w-2 h-2 rounded-full bg-emerald-500" />
              {attFiles.length} attested
            </span>
            {blockingFiles.length > 0 && (
              <span className="flex items-center gap-1.5 text-[10px] font-bold text-rose-700">
                <span className="w-2 h-2 rounded-full bg-rose-500" />
                {blockingFiles.length} blocking
              </span>
            )}
            {infoFiles.length > 0 && (
              <span className="flex items-center gap-1.5 text-[10px] font-semibold text-amber-700">
                <span className="w-2 h-2 rounded-full bg-amber-400" />
                {infoFiles.length} informational
              </span>
            )}
            <span className="text-[11px] font-black tabular-nums px-2.5 py-0.5 rounded-full"
              style={{ background: attPct>=80?"#d1fae5":attPct>=50?"#fef3c7":"#fee2e2", color: attPct>=80?"#065f46":attPct>=50?"#78350f":"#7c2d12" }}>
              {attPct}%
            </span>
          </div>
        </div>
        {/* Segmented bar */}
        <div className="flex h-2.5 rounded-full overflow-hidden gap-0.5" style={{ background:"#e2e8f0" }}>
          {attPct > 0 && (
            <div className="h-full rounded-l-full transition-all duration-700"
              style={{ width:`${attPct}%`, background:"linear-gradient(90deg,#34d399,#10b981)" }} />
          )}
          {attPct < 100 && (
            <div className="h-full flex-1 rounded-r-full"
              style={{ background: pendFiles.some(f=>f.risk_score==="CRITICAL")?"#fca5a5":"#fde68a" }} />
          )}
        </div>
        <div className="flex justify-between mt-1.5">
          <span className="text-[9px] font-semibold text-emerald-600">{attPct}% signed off</span>
          <span className="text-[9px] text-gray-400">Goal: every high-risk file reviewed</span>
        </div>
      </div>

      {/* ── Column headers ──
          Order matches FileRow: PR, File, Risk, Attestation, Reviewer, AI Content —
          Risk/Attestation come right after the file name so they stay visible
          without horizontal scrolling on narrow report panels. */}
      <div className="grid items-center px-4 py-2.5 gap-x-2 border-b border-gray-100"
        style={{
          gridTemplateColumns:"36px 1fr 80px 112px 112px auto",
          background:"#fafafa",
        }}>
        {["PR","File / Path","Risk","Attestation","Reviewer","AI Content"].map(h => (
          <span key={h} className="text-[9px] font-black uppercase tracking-widest text-gray-400">{h}</span>
        ))}
      </div>

      {/* ── Attested group ── */}
      {attFiles.length > 0 && (
        <div>
          <div className="flex items-center gap-2 px-4 py-2"
            style={{ background:"rgba(209,250,229,0.25)", borderBottom:"1px solid #d1fae5" }}>
            <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="#10b981" strokeWidth="3"><polyline points="20 6 9 17 4 12"/></svg>
            <span className="text-[10px] font-black uppercase tracking-wider text-emerald-700">
              Attested — {attFiles.length} record{attFiles.length!==1?"s":""}
            </span>
          </div>
          {attFiles.map((f, i) => <FileRow key={f.file_path+i} f={f} idx={i} />)}
        </div>
      )}

      {/* ── Pending group ── */}
      {pendFiles.length > 0 && (
        <div>
          <div className="flex items-center gap-2 px-4 py-2"
            style={{
              background: pendFiles.some(f=>f.risk_score==="CRITICAL")?"rgba(254,226,226,0.3)":"rgba(254,243,199,0.35)",
              borderBottom:"1px solid #fde68a",
              borderTop: attFiles.length>0?"1px solid #e2e8f0":undefined,
            }}>
            <span className="relative flex w-2.5 h-2.5 shrink-0">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full opacity-50"
                style={{ background: pendFiles.some(f=>f.risk_score==="CRITICAL")?"#ef4444":"#f59e0b" }} />
              <span className="relative inline-flex rounded-full w-2.5 h-2.5"
                style={{ background: pendFiles.some(f=>f.risk_score==="CRITICAL")?"#ef4444":"#f59e0b" }} />
            </span>
            <span className="text-[10px] font-black uppercase tracking-wider"
              style={{ color: pendFiles.some(f=>f.risk_score==="CRITICAL")?"#dc2626":"#92400e" }}>
              Needs Review — {pendFiles.length} record{pendFiles.length!==1?"s":""}
            </span>
          </div>
          {pendFiles.map((f, i) => <FileRow key={f.file_path+i} f={f} idx={attFiles.length+i} />)}
        </div>
      )}
    </div>
  );
}

function StatusBadge({ status }: { status: EvidenceStatus }) {
  const ss = STATUS_STYLE[status];
  return (
    <span className="inline-flex items-center text-[9px] font-black px-2 py-0.5 rounded uppercase tracking-wide whitespace-nowrap"
      style={{ background:ss.bg, color:ss.textColor, border:`1px solid ${ss.border}` }}>
      {STATUS_LABEL[status]}
    </span>
  );
}

/** Each control with the checks behind it, measured from the org's records. No percentages: a status says what
 * the evidence shows, and the numbers are in the check summaries. */
function ControlEvidenceSection({ evidence, failed, color, accentBg }: {
  evidence: EvidencePackageView | null;
  failed: boolean;
  color: string;
  accentBg: string;
}) {
  if (failed) return (
    <div className="rounded-xl border border-rose-200 bg-rose-50 px-5 py-4 text-xs text-rose-700">
      Couldn&apos;t load control evidence for this period. Nothing is shown rather than an estimate.
    </div>
  );
  if (!evidence) return (
    <div className="rounded-xl border border-gray-200 px-5 py-8 text-center text-xs text-gray-400">Collecting evidence…</div>
  );
  const counts = evidence.status_counts;
  const order: EvidenceStatus[] = ["pass", "partial", "fail", "not_tested"];

  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-gray-200 px-5 py-4 flex flex-wrap items-center gap-x-5 gap-y-2" style={{ background:"#f8fafc" }}>
        <p className="text-sm text-gray-600">
          <span className="text-2xl font-black tabular-nums mr-1.5" style={{ color }}>{evidence.controls.length}</span>
          controls in scope
        </p>
        <div className="flex flex-wrap items-center gap-3">
          {order.filter(s => counts[s] > 0).map(s => (
            <span key={s} className="flex items-center gap-1.5 text-[10px] font-semibold" style={{ color: STATUS_STYLE[s].textColor }}>
              <span className="w-2 h-2 rounded-full" style={{ background: STATUS_STYLE[s].border }} />
              {counts[s]} {STATUS_LABEL[s].toLowerCase()}
            </span>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        {evidence.controls.map(c => (
          <div key={c.control_id} className="rounded-xl overflow-hidden border" style={{ borderColor: STATUS_STYLE[c.status].border }}>
            <div className="flex items-center justify-between gap-2 px-4 py-2.5"
              style={{ background: accentBg, borderBottom:`1px solid ${STATUS_STYLE[c.status].border}` }}>
              <span className="font-mono text-[11px] font-black px-2 py-0.5 rounded" style={{ background:"rgba(255,255,255,0.7)", color }}>
                {c.control_id}
              </span>
              <StatusBadge status={c.status} />
            </div>
            <div className="px-4 py-3.5 space-y-2.5 bg-white">
              <p className="text-xs font-bold text-gray-800 leading-snug">{c.control_name}</p>
              {c.checks.map(k => (
                <div key={k.key} className="rounded-lg px-3 py-2" style={{ background:accentBg }}>
                  <div className="flex items-center justify-between gap-2">
                    <p className="text-[10px] font-bold text-gray-700">{k.label}</p>
                    <span className="text-[9px] font-bold" style={{ color: STATUS_STYLE[k.status].textColor }}>{STATUS_LABEL[k.status]}</span>
                  </div>
                  <p className="text-[10px] text-gray-600 leading-relaxed mt-0.5">{k.summary}</p>
                  {k.gaps.map(g => (
                    <p key={g} className="text-[10px] font-semibold text-amber-800 mt-1">Gap: {g}</p>
                  ))}
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

// Real, honest reference metadata for the on-screen preview -- no
// algorithm claim, no fake PGP block. The genuine cryptographic
// signature (HMAC-SHA256 over the actual report content) is computed
// server-side, only for the downloaded PDF (see /api/report), where a
// real signing key is available -- see docs/plan for the follow-up that
// wires that in. Faking one here to look complete was worse than not
// having one.
function ReportReferenceBlock({ id, fw, start, end, org, generatedBy }: {
  id: string; fw: Framework; start: string; end: string; org: string; generatedBy?: string;
}) {
  const ts = new Date().toISOString().replace("T"," ").slice(0,19) + " UTC";

  const row = (label: string, value: ReactNode, mono = false) => (
    <div key={label} className="flex gap-0 border-b border-white/5 last:border-0">
      <div className="w-36 shrink-0 px-4 py-2.5 border-r border-white/5">
        <span className="text-[10px] font-bold uppercase tracking-wider text-slate-500">{label}</span>
      </div>
      <div className="flex-1 px-4 py-2.5">
        <span className={`text-[11px] break-all ${mono ? "font-mono" : ""} text-slate-300`}>{value}</span>
      </div>
    </div>
  );

  return (
    <div className="rounded-xl overflow-hidden border border-slate-800"
      style={{ background:"linear-gradient(135deg,#0f172a,#1a1a2e)" }}>

      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3"
        style={{ background:"rgba(255,255,255,0.03)", borderBottom:"1px solid rgba(255,255,255,0.06)" }}>
        <div className="flex items-center gap-2.5">
          <div className="w-6 h-6 rounded-lg flex items-center justify-center"
            style={{ background:"rgba(99,102,241,0.15)", border:"1px solid rgba(99,102,241,0.3)" }}>
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#818cf8" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
          </div>
          <span className="text-[11px] font-bold text-indigo-400 uppercase tracking-widest">Report Reference</span>
        </div>
        <span className="font-mono text-[10px] text-slate-500">{id.slice(0, 8)}</span>
      </div>

      {/* Metadata rows */}
      <div className="divide-y divide-white/5">
        {row("Report ID",    <span className="text-indigo-400 font-bold font-mono">{id}</span>)}
        {row("Framework",   fw)}
        {row("Organisation",org)}
        {row("Period",       `${start}  →  ${end}`,  true)}
        {row("Generated",    ts,                      true)}
        {generatedBy && row("Generated by", generatedBy)}
      </div>

      {/* Note pointing at the real, signed download */}
      <div style={{ borderTop:"1px solid rgba(255,255,255,0.06)" }}>
        <div className="px-4 py-3 flex items-start gap-2.5">
          <svg className="shrink-0 mt-0.5" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#818cf8" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/>
          </svg>
          <p className="text-[10px] text-slate-400 leading-relaxed">
            This on-screen preview is not signed. Use <span className="text-indigo-400 font-semibold">Generate Report</span> to
            download a PDF with a real HMAC-SHA256 signature over its exact contents.
          </p>
        </div>
      </div>
    </div>
  );
}

// ─── Full report document ─────────────────────────────────────────────────────

function ReportDocument({ data, fw, start, end, violationStatuses, org, generatedBy, evidence, evidenceFailed }: {
  data: DashboardData; fw: Framework; start: string; end: string;
  violationStatuses: Record<string, string>;
  org: string;
  generatedBy?: string;
  evidence: EvidencePackageView | null;
  evidenceFailed: boolean;
}) {
  const def     = FW[fw];
  const metrics = buildMetrics(fw, evidence);
  const evidenceGaps = (evidence?.controls ?? []).flatMap(c => c.checks).filter((k, i, all) => k.gaps.length > 0 && all.findIndex(x => x.key === k.key) === i);
  // One id per render of the document -- shown identically in the
  // letterhead, the Report Reference section, and the footer, unlike the
  // two independently-generated fake ids this replaced.
  const reportId = useMemo(() => crypto.randomUUID().toUpperCase(), []);

  return (
    <div id="report-print-area" className="rounded-2xl overflow-hidden border border-gray-200 min-w-[660px]"
      style={{ boxShadow:"0 8px 40px rgba(0,0,0,0.10), 0 2px 8px rgba(0,0,0,0.06)", background:"#fff" }}>

      {/* ── Letterhead ── */}
      <div className="relative px-8 py-7 overflow-hidden" style={{ background:def.headerBg }}>
        {/* Subtle radial glow */}
        <div className="absolute inset-0 pointer-events-none"
          style={{ backgroundImage:`radial-gradient(ellipse at 70% 50%, ${def.color}30 0%, transparent 65%)` }} />

        <div className="relative flex items-start justify-between gap-8">
          {/* Left: identity */}
          <div>
            {/* Logo row */}
            <div className="flex items-center gap-3 mb-5">
              <div className="w-9 h-9 rounded-xl flex items-center justify-center text-white shrink-0"
                style={{ background:def.gradientCss, boxShadow:`0 2px 12px ${def.color}60` }}>
                {def.icon}
              </div>
              <BrandWordmark height={26} />
            </div>

            {/* Report title */}
            <h2 className="text-2xl font-black text-white leading-tight mb-1">
              {def.shortName} Evidence Assessment
            </h2>
            <p className="text-sm font-medium text-white/50">{def.fullName}</p>
            <p className="text-[11px] text-white/30 mt-0.5">{def.standard}</p>
          </div>

          {/* Right: metadata */}
          <div className="shrink-0 text-right space-y-3">
            <div>
              <p className="text-[9px] font-bold uppercase tracking-widest text-white/30 mb-0.5">Organisation</p>
              <p className="text-sm font-bold text-white">{org}</p>
            </div>
            <div>
              <p className="text-[9px] font-bold uppercase tracking-widest text-white/30 mb-0.5">Report Period</p>
              <p className="text-[11px] font-mono text-white/60">{fmtDate(start)}</p>
              <p className="text-[9px] text-white/30">to</p>
              <p className="text-[11px] font-mono text-white/60">{fmtDate(end)}</p>
            </div>
            <div>
              <p className="text-[9px] font-bold uppercase tracking-widest text-white/30 mb-0.5">Report ID</p>
              <p className="font-mono text-[10px] text-white/40">{reportId.slice(0, 8)}</p>
            </div>
          </div>
        </div>

        {/* Framework badge strip */}
        <div className="relative mt-6 flex items-center gap-2">
          <div className="h-px flex-1 bg-white/10" />
          <span className="px-3 py-1 rounded-full text-[10px] font-black uppercase tracking-widest text-white/80"
            style={{ background:"rgba(255,255,255,0.1)", border:"1px solid rgba(255,255,255,0.15)" }}>
            {def.tagline}
          </span>
          <div className="h-px flex-1 bg-white/10" />
        </div>
      </div>

      {/* ── Body ── */}
      <div className="p-8 space-y-10">

        {/* Scope & Limitations — what this report does and does not cover, stated
            up front rather than left implicit. See the compliance-scope review
            this section came out of: this is a narrow evidence package for a
            handful of controls, not a full framework assessment. */}
        <div className="rounded-xl border px-5 py-4" style={{ borderColor: `${def.color}40`, background: def.accentBg }}>
          <p className="text-[10px] font-black uppercase tracking-widest mb-1.5" style={{ color: def.colorDark }}>
            Scope &amp; Limitations
          </p>
          <p className="text-xs text-gray-700 leading-relaxed">{def.scopeNote}</p>
        </div>

        {/* 1. Executive Summary */}
        <section>
          <SectionHead num={1} title="Executive Summary" color={def.color} />
          <MetricGrid metrics={metrics} color={def.color} />
        </section>

        {/* 2. Risk Overview */}
        <section>
          <SectionHead num={2} title="Risk Overview" color={def.color} />
          <RiskOverview data={data} color={def.color} />
        </section>

        {/* 3. Attestation Records */}
        <section>
          <SectionHead num={3} title="Attestation Records" color={def.color} />
          <AttestationRecords data={data} fw={fw} start={start} color={def.color} violationStatuses={violationStatuses} />
        </section>

        {/* 4. Control Evidence */}
        <section>
          <SectionHead num={4} title="Control Evidence" color={def.color} />
          <ControlEvidenceSection evidence={evidence} failed={evidenceFailed} color={def.color} accentBg={def.accentBg} />
        </section>

        {/* 5. Report Reference */}
        <section>
          <SectionHead num={5} title="Report Reference" color={def.color} />
          <ReportReferenceBlock id={reportId} fw={fw} start={start} end={end} org={org} generatedBy={generatedBy} />
        </section>

        {/* 6. Management Assertion */}
        <section>
          <SectionHead num={6} title="Management Assertion" color={def.color} />
          <div className="rounded-xl border border-gray-200 overflow-hidden">
            <div className="px-6 py-4 border-b border-gray-100" style={{ background:`${def.accentBg}` }}>
              <p className="text-xs font-bold text-gray-800">Management Representation Letter</p>
              <p className="text-[10px] text-gray-500 mt-0.5">
                For the period {start} to {end} · {def.standard}
              </p>
            </div>
            <div className="px-6 py-5 space-y-4 bg-white">
              <p className="text-xs text-gray-700 leading-relaxed">
                Management of <strong>{org}</strong> asserts that, to the best of its knowledge and belief,
                the controls described in this report were suitably designed and operating effectively throughout
                the period <strong>{start}</strong> to <strong>{end}</strong> with respect to the specific
                {" "}{def.shortName} controls listed in Control Evidence above, except for the gaps recorded there.
                This assertion does not extend to any {def.shortName} requirement outside that scope — see
                Scope &amp; Limitations at the top of this report.
              </p>
              <p className="text-xs text-gray-700 leading-relaxed">
                Pull requests in connected repositories were scanned automatically, and reviewer sign-offs on
                high-risk files were recorded with the reviewer&apos;s identity. The scan, sign-off and audit-log
                records summarised in this report are the evidence base for this assertion; the downloaded PDF
                additionally carries a cryptographic signature over its exact contents.
              </p>
              <div className="grid grid-cols-2 gap-6 pt-4 border-t border-gray-100">
                <div>
                  <p className="text-[9px] text-gray-400 font-semibold uppercase tracking-wider mb-3">Prepared by</p>
                  <div className="border-b border-gray-300 h-8 mb-1" />
                  <p className="text-[10px] text-gray-600">Security Lead, {org}</p>
                  <p className="text-[9px] text-gray-400">Date: _______________</p>
                </div>
                <div>
                  <p className="text-[9px] text-gray-400 font-semibold uppercase tracking-wider mb-3">Reviewed by</p>
                  <div className="border-b border-gray-300 h-8 mb-1" />
                  <p className="text-[10px] text-gray-600">Chief Information Security Officer</p>
                  <p className="text-[9px] text-gray-400">Date: _______________</p>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* 7. Gap Analysis & Remediation Status */}
        <section>
          <SectionHead num={7} title="Gap Analysis &amp; Remediation" color={def.color} />
          <div className="space-y-3">
            {evidenceGaps.length > 0 && (
              <div className="rounded-xl border border-amber-200 overflow-hidden">
                <div className="px-4 py-2.5 bg-amber-50 border-b border-amber-100">
                  <p className="text-[10px] font-black uppercase tracking-widest text-amber-700">Gaps found by control evidence</p>
                </div>
                <ul className="divide-y divide-amber-50 bg-white">
                  {evidenceGaps.flatMap(k => k.gaps.map(g => (
                    <li key={`${k.key}-${g}`} className="px-4 py-2.5 text-[11px] text-gray-700">
                      <span className="font-bold text-gray-800">{k.label}:</span> {g}
                    </li>
                  )))}
                </ul>
              </div>
            )}
            {data.top_risk_files.filter(f => !f.attested && (f.risk_score === "CRITICAL" || f.risk_score === "HIGH")).length === 0 ? (
              <div className="rounded-xl border border-emerald-200 bg-emerald-50 px-5 py-4">
                <p className="text-sm font-bold text-emerald-800 flex items-center gap-2">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
                  No unreviewed high-risk files
                </p>
                <p className="text-xs text-emerald-700 mt-1">Every HIGH and CRITICAL file in the latest scans has a reviewer sign-off.</p>
              </div>
            ) : (
              <div className="rounded-xl border border-amber-200 overflow-hidden">
                <div className="px-4 py-2.5 bg-amber-50 border-b border-amber-100 flex items-center justify-between">
                  <p className="text-[10px] font-black uppercase tracking-widest text-amber-700">Open Gaps Requiring Remediation</p>
                  <span className="text-[10px] font-bold text-amber-700 bg-amber-100 px-2 py-0.5 rounded-full">
                    {data.top_risk_files.filter(f=>!f.attested&&(f.risk_score==="CRITICAL"||f.risk_score==="HIGH")).length} items
                  </span>
                </div>
                <div className="divide-y divide-amber-50">
                  {data.top_risk_files.filter(f=>!f.attested&&(f.risk_score==="CRITICAL"||f.risk_score==="HIGH")).map((f, i) => (
                    <div key={i} className="flex items-center gap-4 px-4 py-3 bg-white">
                      <span className="text-[10px] font-black px-2 py-0.5 rounded border shrink-0"
                        style={{ background:f.risk_score==="CRITICAL"?"#ede9fe":"#ffedd5", color:f.risk_score==="CRITICAL"?"#5b21b6":"#7c2d12", borderColor:f.risk_score==="CRITICAL"?"#c4b5fd":"#fed7aa" }}>
                        {f.risk_score}
                      </span>
                      <div className="flex-1 min-w-0">
                        <p className="text-[11px] font-mono font-semibold text-gray-800 truncate">{f.file_path}</p>
                        <p className="text-[9px] text-gray-400">{f.repo.split("/").pop()} · PR #{f.pr_number} · {(f.ai_pct*100).toFixed(0)}% AI</p>
                      </div>
                      <span className="text-[9px] font-bold text-rose-600 shrink-0">Attestation required</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </section>

        {/* Footer */}
        <div className="flex items-center justify-between pt-4 border-t border-gray-100">
          <p suppressHydrationWarning className="text-[10px] text-gray-400">
            Generated by TrustLedger · {new Date().toLocaleDateString("en-GB", { day:"2-digit", month:"long", year:"numeric" })} · {def.shortName} · {org}
          </p>
          <p className="text-[10px] text-gray-400 font-mono">{reportId}</p>
        </div>
      </div>
    </div>
  );
}

/** What went wrong with a report download, in words someone can act on (every failure used to read as
 *  "couldn't render a PDF", including a missing signing key or a rate limit). */
function reportErrorMessage(status: number, code?: string): string {
  if (code === "report_signing_not_configured") return "Reports can't be signed yet: the server has no signing key. An admin needs to set EXPORT_SIGNING_KEY.";
  if (status === 429) return "Too many reports in a short time. Please wait a minute and try again.";
  if (status === 401) return "Your session has expired. Sign in again to generate reports.";
  if (status === 403) return "Your role can't generate reports. Ask an admin for the report permission.";
  return "The server couldn't render a PDF for this report. Please try again, or a different date range.";
}

// ─── AIBOM generator ─────────────────────────────────────────────────────────

function downloadAIBOM(d: DashboardData, fw: Framework, start: string, end: string, org: string) {
  const now = new Date().toISOString();
  const aibom = {
    aibom_version: "1.0.0",
    schema: "https://trustledger.dev/schemas/aibom/1.0",
    metadata: {
      generated_at: now,
      org: org,
      framework: fw,
      period_start: start,
      period_end: end,
      tool: "TrustLedger v1.0",
      report_id: crypto.randomUUID(),
    },
    summary: {
      total_files:      d.top_risk_files.length,
      attested:         d.top_risk_files.filter(f => f.attested).length,
      unattested:       d.top_risk_files.filter(f => !f.attested).length,
      critical:         d.top_risk_files.filter(f => f.risk_score === "CRITICAL").length,
      high:             d.top_risk_files.filter(f => f.risk_score === "HIGH").length,
      medium:           d.top_risk_files.filter(f => f.risk_score === "MEDIUM").length,
      low:              d.top_risk_files.filter(f => f.risk_score === "LOW").length,
      overall_ai_pct:   d.overall_ai_pct,
      attestation_rate: d.attestation_rate,
      repositories:     d.repos.length,
    },
    components: d.top_risk_files.map((f, i) => ({
      bom_ref:    `comp-${String(i + 1).padStart(3, "0")}`,
      file_path:  f.file_path,
      repository: f.repo,
      ai_probability: f.ai_pct,
      risk_level: f.risk_score,
      scan_id:    f.scan_id,
      pr_number:  f.pr_number,
      attestation: {
        attested:    f.attested,
        reviewer:    f.attested_by ?? null,
        attested_at: f.attested_at ?? null,
      },
    })),
    repositories: d.repos.map(r => ({
      name:             r.repo,
      ai_pct:           r.ai_pct,
      attestation_rate: r.attestation_rate,
      scan_count:       r.scan_count,
      file_count:       r.file_count,
      last_scan:        r.last_scan,
    })),
  };
  const blob = new Blob([JSON.stringify(aibom, null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `trustledger-aibom-${org.replace(/\s+/g,"-").toLowerCase()}-${start}.json`;
  a.click();
  URL.revokeObjectURL(a.href);
}

// ─── Icons ────────────────────────────────────────────────────────────────────

const Spinner = () => <svg className="animate-spin" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg>;
const Download = () => <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>;
const Check   = () => <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>;

// ─── Page ─────────────────────────────────────────────────────────────────────

function ReportsContent() {
  const params = useSearchParams();
  const { profile } = useAuth();
  const orgName = profile?.org_name || profile?.org_slug || "your organisation";
  const initialFw = frameworkFromParam(params?.get("fw"));
  const [fw,         setFw]         = useState<Framework>(initialFw);
  const [start,      setStart]      = useState(offsetDate(1));
  const [end,        setEnd]        = useState(todayStr());
  const [generating, setGenerating] = useState(false);
  const [error,      setError]      = useState<string | null>(null);
  const [success,    setSuccess]    = useState(false);
  const [data,              setData]              = useState<DashboardData | null>(null);
  const [loading,           setLoading]           = useState(true);
  const [dataError,         setDataError]         = useState(false);
  const [reportHistory,     setReportHistory]     = useState<ReportHistoryItem[] | null>(null);
  const [evidence,          setEvidence]          = useState<EvidencePackageView | null>(null);
  const [evidenceFailed,    setEvidenceFailed]    = useState(false);
  const [violationStatuses, setViolationStatuses] = useState<Record<string,string>>({});
  const [pciApplicable,     setPciApplicable]     = useState(true); // assume true until settings load, so PCI-DSS isn't visibly yanked from view on first paint

  // PCI-DSS only applies to orgs with a cardholder data environment -- unlike
  // the other three frameworks, it's opt-in, gated on a real per-org setting
  // (Settings > Compliance Scope) rather than shown unconditionally.
  useEffect(() => {
    authedFetch<{ org: { pci_applicable?: boolean } }>("/api/settings")
      .then(res => setPciApplicable(!!res.org?.pci_applicable))
      .catch(() => {});
  }, []);

  const visibleFrameworks = useMemo(
    () => pciApplicable ? FRAMEWORKS : FRAMEWORKS.filter(f => f !== "PCI DSS"),
    [pciApplicable]
  );

  // If PCI DSS was selected (e.g. via ?fw=PCI-DSS) but the org has since
  // turned off PCI applicability, fall back to a framework that's actually visible.
  useEffect(() => {
    if (fw === "PCI DSS" && !pciApplicable) setFw("SOC 2");
  }, [fw, pciApplicable]);

  // Violation statuses: the server's (same on every device), with this tab's just-made sign-offs on top so they
  // show immediately. Refetched on focus / sign-off / another tab's change, and every minute for other devices.
  useEffect(() => {
    let alive = true;
    function sync() { loadStatuses().then(s => { if (alive) setViolationStatuses(s); }); }
    sync();
    window.addEventListener("focus",   sync);
    window.addEventListener("storage", sync);
    window.addEventListener("tl:badge",sync);
    const id = setInterval(sync, 60_000);
    return () => {
      alive = false;
      window.removeEventListener("focus",   sync);
      window.removeEventListener("storage", sync);
      window.removeEventListener("tl:badge",sync);
      clearInterval(id);
    };
  }, []);

  // Patch data with locally-attested files so all metrics stay current
  const effectiveData = useMemo<DashboardData | null>(() => {
    if (!data) return null;
    const patchedFiles = data.top_risk_files.map(f => {
      if (f.attested) return f;
      const pfx = riskPfx(f.risk_score);
      // Only a resolution counts for the report -- "in review" means someone has started, not that it's signed off.
      return violationStatuses[`${pfx}::${f.scan_id}::${f.file_path}`] === "resolved" ? { ...f, attested: true } : f;
    });
    const totalFiles   = patchedFiles.length || 1;
    const attestedCnt  = patchedFiles.filter(f => f.attested).length;
    const newAttRate   = Math.max(data.attestation_rate, attestedCnt / totalFiles);
    const unresolvedRepos = new Set(
      patchedFiles.filter(f => !f.attested && (f.risk_score === "CRITICAL" || f.risk_score === "HIGH")).map(f => f.repo)
    );
    const newDeploys = Math.min(data.unattested_deploy_count, unresolvedRepos.size);
    return { ...data, top_risk_files: patchedFiles, attestation_rate: newAttRate, unattested_deploy_count: newDeploys };
  }, [data, violationStatuses]);

  const fetchData = useCallback(async () => {
    setLoading(true);
    setDataError(false);
    // Check seed mode first -- demo data is only ever shown here, behind an
    // explicit opt-in toggle, never as a stand-in for a real fetch failure
    // below (the preview has no placeholder data at all).
    if (typeof window !== "undefined" && localStorage.getItem("tl_force_seed") === "1") {
      try {
        const snap = JSON.parse(localStorage.getItem("tl_notif_snapshot") ?? "null") as DashboardData | null;
        if (snap?.repos?.length) { setData(snap); setLoading(false); return; }
      } catch {}
    }
    try {
      const d = await api.dashboard(orgName, 90);
      setData(d);
    } catch {
      // A broken fetch used to silently fall back to placeholder data's
      // fictional repos/scans with no on-screen indication -- a report
      // generated from a broken backend looked identical to a real one.
      // Surface the failure instead; see the error state below.
      setData(null);
      setDataError(true);
    }
    setLoading(false);
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  const fetchHistory = useCallback(async () => {
    try {
      const res = await authedFetch<{ reports: ReportHistoryItem[] }>("/api/report/history?limit=8");
      setReportHistory(res.reports ?? []);
    } catch { setReportHistory([]); }
  }, []);

  useEffect(() => { fetchHistory(); }, [fetchHistory]);

  // Control evidence for the selected framework and period -- the same engine the PDF uses (/api/report).
  useEffect(() => {
    if (!start || !end) return;
    let live = true;
    setEvidence(null); setEvidenceFailed(false);
    const q = new URLSearchParams({
      framework: API_FRAMEWORK_ID[fw],
      period_start: new Date(start).toISOString(),
      period_end: new Date(`${end}T23:59:59.999Z`).toISOString(),
    });
    authedFetch<EvidencePackageView>(`/api/evidence/collect?${q}`)
      .then(p => { if (live) setEvidence(p?.facts ? p : null); if (live && !p?.facts) setEvidenceFailed(true); })
      .catch(() => { if (live) setEvidenceFailed(true); });
    return () => { live = false; };
  }, [fw, start, end]);

  async function generate() {
    if (!start || !end) { setError("Select a date range first."); return; }
    setGenerating(true); setError(null); setSuccess(false);

    try {
      const res = await api.generateReport({
        org: orgName, framework: API_FRAMEWORK_ID[fw],
        period_start: new Date(start).toISOString(),
        period_end:   new Date(`${end}T23:59:59.999Z`).toISOString(),
      });
      // The API can return 200 with a JSON body (not a PDF) if server-side
      // PDF rendering failed -- previously this got force-downloaded as
      // "*.pdf" anyway, producing a file that looked generated but wouldn't
      // open. Only ever download bytes the server actually labelled as a PDF.
      const contentType = res.headers.get("content-type") ?? "";
      if (!res.ok || !contentType.includes("application/pdf")) {
        const body = await res.json().catch(() => null) as { error?: string } | null;
        setError(reportErrorMessage(res.status, body?.error));
        setGenerating(false);
        return;
      }
      const blob = await res.blob();
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement("a");
      a.href = url;
      a.download = `trustledger-${API_FRAMEWORK_ID[fw].toLowerCase()}-${start}.pdf`;
      a.click();
      URL.revokeObjectURL(url);
      setSuccess(true);
      setTimeout(() => setSuccess(false), 4000);
      fetchHistory();
    } catch {
      setError("Couldn't generate the report. Please try again.");
    }
    setGenerating(false);
  }

  // On-screen HTML preview only -- not signed, not the compliance-grade
  // artifact. Kept as a quick way to browse the report before committing
  // to a download.
  function printPreview() {
    window.print();
  }

  const def = FW[fw];

  return (
    <AuthGuard>
      <div className="max-w-7xl mx-auto pb-12">

        {/* ── Top bar ── */}
        <div className="mb-6 flex items-center justify-between">
          <div>
            <h1 className="text-xl font-black text-gray-900">Audit Reports</h1>
            <p className="text-xs text-gray-400 mt-0.5">Signed control-evidence reports for auditors: {visibleFrameworks.join(", ")}</p>
          </div>
          <div className="flex items-center gap-2">
            {visibleFrameworks.map(f => (
              <button key={f} onClick={() => setFw(f)}
                className="px-3 py-1.5 rounded-xl text-xs font-bold transition-all"
                style={fw===f
                  ? { background:FW[f].gradientCss, color:"white", boxShadow:`0 2px 10px ${FW[f].color}40` }
                  : { background:"white", color:"#64748b", border:"1px solid #e2e8f0" }
                }>
                {f}
              </button>
            ))}
          </div>
        </div>

        {/* ── Two-column layout ── */}
        <div className="grid grid-cols-1 lg:grid-cols-[340px_1fr] gap-6 items-start">

          {/* ── Left: Config panel ── */}
          <div className="space-y-4 lg:sticky lg:top-6">

            {/* Framework cards */}
            <div className="section-card p-5">
              <p className="text-[10px] font-black uppercase tracking-wider text-gray-400 mb-3">Framework</p>
              <div className="space-y-2">
                {(Object.entries(FW) as [Framework, FwDef][])
                  .filter(([key]) => (visibleFrameworks as readonly string[]).includes(key))
                  .map(([key, d]) => (
                  <button key={key} onClick={() => setFw(key)}
                    className="w-full flex items-center gap-3 p-3.5 rounded-xl text-left transition-all duration-150"
                    style={{
                      background: fw===key ? d.accentBg : "#f8fafc",
                      border: `2px solid ${fw===key ? d.color : "transparent"}`,
                    }}>
                    <div className="w-9 h-9 rounded-xl flex items-center justify-center text-white shrink-0"
                      style={{ background:d.gradientCss }}>
                      {d.icon}
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-xs font-bold text-gray-800">{key}</p>
                      <p className="text-[10px] text-gray-400 truncate leading-snug mt-0.5">{d.standard}</p>
                    </div>
                    {fw===key && (
                      <div className="w-5 h-5 rounded-full flex items-center justify-center text-white shrink-0"
                        style={{ background:d.color }}>
                        <Check />
                      </div>
                    )}
                  </button>
                ))}
              </div>
            </div>

            {/* Date range */}
            <div className="section-card p-5">
              <div className="flex items-center justify-between mb-3">
                <p className="text-[10px] font-black uppercase tracking-wider text-gray-400">Period</p>
                <div className="flex gap-1 bg-gray-100 p-0.5 rounded-lg">
                  {[{l:"1M",m:1},{l:"3M",m:3},{l:"6M",m:6}].map(r => (
                    <button key={r.l} onClick={() => { setStart(offsetDate(r.m)); setEnd(todayStr()); }}
                      className="px-2.5 py-1 text-[10px] font-bold rounded-md text-gray-500 hover:bg-white hover:text-gray-800 hover:shadow-sm transition-all">
                      {r.l}
                    </button>
                  ))}
                </div>
              </div>
              <div className="grid grid-cols-2 gap-2.5">
                {([{label:"From",val:start,set:setStart},{label:"To",val:end,set:setEnd}] as const).map(f => (
                  <div key={f.label}>
                    <label className="block text-[10px] font-semibold text-gray-400 mb-1.5">{f.label}</label>
                    <input type="date" value={f.val} onChange={e => (f.set as (v: string)=>void)(e.target.value)}
                      className="w-full border border-gray-200 rounded-lg px-3 py-2 text-xs font-medium text-gray-700 bg-white focus:outline-none focus:ring-2 focus:border-transparent transition"
                      style={{ ["--tw-ring-color" as string]:def.color+"50" }} />
                  </div>
                ))}
              </div>
            </div>

            {/* Feedback */}
            {error && (
              <div className="flex items-start gap-2.5 bg-rose-50 border border-rose-200 text-rose-700 px-4 py-3 rounded-xl text-xs">
                <svg className="shrink-0 mt-0.5" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                {error}
              </div>
            )}
            {success && (
              <div className="flex items-center gap-2 bg-emerald-50 border border-emerald-200 text-emerald-700 px-4 py-3 rounded-xl text-xs font-semibold">
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
                Signed report downloaded.
              </div>
            )}
            {dataError && (
              <div className="flex items-start gap-2.5 bg-rose-50 border border-rose-200 text-rose-700 px-4 py-3 rounded-xl text-xs">
                <svg className="shrink-0 mt-0.5" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                <div className="flex-1">
                  <p className="font-semibold">Couldn&apos;t load your organisation&apos;s data</p>
                  <p className="mt-0.5 text-rose-600">Report generation is unavailable until this loads — showing fabricated numbers instead would be worse than showing nothing.</p>
                  <button onClick={fetchData} className="mt-2 font-bold underline hover:no-underline">Try again</button>
                </div>
              </div>
            )}

            {/* Evidence status for the selected framework and period */}
            {!dataError && (
              <div className="section-card p-4 space-y-2.5">
                <p className="text-[10px] font-black uppercase tracking-wider text-gray-400">Evidence status</p>
                {evidenceFailed ? (
                  <p className="text-[11px] text-rose-600">Couldn&apos;t load evidence for this period.</p>
                ) : !evidence ? (
                  <p className="text-[11px] text-gray-400">Collecting evidence…</p>
                ) : (
                  <div className="space-y-1.5">
                    {(["pass", "partial", "fail", "not_tested"] as EvidenceStatus[]).map(s => (
                      <div key={s} className="flex items-center justify-between text-[11px]">
                        <span className="flex items-center gap-1.5 text-gray-600">
                          <span className="w-2 h-2 rounded-full" style={{ background: STATUS_STYLE[s].border }} />
                          {STATUS_LABEL[s]}
                        </span>
                        <span className="font-black tabular-nums text-gray-800">{evidence.status_counts[s]}</span>
                      </div>
                    ))}
                    <p className="text-[10px] text-gray-400 leading-snug pt-1">
                      Controls by what TrustLedger&apos;s records show. Evidence for an auditor, not a certification.
                    </p>
                  </div>
                )}
              </div>
            )}

            {/* Generate button -- downloads the real, signed PDF from /api/report */}
            <button onClick={generate} disabled={generating || dataError}
              className="w-full flex items-center justify-center gap-2.5 py-3.5 rounded-xl font-bold text-sm transition-all active:scale-[0.98]"
              style={generating || dataError
                ? { background:"#f1f5f9", color:"#94a3b8", cursor:"not-allowed" }
                : { background:def.gradientCss, color:"white", boxShadow:`0 4px 16px ${def.color}40` }
              }>
              {generating ? <Spinner /> : <Download />}
              {generating ? "Signing & generating…" : `Generate Signed ${fw} Report`}
            </button>

            {/* Print preview -- on-screen HTML only, not the signed artifact */}
            <button onClick={printPreview} disabled={dataError}
              className="w-full text-center text-[10px] text-gray-400 hover:text-gray-600 disabled:opacity-40 disabled:cursor-not-allowed transition-colors">
              Or print this on-screen preview (<kbd className="font-mono text-[9px] bg-gray-100 border border-gray-300 rounded px-1 py-0.5">Ctrl</kbd>+<kbd className="font-mono text-[9px] bg-gray-100 border border-gray-300 rounded px-1 py-0.5">P</kbd>) — not signed
            </button>

            {/* AIBOM divider */}
            <div className="flex items-center gap-2">
              <div className="flex-1 h-px bg-gray-100" />
              <span className="text-[10px] font-semibold text-gray-400 uppercase tracking-wider">or</span>
              <div className="flex-1 h-px bg-gray-100" />
            </div>

            {/* AIBOM export */}
            <div className="section-card p-4 space-y-2.5">
              <div className="flex items-center gap-2">
                <div className="w-7 h-7 rounded-lg flex items-center justify-center shrink-0"
                  style={{ background:"rgba(99,102,241,0.1)", border:"1px solid rgba(99,102,241,0.2)" }}>
                  <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#6366f1" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                    <polyline points="14 2 14 8 20 8"/>
                    <line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/>
                  </svg>
                </div>
                <div>
                  <p className="text-xs font-bold text-gray-800">AIBOM Export</p>
                  <p className="text-[10px] text-gray-400">AI Bill of Materials · JSON</p>
                </div>
              </div>
              <p className="text-[10px] text-gray-500 leading-relaxed">
                Machine-readable inventory of all AI-authored files with risk levels, attestations, and reviewer chains — compatible with SLSA and supply-chain tooling.
              </p>
              <button
                onClick={() => effectiveData && downloadAIBOM(effectiveData, fw, start, end, orgName)}
                disabled={dataError}
                className="w-full flex items-center justify-center gap-2 py-2.5 rounded-xl text-xs font-bold text-indigo-700 border border-indigo-200 hover:bg-indigo-50 transition-colors disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:bg-transparent"
                style={{ background:"rgba(99,102,241,0.05)" }}>
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>
                </svg>
                Download AIBOM (.json)
              </button>
            </div>

            {/* Recent Reports — real generation history, not a cosmetic list */}
            {reportHistory && reportHistory.length > 0 && (
              <div className="section-card p-4 space-y-2.5">
                <p className="text-[10px] font-black uppercase tracking-wider text-gray-400">Recent Reports</p>
                <div className="divide-y divide-gray-50">
                  {reportHistory.map(r => (
                    <div key={r.id} className="py-2 first:pt-0 last:pb-0">
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-xs font-bold text-gray-700">{r.framework}</span>
                        <span className="text-[9px] text-gray-400" suppressHydrationWarning>{new Date(r.created_at).toLocaleDateString("en-GB",{day:"2-digit",month:"short",year:"numeric"})}</span>
                      </div>
                      <p className="text-[9px] text-gray-400 mt-0.5">
                        {r.period_start.slice(0,10)} → {r.period_end.slice(0,10)}
                        {r.generated_by_email && <> · {r.generated_by_email}</>}
                      </p>
                      <p className="text-[9px] font-mono text-gray-300 truncate mt-0.5" title={r.signature}>sig: {r.signature.slice(0,24)}…</p>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* ── Right: Document preview ── */}
          {/* min-w-0 lets this grid track shrink to the available 1fr space instead of
              stretching the page; overflow-x-auto contains any remaining horizontal
              scroll (from #report-print-area's min-width) to this panel, so the table
              columns scroll into view rather than being clipped off-screen. */}
          <div className="min-w-0 overflow-x-auto">
            {loading && !data ? (
              <div className="section-card flex flex-col items-center justify-center h-80 gap-4">
                <svg className="animate-spin w-8 h-8" viewBox="0 0 24 24" fill="none" stroke={def.color} strokeWidth="2">
                  <path d="M21 12a9 9 0 1 1-6.219-8.56"/>
                </svg>
                <p className="text-sm font-medium text-gray-400">Loading report data…</p>
              </div>
            ) : dataError ? (
              <div className="section-card flex flex-col items-center justify-center h-80 gap-3 text-center px-8">
                <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#f43f5e" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                <p className="text-sm font-bold text-gray-700">Couldn&apos;t load report data</p>
                <p className="text-xs text-gray-400 max-w-sm">No preview is shown rather than one built from placeholder data.</p>
                <button onClick={fetchData} className="text-xs font-bold text-indigo-600 hover:text-indigo-800">Try again</button>
              </div>
            ) : (
              effectiveData && <ReportDocument data={effectiveData} fw={fw} start={start} end={end} violationStatuses={violationStatuses} org={orgName} generatedBy={profile?.email ?? undefined} evidence={evidence} evidenceFailed={evidenceFailed} />
            )}
          </div>
        </div>
      </div>
    </AuthGuard>
  );
}

export default function ReportsPage() {
  const tz = useTimezone();
  return (
    <Suspense fallback={
      <div className="flex items-center justify-center h-64">
        <svg className="animate-spin w-8 h-8 text-indigo-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M21 12a9 9 0 1 1-6.219-8.56"/>
        </svg>
      </div>
    }>
      <ReportsContent />
    </Suspense>
  );
}
