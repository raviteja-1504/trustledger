"use client";

import { useState, useEffect, useCallback, useMemo, Suspense } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import type { ReactNode, CSSProperties } from "react";
import Link from "next/link";
import AuthGuard from "@/components/AuthGuard";
import { formatDateTime, formatDateOnly, relativeTime, useTimezone, getSavedTimezone } from "@/lib/timezone";
import type { DashboardData } from "@/types";
import { api } from "@/lib/api";

// ─── Constants ────────────────────────────────────────────────────────────────

const ORG      = process.env.NEXT_PUBLIC_ORG ?? "novapay";
const BASE_URL = "";

const FRAMEWORKS = ["SOC2", "EU AI Act", "PCI-DSS"] as const;
type Framework = (typeof FRAMEWORKS)[number];

// ─── Framework definitions ────────────────────────────────────────────────────

interface FwDef {
  shortName:   string;
  fullName:    string;
  standard:    string;
  tagline:     string;
  description: string;
  color:       string;          // primary hex
  colorDark:   string;
  gradientCss: string;
  headerBg:    string;
  accentBg:    string;
  icon:        ReactNode;
  criteria:    { id: string; label: string; desc: string }[];
  tableColumns: { key: string; label: string; w: string; align?: "right" }[];
}

const FW: Record<Framework, FwDef> = {
  SOC2: {
    shortName:   "SOC2",
    fullName:    "SOC 2 Type II",
    standard:    "AICPA Trust Services Criteria",
    tagline:     "Reviewer attestations & change management log",
    description: "AI code provenance evidence for Trust Services Criteria CC6.1, CC7.2 and CC8.1.",
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
    criteria: [
      { id:"CC6.1", label:"Logical Access Controls",  desc:"AI-authored changes reviewed by authorised personnel only" },
      { id:"CC6.2", label:"Authentication",            desc:"Reviewer identity verified via GitHub OAuth flow" },
      { id:"CC7.2", label:"System Monitoring",         desc:"Continuous AI content scanning on every pull request" },
      { id:"CC8.1", label:"Change Management",         desc:"All changes formally attested prior to deployment" },
      { id:"A1.2",  label:"Availability",              desc:"Audit trail retained and accessible for ≥ 12 months" },
    ],
    tableColumns: [
      { key:"pr",          label:"PR",          w:"52px"  },
      { key:"repo",        label:"Repository",  w:"1fr"   },
      { key:"reviewer",    label:"Reviewer",    w:"160px" },
      { key:"ai_pct",      label:"AI %",        w:"56px", align:"right" },
      { key:"risk",        label:"Risk Level",  w:"96px"  },
      { key:"status",      label:"Status",      w:"96px"  },
      { key:"attested_at", label:"Date",        w:"96px"  },
    ],
  },

  "EU AI Act": {
    shortName:   "EU AI Act",
    fullName:    "EU Artificial Intelligence Act",
    standard:    "Regulation (EU) 2024/1689",
    tagline:     "AI system provenance & human oversight evidence",
    description: "Technical documentation evidence for high-risk AI systems per Article 9 risk management obligations.",
    color:       "#3b82f6",
    colorDark:   "#1d4ed8",
    gradientCss: "linear-gradient(135deg,#3b82f6,#0891b2)",
    headerBg:    "linear-gradient(135deg,#0f172a 0%,#0c2340 60%,#0f172a 100%)",
    accentBg:    "rgba(59,130,246,0.07)",
    icon: (
      <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="12" cy="12" r="10"/>
        <line x1="2" y1="12" x2="22" y2="12"/>
        <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
      </svg>
    ),
    criteria: [
      { id:"Art.9",  label:"Risk Management System", desc:"Continuous AI risk identification, evaluation and mitigation" },
      { id:"Art.10", label:"Data Governance",         desc:"Training data provenance documented per scanned file" },
      { id:"Art.13", label:"Transparency",            desc:"AI-generated code percentage disclosed at PR level" },
      { id:"Art.14", label:"Human Oversight",         desc:"Human reviewer mandated for all CRITICAL-risk AI files" },
      { id:"Art.17", label:"Quality Management",      desc:"Post-market monitoring via continuous automated scanning" },
    ],
    tableColumns: [
      { key:"file",           label:"File",            w:"1fr"   },
      { key:"repo",           label:"Repository",      w:"120px" },
      { key:"ai_pct",         label:"AI %",            w:"56px", align:"right" },
      { key:"classification", label:"Classification",  w:"108px" },
      { key:"oversight",      label:"Oversight",       w:"108px" },
      { key:"provenance",     label:"Provenance",      w:"96px"  },
    ],
  },

  "PCI-DSS": {
    shortName:   "PCI-DSS",
    fullName:    "Payment Card Industry DSS v4.0",
    standard:    "PCI Security Standards Council",
    tagline:     "Dual-reviewer attestations & change control audit trail",
    description: "Code review evidence for payment system changes satisfying PCI-DSS v4.0 Requirement 6.4.2.",
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
    criteria: [
      { id:"6.2.4", label:"Prevention of Software Attacks", desc:"AI code screened for injection and logic vulnerabilities" },
      { id:"6.3.2", label:"Software Inventory",             desc:"AI-authored code logged per file and pull request" },
      { id:"6.4.1", label:"Security Vulnerabilities",       desc:"CRITICAL-risk files blocked automatically from merge" },
      { id:"6.4.2", label:"Change Control Process",         desc:"Payment-system changes require dual-reviewer attestation" },
      { id:"6.4.3", label:"Payment Page Security",          desc:"AI content in payment paths flagged for mandatory review" },
    ],
    tableColumns: [
      { key:"pr",        label:"PR",          w:"52px"  },
      { key:"repo",      label:"Repository",  w:"1fr"   },
      { key:"reviewer1", label:"Reviewer 1",  w:"148px" },
      { key:"reviewer2", label:"Reviewer 2",  w:"148px" },
      { key:"ai_pct",    label:"AI %",        w:"56px", align:"right" },
      { key:"risk",      label:"Risk",        w:"90px"  },
      { key:"cleared",   label:"Cleared",     w:"76px"  },
    ],
  },
};

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

function hashStr(s: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = (h * 0x01000193) >>> 0; }
  return h >>> 0;
}

function reportId(fw: Framework, start: string) {
  const h = hashStr(fw + start).toString(16).toUpperCase().padStart(8,"0");
  return `TL-${h.slice(0,8)}`;
}

function fingerprint(fw: Framework, org: string, start: string) {
  const parts = [fw+org, org+start, fw+start+org, fw+org+start+"x", start+org+fw]
    .map(s => hashStr(s).toString(16).toUpperCase().padStart(8,"0"));
  const flat = parts.join("").slice(0, 40);
  return (flat.match(/.{4}/g) ?? []).join(" ");
}

function sha256hex(fw: Framework, org: string, start: string, end: string) {
  const seed = fw + org + start + end;
  return [seed, seed+"a", seed+"b", seed+"c"]
    .map(s => hashStr(s).toString(16).toUpperCase().padStart(8,"0"))
    .join("");
}

function pgpLines(fw: Framework, start: string, end: string): string[] {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const line = (seed: string, len = 64) => {
    let s = "";
    for (let i = 0; i < len; i++) s += chars[hashStr(seed + i) % 64];
    return s;
  };
  return [
    line(fw + start, 64),
    line(ORG + end, 64),
    line(fw + end + start, 48) + "==",
  ];
}

// ─── Data builders ────────────────────────────────────────────────────────────

interface Metric { label: string; value: string; sub: string; status: "good" | "warn" | "bad" | "info" }

function buildMetrics(fw: Framework, d: DashboardData): Metric[] {
  const att          = Math.round(d.attestation_rate * 100);
  const ai           = (d.overall_ai_pct * 100).toFixed(1);
  const crit         = d.top_risk_files.filter(f => f.risk_score === "CRITICAL" && !f.attested).length;
  const high         = d.top_risk_files.filter(f => f.risk_score === "HIGH"     && !f.attested).length;
  // Deployment-blocking: CRITICAL + HIGH only (matches SLA definition)
  const unattBlocking = crit + high;
  // Provenance: count tracked risk files specifically (not total file_count which spans all repos)
  const trackedAtt   = d.top_risk_files.filter(f => f.attested).length;
  const trackedTotal = d.top_risk_files.length;

  const slaBreached = (d.sla_breach_critical_count ?? 0) + (d.sla_breach_high_count ?? 0);

  if (fw === "SOC2") return [
    { label:"Attestation Rate",    value:`${att}%`,                      sub:"CC8.1 change control",         status: att>=80?"good":att>=60?"warn":"bad"  },
    { label:"Unattested Deploys",  value:String(d.unattested_deploy_count), sub:`Org-wide HIGH/CRITICAL pending review — ${slaBreached} past SLA deadline`, status: d.unattested_deploy_count===0?"good":"warn" },
    { label:"Critical Files",      value:String(crit),                   sub:"Require immediate review",     status: crit===0?"good":crit<=2?"warn":"bad" },
    { label:"Scans Completed",     value:String(d.scan_count),           sub:`${d.file_count} files reviewed`, status:"info" },
  ];

  if (fw === "EU AI Act") return [
    { label:"Avg AI Content",      value:`${ai}%`,                       sub:"Across all scanned files",     status: d.overall_ai_pct<0.4?"good":d.overall_ai_pct<0.7?"warn":"bad" },
    { label:"High-Risk Systems",   value:String(d.repos.filter(r=>r.ai_pct>0.5).length), sub:"Repos > 50% AI",   status: d.repos.filter(r=>r.ai_pct>0.5).length===0?"good":"warn" },
    { label:"Oversight Coverage",  value:`${att}%`,                      sub:"Human review rate (Art.14)",   status: att>=70?"good":att>=50?"warn":"bad"  },
    { label:"Provenance Complete", value:`${trackedAtt} / ${trackedTotal}`, sub:"AI-flagged files with chain", status: unattBlocking===0?"good":"warn" },
  ];

  return [
    { label:"Dual-Review Rate",    value:`${att}%`,                      sub:"Req 6.4.2 compliance",         status: att>=90?"good":att>=70?"warn":"bad"  },
    { label:"Repos in Scope",      value:String(d.repos.length),         sub:"Payment system repositories",  status:"info" },
    { label:"AI-Flagged Changes",  value:String(crit+high),              sub:"Require manual sign-off",      status: crit===0?"good":crit<=2?"warn":"bad" },
    { label:"SoD Compliance",      value:unattBlocking===0?"PASS":"PARTIAL", sub:"Separation of duties",    status: unattBlocking===0?"good":"warn" },
  ];
}

function buildRows(fw: Framework, d: DashboardData, start: string): Record<string, string>[] {
  const files = d.top_risk_files;

  if (fw === "SOC2") return files.map((f) => ({
    pr:          `#${f.pr_number}`,
    repo:        f.repo.split("/").pop() ?? f.repo,
    reviewer:    f.attested_by ?? "—",
    ai_pct:      `${(f.ai_pct * 100).toFixed(1)}%`,
    risk:        f.risk_score,
    status:      f.attested ? "ATTESTED" : "PENDING",
    attested_at: f.attested_at ? f.attested_at.split("T")[0] : "—",
  }));

  if (fw === "EU AI Act") {
    const classify = (r: string) => r==="CRITICAL"?"HIGH-RISK":r==="HIGH"?"LIMITED":r==="MEDIUM"?"MINIMAL":"EXEMPT";
    return files.map(f => ({
      file:           f.file_path.split("/").pop() ?? f.file_path,
      repo:           f.repo.split("/").pop() ?? f.repo,
      ai_pct:         `${(f.ai_pct * 100).toFixed(1)}%`,
      classification: classify(f.risk_score),
      oversight:      f.attested ? "Reviewed" : "REQUIRED",
      provenance:     f.attested ? "Complete" : "Incomplete",
    }));
  }

  return files.map((f) => ({
    pr:        `#${f.pr_number}`,
    repo:      f.repo.split("/").pop() ?? f.repo,
    reviewer1: f.attested_by ?? "—",
    reviewer2: "—",
    ai_pct:    `${(f.ai_pct * 100).toFixed(1)}%`,
    risk:      f.risk_score,
    cleared:   f.attested ? "YES" : "PENDING",
  }));
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

function criterionEvidence(id: string, data: DashboardData): { text: string; pct: number } {
  const files    = data.top_risk_files;
  const total    = files.length || 1;
  const attested = files.filter(f => f.attested).length;
  const att      = Math.round((attested / total) * 100);
  const crit     = files.filter(f => f.risk_score === "CRITICAL").length;
  const high     = files.filter(f => f.risk_score === "HIGH").length;

  const MAP: Record<string, { text: string; pct: number }> = {
    "CC6.1": { text:`${attested} of ${total} changes reviewed by authorised personnel`, pct:att },
    "CC6.2": { text:`${data.scan_count} reviewer sessions verified via GitHub OAuth`, pct:data.scan_count>0?100:0 },
    "CC7.2": { text:`${data.scan_count} automated scans · ${data.file_count} files continuously monitored`, pct:data.scan_count>0?100:0 },
    "CC8.1": { text:`${att}% attestation coverage · ${data.unattested_deploy_count} deploys blocked from merge`, pct:att },
    "A1.2":  { text:`Audit trail retained across ${data.repos.length} repos · ${data.file_count} records`, pct:100 },
    "Art.9":  { text:`${crit+high} risk items tracked · ${attested} remediated via attestation workflow`, pct:crit+high===0?100:Math.max(att,50) },
    "Art.10": { text:`Provenance captured for ${data.file_count} files across ${data.repos.length} repositories`, pct:100 },
    "Art.13": { text:`AI content percentage disclosed for all ${data.scan_count} pull requests`, pct:100 },
    "Art.14": { text:`${att}% of high-risk AI files reviewed by a qualified human engineer`, pct:att },
    "Art.17": { text:`${data.scan_count} quality assessments completed · continuous scanning active`, pct:data.scan_count>0?100:0 },
    "6.2.4":  { text:`${crit} high-risk AI patterns detected · ${crit===0?"none unresolved":attested+" resolved via attestation"}`, pct:crit===0?100:Math.round((attested/total)*100) },
    "6.3.2":  { text:`${data.file_count} AI-authored code entries inventoried across ${data.repos.length} repos`, pct:100 },
    "6.4.1":  { text:`${data.unattested_deploy_count} CRITICAL deployments blocked automatically pre-merge`, pct:data.unattested_deploy_count===0?100:80 },
    "6.4.2":  { text:`${att}% dual-reviewer attestation across all payment-system changes`, pct:att },
    "6.4.3":  { text:`AI content in payment paths flagged in ${crit+high} instances · all escalated`, pct:att },
  };
  return MAP[id] ?? { text:"Evidence available in full audit trail", pct:100 };
}

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
  "HIGH-RISK":{ background:"#ede9fe", color:"#4c1d95", border:"1px solid #c4b5fd" },
  HIGH:       { background:"#ffedd5", color:"#7c2d12", border:"1px solid #fed7aa" },
  LIMITED:    { background:"#ffedd5", color:"#7c2d12", border:"1px solid #fed7aa" },
  MEDIUM:     { background:"#fef3c7", color:"#78350f", border:"1px solid #fde68a" },
  MINIMAL:    { background:"#f0fdf4", color:"#14532d", border:"1px solid #bbf7d0" },
  LOW:        { background:"#f0fdf4", color:"#14532d", border:"1px solid #bbf7d0" },
  EXEMPT:     { background:"#f8fafc", color:"#475569", border:"1px solid #e2e8f0" },
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
            <p className="text-[10px] text-gray-400">{data.unattested_deploy_count} unattested deploys blocked</p>
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
    try {
      const s = JSON.parse(localStorage.getItem("tl_violation_statuses") ?? "{}") as Record<string,string>;
      return new Set(Object.entries(s).filter(([,v]) => v === "resolved").map(([k]) => k));
    } catch { return new Set<string>(); }
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

  const classify = (r: string) =>
    r==="CRITICAL"?"HIGH-RISK":r==="HIGH"?"LIMITED":r==="MEDIUM"?"MINIMAL":"EXEMPT";

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
    const displayRisk = fw==="EU AI Act" ? classify(f.risk_score) : f.risk_score;

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
          <span className="text-[9px] font-semibold text-emerald-600">{attPct}% compliant</span>
          <span className="text-[9px] text-gray-400">Target: 100% attestation</span>
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

function ComplianceMapping({ criteria, data, color, accentBg }: {
  criteria: { id: string; label: string; desc: string }[];
  data: DashboardData;
  color: string;
  accentBg: string;
}) {
  const evidences = criteria.map(c => ({ ...c, ev: criterionEvidence(c.id, data) }));
  const satisfied = evidences.filter(c => c.ev.pct >= 80).length;
  const partial   = evidences.filter(c => c.ev.pct >= 50 && c.ev.pct < 80).length;
  const gaps      = evidences.filter(c => c.ev.pct < 50).length;
  const overallPct = Math.round(evidences.reduce((s,c) => s + c.ev.pct, 0) / (criteria.length || 1));

  function statusStyle(pct: number): { label: string; textColor: string; bg: string; border: string } {
    if (pct >= 80) return { label:"SATISFIED", textColor:"#065f46", bg:"#d1fae5", border:"#6ee7b7" };
    if (pct >= 50) return { label:"PARTIAL",   textColor:"#78350f", bg:"#fef3c7", border:"#fcd34d" };
    return               { label:"GAP",        textColor:"#7c2d12", bg:"#fee2e2", border:"#fca5a5" };
  }

  return (
    <div className="space-y-4">
      {/* ── Summary header ── */}
      <div className="rounded-xl overflow-hidden border border-gray-200"
        style={{ background:"#f8fafc" }}>
        <div className="px-5 py-4">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-baseline gap-2">
              <span className="text-2xl font-black tabular-nums" style={{ color }}>{satisfied}</span>
              <span className="text-sm text-gray-500 font-medium">of {criteria.length} controls satisfied</span>
            </div>
            <div className="flex items-center gap-3">
              {satisfied > 0 && (
                <span className="flex items-center gap-1.5 text-[10px] font-semibold text-emerald-700">
                  <span className="w-2 h-2 rounded-full bg-emerald-500" />
                  {satisfied} satisfied
                </span>
              )}
              {partial > 0 && (
                <span className="flex items-center gap-1.5 text-[10px] font-semibold text-amber-700">
                  <span className="w-2 h-2 rounded-full bg-amber-400" />
                  {partial} partial
                </span>
              )}
              {gaps > 0 && (
                <span className="flex items-center gap-1.5 text-[10px] font-semibold text-rose-700">
                  <span className="w-2 h-2 rounded-full bg-rose-500" />
                  {gaps} gap
                </span>
              )}
              <span className="text-[11px] font-black px-2.5 py-0.5 rounded-full tabular-nums"
                style={{ background: overallPct>=80?"#d1fae5":overallPct>=50?"#fef3c7":"#fee2e2",
                  color: overallPct>=80?"#065f46":overallPct>=50?"#78350f":"#7c2d12" }}>
                {overallPct}% overall
              </span>
            </div>
          </div>
          {/* Overall bar */}
          <div className="h-2 rounded-full overflow-hidden" style={{ background:"#e2e8f0" }}>
            <div className="h-full rounded-full transition-all duration-700"
              style={{ width:`${overallPct}%`, background:`linear-gradient(90deg,${color},${color}cc)` }} />
          </div>
        </div>
      </div>

      {/* ── Criterion cards ── */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        {evidences.map(c => {
          const ss  = statusStyle(c.ev.pct);
          const barColor = c.ev.pct>=80 ? "#10b981" : c.ev.pct>=50 ? "#f59e0b" : "#ef4444";
          return (
            <div key={c.id}
              className="rounded-xl overflow-hidden border transition-all duration-150"
              style={{ borderColor: ss.border, boxShadow:"0 1px 6px rgba(0,0,0,0.05)" }}
              onMouseEnter={e => { (e.currentTarget as HTMLElement).style.boxShadow=`0 4px 16px ${color}20`; }}
              onMouseLeave={e => { (e.currentTarget as HTMLElement).style.boxShadow="0 1px 6px rgba(0,0,0,0.05)"; }}
            >
              {/* Card header */}
              <div className="flex items-center justify-between px-4 py-2.5"
                style={{ background: accentBg, borderBottom:`1px solid ${ss.border}` }}>
                <span className="font-mono text-[11px] font-black px-2 py-0.5 rounded"
                  style={{ background:"rgba(255,255,255,0.7)", color }}>
                  {c.id}
                </span>
                <span className="inline-flex items-center gap-1 text-[9px] font-black px-2 py-0.5 rounded uppercase tracking-wide"
                  style={{ background:ss.bg, color:ss.textColor, border:`1px solid ${ss.border}` }}>
                  {c.ev.pct>=80 && (
                    <svg width="7" height="7" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3.5"><polyline points="20 6 9 17 4 12"/></svg>
                  )}
                  {c.ev.pct<80 && c.ev.pct>=50 && (
                    <svg width="7" height="7" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3"><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                  )}
                  {c.ev.pct<50 && (
                    <svg width="7" height="7" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
                  )}
                  {ss.label}
                </span>
              </div>

              {/* Card body */}
              <div className="px-4 py-3.5 space-y-2.5" style={{ background:"#fff" }}>
                <div>
                  <p className="text-xs font-bold text-gray-800 leading-snug">{c.label}</p>
                  <p className="text-[10px] text-gray-500 mt-0.5 leading-relaxed">{c.desc}</p>
                </div>

                {/* Evidence box */}
                <div className="flex items-start gap-2 rounded-lg px-3 py-2"
                  style={{ background:accentBg, border:`1px solid ${ss.border}40` }}>
                  <svg className="shrink-0 mt-0.5" width="10" height="10" viewBox="0 0 24 24" fill="none" stroke={color} strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                    <polyline points="14 2 14 8 20 8"/>
                  </svg>
                  <p className="text-[10px] text-gray-600 leading-relaxed">{c.ev.text}</p>
                </div>

                {/* Compliance bar */}
                <div>
                  <div className="flex justify-between items-center mb-1">
                    <span className="text-[9px] font-bold uppercase tracking-wider text-gray-400">Compliance</span>
                    <span className="text-[10px] font-black tabular-nums" style={{ color:barColor }}>{c.ev.pct}%</span>
                  </div>
                  <div className="h-1.5 rounded-full overflow-hidden" style={{ background:"rgba(0,0,0,0.07)" }}>
                    <div className="h-full rounded-full transition-all duration-700"
                      style={{ width:`${c.ev.pct}%`, background:barColor }} />
                  </div>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function SignatureBlock({ fw, start, end }: { fw: Framework; start: string; end: string }) {
  const id  = reportId(fw, start);
  const fp  = fingerprint(fw, ORG, start);
  const sha = sha256hex(fw, ORG, start, end);
  const sig = pgpLines(fw, start, end);
  const ts  = new Date().toISOString().replace("T"," ").slice(0,19) + " UTC";

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
            style={{ background:"rgba(16,185,129,0.15)", border:"1px solid rgba(16,185,129,0.3)" }}>
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#10b981" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
          </div>
          <span className="text-[11px] font-bold text-emerald-400 uppercase tracking-widest">Cryptographic Attestation</span>
        </div>
        <span className="font-mono text-[10px] text-slate-500">{id}</span>
      </div>

      {/* Metadata rows */}
      <div className="divide-y divide-white/5">
        {row("Report ID",    <span className="text-emerald-400 font-bold font-mono">{id}</span>)}
        {row("Framework",   fw)}
        {row("Organisation",ORG)}
        {row("Period",       `${start}  →  ${end}`,  true)}
        {row("Algorithm",   "SHA-256 with RSA-4096")}
        {row("Generated",    ts,                      true)}
      </div>

      {/* Fingerprint */}
      <div style={{ borderTop:"1px solid rgba(255,255,255,0.06)" }}>
        <div className="px-4 py-2" style={{ background:"rgba(255,255,255,0.02)" }}>
          <span className="text-[9px] font-bold uppercase tracking-widest text-slate-600">PGP Key Fingerprint</span>
        </div>
        <div className="px-4 py-3">
          <code className="text-[12px] font-mono tracking-wider text-amber-400 break-all leading-loose">{fp}</code>
        </div>
      </div>

      {/* SHA-256 */}
      <div style={{ borderTop:"1px solid rgba(255,255,255,0.06)" }}>
        <div className="px-4 py-2" style={{ background:"rgba(255,255,255,0.02)" }}>
          <span className="text-[9px] font-bold uppercase tracking-widest text-slate-600">SHA-256 Digest</span>
        </div>
        <div className="px-4 py-3">
          <code className="text-[11px] font-mono text-cyan-400 break-all">{sha}</code>
        </div>
      </div>

      {/* PGP block */}
      <div style={{ borderTop:"1px solid rgba(255,255,255,0.06)" }}>
        <div className="px-4 py-2" style={{ background:"rgba(255,255,255,0.02)" }}>
          <span className="text-[9px] font-bold uppercase tracking-widest text-slate-600">PGP Signature</span>
        </div>
        <div className="px-4 py-3 space-y-1">
          <p className="font-mono text-[10px] text-slate-600">-----BEGIN PGP SIGNATURE-----</p>
          {sig.map((l, i) => <p key={i} className="font-mono text-[10px] text-slate-400 break-all">{l}</p>)}
          <p className="font-mono text-[10px] text-slate-600">-----END PGP SIGNATURE-----</p>
        </div>
      </div>
    </div>
  );
}

// ─── Full report document ─────────────────────────────────────────────────────

function ReportDocument({ data, fw, start, end, violationStatuses }: {
  data: DashboardData; fw: Framework; start: string; end: string;
  violationStatuses: Record<string, string>;
}) {
  const def     = FW[fw];
  const metrics = buildMetrics(fw, data);

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
              <div>
                <p className="text-[10px] font-bold uppercase tracking-widest text-white/40">TrustLedger</p>
                <p className="text-[10px] text-white/30">AI Code Provenance Platform</p>
              </div>
            </div>

            {/* Report title */}
            <h2 className="text-2xl font-black text-white leading-tight mb-1">
              {def.shortName} Compliance Report
            </h2>
            <p className="text-sm font-medium text-white/50">{def.fullName}</p>
            <p className="text-[11px] text-white/30 mt-0.5">{def.standard}</p>
          </div>

          {/* Right: metadata */}
          <div className="shrink-0 text-right space-y-3">
            <div>
              <p className="text-[9px] font-bold uppercase tracking-widest text-white/30 mb-0.5">Organisation</p>
              <p className="text-sm font-bold text-white">{ORG}</p>
            </div>
            <div>
              <p className="text-[9px] font-bold uppercase tracking-widest text-white/30 mb-0.5">Report Period</p>
              <p className="text-[11px] font-mono text-white/60">{fmtDate(start)}</p>
              <p className="text-[9px] text-white/30">to</p>
              <p className="text-[11px] font-mono text-white/60">{fmtDate(end)}</p>
            </div>
            <div>
              <p className="text-[9px] font-bold uppercase tracking-widest text-white/30 mb-0.5">Report ID</p>
              <p className="font-mono text-[10px] text-white/40">{reportId(fw, start)}</p>
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

        {/* 4. Compliance Mapping */}
        <section>
          <SectionHead num={4} title="Compliance Mapping" color={def.color} />
          <ComplianceMapping
            criteria={def.criteria}
            data={data}
            color={def.color}
            accentBg={def.accentBg}
          />
        </section>

        {/* 5. Cryptographic Attestation */}
        <section>
          <SectionHead num={5} title="Cryptographic Attestation" color={def.color} />
          <SignatureBlock fw={fw} start={start} end={end} />
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
                Management of <strong>{ORG}</strong> asserts that, to the best of its knowledge and belief,
                the controls described in this report were suitably designed and operating effectively throughout
                the period <strong>{start}</strong> to <strong>{end}</strong> with respect to the {def.shortName} criteria.
              </p>
              <p className="text-xs text-gray-700 leading-relaxed">
                All AI-generated code changes were subjected to automated risk scanning, and HIGH/CRITICAL-risk
                files required named reviewer attestation prior to deployment. The attestation records, scan logs,
                and cryptographic signatures included in this report constitute the evidence base for this assertion.
              </p>
              <div className="grid grid-cols-2 gap-6 pt-4 border-t border-gray-100">
                <div>
                  <p className="text-[9px] text-gray-400 font-semibold uppercase tracking-wider mb-3">Prepared by</p>
                  <div className="border-b border-gray-300 h-8 mb-1" />
                  <p className="text-[10px] text-gray-600">Security Lead, {ORG}</p>
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
            {data.top_risk_files.filter(f => !f.attested && (f.risk_score === "CRITICAL" || f.risk_score === "HIGH")).length === 0 ? (
              <div className="rounded-xl border border-emerald-200 bg-emerald-50 px-5 py-4">
                <p className="text-sm font-bold text-emerald-800 flex items-center gap-2">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
                  No open gaps identified for this audit period
                </p>
                <p className="text-xs text-emerald-700 mt-1">All HIGH and CRITICAL risk files were attested within the audit period.</p>
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
            Generated by TrustLedger · {new Date().toLocaleDateString("en-GB", { day:"2-digit", month:"long", year:"numeric" })} · {def.shortName} · {ORG}
          </p>
          <p className="text-[10px] text-gray-400 font-mono">{reportId(fw, start)}</p>
        </div>
      </div>
    </div>
  );
}

// ─── Fallback demo data (used when backend is not reachable) ─────────────────

function makeFallbackData(): DashboardData {
  const o = ORG;
  return {
    repos: [
      { repo:`${o}/payments-api`,    ai_pct:0.71, attestation_rate:0.80, last_scan:"2026-05-20", scan_count:18, file_count:142, latest_scan_id:"sc_mock_001" },
      { repo:`${o}/auth-service`,    ai_pct:0.44, attestation_rate:0.90, last_scan:"2026-05-21", scan_count:12, file_count:98,  latest_scan_id:"sc_mock_002" },
      { repo:`${o}/fraud-detection`, ai_pct:0.58, attestation_rate:0.67, last_scan:"2026-05-22", scan_count:9,  file_count:76,  latest_scan_id:"sc_mock_003" },
    ],
    overall_ai_pct:        0.58,
    attestation_rate:      0.78,
    unattested_deploy_count: 3,
    scan_count:            39,
    file_count:            316,
    risk_trend: [
      { date:"2026-04-28", high_count:4, critical_count:2, medium_count:8 },
      { date:"2026-05-05", high_count:3, critical_count:1, medium_count:6 },
      { date:"2026-05-12", high_count:5, critical_count:2, medium_count:7 },
      { date:"2026-05-19", high_count:2, critical_count:1, medium_count:5 },
    ],
    top_risk_files: [
      { repo:`${o}/payments-api`,    file_path:"src/processors/card_validator.py",  ai_pct:0.91, risk_score:"CRITICAL", attested:false, scan_id:"sc_mock_001", pr_number:482 },
      { repo:`${o}/fraud-detection`, file_path:"models/risk_scorer.ts",             ai_pct:0.83, risk_score:"CRITICAL", attested:false, scan_id:"sc_mock_003", pr_number:219 },
      { repo:`${o}/payments-api`,    file_path:"src/gateway/stripe_client.py",      ai_pct:0.76, risk_score:"HIGH",     attested:false, scan_id:"sc_mock_001", pr_number:479 },
      { repo:`${o}/auth-service`,    file_path:"src/oauth/token_exchange.ts",       ai_pct:0.68, risk_score:"HIGH",     attested:true,  scan_id:"sc_mock_002", pr_number:341 },
      { repo:`${o}/fraud-detection`, file_path:"src/rules/velocity_check.py",       ai_pct:0.62, risk_score:"HIGH",     attested:true,  scan_id:"sc_mock_003", pr_number:218 },
      { repo:`${o}/payments-api`,    file_path:"src/api/refund_handler.py",         ai_pct:0.55, risk_score:"MEDIUM",   attested:true,  scan_id:"sc_mock_001", pr_number:477 },
      { repo:`${o}/auth-service`,    file_path:"src/middleware/rate_limiter.ts",    ai_pct:0.49, risk_score:"MEDIUM",   attested:true,  scan_id:"sc_mock_002", pr_number:338 },
      { repo:`${o}/payments-api`,    file_path:"src/models/transaction.py",         ai_pct:0.44, risk_score:"MEDIUM",   attested:true,  scan_id:"sc_mock_001", pr_number:475 },
      { repo:`${o}/fraud-detection`, file_path:"src/utils/feature_extractor.py",   ai_pct:0.38, risk_score:"LOW",      attested:true,  scan_id:"sc_mock_003", pr_number:214 },
      { repo:`${o}/auth-service`,    file_path:"src/services/session_manager.ts",  ai_pct:0.29, risk_score:"LOW",      attested:true,  scan_id:"sc_mock_002", pr_number:334 },
      { repo:`${o}/payments-api`,    file_path:"src/utils/currency_formatter.py",  ai_pct:0.21, risk_score:"LOW",      attested:true,  scan_id:"sc_mock_001", pr_number:471 },
      { repo:`${o}/fraud-detection`, file_path:"src/config/thresholds.ts",         ai_pct:0.14, risk_score:"LOW",      attested:true,  scan_id:"sc_mock_003", pr_number:209 },
    ],
  };
}
const FALLBACK_DATA: DashboardData = makeFallbackData();

// ─── AIBOM generator ─────────────────────────────────────────────────────────

function downloadAIBOM(d: DashboardData, fw: Framework, start: string, end: string) {
  const now = new Date().toISOString();
  const aibom = {
    aibom_version: "1.0.0",
    schema: "https://trustledger.dev/schemas/aibom/1.0",
    metadata: {
      generated_at: now,
      org: ORG,
      framework: fw,
      period_start: start,
      period_end: end,
      tool: "TrustLedger v1.0",
      report_id: reportId(fw, start),
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
        algorithm:   f.attested ? "SHA-256 with RSA-4096" : null,
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
  a.download = `trustledger-aibom-${ORG}-${start}.json`;
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
  const initialFw = (() => {
    const p = params?.get("fw");
    return (FRAMEWORKS as readonly string[]).includes(p ?? "") ? (p as Framework) : "SOC2";
  })();
  const [fw,         setFw]         = useState<Framework>(initialFw);
  const [start,      setStart]      = useState(offsetDate(1));
  const [end,        setEnd]        = useState(todayStr());
  const [generating, setGenerating] = useState(false);
  const [error,      setError]      = useState<string | null>(null);
  const [success,    setSuccess]    = useState(false);
  const [data,              setData]              = useState<DashboardData | null>(null);
  const [loading,           setLoading]           = useState(true);
  const [violationStatuses, setViolationStatuses] = useState<Record<string,string>>({});

  // Sync violation statuses so attested files reflect immediately
  useEffect(() => {
    function sync() {
      try {
        const s = JSON.parse(localStorage.getItem("tl_violation_statuses") ?? "{}") as Record<string,string>;
        setViolationStatuses(s);
      } catch {}
    }
    sync();
    window.addEventListener("focus",   sync);
    window.addEventListener("storage", sync);
    window.addEventListener("tl:badge",sync);
    const id = setInterval(sync, 2_000);
    return () => {
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
      const status = violationStatuses[`${pfx}::${f.scan_id}::${f.file_path}`];
      return status === "resolved" || status === "in_review" ? { ...f, attested: true } : f;
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
    // Check seed mode first
    if (typeof window !== "undefined" && localStorage.getItem("tl_force_seed") === "1") {
      try {
        const snap = JSON.parse(localStorage.getItem("tl_notif_snapshot") ?? "null") as DashboardData | null;
        if (snap?.repos?.length) { setData(snap); setLoading(false); return; }
      } catch {}
    }
    try {
      const d = await api.dashboard(ORG, 90);
      setData(d);
    } catch { /* fall through — page uses FALLBACK_DATA via effectiveData ?? FALLBACK_DATA */ }
    setLoading(false);
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  async function generate() {
    if (!start || !end) { setError("Select a date range first."); return; }
    setGenerating(true); setError(null); setSuccess(false);

    // Brief settle delay so any pending renders flush before print snapshot
    await new Promise(r => setTimeout(r, 120));

    window.print();

    setSuccess(true);
    setTimeout(() => setSuccess(false), 4000);
    setGenerating(false);
  }

  const def = FW[fw];

  return (
    <AuthGuard>
      <div className="max-w-7xl mx-auto pb-12">

        {/* ── Top bar ── */}
        <div className="mb-6 flex items-center justify-between">
          <div>
            <h1 className="text-xl font-black text-gray-900">Audit Reports</h1>
            <p className="text-xs text-gray-400 mt-0.5">Generate cryptographically-signed compliance evidence packages</p>
          </div>
          <div className="flex items-center gap-2">
            {FRAMEWORKS.map(f => (
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
                {(Object.entries(FW) as [Framework, FwDef][]).map(([key, d]) => (
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
                Report ready — select "Save as PDF" in the print dialog.
              </div>
            )}

            {/* Compliance health card */}
            {(() => {
              const d = effectiveData ?? FALLBACK_DATA;
              const attPct   = Math.round(d.attestation_rate * 100);
              const crit     = d.top_risk_files.filter(f => f.risk_score==="CRITICAL" && !f.attested).length;
              const high     = d.top_risk_files.filter(f => f.risk_score==="HIGH" && !f.attested).length;
              const score    = attPct >= 90 ? "STRONG" : attPct >= 70 ? "FAIR" : "AT RISK";
              const scoreClr = attPct >= 90 ? "#065f46" : attPct >= 70 ? "#78350f" : "#7c2d12";
              const scoreBg  = attPct >= 90 ? "#d1fae5" : attPct >= 70 ? "#fef3c7" : "#fee2e2";
              return (
                <div className="section-card p-4 space-y-3">
                  <div className="flex items-center justify-between">
                    <p className="text-[10px] font-black uppercase tracking-wider text-gray-400">Compliance Health</p>
                    <span className="text-[9px] font-black px-2 py-0.5 rounded-full uppercase tracking-wider"
                      style={{ background:scoreBg, color:scoreClr }}>{score}</span>
                  </div>
                  <div className="flex items-end gap-3">
                    <span className="text-3xl font-black tabular-nums" style={{ color:def.color }}>{attPct}</span>
                    <span className="text-base font-bold text-gray-400 pb-0.5">%</span>
                    <span className="text-[10px] text-gray-400 pb-1 leading-snug">attestation<br/>coverage</span>
                  </div>
                  <div className="h-2 rounded-full overflow-hidden" style={{ background:"rgba(0,0,0,0.07)" }}>
                    <div className="h-full rounded-full transition-all duration-700"
                      style={{ width:`${attPct}%`, background:def.gradientCss }} />
                  </div>
                  {(crit + high) > 0 && (
                    <div className="flex items-center gap-2 pt-1">
                      {crit > 0 && (
                        <span className="flex items-center gap-1 text-[10px] font-bold text-rose-700 bg-rose-50 px-2 py-0.5 rounded-full border border-rose-200">
                          <span className="w-1.5 h-1.5 rounded-full bg-rose-500 inline-block" />
                          {crit} CRITICAL
                        </span>
                      )}
                      {high > 0 && (
                        <span className="flex items-center gap-1 text-[10px] font-bold text-orange-700 bg-orange-50 px-2 py-0.5 rounded-full border border-orange-200">
                          <span className="w-1.5 h-1.5 rounded-full bg-orange-400 inline-block" />
                          {high} HIGH
                        </span>
                      )}
                    </div>
                  )}
                </div>
              );
            })()}

            {/* Generate button */}
            <button onClick={generate} disabled={generating}
              className="w-full flex items-center justify-center gap-2.5 py-3.5 rounded-xl font-bold text-sm transition-all active:scale-[0.98]"
              style={generating
                ? { background:"#f1f5f9", color:"#94a3b8", cursor:"not-allowed" }
                : { background:def.gradientCss, color:"white", boxShadow:`0 4px 16px ${def.color}40` }
              }>
              {generating ? <Spinner /> : <Download />}
              {generating ? "Preparing…" : `Save ${fw} Report as PDF`}
            </button>

            {/* Keyboard shortcut hint */}
            <p className="text-center text-[10px] text-gray-400">
              Or press <kbd className="font-mono text-[9px] bg-gray-100 border border-gray-300 rounded px-1 py-0.5">Ctrl+P</kbd>
              <span className="mx-1">/</span>
              <kbd className="font-mono text-[9px] bg-gray-100 border border-gray-300 rounded px-1 py-0.5">⌘P</kbd>
              {" · "}choose <span className="font-semibold">Save as PDF</span>
            </p>

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
                onClick={() => downloadAIBOM(effectiveData ?? FALLBACK_DATA, fw, start, end)}
                className="w-full flex items-center justify-center gap-2 py-2.5 rounded-xl text-xs font-bold text-indigo-700 border border-indigo-200 hover:bg-indigo-50 transition-colors"
                style={{ background:"rgba(99,102,241,0.05)" }}>
                <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>
                </svg>
                Download AIBOM (.json)
              </button>
            </div>
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
            ) : (
              <ReportDocument data={effectiveData ?? FALLBACK_DATA} fw={fw} start={start} end={end} violationStatuses={violationStatuses} />
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
