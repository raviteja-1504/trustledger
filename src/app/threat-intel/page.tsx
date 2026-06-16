"use client";

import { useState, useMemo, useEffect, useCallback } from "react";
import Link from "next/link";
import AuthGuard from "@/components/AuthGuard";
import PageSkeleton from "@/components/PageSkeleton";
import InfoTooltip from "@/components/InfoTooltip";
import { api } from "@/lib/api";
import { DEFAULT_THREATS } from "@/lib/threatCatalog";
import type { ThreatEntry as ThreatEntryLib } from "@/lib/threatCatalog";
import type { DashboardData, ScanResult } from "@/types";

// ── Types ──────────────────────────────────────────────────────────────────────

type ThreatSeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
type ThreatStatus   = "active" | "monitoring" | "patched" | "not-affected";
type ThreatCategory = "ai-generated" | "supply-chain" | "zero-day" | "emerging" | "credential";

interface ThreatEntry {
  id: string;
  cve?: string;
  title: string;
  description: string;
  severity: ThreatSeverity;
  category: ThreatCategory;
  status: ThreatStatus;
  cvss?: number;
  epss_score?: number;       // Exploit Prediction Scoring System (0–100 %)
  mitre_tactic?: string;     // ATT&CK tactic  e.g. "Initial Access"
  mitre_technique?: string;  // ATT&CK technique ID e.g. "T1190"
  sla_hours?: number;        // hours to remediate once in-codebase
  published: string;
  last_updated: string;
  affected_pattern: string;     // AI code pattern that triggers this
  affected_languages: string[];
  in_your_codebase: boolean;    // detected in current repos
  exploit_available: boolean;
  exploit_in_wild: boolean;
  references: string[];
  mitigation: string;
  ai_specific: boolean;         // specifically affects AI-generated code
  relevance_score: number;      // 0-100 how relevant to your stack
}

// ── Config ─────────────────────────────────────────────────────────────────────

const SEV_STYLE: Record<ThreatSeverity, { bg:string; text:string; border:string; dot:string }> = {
  CRITICAL: { bg:"#ede9fe", text:"#5b21b6", border:"#c4b5fd", dot:"#7c3aed" },
  HIGH:     { bg:"#ffedd5", text:"#7c2d12", border:"#fed7aa", dot:"#f97316" },
  MEDIUM:   { bg:"#fef3c7", text:"#78350f", border:"#fde68a", dot:"#f59e0b" },
  LOW:      { bg:"#f0fdf4", text:"#14532d", border:"#bbf7d0", dot:"#22c55e" },
};

const STATUS_STYLE: Record<ThreatStatus, { bg:string; text:string; border:string; label:string }> = {
  active:       { bg:"#fef2f2", text:"#be123c", border:"#fecdd3", label:"Active Threat" },
  monitoring:   { bg:"#fffbeb", text:"#b45309", border:"#fde68a", label:"Monitoring"    },
  patched:      { bg:"#f0fdf4", text:"#15803d", border:"#bbf7d0", label:"Patched"       },
  "not-affected": { bg:"#f8fafc", text:"#475569", border:"#e2e8f0", label:"Not Affected" },
};

const CAT_LABELS: Record<ThreatCategory, string> = {
  "ai-generated": "AI-Generated Code",
  "supply-chain": "Supply Chain",
  "zero-day":     "Zero-Day",
  "emerging":     "Emerging Threat",
  "credential":   "Credential",
};

function cvssColor(s: number) { return s>=9?"#7c3aed":s>=7?"#f97316":s>=4?"#f59e0b":"#22c55e"; }
function fmtDate(iso: string) {
  const d = new Date(iso);
  return `${d.getDate()} ${["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"][d.getMonth()]} ${d.getFullYear()}`;
}
function daysAgo(iso: string) {
  const d = Math.floor((Date.now() - new Date(iso).getTime()) / 86400000);
  return d === 0 ? "Today" : d === 1 ? "Yesterday" : `${d}d ago`;
}

const SEV_SLA: Record<ThreatSeverity, number> = { CRITICAL:24, HIGH:72, MEDIUM:168, LOW:720 };

function slaInfo(t: ThreatEntry): { label: string; color: string; bg: string } | null {
  if (!t.in_your_codebase || t.status === "patched" || t.status === "not-affected") return null;
  const slaHours  = t.sla_hours ?? SEV_SLA[t.severity];
  const detected  = new Date(t.last_updated).getTime();
  const deadline  = detected + slaHours * 3_600_000;
  const hoursLeft = Math.round((deadline - Date.now()) / 3_600_000);
  if (hoursLeft < 0) return { label:`SLA BREACHED ${Math.abs(hoursLeft)}h ago`, color:"#be123c", bg:"#fef2f2" };
  if (hoursLeft < slaHours * 0.25) return { label:`SLA: ${hoursLeft}h left`, color:"#b45309", bg:"#fffbeb" };
  return { label:`SLA: ${hoursLeft}h left`, color:"#15803d", bg:"#f0fdf4" };
}

const ORG = process.env.NEXT_PUBLIC_ORG ?? "novapay";

// ── Language detection helpers ─────────────────────────────────────────────────

const EXT_LANG: Record<string, string> = {
  ts:"typescript", tsx:"typescript", js:"javascript", jsx:"javascript",
  py:"python", go:"go", java:"java", rb:"ruby", rs:"rust",
  php:"php", cs:"csharp", cpp:"cpp", c:"c", dockerfile:"dockerfile",
  pl:"perl", kt:"kotlin",
};

function detectLangs(files: { file_path: string; language?: string }[]): Set<string> {
  const s = new Set<string>();
  files.forEach(f => {
    if (f.language) s.add(f.language.toLowerCase());
    const ext = f.file_path.split(".").pop()?.toLowerCase() ?? "";
    if (EXT_LANG[ext]) s.add(EXT_LANG[ext]);
  });
  return s;
}

function enrichThreat(t: ThreatEntry, detected: Set<string>, riskPats: Set<string>, aiPct: number, hasCritical: boolean): ThreatEntry {
  const overlap = t.affected_languages.filter(l => detected.has(l)).length;
  if (overlap === 0) return { ...t, relevance_score: Math.max(10, t.relevance_score - 35) };

  const ratio = overlap / t.affected_languages.length;
  let inCodebase = false;
  if (t.category === "ai-generated"  && aiPct > 15)  inCodebase = true;
  if (t.category === "supply-chain"  && (riskPats.has("vuln-dep") || riskPats.has("dependency"))) inCodebase = true;
  if (t.category === "credential"    && riskPats.has("hardcoded-secret")) inCodebase = true;
  if (t.category === "zero-day"      && hasCritical)  inCodebase = true;
  if (t.category === "emerging"      && aiPct > 20)   inCodebase = true;

  const aiBoost      = aiPct > 40 ? 10 : aiPct > 20 ? 5 : 0;
  const langBoost    = Math.round(ratio * 20);
  const codeBoost    = inCodebase ? 8 : 0;
  const newScore     = Math.min(100, Math.max(10, t.relevance_score + aiBoost + langBoost + codeBoost));
  return { ...t, in_your_codebase: inCodebase, relevance_score: newScore };
}

// ── Page ───────────────────────────────────────────────────────────────────────

export default function ThreatIntelPage() {
  const [filterSev,    setFilterSev]    = useState<ThreatSeverity | "all">("all");
  const [filterCat,    setFilterCat]    = useState<ThreatCategory | "all">("all");
  const [filterStatus, setFilterStatus] = useState<ThreatStatus | "all">("all");
  const [filterScope,  setFilterScope]  = useState<"all" | "in-codebase">("all");
  const [search,       setSearch]       = useState("");
  const [expanded,     setExpanded]     = useState<string | null>(null);
  const [threatFeed,   setThreatFeed]   = useState<ThreatEntry[]>(DEFAULT_THREATS as ThreatEntry[]);
  const [enrichedThreats, setEnrichedThreats] = useState<ThreatEntry[]>([]);
  const [lastSync,     setLastSync]     = useState<Date | null>(null);
  const [syncing,      setSyncing]      = useState(false);

  // Load: fetch threat catalog from API, then seed key → DEFAULT_THREATS fallback
  useEffect(() => {
    api.threatCatalog()
      .then(res => { if (Array.isArray(res?.threats) && res.threats.length > 0) setThreatFeed(res.threats as ThreatEntry[]); })
      .catch(() => { /* keep DEFAULT_THREATS */ });
    try {
      const raw = localStorage.getItem("tl_threat_intel");
      if (raw) { setEnrichedThreats(JSON.parse(raw) as ThreatEntry[]); setLastSync(new Date()); return; }
    } catch {}
    setEnrichedThreats(DEFAULT_THREATS as ThreatEntry[]);
  }, []);

  const enrichThreats = useCallback(async () => {
    setSyncing(true);
    try {
      const data = await api.dashboard(ORG, 90);
      const allFiles: { file_path: string; language?: string }[] = [];
      const riskPats = new Set<string>();

      const scanIds = data.repos.filter(r => r.latest_scan_id).slice(0, 5).map(r => r.latest_scan_id);
      const scans = await Promise.allSettled(scanIds.map(id => api.getScan(id)));
      scans.forEach(r => {
        if (r.status !== "fulfilled" || !r.value) return;
        r.value.files.forEach(f => {
          allFiles.push({ file_path: f.file_path, language: f.language });
          f.risk_indicators.forEach(ri => riskPats.add(ri.toLowerCase()));
        });
      });

      // Infer common stack if no files returned (offline backend)
      const detected = allFiles.length > 0
        ? detectLangs(allFiles)
        : (() => { const s = new Set<string>(); ["typescript","javascript","python"].forEach(l => s.add(l)); return s; })();

      const hasCritical = data.top_risk_files.some(f => f.risk_score === "CRITICAL");
      const enriched = threatFeed.map(t => enrichThreat(t, detected, riskPats, data.overall_ai_pct, hasCritical));
      setEnrichedThreats(enriched);
      setLastSync(new Date());
      // Cache enriched result so next page load is pre-enriched
      try { localStorage.setItem("tl_threat_intel", JSON.stringify(enriched)); } catch {}
    } catch {
      // keep current data on error
    } finally {
      setSyncing(false);
    }
  }, [threatFeed]);

  useEffect(() => {
    enrichThreats();
    const id = setInterval(enrichThreats, 30_000);
    return () => clearInterval(id);
  }, [enrichThreats]);

  const filtered = useMemo(() => enrichedThreats.filter(t => {
    if (filterSev    !== "all" && t.severity !== filterSev)    return false;
    if (filterCat    !== "all" && t.category !== filterCat)    return false;
    if (filterStatus !== "all" && t.status   !== filterStatus) return false;
    if (filterScope  === "in-codebase" && !t.in_your_codebase) return false;
    if (search) { const q = search.toLowerCase(); if (![t.title, t.cve??"", t.description, t.affected_pattern].join(" ").toLowerCase().includes(q)) return false; }
    return true;
  }).sort((a,b) => b.relevance_score - a.relevance_score), [enrichedThreats, filterSev, filterCat, filterStatus, filterScope, search]);

  const inCodebase   = enrichedThreats.filter(t => t.in_your_codebase && t.status !== "patched").length;
  const activeThreats= enrichedThreats.filter(t => t.status === "active").length;
  const exploitWild  = enrichedThreats.filter(t => t.exploit_in_wild && t.status !== "patched").length;
  const aiSpecific   = enrichedThreats.filter(t => t.ai_specific).length;
  const slaBreach    = enrichedThreats.filter(t => slaInfo(t)?.color === "#be123c").length;

  return (
    <AuthGuard>
      <PageSkeleton rows={5} cards={4}>
      <div className="max-w-7xl mx-auto space-y-5 pb-10">

        {/* Header */}
        <div className="animate-fade-up flex items-start justify-between gap-4 flex-wrap">
          <div>
            <div className="flex items-center gap-2.5 mb-1">
              <div className="w-8 h-8 rounded-xl flex items-center justify-center"
                style={{ background:"rgba(239,68,68,0.1)", border:"1px solid rgba(239,68,68,0.2)" }}>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#ef4444" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/>
                </svg>
              </div>
              <h1 className="text-xl font-black text-gray-900 tracking-tight">Threat Intelligence</h1>
              {inCodebase > 0 && (
                <span className="text-xs font-black text-white bg-rose-600 px-2 py-0.5 rounded-full animate-pulse">
                  {inCodebase} in your codebase
                </span>
              )}
            </div>
            <p className="text-sm text-gray-400">
              AI-specific CVEs, zero-days, and emerging threat patterns targeting AI-generated codebases · updated daily
            </p>
          </div>
          <div className="flex items-center gap-2">
            {lastSync && (
              <span className="text-xs text-gray-400">
                {syncing ? "Syncing…" : `Synced ${daysAgo(lastSync.toISOString())}`}
              </span>
            )}
            <button onClick={enrichThreats} disabled={syncing}
              className="flex items-center gap-1.5 px-3 py-2 text-xs font-semibold text-gray-600 bg-white border border-gray-200 rounded-xl hover:bg-gray-50 transition-all shadow-sm disabled:opacity-50">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" className={syncing ? "animate-spin" : ""}><path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"/><path d="M8 16H3v5"/></svg>
              Refresh
            </button>
            <a href="https://nvd.nist.gov/vuln/search" target="_blank" rel="noopener noreferrer"
              className="flex items-center gap-1.5 px-3 py-2 text-xs font-semibold text-gray-600 bg-white border border-gray-200 rounded-xl hover:bg-gray-50 transition-all shadow-sm">
              NVD Search ↗
            </a>
          </div>
        </div>

        {/* Summary */}
        <div className="animate-fade-up grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[
            { label:"In Your Codebase",  value:inCodebase,    color:"#ef4444", bg:"#fef2f2", sub: slaBreach > 0 ? `${slaBreach} SLA breached` : undefined,
              info:{ title:"In Your Codebase", description:"Threats where the vulnerable pattern was detected in your scanned repositories. Requires immediate attention." } },
            { label:"Active Threats",    value:activeThreats, color:"#7c3aed", bg:"#ede9fe", sub: undefined,
              info:{ title:"Active Threats", description:"Threats currently being exploited in the wild or with confirmed proof-of-concept exploits." } },
            { label:"Exploited in Wild", value:exploitWild,   color:"#f97316", bg:"#fff7ed", sub: undefined,
              info:{ title:"Exploited in Wild", description:"Confirmed active exploitation of this vulnerability has been observed. Treat as urgent." } },
            { label:"AI-Specific",       value:aiSpecific,    color:"#6366f1", bg:"#eef2ff", sub: undefined,
              info:{ title:"AI-Specific Threats", description:"Vulnerabilities specifically targeting or amplified by AI-generated code patterns — the primary focus of TrustLedger." } },
          ].map(s => (
            <div key={s.label} className="rounded-2xl p-4 border" style={{ background:s.bg, borderColor:s.color+"30" }}>
              <p className="text-2xl font-black tabular-nums" style={{ color:s.color }}>{s.value}</p>
              <div className="flex items-center gap-1.5 mt-1">
                <p className="text-xs font-semibold text-gray-500">{s.label}</p>
                <InfoTooltip title={s.info.title} description={s.info.description} position="top" />
              </div>
              {s.sub && <p className="text-[9px] font-black text-rose-700 mt-1">⚠ {s.sub}</p>}
            </div>
          ))}
        </div>

        {/* Alert banner for in-codebase threats */}
        {inCodebase > 0 && (
          <div className="animate-fade-up rounded-2xl overflow-hidden border"
            style={{ background:"linear-gradient(135deg,rgba(239,68,68,0.08),rgba(124,58,237,0.08))", borderColor:"rgba(239,68,68,0.25)" }}>
            <div className="flex items-start gap-4 px-5 py-4">
              <svg className="shrink-0 mt-0.5 text-rose-600" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
              </svg>
              <div>
                <p className="text-sm font-bold text-rose-800">
                  {inCodebase} threat pattern{inCodebase > 1 ? "s" : ""} detected in your repositories
                </p>
                <p className="text-xs text-rose-600 mt-1">
                  {enrichedThreats.filter(t=>t.in_your_codebase&&t.status!=="patched").map(t=>t.title.split("—")[0].trim()).join(" · ")}
                </p>
                <button onClick={() => setFilterScope("in-codebase")}
                  className="mt-2 text-xs font-bold text-rose-700 underline underline-offset-2">
                  Show only threats in your codebase →
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Filters */}
        <div className="animate-fade-up flex flex-wrap items-center gap-2">
          <div className="flex items-center rounded-xl border border-gray-200 bg-white overflow-hidden">
            <svg className="ml-3 text-gray-400 shrink-0" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
            <input value={search} onChange={e=>setSearch(e.target.value)} placeholder="Search CVE, title, pattern…"
              className="px-3 py-2 text-xs text-gray-700 bg-transparent outline-none w-48" />
            {search && <button onClick={()=>setSearch("")} className="pr-2 text-gray-400 hover:text-gray-600 text-xs">✕</button>}
          </div>
          <div className="flex gap-0.5 bg-gray-100 p-0.5 rounded-xl">
            {(["all","in-codebase"] as const).map(s => (
              <button key={s} onClick={()=>setFilterScope(s)}
                className={`px-3 py-1.5 text-xs font-semibold rounded-lg transition-all ${filterScope===s?"bg-white text-gray-900 shadow-sm":"text-gray-500 hover:text-gray-700"}`}>
                {s==="all"?"All Threats":"In My Codebase"}
              </button>
            ))}
          </div>
          <div className="flex gap-0.5 bg-gray-100 p-0.5 rounded-xl">
            {(["all","CRITICAL","HIGH","MEDIUM"] as const).map(s => (
              <button key={s} onClick={()=>setFilterSev(s)}
                className={`px-2.5 py-1.5 text-xs font-semibold rounded-lg transition-all ${filterSev===s?"bg-white text-gray-900 shadow-sm":"text-gray-500 hover:text-gray-700"}`}>
                {s==="all"?"All":s}
              </button>
            ))}
          </div>
          <select value={filterCat} onChange={e=>setFilterCat(e.target.value as ThreatCategory|"all")}
            className="text-xs font-semibold text-gray-600 bg-white border border-gray-200 rounded-xl px-3 py-2 focus:outline-none">
            <option value="all">All Categories</option>
            {(Object.keys(CAT_LABELS) as ThreatCategory[]).map(c=><option key={c} value={c}>{CAT_LABELS[c]}</option>)}
          </select>
          <select value={filterStatus} onChange={e=>setFilterStatus(e.target.value as ThreatStatus|"all")}
            className="text-xs font-semibold text-gray-600 bg-white border border-gray-200 rounded-xl px-3 py-2 focus:outline-none">
            <option value="all">All Status</option>
            <option value="active">Active Threat</option>
            <option value="monitoring">Monitoring</option>
            <option value="patched">Patched</option>
          </select>
          <span className="text-xs text-gray-400 ml-auto">{filtered.length} threats · sorted by relevance</span>
        </div>

        {/* Threat list */}
        <div className="animate-fade-up space-y-3">
          {filtered.map(t => {
            const sev    = SEV_STYLE[t.severity];
            const stat   = STATUS_STYLE[t.status];
            const isOpen = expanded === t.id;
            return (
              <div key={t.id}
                className={`section-card overflow-hidden border-l-4 transition-all hover:shadow-md ${t.in_your_codebase && t.status !== "patched" ? "ring-1 ring-rose-200" : ""}`}
                style={{ borderLeftColor: sev.dot }}>
                <div className="flex items-start gap-4 px-5 py-4 cursor-pointer"
                  onClick={() => setExpanded(isOpen ? null : t.id)}>

                  {/* CVSS + EPSS */}
                  <div className="shrink-0 flex flex-col items-center gap-0.5">
                    {t.cvss && (
                      <div className="w-12 h-12 rounded-xl flex items-center justify-center text-base font-black text-white"
                        style={{ background:`linear-gradient(135deg,${cvssColor(t.cvss)},${cvssColor(t.cvss)}cc)` }}>
                        {t.cvss}
                      </div>
                    )}
                    {!t.cvss && (
                      <div className="w-12 h-12 rounded-xl flex items-center justify-center text-[9px] font-black"
                        style={{ background:sev.bg, color:sev.text, border:`1px solid ${sev.border}` }}>
                        NEW
                      </div>
                    )}
                    <span className="text-[8px] text-gray-400 font-semibold">{t.cvss ? "CVSS" : ""}</span>
                    {t.epss_score !== undefined && (
                      <div className="text-center mt-0.5">
                        <div className="text-[10px] font-black tabular-nums leading-none"
                          style={{ color:t.epss_score>=70?"#dc2626":t.epss_score>=30?"#d97706":"#6b7280" }}>
                          {t.epss_score}%
                        </div>
                        <div className="text-[8px] text-gray-400 font-semibold">EPSS</div>
                      </div>
                    )}
                  </div>

                  {/* Content */}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap mb-1">
                      {t.cve && <span className="text-[10px] font-black font-mono text-gray-500 bg-gray-100 px-2 py-0.5 rounded">{t.cve}</span>}
                      {t.mitre_technique && (
                        <span className="text-[9px] font-black font-mono px-1.5 py-0.5 rounded border"
                          style={{ color:"#1e40af", background:"#eff6ff", borderColor:"#bfdbfe" }}>
                          ATT&CK · {t.mitre_technique}
                        </span>
                      )}
                      <span className="text-[10px] font-bold px-2 py-0.5 rounded-full border"
                        style={{ background:sev.bg, color:sev.text, borderColor:sev.border }}>{t.severity}</span>
                      <span className="text-[10px] font-semibold text-gray-500 bg-gray-50 px-2 py-0.5 rounded border border-gray-200">
                        {CAT_LABELS[t.category]}
                      </span>
                      <span className="text-[10px] font-bold px-2 py-0.5 rounded-full border"
                        style={{ background:stat.bg, color:stat.text, borderColor:stat.border }}>{stat.label}</span>
                      {t.exploit_in_wild && (
                        <span className="text-[9px] font-black text-white bg-rose-600 px-1.5 py-0.5 rounded animate-pulse">⚡ Exploited</span>
                      )}
                      {t.in_your_codebase && t.status !== "patched" && (
                        <span className="text-[9px] font-black text-white bg-rose-700 px-1.5 py-0.5 rounded">IN YOUR CODE</span>
                      )}
                      {(() => { const sla = slaInfo(t); return sla ? (
                        <span className="text-[9px] font-bold px-1.5 py-0.5 rounded border"
                          style={{ color:sla.color, background:sla.bg, borderColor:sla.color+"50" }}>
                          ⏱ {sla.label}
                        </span>
                      ) : null; })()}
                      {t.ai_specific && (
                        <span className="text-[9px] font-bold text-indigo-600 bg-indigo-50 border border-indigo-100 px-1.5 py-0.5 rounded">AI-Specific</span>
                      )}
                    </div>
                    <p className="text-sm font-bold text-gray-900">{t.title}</p>
                    {!isOpen && <p className="text-xs text-gray-500 mt-0.5 line-clamp-2">{t.description}</p>}
                    <div className="flex items-center gap-4 mt-1.5 flex-wrap text-[10px] text-gray-400">
                      <span>Published {fmtDate(t.published)}</span>
                      <span>Updated {daysAgo(t.last_updated)}</span>
                      <div className="flex items-center gap-1">
                        {t.affected_languages.map(l => (
                          <span key={l} className="font-mono bg-gray-100 px-1.5 py-0.5 rounded text-gray-600">{l}</span>
                        ))}
                      </div>
                      <span className="ml-auto font-bold" style={{ color:t.relevance_score>=80?"#ef4444":t.relevance_score>=50?"#f59e0b":"#94a3b8" }}>
                        {t.relevance_score}% relevant to your stack
                      </span>
                    </div>
                  </div>

                  <svg className="shrink-0 text-gray-300 mt-1" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"
                    style={{ transform:isOpen?"rotate(180deg)":"none", transition:"transform 0.2s" }}>
                    <polyline points="6 9 12 15 18 9"/>
                  </svg>
                </div>

                {/* Expanded */}
                {isOpen && (
                  <div className="border-t border-gray-100 px-5 py-5 space-y-4" style={{ background:"rgba(248,250,252,0.8)" }}>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                      <div>
                        <p className="text-[10px] font-black uppercase tracking-widest text-gray-400 mb-2">Full Description</p>
                        <p className="text-xs text-gray-700 leading-relaxed">{t.description}</p>
                      </div>
                      <div>
                        <p className="text-[10px] font-black uppercase tracking-widest text-gray-400 mb-2">Affected AI Pattern</p>
                        <div className="bg-gray-900 rounded-xl px-4 py-3">
                          <p className="text-[9px] text-gray-500 font-mono mb-1">Vulnerable code signature</p>
                          <p className="text-xs text-amber-300 font-mono leading-relaxed">{t.affected_pattern}</p>
                        </div>
                      </div>
                    </div>

                    {/* MITRE ATT&CK + EPSS */}
                    {(t.mitre_tactic || t.epss_score !== undefined) && (
                      <div className="bg-blue-50 border border-blue-100 rounded-xl px-4 py-3 flex items-center gap-5 flex-wrap">
                        {t.mitre_tactic && (
                          <div>
                            <p className="text-[9px] font-bold text-blue-400 uppercase tracking-widest mb-0.5">MITRE ATT&CK Tactic</p>
                            <p className="text-xs font-bold text-blue-900">{t.mitre_tactic}</p>
                          </div>
                        )}
                        {t.mitre_technique && (
                          <>
                            <div className="w-px h-8 bg-blue-200 shrink-0" />
                            <div>
                              <p className="text-[9px] font-bold text-blue-400 uppercase tracking-widest mb-0.5">Technique ID</p>
                              <p className="text-xs font-black font-mono text-blue-900">{t.mitre_technique}</p>
                            </div>
                          </>
                        )}
                        {t.epss_score !== undefined && (
                          <>
                            <div className="w-px h-8 bg-blue-200 shrink-0" />
                            <div>
                              <p className="text-[9px] font-bold text-blue-400 uppercase tracking-widest mb-0.5">EPSS · 30-day exploitation</p>
                              <p className="text-xs font-black"
                                style={{ color:t.epss_score>=70?"#dc2626":t.epss_score>=30?"#d97706":"#1d4ed8" }}>
                                {t.epss_score}% — {t.epss_score>=70?"High risk":t.epss_score>=30?"Medium risk":"Low risk"}
                              </p>
                            </div>
                          </>
                        )}
                        {t.mitre_technique && (
                          <a href={`https://attack.mitre.org/techniques/${t.mitre_technique.split(".")[0]}/`}
                            target="_blank" rel="noopener noreferrer"
                            className="text-[10px] font-bold text-blue-600 hover:text-blue-800 underline underline-offset-2 ml-auto shrink-0">
                            ATT&CK Navigator ↗
                          </a>
                        )}
                      </div>
                    )}

                    <div>
                      <p className="text-[10px] font-black uppercase tracking-widest text-gray-400 mb-2">Mitigation</p>
                      <div className="bg-emerald-50 border border-emerald-100 rounded-xl px-4 py-3">
                        <p className="text-xs text-emerald-800 leading-relaxed">{t.mitigation}</p>
                      </div>
                    </div>

                    {t.in_your_codebase && t.status !== "patched" && (
                      <div className="bg-rose-50 border border-rose-200 rounded-xl px-4 py-3">
                        <p className="text-xs font-bold text-rose-800 mb-1">⚠ Pattern detected in your repositories</p>
                        <p className="text-xs text-rose-600">Run a targeted scan to identify affected files. Check the Vulnerabilities page for specific file locations.</p>
                        <div className="flex gap-2 mt-2">
                          <Link href="/vulnerabilities" className="text-[10px] font-bold text-rose-700 bg-rose-100 border border-rose-200 px-2.5 py-1 rounded-lg hover:bg-rose-200 transition-colors">
                            View in Vulnerabilities →
                          </Link>
                          <Link href="/dependencies" className="text-[10px] font-bold text-rose-700 bg-rose-100 border border-rose-200 px-2.5 py-1 rounded-lg hover:bg-rose-200 transition-colors">
                            Check Dependencies →
                          </Link>
                        </div>
                      </div>
                    )}

                    <div className="flex items-center gap-2 flex-wrap">
                      {t.references.map((ref,i) => (
                        <a key={i} href={ref} target="_blank" rel="noopener noreferrer"
                          className="text-[10px] font-bold text-indigo-600 bg-indigo-50 border border-indigo-100 px-2.5 py-1 rounded-lg hover:bg-indigo-100 transition-colors">
                          {ref.replace("https://","").split("/")[0]} ↗
                        </a>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>

        <div className="animate-fade-up flex items-start gap-3 bg-indigo-50 border border-indigo-100 rounded-xl px-4 py-3">
          <svg className="shrink-0 mt-0.5 text-indigo-500" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
          </svg>
          <p className="text-xs text-indigo-800 leading-relaxed">
            <span className="font-bold">About this feed:</span> Threat intelligence is curated specifically for AI-generated code vulnerabilities — the fastest-growing attack surface in modern software development.
            CVE data sourced from NVD. Relevance score reflects pattern detection in your scanned repositories and language stack alignment.
            <span className="font-bold ml-1">Updated daily.</span>
          </p>
        </div>

      </div>
      </PageSkeleton>
    </AuthGuard>
  );
}
