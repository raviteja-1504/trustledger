"use client";

import { useEffect, useState, useMemo } from "react";
import Link from "next/link";
import AuthGuard from "@/components/AuthGuard";
import { formatDateTime, formatDateOnly, relativeTime as tzRelativeTime, useTimezone, getSavedTimezone } from "@/lib/timezone";
import PageSkeleton from "@/components/PageSkeleton";
import RiskBadge from "@/components/RiskBadge";
import { authedFetch, isSeedMode } from "@/lib/useRealData";
import { useAuth } from "@/lib/auth";
import type { RiskLevel } from "@/types";

const ORG = process.env.NEXT_PUBLIC_ORG ?? "novapay";

// ── Types ─────────────────────────────────────────────────────────────────────

interface ScanSummary {
  scan_id:             string;
  repo:                string;
  pr_number:           number;
  commit_sha:          string;
  branch:              string;
  overall_risk:        RiskLevel;
  total_ai_percentage: number;
  file_count:          number;
  attested_count:      number;
  created_at:          string;
  triggered_by:        string;
}

// ── Mock data ─────────────────────────────────────────────────────────────────

function makeMockScans(): ScanSummary[] {
  const o = ORG;
  const ts = (daysBack: number, hour: number, min = 0) => {
    const d = new Date();
    d.setDate(d.getDate() - daysBack);
    d.setHours(hour, min, 0, 0);
    return d.toISOString();
  };
  return [
    { scan_id:"sc_mock_001", repo:`${o}/payments-api`,    pr_number:482, commit_sha:"a1b2c3d", branch:"feature/card-validator",   overall_risk:"CRITICAL", total_ai_percentage:0.71, file_count:7,  attested_count:3,  created_at:ts(0,14,32), triggered_by:"webhook" },
    { scan_id:"sc_mock_003", repo:`${o}/fraud-detection`, pr_number:219, commit_sha:"e4f5g6h", branch:"feat/risk-scorer",         overall_risk:"CRITICAL", total_ai_percentage:0.58, file_count:5,  attested_count:3,  created_at:ts(0,10, 5), triggered_by:"webhook" },
    { scan_id:"sc_mock_017", repo:`${o}/auth-service`,    pr_number:345, commit_sha:"b2c3d4e", branch:"feat/mfa-flow",            overall_risk:"HIGH",     total_ai_percentage:0.53, file_count:6,  attested_count:5,  created_at:ts(0, 9,15), triggered_by:"webhook" },
    { scan_id:"sc_mock_002", repo:`${o}/auth-service`,    pr_number:341, commit_sha:"i7j8k9l", branch:"fix/token-exchange",       overall_risk:"HIGH",     total_ai_percentage:0.44, file_count:4,  attested_count:3,  created_at:ts(1,11, 0), triggered_by:"webhook" },
    { scan_id:"sc_mock_008", repo:`${o}/payments-api`,    pr_number:479, commit_sha:"m1n2o3p", branch:"fix/stripe-client",        overall_risk:"HIGH",     total_ai_percentage:0.67, file_count:3,  attested_count:0,  created_at:ts(1, 9,22), triggered_by:"webhook" },
    { scan_id:"sc_mock_014", repo:`${o}/fraud-detection`, pr_number:218, commit_sha:"w1x2y3z", branch:"feat/velocity-check",      overall_risk:"HIGH",     total_ai_percentage:0.62, file_count:4,  attested_count:4,  created_at:ts(1,16,30), triggered_by:"webhook" },
    { scan_id:"sc_mock_018", repo:`${o}/risk-engine`,     pr_number:91,  commit_sha:"f5g6h7i", branch:"feat/ml-pipeline",         overall_risk:"CRITICAL", total_ai_percentage:0.84, file_count:9,  attested_count:0,  created_at:ts(1, 8, 0), triggered_by:"webhook" },
    { scan_id:"sc_mock_025", repo:`${o}/data-platform`,   pr_number:107, commit_sha:"d3e4f5a", branch:"feat/customer-sync-v2",    overall_risk:"HIGH",     total_ai_percentage:0.43, file_count:2,  attested_count:1,  created_at:ts(1,13, 0), triggered_by:"webhook" },
    { scan_id:"sc_mock_004", repo:`${o}/risk-engine`,     pr_number:88,  commit_sha:"u7v8w9x", branch:"refactor/scoring",         overall_risk:"MEDIUM",   total_ai_percentage:0.36, file_count:4,  attested_count:3,  created_at:ts(2,16,20), triggered_by:"webhook" },
    { scan_id:"sc_mock_024", repo:`${o}/auth-service`,    pr_number:338, commit_sha:"y1z2a3b", branch:"chore/deps-update",        overall_risk:"MEDIUM",   total_ai_percentage:0.31, file_count:3,  attested_count:3,  created_at:ts(2,10,30), triggered_by:"webhook" },
    { scan_id:"sc_mock_009", repo:`${o}/payments-api`,    pr_number:477, commit_sha:"c4d5e6f", branch:"feat/refund-handler",      overall_risk:"MEDIUM",   total_ai_percentage:0.55, file_count:5,  attested_count:5,  created_at:ts(2,17,30), triggered_by:"webhook" },
    { scan_id:"sc_mock_019", repo:`${o}/data-platform`,   pr_number:0,   commit_sha:"j8k9l0m", branch:"main",                    overall_risk:"LOW",      total_ai_percentage:0.19, file_count:14, attested_count:12, created_at:ts(2,12, 0), triggered_by:"push"    },
    { scan_id:"sc_mock_015", repo:`${o}/auth-service`,    pr_number:0,   commit_sha:"a4b5c6d", branch:"main",                    overall_risk:"LOW",      total_ai_percentage:0.18, file_count:12, attested_count:12, created_at:ts(3,10, 0), triggered_by:"push"    },
    { scan_id:"sc_mock_020", repo:`${o}/fraud-detection`, pr_number:215, commit_sha:"n1o2p3q", branch:"fix/duplicate-tx",         overall_risk:"HIGH",     total_ai_percentage:0.49, file_count:3,  attested_count:3,  created_at:ts(3,15,45), triggered_by:"webhook" },
    { scan_id:"sc_mock_005", repo:`${o}/data-platform`,   pr_number:103, commit_sha:"q4r5s6t", branch:"feat/etl-runner",          overall_risk:"HIGH",     total_ai_percentage:0.62, file_count:6,  attested_count:4,  created_at:ts(4,14, 0), triggered_by:"webhook" },
    { scan_id:"sc_mock_006", repo:`${o}/ml-platform`,    pr_number:57,  commit_sha:"h2i3j4k", branch:"feat/inference-engine",     overall_risk:"CRITICAL", total_ai_percentage:0.88, file_count:5,  attested_count:1,  created_at:ts(4, 8,45), triggered_by:"webhook" },
    { scan_id:"sc_mock_021", repo:`${o}/payments-api`,    pr_number:474, commit_sha:"r4s5t6u", branch:"feat/payout-scheduler",    overall_risk:"MEDIUM",   total_ai_percentage:0.41, file_count:5,  attested_count:5,  created_at:ts(4,11,30), triggered_by:"webhook" },
    { scan_id:"sc_mock_010", repo:`${o}/risk-engine`,     pr_number:85,  commit_sha:"g7h8i9j", branch:"feat/scoring-engine",      overall_risk:"LOW",      total_ai_percentage:0.28, file_count:3,  attested_count:3,  created_at:ts(5,15,45), triggered_by:"webhook" },
    { scan_id:"sc_mock_011", repo:`${o}/auth-service`,    pr_number:336, commit_sha:"k1l2m3n", branch:"fix/rate-limiter",         overall_risk:"LOW",      total_ai_percentage:0.22, file_count:3,  attested_count:3,  created_at:ts(5,11,20), triggered_by:"webhook" },
    { scan_id:"sc_mock_013", repo:`${o}/data-platform`,   pr_number:101, commit_sha:"s7t8u9v", branch:"fix/ai-threshold",         overall_risk:"HIGH",     total_ai_percentage:0.81, file_count:4,  attested_count:2,  created_at:ts(5, 9,10), triggered_by:"webhook" },
    { scan_id:"sc_mock_012", repo:`${o}/payments-api`,    pr_number:471, commit_sha:"o4p5q6r", branch:"feat/currency-formatter",  overall_risk:"MEDIUM",   total_ai_percentage:0.34, file_count:5,  attested_count:5,  created_at:ts(6,16, 0), triggered_by:"webhook" },
    { scan_id:"sc_mock_022", repo:`${o}/risk-engine`,     pr_number:82,  commit_sha:"v7w8x9y", branch:"chore/lint-fixes",         overall_risk:"LOW",      total_ai_percentage:0.14, file_count:2,  attested_count:2,  created_at:ts(6,14, 0), triggered_by:"webhook" },
    { scan_id:"sc_mock_016", repo:`${o}/payments-api`,    pr_number:0,   commit_sha:"e7f8g9h", branch:"main",                    overall_risk:"MEDIUM",   total_ai_percentage:0.42, file_count:22, attested_count:18, created_at:ts(7, 9, 0), triggered_by:"push"    },
    { scan_id:"sc_mock_023", repo:`${o}/fraud-detection`, pr_number:212, commit_sha:"z0a1b2c", branch:"feat/geo-block",           overall_risk:"MEDIUM",   total_ai_percentage:0.37, file_count:4,  attested_count:4,  created_at:ts(7,16,20), triggered_by:"webhook" },
  ];
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function relativeTime(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1)  return "just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24)  return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  if (days === 1) return "yesterday";
  if (days < 7)  return `${days}d ago`;
  return formatDateOnly(new Date(iso), getSavedTimezone());
}

function shortSha(sha: string): string { return sha.slice(0, 7); }

const RISK_ORDER: Record<RiskLevel, number> = { CRITICAL:4, HIGH:3, MEDIUM:2, LOW:1, UNKNOWN:0 };

const RISK_ACCENT: Record<RiskLevel, string> = {
  CRITICAL:"#be123c", HIGH:"#c2410c", MEDIUM:"#b45309", LOW:"#15803d", UNKNOWN:"#6b7280",
};

function dateGroupLabel(iso: string): string {
  const d = new Date(iso);
  const today = new Date(); today.setHours(0,0,0,0);
  const target = new Date(d); target.setHours(0,0,0,0);
  const diffDays = Math.round((today.getTime() - target.getTime()) / 86400000);
  if (diffDays === 0) return "Today";
  if (diffDays === 1) return "Yesterday";
  if (diffDays < 7)  return d.toLocaleDateString("en", { weekday:"long" });
  return d.toLocaleDateString("en-GB", { day:"numeric", month:"long" });
}

function attestChip(attested: number, total: number): { label: string; textColor: string; bg: string; border: string } {
  if (total === 0) return { label:"—", textColor:"#9ca3af", bg:"#f9fafb", border:"#e5e7eb" };
  const pct = attested / total;
  if (pct >= 1)   return { label:"All attested",          textColor:"#059669", bg:"#ecfdf5", border:"#a7f3d0" };
  if (pct >= 0.5) return { label:`${attested}/${total} attested`, textColor:"#b45309", bg:"#fffbeb", border:"#fde68a" };
  if (attested > 0) return { label:`${attested}/${total} attested`, textColor:"#be123c", bg:"#fff1f2", border:"#fecdd3" };
  return { label:"Unattested",          textColor:"#be123c", bg:"#fff1f2", border:"#fecdd3" };
}

// ── Activity sparkline ────────────────────────────────────────────────────────

function ActivitySparkline({ scans }: { scans: ScanSummary[] }) {
  const days = Array.from({ length: 14 }, (_, i) => {
    const d = new Date(); d.setDate(d.getDate() - (13 - i)); d.setHours(0,0,0,0);
    const dateStr = d.toISOString().slice(0, 10);
    const dayScans = scans.filter(s => s.created_at.slice(0, 10) === dateStr);
    const worst = dayScans.reduce<RiskLevel | null>((m, s) =>
      m === null ? s.overall_risk : (RISK_ORDER[s.overall_risk] > RISK_ORDER[m] ? s.overall_risk : m), null);
    const label = i === 13 ? "Today" : i === 12 ? "Yest"
      : d.toLocaleDateString("en", { weekday:"short" });
    const showLabel = i % 2 === 1 || i === 13;
    return { dateStr, count: dayScans.length, worst, label, showLabel };
  });
  const maxCount = Math.max(...days.map(d => d.count), 1);

  const barBg = (risk: RiskLevel | null, count: number) => {
    if (count === 0) return "#e5e7eb";
    return { CRITICAL:"#be123c", HIGH:"#ea580c", MEDIUM:"#d97706", LOW:"#10b981", UNKNOWN:"#9ca3af" }[risk!] ?? "#9ca3af";
  };

  const totalToday  = days[13].count;
  const totalYest   = days[12].count;
  const weekTotal   = days.slice(7).reduce((s, d) => s + d.count, 0);
  const critToday   = scans.filter(s => s.created_at.slice(0,10) === days[13].dateStr && s.overall_risk === "CRITICAL").length;

  return (
    <div className="section-card px-5 py-4">
      <div className="flex items-start justify-between gap-6">
        {/* Bar chart */}
        <div className="flex-1">
          <p className="text-[10px] font-bold text-gray-400 uppercase tracking-wider mb-2">Scan activity — last 14 days</p>
          <div className="flex items-end gap-1" style={{ height:52 }}>
            {days.map((d, i) => (
              <div key={i} className="flex-1 flex flex-col items-center gap-0.5">
                <div className="w-full rounded-t-sm transition-all"
                  style={{ height: d.count > 0 ? Math.max(3, (d.count / maxCount) * 44) : 2,
                           background: barBg(d.worst, d.count), opacity: d.count === 0 ? 0.35 : 1 }} />
                {d.showLabel && (
                  <span className="text-[7px] text-gray-400 leading-none" style={{ fontSize:"7px" }}>{d.label}</span>
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Quick stats beside chart */}
        <div className="shrink-0 flex flex-col gap-2 min-w-[140px]">
          <div className="flex items-center justify-between gap-3">
            <span className="text-[10px] text-gray-400">Today</span>
            <span className="text-[11px] font-black tabular-nums text-gray-800">{totalToday}</span>
          </div>
          <div className="flex items-center justify-between gap-3">
            <span className="text-[10px] text-gray-400">Yesterday</span>
            <span className="text-[11px] font-bold tabular-nums text-gray-600">{totalYest}</span>
          </div>
          <div className="flex items-center justify-between gap-3">
            <span className="text-[10px] text-gray-400">This week</span>
            <span className="text-[11px] font-bold tabular-nums text-gray-600">{weekTotal}</span>
          </div>
          {critToday > 0 && (
            <div className="flex items-center justify-between gap-3 bg-rose-50 rounded-lg px-2 py-1 border border-rose-100">
              <span className="text-[10px] text-rose-600 font-semibold">Critical today</span>
              <span className="text-[11px] font-black tabular-nums text-rose-700">{critToday}</span>
            </div>
          )}
          <div className="w-full border-t border-gray-100 pt-1.5 flex items-center gap-2 flex-wrap">
            {[
              { color:"#be123c", label:"Critical" },
              { color:"#ea580c", label:"High" },
              { color:"#d97706", label:"Medium" },
              { color:"#10b981", label:"Low" },
            ].map(l => (
              <span key={l.label} className="flex items-center gap-1 text-[8px] text-gray-400">
                <span className="w-2 h-2 rounded-sm shrink-0" style={{ background: l.color }} />{l.label}
              </span>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Icons ─────────────────────────────────────────────────────────────────────

function ScanIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M3 7V5a2 2 0 0 1 2-2h2"/><path d="M17 3h2a2 2 0 0 1 2 2v2"/>
      <path d="M21 17v2a2 2 0 0 1-2 2h-2"/><path d="M7 21H5a2 2 0 0 1-2-2v-2"/>
      <rect x="7" y="7" width="10" height="10" rx="1"/>
    </svg>
  );
}

function GitBranchIcon() {
  return (
    <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <line x1="6" y1="3" x2="6" y2="15"/><circle cx="18" cy="6" r="3"/><circle cx="6" cy="18" r="3"/>
      <path d="M18 9a9 9 0 0 1-9 9"/>
    </svg>
  );
}

function CommitIcon() {
  return (
    <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="4"/><line x1="1.05" y1="12" x2="7" y2="12"/><line x1="17.01" y1="12" x2="22.96" y2="12"/>
    </svg>
  );
}

function ArrowRightIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/>
    </svg>
  );
}

function PrIcon() {
  return (
    <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="18" cy="18" r="3"/><circle cx="6" cy="6" r="3"/><path d="M6 9v12"/><path d="M13 5a4 4 0 0 1 4 4v4a3 3 0 0 0 3 3"/>
    </svg>
  );
}

// ── Attestation patch helper ──────────────────────────────────────────────────
// Count how many files for a given scan_id have been locally attested via
// tl_violation_statuses (format: "{riskPrefix}::{scan_id}::{file_path}").
function localAttestedCount(scanId: string, statuses: Record<string, string>): number {
  return Object.entries(statuses).filter(([key, val]) => {
    const parts = key.split("::");
    return parts.length === 3 && parts[1] === scanId && (val === "resolved" || val === "in_review");
  }).length;
}

function effectiveAttestedCount(s: ScanSummary, statuses: Record<string, string>): number {
  return Math.min(s.file_count, s.attested_count + localAttestedCount(s.scan_id, statuses));
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function ScansPage() {
    const tz = useTimezone();
  const { profile } = useAuth();
  const [scans,            setScans]            = useState<ScanSummary[]>([]);
  const [loading,          setLoading]          = useState(true);
  const [repoFilter,       setRepoFilter]       = useState("all");
  const [riskFilter,       setRiskFilter]       = useState<RiskLevel | "all">("all");
  const [trigFilter,       setTrigFilter]       = useState<"all" | "webhook" | "push">("all");
  const [dateFilter,       setDateFilter]       = useState<"7" | "30" | "90" | "all">("30");
  const [search,           setSearch]           = useState("");
  const [sortKey,          setSortKey]          = useState<"date" | "risk" | "ai" | "files">("date");
  const [violationStatuses,setViolationStatuses]= useState<Record<string,string>>({});

  // Keep violation statuses in sync so attestation chips update without a reload
  useEffect(() => {
    function sync() {
      try {
        const s = JSON.parse(localStorage.getItem("tl_violation_statuses") ?? "{}") as Record<string,string>;
        setViolationStatuses(s);
      } catch {}
    }
    function onVisibility() { if (!document.hidden) sync(); }
    sync();
    window.addEventListener("focus", sync);
    window.addEventListener("storage", sync);
    document.addEventListener("visibilitychange", onVisibility);
    const id = setInterval(sync, 2_000);
    return () => {
      window.removeEventListener("focus", sync);
      window.removeEventListener("storage", sync);
      document.removeEventListener("visibilitychange", onVisibility);
      clearInterval(id);
    };
  }, []);

  useEffect(() => {
    async function load() {
      if (isSeedMode() && !profile?.org_id) {
        const stored = typeof window !== "undefined" ? localStorage.getItem("tl_scans") : null;
        if (stored) {
          try { setScans(JSON.parse(stored)); setLoading(false); return; } catch { /* fall through */ }
        }
        setScans(makeMockScans());
        setLoading(false);
        return;
      }
      try {
        const json = await authedFetch<{ scans: ScanSummary[] }>("/api/scans?limit=200");
        setScans(json.scans ?? []);
      } catch {
        setScans(makeMockScans());
      }
      setLoading(false);
    }
    load();
  }, [profile?.org_id]);

  const repos = useMemo(() => {
    const set = new Set(scans.map(s => s.repo));
    return Array.from(set).sort();
  }, [scans]);

  const filtered = useMemo(() => {
    return scans
      .filter(s => {
        if (repoFilter !== "all" && s.repo !== repoFilter) return false;
        if (riskFilter !== "all" && s.overall_risk !== riskFilter) return false;
        if (trigFilter === "webhook" && s.triggered_by !== "webhook") return false;
        if (trigFilter === "push"    && s.triggered_by !== "push")   return false;
        if (dateFilter !== "all") {
          const cutoff = Date.now() - Number(dateFilter) * 86400000;
          if (new Date(s.created_at).getTime() < cutoff) return false;
        }
        if (search) {
          const q = search.toLowerCase();
          if (!s.repo.toLowerCase().includes(q) &&
              !s.branch.toLowerCase().includes(q) &&
              !s.commit_sha.toLowerCase().includes(q) &&
              !(s.pr_number > 0 && String(s.pr_number).includes(q))) return false;
        }
        return true;
      })
      .sort((a, b) => {
        if (sortKey === "risk")  return RISK_ORDER[b.overall_risk] - RISK_ORDER[a.overall_risk];
        if (sortKey === "ai")    return b.total_ai_percentage - a.total_ai_percentage;
        if (sortKey === "files") return b.file_count - a.file_count;
        return new Date(b.created_at).getTime() - new Date(a.created_at).getTime();
      });
  }, [scans, repoFilter, riskFilter, trigFilter, dateFilter, search, sortKey]);

  // For each repo+PR combo, find the latest scan. Any older scan for the same
  // repo+PR is "superseded" — its individual attestation count is misleading
  // because attestation inheritance only creates rows on the latest scan. Show
  // a "Superseded" badge instead of a partial count so reviewers don't think
  // they need to take action on an old commit's scan.
  const latestScanPerPR = useMemo(() => {
    const latest = new Map<string, { scan_id: string; created_at: string }>();
    for (const s of scans) {
      const key = `${s.repo}::${s.pr_number}`;
      const existing = latest.get(key);
      if (!existing || s.created_at > existing.created_at) {
        latest.set(key, { scan_id: s.scan_id, created_at: s.created_at });
      }
    }
    return new Set([...latest.values()].map(v => v.scan_id));
  }, [scans]);

  // Build date-grouped list (only when sorted by date)
  const groupedRows = useMemo(() => {
    if (sortKey !== "date") return null;
    const groups: Array<{ label: string; items: ScanSummary[] }> = [];
    let lastLabel = "";
    for (const s of filtered) {
      const label = dateGroupLabel(s.created_at);
      if (label !== lastLabel) {
        groups.push({ label, items: [] });
        lastLabel = label;
      }
      groups[groups.length - 1].items.push(s);
    }
    return groups;
  }, [filtered, sortKey]);

  const stats = useMemo(() => {
    const filesTotal = scans.reduce((s, x) => s + x.file_count, 0);
    const fullyAttested = scans.filter(s => {
      const eff = effectiveAttestedCount(s, violationStatuses);
      return s.file_count > 0 && eff >= s.file_count;
    }).length;
    return {
      total:         scans.length,
      critical:      scans.filter(s => s.overall_risk === "CRITICAL").length,
      high:          scans.filter(s => s.overall_risk === "HIGH").length,
      avgAI:         scans.length === 0 ? 0 : scans.reduce((s, x) => s + x.total_ai_percentage, 0) / scans.length,
      repos:         new Set(scans.map(s => s.repo)).size,
      filesTotal,
      fullyAttested,
    };
  }, [scans, violationStatuses]);

  const SORT_OPTS = [
    { key:"date",  label:"Latest"    },
    { key:"risk",  label:"Risk"      },
    { key:"ai",    label:"AI%"       },
    { key:"files", label:"Files"     },
  ] as const;

  function ScanRow({ s, superseded }: { s: ScanSummary; superseded?: boolean }) {
    const repoShort   = s.repo.includes("/") ? s.repo.split("/").slice(1).join("/") : s.repo;
    const isPR        = s.pr_number > 0;
    const attested    = effectiveAttestedCount(s, violationStatuses);
    const chip        = superseded
      ? { label:"Superseded", textColor:"#6b7280", bg:"#f3f4f6", border:"#e5e7eb" }
      : attestChip(attested, s.file_count);
    const aiPct     = Math.round(s.total_ai_percentage * 100);
    const aiColor   = s.total_ai_percentage >= 0.7 ? "#be123c" : s.total_ai_percentage >= 0.4 ? "#b45309" : "#059669";
    const aiBg      = s.total_ai_percentage >= 0.7 ? "#fff1f2" : s.total_ai_percentage >= 0.4 ? "#fffbeb" : "#f0fdf4";

    return (
      <Link href={`/pr/${s.scan_id}`}
        className="group flex items-center gap-0 hover:bg-indigo-50/30 transition-colors"
        style={{ borderBottom:"1px solid #f3f4f6" }}>

        {/* Left risk accent bar */}
        <div className="w-0.5 self-stretch shrink-0" style={{ background: RISK_ACCENT[s.overall_risk] }} />

        <div className="flex items-center gap-4 flex-1 px-5 py-3.5 min-w-0">

          {/* Risk badge */}
          <div className="shrink-0 w-[78px]">
            <RiskBadge level={s.overall_risk} />
          </div>

          {/* Repo + context */}
          <div className="flex-1 min-w-0">
            <p className="font-bold text-sm text-gray-900 truncate">{repoShort}</p>
            <div className="flex items-center gap-2.5 mt-0.5 flex-wrap">
              {isPR ? (
                <span className="flex items-center gap-1 text-[11px] text-indigo-600 font-semibold">
                  <PrIcon />PR #{s.pr_number}
                </span>
              ) : (
                <span className="flex items-center gap-1 text-[11px] text-gray-400 font-medium">
                  <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="15 3 21 3 21 9"/><polyline points="9 21 3 21 3 15"/><line x1="21" y1="3" x2="14" y2="10"/><line x1="3" y1="21" x2="10" y2="14"/></svg>
                  direct push
                </span>
              )}
              <span className="flex items-center gap-1 text-[11px] text-gray-400">
                <GitBranchIcon />{s.branch}
              </span>
              <span className="flex items-center gap-1 text-[11px] text-gray-400 font-mono">
                <CommitIcon />{shortSha(s.commit_sha)}
              </span>
            </div>
          </div>

          {/* Attestation status chip */}
          <div className="shrink-0 hidden sm:block">
            <span className="text-[10px] font-bold px-2 py-0.5 rounded-full border"
              style={{ color: chip.textColor, background: chip.bg, borderColor: chip.border }}>
              {chip.label}
            </span>
          </div>

          {/* AI% pill */}
          <div className="shrink-0 hidden md:block">
            <span className="text-[11px] font-black px-2 py-0.5 rounded-lg tabular-nums"
              style={{ color: aiColor, background: aiBg }}>
              {aiPct}% AI
            </span>
          </div>

          {/* File count */}
          <div className="shrink-0 hidden lg:flex flex-col items-end gap-0.5">
            <span className="text-sm font-black text-gray-700 tabular-nums">{s.file_count}</span>
            <span className="text-[9px] text-gray-400">files</span>
          </div>

          {/* Timestamp + trigger */}
          <div className="shrink-0 text-right hidden sm:block w-20">
            <p className="text-xs text-gray-600 font-medium">{relativeTime(s.created_at)}</p>
            <p className="text-[9px] text-gray-300 mt-0.5">{s.triggered_by}</p>
          </div>

          {/* Arrow */}
          <div className="shrink-0 text-gray-300 group-hover:text-indigo-400 transition-colors">
            <ArrowRightIcon />
          </div>
        </div>
      </Link>
    );
  }

  return (
    <AuthGuard>
      <div className="max-w-7xl mx-auto space-y-5 pb-10">

        {/* Header */}
        <div className="animate-fade-up flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <div className="flex items-center gap-2.5 mb-1">
              <div className="w-8 h-8 rounded-xl flex items-center justify-center text-indigo-600"
                style={{ background:"rgba(99,102,241,0.1)", border:"1px solid rgba(99,102,241,0.2)" }}>
                <ScanIcon />
              </div>
              <h1 className="text-xl font-black text-gray-900 tracking-tight">Scan History</h1>
            </div>
            <p className="text-sm text-gray-400">Every PR and push scan — click any row to see file-level results</p>
          </div>
        </div>

        {/* Stats bar */}
        <div className="animate-fade-up grid grid-cols-3 sm:grid-cols-6 gap-3">
          {[
            { label:"Total Scans",   value: stats.total,                       color:"text-indigo-600", bg:"bg-indigo-50"  },
            { label:"Critical",      value: stats.critical,                    color:"text-rose-600",   bg:"bg-rose-50"    },
            { label:"High Risk",     value: stats.high,                        color:"text-orange-600", bg:"bg-orange-50"  },
            { label:"Repos",         value: stats.repos,                       color:"text-violet-600", bg:"bg-violet-50"  },
            { label:"Files Scanned", value: stats.filesTotal,                  color:"text-sky-600",    bg:"bg-sky-50"     },
            { label:"Fully Attested",value: stats.fullyAttested,               color:"text-emerald-600",bg:"bg-emerald-50" },
          ].map(s => (
            <div key={s.label} className={`section-card px-4 py-3 flex flex-col gap-1 ${s.bg} border-0`}>
              <p className={`text-2xl font-black tabular-nums ${s.color}`}>{s.value}</p>
              <p className="text-[10px] text-gray-500 font-medium leading-tight">{s.label}</p>
            </div>
          ))}
        </div>

        {/* 14-day activity chart */}
        {!loading && scans.length > 0 && (
          <div className="animate-fade-up">
            <ActivitySparkline scans={scans} />
          </div>
        )}

        {/* Filters */}
        <div className="animate-fade-up section-card px-4 py-3 flex flex-wrap items-center gap-3">
          <div className="relative flex-1 min-w-[180px]">
            <svg className="absolute left-2.5 top-1/2 -translate-y-1/2 text-gray-400" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
            <input
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Search repo, branch, commit, PR…"
              className="w-full pl-7 pr-3 py-1.5 text-xs border border-gray-200 rounded-lg focus:outline-none focus:ring-2 focus:ring-indigo-200"
            />
          </div>

          <select value={repoFilter} onChange={e => setRepoFilter(e.target.value)}
            className="text-xs border border-gray-200 rounded-lg px-2 py-1.5 focus:outline-none focus:ring-2 focus:ring-indigo-200 bg-white">
            <option value="all">All repos</option>
            {repos.map(r => <option key={r} value={r}>{r.split("/")[1] ?? r}</option>)}
          </select>

          <select value={riskFilter} onChange={e => setRiskFilter(e.target.value as RiskLevel | "all")}
            className="text-xs border border-gray-200 rounded-lg px-2 py-1.5 focus:outline-none focus:ring-2 focus:ring-indigo-200 bg-white">
            <option value="all">All risk levels</option>
            {(["CRITICAL","HIGH","MEDIUM","LOW"] as RiskLevel[]).map(r => <option key={r} value={r}>{r}</option>)}
          </select>

          <select value={trigFilter} onChange={e => setTrigFilter(e.target.value as typeof trigFilter)}
            className="text-xs border border-gray-200 rounded-lg px-2 py-1.5 focus:outline-none focus:ring-2 focus:ring-indigo-200 bg-white">
            <option value="all">All triggers</option>
            <option value="webhook">PR scans</option>
            <option value="push">Direct push</option>
          </select>

          <select value={dateFilter} onChange={e => setDateFilter(e.target.value as typeof dateFilter)}
            className="text-xs border border-gray-200 rounded-lg px-2 py-1.5 focus:outline-none focus:ring-2 focus:ring-indigo-200 bg-white">
            <option value="7">Last 7 days</option>
            <option value="30">Last 30 days</option>
            <option value="90">Last 90 days</option>
            <option value="all">All time</option>
          </select>

          <div className="flex items-center gap-1 ml-auto">
            <span className="text-[10px] text-gray-400 mr-1">Sort:</span>
            {SORT_OPTS.map(o => (
              <button key={o.key} onClick={() => setSortKey(o.key)}
                className={`px-2.5 py-1.5 text-xs font-semibold rounded-lg transition-all ${
                  sortKey === o.key
                    ? "bg-indigo-600 text-white shadow-sm"
                    : "text-gray-500 hover:text-gray-700 hover:bg-gray-100"
                }`}>
                {o.label}
              </button>
            ))}
          </div>
        </div>

        {/* Scan list */}
        <div className="animate-fade-up section-card overflow-hidden">
          {loading ? (
            <PageSkeleton><div /></PageSkeleton>
          ) : filtered.length === 0 ? (
            <div className="px-6 py-16 text-center">
              <div className="w-12 h-12 rounded-full bg-gray-100 flex items-center justify-center mx-auto mb-3 text-gray-400">
                <ScanIcon />
              </div>
              <p className="text-sm font-semibold text-gray-500">No scans match your filters</p>
              <p className="text-xs text-gray-400 mt-1">Try clearing the search or adjusting the filters above</p>
            </div>
          ) : groupedRows ? (
            // Date-grouped view
            groupedRows.map(group => (
              <div key={group.label}>
                <div className="px-5 py-2 bg-gray-50 border-b border-gray-100 sticky top-0 z-10">
                  <span className="text-[10px] font-black text-gray-500 uppercase tracking-widest">{group.label}</span>
                  <span className="ml-2 text-[10px] text-gray-400">{group.items.length} scan{group.items.length !== 1 ? "s" : ""}</span>
                </div>
                {group.items.map(s => <ScanRow key={s.scan_id} s={s} superseded={!latestScanPerPR.has(s.scan_id)} />)}
              </div>
            ))
          ) : (
            // Flat sorted view
            filtered.map(s => <ScanRow key={s.scan_id} s={s} superseded={!latestScanPerPR.has(s.scan_id)} />)
          )}
        </div>

        {!loading && filtered.length > 0 && (
          <p className="text-center text-xs text-gray-400">
            Showing {filtered.length} of {scans.length} scans
            {filtered.length < scans.length && (
              <button onClick={() => { setSearch(""); setRepoFilter("all"); setRiskFilter("all"); setTrigFilter("all"); }}
                className="ml-2 text-indigo-500 hover:text-indigo-700 font-medium">
                Clear filters
              </button>
            )}
          </p>
        )}

      </div>
    </AuthGuard>
  );
}
