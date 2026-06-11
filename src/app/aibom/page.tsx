"use client";

import { useEffect, useState, useMemo } from "react";
import AuthGuard from "@/components/AuthGuard";
import PageSkeleton from "@/components/PageSkeleton";
import ProgressBar from "@/components/ProgressBar";
import { authedFetch, isSeedMode } from "@/lib/useRealData";
import { useAuth } from "@/lib/auth";

// ── Types ─────────────────────────────────────────────────────────────────────

interface AIBOMEntry {
  file_path:       string;
  language:        string;
  ai_percentage:   number;
  risk_score:      string;
  risk_indicators: string[];
  scan_id:         string;
  repo:            string;
  scanned_at:      string;
  attested:        boolean;
}

interface RepoBOM {
  repo:           string;
  total_files:    number;
  ai_files:       number;      // files with ai_percentage > 0.5
  avg_ai_pct:     number;
  critical_count: number;
  high_count:     number;
  entries:        AIBOMEntry[];
}

// ── AIBOM export helpers ──────────────────────────────────────────────────────

function exportJSON(entries: AIBOMEntry[], orgName: string) {
  const aibom = {
    aibom_version:  "1.0.0",
    schema:         "https://trustledger.dev/schemas/aibom/1.0",
    metadata: {
      generated_at: new Date().toISOString(),
      org:          orgName,
      spec:         "AIBOM — AI Bill of Materials",
      description:  "Per-file AI content provenance inventory",
    },
    components: entries.map(e => ({
      type:            "file",
      name:            e.file_path.split("/").pop(),
      file_path:       e.file_path,
      language:        e.language,
      ai_percentage:   e.ai_percentage,
      risk_level:      e.risk_score,
      risk_indicators: e.risk_indicators,
      repository:      e.repo,
      scan_id:         e.scan_id,
      scanned_at:      e.scanned_at,
      attested:        e.attested,
    })),
  };
  const blob = new Blob([JSON.stringify(aibom, null, 2)], { type: "application/json" });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a");
  a.href     = url;
  a.download = `aibom-${orgName}-${new Date().toISOString().split("T")[0]}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

function exportCSV(entries: AIBOMEntry[], orgName: string) {
  const header = "repo,file_path,language,ai_percentage,risk_score,indicators,scan_id,scanned_at,attested";
  const rows   = entries.map(e =>
    [e.repo, e.file_path, e.language, (e.ai_percentage*100).toFixed(1)+"%",
     e.risk_score, e.risk_indicators.join("|"), e.scan_id, e.scanned_at, e.attested].join(",")
  );
  const csv = [header, ...rows].join("\n");
  const blob = new Blob([csv], { type:"text/csv" });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a");
  a.href     = url;
  a.download = `aibom-${orgName}-${new Date().toISOString().split("T")[0]}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

// ── Risk colour helpers ───────────────────────────────────────────────────────

const RISK_COLOR: Record<string, string> = {
  CRITICAL:"#7c3aed", HIGH:"#ea580c", MEDIUM:"#d97706", LOW:"#15803d",
};

// Same key format used by Reports/PR pages for `tl_violation_statuses`
const riskPfx = (r: string) =>
  r === "CRITICAL" ? "crit" : r === "HIGH" ? "high" : r === "MEDIUM" ? "med" : "low";

// Mirrors src/lib/seed.ts top_risk_files — kept in sync so attested status
// matches what Reports/Dashboard/PR pages show for the same files.
const DEMO_ENTRIES: AIBOMEntry[] = [
  { file_path:"src/processors/card_validator.py",            language:"python",     ai_percentage:0.95, risk_score:"CRITICAL", risk_indicators:["sql-injection","hardcoded-secret","eval-exec"], scan_id:"sc_001", repo:"novapay/payments-api",         scanned_at:"2026-06-02T10:00:00Z", attested:false },
  { file_path:"src/gateway/stripe_client.py",                 language:"python",     ai_percentage:0.79, risk_score:"HIGH",     risk_indicators:["hardcoded-secret"],                              scan_id:"sc_001", repo:"novapay/payments-api",         scanned_at:"2026-06-02T10:00:00Z", attested:false },
  { file_path:"src/middleware/auth_check.ts",                 language:"typescript", ai_percentage:0.66, risk_score:"HIGH",     risk_indicators:["structural-uniformity"],                         scan_id:"sc_001", repo:"novapay/payments-api",         scanned_at:"2026-06-02T10:00:00Z", attested:false },
  { file_path:"src/services/payment_service.ts",              language:"typescript", ai_percentage:0.84, risk_score:"HIGH",     risk_indicators:["hardcoded-secret"],                              scan_id:"sc_001", repo:"novapay/payments-api",         scanned_at:"2026-06-02T10:00:00Z", attested:false },
  { file_path:"src/auth/token_service.py",                    language:"python",     ai_percentage:0.77, risk_score:"HIGH",     risk_indicators:["hardcoded-secret"],                              scan_id:"sc_002", repo:"novapay/auth-service",         scanned_at:"2026-06-01T10:00:00Z", attested:false },
  { file_path:"models/risk_scorer.ts",                        language:"typescript", ai_percentage:0.89, risk_score:"CRITICAL", risk_indicators:["eval-exec"],                                      scan_id:"sc_003", repo:"novapay/fraud-detection",      scanned_at:"2026-05-31T10:00:00Z", attested:false },
  { file_path:"src/database/connection.py",                   language:"python",     ai_percentage:0.73, risk_score:"HIGH",     risk_indicators:["hardcoded-secret","sql-injection"],              scan_id:"sc_003", repo:"novapay/fraud-detection",      scanned_at:"2026-05-31T10:00:00Z", attested:false },
  { file_path:"src/models/anomaly_detector.py",               language:"python",     ai_percentage:0.68, risk_score:"MEDIUM",   risk_indicators:["structural-uniformity"],                         scan_id:"sc_003", repo:"novapay/fraud-detection",      scanned_at:"2026-05-31T10:00:00Z", attested:false },
  { file_path:"src/connectors/bigquery_writer.ts",            language:"typescript", ai_percentage:0.85, risk_score:"HIGH",     risk_indicators:["hardcoded-secret","sql-injection"],              scan_id:"sc_005", repo:"novapay/data-platform",        scanned_at:"2026-05-29T10:00:00Z", attested:false },
  { file_path:"src/pipelines/etl_runner.py",                  language:"python",     ai_percentage:0.67, risk_score:"HIGH",     risk_indicators:["sql-injection"],                                 scan_id:"sc_005", repo:"novapay/data-platform",        scanned_at:"2026-05-29T10:00:00Z", attested:false },
  { file_path:"src/models/inference_engine.py",               language:"python",     ai_percentage:0.93, risk_score:"CRITICAL", risk_indicators:["eval-exec","hardcoded-secret","sql-injection"],  scan_id:"sc_006", repo:"novapay/ml-platform",          scanned_at:"2026-05-28T10:00:00Z", attested:false },
  { file_path:"src/training/data_pipeline.py",                language:"python",     ai_percentage:0.87, risk_score:"HIGH",     risk_indicators:["hardcoded-secret","sql-injection"],              scan_id:"sc_006", repo:"novapay/ml-platform",          scanned_at:"2026-05-28T10:00:00Z", attested:false },
  { file_path:"src/serving/model_server.py",                  language:"python",     ai_percentage:0.81, risk_score:"HIGH",     risk_indicators:["eval-exec"],                                     scan_id:"sc_006", repo:"novapay/ml-platform",          scanned_at:"2026-05-28T10:00:00Z", attested:false },
  { file_path:"src/providers/email_sender.py",                language:"python",     ai_percentage:0.78, risk_score:"HIGH",     risk_indicators:["hardcoded-secret"],                              scan_id:"sc_009", repo:"novapay/notification-service", scanned_at:"2026-05-25T10:00:00Z", attested:false },
  { file_path:"src/templates/render_engine.ts",               language:"typescript", ai_percentage:0.64, risk_score:"MEDIUM",   risk_indicators:["structural-uniformity"],                         scan_id:"sc_009", repo:"novapay/notification-service", scanned_at:"2026-05-25T10:00:00Z", attested:false },
  { file_path:"pkg/orders/handler.go",                        language:"go",         ai_percentage:0.87, risk_score:"CRITICAL", risk_indicators:["sql-injection","hardcoded-secret"],              scan_id:"sc_010", repo:"novapay/order-service",        scanned_at:"2026-05-24T10:00:00Z", attested:false },
  { file_path:"internal/db/queries.go",                       language:"go",         ai_percentage:0.71, risk_score:"HIGH",     risk_indicators:["sql-injection"],                                 scan_id:"sc_010", repo:"novapay/order-service",        scanned_at:"2026-05-24T10:00:00Z", attested:false },
  { file_path:"src/main/java/billing/PaymentProcessor.java",  language:"java",       ai_percentage:0.82, risk_score:"HIGH",     risk_indicators:["hardcoded-secret"],                              scan_id:"sc_011", repo:"novapay/billing-service",      scanned_at:"2026-05-23T10:00:00Z", attested:false },
  { file_path:"src/main/java/billing/InvoiceService.java",    language:"java",       ai_percentage:0.64, risk_score:"MEDIUM",   risk_indicators:["structural-uniformity"],                         scan_id:"sc_011", repo:"novapay/billing-service",      scanned_at:"2026-05-23T10:00:00Z", attested:false },
  { file_path:"src/crypto/hash.rs",                           language:"rust",       ai_percentage:0.76, risk_score:"HIGH",     risk_indicators:["hardcoded-secret"],                              scan_id:"sc_012", repo:"novapay/cli-tools",            scanned_at:"2026-05-22T10:00:00Z", attested:false },
  { file_path:"src/net/http_client.rs",                       language:"rust",       ai_percentage:0.69, risk_score:"MEDIUM",   risk_indicators:["structural-uniformity"],                         scan_id:"sc_012", repo:"novapay/cli-tools",            scanned_at:"2026-05-22T10:00:00Z", attested:false },
  { file_path:"src/middleware/auth_interceptor.ts",           language:"typescript", ai_percentage:0.81, risk_score:"HIGH",     risk_indicators:["structural-uniformity"],                         scan_id:"sc_007", repo:"novapay/api-gateway",          scanned_at:"2026-05-27T10:00:00Z", attested:true  },
  { file_path:"src/scoring/ml_pipeline.ts",                   language:"typescript", ai_percentage:0.74, risk_score:"MEDIUM",   risk_indicators:["comment-density"],                               scan_id:"sc_004", repo:"novapay/risk-engine",          scanned_at:"2026-05-30T10:00:00Z", attested:true  },
  { file_path:"src/handlers/profile_update.ts",               language:"typescript", ai_percentage:0.61, risk_score:"MEDIUM",   risk_indicators:["comment-density"],                               scan_id:"sc_008", repo:"novapay/user-service",         scanned_at:"2026-05-26T10:00:00Z", attested:true  },
];

// ── Page ──────────────────────────────────────────────────────────────────────

export default function AIBOMPage() {
  const { profile }   = useAuth();
  const [entries,     setEntries]     = useState<AIBOMEntry[]>([]);
  const [loading,     setLoading]     = useState(true);
  const [search,      setSearch]      = useState("");
  const [filterRisk,  setFilterRisk]  = useState("all");
  const [filterRepo,  setFilterRepo]  = useState("all");
  const [unattestedOnly, setUnattestedOnly] = useState(false);
  const [filterLang,  setFilterLang]  = useState("all");
  const [sortBy,      setSortBy]      = useState<"ai_desc"|"ai_asc"|"risk"|"path">("ai_desc");
  const [expandedRepo,setExpandedRepo]= useState<string | null>(null);
  const [expandedFile,setExpandedFile]= useState<string | null>(null);
  const [days,        setDays]        = useState(90);
  const [violationStatuses, setViolationStatuses] = useState<Record<string,string>>({});

  useEffect(() => {
    async function load() {
      setLoading(true);
      if (isSeedMode()) {
        setEntries(DEMO_ENTRIES);
        setLoading(false);
        return;
      }
      if (!profile?.org_id) { setLoading(false); return; }
      try {
        const data = await authedFetch<{ data: AIBOMEntry[] }>(`/api/export?type=aibom&format=json&days=${days}`);
        setEntries(data.data ?? []);
      } catch { setEntries([]); }
      setLoading(false);
    }
    load();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [profile?.org_id, days]);

  // Keep attested status in sync with attestations made on Reports/PR pages
  useEffect(() => {
    if (!isSeedMode()) return;
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

  // Patch entries with locally-attested status so the AIBOM page reflects
  // attestations made elsewhere without a backend round-trip
  const effectiveEntries = useMemo(() => {
    if (!isSeedMode()) return entries;
    return entries.map(e => {
      if (e.attested) return e;
      const status = violationStatuses[`${riskPfx(e.risk_score)}::${e.scan_id}::${e.file_path}`];
      return status === "resolved" || status === "in_review" ? { ...e, attested: true } : e;
    });
  }, [entries, violationStatuses]);

  // Group by repo
  const byRepo = useMemo((): RepoBOM[] => {
    const map: Record<string, AIBOMEntry[]> = {};
    effectiveEntries.forEach(e => { if (!map[e.repo]) map[e.repo] = []; map[e.repo].push(e); });
    return Object.entries(map).map(([repo, files]) => ({
      repo,
      total_files:    files.length,
      ai_files:       files.filter(f => f.ai_percentage > 0.5).length,
      avg_ai_pct:     files.reduce((s, f) => s + f.ai_percentage, 0) / files.length,
      critical_count: files.filter(f => f.risk_score === "CRITICAL").length,
      high_count:     files.filter(f => f.risk_score === "HIGH").length,
      entries:        files,
    })).sort((a, b) => b.avg_ai_pct - a.avg_ai_pct);
  }, [effectiveEntries]);

  const repos = useMemo(() => ["all", ...byRepo.map(r => r.repo)], [byRepo]);

  const languages = useMemo(() =>
    ["all", ...Array.from(new Set(effectiveEntries.map(e => e.language))).sort()],
  [effectiveEntries]);

  const RISK_RANK: Record<string, number> = { CRITICAL:4, HIGH:3, MEDIUM:2, LOW:1 };

  const filtered = useMemo(() => {
    const rows = effectiveEntries.filter(e => {
      if (filterRisk !== "all" && e.risk_score !== filterRisk) return false;
      if (filterRepo !== "all" && e.repo !== filterRepo) return false;
      if (filterLang !== "all" && e.language !== filterLang) return false;
      if (unattestedOnly && e.attested) return false;
      if (search && !e.file_path.toLowerCase().includes(search.toLowerCase()) && !e.repo.toLowerCase().includes(search.toLowerCase())) return false;
      return true;
    });
    return rows.sort((a, b) => {
      switch (sortBy) {
        case "ai_asc":  return a.ai_percentage - b.ai_percentage;
        case "risk":    return (RISK_RANK[b.risk_score] ?? 0) - (RISK_RANK[a.risk_score] ?? 0);
        case "path":    return a.file_path.localeCompare(b.file_path);
        default:        return b.ai_percentage - a.ai_percentage;
      }
    });
  }, [effectiveEntries, filterRisk, filterRepo, filterLang, unattestedOnly, search, sortBy]);

  // Most common risk indicators across the current filter set
  const topIndicators = useMemo(() => {
    const counts: Record<string, number> = {};
    filtered.forEach(e => (e.risk_indicators ?? []).forEach(ind => { counts[ind] = (counts[ind] ?? 0) + 1; }));
    return Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 6);
  }, [filtered]);

  const orgName = profile?.org_slug ?? "org";

  if (loading) return <AuthGuard><PageSkeleton><div /></PageSkeleton></AuthGuard>;

  return (
    <AuthGuard>
      <div className="max-w-5xl mx-auto space-y-5 pb-10">

        {/* Header */}
        <div className="flex items-start justify-between gap-4 flex-wrap pt-1">
          <div>
            <h1 className="text-xl font-black text-gray-900">AI Bill of Materials</h1>
            <p className="text-sm text-gray-400 mt-0.5">
              Complete inventory of AI-generated code across all repositories · {effectiveEntries.length} files
            </p>
          </div>
          <div className="flex items-center gap-2">
            <select value={days} onChange={e => setDays(Number(e.target.value))}
              className="text-sm border border-gray-200 rounded-xl px-3 py-2 focus:outline-none bg-white">
              {[30,90,180,365].map(d => <option key={d} value={d}>{d}d</option>)}
            </select>
            <button onClick={() => exportJSON(filtered, orgName)}
              className="px-4 py-2 text-sm font-bold rounded-xl bg-indigo-600 text-white hover:bg-indigo-700 transition-colors">
              Export JSON
            </button>
            <button onClick={() => exportCSV(filtered, orgName)}
              className="px-4 py-2 text-sm font-bold rounded-xl border border-gray-200 text-gray-700 hover:border-indigo-300 transition-colors">
              Export CSV
            </button>
          </div>
        </div>

        {/* Summary stats */}
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-4">
          {[
            { label:"Total files",       value:effectiveEntries.length,                                              color:"#6366f1" },
            { label:"AI-heavy files",    value:effectiveEntries.filter(e=>e.ai_percentage>0.5).length,              color:"#f59e0b" },
            { label:"CRITICAL findings", value:effectiveEntries.filter(e=>e.risk_score==="CRITICAL").length,         color:"#ef4444" },
            { label:"Unattested",        value:effectiveEntries.filter(e=>!e.attested).length,                       color:"#dc2626" },
            { label:"Repos scanned",     value:byRepo.length,                                              color:"#10b981" },
          ].map(s => (
            <div key={s.label} className="bg-white rounded-2xl border border-gray-200 p-4 shadow-sm text-center">
              <p className="text-2xl font-black" style={{ color: s.color }}>{s.value}</p>
              <p className="text-xs text-gray-400 mt-0.5">{s.label}</p>
            </div>
          ))}
        </div>

        {/* Repo breakdown cards */}
        <div className="space-y-3">
          <h2 className="text-sm font-black text-gray-700">By Repository</h2>
          {byRepo.map(r => (
            <div key={r.repo} className="bg-white rounded-2xl border border-gray-200 shadow-sm overflow-hidden">
              <button
                onClick={() => setExpandedRepo(expandedRepo === r.repo ? null : r.repo)}
                className="w-full flex items-center gap-4 px-5 py-4 hover:bg-gray-50 transition-colors text-left"
              >
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-bold text-gray-900 truncate">{r.repo}</p>
                  <p className="text-xs text-gray-400 mt-0.5">{r.total_files} files · {r.ai_files} AI-heavy</p>
                </div>
                <div className="w-32 hidden sm:block">
                  <ProgressBar value={r.avg_ai_pct} mode="ai" height="h-1.5" />
                  <p className="text-[10px] text-gray-400 mt-0.5 text-right">{(r.avg_ai_pct*100).toFixed(0)}% avg AI</p>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  {r.critical_count > 0 && (
                    <span className="text-[9px] font-black px-2 py-0.5 rounded-full" style={{ background:"#ede9fe", color:"#6d28d9" }}>
                      {r.critical_count} CRIT
                    </span>
                  )}
                  {r.high_count > 0 && (
                    <span className="text-[9px] font-black px-2 py-0.5 rounded-full" style={{ background:"#fff7ed", color:"#c2410c" }}>
                      {r.high_count} HIGH
                    </span>
                  )}
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"
                    style={{ transform: expandedRepo === r.repo ? "rotate(180deg)" : "none", transition:"transform 0.2s" }}>
                    <polyline points="6 9 12 15 18 9"/>
                  </svg>
                </div>
              </button>

              {expandedRepo === r.repo && (
                <div className="border-t border-gray-50">
                  <div className="divide-y divide-gray-50">
                    {r.entries.sort((a, b) => b.ai_percentage - a.ai_percentage).map(e => (
                      <div key={e.file_path} className="flex items-center gap-3 px-5 py-2.5">
                        <div className="w-2 h-2 rounded-full shrink-0" style={{ background: RISK_COLOR[e.risk_score] ?? "#94a3b8" }} />
                        <p className="text-xs font-mono text-gray-700 flex-1 truncate">{e.file_path}</p>
                        <div className="w-20 hidden sm:block">
                          <ProgressBar value={e.ai_percentage} mode="ai" height="h-1" />
                        </div>
                        <span className="text-[10px] tabular-nums text-gray-500 w-10 text-right shrink-0">
                          {(e.ai_percentage*100).toFixed(0)}%
                        </span>
                        <div className="flex gap-1 shrink-0">
                          {(e.risk_indicators ?? []).slice(0, 2).map(ind => (
                            <span key={ind} className="text-[8px] font-bold px-1.5 py-0.5 rounded bg-gray-100 text-gray-500">
                              {ind.replace(/-/g," ").slice(0,12)}
                            </span>
                          ))}
                        </div>
                        {e.attested ? (
                          <span className="text-[8px] font-black px-1.5 py-0.5 rounded-full shrink-0" style={{ background:"#ecfdf5", color:"#059669" }}>
                            ATTESTED
                          </span>
                        ) : (
                          <span className="text-[8px] font-black px-1.5 py-0.5 rounded-full shrink-0" style={{ background:"#fef2f2", color:"#dc2626" }}>
                            UNATTESTED
                          </span>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>

        {/* Flat file table with filters */}
        <div className="bg-white rounded-2xl border border-gray-200 shadow-sm overflow-hidden">
          <div className="px-5 py-3.5 border-b border-gray-100 flex items-center gap-3 flex-wrap">
            <p className="text-sm font-black text-gray-900">All Files</p>
            <input value={search} onChange={e => setSearch(e.target.value)}
              placeholder="Search file path…" className="text-xs border border-gray-200 rounded-lg px-3 py-1.5 focus:outline-none w-48" />
            <select value={filterRisk} onChange={e => setFilterRisk(e.target.value)}
              className="text-xs border border-gray-200 rounded-lg px-2 py-1.5 bg-white">
              <option value="all">All risk levels</option>
              {["CRITICAL","HIGH","MEDIUM","LOW"].map(r => <option key={r} value={r}>{r}</option>)}
            </select>
            <select value={filterRepo} onChange={e => setFilterRepo(e.target.value)}
              className="text-xs border border-gray-200 rounded-lg px-2 py-1.5 bg-white max-w-[160px] truncate">
              {repos.map(r => <option key={r} value={r}>{r === "all" ? "All repos" : r.split("/")[1]}</option>)}
            </select>
            <select value={filterLang} onChange={e => setFilterLang(e.target.value)}
              className="text-xs border border-gray-200 rounded-lg px-2 py-1.5 bg-white">
              {languages.map(l => <option key={l} value={l}>{l === "all" ? "All languages" : l}</option>)}
            </select>
            <select value={sortBy} onChange={e => setSortBy(e.target.value as typeof sortBy)}
              className="text-xs border border-gray-200 rounded-lg px-2 py-1.5 bg-white">
              <option value="ai_desc">Sort: AI % high → low</option>
              <option value="ai_asc">Sort: AI % low → high</option>
              <option value="risk">Sort: Risk severity</option>
              <option value="path">Sort: File path</option>
            </select>
            <label className="flex items-center gap-1.5 text-xs text-gray-600 cursor-pointer">
              <input type="checkbox" checked={unattestedOnly} onChange={e => setUnattestedOnly(e.target.checked)} />
              Unattested only
            </label>
            <span className="text-xs text-gray-400 ml-auto">{filtered.length} file{filtered.length !== 1 ? "s" : ""}</span>
          </div>

          {topIndicators.length > 0 && (
            <div className="px-5 py-2.5 border-b border-gray-100 flex items-center gap-2 flex-wrap bg-gray-50">
              <span className="text-[10px] font-bold text-gray-400 uppercase tracking-wide">Top risk indicators</span>
              {topIndicators.map(([ind, count]) => (
                <span key={ind} className="text-[10px] font-bold px-2 py-0.5 rounded-full bg-white border border-gray-200 text-gray-600">
                  {ind.replace(/-/g," ")} <span className="text-gray-400">×{count}</span>
                </span>
              ))}
            </div>
          )}

          <div className="divide-y divide-gray-50 max-h-96 overflow-y-auto">
            {filtered.length === 0 ? (
              <p className="text-sm text-gray-400 text-center py-10">No files match your filters</p>
            ) : (
              filtered.map((e, i) => {
                const fileKey = `${e.scan_id}::${e.file_path}`;
                const isOpen  = expandedFile === fileKey;
                return (
                <div key={i}>
                  <div className="flex items-center gap-3 px-5 py-2.5 hover:bg-gray-50 cursor-pointer"
                    onClick={() => setExpandedFile(isOpen ? null : fileKey)}>
                    <div className="w-2 h-2 rounded-full shrink-0" style={{ background: RISK_COLOR[e.risk_score] ?? "#94a3b8" }} />
                    <div className="flex-1 min-w-0">
                      <p className="text-xs font-mono text-gray-700 truncate">{e.file_path}</p>
                      <p className="text-[10px] text-gray-400">{e.repo.split("/")[1]} · {e.language}</p>
                    </div>
                    <div className="w-24 hidden sm:block shrink-0">
                      <ProgressBar value={e.ai_percentage} mode="ai" height="h-1.5" />
                    </div>
                    <span className="text-[10px] tabular-nums text-gray-500 w-8 text-right shrink-0">{(e.ai_percentage*100).toFixed(0)}%</span>
                    <span className="text-[9px] font-black shrink-0 px-2 py-0.5 rounded-full"
                      style={{ background:`${RISK_COLOR[e.risk_score]}18`, color: RISK_COLOR[e.risk_score] }}>
                      {e.risk_score}
                    </span>
                    <span className="text-[9px] font-black shrink-0 w-20 text-right" style={{ color: e.attested ? "#059669" : "#dc2626" }}>
                      {e.attested ? "Attested" : "Unattested"}
                    </span>
                  </div>
                  {isOpen && (
                    <div className="px-5 pb-3 pl-10 -mt-1 flex flex-wrap items-center gap-3 text-[10px] text-gray-500">
                      <span>Scan <span className="font-mono text-gray-700">{e.scan_id}</span></span>
                      <span>Scanned {new Date(e.scanned_at).toLocaleDateString()}</span>
                      <div className="flex flex-wrap gap-1">
                        {(e.risk_indicators ?? []).length === 0 ? (
                          <span className="text-gray-400">No risk indicators</span>
                        ) : (e.risk_indicators ?? []).map(ind => (
                          <span key={ind} className="font-bold px-1.5 py-0.5 rounded bg-gray-100 text-gray-500">
                            {ind.replace(/-/g," ")}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              );})
            )}
          </div>
        </div>

      </div>
    </AuthGuard>
  );
}
