"use client";

/**
 * Phantom Dependency Scanner
 *
 * AI tools sometimes hallucinate npm/PyPI package names that don't exist.
 * This is called "slopsquatting" — when attackers register those hallucinated
 * package names as malicious packages waiting to be installed.
 *
 * This scanner checks every dependency from your AI-heavy PRs against the
 * live npm registry to detect packages that don't exist.
 */

import { useState, useEffect, useCallback, useMemo } from "react";
import AuthGuard from "@/components/AuthGuard";
import PageSkeleton from "@/components/PageSkeleton";
import InfoTooltip from "@/components/InfoTooltip";

// ── Private package scopes/prefixes for this org ─────────────────────────────
// Packages matching these are from an internal registry — not public npm.
// They are not phantom; they just aren't published publicly.
const ORG_SCOPE = `@${process.env.NEXT_PUBLIC_ORG ?? "acmecorp"}`;
const PRIVATE_SCOPES   = [ORG_SCOPE, "@trustledger"];
const PRIVATE_PACKAGES = [`${process.env.NEXT_PUBLIC_ORG ?? "acmecorp"}-shared-utils`, "crypto-payment-flow"];

function isPrivatePackage(name: string): boolean {
  if (PRIVATE_PACKAGES.includes(name)) return true;
  return PRIVATE_SCOPES.some(s => name.startsWith(s + "/"));
}

// ── Sample packages from AI-heavy scans (in production pulled from Supabase) ──

const SAMPLE_PACKAGES = [
  // Public packages — verified on npm
  { name:"react",               version:"^18.0.0",  source:"payments-api",    aiPr: false },
  { name:"next",                version:"^13.5.0",  source:"payments-api",    aiPr: false },
  { name:"@supabase/supabase-js",version:"^2.0.0",  source:"auth-service",    aiPr: false },
  { name:"zod",                 version:"^3.22.0",  source:"payments-api",    aiPr: true  },
  { name:"stripe",              version:"^13.0.0",  source:"payments-api",    aiPr: true  },
  { name:"axios",               version:"^1.6.0",   source:"fraud-detection", aiPr: true  },
  { name:"express",             version:"^4.18.0",  source:"risk-engine",     aiPr: false },
  { name:"typescript",          version:"^5.0.0",   source:"auth-service",    aiPr: false },

  // Private/internal packages — exist in internal registry, not public npm
  { name:"payment-utils-pro",   version:"^2.1.0",   source:"payments-api",    aiPr: true  },
  { name:"@novapay/card-tools",  version:"^3.0.0",  source:"payments-api",    aiPr: true  },
  { name:"crypto-payment-flow",  version:"^0.9.1",  source:"risk-engine",     aiPr: false },

  // Hallucinated packages — AI made these up; don't exist anywhere
  { name:"secure-validator-kit",version:"^1.0.3",   source:"fraud-detection", aiPr: true  },
  { name:"fraud-score-ai",      version:"^1.2.0",   source:"fraud-detection", aiPr: true  },
];

type CheckStatus = "pending" | "checking" | "exists" | "phantom" | "private" | "error";
type RemediationStatus = "open" | "remediating" | "resolved";

interface PackageResult {
  name:        string;
  version:     string;
  source:      string;  // repo name (not a path — the package.json is in this repo)
  aiPr:        boolean;
  status:      CheckStatus;
  registry?:   string;
  description?:string;
  downloads?:  number;
  riskScore?:  "critical" | "high" | "low";
}

interface PackageOverride {
  status?: RemediationStatus;
  notes?:  string[];
}

const REMEDIATION_STYLE: Record<RemediationStatus, { bg:string; text:string; border:string; label:string }> = {
  open:        { bg:"#fef2f2", text:"#be123c", border:"#fecdd3", label:"Open"        },
  remediating: { bg:"#fffbeb", text:"#b45309", border:"#fde68a", label:"Remediating" },
  resolved:    { bg:"#f0fdf4", text:"#15803d", border:"#bbf7d0", label:"Resolved"    },
};

const OVERRIDES_KEY    = "tl_phantom_overrides";
const LAST_SCANNED_KEY = "tl_phantom_last_scanned";

function pkgId(p: { name:string; source:string }) { return `${p.name}|${p.source}`; }

function loadOverrides(): Record<string, PackageOverride> {
  try { return JSON.parse(localStorage.getItem(OVERRIDES_KEY) ?? "{}"); } catch { return {}; }
}
function saveOverrides(o: Record<string, PackageOverride>) {
  localStorage.setItem(OVERRIDES_KEY, JSON.stringify(o));
}

function timeAgo(iso: string) {
  const s = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 10) return "just now";
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s/60)}m ago`;
  if (s < 86400) return `${Math.floor(s/3600)}h ago`;
  return `${Math.floor(s/86400)}d ago`;
}

async function checkNpm(pkgName: string): Promise<{ exists: boolean; description?: string; downloads?: number }> {
  try {
    // Sanitise the name before using in URL
    const safe = encodeURIComponent(pkgName).replace(/%2F/g, "/");
    const res = await fetch(`https://registry.npmjs.org/${safe}`, {
      signal: AbortSignal.timeout(5000),
    });
    if (res.status === 404) return { exists: false };
    if (res.ok) {
      const data = await res.json() as { description?: string };
      return { exists: true, description: data.description };
    }
    return { exists: false };
  } catch {
    return { exists: false };
  }
}

export default function PhantomDepsPage() {
  const [results, setResults]   = useState<PackageResult[]>([]);
  const [loading, setLoading]   = useState(true);
  const [scanning, setScanning] = useState(false);
  const [done,     setDone]     = useState(false);
  const [filter,   setFilter]   = useState<"all"|"phantom"|"private"|"ai-prs">("all");
  const [search,   setSearch]   = useState("");
  const [repoFilter, setRepoFilter] = useState("all");
  const [sortBy,   setSortBy]   = useState<"risk"|"name"|"repo">("risk");
  const [overrides, setOverrides] = useState<Record<string, PackageOverride>>({});
  const [lastScanned, setLastScanned] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [noteInput, setNoteInput] = useState<Record<string,string>>({});
  const [copied, setCopied] = useState<string | null>(null);

  // Load package list: seed → API → SAMPLE_PACKAGES fallback
  useEffect(() => {
    setOverrides(loadOverrides());
    setLastScanned(localStorage.getItem(LAST_SCANNED_KEY));
    try {
      const raw = localStorage.getItem("tl_phantom_packages");
      const pkgs = raw ? JSON.parse(raw) as typeof SAMPLE_PACKAGES : SAMPLE_PACKAGES;
      setResults(pkgs.map(p => ({ ...p, status:"pending" as CheckStatus })));
    } catch {
      setResults(SAMPLE_PACKAGES.map(p => ({ ...p, status:"pending" as CheckStatus })));
    }
    setLoading(false);
  }, []);

  function updateOverride(id: string, patch: Partial<PackageOverride>) {
    setOverrides(prev => {
      const next = { ...prev, [id]: { ...prev[id], ...patch } };
      saveOverrides(next);
      return next;
    });
  }

  function addNote(id: string) {
    const text = noteInput[id]?.trim();
    if (!text) return;
    const existing = overrides[id]?.notes ?? [];
    const date = new Date().toLocaleDateString("en-GB",{day:"2-digit",month:"short",year:"numeric"});
    updateOverride(id, { notes:[...existing, `${date}: ${text}`] });
    setNoteInput(p=>({...p,[id]:""}));
  }

  function copyCommand(pkg: string) {
    const cmd = `npm uninstall ${pkg}`;
    navigator.clipboard?.writeText(cmd).then(() => {
      setCopied(pkg);
      setTimeout(() => setCopied(null), 1500);
    });
  }

  const runScan = useCallback(async () => {
    setScanning(true);
    setDone(false);
    setResults(prev => prev.map(r => ({ ...r, status:"pending" })));

    const currentResults = results;
    for (let i = 0; i < currentResults.length; i++) {
      const pkg = currentResults[i];
      setResults(prev => prev.map((r, j) => j === i ? { ...r, status:"checking" } : r));

      // Private packages live in an internal registry — skip public npm check
      if (isPrivatePackage(pkg.name)) {
        await new Promise(res => setTimeout(res, 80));
        setResults(prev => prev.map((r, j) =>
          j === i ? { ...r, status:"private", description:"Internal package — not published to public npm", riskScore:"low" } : r
        ));
        continue;
      }

      const { exists, description } = await checkNpm(pkg.name);
      const status: CheckStatus = exists ? "exists" : "phantom";
      const riskScore = !exists && pkg.aiPr ? "critical" as const
                      : !exists             ? "high" as const
                      :                       "low" as const;
      setResults(prev => prev.map((r, j) =>
        j === i ? { ...r, status, description, riskScore } : r
      ));
      await new Promise(res => setTimeout(res, 120));
    }
    setScanning(false);
    setDone(true);
    const now = new Date().toISOString();
    localStorage.setItem(LAST_SCANNED_KEY, now);
    setLastScanned(now);
  }, [results]);

  const repos = useMemo(() => Array.from(new Set(results.map(r=>r.source))).sort(), [results]);

  const filtered = useMemo(() => {
    let list = results.filter(r =>
      filter === "all"     ? true :
      filter === "phantom" ? r.status === "phantom" :
      filter === "private" ? r.status === "private" :
      filter === "ai-prs"  ? r.aiPr : true
    );
    if (repoFilter !== "all") list = list.filter(r => r.source === repoFilter);
    if (search) {
      const q = search.toLowerCase();
      list = list.filter(r => r.name.toLowerCase().includes(q) || r.source.toLowerCase().includes(q));
    }
    const riskRank: Record<string, number> = { critical:0, high:1, low:2 };
    return [...list].sort((a,b) => {
      if (sortBy === "name") return a.name.localeCompare(b.name);
      if (sortBy === "repo") return a.source.localeCompare(b.source) || a.name.localeCompare(b.name);
      return (riskRank[a.riskScore ?? "low"] - riskRank[b.riskScore ?? "low"]) || a.name.localeCompare(b.name);
    });
  }, [results, filter, repoFilter, search, sortBy]);

  const phantomCount  = results.filter(r => r.status === "phantom").length;
  const privateCount  = results.filter(r => r.status === "private").length;
  const criticalCount = results.filter(r => r.riskScore === "critical").length;
  const resolvedCount = results.filter(r => r.status === "phantom" && (overrides[pkgId(r)]?.status === "resolved")).length;

  if (loading) return <AuthGuard><PageSkeleton rows={4} cards={4}><div /></PageSkeleton></AuthGuard>;

  return (
    <AuthGuard>
      <div className="max-w-7xl mx-auto space-y-5 pb-10">

        {/* Header */}
        <div className="animate-fade-up flex items-start justify-between gap-4 flex-wrap">
          <div>
            <div className="flex items-center gap-2.5 mb-1">
              <div className="w-8 h-8 rounded-xl flex items-center justify-center"
                style={{ background:"rgba(99,102,241,0.1)", border:"1px solid rgba(99,102,241,0.2)" }}>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#6366f1" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
                </svg>
              </div>
              <h1 className="text-xl font-black text-gray-900 tracking-tight">Phantom Dependency Scanner</h1>
              {phantomCount>0 && <span className="text-xs font-black text-white bg-rose-500 px-2 py-0.5 rounded-full">{phantomCount} phantom</span>}
            </div>
            <p className="text-sm text-gray-400">
              Detects AI-hallucinated packages that don&apos;t exist on npm — a real supply chain attack vector
            </p>
          </div>
          <div className="flex flex-col items-end gap-0.5">
            <button onClick={runScan} disabled={scanning}
              className="px-5 py-2.5 bg-indigo-600 text-white text-sm font-bold rounded-xl hover:bg-indigo-700 disabled:opacity-60 transition-colors shadow-sm">
              {scanning ? "🔍 Scanning…" : "🔍 Scan Now"}
            </button>
            {lastScanned && !scanning && <span className="text-[9px] text-gray-400">Last scanned {timeAgo(lastScanned)}</span>}
          </div>
        </div>

        {/* ── Explainer ── */}
        <div className="animate-fade-up bg-amber-50 border border-amber-200 rounded-2xl p-5">
          <div className="flex gap-3">
            <span className="text-2xl shrink-0">⚠️</span>
            <div>
              <p className="font-bold text-amber-900 mb-1">What is &quot;Slopsquatting&quot;?</p>
              <p className="text-sm text-amber-800 leading-relaxed">
                AI code generators sometimes hallucinate npm/PyPI package names that don&apos;t exist.
                Attackers monitor AI-generated code, then register those exact hallucinated package names
                as malicious packages. When developers run <code className="bg-amber-100 px-1 rounded font-mono">npm install</code>,
                they unknowingly install the attacker&apos;s package. This scanner checks every dependency
                against the live npm registry in real-time.
              </p>
            </div>
          </div>
        </div>

        {/* ── Stats ── */}
        <div className="animate-fade-up grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[
            { label:"Packages Scanned", value: results.length, color:"#1e293b", bg:"#f8fafc",
              info:{ title:"Packages Scanned", description:"Total dependencies pulled from package.json files in AI-heavy PRs across your repos." } },
            { label:"Phantom (Hallucinated)", value: phantomCount, color: phantomCount > 0 ? "#dc2626" : "#16a34a", bg: phantomCount > 0 ? "#fef2f2" : "#f0fdf4",
              info:{ title:"Phantom Packages", description:"Dependencies not found on the public npm registry — likely AI-hallucinated and a slopsquatting risk. Remove immediately." } },
            { label:"Private / Internal", value: privateCount, color:"#6366f1", bg:"#eef2ff",
              info:{ title:"Private / Internal", description:"Packages that match your org's private scopes/prefixes. Not published publicly, so a 404 on npm is expected and not a phantom." } },
            { label:"Critical (AI PRs)", value: criticalCount, color: criticalCount > 0 ? "#dc2626" : "#16a34a", bg: criticalCount > 0 ? "#fef2f2" : "#f0fdf4",
              info:{ title:"Critical Risk", description:"Phantom packages that were introduced via an AI-authored PR — highest slopsquatting risk since attackers specifically target AI-hallucinated names." } },
          ].map(s => (
            <div key={s.label} className="rounded-2xl p-4 border border-gray-200" style={{ background:s.bg }}>
              <p className="text-2xl font-black tabular-nums" style={{ color: s.color }}>{s.value}</p>
              <div className="flex items-center gap-1.5 mt-1">
                <p className="text-xs font-semibold text-gray-500">{s.label}</p>
                <InfoTooltip title={s.info.title} description={s.info.description} position="top" />
              </div>
            </div>
          ))}
        </div>

        {resolvedCount > 0 && (
          <div className="animate-fade-up flex items-center gap-2 bg-emerald-50 border border-emerald-200 rounded-xl px-4 py-2.5 text-xs font-semibold text-emerald-700">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
            {resolvedCount} of {phantomCount} phantom packages marked resolved
          </div>
        )}

        {/* ── Filters ── */}
        <div className="animate-fade-up flex flex-wrap items-center gap-2">
          {(["all","phantom","private","ai-prs"] as const).map(f => (
            <button key={f} onClick={() => setFilter(f)}
              className={`px-3 py-1.5 text-xs font-semibold rounded-xl transition-all ${filter === f ? "bg-indigo-600 text-white" : "bg-white border border-gray-200 text-gray-600 hover:bg-gray-50"}`}>
              {f === "all"     ? `All (${results.length})` :
               f === "phantom" ? `Phantom (${phantomCount})` :
               f === "private" ? `Private / Internal (${privateCount})` :
               "From AI PRs"}
            </button>
          ))}
          <div className="flex items-center rounded-xl border border-gray-200 bg-white overflow-hidden">
            <svg className="ml-3 text-gray-400 shrink-0" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
            <input value={search} onChange={e=>setSearch(e.target.value)} placeholder="Search package, repo…"
              className="px-3 py-2 text-xs text-gray-700 bg-transparent outline-none w-44" />
            {search && <button onClick={()=>setSearch("")} className="pr-2 text-gray-400 hover:text-gray-600 text-xs">✕</button>}
          </div>
          {repos.length > 1 && (
            <select value={repoFilter} onChange={e=>setRepoFilter(e.target.value)}
              className="text-xs font-semibold text-gray-600 bg-white border border-gray-200 rounded-xl px-3 py-2 focus:outline-none">
              <option value="all">All Repos</option>
              {repos.map(r => <option key={r} value={r}>{r}</option>)}
            </select>
          )}
          <div className="flex items-center gap-0.5 bg-gray-100 p-0.5 rounded-xl">
            {(["risk","name","repo"] as const).map(s => (
              <button key={s} onClick={()=>setSortBy(s)}
                className={`px-3 py-1.5 text-xs font-semibold rounded-lg transition-all ${sortBy===s ? "bg-white text-gray-900 shadow-sm" : "text-gray-500 hover:text-gray-700"}`}>
                {s === "risk" ? "Sort: Risk" : s === "name" ? "Sort: Name" : "Sort: Repo"}
              </button>
            ))}
          </div>
          {(search||repoFilter!=="all"||filter!=="all")&&(
            <button onClick={()=>{setSearch("");setRepoFilter("all");setFilter("all");}}
              className="text-xs font-bold text-rose-600 hover:text-rose-800 px-2 py-1 rounded-lg hover:bg-rose-50 transition-colors">
              Clear all
            </button>
          )}
          <span className="text-xs text-gray-400 ml-auto">{filtered.length} of {results.length}</span>
        </div>

        {/* ── Package list ── */}
        <div className="animate-fade-up section-card overflow-hidden">
          <div className="px-5 py-3 border-b border-gray-100 bg-gray-50 flex items-center justify-between">
            <p className="text-xs font-black text-gray-700 uppercase tracking-wider">Packages</p>
            {!done && !scanning && <p className="text-xs text-gray-400">Click &quot;Scan Now&quot; to check against npm registry</p>}
          </div>
          <div className="divide-y divide-gray-50">
            {filtered.map(r => {
              const id = pkgId(r);
              const ov = overrides[id];
              const remStatus = ov?.status ?? "open";
              const remStyle = REMEDIATION_STYLE[remStatus];
              const open = expanded === id;
              const isExpandable = r.status === "phantom";
              return (
                <div key={id}>
                  <div className={`flex items-center gap-4 px-5 py-3.5 ${r.status === "phantom" ? "bg-red-50/50" : r.status === "private" ? "bg-indigo-50/30" : ""} ${isExpandable ? "cursor-pointer hover:bg-red-50" : ""}`}
                    onClick={() => isExpandable && setExpanded(open ? null : id)}>
                    {/* Status indicator */}
                    <div className="w-6 h-6 rounded-full shrink-0 flex items-center justify-center">
                      {r.status === "pending"  && <span className="w-2 h-2 rounded-full bg-gray-300" />}
                      {r.status === "checking" && <span className="w-4 h-4 border-2 border-indigo-500 border-t-transparent rounded-full animate-spin block" />}
                      {r.status === "exists"   && <span className="text-green-600 font-bold">✓</span>}
                      {r.status === "phantom"  && <span className="text-red-600 font-bold">✗</span>}
                      {r.status === "private"  && <span className="text-indigo-500 font-bold">🔒</span>}
                      {r.status === "error"    && <span className="text-amber-500 font-bold">?</span>}
                    </div>

                    {/* Package info */}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-mono text-sm font-bold text-gray-900">{r.name}</span>
                        <span className="font-mono text-xs text-gray-400">{r.version}</span>
                        {r.aiPr && <span className="text-[10px] bg-purple-100 text-purple-700 px-1.5 py-0.5 rounded font-bold">AI PR</span>}
                        {r.status === "phantom" && (
                          <span className="text-[10px] bg-red-100 text-red-700 px-1.5 py-0.5 rounded-full font-bold">
                            {r.riskScore === "critical" ? "🚨 CRITICAL" : "⚠️ PHANTOM"}
                          </span>
                        )}
                        {r.status === "private" && (
                          <span className="text-[10px] bg-indigo-100 text-indigo-700 px-1.5 py-0.5 rounded-full font-bold">
                            🔒 PRIVATE REGISTRY
                          </span>
                        )}
                        {r.status === "phantom" && (
                          <span className="text-[10px] font-bold px-1.5 py-0.5 rounded-full border" style={{ background:remStyle.bg, color:remStyle.text, borderColor:remStyle.border }}>
                            {remStyle.label}
                          </span>
                        )}
                        {ov?.notes && ov.notes.length>0 && <span className="text-[9px] text-gray-400">💬 {ov.notes.length}</span>}
                      </div>
                      <div className="text-xs text-gray-400 mt-0.5">
                        Repo: <span className="font-medium text-gray-500">{r.source}</span>
                        <span className="text-gray-300 mx-1">·</span>package.json
                      </div>
                      {r.status === "exists" && r.description && (
                        <div className="text-xs text-gray-500 mt-0.5 truncate">{r.description}</div>
                      )}
                      {r.status === "phantom" && (
                        <div className="text-xs text-red-600 mt-0.5 font-medium">
                          ⚠️ Not found on npm registry — likely AI-hallucinated. Remove immediately.
                        </div>
                      )}
                      {r.status === "private" && (
                        <div className="text-xs text-indigo-600 mt-0.5 font-medium">
                          Internal package — not published to public npm. Ensure it&apos;s served from your private registry.
                        </div>
                      )}
                    </div>

                    {/* Status badge */}
                    <div className="shrink-0 flex items-center gap-2">
                      {r.status === "phantom" && (
                        <button onClick={(e) => { e.stopPropagation(); copyCommand(r.name); }}
                          className="text-[10px] font-bold text-gray-500 bg-white border border-gray-200 px-2 py-1 rounded-lg hover:bg-gray-50 transition-colors whitespace-nowrap">
                          {copied === r.name ? "Copied ✓" : "Copy uninstall"}
                        </button>
                      )}
                      <div className="text-right">
                        {r.status === "exists"   && <span className="text-xs bg-green-100 text-green-700 px-2.5 py-1 rounded-full font-bold">Verified ✓</span>}
                        {r.status === "phantom"  && <span className="text-xs bg-red-100 text-red-700 px-2.5 py-1 rounded-full font-bold">Not Found</span>}
                        {r.status === "private"  && <span className="text-xs bg-indigo-100 text-indigo-700 px-2.5 py-1 rounded-full font-bold">Private Registry</span>}
                        {r.status === "checking" && <span className="text-xs bg-indigo-100 text-indigo-700 px-2.5 py-1 rounded-full font-bold">Checking…</span>}
                        {r.status === "pending"  && <span className="text-xs bg-gray-100 text-gray-500 px-2.5 py-1 rounded-full font-bold">Pending</span>}
                      </div>
                      {isExpandable && (
                        <svg className="text-gray-300" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"
                          style={{ transform:open?"rotate(180deg)":"none", transition:"transform 0.2s" }}>
                          <polyline points="6 9 12 15 18 9"/>
                        </svg>
                      )}
                    </div>
                  </div>

                  {/* Remediation panel */}
                  {open && isExpandable && (
                    <div className="border-t border-gray-100 px-5 py-4 space-y-3" style={{ background:"rgba(248,250,252,0.8)" }}>
                      <div>
                        <p className="text-[9px] font-black uppercase tracking-widest text-gray-400 mb-1">Remediation Status</p>
                        <select value={remStatus} onChange={e=>updateOverride(id,{status:e.target.value as RemediationStatus})}
                          className="text-xs border border-gray-200 rounded-lg px-2.5 py-1.5 focus:outline-none focus:ring-2 focus:ring-indigo-400">
                          {(["open","remediating","resolved"] as const).map(s=><option key={s} value={s}>{REMEDIATION_STYLE[s].label}</option>)}
                        </select>
                      </div>
                      <div>
                        <p className="text-[10px] font-black uppercase tracking-widest text-gray-400 mb-2">Notes</p>
                        {ov?.notes && ov.notes.length>0 && (
                          <div className="space-y-1.5 mb-2">
                            {ov.notes.map((n,i)=>(
                              <div key={i} className="text-[11px] text-gray-600 bg-white rounded-lg px-3 py-2 border border-gray-100">{n}</div>
                            ))}
                          </div>
                        )}
                        <div className="flex gap-2">
                          <input value={noteInput[id]??""} onChange={e=>setNoteInput(p=>({...p,[id]:e.target.value}))}
                            onKeyDown={e=>{if(e.key==="Enter")addNote(id);}}
                            placeholder="Add a note (Enter to save)…"
                            className="flex-1 text-xs border border-gray-200 rounded-lg px-3 py-2 focus:outline-none focus:ring-2 focus:ring-indigo-400 bg-white" />
                          <button onClick={()=>addNote(id)}
                            className="text-xs font-bold text-indigo-700 bg-indigo-50 border border-indigo-200 px-3 py-2 rounded-lg hover:bg-indigo-100 transition-colors">
                            Save
                          </button>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>

        {done && phantomCount === 0 && (
          <div className="animate-fade-up bg-green-50 border border-green-200 rounded-2xl p-8 text-center">
            <div className="text-4xl mb-3">✅</div>
            <div className="font-black text-green-800 text-lg mb-2">No Phantom Packages Found</div>
            <div className="text-sm text-green-600">All {results.length} packages verified on npm registry. No hallucinated dependencies detected.</div>
          </div>
        )}

      </div>
    </AuthGuard>
  );
}
