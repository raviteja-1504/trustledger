"use client";

import { useState, useEffect, useRef, useMemo, useCallback } from "react";
import { useRouter } from "next/navigation";

const ORG = process.env.NEXT_PUBLIC_ORG ?? "novapay";

// ── Types ──────────────────────────────────────────────────────────────────────

type ResultKind = "page" | "repo" | "violation" | "secret" | "alert" | "cve" | "pr";

interface SearchResult {
  id: string;
  kind: ResultKind;
  title: string;
  sub: string;
  href: string;
  badge?: string;
  badgeColor?: string;
}

// ── Static index (augmented by localStorage snapshot at runtime) ───────────────

function makeStaticResults(): SearchResult[] {
  const o = ORG;
  return [
  // Pages
  { id:"p-dash",    kind:"page",      title:"Overview Dashboard",        sub:"Org-wide health score and metrics",          href:"/dashboard",      badge:"Page",     badgeColor:"#6366f1" },
  { id:"p-posture", kind:"page",      title:"Security Posture",          sub:"Real-time security health score and trend",  href:"/posture",        badge:"Page",     badgeColor:"#6366f1" },
  { id:"p-comp",    kind:"page",      title:"Compliance Center",         sub:"SOC 2 · EU AI Act · PCI-DSS status",         href:"/compliance",     badge:"Page",     badgeColor:"#6366f1" },
  { id:"p-vuln",    kind:"page",      title:"Vulnerability Intelligence", sub:"CVE mapping for AI code patterns",           href:"/vulnerabilities",badge:"Page",     badgeColor:"#6366f1" },
  { id:"p-viol",    kind:"page",      title:"Policy Violations",         sub:"Active violations requiring remediation",     href:"/violations",     badge:"Page",     badgeColor:"#6366f1" },
  { id:"p-alert",   kind:"page",      title:"Security Alerts",           sub:"Real-time incident management",               href:"/alerts",         badge:"Page",     badgeColor:"#6366f1" },
  { id:"p-secrets", kind:"page",      title:"Secret Scanner",            sub:"Hardcoded credential detection",              href:"/secrets",         badge:"Page",     badgeColor:"#6366f1" },
  { id:"p-deps",    kind:"page",      title:"Dependency Scanner",        sub:"AI-introduced package risk",                  href:"/dependencies",   badge:"Page",     badgeColor:"#6366f1" },
  { id:"p-reports", kind:"page",      title:"Audit Reports",             sub:"SOC 2, EU AI Act, PCI-DSS reports",           href:"/reports",        badge:"Page",     badgeColor:"#6366f1" },
  { id:"p-audit",   kind:"page",      title:"Audit Trail",               sub:"Tamper-evident security event log",           href:"/audit",          badge:"Page",     badgeColor:"#6366f1" },
  { id:"p-settings",kind:"page",      title:"Settings",                  sub:"Policies, integrations, team roles",          href:"/settings",       badge:"Page",     badgeColor:"#6366f1" },
  // Repos
  { id:"r-pay",     kind:"repo",      title:`${o}/payments-api`,      sub:"AI: 71% · Attestation: 80% · 18 scans",     href:`/repo/${o}/payments-api`,    badge:"Repo", badgeColor:"#0ea5e9" },
  { id:"r-auth",    kind:"repo",      title:`${o}/auth-service`,      sub:"AI: 44% · Attestation: 92% · 12 scans",     href:`/repo/${o}/auth-service`,    badge:"Repo", badgeColor:"#0ea5e9" },
  { id:"r-fraud",   kind:"repo",      title:`${o}/fraud-detection`,   sub:"AI: 58% · Attestation: 67% · 9 scans",      href:`/repo/${o}/fraud-detection`, badge:"Repo", badgeColor:"#0ea5e9" },
  { id:"r-risk",    kind:"repo",      title:`${o}/risk-engine`,       sub:"AI: 36% · Attestation: 95% · 7 scans",      href:`/repo/${o}/risk-engine`,     badge:"Repo", badgeColor:"#0ea5e9" },
  { id:"r-data",    kind:"repo",      title:`${o}/data-platform`,     sub:"AI: 62% · Attestation: 55% · 5 scans",      href:`/repo/${o}/data-platform`,   badge:"Repo", badgeColor:"#0ea5e9" },
  // Secrets
  { id:"s-stripe",  kind:"secret",    title:"Stripe API key — card_validator.py", sub:"payments-api · PR #482 · CRITICAL", href:"/secrets", badge:"Secret", badgeColor:"#9333ea" },
  { id:"s-jwt",     kind:"secret",    title:"JWT secret — token_service.py",       sub:"auth-service · PR #341 · CRITICAL", href:"/secrets", badge:"Secret", badgeColor:"#9333ea" },
  { id:"s-db",      kind:"secret",    title:"DB password — connection.py",          sub:"fraud-detection · PR #219 · CRITICAL", href:"/secrets", badge:"Secret", badgeColor:"#9333ea" },
  // Violations
  { id:"v-cv1",     kind:"violation", title:"CRITICAL file unattested — card_validator.py", sub:"payments-api · Merge blocked · SLA: 24h", href:"/violations", badge:"Violation", badgeColor:"#ef4444" },
  { id:"v-cv2",     kind:"violation", title:"CRITICAL file unattested — risk_scorer.ts",    sub:"fraud-detection · SLA breach",            href:"/violations", badge:"Violation", badgeColor:"#ef4444" },
  { id:"v-sla",     kind:"violation", title:"SLA breach — stripe_client.py unattested 50h", sub:"payments-api · HIGH risk",                href:"/violations", badge:"Violation", badgeColor:"#f97316" },
  // CVEs
  { id:"c-sql",     kind:"cve",       title:"CVE-2023-20052 — SQL Injection",      sub:"CVSS 9.8 · CRITICAL · payments-api, fraud-detection", href:"/vulnerabilities", badge:"CVE", badgeColor:"#dc2626" },
  { id:"c-jwt",     kind:"cve",       title:"CVE-2022-21449 — JWT None Algorithm", sub:"CVSS 9.1 · CRITICAL · auth-service",                  href:"/vulnerabilities", badge:"CVE", badgeColor:"#dc2626" },
  { id:"c-eval",    kind:"cve",       title:"CVE-2021-44228 — eval/exec RCE",      sub:"CVSS 10.0 · CRITICAL · payments-api, risk-engine",    href:"/vulnerabilities", badge:"CVE", badgeColor:"#dc2626" },
  // PRs
  { id:"pr-482",    kind:"pr",        title:"PR #482 — payments-api",    sub:"CRITICAL risk · 8 files · 91% AI",  href:"/pr/sc_mock_001", badge:"PR", badgeColor:"#10b981" },
  { id:"pr-341",    kind:"pr",        title:"PR #341 — auth-service",    sub:"HIGH risk · 4 files · 68% AI",     href:"/pr/sc_mock_002", badge:"PR", badgeColor:"#10b981" },
  { id:"pr-219",    kind:"pr",        title:"PR #219 — fraud-detection", sub:"CRITICAL risk · 5 files · 83% AI", href:"/pr/sc_mock_003", badge:"PR", badgeColor:"#10b981" },
  // Alerts
  { id:"al-stripe", kind:"alert",     title:"P1 — Production Stripe key committed",   sub:"Firing · payments-api · Rotate immediately", href:"/alerts", badge:"Alert", badgeColor:"#f97316" },
  { id:"al-typo",   kind:"alert",     title:"P1 — Typosquatting package detected",    sub:"Firing · fraud-detection · stripe-client",   href:"/alerts", badge:"Alert", badgeColor:"#f97316" },
  ];
}
const STATIC_RESULTS: SearchResult[] = makeStaticResults();

const KIND_ORDER: Record<ResultKind, number> = {
  violation: 0, alert: 1, secret: 2, cve: 3, pr: 4, repo: 5, page: 6,
};

// ── Icons ──────────────────────────────────────────────────────────────────────

function KindIcon({ kind }: { kind: ResultKind }) {
  const icons: Record<ResultKind, JSX.Element> = {
    page:      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>,
    repo:      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M3 3h18v18H3z"/><path d="M9 3v18"/></svg>,
    violation: <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>,
    secret:    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>,
    alert:     <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg>,
    cve:       <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>,
    pr:        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="18" cy="18" r="3"/><circle cx="6" cy="6" r="3"/><path d="M13 6h3a2 2 0 0 1 2 2v7"/><line x1="6" y1="9" x2="6" y2="21"/></svg>,
  };
  return icons[kind];
}

// ── Component ──────────────────────────────────────────────────────────────────

export default function GlobalSearch() {
  const [open,        setOpen]        = useState(false);
  const [query,       setQuery]       = useState("");
  const [cursor,      setCursor]      = useState(0);
  const [apiResults,  setApiResults]  = useState<SearchResult[]>([]);
  const [searching,   setSearching]   = useState(false);
  const inputRef      = useRef<HTMLInputElement>(null);
  const searchTimer   = useRef<ReturnType<typeof setTimeout> | null>(null);
  const router        = useRouter();

  // Open on Cmd+K / Ctrl+K
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        setOpen(v => !v);
      }
      if (e.key === "Escape") setOpen(false);
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  // Focus input when opened
  useEffect(() => {
    if (open) { setQuery(""); setCursor(0); setTimeout(() => inputRef.current?.focus(), 50); }
  }, [open]);

  // Debounced search — tries real API first, falls back to static
  useEffect(() => {
    if (searchTimer.current) clearTimeout(searchTimer.current);
    if (!query.trim() || query.length < 2) { setApiResults([]); return; }

    setSearching(true);
    searchTimer.current = setTimeout(async () => {
      try {
        const { authedFetch } = await import("@/lib/useRealData");
        const data = await authedFetch<{ results: Array<{ type: string; title: string; subtitle: string; href: string; risk?: string; id: string }> }>(
          `/api/search?q=${encodeURIComponent(query)}&limit=12`,
        );
        const mapped: SearchResult[] = (data.results ?? []).map(r => ({
          id:         r.id,
          kind:       (r.type as ResultKind) ?? "page",
          title:      r.title,
          sub:        r.subtitle,
          href:       r.href,
          badge:      r.type.replace(/_/g," "),
          badgeColor: r.risk ? ({ CRITICAL:"#ef4444",HIGH:"#f97316",MEDIUM:"#f59e0b",LOW:"#22c55e" }[r.risk] ?? "#6366f1") : "#6366f1",
        }));
        setApiResults(mapped);
      } catch {
        setApiResults([]);
      } finally {
        setSearching(false);
      }
    }, 300);
  }, [query]);

  const results = useMemo<SearchResult[]>(() => {
    if (!query.trim()) return STATIC_RESULTS.slice(0, 8);
    // Use real API results if available, otherwise filter static
    if (apiResults.length > 0) return apiResults;
    const q = query.toLowerCase();
    return STATIC_RESULTS
      .filter(r => r.title.toLowerCase().includes(q) || r.sub.toLowerCase().includes(q) || (r.badge?.toLowerCase() ?? "").includes(q))
      .sort((a, b) => KIND_ORDER[a.kind] - KIND_ORDER[b.kind])
      .slice(0, 10);
  }, [query, apiResults]);

  const navigate = useCallback((href: string) => {
    setOpen(false);
    router.push(href);
  }, [router]);

  // Keyboard navigation inside palette
  function onKeyDown(e: React.KeyboardEvent) {
    if (e.key === "ArrowDown") { e.preventDefault(); setCursor(c => Math.min(c + 1, results.length - 1)); }
    if (e.key === "ArrowUp")   { e.preventDefault(); setCursor(c => Math.max(c - 1, 0)); }
    if (e.key === "Enter" && results[cursor]) navigate(results[cursor].href);
  }

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-[100] flex items-start justify-center pt-[12vh] px-4"
      style={{ background: "rgba(15,23,42,0.65)", backdropFilter: "blur(4px)" }}
      onClick={() => setOpen(false)}>

      <div className="w-full max-w-xl rounded-2xl overflow-hidden shadow-2xl"
        style={{ background: "#fff", border: "1px solid rgba(226,232,240,0.9)", boxShadow: "0 24px 64px rgba(0,0,0,0.2)" }}
        onClick={e => e.stopPropagation()}>

        {/* Search input */}
        <div className="flex items-center gap-3 px-4 py-3.5 border-b border-gray-100">
          <svg className="text-gray-400 shrink-0" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
            <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
          </svg>
          <input
            ref={inputRef}
            value={query}
            onChange={e => { setQuery(e.target.value); setCursor(0); }}
            onKeyDown={onKeyDown}
            placeholder="Search pages, repos, PRs, CVEs, violations…"
            className="flex-1 text-sm text-gray-800 placeholder-gray-400 outline-none bg-transparent"
          />
          <kbd className="text-[10px] font-mono text-gray-400 bg-gray-100 border border-gray-200 px-1.5 py-0.5 rounded-md shrink-0">
            Esc
          </kbd>
        </div>

        {/* Results */}
        <div className="max-h-[60vh] overflow-y-auto">
          {searching && (
            <div className="py-4 flex items-center justify-center gap-2 text-xs text-gray-400">
              <svg className="animate-spin w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M21 12a9 9 0 1 1-6.219-8.56"/></svg>
              Searching…
            </div>
          )}
          {!searching && results.length === 0 ? (
            <div className="py-10 text-center">
              <p className="text-sm text-gray-400 font-medium">No results for "{query}"</p>
            </div>
          ) : !searching && (
            <div className="py-1.5">
              {results.map((r, i) => (
                <button key={r.id}
                  className="w-full flex items-center gap-3 px-4 py-2.5 text-left transition-colors"
                  style={{ background: i === cursor ? "rgba(99,102,241,0.07)" : "transparent" }}
                  onMouseEnter={() => setCursor(i)}
                  onClick={() => navigate(r.href)}
                >
                  <div className="w-7 h-7 rounded-lg flex items-center justify-center shrink-0"
                    style={{ background: `${r.badgeColor}15`, color: r.badgeColor }}>
                    <KindIcon kind={r.kind} />
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-semibold text-gray-800 truncate">{r.title}</p>
                    <p className="text-[11px] text-gray-400 truncate mt-0.5">{r.sub}</p>
                  </div>
                  <span className="text-[10px] font-bold px-2 py-0.5 rounded-full shrink-0"
                    style={{ background: `${r.badgeColor}15`, color: r.badgeColor }}>
                    {r.badge}
                  </span>
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-4 py-2.5 border-t border-gray-100 flex items-center gap-4"
          style={{ background: "rgba(248,250,252,0.8)" }}>
          <span className="text-[10px] text-gray-400 flex items-center gap-1">
            <kbd className="font-mono bg-white border border-gray-200 px-1 rounded text-[9px]">↑↓</kbd> navigate
          </span>
          <span className="text-[10px] text-gray-400 flex items-center gap-1">
            <kbd className="font-mono bg-white border border-gray-200 px-1 rounded text-[9px]">↵</kbd> open
          </span>
          <span className="text-[10px] text-gray-400 flex items-center gap-1">
            <kbd className="font-mono bg-white border border-gray-200 px-1 rounded text-[9px]">⌘K</kbd> toggle
          </span>
          <span className="ml-auto text-[10px] text-gray-400">{results.length} result{results.length !== 1 ? "s" : ""}</span>
        </div>
      </div>
    </div>
  );
}
