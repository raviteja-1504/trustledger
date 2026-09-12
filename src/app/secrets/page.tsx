"use client";

import { useState, useEffect, useCallback, useMemo } from "react";
import Link from "next/link";
import InfoTooltip from "@/components/InfoTooltip";
import AuthGuard from "@/components/AuthGuard";
import PageSkeleton from "@/components/PageSkeleton";
import { authedFetch } from "@/lib/useRealData";
import { useAuth } from "@/lib/auth";

// ── Types ──────────────────────────────────────────────────────────────────────

type SecretSeverity = "CRITICAL" | "HIGH" | "MEDIUM";
type SecretStatus = "open" | "resolved";

// Matches the shape returned by GET /api/secrets — a direct read of the
// secret_findings table (see api/secrets/route.ts). Previously this page
// re-derived "findings" client-side by re-fetching every repo's latest scan
// and re-scanning file content for secret-shaped indicators, and stored
// resolved/open status ONLY in localStorage. That's exactly why the same
// secret could show a different status on different devices or sessions --
// the "resolved" flag never left whichever one browser's storage it was
// written to. Now the server is the only source of truth for both read and
// write; nothing here is ever stored in localStorage.
interface SecretFinding {
  id:            string;
  severity:      SecretSeverity;
  type:          string;
  label:         string;
  file_path:     string;
  repo:          string;
  line_number:   number | null;
  masked_value:  string;
  pr_number:     number;
  scan_id:       string;
  detected_at:   string;
  status:        SecretStatus;
  resolved_by?:  string;
  resolved_at?:  string;
}

const TYPE_LABELS: Record<string, string> = {
  api_key:     "API Key",
  jwt_secret:  "JWT Secret",
  db_password: "DB Password",
  private_key: "Private Key",
  oauth_token: "OAuth Token",
  webhook_url: "Webhook URL",
};

function typeLabel(type: string): string {
  return TYPE_LABELS[type] ?? type.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase());
}

// ── Icons ──────────────────────────────────────────────────────────────────────

function SecretIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
    </svg>
  );
}

function ExternalIcon() {
  return (
    <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/>
      <polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/>
    </svg>
  );
}

// ── Helpers ────────────────────────────────────────────────────────────────────

const SEV: Record<SecretSeverity, { bg: string; text: string; border: string; dot: string }> = {
  CRITICAL: { bg: "#ede9fe", text: "#5b21b6", border: "#c4b5fd", dot: "#7c3aed" },
  HIGH:     { bg: "#ffedd5", text: "#7c2d12", border: "#fed7aa", dot: "#f97316" },
  MEDIUM:   { bg: "#fef3c7", text: "#78350f", border: "#fde68a", dot: "#f59e0b" },
};

function timeAgo(iso: string) {
  const s = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60)   return "just now";
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400)return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

// ── Page ───────────────────────────────────────────────────────────────────────

export default function SecretsPage() {
  const { profile } = useAuth();
  const [findings,     setFindings]     = useState<SecretFinding[]>([]);
  const [loading,      setLoading]      = useState(true);
  const [filterSev,    setFilterSev]    = useState<SecretSeverity | "all">("all");
  const [filterStatus, setFilterStatus] = useState<SecretStatus | "all">("all");
  const [filterRepo,   setFilterRepo]   = useState("all");
  const [expanded,     setExpanded]     = useState<string | null>(null);
  const [refreshing,   setRefreshing]   = useState(false);
  const [lastRefreshed, setLastRefreshed] = useState<Date | null>(null);
  const [pendingIds,   setPendingIds]   = useState<Set<string>>(new Set());

  // The single source of truth: GET /api/secrets, a direct read of
  // secret_findings. No caching, no localStorage merge -- whatever the
  // server returns is exactly what's shown, on every device, every time.
  const fetchLive = useCallback(async () => {
    if (!profile?.org_id) return;
    try {
      const data = await authedFetch<{ findings: SecretFinding[] }>("/api/secrets");
      setFindings(data.findings ?? []);
      setLastRefreshed(new Date());
      window.dispatchEvent(new Event("tl:badge"));
    } catch { /* offline — keep whatever's currently shown */ }
    finally { setLoading(false); }
  }, [profile?.org_id]);

  async function handleRefreshClick() {
    setRefreshing(true);
    try { await fetchLive(); } finally { setRefreshing(false); }
  }

  useEffect(() => {
    fetchLive();
  }, [fetchLive]);

  // Resolve/re-open now writes through to the server first. The local state
  // update only happens after the server confirms, so there's no window
  // where the UI claims a status the database doesn't actually have --
  // and no per-device drift, since every device reads the same row.
  async function setStatus(id: string, status: SecretStatus) {
    setPendingIds(prev => new Set(prev).add(id));
    try {
      await authedFetch("/api/secrets", { method: "PATCH", body: JSON.stringify({ id, status }) });
      setFindings(prev => prev.map(f => f.id === id
        ? { ...f, status, resolved_by: status === "resolved" ? (profile?.email ?? "you") : undefined,
            resolved_at: status === "resolved" ? new Date().toISOString() : undefined }
        : f));
      window.dispatchEvent(new Event("tl:badge"));
    } catch {
      // Failed server-side -- re-sync with the real state rather than
      // leaving the UI showing a status change that didn't actually persist.
      fetchLive();
    } finally {
      setPendingIds(prev => { const next = new Set(prev); next.delete(id); return next; });
    }
  }

  const repos = useMemo(() => Array.from(new Set(findings.map(f => f.repo))), [findings]);

  function matchesSev(f: SecretFinding): boolean {
    return filterSev === "all" || f.severity === filterSev;
  }
  function matchesStatus(f: SecretFinding): boolean {
    return filterStatus === "all" || f.status === filterStatus;
  }
  function matchesRepo(f: SecretFinding): boolean {
    return filterRepo === "all" || f.repo === filterRepo;
  }

  const bySevRepo = findings.filter(f => matchesSev(f) && matchesRepo(f));
  const filtered  = bySevRepo.filter(matchesStatus);

  const open     = bySevRepo.filter(f => f.status === "open").length;
  const critical = bySevRepo.filter(f => f.severity === "CRITICAL" && f.status === "open").length;
  const resolved = bySevRepo.filter(f => f.status === "resolved").length;

  function exportCSV() {
    const rows = [
      ["Severity","Type","File","Repository","Line","Status","Detected","Resolved By"],
      ...filtered.map(f => [
        f.severity, typeLabel(f.type), f.file_path, f.repo,
        String(f.line_number ?? ""), f.status, f.detected_at,
        f.resolved_by ?? "",
      ]),
    ];
    const csv = rows.map(r => r.map(c => `"${c}"`).join(",")).join("\n");
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
    a.download = "trustledger-secrets.csv";
    a.click();
  }

  return (
    <AuthGuard>
      <PageSkeleton rows={5} cards={4}>
      <div className="max-w-7xl mx-auto space-y-5 pb-10">

        {/* Header */}
        <div className="animate-fade-up flex items-start justify-between gap-4 flex-wrap">
          <div>
            <div className="flex items-center gap-2.5 mb-1">
              <div className="w-8 h-8 rounded-xl flex items-center justify-center text-rose-600"
                style={{ background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.2)" }}>
                <SecretIcon />
              </div>
              <h1 className="text-xl font-black text-gray-900 tracking-tight">Secret Scanner</h1>
              {open > 0 && (
                <span className="text-xs font-black text-white bg-rose-500 px-2 py-0.5 rounded-full">
                  {open} open
                </span>
              )}
            </div>
            <p className="text-sm text-gray-400 mt-0.5">
              Hardcoded credentials detected in AI-generated code — review and remediate before production.
            </p>
          </div>
          <div className="flex items-center gap-2">
            {lastRefreshed && (
              <span className="text-[11px] text-gray-400 hidden sm:inline">
                Synced {timeAgo(lastRefreshed.toISOString())}
              </span>
            )}
            <button onClick={handleRefreshClick} disabled={refreshing}
              title="Re-fetch current findings from the server"
              className="flex items-center gap-1.5 px-3 py-2 text-sm font-semibold text-gray-600 bg-white border border-gray-200 rounded-xl hover:bg-gray-50 disabled:opacity-50 transition-all shadow-sm">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"
                className={refreshing ? "animate-spin" : ""}>
                <polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>
              </svg>
              {refreshing ? "Refreshing…" : "Refresh"}
            </button>
            <button onClick={exportCSV}
              className="flex items-center gap-1.5 px-3 py-2 text-sm font-semibold text-gray-600 bg-white border border-gray-200 rounded-xl hover:bg-gray-50 transition-all shadow-sm">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>
              </svg>
              Export CSV
            </button>
          </div>
        </div>

        {/* Summary cards */}
        <div className="animate-fade-up grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[
            { label: "Total Detected",  value: bySevRepo.length, color: "#6366f1", bg: "#eef2ff", info: { title: "Total Detected",  description: "All hardcoded credentials found across scanned repos — API keys, passwords, tokens, secrets. Every occurrence is flagged regardless of whether it's already been rotated." } },
            { label: "Critical Open",   value: critical,        color: "#7c3aed", bg: "#ede9fe", info: { title: "Critical Open",   description: "CRITICAL-severity secrets (production API keys, DB passwords, JWT signing secrets) that are still in 'Open' status and haven't been rotated." } },
            { label: "Open",            value: open,            color: "#ef4444", bg: "#fef2f2", info: { title: "Open Secrets",    description: "All secrets not yet marked as resolved. Click a finding and choose 'Resolved' once the credential has been rotated and removed from source." } },
            { label: "Resolved",        value: resolved,        color: "#10b981", bg: "#f0fdf4", info: { title: "Resolved",        description: "Secrets confirmed rotated and removed from source code. Mark resolved only after the credential is invalidated in the issuing system (Stripe, AWS, etc.)." } },
          ].map(s => (
            <div key={s.label} className="rounded-2xl p-4 border"
              style={{ background: s.bg, borderColor: s.color + "30" }}>
              <p className="text-2xl font-black tabular-nums" style={{ color: s.color }}>{s.value}</p>
              <div className="flex items-center gap-1.5 mt-1">
                <p className="text-xs font-semibold text-gray-500">{s.label}</p>
                <InfoTooltip title={s.info.title} description={s.info.description} position="top" />
              </div>
            </div>
          ))}
        </div>

        {/* Filters */}
        <div className="animate-fade-up flex flex-wrap items-center gap-2">
          {/* Status with counts */}
          <div className="flex items-center gap-0.5 bg-gray-100 p-0.5 rounded-xl">
            {([
              { val:"all",      label:`All (${bySevRepo.length})` },
              { val:"open",     label:`Open (${open})` },
              { val:"resolved", label:`Resolved (${resolved})` },
            ] as const).map(s => (
              <button key={s.val} onClick={() => setFilterStatus(s.val)}
                className={`px-3 py-1.5 text-xs font-semibold rounded-lg transition-all ${
                  filterStatus === s.val ? "bg-white text-gray-900 shadow-sm" : "text-gray-500 hover:text-gray-700"
                }`}>
                {s.label}
              </button>
            ))}
          </div>
          {/* Severity */}
          <div className="flex items-center gap-0.5 bg-gray-100 p-0.5 rounded-xl">
            {(["all","CRITICAL","HIGH","MEDIUM"] as const).map(s => (
              <button key={s} onClick={() => setFilterSev(s)}
                className={`px-3 py-1.5 text-xs font-semibold rounded-lg transition-all ${
                  filterSev === s ? "bg-white text-gray-900 shadow-sm" : "text-gray-500 hover:text-gray-700"
                }`}>
                {s === "all" ? "All Severity" : s}
              </button>
            ))}
          </div>
          {/* Repo */}
          <select value={filterRepo} onChange={e => setFilterRepo(e.target.value)}
            className="text-xs font-semibold text-gray-600 bg-white border border-gray-200 rounded-xl px-3 py-2 focus:outline-none focus:ring-2 focus:ring-indigo-400">
            <option value="all">All Repos</option>
            {repos.map(r => <option key={r} value={r}>{r.split("/").pop()}</option>)}
          </select>
          <span className="text-xs text-gray-400 ml-auto">
            {filtered.length} finding{filtered.length !== 1 ? "s" : ""}
          </span>
        </div>

        {/* Findings table */}
        <div className="animate-fade-up section-card overflow-hidden">

          {loading ? (
            <div className="flex flex-col items-center justify-center py-16 gap-3 text-gray-400">
              <svg className="animate-spin" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M21 12a9 9 0 1 1-6.219-8.56"/>
              </svg>
              <p className="text-sm font-semibold">Loading findings…</p>
            </div>
          ) : filtered.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 gap-3">
              <div className="w-12 h-12 rounded-2xl bg-emerald-50 flex items-center justify-center text-emerald-500">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>
                </svg>
              </div>
              <p className="text-sm font-bold text-gray-700">
                {bySevRepo.length > 0 ? "All findings in this view are resolved" : "No findings match this filter"}
              </p>
              <p className="text-xs text-gray-400">
                {bySevRepo.length > 0
                  ? <button onClick={() => setFilterStatus("all")} className="text-indigo-600 hover:underline">Show all {bySevRepo.length} finding{bySevRepo.length > 1 ? "s" : ""}</button>
                  : "Try adjusting the severity or status filter"
                }
              </p>
            </div>
          ) : (
            <div>
              {/* Column headers */}
              <div className="grid items-center px-5 py-2.5 border-b border-gray-100 text-[10px] font-black uppercase tracking-widest text-gray-400"
                style={{ gridTemplateColumns: "100px 120px 1fr 120px 90px 110px" }}>
                <span>Severity</span><span>Type</span><span>File / Repo</span>
                <span>Detected</span><span>PR</span><span>Status</span>
              </div>

              <div className="divide-y divide-gray-50">
                {filtered.map(f => {
                  const sev     = SEV[f.severity];
                  const isOpen  = expanded === f.id;
                  const pending = pendingIds.has(f.id);
                  return (
                    <div key={f.id}>
                      <div
                        className="grid items-center px-5 py-3.5 cursor-pointer transition-colors hover:bg-gray-50/70"
                        style={{ gridTemplateColumns: "100px 120px 1fr 120px 90px 110px" }}
                        onClick={() => setExpanded(isOpen ? null : f.id)}
                      >
                        {/* Severity */}
                        <span className="inline-flex items-center gap-1.5 text-[11px] font-bold px-2 py-0.5 rounded-full w-fit"
                          style={{ background: sev.bg, color: sev.text, border: `1px solid ${sev.border}` }}>
                          <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: sev.dot }} />
                          {f.severity}
                        </span>

                        {/* Type */}
                        <span className="text-xs font-semibold text-gray-600">{typeLabel(f.type)}</span>

                        {/* File */}
                        <div className="min-w-0 pr-3">
                          <p className="text-[11px] font-mono font-semibold text-gray-800 truncate">
                            {f.file_path.split("/").pop()}
                            {f.line_number != null && <span className="text-gray-400 font-normal">:{f.line_number}</span>}
                          </p>
                          <p className="text-[10px] text-gray-400 mt-0.5">{f.repo.split("/").pop()}</p>
                        </div>

                        {/* Detected */}
                        <span className="text-xs text-gray-400 tabular-nums">{timeAgo(f.detected_at)}</span>

                        {/* PR */}
                        <Link href={`/pr/${f.scan_id}`} onClick={e => e.stopPropagation()}
                          className="text-xs font-bold text-indigo-600 hover:text-indigo-800 flex items-center gap-1 w-fit">
                          #{f.pr_number} <ExternalIcon />
                        </Link>

                        {/* Status + Resolve action */}
                        <div className="flex flex-col gap-1" onClick={e => e.stopPropagation()}>
                          {f.status === "open" ? (
                            <button
                              onClick={() => setStatus(f.id, "resolved")}
                              disabled={pending}
                              className="text-[11px] font-bold text-emerald-700 bg-emerald-50 border border-emerald-200 px-2.5 py-1 rounded-lg hover:bg-emerald-100 disabled:opacity-50 transition-colors whitespace-nowrap flex items-center gap-1">
                              <svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
                              {pending ? "Saving…" : "Resolve"}
                            </button>
                          ) : (
                            <>
                              <span className="text-[11px] font-bold text-emerald-700 flex items-center gap-1">
                                <svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
                                Resolved
                              </span>
                              <button
                                onClick={() => setStatus(f.id, "open")}
                                disabled={pending}
                                className="text-[10px] text-gray-400 hover:text-rose-600 disabled:opacity-50 transition-colors whitespace-nowrap">
                                {pending ? "Saving…" : "Re-open"}
                              </button>
                            </>
                          )}
                        </div>
                      </div>

                      {/* Expanded detail */}
                      {isOpen && (
                        <div className="px-5 pb-4 border-b border-gray-100"
                          style={{ background: "linear-gradient(90deg,rgba(248,250,252,0.9),rgba(248,250,252,0.3))" }}>
                          <div className="space-y-3">
                            {/* Masked value */}
                            <div>
                              <p className="text-[10px] font-bold uppercase tracking-widest text-gray-400 mb-1.5">Detected Pattern</p>
                              <div className="bg-gray-900 rounded-xl px-4 py-3 font-mono text-xs">
                                <p className="text-gray-500 mb-1">
                                  <span className="text-gray-600 select-none">
                                    {f.file_path}{f.line_number != null ? `:${f.line_number}` : ""}
                                  </span>
                                </p>
                                <p>
                                  <span className="text-rose-400">{f.label}</span>
                                  <span className="text-gray-400"> — </span>
                                  <span className="text-amber-300">"{f.masked_value}"</span>
                                </p>
                              </div>
                            </div>
                            {/* Remediation */}
                            <div className="bg-indigo-50 border border-indigo-100 rounded-xl px-4 py-3">
                              <p className="text-[10px] font-bold uppercase tracking-widest text-indigo-600 mb-1.5">Remediation</p>
                              <p className="text-xs text-indigo-800 leading-relaxed">
                                Move this value to an environment variable or secrets manager (AWS Secrets Manager, Vault, etc.).
                                Rotate the credential immediately — treat it as compromised.
                                Never commit credentials to source code, even in test or demo files.
                              </p>
                            </div>
                            {/* Resolved info */}
                            {f.status === "resolved" && f.resolved_by && (
                              <p className="text-xs text-emerald-700 flex items-center gap-1.5">
                                <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><polyline points="20 6 9 17 4 12"/></svg>
                                Resolved by <strong>{f.resolved_by}</strong>{f.resolved_at ? <> · {timeAgo(f.resolved_at)}</> : null}
                              </p>
                            )}
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </div>

        {/* Info banner */}
        <div className="animate-fade-up flex items-start gap-3 bg-amber-50 border border-amber-200 rounded-xl px-4 py-3">
          <svg className="shrink-0 mt-0.5 text-amber-600" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
            <path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
            <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
          </svg>
          <p className="text-xs text-amber-800 leading-relaxed">
            <span className="font-bold">Treat every detected secret as compromised</span> — even if not yet in production.
            Rotate credentials immediately and use environment variables or a secrets manager going forward.
            TrustLedger scans for patterns including Stripe, AWS, GitHub, JWT, SSH, and database credential formats.
          </p>
        </div>

      </div>
      </PageSkeleton>
    </AuthGuard>
  );
}
