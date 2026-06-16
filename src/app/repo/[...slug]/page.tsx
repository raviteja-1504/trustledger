"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import AuthGuard from "@/components/AuthGuard";
import RiskBadge from "@/components/RiskBadge";
import ProgressBar from "@/components/ProgressBar";
import { api } from "@/lib/api";
import { isSeedMode } from "@/lib/useRealData";
import { useAuth } from "@/lib/auth";
import type { ScanResult, FileResult, RiskLevel, DashboardData } from "@/types";

const RISK_ORDER: RiskLevel[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];

function riskPfx(r: string) {
  return r === "CRITICAL" ? "crit" : r === "HIGH" ? "high" : r === "MEDIUM" ? "med" : "low";
}

function buildScansFromSeed(repo: string): ScanResult[] {
  try {
    const raw = localStorage.getItem("tl_notif_snapshot");
    if (!raw) return [];
    const dash = JSON.parse(raw) as DashboardData;
    const repoStat = dash.repos.find(r => r.repo === repo);
    const files = dash.top_risk_files.filter(f => f.repo === repo);
    if (!files.length) return [];

    const vs = JSON.parse(localStorage.getItem("tl_violation_statuses") ?? "{}") as Record<string, string>;

    const byId = new Map<string, typeof files>();
    for (const f of files) {
      if (!byId.has(f.scan_id)) byId.set(f.scan_id, []);
      byId.get(f.scan_id)!.push(f);
    }

    const baseTime = repoStat?.last_scan
      ? new Date(repoStat.last_scan).getTime()
      : Date.now() - 2 * 86400000;

    return Array.from(byId.entries()).map(([scan_id, scanFiles], idx) => {
      const fileResults: FileResult[] = scanFiles.map(f => ({
        file_path: f.file_path,
        language: f.file_path.endsWith(".py") ? "python"
          : f.file_path.endsWith(".ts") || f.file_path.endsWith(".tsx") ? "typescript"
            : f.file_path.endsWith(".go") ? "go"
              : "unknown",
        ai_percentage: f.ai_pct,
        risk_score: f.risk_score,
        risk_indicators: [],
        attested: f.attested || vs[`${riskPfx(f.risk_score)}::${f.scan_id}::${f.file_path}`] === "resolved",
      }));

      const overall_risk = fileResults.reduce<RiskLevel>((best, f) =>
        RISK_ORDER.indexOf(f.risk_score) < RISK_ORDER.indexOf(best) ? f.risk_score : best,
        "LOW"
      );

      const total_ai_percentage =
        fileResults.reduce((s, f) => s + f.ai_percentage, 0) / fileResults.length;

      const commit_sha = (scan_id.replace(/[^a-f0-9]/gi, "a") + "0".repeat(40)).slice(0, 40);

      return {
        scan_id,
        repo,
        pr_number: scanFiles[0].pr_number,
        commit_sha,
        files: fileResults,
        overall_risk,
        total_ai_percentage,
        timestamp: new Date(baseTime - idx * 3 * 86400000).toISOString(),
      };
    });
  } catch {
    return [];
  }
}

function relDate(iso: string) {
  if (!iso) return "—";
  const d = Math.floor((Date.now() - new Date(iso).getTime()) / 86400000);
  if (d === 0) return "Today";
  if (d === 1) return "Yesterday";
  if (d < 7) return `${d}d ago`;
  if (d < 30) return `${Math.floor(d / 7)}w ago`;
  return `${Math.floor(d / 30)}mo ago`;
}

function BackIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="15 18 9 12 15 6" />
    </svg>
  );
}

function BranchIcon() {
  return (
    <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <line x1="6" y1="3" x2="6" y2="15"/><circle cx="18" cy="6" r="3"/><circle cx="6" cy="18" r="3"/>
      <path d="M18 9a9 9 0 0 1-9 9"/>
    </svg>
  );
}

function WebhookIcon() {
  return (
    <svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M18 16.98h-5.99c-1.1 0-1.95.94-2.48 1.9A4 4 0 0 1 2 17c.01-.7.2-1.4.57-2"/><path d="m6 17 3.13-5.78c.53-.97.1-2.18-.5-3.1a4 4 0 1 1 6.89-4.06"/><path d="m12 6 3.13 5.73C15.66 12.7 16.9 13 18 13a4 4 0 0 1 0 8"/>
    </svg>
  );
}

export default function RepoDetailPage() {
  const { profile } = useAuth();
  const { slug } = (useParams<{ slug: string[] }>() ?? { slug: [] });
  const repo = Array.isArray(slug) ? slug.join("/") : slug;
  const [scans, setScans] = useState<ScanResult[]>([]);
  const [loading, setLoading] = useState(true);
  const [offline, setOffline] = useState(false);

  useEffect(() => {
    if (isSeedMode() && !profile?.org_id) {
      setScans(buildScansFromSeed(repo));
      setOffline(true);
      setLoading(false);
      return;
    }
    api.repoScans(repo)
      .then(scans => {
        if (scans.length > 0) {
          setScans(scans);
        } else {
          setScans(buildScansFromSeed(repo));
          setOffline(true);
        }
      })
      .catch(() => {
        const seed = buildScansFromSeed(repo);
        setScans(seed);
        setOffline(true);
      })
      .finally(() => setLoading(false));
  }, [repo, profile?.org_id]);

  const repoShort = repo.split("/").slice(1).join("/");
  const org = repo.split("/")[0];

  const avgAi = scans.length
    ? scans.reduce((s, sc) => s + sc.total_ai_percentage, 0) / scans.length
    : 0;

  const critCount = scans.filter(s => s.overall_risk === "CRITICAL").length;
  const highCount = scans.filter(s => s.overall_risk === "HIGH").length;

  // Deduplicated file list across all scans — keep most recent occurrence
  const allFiles = (() => {
    const seen = new Map<string, { file: FileResult; scan_id: string; pr_number?: number }>();
    for (const sc of scans) {
      for (const f of sc.files) {
        if (!seen.has(f.file_path)) {
          seen.set(f.file_path, { file: f, scan_id: sc.scan_id, pr_number: sc.pr_number });
        }
      }
    }
    const RISK_ORDER: RiskLevel[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];
    return Array.from(seen.values()).sort((a, b) =>
      RISK_ORDER.indexOf(a.file.risk_score) - RISK_ORDER.indexOf(b.file.risk_score)
    );
  })();

  return (
    <AuthGuard>
      <div className="max-w-5xl mx-auto space-y-5 pb-10">

        {/* Header */}
        <div className="animate-fade-up flex items-start justify-between gap-4">
          <div>
            <Link
              href="/dashboard"
              className="inline-flex items-center gap-1 text-xs text-gray-400 hover:text-indigo-600 mb-2 transition-colors"
            >
              <BackIcon /> Back to dashboard
            </Link>
            <h1 className="text-xl font-extrabold text-gray-900 tracking-tight">{repoShort}</h1>
            <p className="text-xs text-gray-400 mt-0.5 font-mono">{org}</p>
            {offline && (
              <span className="inline-flex items-center gap-1 text-[10px] font-semibold text-amber-700 bg-amber-50 border border-amber-200 px-2 py-0.5 rounded-full mt-1.5">
                <svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                  <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
                </svg>
                Showing local data · API offline
              </span>
            )}
          </div>
          <div className="flex items-center gap-2 shrink-0">
            {[
              { label: "Scans",    value: scans.length,  cls: "bg-indigo-50 text-indigo-700"  },
              { label: "Critical", value: critCount,     cls: "bg-violet-50 text-violet-700"  },
              { label: "High",     value: highCount,     cls: "bg-orange-50 text-orange-700"  },
            ].map(s => (
              <div key={s.label} className={`rounded-xl px-3.5 py-2 text-center border border-transparent ${s.cls}`}>
                <p className="text-xl font-black leading-none">{s.value}</p>
                <p className="text-[10px] font-semibold mt-0.5 opacity-70">{s.label}</p>
              </div>
            ))}
          </div>
        </div>

        {/* Stats bar */}
        {scans.length > 0 && (
          <div className="animate-fade-up section-card p-4 flex items-center gap-6 flex-wrap">
            <div className="flex-1 min-w-[180px]">
              <p className="text-[10px] font-bold uppercase tracking-wider text-gray-400 mb-1.5">Avg AI Content</p>
              <ProgressBar value={avgAi} mode="ai" height="h-2" />
            </div>
            <div>
              <p className="text-[10px] font-bold uppercase tracking-wider text-gray-400 mb-1">Scan frequency</p>
              <p className="text-sm font-bold text-gray-800">
                {scans.length} scan{scans.length !== 1 ? "s" : ""} total
              </p>
            </div>
            <div>
              <p className="text-[10px] font-bold uppercase tracking-wider text-gray-400 mb-1">Latest</p>
              <p className="text-sm font-semibold text-gray-700">{relDate(scans[0]?.timestamp ?? "")}</p>
            </div>
          </div>
        )}

        {/* Scan history */}
        <div className="animate-fade-up section-card">
          <div className="px-5 py-4 border-b border-gray-100">
            <p className="font-bold text-gray-900 text-sm">Scan History</p>
            <p className="text-xs text-gray-400 mt-0.5">All scans for this repository, newest first</p>
          </div>

          {loading ? (
            <div className="p-5 space-y-3">
              {[0, 1, 2].map(i => (
                <div key={i} className="h-16 bg-gray-100 rounded-lg animate-pulse" />
              ))}
            </div>
          ) : scans.length === 0 ? (
            <div className="py-12 text-center">
              <p className="text-sm text-gray-500 font-semibold">No scans found for this repo</p>
              <p className="text-xs text-gray-400 mt-1">Submit a scan via the API or dashboard form</p>
            </div>
          ) : (
            <div className="divide-y divide-gray-50">
              {scans.map((sc, idx) => {
                const fileCount    = sc.file_count ?? sc.files.length;
                const attestedCount = sc.attested_count ?? sc.files.filter(f => f.attested).length;
                const attPct       = fileCount > 0 ? Math.round((attestedCount / fileCount) * 100) : 0;
                const attColor     = attPct === 100 ? "#10b981" : attPct >= 50 ? "#f59e0b" : "#ef4444";
                const riskAccent   = sc.overall_risk === "CRITICAL" ? "#7c3aed"
                  : sc.overall_risk === "HIGH"     ? "#f97316"
                  : sc.overall_risk === "MEDIUM"   ? "#f59e0b" : "#10b981";
                const isLatest     = idx === 0;
                const absDate      = sc.timestamp ? new Date(sc.timestamp).toLocaleString("en-GB", { day:"numeric", month:"short", year:"numeric", hour:"2-digit", minute:"2-digit" }) : "—";
                const triggerLabel = sc.triggered_by === "webhook" || sc.triggered_by === "github-app" ? "GitHub" : sc.triggered_by === "scheduled" ? "Scheduled" : "API";
                const triggerColor = triggerLabel === "GitHub" ? "text-violet-600 bg-violet-50 border-violet-200"
                  : triggerLabel === "Scheduled" ? "text-sky-600 bg-sky-50 border-sky-200"
                  : "text-gray-500 bg-gray-50 border-gray-200";

                return (
                  <div key={sc.scan_id} className="group hover:bg-gray-50/60 transition-colors"
                    style={{ borderLeft: `3px solid ${riskAccent}` }}>
                    <div className="flex items-center gap-4 px-5 py-3.5 flex-wrap">

                      {/* PR + branch */}
                      <div className="min-w-[120px]">
                        <div className="flex items-center gap-1.5">
                          <span className="text-sm font-extrabold text-indigo-600">#{sc.pr_number}</span>
                          {isLatest && (
                            <span className="text-[9px] font-bold text-emerald-700 bg-emerald-100 border border-emerald-200 px-1.5 py-0.5 rounded-full leading-none">
                              LATEST
                            </span>
                          )}
                        </div>
                        {sc.branch && (
                          <div className="flex items-center gap-1 mt-0.5 text-[10px] text-gray-400 font-mono">
                            <BranchIcon />
                            <span className="truncate max-w-[100px]">{sc.branch}</span>
                          </div>
                        )}
                      </div>

                      {/* Commit */}
                      <div className="shrink-0">
                        <span className="font-mono text-[12px] text-gray-700 bg-gray-100 px-2 py-1 rounded-md font-bold tracking-tight">
                          {sc.commit_sha.slice(0, 9)}
                        </span>
                      </div>

                      {/* Risk */}
                      <div className="shrink-0">
                        <RiskBadge level={sc.overall_risk as RiskLevel} />
                      </div>

                      {/* Files + attested */}
                      <div className="shrink-0 min-w-[90px]">
                        <div className="flex items-center gap-1.5">
                          <div className="w-16 h-1.5 rounded-full overflow-hidden bg-gray-100">
                            <div className="h-full rounded-full transition-all" style={{ width: `${attPct}%`, background: attColor }} />
                          </div>
                          <span className="text-[11px] font-bold tabular-nums" style={{ color: attColor }}>
                            {attestedCount}/{fileCount}
                          </span>
                        </div>
                        <p className="text-[9px] text-gray-400 mt-0.5">attested</p>
                      </div>

                      {/* AI% */}
                      <div className="shrink-0 min-w-[100px]">
                        <ProgressBar value={sc.total_ai_percentage} mode="ai" />
                        <p className="text-[9px] text-gray-400 mt-0.5">avg AI%</p>
                      </div>

                      {/* Trigger source */}
                      <div className="shrink-0">
                        <span className={`inline-flex items-center gap-1 text-[10px] font-semibold px-2 py-0.5 rounded-full border ${triggerColor}`}>
                          {triggerLabel === "GitHub" && <WebhookIcon />}
                          {triggerLabel}
                        </span>
                      </div>

                      {/* Date */}
                      <div className="shrink-0 ml-auto text-right">
                        <p className="text-xs font-semibold text-gray-600">{relDate(sc.timestamp)}</p>
                        <p className="text-[10px] text-gray-400 mt-0.5">{absDate}</p>
                      </div>

                      {/* View link */}
                      <Link
                        href={`/pr/${sc.scan_id}`}
                        className="shrink-0 inline-flex items-center gap-1 text-[11px] font-bold text-indigo-600 hover:text-indigo-800 opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap"
                      >
                        View →
                      </Link>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Files at Risk */}
        {allFiles.length > 0 && (
          <div className="animate-fade-up section-card">
            <div className="px-5 py-4 border-b border-gray-100 flex items-center justify-between">
              <div>
                <p className="font-bold text-gray-900 text-sm">Files at Risk</p>
                <p className="text-xs text-gray-400 mt-0.5">{allFiles.length} file{allFiles.length !== 1 ? "s" : ""} across all scans, sorted by risk</p>
              </div>
              <div className="flex items-center gap-2 text-[10px] font-semibold">
                {(["CRITICAL","HIGH","MEDIUM","LOW"] as RiskLevel[]).map(r => {
                  const count = allFiles.filter(e => e.file.risk_score === r).length;
                  if (!count) return null;
                  const color = r === "CRITICAL" ? "#7c3aed" : r === "HIGH" ? "#f97316" : r === "MEDIUM" ? "#f59e0b" : "#10b981";
                  return (
                    <span key={r} className="px-2 py-0.5 rounded-full" style={{ background: `${color}18`, color, border: `1px solid ${color}30` }}>
                      {count} {r.toLowerCase()}
                    </span>
                  );
                })}
              </div>
            </div>
            <div className="divide-y divide-gray-50">
              {allFiles.map(({ file: f, scan_id, pr_number }) => {
                const accent = f.risk_score === "CRITICAL" ? "#7c3aed" : f.risk_score === "HIGH" ? "#f97316" : f.risk_score === "MEDIUM" ? "#f59e0b" : "#10b981";
                const fileShort = f.file_path.split("/").pop() ?? f.file_path;
                const fileDir   = f.file_path.includes("/") ? f.file_path.split("/").slice(0, -1).join("/") + "/" : "";
                const aiPct     = Math.round(f.ai_percentage * 100);
                const aiColor   = f.ai_percentage > 0.7 ? "#ef4444" : f.ai_percentage > 0.4 ? "#f59e0b" : "#10b981";
                return (
                  <div key={f.file_path} className="flex items-center gap-3 px-5 py-3 hover:bg-gray-50/60 transition-colors group"
                    style={{ background: f.attested ? "rgba(240,253,244,0.4)" : undefined }}>
                    {/* Risk accent bar */}
                    <div className="w-1 self-stretch rounded-full shrink-0" style={{ background: f.attested ? "#10b981" : accent, minHeight: "32px" }} />

                    {/* File info */}
                    <div className="flex-1 min-w-0">
                      {fileDir && <span className="text-[10px] text-gray-400 font-mono block truncate leading-none mb-0.5">{fileDir}</span>}
                      <span className={`font-mono text-[13px] font-bold block truncate ${f.attested ? "text-gray-400" : "text-gray-800"}`}>
                        {fileShort}
                      </span>
                    </div>

                    {/* Risk badge */}
                    <RiskBadge level={f.risk_score as RiskLevel} />

                    {/* AI% bar */}
                    <div className="shrink-0 w-[80px] flex flex-col gap-0.5">
                      <div className="flex items-center justify-between">
                        <span className="text-[9px] text-gray-400">AI</span>
                        <span className="text-[11px] tabular-nums font-bold" style={{ color: aiColor }}>{aiPct}%</span>
                      </div>
                      <div className="h-1.5 rounded-full overflow-hidden bg-gray-100">
                        <div className="h-full rounded-full" style={{ width: `${aiPct}%`, background: aiColor }} />
                      </div>
                    </div>

                    {/* Attestation */}
                    <div className="shrink-0 w-20 text-center">
                      {f.attested ? (
                        <span className="inline-flex items-center gap-1 text-[10px] font-bold text-emerald-700 bg-emerald-50 border border-emerald-200 px-2 py-0.5 rounded-full">
                          <svg width="8" height="8" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
                          Attested
                        </span>
                      ) : (
                        <span className="text-[10px] font-semibold text-rose-600 bg-rose-50 border border-rose-100 px-2 py-0.5 rounded-full">
                          Needs review
                        </span>
                      )}
                    </div>

                    {/* PR link */}
                    {pr_number && (
                      <Link href={`/pr/${scan_id}`}
                        className="shrink-0 text-[11px] font-bold text-indigo-600 hover:text-indigo-800 opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap">
                        PR #{pr_number} →
                      </Link>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}

      </div>
    </AuthGuard>
  );
}
