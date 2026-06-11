"use client";

import { useState, useCallback, useMemo } from "react";
// localAttested is read-only here — attestation is enforced on the PR review page
import Link from "next/link";
import RiskBadge from "@/components/RiskBadge";
import type { TopRiskFile } from "@/types";

const riskPfx = (r: string) =>
  r === "CRITICAL" ? "crit" : r === "HIGH" ? "high" : r === "MEDIUM" ? "med" : "low";

function loadLocalAttested(): Set<string> {
  try {
    const s = JSON.parse(localStorage.getItem("tl_violation_statuses") ?? "{}") as Record<string, string>;
    return new Set(Object.entries(s).filter(([, v]) => v === "resolved").map(([k]) => k));
  } catch { return new Set(); }
}

const RISK_ACCENT: Record<string, string> = {
  CRITICAL: "#7c3aed",
  HIGH: "#f97316",
  MEDIUM: "#f59e0b",
  LOW: "#10b981",
};

export default function TopRiskFilesPanel({ files }: { files: TopRiskFile[] }) {
  const [localAttested] = useState<Set<string>>(() => loadLocalAttested());

  const isAttested = useCallback((f: TopRiskFile) =>
    f.attested || localAttested.has(`${riskPfx(f.risk_score)}::${f.scan_id}::${f.file_path}`),
    [localAttested]
  );

  const enriched = useMemo(() => files.map(f => ({
    ...f,
    repoName: f.repo.split("/").pop() ?? f.repo,
    fileShort: f.file_path.split("/").pop() ?? f.file_path,
    fileDir: f.file_path.includes("/") ? f.file_path.split("/").slice(0, -1).join("/") + "/" : "",
    aiPct: (f.ai_pct * 100).toFixed(1),
    aiBarColor:
      f.ai_pct > 0.7 ? "linear-gradient(90deg,#f87171,#ef4444)"
        : f.ai_pct > 0.4 ? "linear-gradient(90deg,#fbbf24,#f59e0b)"
          : "linear-gradient(90deg,#34d399,#10b981)",
  })), [files]);

  if (files.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-12 gap-3 text-center">
        <div className="w-12 h-12 rounded-2xl bg-emerald-50 flex items-center justify-center text-emerald-500"
          style={{ boxShadow: "0 4px 16px rgba(16,185,129,0.12)" }}>
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" /><polyline points="22 4 12 14.01 9 11.01" />
          </svg>
        </div>
        <p className="text-sm font-bold text-gray-700">No high-risk files</p>
        <p className="text-xs text-gray-400">All scanned files are LOW or MEDIUM risk</p>
      </div>
    );
  }

  return (
    <div className="w-full divide-y divide-gray-100">
      {enriched.map((f, i) => {
        const attested = isAttested(f);
        const accent = RISK_ACCENT[f.risk_score] ?? "#94a3b8";

        return (
          <div
            key={`${f.scan_id}::${f.file_path}`}
            className="flex items-center gap-3 px-4 py-3 transition-colors duration-150 group"
            style={{
              background: attested
                ? "rgba(240,253,244,0.6)"
                : i % 2 === 0 ? "white" : "rgba(249,250,251,0.6)",
            }}
            onMouseEnter={e => {
              (e.currentTarget as HTMLElement).style.background = attested
                ? "rgba(220,252,231,0.7)" : "rgba(238,242,255,0.4)";
            }}
            onMouseLeave={e => {
              (e.currentTarget as HTMLElement).style.background = attested
                ? "rgba(240,253,244,0.6)"
                : i % 2 === 0 ? "white" : "rgba(249,250,251,0.6)";
            }}
          >
            {/* Colored risk accent bar */}
            <div
              className="w-1 self-stretch rounded-full shrink-0"
              style={{ background: attested ? "#10b981" : accent, minHeight: "36px" }}
            />

            {/* Rank */}
            <span className="text-[11px] font-bold tabular-nums text-gray-300 shrink-0 w-5 text-right">
              {String(i + 1).padStart(2, "0")}
            </span>

            {/* Repo chip + filename */}
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-1.5 mb-0.5 flex-wrap">
                <span
                  className="text-[10px] font-semibold px-1.5 py-0.5 rounded-md border shrink-0"
                  style={{
                    color: attested ? "#059669" : "#6b7280",
                    background: attested ? "rgba(209,250,229,0.6)" : "rgba(243,244,246,0.8)",
                    borderColor: attested ? "rgba(167,243,208,0.8)" : "rgba(229,231,235,0.8)",
                  }}
                >
                  {f.repoName}
                </span>
                <RiskBadge level={f.risk_score} />
              </div>
              {f.fileDir && (
                <span className="text-[10px] text-gray-400 font-mono block truncate leading-none mb-0.5">
                  {f.fileDir}
                </span>
              )}
              <span className={`font-mono text-[13px] font-bold block truncate leading-tight ${attested ? "text-gray-400" : "text-gray-800"}`}>
                {f.fileShort}
              </span>
            </div>

            {/* AI % bar + label */}
            <div className="shrink-0 w-[72px] flex flex-col gap-1">
              <div className="flex items-center justify-between">
                <span className="text-[9px] text-gray-400 font-medium">AI</span>
                <span className="text-[11px] tabular-nums font-bold text-gray-600">{f.aiPct}%</span>
              </div>
              <div className="h-1.5 rounded-full overflow-hidden bg-gray-100">
                <div className="h-full rounded-full" style={{ width: `${f.ai_pct * 100}%`, background: f.aiBarColor }} />
              </div>
            </div>

            {/* Action */}
            <div className="shrink-0 flex items-center gap-1.5">
              {attested ? (
                <span className="inline-flex items-center gap-1 text-[11px] font-bold text-white bg-emerald-500 px-2.5 py-1 rounded-lg whitespace-nowrap">
                  <svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">
                    <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                    <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                  </svg>
                  Attested
                </span>
              ) : (
                <Link
                  href={`/pr/${f.scan_id}`}
                  className="inline-flex items-center gap-1 text-[11px] font-bold text-white bg-indigo-600 hover:bg-indigo-700 active:bg-indigo-800 px-2.5 py-1 rounded-lg transition-colors whitespace-nowrap shadow-sm"
                >
                  Review
                  <svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                    <line x1="5" y1="12" x2="19" y2="12" /><polyline points="12 5 19 12 12 19" />
                  </svg>
                </Link>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}
