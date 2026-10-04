"use client";

import { useState } from "react";
import Link from "next/link";
import { countOpenViolations } from "@/lib/violations";
import type { DashboardData } from "@/types";

function AlertIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
    </svg>
  );
}
function SLAIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>
    </svg>
  );
}

export type SlaCounts = { crit: number; high: number; total: number };

/**
 * One "Needs attention" panel: repos whose HIGH/CRITICAL files await sign-off (unattested_deploy_count counts repos), attestation SLA breaches, and the other open
 * queues (secrets, risky packages, violations). These used to be two stacked banners plus a chip row that
 * repeated the same counts three times.
 */
export default function AttentionPanel({ data, violationStatuses, openSecrets, unresolvedRepoScans, sla, showQueues }: {
  data: DashboardData; violationStatuses: Record<string, string>; openSecrets: number;
  unresolvedRepoScans: Array<{ repoName: string; scanId: string }>; sla: SlaCounts | null; showQueues: boolean;
}) {
  const [expanded, setExpanded] = useState(false);
  const deploys = data.unattested_deploy_count;
  const crit    = data.top_risk_files.filter(f => !f.attested && f.risk_score === "CRITICAL").length;
  const high    = data.top_risk_files.filter(f => !f.attested && f.risk_score === "HIGH").length;

  // Hallucinated/typosquatting packages — published by the /dependencies page (tl_dep_risky_count).
  const critDepCount = (() => {
    try {
      const count = parseInt(localStorage.getItem("tl_dep_risky_count") ?? "0", 10);
      return isNaN(count) ? 0 : count;
    } catch { return 0; }
  })();
  // Same count as /violations and the sidebar badge (src/lib/violations.ts).
  const violationsCount = countOpenViolations(data, violationStatuses);

  type Chip = { label: string; href: string; bg: string; text: string; border: string; dot: string };
  const chips: Chip[] = showQueues ? [
    ...(crit > 0            ? [{ label:`${crit} CRITICAL unattested`,    href:"/violations",   bg:"#ede9fe", text:"#5b21b6", border:"#c4b5fd", dot:"#7c3aed" }] : []),
    ...(high > 0            ? [{ label:`${high} HIGH unattested`,        href:"/violations",   bg:"#ffedd5", text:"#7c2d12", border:"#fed7aa", dot:"#f97316" }] : []),
    ...(openSecrets > 0     ? [{ label:`${openSecrets} open secrets`,    href:"/secrets",      bg:"#f3e8ff", text:"#6b21a8", border:"#ddd6fe", dot:"#9333ea" }] : []),
    ...(critDepCount > 0    ? [{ label:`${critDepCount} risky packages`, href:"/dependencies", bg:"#ede9fe", text:"#5b21b6", border:"#c4b5fd", dot:"#7c3aed" }] : []),
    ...(violationsCount > 0 ? [{ label:`${violationsCount} violations`,  href:"/violations",   bg:"#fef3c7", text:"#78350f", border:"#fde68a", dot:"#f59e0b" }] : []),
  ] : [];

  const breachFiles = data.sla_breach_files ?? [];
  const hasSla = !!sla && sla.total > 0;
  if (deploys === 0 && !hasSla && chips.length === 0) return null;

  const SHOW_INIT = 3;
  const visible = expanded ? breachFiles : breachFiles.slice(0, SHOW_INIT);
  const hidden  = breachFiles.length - SHOW_INIT;

  return (
    <section aria-label="Needs attention" className="animate-fade-up section-card overflow-hidden">
      {/* Header: what's open, at a glance */}
      <div className="px-4 sm:px-5 py-3 border-b border-gray-100 space-y-2">
        <div className="flex items-center justify-between gap-3">
          <p className="text-sm font-bold text-gray-900">Needs attention</p>
          <Link href="/alerts" className="text-xs font-bold text-indigo-600 hover:text-indigo-800 shrink-0">All alerts →</Link>
        </div>
        {chips.length > 0 && (
        <div className="flex items-center gap-1.5 flex-wrap">
          {chips.map(chip => (
            <Link key={chip.label} href={chip.href}
              className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[11px] font-bold border transition-all hover:-translate-y-px hover:shadow-sm"
              style={{ background: chip.bg, color: chip.text, borderColor: chip.border }}>
              <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: chip.dot }} />
              {chip.label}
            </Link>
          ))}
        </div>
        )}
      </div>

      {/* Repos waiting for sign-off */}
      {deploys > 0 && (
        <div className="flex items-start gap-3 px-4 sm:px-5 py-3 bg-rose-50/60 border-b border-rose-100 last:border-b-0">
          <div className="w-8 h-8 rounded-lg bg-rose-100 flex items-center justify-center text-rose-600 shrink-0"><AlertIcon /></div>
          <div className="flex-1 min-w-0">
            <p className="text-sm font-bold text-rose-800">{deploys} repo{deploys !== 1 ? "s" : ""} awaiting sign-off</p>
            <p className="text-xs text-rose-600 mt-0.5">The latest scan has HIGH or CRITICAL files no reviewer has attested yet; their pull requests stay held at the merge gate. Review and attest to clear.</p>
            {unresolvedRepoScans.length > 0 && (
              <div className="flex flex-wrap gap-1.5 mt-2">
                {unresolvedRepoScans.map(({ repoName, scanId }) => (
                  <Link key={scanId} href={`/pr/${scanId}`}
                    className="inline-flex items-center gap-1 px-2.5 py-1 text-[11px] font-bold text-rose-700 bg-white hover:bg-rose-100 rounded-lg border border-rose-200 transition-colors whitespace-nowrap">
                    {repoName} →
                  </Link>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Attestation SLA breaches */}
      {hasSla && (
        <div className="bg-amber-50/50">
          <div className="px-4 sm:px-5 py-3 space-y-1.5">
            <div className="flex items-center justify-between gap-3">
              <div className="flex items-center gap-2 text-amber-700"><SLAIcon /><p className="text-sm font-bold text-amber-800">Attestation SLA breached</p></div>
              <Link href="/sla" className="text-xs font-bold text-amber-700 hover:text-amber-900 whitespace-nowrap shrink-0">Full SLA dashboard →</Link>
            </div>
            <div className="flex items-center gap-2 flex-wrap">
              {sla!.crit > 0 && <span className="text-[11px] font-bold bg-violet-100 text-violet-800 px-2 py-0.5 rounded-full ring-1 ring-violet-200">{sla!.crit} CRITICAL · 24 h</span>}
              {sla!.high > 0 && <span className="text-[11px] font-bold bg-orange-100 text-orange-800 px-2 py-0.5 rounded-full ring-1 ring-orange-200">{sla!.high} HIGH · 72 h</span>}
              <span className="text-[11px] text-amber-700">{sla!.total} file{sla!.total !== 1 ? "s" : ""} missed the attestation deadline</span>
            </div>
          </div>
          {breachFiles.length > 0 && (
            <div className="divide-y divide-amber-100 border-t border-amber-100">
              {visible.map(f => {
                const hoursOverdue = f.sla_deadline ? Math.max(0, Math.round((Date.now() - new Date(f.sla_deadline).getTime()) / 3600000)) : null;
                const isCrit = f.risk_score === "CRITICAL";
                return (
                  <Link key={`${f.scan_id}::${f.file_path}`} href={`/pr/${f.scan_id}`}
                    className="flex items-center gap-3 px-4 sm:px-5 py-2.5 hover:bg-amber-100/60 transition-colors group">
                    <span className={`w-2 h-2 rounded-full shrink-0 ${isCrit ? "bg-violet-500" : "bg-orange-400"}`} />
                    <div className="flex-1 min-w-0">
                      <p className="text-xs font-semibold text-gray-800 truncate">{f.file_path.split("/").pop()}</p>
                      <p className="text-[10px] text-gray-400 truncate">{f.repo} · {f.file_path}</p>
                    </div>
                    <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full shrink-0 ${isCrit ? "bg-violet-100 text-violet-700" : "bg-orange-100 text-orange-700"}`}>{isCrit ? "CRITICAL" : "HIGH"}</span>
                    {hoursOverdue !== null && <span className="text-[10px] font-bold text-rose-600 bg-rose-50 px-2 py-0.5 rounded-full shrink-0 whitespace-nowrap">{hoursOverdue}h overdue</span>}
                  </Link>
                );
              })}
              {hidden > 0 && (
                <button onClick={() => setExpanded(e => !e)}
                  className="w-full px-4 sm:px-5 py-2 text-xs font-semibold text-amber-700 hover:bg-amber-100/60 transition-colors text-left">
                  {expanded ? "Show less ↑" : `Show ${hidden} more file${hidden !== 1 ? "s" : ""} →`}
                </button>
              )}
            </div>
          )}
        </div>
      )}
    </section>
  );
}

