"use client";

/**
 * The review queue: HIGH/CRITICAL files with no sign-off yet, worst first -- past-deadline files, then CRITICAL,
 * then the most AI-written. Each row opens the file on its PR page, where the reviewer reads the code before signing.
 * "View all" expands the full queue here (the violations list is a different, broader view).
 */
import { useState } from "react";
import Link from "next/link";
import { fileReviewHref } from "@/lib/reviewLinks";
import type { DashboardData, TopRiskFile } from "@/types";

export interface QueueItem extends TopRiskFile { overdueHours: number | null }

/** `inReview` marks files someone has already picked up (left out: they aren't waiting for a reviewer). */
export function buildQueue(data: Pick<DashboardData, "top_risk_files" | "sla_breach_files">, now = Date.now(), inReview: (f: TopRiskFile) => boolean = () => false): QueueItem[] {
  const deadline = new Map((data.sla_breach_files ?? []).map(b => [`${b.scan_id}::${b.file_path}`, b.sla_deadline]));
  return data.top_risk_files
    .filter(f => !f.attested && (f.risk_score === "CRITICAL" || f.risk_score === "HIGH") && !inReview(f))
    .map(f => {
      const d = deadline.get(`${f.scan_id}::${f.file_path}`);
      return { ...f, overdueHours: d ? Math.max(0, Math.floor((now - Date.parse(d)) / 3600_000)) : null };
    })
    .sort((a, b) =>
      (a.overdueHours == null ? 1 : 0) - (b.overdueHours == null ? 1 : 0)
      || (a.risk_score === "CRITICAL" ? 0 : 1) - (b.risk_score === "CRITICAL" ? 0 : 1)
      || b.ai_pct - a.ai_pct);
}

function overdueLabel(h: number) {
  return h >= 48 ? `${Math.floor(h / 24)}d overdue` : `${h}h overdue`;
}

export default function ReviewQueue({ items, limit = 6, canAttestRisk }: {
  items: readonly QueueItem[]; limit?: number;
  /** Whether the viewer may sign off a file of this risk; if not, the row opens the file rather than its sign-off. */
  canAttestRisk?: (risk: string) => boolean;
}) {
  const [expanded, setExpanded] = useState(false);
  const shown = expanded ? items : items.slice(0, limit);
  const hidden = items.length - shown.length;
  return (
    <section id="review-queue" aria-label="Review queue" className="section-card flex flex-col h-full scroll-mt-6">
      <div className="flex items-center justify-between gap-3 px-6 pt-5 pb-4 border-b border-gray-100">
        <div>
          <h2 className="text-sm font-bold text-gray-900">Review queue</h2>
          <p className="text-xs text-gray-400 mt-0.5">
            {items.length ? `${items.length} high-risk file${items.length === 1 ? "" : "s"} waiting for a reviewer` : "Nothing waiting for review"}
          </p>
        </div>
        {items.length > limit && (
          <button onClick={() => setExpanded(e => !e)} aria-expanded={expanded}
            className="text-xs font-semibold text-indigo-600 hover:text-indigo-800 whitespace-nowrap">
            {expanded ? "Show less" : `View all ${items.length}`}
          </button>
        )}
      </div>
      {shown.length === 0 ? (
        <div className="flex-1 flex flex-col items-center justify-center gap-2 py-10 text-center px-6">
          <span className="w-10 h-10 rounded-2xl bg-emerald-50 text-emerald-500 flex items-center justify-center">
            <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12" /></svg>
          </span>
          <p className="text-sm font-bold text-gray-700">All high-risk files are signed off</p>
          <p className="text-xs text-gray-400">New ones appear here as pull requests are scanned.</p>
        </div>
      ) : (
        <ul className="divide-y divide-gray-50 flex-1">
          {shown.map(f => {
            const name = f.file_path.split("/").pop() ?? f.file_path;
            const crit = f.risk_score === "CRITICAL";
            return (
              <li key={`${f.scan_id}::${f.file_path}`}>
                <Link href={fileReviewHref(f.scan_id, f.file_path, canAttestRisk ? canAttestRisk(f.risk_score) : true)}
                  title={f.file_path}
                  className="flex items-start gap-3 px-6 py-3.5 hover:bg-gray-50/70 transition-colors">
                  <span className={`mt-0.5 text-[9px] font-black px-1.5 py-0.5 rounded shrink-0 ${crit ? "bg-violet-100 text-violet-700" : "bg-orange-100 text-orange-700"}`}>
                    {crit ? "CRIT" : "HIGH"}
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className="block text-xs font-semibold font-mono text-gray-800 break-all leading-snug">{name}</span>
                    <span className="block text-[11px] text-gray-500 leading-snug mt-0.5">
                      {f.repo.split("/").pop()}{f.pr_number > 0 ? ` · PR #${f.pr_number}` : ""} · {Math.round(f.ai_pct * 100)}% AI
                    </span>
                  </span>
                  {f.overdueHours != null
                    ? <span className="mt-0.5 text-[10px] font-bold text-rose-600 bg-rose-50 px-1.5 py-0.5 rounded shrink-0 whitespace-nowrap">{overdueLabel(f.overdueHours)}</span>
                    : <span className="mt-0.5 text-[11px] font-semibold text-indigo-600 shrink-0">Review</span>}
                </Link>
              </li>
            );
          })}
        </ul>
      )}
      {hidden > 0 && (
        <button onClick={() => setExpanded(true)}
          className="w-full px-6 py-3 border-t border-gray-100 text-[11px] font-semibold text-indigo-600 hover:bg-indigo-50/40 text-left">
          +{hidden} more waiting
        </button>
      )}
    </section>
  );
}
