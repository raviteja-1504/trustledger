"use client";

/**
 * The review queue: HIGH/CRITICAL files with no sign-off yet, worst first -- past-deadline files, then CRITICAL,
 * then the most AI-written. Each row opens the file on its PR page, where the reviewer reads the code before signing.
 */
import Link from "next/link";
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

export default function ReviewQueue({ items, limit = 6 }: { items: readonly QueueItem[]; limit?: number }) {
  const shown = items.slice(0, limit);
  return (
    <section aria-label="Review queue" className="section-card flex flex-col h-full">
      <div className="flex items-center justify-between gap-3 px-5 pt-4 pb-3 border-b border-gray-100">
        <div>
          <h2 className="text-sm font-bold text-gray-900">Review queue</h2>
          <p className="text-xs text-gray-400 mt-0.5">
            {items.length ? `${items.length} high-risk file${items.length === 1 ? "" : "s"} waiting for a reviewer` : "Nothing waiting for review"}
          </p>
        </div>
        {items.length > 0 && (
          <Link href="/violations" className="text-xs font-semibold text-indigo-600 hover:text-indigo-800 whitespace-nowrap">View all →</Link>
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
                <Link href={`/pr/${f.scan_id}?attest=${encodeURIComponent(f.file_path)}`}
                  className="flex items-center gap-3 px-5 py-2.5 hover:bg-gray-50/70 transition-colors">
                  <span className={`text-[9px] font-black px-1.5 py-0.5 rounded shrink-0 ${crit ? "bg-violet-100 text-violet-700" : "bg-orange-100 text-orange-700"}`}>
                    {crit ? "CRIT" : "HIGH"}
                  </span>
                  <span className="min-w-0 flex-1">
                    <span className="block text-xs font-semibold font-mono text-gray-800 truncate">{name}</span>
                    <span className="block text-[10px] text-gray-400 truncate">
                      {f.repo.split("/").pop()}{f.pr_number > 0 ? ` · PR #${f.pr_number}` : ""} · {Math.round(f.ai_pct * 100)}% AI
                    </span>
                  </span>
                  {f.overdueHours != null
                    ? <span className="text-[10px] font-bold text-rose-600 bg-rose-50 px-1.5 py-0.5 rounded shrink-0">{overdueLabel(f.overdueHours)}</span>
                    : <span className="text-[10px] font-semibold text-indigo-600 shrink-0">Review</span>}
                </Link>
              </li>
            );
          })}
        </ul>
      )}
      {items.length > limit && (
        <p className="px-5 py-2.5 border-t border-gray-100 text-[11px] text-gray-400">+{items.length - limit} more in Violations</p>
      )}
    </section>
  );
}
