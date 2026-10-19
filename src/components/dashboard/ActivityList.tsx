"use client";

/** Recent scans and sign-offs (lib/dashboardActivity.ts -- real events only), newest first. */
import Link from "next/link";
import type { ActivityEvent } from "@/types";

function when(iso: string) {
  const m = Math.floor((Date.now() - new Date(iso).getTime()) / 60000);
  if (m < 60) return m <= 1 ? "just now" : `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  return d === 1 ? "yesterday" : `${d}d ago`;
}

export default function ActivityList({ events, limit = 8 }: { events: readonly ActivityEvent[]; limit?: number }) {
  const shown = events.slice(0, limit);
  return (
    <section aria-label="Recent activity" className="section-card flex flex-col min-w-0">
      <div className="flex items-center justify-between px-5 pt-4 pb-3 border-b border-gray-100">
        <h2 className="text-sm font-bold text-gray-900">Recent activity</h2>
        <Link href="/audit" className="text-xs font-semibold text-indigo-600 hover:text-indigo-800">Audit trail →</Link>
      </div>
      {shown.length === 0 ? (
        <p className="px-5 py-10 text-center text-xs text-gray-400">Scans and sign-offs will appear here.</p>
      ) : (
        <ol className="relative px-5 py-3 space-y-3">
          <span className="absolute left-[29px] top-5 bottom-5 w-px bg-gray-100" aria-hidden="true" />
          {shown.map((e, i) => {
            const scan = e.type === "scan";
            return (
              <li key={`${e.type}-${e.scan_id}-${e.file_path}-${e.timestamp}-${i}`} className="relative flex items-start gap-3">
                <span className={`relative z-10 mt-0.5 w-[18px] h-[18px] rounded-full flex items-center justify-center ring-4 ring-white shrink-0 ${scan ? "bg-indigo-100 text-indigo-600" : "bg-emerald-100 text-emerald-600"}`}>
                  {scan
                    ? <svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round"><circle cx="11" cy="11" r="7" /><line x1="21" y1="21" x2="16.65" y2="16.65" /></svg>
                    : <svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12" /></svg>}
                </span>
                <div className="min-w-0 flex-1">
                  <Link href={`/pr/${e.scan_id}`} className="block text-xs font-semibold text-gray-800 hover:text-indigo-600 break-words leading-snug">
                    {scan ? `Scanned ${e.repo.split("/").pop()}` : `Signed off ${e.file_path.split("/").pop()}`}
                  </Link>
                  <p className="text-[11px] text-gray-500 break-words leading-snug">
                    {scan ? `${Math.round(e.total_ai_pct * 100)}% AI content` : `${e.repo.split("/").pop()}${e.pr_number > 0 ? ` · PR #${e.pr_number}` : ""}${e.reviewer_email ? ` · ${e.reviewer_email}` : ""}`}
                  </p>
                </div>
                <span className="text-[10px] text-gray-400 tabular-nums shrink-0">{when(e.timestamp)}</span>
              </li>
            );
          })}
        </ol>
      )}
    </section>
  );
}
