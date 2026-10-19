"use client";

/**
 * Repositories at a glance: each repo's Trust Score (when the server score is loaded), open CRITICAL/HIGH files,
 * review coverage, AI content and scan freshness. Searchable and sortable; worst first by default.
 */
import { useMemo, useState } from "react";
import Link from "next/link";
import type { RepoStat } from "@/types";
import type { RepoScore } from "@/lib/governanceScore";
import { repoHref } from "./NeedsAttention";

export interface RepoRow {
  repo: string;
  score: number | null;
  openCritical: number | null;
  openHigh: number | null;
  /** CRITICAL+HIGH files in the latest scan (dashboard payload) when the per-repo score isn't loaded. */
  highCrit: number;
  review: number;
  ai: number;
  scans: number;
  lastScan: string | null;
  latestScanId: string;
}

export function buildRepoRows(repos: readonly RepoStat[], scores: readonly RepoScore[] | null): RepoRow[] {
  const byRepo = new Map((scores ?? []).map(s => [s.repo, s]));
  return repos.map(r => {
    const s = byRepo.get(r.repo);
    return {
      repo: r.repo,
      score: s ? s.score : null,
      openCritical: s ? s.open_critical : null,
      openHigh: s ? s.open_high : null,
      highCrit: r.high_crit_count ?? 0,
      review: r.attestation_rate,
      ai: r.ai_pct,
      scans: r.scan_count,
      lastScan: r.last_scan || null,
      latestScanId: r.latest_scan_id,
    };
  });
}

type SortKey = "risk" | "score" | "review" | "ai" | "recent";
const openRisk = (r: RepoRow) => r.openCritical != null ? r.openCritical * 10 + (r.openHigh ?? 0) : r.highCrit;

export function sortRepoRows(rows: readonly RepoRow[], key: SortKey): RepoRow[] {
  const cmp: Record<SortKey, (a: RepoRow, b: RepoRow) => number> = {
    risk:   (a, b) => openRisk(b) - openRisk(a) || a.review - b.review,
    score:  (a, b) => (a.score ?? 1001) - (b.score ?? 1001),
    review: (a, b) => a.review - b.review,
    ai:     (a, b) => b.ai - a.ai,
    recent: (a, b) => (b.lastScan ?? "").localeCompare(a.lastScan ?? ""),
  };
  return [...rows].sort(cmp[key]);
}

function ago(iso: string | null) {
  if (!iso) return "never";
  const d = Math.floor((Date.now() - new Date(iso).getTime()) / 86400000);
  return d <= 0 ? "today" : d === 1 ? "yesterday" : d < 30 ? `${d}d ago` : `${Math.floor(d / 30)}mo ago`;
}
const scoreTone = (s: number) => s >= 850 ? "bg-emerald-500" : s >= 700 ? "bg-green-500" : s >= 550 ? "bg-amber-400" : s >= 400 ? "bg-orange-500" : "bg-rose-500";

export default function RepoTable({ rows, onExport }: { rows: readonly RepoRow[]; onExport?: () => void }) {
  const [q, setQ] = useState("");
  const [sort, setSort] = useState<SortKey>("risk");
  const [limit, setLimit] = useState(8);
  const filtered = useMemo(
    () => sortRepoRows(rows.filter(r => !q || r.repo.toLowerCase().includes(q.toLowerCase())), sort),
    [rows, q, sort]);
  const shown = filtered.slice(0, limit);
  const hasScores = rows.some(r => r.score != null);

  return (
    <section id="repositories" aria-label="Repositories" className="section-card overflow-hidden min-w-0 scroll-mt-6">
      <div className="flex flex-wrap items-center justify-between gap-3 px-6 pt-5 pb-4 border-b border-gray-100">
        <div>
          <h2 className="text-sm font-bold text-gray-900">Repositories</h2>
          <p className="text-xs text-gray-400 mt-0.5">{rows.length} with scans in this period</p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <input value={q} onChange={e => setQ(e.target.value)} placeholder="Search repos" aria-label="Search repositories"
            className="w-36 sm:w-44 text-xs border border-gray-200 rounded-lg px-2.5 py-1.5 focus:outline-none focus:ring-2 focus:ring-indigo-300" />
          <select value={sort} onChange={e => setSort(e.target.value as SortKey)} aria-label="Sort repositories"
            className="text-xs border border-gray-200 rounded-lg px-2 py-1.5 bg-white text-gray-600 focus:outline-none">
            <option value="risk">Most open risk</option>
            {hasScores && <option value="score">Lowest Trust Score</option>}
            <option value="review">Least reviewed</option>
            <option value="ai">Most AI content</option>
            <option value="recent">Recently scanned</option>
          </select>
          {onExport && (
            <button onClick={onExport} className="text-xs font-semibold text-gray-600 border border-gray-200 rounded-lg px-2.5 py-1.5 hover:bg-gray-50">CSV</button>
          )}
        </div>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full min-w-[640px]">
          <thead>
            <tr className="text-left text-[10px] font-bold uppercase tracking-wider text-gray-400 border-b border-gray-100">
              <th className="px-6 py-3">Repository</th>
              {hasScores && <th className="px-4 py-3">Trust Score</th>}
              <th className="px-4 py-3">Open high-risk</th>
              <th className="px-4 py-3">Reviewed</th>
              <th className="px-4 py-3">AI content</th>
              <th className="px-3 py-2.5 text-right pr-5">Last scan</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-50">
            {shown.map(r => {
              const risky = r.openCritical != null ? r.openCritical + (r.openHigh ?? 0) : r.highCrit;
              return (
                <tr key={r.repo} className="hover:bg-gray-50/60">
                  <td className="px-6 py-3.5 min-w-[160px]">
                    <Link href={repoHref(r.repo)} title={r.repo} className="block text-xs font-bold text-gray-800 hover:text-indigo-600 break-words leading-snug">{r.repo.split("/").pop()}</Link>
                    <span className="block text-[11px] text-gray-500 break-words">{r.repo.split("/")[0]} · {r.scans} scan{r.scans === 1 ? "" : "s"}</span>
                  </td>
                  {hasScores && (
                    <td className="px-4 py-3.5">
                      {r.score == null ? <span className="text-xs text-gray-300">—</span> : (
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-black tabular-nums text-gray-900 w-8">{r.score}</span>
                          <span className="w-14 h-1.5 rounded-full bg-gray-100 overflow-hidden"><span className={`block h-full ${scoreTone(r.score)}`} style={{ width: `${r.score / 10}%` }} /></span>
                        </div>
                      )}
                    </td>
                  )}
                  <td className="px-4 py-3.5">
                    {risky === 0 ? <span className="text-xs text-emerald-600 font-semibold">None</span> : (
                      <span className="text-xs font-bold text-gray-800 tabular-nums">
                        {r.openCritical != null && r.openCritical > 0 && <span className="text-violet-700">{r.openCritical} crit · </span>}{r.openCritical != null ? `${r.openHigh ?? 0} high` : risky}
                      </span>
                    )}
                  </td>
                  <td className="px-4 py-3.5">
                    <div className="flex items-center gap-2">
                      <span className="w-14 h-1.5 rounded-full bg-gray-100 overflow-hidden">
                        <span className={`block h-full ${r.review >= 0.9 ? "bg-emerald-500" : r.review >= 0.5 ? "bg-amber-400" : "bg-rose-500"}`} style={{ width: `${Math.round(r.review * 100)}%` }} />
                      </span>
                      <span className="text-xs tabular-nums text-gray-600">{Math.round(r.review * 100)}%</span>
                    </div>
                  </td>
                  <td className="px-4 py-3.5 text-xs tabular-nums text-gray-600">{Math.round(r.ai * 100)}%</td>
                  <td className="px-4 py-3.5 pr-6 text-right">
                    {r.latestScanId
                      ? <Link href={`/pr/${r.latestScanId}`} className="text-xs text-gray-500 hover:text-indigo-600">{ago(r.lastScan)}</Link>
                      : <span className="text-xs text-gray-400">{ago(r.lastScan)}</span>}
                  </td>
                </tr>
              );
            })}
            {shown.length === 0 && (
              <tr><td colSpan={6} className="px-5 py-8 text-center text-xs text-gray-400">No repositories match “{q}”.</td></tr>
            )}
          </tbody>
        </table>
      </div>
      {filtered.length > limit && (
        <button onClick={() => setLimit(l => l + 12)} className="w-full py-3 text-xs font-semibold text-indigo-600 hover:bg-indigo-50/50 border-t border-gray-100">
          Show more ({filtered.length - limit} more)
        </button>
      )}
    </section>
  );
}
