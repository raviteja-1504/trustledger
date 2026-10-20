"use client";

/**
 * Report section 3a: every sign-off recorded in the report period (/api/attest GET, lib/attestationRecords.ts) --
 * WHEN it was signed, WHAT (repository, pull request, commit, file), WHY it needed a sign-off (risk level and the
 * findings behind it), and HOW (who signed, independent of the PR's author or not, time from scan to sign-off, and
 * the record's hash). These rows can't be edited or deleted, which is what makes them audit evidence.
 */
import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { authedFetch } from "@/lib/useRealData";
import type { AttestationRecord, AttestationRecordSummary } from "@/lib/attestationRecords";
import { LoadingBlock } from "@/components/Loading";

interface Response_ { records: AttestationRecord[]; summary: AttestationRecordSummary; period: { start: string; end: string }; scope: "org" | "own" }

const ROWS = 50;
const RISK_CLS: Record<string, string> = {
  CRITICAL: "bg-violet-100 text-violet-700", HIGH: "bg-orange-100 text-orange-700", MEDIUM: "bg-amber-100 text-amber-800", LOW: "bg-gray-100 text-gray-600",
};
const INDEP: Record<AttestationRecord["independence"], { label: string; cls: string; title: string }> = {
  independent: { label: "Independent", cls: "text-emerald-700 bg-emerald-50 border-emerald-200", title: "Signed off by someone other than the pull request's author" },
  self:        { label: "Self-approved", cls: "text-rose-700 bg-rose-50 border-rose-200", title: "The pull request's author signed off their own change" },
  unknown:     { label: "Author unknown", cls: "text-gray-500 bg-gray-50 border-gray-200", title: "No GitHub login recorded for the reviewer or the PR author, so independence can't be shown" },
};
const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;
const fmtDay = (iso: string) => new Date(iso).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric", timeZone: "UTC" });
const fmtTime = (iso: string) => new Date(iso).toLocaleString("en-GB", { day: "numeric", month: "short", year: "numeric", hour: "2-digit", minute: "2-digit", timeZone: "UTC" }) + " UTC";
export function fmtDuration(h: number | null): string {
  if (h == null) return "—";
  if (h < 1) return `${Math.max(1, Math.round(h * 60))} min`;
  if (h < 48) return `${Math.round(h)} h`;
  return `${Math.round(h / 24)} days`;
}

export default function PeriodAttestations({ start, end, color }: { start: string; end: string; color: string }) {
  const [data, setData] = useState<Response_ | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [repo, setRepo] = useState("all");
  const [showAll, setShowAll] = useState(false);

  useEffect(() => {
    let alive = true;
    setData(null); setError(null);
    authedFetch<Response_>(`/api/attest?since=${encodeURIComponent(start)}&until=${encodeURIComponent(end)}`)
      .then(r => { if (alive) setData(r); }, e => { if (alive) setError(e instanceof Error ? e.message : "Couldn't load sign-off records."); });
    return () => { alive = false; };
  }, [start, end]);

  const rows = useMemo(() => (data?.records ?? []).filter(r => repo === "all" || r.repo === repo), [data, repo]);
  const s = data?.summary;

  return (
    <div className="space-y-3">
      <div className="rounded-xl border border-gray-200 px-5 py-4 bg-gray-50/60">
        <p className="text-[10px] font-black uppercase tracking-widest text-gray-400">Why these records exist</p>
        <p className="text-xs text-gray-600 mt-1 leading-relaxed">
          Every HIGH or CRITICAL file must be reviewed and signed off by a named person before it merges (change-management
          evidence, e.g. SOC 2 CC8.1). Each sign-off is stored as a permanent record — it can&apos;t be edited or deleted — with a
          SHA-256 hash of the scan, file, reviewer and time, so it can be checked later.
        </p>
      </div>

      {error && <p role="alert" className="text-xs text-rose-600">Couldn&apos;t load sign-off records for this period. {error}</p>}
      {!data && !error && <LoadingBlock label="sign-off records" rows={2} />}

      {data && s && (
        <>
          <div aria-label="Sign-offs in this period" role="region" className="rounded-xl border border-gray-200 px-5 py-4">
            <p className="text-sm text-gray-800">
              <span className="font-black tabular-nums" style={{ color }}>{s.records}</span>{" "}
              sign-off record{s.records === 1 ? "" : "s"} from <strong>{fmtDay(data.period.start)}</strong> to <strong>{fmtDay(data.period.end)}</strong>
              {s.records > 0 && <> — {plural(s.files, "file")} in {plural(s.repos.length, "repository", "repositories")}, by {plural(s.reviewers.length, "reviewer")}</>}
              {data.scope === "own" && <span className="text-gray-500"> (your pull requests)</span>}
            </p>
            {s.records > 0 && (
              <div className="flex flex-wrap gap-x-5 gap-y-1 mt-2 text-xs text-gray-600">
                <span>First: <strong>{fmtTime(s.first!)}</strong></span>
                <span>Latest: <strong>{fmtTime(s.last!)}</strong></span>
                <span>Typical time from scan to sign-off: <strong>{fmtDuration(s.median_hours)}</strong></span>
                <span><span className="text-emerald-700 font-bold">{s.independent}</span> independent · <span className="text-rose-700 font-bold">{s.self}</span> self-approved · {s.unknown} unknown</span>
                <span>{Object.entries(s.by_risk).sort().map(([k, n]) => `${n} ${k.toLowerCase()}`).join(" · ")}</span>
              </div>
            )}
          </div>

          {s.records === 0 ? (
            <p className="rounded-xl border border-gray-200 py-8 text-center text-sm text-gray-500">No files were signed off in this period.</p>
          ) : (
            <div className="rounded-xl border border-gray-200 overflow-hidden">
              <div className="flex flex-wrap items-center justify-between gap-2 px-4 py-2.5 bg-gray-50 border-b border-gray-100">
                <p className="text-[10px] font-black uppercase tracking-widest text-gray-500">Sign-off records, newest first</p>
                {s.repos.length > 1 && (
                  <select aria-label="Repository" value={repo} onChange={e => setRepo(e.target.value)}
                    className="text-xs font-semibold text-gray-700 bg-white border border-gray-200 rounded-lg px-2 py-1">
                    <option value="all">All repositories ({s.repos.length})</option>
                    {s.repos.map(r => <option key={r} value={r}>{r}</option>)}
                  </select>
                )}
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="text-[9px] font-black uppercase tracking-widest text-gray-400 text-left">
                      <th className="px-4 py-2">When</th><th className="px-2 py-2">What</th><th className="px-2 py-2">Why</th>
                      <th className="px-2 py-2">Who &amp; how</th><th className="px-2 py-2 text-right">After scan</th><th className="px-4 py-2">Record</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(showAll ? rows : rows.slice(0, ROWS)).map(r => {
                      const ind = INDEP[r.independence];
                      return (
                        <tr key={r.id} className="border-t border-gray-50 align-top">
                          <td className="px-4 py-2.5 whitespace-nowrap text-gray-700">{fmtTime(r.signed_at)}{r.repeat && <p className="text-[10px] text-gray-400">additional sign-off</p>}</td>
                          <td className="px-2 py-2.5 min-w-[200px]">
                            <Link href={`/pr/${r.scan_id}`} className="font-mono font-semibold text-gray-900 hover:text-indigo-700 break-all">{r.file_path}</Link>
                            <p className="text-[10px] text-gray-500 mt-0.5">
                              {r.repo} · {r.pr_number > 0 ? `PR #${r.pr_number}` : "direct push"}{r.commit_sha ? ` · ${r.commit_sha.slice(0, 7)}` : ""}{r.branch ? ` · ${r.branch}` : ""}
                            </p>
                          </td>
                          <td className="px-2 py-2.5 min-w-[150px]">
                            <span className={`inline-block text-[10px] font-black px-1.5 py-0.5 rounded ${RISK_CLS[r.risk_score] ?? RISK_CLS.LOW}`}>{r.risk_score}</span>
                            {r.findings.length > 0 ? (
                              <div className="flex flex-wrap gap-1 mt-1">
                                {r.findings.slice(0, 3).map(f => <Link key={f} href={`/rules#${encodeURIComponent(f)}`} className="text-[10px] font-mono text-gray-600 bg-gray-100 hover:bg-indigo-50 px-1 rounded">{f}</Link>)}
                                {r.findings.length > 3 && <span className="text-[10px] text-gray-400">+{r.findings.length - 3}</span>}
                              </div>
                            ) : <p className="text-[10px] text-gray-400 mt-1">risk level from the scan</p>}
                          </td>
                          <td className="px-2 py-2.5 min-w-[160px]">
                            <p className="text-gray-800 font-medium break-all">{r.reviewer_email ?? r.reviewer_github ?? "unknown reviewer"}</p>
                            <span title={ind.title} className={`inline-block mt-1 text-[10px] font-bold px-1.5 py-0.5 rounded-full border ${ind.cls}`}>{ind.label}</span>
                            {r.pr_author && <p className="text-[10px] text-gray-400 mt-0.5">PR author: {r.pr_author}</p>}
                          </td>
                          <td className="px-2 py-2.5 text-right tabular-nums text-gray-700 whitespace-nowrap">{fmtDuration(r.hours_to_signoff)}</td>
                          <td className="px-4 py-2.5">
                            {r.payload_hash ? <code title={`SHA-256 ${r.payload_hash}`} className="text-[10px] font-mono text-gray-500">{r.payload_hash.slice(0, 12)}…</code> : <span className="text-gray-300">—</span>}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
              {rows.length > ROWS && (
                <button onClick={() => setShowAll(v => !v)} className="w-full py-2 text-xs font-semibold text-indigo-600 hover:bg-indigo-50 border-t border-gray-100">
                  {showAll ? "Show fewer" : `Show all ${rows.length} records`}
                </button>
              )}
            </div>
          )}
        </>
      )}
    </div>
  );
}
