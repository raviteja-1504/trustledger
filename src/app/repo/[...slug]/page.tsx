"use client";

/**
 * Repository detail, from real records only (/api/repos/summary, lib/repoSummary.ts): where the repository stands
 * now (the latest scan's files and their sign-off status), its pull requests, its full scan history and who has
 * been changing it. A failed load shows an error -- never placeholder scans or made-up commits.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import AuthGuard from "@/components/AuthGuard";
import RiskBadge from "@/components/RiskBadge";
import { authedFetch, isSeedMode } from "@/lib/useRealData";
import { relativeTime, formatDateTime, formatDateOnly, useTimezone } from "@/lib/timezone";
import { useAuth } from "@/lib/auth";
import { useScansRealtime } from "@/lib/realtime";
import type { RiskLevel } from "@/types";
import type { FileStatus, RepoFile, RepoSummary } from "@/lib/repoSummary";
import { LoadingBlock } from "@/components/Loading";

interface SummaryResponse extends RepoSummary {
  repo: { name: string; default_branch: string | null; is_active: boolean; connected_at: string | null };
  scope: "org" | "own";
  open_secrets: number;
}

const STATUS: Record<FileStatus, { label: string; cls: string }> = {
  attested:     { label: "Signed off",   cls: "text-emerald-700 bg-emerald-50 border-emerald-200" },
  resolved:     { label: "Resolved",     cls: "text-sky-700 bg-sky-50 border-sky-200" },
  in_review:    { label: "In review",    cls: "text-amber-700 bg-amber-50 border-amber-200" },
  waiting:      { label: "Needs sign-off", cls: "text-rose-700 bg-rose-50 border-rose-200" },
  not_required: { label: "No sign-off needed", cls: "text-gray-500 bg-gray-50 border-gray-200" },
};
const TRIGGER: Record<string, string> = { webhook: "GitHub", "github-app": "GitHub", manual: "Dashboard", scheduled: "Scheduled", api: "API" };
const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;
const pct = (x: number) => `${Math.round(x * 100)}%`;
const SCANS_SHOWN = 20;

function Stat({ label, value, sub, tone }: { label: string; value: string; sub: string; tone?: "good" | "warn" | "bad" }) {
  const c = tone === "bad" ? "text-rose-600" : tone === "warn" ? "text-amber-600" : tone === "good" ? "text-emerald-600" : "text-gray-900";
  return (
    <div className="section-card px-4 py-3.5">
      <p className="text-[10px] font-black uppercase tracking-widest text-gray-400">{label}</p>
      <p className={`text-2xl font-black tabular-nums mt-1 ${c}`}>{value}</p>
      <p className="text-[11px] text-gray-500 mt-0.5 leading-snug">{sub}</p>
    </div>
  );
}

export default function RepoDetailPage() {
  const { profile } = useAuth();
  const tz = useTimezone();
  const { slug } = (useParams<{ slug: string[] }>() ?? { slug: [] });
  const repo = Array.isArray(slug) ? slug.map(decodeURIComponent).join("/") : String(slug ?? "");
  const demo = isSeedMode() && !profile?.org_id;
  const [data, setData] = useState<SummaryResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [fileFilter, setFileFilter] = useState<"signoff" | "all">("signoff");
  const [showAllScans, setShowAllScans] = useState(false);

  const load = useCallback(async () => {
    if (demo || !repo) return;
    try {
      setData(await authedFetch<SummaryResponse>(`/api/repos/summary?repo=${encodeURIComponent(repo)}`));
      setError(null);
    } catch (e) { setError(e instanceof Error ? e.message : "Couldn't load this repository."); }
  }, [demo, repo]);

  useEffect(() => { load(); }, [load]);
  useScansRealtime(profile?.org_id, () => { load(); });
  useEffect(() => {
    const tick = () => { if (!document.hidden) load(); };
    window.addEventListener("focus", tick);
    window.addEventListener("tl:attestation", tick);
    window.addEventListener("tl:attest-complete", tick);
    return () => { window.removeEventListener("focus", tick); window.removeEventListener("tl:attestation", tick); window.removeEventListener("tl:attest-complete", tick); };
  }, [load]);

  const files = useMemo(() => (data?.files ?? []).filter(f => fileFilter === "all" || f.status !== "not_required"), [data, fileFilter]);
  const [owner, ...rest] = repo.split("/");
  const name = rest.join("/");

  return (
    <AuthGuard>
      <div className="max-w-6xl mx-auto space-y-5 pb-10">
        <header className="animate-fade-up flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0">
            <Link href="/dashboard#repositories" className="inline-flex items-center gap-1 text-xs text-gray-400 hover:text-indigo-600 mb-2">← Back to dashboard</Link>
            <h1 className="text-xl font-extrabold text-gray-900 tracking-tight break-all">{name || repo}</h1>
            <div className="flex flex-wrap items-center gap-2 mt-1 text-xs text-gray-500">
              <span className="font-mono">{owner}</span>
              {data?.repo.default_branch && <span>· default branch <span className="font-mono">{data.repo.default_branch}</span></span>}
              {data?.repo.connected_at && <span>· connected {formatDateOnly(data.repo.connected_at, tz)}</span>}
              {data && !data.repo.is_active && <span className="text-[10px] font-bold text-amber-700 bg-amber-50 border border-amber-200 px-2 py-0.5 rounded-full">Switched off — not counted on the dashboard</span>}
              {data?.scope === "own" && <span className="text-[10px] font-bold text-indigo-700 bg-indigo-50 border border-indigo-200 px-2 py-0.5 rounded-full">Your pull requests only</span>}
            </div>
          </div>
          <div className="flex items-center gap-2">
            <a href={`https://github.com/${repo}`} target="_blank" rel="noreferrer" className="px-3 py-2 text-xs font-semibold text-gray-700 bg-white border border-gray-200 rounded-xl hover:bg-gray-50">Open on GitHub ↗</a>
            <Link href={`/scans?repo=${encodeURIComponent(repo)}`} className="px-3 py-2 text-xs font-semibold text-indigo-700 bg-indigo-50 border border-indigo-100 rounded-xl hover:bg-indigo-100">Scan history →</Link>
          </div>
        </header>

        {demo && <div className="section-card p-6 text-sm text-gray-600">Repository detail is built from real scans. Connect a repository to see it.</div>}
        {error && (
          <div role="alert" className="flex items-center justify-between gap-3 bg-rose-50 border border-rose-200 text-rose-800 px-4 py-3 rounded-xl text-sm">
            <span>Couldn&apos;t load this repository. {error}</span>
            <button onClick={load} className="font-bold text-xs">Retry</button>
          </div>
        )}
        {!demo && !data && !error && <LoadingBlock label="this repository" rows={5} cards={4} />}

        {data && (
          <>
            <section aria-label="Repository summary" className="grid grid-cols-2 lg:grid-cols-5 gap-3">
              <Stat label="High-risk signed off" value={data.signoff.required ? `${data.signoff.attested + data.signoff.resolved}/${data.signoff.required}` : "—"}
                sub={data.signoff.required ? "HIGH/CRITICAL files in the latest scan" : "No HIGH/CRITICAL files in the latest scan"}
                tone={data.signoff.required === 0 ? "good" : data.signoff.waiting + data.signoff.in_review === 0 ? "good" : "warn"} />
              <Stat label="Waiting for sign-off" value={String(data.signoff.waiting + data.signoff.in_review)}
                sub={data.signoff.overdue ? `${data.signoff.overdue} past the fix deadline` : data.signoff.in_review ? `${data.signoff.in_review} in review` : "None overdue"}
                tone={data.signoff.overdue ? "bad" : data.signoff.waiting + data.signoff.in_review ? "warn" : "good"} />
              <Stat label="AI-written code" value={pct(data.stats.ai_share)} sub={`Across ${plural(data.stats.scans, "scan")}, weighted by files`} />
              <Stat label="Scans" value={String(data.stats.scans)}
                sub={data.stats.first_scan ? `Since ${formatDateOnly(data.stats.first_scan, tz)} · last ${relativeTime(data.stats.last_scan!, tz)}` : "Not scanned yet"} />
              <Stat label="Open secrets" value={String(data.open_secrets)} sub="In the latest scan" tone={data.open_secrets ? "bad" : "good"} />
            </section>

            {/* Current state */}
            <section aria-label="Current files" className="section-card overflow-hidden">
              <div className="px-5 py-4 border-b border-gray-100 flex flex-wrap items-start justify-between gap-3">
                <div>
                  <h2 className="font-bold text-gray-900 text-sm">Where it stands now</h2>
                  {data.latest_scan ? (
                    <p className="text-xs text-gray-500 mt-0.5">
                      Latest scan {relativeTime(data.latest_scan.created_at, tz)} · {data.latest_scan.pr_number > 0 ? `PR #${data.latest_scan.pr_number}` : "direct push"}
                      {data.latest_scan.branch ? <> on <span className="font-mono">{data.latest_scan.branch}</span></> : null} · commit <span className="font-mono">{data.latest_scan.commit_sha.slice(0, 9)}</span>
                      {" · "}<Link href={`/pr/${data.latest_scan.scan_id}`} className="text-indigo-600 hover:text-indigo-800 font-semibold">open scan →</Link>
                    </p>
                  ) : <p className="text-xs text-gray-500 mt-0.5">Not scanned yet.</p>}
                </div>
                <div className="flex gap-0.5 bg-gray-100 p-1 rounded-xl" role="group" aria-label="Files">
                  {([["signoff", "Need sign-off"], ["all", `All files (${data.files.length})`]] as const).map(([k, l]) => (
                    <button key={k} onClick={() => setFileFilter(k)} aria-pressed={fileFilter === k}
                      className={`px-3 py-1.5 text-xs font-semibold rounded-lg ${fileFilter === k ? "bg-white text-gray-900 shadow-sm" : "text-gray-500 hover:text-gray-700"}`}>{l}</button>
                  ))}
                </div>
              </div>
              {files.length === 0 ? (
                <p className="px-5 py-10 text-center text-sm text-gray-500">{data.latest_scan ? (fileFilter === "signoff" ? "No HIGH/CRITICAL files in the latest scan." : "The latest scan has no files.") : "—"}</p>
              ) : (
                <ul className="divide-y divide-gray-50">{files.map(f => <FileRow key={f.file_path} f={f} scanId={data.latest_scan!.scan_id} tz={tz} />)}</ul>
              )}
            </section>

            {/* Pull requests */}
            <section aria-label="Pull requests" className="section-card overflow-hidden">
              <div className="px-5 py-4 border-b border-gray-100">
                <h2 className="font-bold text-gray-900 text-sm">Pull requests</h2>
                <p className="text-xs text-gray-500 mt-0.5">{plural(data.stats.prs, "pull request")}{data.stats.direct_pushes ? ` · ${plural(data.stats.direct_pushes, "direct push", "direct pushes")}` : ""} · sign-off counts from each PR&apos;s latest scan</p>
              </div>
              {data.prs.length === 0 ? <p className="px-5 py-8 text-center text-sm text-gray-500">No pull request scans yet.</p> : (
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead><tr className="text-[10px] font-black uppercase tracking-widest text-gray-400 bg-gray-50/70 text-left">
                      <th className="px-5 py-2">PR</th><th className="px-2 py-2">Author</th><th className="px-2 py-2">Risk</th>
                      <th className="px-2 py-2 text-right">Signed off</th><th className="px-2 py-2 text-right">Scans</th><th className="px-5 py-2 text-right">Last scan</th>
                    </tr></thead>
                    <tbody>
                      {data.prs.map(p => (
                        <tr key={p.pr_number} className="border-t border-gray-50 hover:bg-gray-50/60">
                          <td className="px-5 py-2.5"><Link href={`/pr/${p.latest_scan_id}`} className="font-extrabold text-indigo-600 hover:text-indigo-800">#{p.pr_number}</Link></td>
                          <td className="px-2 py-2.5 text-gray-700">{p.author ?? <span className="text-gray-400">—</span>}</td>
                          <td className="px-2 py-2.5"><RiskBadge level={p.overall_risk as RiskLevel} /></td>
                          <td className={`px-2 py-2.5 text-right tabular-nums font-bold ${p.high_crit === 0 ? "text-gray-400" : p.signed_off === p.high_crit ? "text-emerald-600" : "text-amber-600"}`}>
                            {p.high_crit === 0 ? "nothing to sign" : `${p.signed_off}/${p.high_crit}`}
                          </td>
                          <td className="px-2 py-2.5 text-right tabular-nums text-gray-600">{p.scans}</td>
                          <td className="px-5 py-2.5 text-right text-gray-500" title={formatDateTime(p.last_scan_at, tz)}>{relativeTime(p.last_scan_at, tz)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </section>

            <div className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_280px]">
              {/* Scan history */}
              <section aria-label="Scans" className="section-card overflow-hidden min-w-0">
                <div className="px-5 py-4 border-b border-gray-100">
                  <h2 className="font-bold text-gray-900 text-sm">Scan history</h2>
                  <p className="text-xs text-gray-500 mt-0.5">Newest first · an older scan of the same pull request is superseded by the newer one</p>
                </div>
                {data.scans.length === 0 ? <p className="px-5 py-8 text-center text-sm text-gray-500">No scans yet.</p> : (
                  <ul className="divide-y divide-gray-50">
                    {(showAllScans ? data.scans : data.scans.slice(0, SCANS_SHOWN)).map(s => (
                      <li key={s.scan_id}>
                        <Link href={`/pr/${s.scan_id}`} className={`flex flex-wrap items-center gap-3 px-5 py-3 hover:bg-gray-50/60 ${s.superseded ? "opacity-60" : ""}`}>
                          <span className="text-sm font-extrabold text-indigo-600 w-16">{s.pr_number > 0 ? `#${s.pr_number}` : "push"}</span>
                          <span className="font-mono text-[11px] text-gray-700 bg-gray-100 px-1.5 py-0.5 rounded">{s.commit_sha.slice(0, 9)}</span>
                          <RiskBadge level={s.overall_risk as RiskLevel} />
                          <span className="text-xs text-gray-600 tabular-nums">{pct(s.ai_share)} AI · {plural(s.file_count, "file")}</span>
                          {s.latest && <span className="text-[10px] font-bold text-emerald-700 bg-emerald-50 border border-emerald-200 px-1.5 py-0.5 rounded-full">LATEST</span>}
                          {s.superseded && <span className="text-[10px] font-semibold text-gray-500 bg-gray-100 px-1.5 py-0.5 rounded-full">Superseded</span>}
                          <span className="text-[11px] text-gray-500">{TRIGGER[s.triggered_by] ?? s.triggered_by}{s.author ? ` · ${s.author}` : ""}{s.branch ? ` · ${s.branch}` : ""}</span>
                          <span className="ml-auto text-right text-[11px] text-gray-500" title={formatDateTime(s.created_at, tz)}>{relativeTime(s.created_at, tz)}</span>
                        </Link>
                      </li>
                    ))}
                  </ul>
                )}
                {data.scans.length > SCANS_SHOWN && (
                  <button onClick={() => setShowAllScans(v => !v)} className="w-full py-2.5 text-xs font-semibold text-indigo-600 hover:bg-indigo-50 border-t border-gray-100">
                    {showAllScans ? "Show fewer" : `Show all ${data.scans.length} scans`}
                  </button>
                )}
              </section>

              {/* People */}
              <section aria-label="Contributors" className="section-card p-5 h-fit">
                <h2 className="font-bold text-gray-900 text-sm">Most active authors</h2>
                <p className="text-xs text-gray-500 mt-0.5 mb-3">By scans of their pull requests</p>
                {data.stats.contributors.length === 0 ? <p className="text-xs text-gray-400">No pull request authors recorded.</p> : (
                  <ol className="space-y-2">
                    {data.stats.contributors.map(c => (
                      <li key={c.login} className="flex items-center justify-between text-xs">
                        <span className="font-semibold text-gray-800 truncate">{c.login}</span>
                        <span className="tabular-nums text-gray-500">{plural(c.scans, "scan")}</span>
                      </li>
                    ))}
                  </ol>
                )}
              </section>
            </div>
          </>
        )}
      </div>
    </AuthGuard>
  );
}

function FileRow({ f, scanId, tz }: { f: RepoFile; scanId: string; tz: string }) {
  const dir = f.file_path.includes("/") ? f.file_path.slice(0, f.file_path.lastIndexOf("/") + 1) : "";
  const base = f.file_path.slice(dir.length);
  const st = STATUS[f.status];
  return (
    <li className="flex flex-wrap items-center gap-3 px-5 py-3">
      <div className="flex-1 min-w-[200px]">
        {dir && <span className="text-[10px] text-gray-400 font-mono block truncate">{dir}</span>}
        <span className="font-mono text-[13px] font-bold text-gray-800 break-all">{base}</span>
        {f.indicators.length > 0 && (
          <div className="flex flex-wrap gap-1 mt-1">
            {f.indicators.slice(0, 4).map(i => <Link key={i} href={`/rules#${encodeURIComponent(i)}`} className="text-[10px] font-mono text-gray-600 bg-gray-100 hover:bg-indigo-50 px-1.5 py-0.5 rounded">{i}</Link>)}
            {f.indicators.length > 4 && <span className="text-[10px] text-gray-400">+{f.indicators.length - 4}</span>}
          </div>
        )}
      </div>
      <RiskBadge level={f.risk_score as RiskLevel} />
      <span className="text-[11px] tabular-nums font-bold text-gray-600 w-14 text-right">{pct(f.ai_percentage)} AI</span>
      <div className="w-48 text-right">
        <span className={`inline-block text-[10px] font-bold px-2 py-0.5 rounded-full border ${st.cls}`}>{st.label}</span>
        {f.status === "attested" && <p className="text-[10px] text-gray-500 mt-0.5 truncate">{f.attested_by ?? "reviewer"} · {f.attested_at ? relativeTime(f.attested_at, tz) : ""}</p>}
        {(f.status === "waiting" || f.status === "in_review") && f.sla_deadline && (
          <p className={`text-[10px] mt-0.5 ${f.overdue ? "text-rose-600 font-bold" : "text-gray-500"}`}>{f.overdue ? "Overdue since" : "Due"} {formatDateTime(f.sla_deadline, tz)}</p>
        )}
      </div>
      {(f.status === "waiting" || f.status === "in_review") && (
        <Link href={`/pr/${scanId}?attest=${encodeURIComponent(f.file_path)}`} className="text-[11px] font-bold text-indigo-600 hover:text-indigo-800 whitespace-nowrap">Review &amp; sign off →</Link>
      )}
    </li>
  );
}
