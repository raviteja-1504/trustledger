"use client";

/**
 * Report section: the change-management register (/api/report/change-register, lib/changeRegister.ts) -- every pull
 * request merged in the period with its approval, scan and sign-off evidence, the exceptions, and an auditor sample
 * re-drawn here for any seed (lib/changeRegisterShared.ts draws the same rows the server and the signed report do).
 *
 * Built on request, not on load: it reads every merged pull request and its reviews from GitHub, and counts towards
 * the hourly report limit.
 */
import { useMemo, useState } from "react";
import Link from "next/link";
import { authedFetch } from "@/lib/useRealData";
import { protectionValue, type BranchProtection } from "@/lib/branchProtection";
import {
  DEFAULT_SAMPLE_SIZE, EXCEPTION_INFO, drawSample, registerToCsv, type ChangeRegister as Register, type ExceptionCode, type RegisterRow,
} from "@/lib/changeRegisterShared";

const ROWS = 50;
const RISK_CLS: Record<string, string> = {
  CRITICAL: "bg-violet-100 text-violet-700", HIGH: "bg-orange-100 text-orange-700", MEDIUM: "bg-amber-100 text-amber-800", LOW: "bg-gray-100 text-gray-600",
};
const fmtDay = (iso: string) => new Date(iso).toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric", timeZone: "UTC" });

function save(name: string, body: string, type: string) {
  const a = Object.assign(document.createElement("a"), { href: URL.createObjectURL(new Blob([body], { type })), download: name });
  a.click();
  URL.revokeObjectURL(a.href);
}

function ExceptionChips({ codes }: { codes: ExceptionCode[] }) {
  if (codes.length === 0) return <span className="text-[10px] font-bold text-emerald-700">None</span>;
  return (
    <div className="flex flex-wrap gap-1">
      {codes.map(c => (
        <span key={c} title={EXCEPTION_INFO[c].label}
          className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${EXCEPTION_INFO[c].severity === "exception" ? "text-rose-700 bg-rose-50 border-rose-200" : "text-amber-800 bg-amber-50 border-amber-200"}`}>
          {EXCEPTION_INFO[c].label}
        </span>
      ))}
    </div>
  );
}

function ProtectionTable({ rows }: { rows: BranchProtection[] }) {
  const cell = (v: boolean | number | null, good: boolean) =>
    <span className={v === null ? "text-gray-400" : good ? "text-emerald-700 font-semibold" : "text-rose-700 font-semibold"}>{protectionValue(v)}</span>;
  const limits = rows.flatMap(r => r.limits.map(l => `${r.repo}: ${l}`));
  return (
    <div className="rounded-xl border border-gray-200 overflow-hidden">
      <div className="px-4 py-2.5 bg-gray-50 border-b border-gray-100">
        <p className="text-[10px] font-black uppercase tracking-widest text-gray-500">How merging is protected (default branch, read when the register was built)</p>
        <p className="text-[10px] text-gray-500 mt-0.5">The control&apos;s design. The register above shows how it operated; this is a snapshot, not a history of the settings.</p>
      </div>
      <div className="overflow-x-auto">
        <table aria-label="Branch protection" className="w-full text-xs">
          <thead>
            <tr className="text-[9px] font-black uppercase tracking-widest text-gray-400 text-left">
              <th className="px-4 py-2">Repository</th><th className="px-2 py-2">Pull request required</th><th className="px-2 py-2 text-right">Approvals</th>
              <th className="px-2 py-2">New pushes dismiss approvals</th><th className="px-2 py-2">Required checks</th><th className="px-4 py-2">Force push blocked</th>
            </tr>
          </thead>
          <tbody>
            {rows.map(r => (
              <tr key={r.repo} className="border-t border-gray-50">
                <td className="px-4 py-2.5"><span className="font-semibold text-gray-900">{r.repo}</span>{r.branch && <span className="text-[10px] text-gray-400 font-mono"> {r.branch}</span>}</td>
                <td className="px-2 py-2.5">{cell(r.pull_request_required, !!r.pull_request_required)}</td>
                <td className="px-2 py-2.5 text-right tabular-nums">{cell(r.approvals_required, (r.approvals_required ?? 0) > 0)}</td>
                <td className="px-2 py-2.5">{cell(r.dismiss_stale_approvals, !!r.dismiss_stale_approvals)}</td>
                <td className="px-2 py-2.5 text-[10px] text-gray-600">{r.required_status_checks.join(", ") || "—"}</td>
                <td className="px-4 py-2.5">{cell(r.force_push_blocked, !!r.force_push_blocked)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {limits.length > 0 && (
        <ul className="px-4 py-2.5 border-t border-gray-100 space-y-0.5">
          {limits.map(l => <li key={l} className="text-[10px] text-amber-800">{l}</li>)}
        </ul>
      )}
    </div>
  );
}

function RegisterTable({ rows, label }: { rows: RegisterRow[]; label: string }) {
  return (
    <div className="overflow-x-auto">
      <table aria-label={label} className="w-full text-xs">
        <thead>
          <tr className="text-[9px] font-black uppercase tracking-widest text-gray-400 text-left">
            <th className="px-4 py-2">Pull request</th><th className="px-2 py-2">Merged</th><th className="px-2 py-2">Approved before merge</th>
            <th className="px-2 py-2">Scan</th><th className="px-2 py-2 text-right">High-risk signed off</th><th className="px-4 py-2">Exceptions</th>
          </tr>
        </thead>
        <tbody>
          {rows.map(r => (
            <tr key={`${r.repo}#${r.number}`} className="border-t border-gray-50 align-top">
              <td className="px-4 py-2.5 min-w-[200px]">
                <a href={r.url} target="_blank" rel="noreferrer" className="font-semibold text-gray-900 hover:text-indigo-700">{r.repo}#{r.number}</a>
                <p className="text-[10px] text-gray-500 mt-0.5 break-words">{r.title}{r.author ? ` · by ${r.author}` : ""}</p>
              </td>
              <td className="px-2 py-2.5 whitespace-nowrap text-gray-700">
                {fmtDay(r.merged_at)}{r.merged_by && <p className="text-[10px] text-gray-400">by {r.merged_by}</p>}
              </td>
              <td className="px-2 py-2.5 min-w-[130px]">
                {r.approvals.length === 0 ? <span className="text-gray-300">—</span> : r.approvals.map(a => (
                  <p key={`${a.reviewer}${a.at}`} className="text-gray-700">
                    {a.reviewer}{!a.on_merged_commit && <span className="text-[10px] text-amber-700"> (earlier commit)</span>}
                  </p>
                ))}
              </td>
              <td className="px-2 py-2.5 whitespace-nowrap">
                {r.scan ? (
                  <Link href={`/pr/${r.scan.scan_id}`} className={`inline-block text-[10px] font-black px-1.5 py-0.5 rounded ${RISK_CLS[r.scan.overall_risk] ?? RISK_CLS.LOW}`}>
                    {r.scan.overall_risk}
                  </Link>
                ) : <span className="text-[10px] text-gray-400">not scanned</span>}
              </td>
              <td className="px-2 py-2.5 text-right tabular-nums text-gray-700">{r.high_risk_files > 0 ? `${r.high_risk_signed_off}/${r.high_risk_files}` : "—"}</td>
              <td className="px-4 py-2.5 min-w-[200px]"><ExceptionChips codes={r.exceptions} /></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default function ChangeRegister({ start, end, control, color }: { start: string; end: string; control: string; color: string }) {
  const [register, setRegister] = useState<Register | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [view, setView] = useState<"exceptions" | "all">("exceptions");
  const [showAll, setShowAll] = useState(false);
  const [seed, setSeed] = useState(() => Math.random().toString(36).slice(2, 10));
  const [size, setSize] = useState(DEFAULT_SAMPLE_SIZE);
  // a register is for one period: a different period needs building again
  const [builtFor, setBuiltFor] = useState("");
  const periodKey = `${start}..${end}`;
  const current = builtFor === periodKey ? register : null;

  async function build() {
    setLoading(true); setError(null);
    try {
      const qs = new URLSearchParams({ period_start: new Date(start).toISOString(), period_end: `${end}T23:59:59.999Z` });
      setRegister(await authedFetch<Register>(`/api/report/change-register?${qs}`));
      setBuiltFor(periodKey);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Couldn't build the change register.");
    } finally {
      setLoading(false);
    }
  }

  const exceptionRows = useMemo(() => (current?.rows ?? []).filter(r => r.exceptions.length > 0), [current]);
  const sample = useMemo(() => (current && seed ? drawSample(current.rows, size, seed) : []), [current, seed, size]);
  const listed = view === "exceptions" ? exceptionRows : current?.rows ?? [];
  const s = current?.summary;
  const base = `trustledger-change-register-${start}-${end}`;

  return (
    <div className="space-y-3">
      <div className="rounded-xl border border-gray-200 px-5 py-4 bg-gray-50/60">
        <p className="text-[10px] font-black uppercase tracking-widest text-gray-400">How an auditor tests {control}</p>
        <p className="text-xs text-gray-600 mt-1 leading-relaxed">
          They start from the complete list of changes in the period, then test a random sample of them: was each one
          approved by someone other than its author before it merged, scanned, and were its high-risk files signed off?
          This register is that list, read from GitHub and TrustLedger&apos;s records, with the exceptions marked. The signed
          PDF report carries the same register and a sample drawn with the report&apos;s id as its seed.
        </p>
      </div>

      {!current && (
        <div className="flex flex-wrap items-center gap-3">
          <button onClick={build} disabled={loading}
            className="px-4 py-2 rounded-lg text-xs font-bold text-white disabled:opacity-60" style={{ background: color }}>
            {loading ? "Reading pull requests from GitHub…" : "Build change register"}
          </button>
          <p className="text-[11px] text-gray-500">Reads every pull request merged from {fmtDay(start)} to {fmtDay(end)}. Counts towards the hourly report limit.</p>
        </div>
      )}
      {error && <p role="alert" className="text-xs text-rose-600">Couldn&apos;t build the change register. {error}</p>}

      {current && s && (
        <>
          <div role="region" aria-label="Change register summary" className="grid grid-cols-2 sm:grid-cols-4 gap-2">
            {[
              ["Pull requests merged", s.merged, ""],
              ["Approved before merge", s.approved_before_merge, ""],
              ["Scanned before merge", s.scanned, ""],
              ["With exceptions", s.with_exceptions, s.with_exceptions ? "text-rose-600" : ""],
            ].map(([label, n, cls]) => (
              <div key={label as string} className="rounded-xl border border-gray-200 px-4 py-3">
                <p className={`text-xl font-black tabular-nums ${cls}`} style={cls ? undefined : { color }}>{n}</p>
                <p className="text-[10px] text-gray-500 mt-0.5">{label}</p>
              </div>
            ))}
          </div>

          {current.complete ? (
            <p className="text-[11px] text-emerald-700">
              Population complete: all {current.coverage.length} connected repositor{current.coverage.length === 1 ? "y was" : "ies were"} read from GitHub in full.
            </p>
          ) : (
            <div role="alert" className="rounded-xl border border-amber-200 bg-amber-50 px-4 py-3">
              <p className="text-[10px] font-black uppercase tracking-widest text-amber-800">Population incomplete</p>
              <ul className="mt-1 space-y-0.5">
                {current.coverage.filter(c => !c.read || c.truncated).map(c => (
                  <li key={c.repo} className="text-[11px] text-amber-900"><span className="font-semibold">{c.repo}</span>: {c.reason ?? "not read in full"}</li>
                ))}
              </ul>
              <p className="text-[11px] text-amber-900 mt-1">Changes in these repositories may be missing from the register and the sample.</p>
            </div>
          )}

          <div className="flex flex-wrap items-center gap-2">
            <button onClick={() => save(`${base}.csv`, registerToCsv(current.rows), "text/csv")}
              className="px-3 py-1.5 rounded-lg text-xs font-semibold border border-gray-200 text-gray-700 hover:bg-gray-50">Download CSV</button>
            <button onClick={() => save(`${base}.json`, JSON.stringify({ ...current, sample: { seed, size, rows: sample } }, null, 2), "application/json")}
              className="px-3 py-1.5 rounded-lg text-xs font-semibold border border-gray-200 text-gray-700 hover:bg-gray-50">Download JSON (with sample)</button>
            <button onClick={build} disabled={loading} className="px-3 py-1.5 rounded-lg text-xs font-semibold text-gray-500 hover:text-gray-800 disabled:opacity-60">
              {loading ? "Rebuilding…" : "Rebuild"}
            </button>
          </div>

          <div className="rounded-xl border border-gray-200 overflow-hidden">
            <div className="flex flex-wrap items-center justify-between gap-2 px-4 py-2.5 bg-gray-50 border-b border-gray-100">
              <div role="tablist" className="flex gap-1">
                {([["exceptions", `Exceptions (${exceptionRows.length})`], ["all", `All pull requests (${current.rows.length})`]] as const).map(([v, label]) => (
                  <button key={v} role="tab" aria-selected={view === v} onClick={() => { setView(v); setShowAll(false); }}
                    className={`px-2.5 py-1 rounded-md text-[11px] font-bold ${view === v ? "bg-white text-gray-900 shadow-sm" : "text-gray-500 hover:text-gray-800"}`}>
                    {label}
                  </button>
                ))}
              </div>
              <p className="text-[10px] text-gray-500">
                {(Object.keys(EXCEPTION_INFO) as ExceptionCode[]).filter(c => s.exceptions[c] > 0).map(c => `${s.exceptions[c]} ${EXCEPTION_INFO[c].label.toLowerCase()}`).join(" · ")}
              </p>
            </div>
            {listed.length === 0 ? (
              <p className="py-8 text-center text-sm text-gray-500">
                {view === "exceptions" ? "No exceptions: every merged pull request has the evidence." : "No pull requests were merged in this period."}
              </p>
            ) : (
              <>
                <RegisterTable rows={showAll ? listed : listed.slice(0, ROWS)} label={view === "exceptions" ? "Pull requests with exceptions" : "All merged pull requests"} />
                {listed.length > ROWS && (
                  <button onClick={() => setShowAll(v => !v)} className="w-full py-2 text-xs font-semibold text-indigo-600 hover:bg-indigo-50 border-t border-gray-100">
                    {showAll ? "Show fewer" : `Show all ${listed.length}`}
                  </button>
                )}
              </>
            )}
          </div>

          {current.branch_protection && current.branch_protection.length > 0 && <ProtectionTable rows={current.branch_protection} />}

          <div className="rounded-xl border border-gray-200 overflow-hidden">
            <div className="px-4 py-3 bg-gray-50 border-b border-gray-100 space-y-2">
              <p className="text-[10px] font-black uppercase tracking-widest text-gray-500">Auditor sample</p>
              <div className="flex flex-wrap items-end gap-3">
                <label className="text-[11px] text-gray-600">Seed
                  <input value={seed} onChange={e => setSeed(e.target.value.trim())} aria-label="Sample seed"
                    className="block mt-0.5 w-40 font-mono text-xs border border-gray-200 rounded-lg px-2 py-1 bg-white" />
                </label>
                <label className="text-[11px] text-gray-600">Size
                  <input type="number" min={1} max={500} value={size} aria-label="Sample size"
                    onChange={e => setSize(Math.max(1, Math.min(500, Number(e.target.value) || DEFAULT_SAMPLE_SIZE)))}
                    className="block mt-0.5 w-20 text-xs border border-gray-200 rounded-lg px-2 py-1 bg-white tabular-nums" />
                </label>
                <p className="text-[11px] text-gray-500 flex-1 min-w-[200px]">
                  {sample.length} of {current.rows.length} pull requests. The same seed always draws the same rows, so the auditor
                  can choose the seed and re-draw it from the downloaded register.
                </p>
              </div>
            </div>
            {sample.length > 0
              ? <RegisterTable rows={sample} label="Auditor sample" />
              : <p className="py-6 text-center text-sm text-gray-500">{seed ? "Nothing to sample." : "Enter a seed to draw a sample."}</p>}
          </div>
        </>
      )}
    </div>
  );
}
