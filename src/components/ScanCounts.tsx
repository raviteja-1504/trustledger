"use client";

/**
 * The PR page's numbers, as three cards that each name their unit (see lib/scanCounts.ts):
 *   Files            -> scanned, need review (rated High/Critical), signed off
 *   Security findings -> total by severity, introduced by this PR vs already there, open vs under a decision
 *   Since last scan  -> what changed against the PR's previous scan, in words, with the findings behind each number
 */
import { useState } from "react";
import { describeChanges, type ChangedFinding, type ScanCounts } from "@/lib/scanCounts";
import type { FixedFinding } from "@/lib/findingLifecycle";
import Tip from "@/components/Tip";
import InfoTooltip from "@/components/InfoTooltip";
import { COUNT_TIP, SEVERITY_TIP } from "@/lib/prTooltips";
import { CAPS } from "@/lib/limits";

/** A term with a dotted underline that explains itself on hover or keyboard focus. */
function Term({ tip, children }: { tip: string; children: React.ReactNode }) {
  return (
    <Tip tip={tip}>
      <span tabIndex={0} className="cursor-help underline decoration-dotted decoration-slate-500 underline-offset-2 focus:outline-none focus-visible:decoration-solid focus-visible:decoration-sky-400">{children}</span>
    </Tip>
  );
}

function CardTitle({ title, tip }: { title: string; tip: string }) {
  return (
    <h3 className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-wider text-slate-400">
      {title}
      <InfoTooltip title={title} description={tip} position="bottom" />
    </h3>
  );
}

interface Props {
  counts: ScanCounts;
  /** The scan the comparison is against (API: lifecycle.previous_scan). */
  previousScan?: { commit_sha: string; created_at: string } | null;
  /** This scan's commit, to say when a "change" can't come from new code. */
  commitSha?: string;
  newFindings: ChangedFinding[];
  fixed: FixedFinding[];
  /** Whether a path is a file of this scan (so its name is a link). */
  canOpenFile?: (path: string) => boolean;
  onOpenFile?: (path: string, line?: number) => void;
  formatWhen?: (iso: string) => string;
  /** The "decisions" detail (accepted risk / false positives), rendered by the page where triage lives. */
  decisions?: React.ReactNode;
}

const SEV_PILL: Record<string, string> = {
  critical: "text-violet-100 bg-violet-500/20 border-violet-400/40",
  high: "text-orange-100 bg-orange-500/15 border-orange-400/40",
  medium: "text-amber-100 bg-amber-400/15 border-amber-400/40",
  low: "text-sky-100 bg-sky-400/15 border-sky-400/40",
};
const SEV_DOT: Record<string, string> = { critical: "bg-violet-400", high: "bg-orange-400", medium: "bg-amber-300", low: "bg-sky-300" };

const CARD = "rounded-xl border border-white/10 bg-white/[0.04] px-4 py-3 min-w-0";
const CARD_TITLE = "text-[10px] font-bold uppercase tracking-wider text-slate-400";

function Big({ value, unit }: { value: React.ReactNode; unit: string }) {
  return (
    <p className="mt-1 flex items-baseline gap-1.5">
      <span className="text-2xl font-black leading-none tabular-nums text-white">{value}</span>
      <span className="text-[12px] text-slate-300">{unit}</span>
    </p>
  );
}

function FileLink({ path, line, canOpenFile, onOpenFile }: { path: string; line?: number; canOpenFile?: (p: string) => boolean; onOpenFile?: (p: string, l?: number) => void }) {
  const text = `${path}${line ? `:${line}` : ""}`;
  if (onOpenFile && canOpenFile?.(path)) {
    return (
      <button type="button" onClick={() => onOpenFile(path, line)} title={`Open ${text}`}
        className="font-mono text-sky-300 hover:text-sky-200 hover:underline truncate text-left focus:outline-none focus-visible:underline">{text}</button>
    );
  }
  return <code className="font-mono text-slate-300 truncate">{text}</code>;
}

export default function ScanCountsSummary({ counts, previousScan, commitSha, newFindings, fixed, canOpenFile, onOpenFile, formatWhen, decisions }: Props) {
  const [showChanges, setShowChanges] = useState(false);
  const [showDecisions, setShowDecisions] = useState(false);
  const { files, security, otherSignals, changes } = counts;
  const sevs = (["critical", "high", "medium", "low"] as const).filter(s => security.bySeverity[s] > 0);
  const sameCommit = !!previousScan && !!commitSha && previousScan.commit_sha === commitSha;
  const when = (iso: string) => (formatWhen ? formatWhen(iso) : new Date(iso).toLocaleString());
  const hasDetail = !!changes && (newFindings.length > 0 || fixed.length > 0);

  return (
    <section aria-label="Scan summary" className="mt-4 space-y-2">
      <div className="grid gap-2.5 md:grid-cols-3">
        {/* ── Files ─────────────────────────────────────────────── */}
        <div className={CARD} data-testid="card-files">
          <CardTitle title="Files" tip={COUNT_TIP.files} />
          <Big value={files.scanned} unit={files.scanned === 1 ? "file scanned" : "files scanned"} />
          <ul className="mt-2 space-y-0.5 text-[12px] text-slate-300">
            <li>
              <span className={`font-bold tabular-nums ${files.toReview > 0 ? "text-orange-300" : "text-slate-400"}`}>{files.toReview}</span>{" "}
              <Term tip={COUNT_TIP.needReview}>{files.toReview === 1 ? "needs" : "need"} review</Term> <span className="text-slate-500">(rated High or Critical)</span>
            </li>
            {files.toReview > 0 && (
              <li>
                <span className={`font-bold tabular-nums ${files.signedOff === files.toReview ? "text-emerald-300" : "text-amber-300"}`}>{files.signedOff} of {files.toReview}</span>{" "}
                <Term tip={COUNT_TIP.signedOff}>signed off</Term> by a reviewer
              </li>
            )}
          </ul>
        </div>

        {/* ── Security findings ─────────────────────────────────── */}
        <div className={CARD} data-testid="card-findings">
          <CardTitle title="Security findings" tip={COUNT_TIP.findings} />
          <Big value={security.total} unit={security.total === 1 ? "finding" : "findings"} />
          {security.total > 0 && (
            <>
              <div className="mt-2 flex flex-wrap gap-1.5">
                {sevs.map(s => (
                  <Tip key={s} tip={SEVERITY_TIP[s]}>
                    <span tabIndex={0} className={`cursor-help text-[11px] font-semibold px-2 py-0.5 rounded-full border focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400 ${SEV_PILL[s]}`}>{security.bySeverity[s]} {s}</span>
                  </Tip>
                ))}
              </div>
              <ul className="mt-2 space-y-0.5 text-[12px] text-slate-300">
                {security.introduced != null && security.preexisting != null && (
                  <li>
                    <span className="font-bold tabular-nums text-rose-200">{security.introduced}</span> <Term tip={COUNT_TIP.introduced}>introduced by this PR</Term>
                    {security.preexisting > 0 && <> · <span className="font-bold tabular-nums">{security.preexisting}</span> <Term tip={COUNT_TIP.preexisting}><span className="text-slate-400">already in the files it touches</span></Term></>}
                  </li>
                )}
                {security.suppressed > 0 ? (
                  <li>
                    <span className="font-bold tabular-nums text-white">{security.open}</span> open ·{" "}
                    <Tip tip={COUNT_TIP.decision}>
                      <button type="button" onClick={() => setShowDecisions(v => !v)} aria-expanded={showDecisions}
                        className="font-semibold text-violet-200 underline decoration-dotted underline-offset-2 hover:decoration-solid">
                        {security.suppressed} under a triage decision {showDecisions ? "▴" : "▾"}
                      </button>
                    </Tip>
                  </li>
                ) : null}
              </ul>
            </>
          )}
          {security.total === 0 && <p className="mt-2 text-[12px] text-slate-400">None found in the files scanned.</p>}
        </div>

        {/* ── Since the previous scan ───────────────────────────── */}
        <div className={CARD} data-testid="card-changes">
          <CardTitle title="Since the previous scan" tip={COUNT_TIP.changes} />
          {!changes ? (
            <>
              <p className="mt-1 text-[13px] font-semibold text-white">First scan of this PR</p>
              <p className="mt-1 text-[12px] text-slate-400">Nothing to compare with yet. Each later push or rescan is compared with the scan before it.</p>
            </>
          ) : (
            <>
              <p className="mt-1 flex flex-wrap items-baseline gap-x-3 gap-y-1">
                <span className="text-[12px]"><span className="text-xl font-black tabular-nums text-sky-200">{changes.new}</span> <span className="text-slate-300">new</span></span>
                <span className="text-[12px]"><span className="text-xl font-black tabular-nums text-emerald-200">{changes.fixed}{changes.fixedIsLowerBound ? "+" : ""}</span> <span className="text-slate-300">fixed</span></span>
                <span className="text-[12px]"><span className="text-xl font-black tabular-nums text-slate-200">{changes.existing}</span> <span className="text-slate-300">unchanged</span></span>
              </p>
              <p className="mt-1.5 text-[11px] text-slate-400">
                {previousScan
                  ? <>Compared with the scan of commit <code className="font-mono text-slate-300">{previousScan.commit_sha.slice(0, 7)}</code>, {when(previousScan.created_at)}.</>
                  : "Compared with the previous scan of this PR."}
              </p>
              {sameCommit && (
                <p className="mt-1 text-[11px] text-amber-200/90">Same commit as that scan, so changes here come from the scanner or your triage decisions, not new code.</p>
              )}
              {hasDetail && (
                <button type="button" onClick={() => setShowChanges(v => !v)} aria-expanded={showChanges}
                  className="mt-2 text-[11px] font-bold text-indigo-200 underline decoration-dotted underline-offset-2 hover:decoration-solid">
                  {showChanges ? "Hide what changed ▴" : "See what changed ▾"}
                </button>
              )}
            </>
          )}
        </div>
      </div>

      <p className="text-[11px] text-slate-500 leading-relaxed">
        Files are rated by their worst finding, so {files.toReview} {files.toReview === 1 ? "file" : "files"} to review and {security.total} {security.total === 1 ? "finding" : "findings"} are different counts
        {files.withFindings > 0 ? <> ({security.total} {security.total === 1 ? "finding" : "findings"} in {files.withFindings} {files.withFindings === 1 ? "file" : "files"})</> : null}.
        {otherSignals > 0 && <> <Term tip={COUNT_TIP.otherSignals}>{otherSignals} other {otherSignals === 1 ? "signal" : "signals"}</Term> (AI-provenance and code-hygiene hints) are not vulnerabilities and are not counted above.</>}
      </p>

      {/* ── What changed ───────────────────────────────────────── */}
      {showChanges && changes && (
        <div className="rounded-xl border border-white/10 bg-white/[0.03] px-4 py-3 space-y-3" data-testid="what-changed">
          <ul className="space-y-0.5 text-[12px] text-slate-300 list-disc pl-4 marker:text-slate-500">
            {describeChanges(changes).map(line => <li key={line}>{line}</li>)}
          </ul>
          {newFindings.length > 0 && (
            <div>
              <p className="text-[10px] font-bold uppercase tracking-wider text-sky-300 mb-1">New or back since the previous scan ({newFindings.length})</p>
              <ul className="space-y-1 max-h-56 overflow-auto">
                {newFindings.map((f, i) => (
                  <li key={`${f.file}:${f.line}:${f.id}:${i}`} className="text-[11px] flex items-center gap-2 min-w-0">
                    <span className={`h-1.5 w-1.5 rounded-full shrink-0 ${SEV_DOT[f.severity]}`} aria-hidden />
                    <span className="font-semibold text-slate-100 shrink-0">{f.label}</span>
                    {f.status === "reopened" && <span className="text-[10px] font-semibold text-orange-200 shrink-0">came back</span>}
                    <FileLink path={f.file} line={f.line} canOpenFile={canOpenFile} onOpenFile={onOpenFile} />
                  </li>
                ))}
              </ul>
            </div>
          )}
          {fixed.length > 0 && (
            <div>
              <p className="text-[10px] font-bold uppercase tracking-wider text-emerald-300 mb-1">Fixed: in the previous scan, gone now ({fixed.length}{changes.fixedIsLowerBound ? "+" : ""})</p>
              {fixed.length >= CAPS.fixedFindingsListed.value && <p className="text-[10px] text-slate-400 mb-1">{CAPS.fixedFindingsListed.effect} {CAPS.fixedFindingsListed.advice}</p>}
              <ul className="space-y-1 max-h-56 overflow-auto">
                {fixed.map(f => (
                  <li key={f.fingerprint} className="text-[11px] flex gap-2 min-w-0">
                    <span className="text-emerald-300 font-semibold shrink-0">✓ {f.label}</span>
                    <code className="font-mono text-slate-400 truncate">{f.file_path}{f.line ? `:${f.line}` : ""}</code>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {showDecisions && decisions}
    </section>
  );
}
