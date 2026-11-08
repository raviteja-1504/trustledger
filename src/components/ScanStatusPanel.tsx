"use client";

/**
 * The PR page's scan status strip: whether the scan was complete (scanHealth.ts), how long it took, and the
 * actions that follow -- rescan (degraded scan, older engine, or triage decisions to apply) and baseline (accept
 * every current finding so only new ones gate merges). The counts live in ScanCounts.tsx.
 *
 * Rescan queues a NEW scan of the PR's current head: this page keeps showing the scan it was opened on. So the
 * panel waits for the new scan to exist, says what to expect from it, and links to it.
 */
import { useEffect, useState } from "react";
import { authedFetch } from "@/lib/useRealData";
import { describeHealth, GAP_REASON_TEXT, languageName, type ScanHealth, type ScanTelemetry } from "@/lib/scanHealth";
import type { LifecycleSummary, FixedFinding } from "@/lib/findingLifecycle";
import Tip from "@/components/Tip";
import { ACTION_TIP } from "@/lib/prTooltips";
import { CAPS } from "@/lib/limits";

interface Props {
  scanId: string;
  health?: ScanHealth | null;
  telemetry?: ScanTelemetry | null;
  currentEngineVersion?: string;
  lifecycle?: { summary: LifecycleSummary; fixed: FixedFinding[]; has_previous_scan: boolean };
  canTriage: boolean;
  /** Paste-ready markdown summary of this scan (lib/prSecuritySummary.ts). */
  summaryMarkdown?: string;
  /** Open a file's row on the page (scan-health list click-through). */
  canOpenFile?: (path: string) => boolean;
  onOpenFile?: (path: string) => void;
  /** Called after a baseline so the page can reload statuses. */
  onChanged: () => void;
  /** To find the scan a rescan produces: this PR's repo and number, this scan's commit and time. */
  repo?: string;
  prNumber?: number;
  commitSha?: string;
  scanCreatedAt?: string;
  /** Open security findings (not under a decision), to say what a baseline would accept. */
  securityOpen?: number;
  /** Triage decisions saved on this page since the scan: they apply to the merge check after a rescan. */
  unappliedDecisions?: number;
  /** How often to look for the rescan's scan, in ms (tests shorten it). */
  rescanPollMs?: number;
}

const fmtMs = (ms: number) => (ms >= 1000 ? `${(ms / 1000).toFixed(1)}s` : `${ms}ms`);
const MAX_POLLS = 45;

interface ScanListItem { scan_id: string; pr_number: number; commit_sha?: string; created_at: string }
/** The newest scan of this pull request made after the one on screen, or null if this is the latest. */
export function newestNewerScan(scans: readonly ScanListItem[], prNumber: number, scanId: string, scanCreatedAt: string): ScanListItem | null {
  return scans
    .filter(x => x.pr_number === prNumber && x.scan_id !== scanId && Date.parse(x.created_at) > Date.parse(scanCreatedAt))
    .sort((a, b) => Date.parse(b.created_at) - Date.parse(a.created_at))[0] ?? null;
}
/** The scan time as plain UTC ISO ("...Z"), whichever spelling the database gave ("...+00:00" with microseconds). */
export function sinceParam(createdAt: string): string {
  const t = Date.parse(createdAt);
  return Number.isNaN(t) ? createdAt : new Date(t).toISOString();
}

type RescanState =
  | { phase: "idle" }
  | { phase: "waiting"; headSha?: string }
  | { phase: "done"; newScanId: string; headSha?: string }
  | { phase: "timeout" };

export default function ScanStatusPanel({
  scanId, health, telemetry, currentEngineVersion, lifecycle, canTriage, summaryMarkdown, canOpenFile, onOpenFile, onChanged,
  repo, prNumber, commitSha, scanCreatedAt, securityOpen, unappliedDecisions = 0, rescanPollMs = 4000,
}: Props) {
  const [copied, setCopied] = useState(false);
  const [showSummary, setShowSummary] = useState(false);
  async function copySummary() {
    if (!summaryMarkdown) return;
    try {
      await navigator.clipboard.writeText(summaryMarkdown);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      setShowSummary(true);                                   // clipboard refused: show it to copy by hand
    }
  }
  const [busy, setBusy] = useState<"rescan" | "baseline" | "record" | null>(null);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [showGaps, setShowGaps] = useState(false);
  const [confirmBaseline, setConfirmBaseline] = useState(false);
  const [showPerf, setShowPerf] = useState(false);
  const [rescanState, setRescanState] = useState<RescanState>({ phase: "idle" });

  const olderEngine = !!health?.engine_version && !!currentEngineVersion && health.engine_version !== currentEngineVersion;
  const s = lifecycle?.summary;
  const openCount = s ? s.new + s.existing + s.reopened : 0;
  const otherOpen = securityOpen != null ? Math.max(0, openCount - securityOpen) : null;

  // Is there a newer scan of this PR (a push, or an earlier rescan)? Said on the page itself, with a link, so an old
  // scan is never mistaken for the current one -- and the link is still there after a reload.
  const [newerScan, setNewerScan] = useState<ScanListItem | null>(null);
  useEffect(() => {
    if (!repo || prNumber == null || !scanCreatedAt) return;
    let live = true;
    Promise.resolve(authedFetch<{ scans: ScanListItem[] }>(`/api/scans?repo=${encodeURIComponent(repo)}&since=${encodeURIComponent(sinceParam(scanCreatedAt))}&limit=50`))
      .then(r => { if (live) setNewerScan(newestNewerScan(r?.scans ?? [], prNumber, scanId, scanCreatedAt)); })
      .catch(() => { /* no banner: the page works without it */ });
    return () => { live = false; };
  }, [repo, prNumber, scanCreatedAt, scanId]);

  // After a rescan is queued, look for the scan it produces: a newer scan of this PR than the one on screen.
  useEffect(() => {
    if (rescanState.phase !== "waiting" || !repo || prNumber == null || !scanCreatedAt) return;
    let cancelled = false;
    let polls = 0;
    let timer: ReturnType<typeof setTimeout>;
    const tick = async () => {
      polls++;
      try {
        const r = await authedFetch<{ scans: Array<{ scan_id: string; pr_number: number; commit_sha?: string; created_at: string }> }>(
          `/api/scans?repo=${encodeURIComponent(repo)}&since=${encodeURIComponent(sinceParam(scanCreatedAt))}&limit=20`);
        const newer = newestNewerScan(r.scans ?? [], prNumber, scanId, scanCreatedAt);
        if (newer) { if (!cancelled) setRescanState(prev => ({ phase: "done", newScanId: newer.scan_id, headSha: newer.commit_sha ?? (prev.phase === "waiting" ? prev.headSha : undefined) })); return; }
      } catch { /* keep waiting: a failed poll is not a failed rescan */ }
      if (cancelled) return;
      if (polls >= MAX_POLLS) setRescanState({ phase: "timeout" });
      else timer = setTimeout(tick, rescanPollMs);
    };
    timer = setTimeout(tick, rescanPollMs);
    return () => { cancelled = true; clearTimeout(timer); };
  }, [rescanState.phase, repo, prNumber, scanCreatedAt, scanId, rescanPollMs]);

  async function rescan() {
    setBusy("rescan"); setMsg(null);
    try {
      const r = await authedFetch<{ head_sha?: string }>(`/api/scans/${scanId}/rescan`, { method: "POST" });
      setRescanState({ phase: "waiting", headSha: r?.head_sha });
    } catch (e) {
      setRescanState({ phase: "idle" });
      setMsg({ ok: false, text: e instanceof Error && e.message ? e.message : "Couldn't start the rescan." });
    } finally { setBusy(null); }
  }

  async function downloadTrustRecord() {
    setBusy("record"); setMsg(null);
    try {
      const doc = await authedFetch<{ record: { change: { repository: string; pull_request: number; commit: string } }; signature: unknown }>(`/api/scans/${scanId}/trust-record`);
      const c = doc.record.change;
      const a = document.createElement("a");
      a.href = URL.createObjectURL(new Blob([JSON.stringify(doc, null, 2)], { type: "application/json" }));
      a.download = `trust-record-${c.repository.replace(/[^\w.-]+/g, "-")}-pr${c.pull_request}-${c.commit.slice(0, 8)}.json`;
      a.click();
      URL.revokeObjectURL(a.href);
      if (!doc.signature) setMsg({ ok: false, text: "Downloaded, but unsigned: no export signing key is configured on the server." });
    } catch (e) {
      setMsg({ ok: false, text: e instanceof Error && e.message ? e.message : "Couldn't build the Trust Record." });
    } finally { setBusy(null); }
  }

  async function baseline() {
    setBusy("baseline"); setMsg(null); setConfirmBaseline(false);
    try {
      const r = await authedFetch<{ baselined: number }>("/api/findings/baseline", { method: "POST", body: JSON.stringify({ scan_id: scanId }) });
      setMsg({ ok: true, text: r.baselined ? `${r.baselined} finding${r.baselined === 1 ? "" : "s"} accepted as the baseline. Rescan to apply it to this PR's merge check.` : "Every finding here already has a decision." });
      onChanged();
    } catch (e) {
      setMsg({ ok: false, text: e instanceof Error && e.message ? e.message : "Couldn't save the baseline." });
    } finally { setBusy(null); }
  }

  if (!health && !telemetry && !lifecycle && !summaryMarkdown && !unappliedDecisions) return null;

  const sameCommit = rescanState.phase !== "idle" && rescanState.phase !== "timeout" && !!commitSha && !!rescanState.headSha && rescanState.headSha === commitSha;

  return (
    <div className="mt-4 space-y-2.5">
      {health && health.status !== "complete" && (
        <div className={`rounded-xl border px-4 py-2.5 ${health.status === "degraded" ? "border-amber-700/50 bg-amber-950/40" : "border-slate-700/60 bg-slate-800/40"}`}>
          <div className="flex items-start justify-between gap-3 flex-wrap">
            <p className={`text-xs leading-relaxed min-w-0 ${health.status === "degraded" ? "text-amber-200" : "text-slate-300"}`}>
              <button type="button" onClick={() => {
                  // One affected file: go straight to it. Several: list them all (never jump past the others).
                  const only = health.gaps.length === 1 ? health.gaps[0] : undefined;
                  if (only && onOpenFile && canOpenFile?.(only.file)) onOpenFile(only.file);
                  else setShowGaps(true);
                }}
                className="font-bold underline decoration-dotted underline-offset-2 hover:decoration-solid focus:outline-none focus-visible:decoration-solid"
                title="Show the affected files">
                {health.status === "degraded" ? "Incomplete scan:" : "Partial coverage:"}
              </button>{" "}
              {describeHealth(health)}
              {health.status === "degraded" && " A rescan normally fixes this."}
            </p>
            {health.gaps.length > 0 && (
              <Tip tip={ACTION_TIP.whichFiles}>
                <button onClick={() => setShowGaps(v => !v)} className="shrink-0 text-[11px] font-semibold text-slate-300 hover:text-white underline underline-offset-2">
                  {showGaps ? "Hide files" : "Which files?"}
                </button>
              </Tip>
            )}
          </div>
          {showGaps && (
            <ul className="mt-2 space-y-1 max-h-48 overflow-auto">
              {health.gaps.map(g => (
                <li key={`${g.file}:${g.reason}`} className="text-[11px] flex gap-2 min-w-0">
                  {onOpenFile && canOpenFile?.(g.file)
                    ? <button type="button" onClick={() => onOpenFile(g.file)} title={`Open ${g.file}`}
                        className="font-mono text-sky-300 hover:text-sky-200 hover:underline truncate focus:outline-none focus-visible:underline">{g.file}</button>
                    : <code className="font-mono text-slate-200 truncate">{g.file}</code>}
                  <span className="text-slate-400 shrink-0">{languageName(g.language)} · {GAP_REASON_TEXT[g.reason]}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      {unappliedDecisions > 0 && rescanState.phase === "idle" && (
        <div role="status" className="flex items-center justify-between gap-3 flex-wrap rounded-xl border border-violet-400/30 bg-violet-500/10 px-4 py-2.5">
          <p className="text-xs text-violet-100 leading-relaxed">
            <strong>{unappliedDecisions} triage decision{unappliedDecisions === 1 ? "" : "s"} saved.</strong>{" "}
            They are recorded now, but this scan&apos;s risk ratings and the merge check only change after a rescan.
          </p>
          <Tip tip={ACTION_TIP.rescanNow}>
            <button onClick={rescan} disabled={busy !== null}
              className="shrink-0 text-[11px] font-bold text-violet-50 bg-violet-500/30 hover:bg-violet-500/40 border border-violet-400/40 rounded-lg px-2.5 py-1 disabled:opacity-50">
              {busy === "rescan" ? "Queuing…" : "Rescan now"}
            </button>
          </Tip>
        </div>
      )}

      {newerScan && rescanState.phase !== "done" && (
        <div role="status" data-testid="newer-scan" className="flex items-center justify-between gap-3 flex-wrap rounded-xl border border-sky-400/30 bg-sky-500/10 px-4 py-2.5">
          <p className="text-xs text-sky-100 leading-relaxed min-w-0">
            <strong>This isn&apos;t the latest scan of this pull request.</strong>{" "}
            A newer one{newerScan.commit_sha ? <> (commit <code className="font-mono">{newerScan.commit_sha.slice(0, 7)}</code>)</> : null} was made {new Date(newerScan.created_at).toLocaleString()}.
          </p>
          <a href={`/pr/${newerScan.scan_id}`}
            className="shrink-0 text-[11px] font-bold text-sky-50 bg-sky-500/30 hover:bg-sky-500/40 border border-sky-400/40 rounded-lg px-2.5 py-1">
            Open the latest scan →
          </a>
        </div>
      )}

      <div className="flex items-center gap-2 flex-wrap">
        <span className="flex-1" />
        {telemetry && (
          <Tip tip={ACTION_TIP.timing}>
            <button onClick={() => setShowPerf(v => !v)} className="text-[11px] text-slate-400 hover:text-slate-200 tabular-nums" aria-expanded={showPerf}>
              {fmtMs(telemetry.total_ms)} · {telemetry.files_analyzed} analyzed{telemetry.files_reused ? ` · ${telemetry.files_reused} reused` : ""} {showPerf ? "▴" : "▾"}
            </button>
          </Tip>
        )}
        {olderEngine && (
          <Tip tip={`${ACTION_TIP.olderEngine} (This scan: engine ${health?.engine_version}; current: ${currentEngineVersion}.)`}>
            <span tabIndex={0} className="cursor-help text-[11px] font-semibold text-amber-200 bg-amber-500/10 border border-amber-400/30 px-2 py-0.5 rounded-full focus:outline-none focus-visible:ring-2 focus-visible:ring-sky-400">
              Older engine
            </span>
          </Tip>
        )}
        <Tip tip={ACTION_TIP.rescan}>
          <button onClick={rescan} disabled={busy !== null || rescanState.phase === "waiting"}
            className="text-[11px] font-bold text-indigo-100 bg-indigo-500/20 hover:bg-indigo-500/30 border border-indigo-400/30 rounded-lg px-2.5 py-1 disabled:opacity-50 transition-colors">
            {busy === "rescan" ? "Queuing…" : rescanState.phase === "waiting" ? "Rescanning…" : "Rescan"}
          </button>
        </Tip>
        {summaryMarkdown && (
          <Tip tip={ACTION_TIP.copySummary}>
            <button onClick={copySummary}
              className="text-[11px] font-bold text-slate-200 bg-white/5 hover:bg-white/10 border border-white/10 rounded-lg px-2.5 py-1 transition-colors">
              {copied ? "Copied ✓" : "Copy summary"}
            </button>
          </Tip>
        )}
        <Tip tip={ACTION_TIP.trustRecord}>
          <button onClick={downloadTrustRecord} disabled={busy !== null}
            className="text-[11px] font-bold text-emerald-100 bg-emerald-500/15 hover:bg-emerald-500/25 border border-emerald-400/30 rounded-lg px-2.5 py-1 disabled:opacity-50 transition-colors">
            {busy === "record" ? "Building…" : "Trust Record"}
          </button>
        </Tip>
        {canTriage && openCount > 0 && (
          confirmBaseline ? (
            <span className="flex items-center gap-1.5 flex-wrap">
              <span className="text-[11px] text-slate-300">
                Accept all {openCount} open items
                {securityOpen != null && otherOpen != null ? ` (${securityOpen} security finding${securityOpen === 1 ? "" : "s"} and ${otherOpen} other signal${otherOpen === 1 ? "" : "s"})` : ""}?
              </span>
              {openCount > CAPS.baselineFindings.value && (
                <span role="note" className="text-[11px] text-amber-300">{CAPS.baselineFindings.effect} {CAPS.baselineFindings.advice}</span>
              )}
              <Tip tip={ACTION_TIP.acceptBaseline}>
                <button onClick={baseline} disabled={busy !== null} className="text-[11px] font-bold text-violet-100 bg-violet-500/30 hover:bg-violet-500/40 border border-violet-400/40 rounded-lg px-2.5 py-1">Accept as baseline</button>
              </Tip>
              <button onClick={() => setConfirmBaseline(false)} className="text-[11px] text-slate-400 hover:text-slate-200 px-1">Cancel</button>
            </span>
          ) : (
            <Tip tip={ACTION_TIP.baseline}>
              <button onClick={() => setConfirmBaseline(true)} disabled={busy !== null}
                className="text-[11px] font-bold text-slate-200 bg-white/5 hover:bg-white/10 border border-white/10 rounded-lg px-2.5 py-1 disabled:opacity-50 transition-colors">
                {busy === "baseline" ? "Saving…" : "Baseline"}
              </button>
            </Tip>
          )
        )}
      </div>

      {/* ── Rescan progress / result ───────────────────────────── */}
      {rescanState.phase === "waiting" && (
        <div role="status" className="rounded-xl border border-indigo-400/30 bg-indigo-500/10 px-4 py-2.5 text-xs text-indigo-100 leading-relaxed">
          <strong>Rescanning{rescanState.headSha ? <> commit <code className="font-mono">{rescanState.headSha.slice(0, 7)}</code></> : null}…</strong>{" "}
          This page stays as it is. The result is a new scan that opens separately when it finishes, usually in under a minute.
        </div>
      )}
      {rescanState.phase === "done" && (
        <div role="status" className="flex items-center justify-between gap-3 flex-wrap rounded-xl border border-emerald-400/30 bg-emerald-500/10 px-4 py-2.5">
          <p className="text-xs text-emerald-100 leading-relaxed min-w-0">
            <strong>Rescan finished.</strong> The new scan compares itself with this one: its “new” findings appeared since, its “fixed” ones are gone.
            {sameCommit ? " It is the same commit, so differences come from the scanner or your triage decisions, not new code." : " The PR has newer commits than this scan, so code changes show up too."}
          </p>
          <a href={`/pr/${rescanState.newScanId}`}
            className="shrink-0 text-[11px] font-bold text-emerald-50 bg-emerald-500/30 hover:bg-emerald-500/40 border border-emerald-400/40 rounded-lg px-2.5 py-1">
            Open the new results →
          </a>
        </div>
      )}
      {rescanState.phase === "timeout" && (
        <div role="status" className="rounded-xl border border-amber-400/30 bg-amber-500/10 px-4 py-2.5 text-xs text-amber-100 leading-relaxed">
          The rescan is taking longer than usual. It may still finish: check Scan History, or reload this page in a minute.
        </div>
      )}

      {showPerf && telemetry && (
        <div className="rounded-xl border border-white/10 bg-white/[0.03] px-4 py-3 grid gap-3 sm:grid-cols-2">
          <div className="min-w-0">
            <p className="text-[10px] font-bold uppercase tracking-wider text-slate-500 mb-1.5">Where the time went</p>
            {([["Cross-file preparation", telemetry.cross_file_ms], ["Per-file analysis", telemetry.per_file_ms], ["Correlation & scoring", telemetry.post_ms]] as const).map(([label, ms]) => (
              <div key={label} className="flex items-center gap-2 text-[11px] py-0.5">
                <span className="w-40 text-slate-300 shrink-0">{label}</span>
                <span className="flex-1 h-1.5 rounded-full bg-white/10 overflow-hidden">
                  <span className="block h-full rounded-full bg-indigo-400/70" style={{ width: `${telemetry.total_ms ? Math.round((ms / telemetry.total_ms) * 100) : 0}%` }} />
                </span>
                <span className="w-14 text-right text-slate-400 tabular-nums">{fmtMs(ms)}</span>
              </div>
            ))}
            <p className="text-[10px] text-slate-500 mt-1.5">Engine {telemetry.engine_version}{telemetry.files_reused ? ` · ${telemetry.files_reused} unchanged files reused from the previous scan` : ""}</p>
          </div>
          {telemetry.slowest.length > 0 && (
            <div className="min-w-0">
              <p className="text-[10px] font-bold uppercase tracking-wider text-slate-500 mb-1.5">Slowest files</p>
              {telemetry.slowest.map(s => (
                <div key={s.file} className="flex items-center gap-2 text-[11px] py-0.5 min-w-0">
                  <code className="font-mono text-slate-300 truncate flex-1">{s.file}</code>
                  <span className="text-slate-400 tabular-nums shrink-0">{fmtMs(s.ms)}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {showSummary && summaryMarkdown && (
        <div className="space-y-1.5">
          <p className="text-[11px] text-slate-400">Your browser blocked the clipboard. Select the text below and copy it.</p>
          <label htmlFor={`summary-${scanId}`} className="sr-only">Security summary</label>
          <textarea id={`summary-${scanId}`} readOnly value={summaryMarkdown} rows={8} onFocus={e => e.currentTarget.select()}
            className="w-full rounded-lg bg-slate-950/60 ring-1 ring-white/10 px-2.5 py-1.5 font-mono text-[11px] text-slate-100" />
        </div>
      )}

      {msg && <p className={`text-[11px] ${msg.ok ? "text-emerald-300" : "text-rose-300"}`}>{msg.text}</p>}
    </div>
  );
}
