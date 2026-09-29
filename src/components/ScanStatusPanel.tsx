"use client";

/**
 * The PR page's scan status strip: whether the scan was complete (scanHealth.ts), what changed since the
 * previous push (findingLifecycle.ts), how long it took, and the two actions that follow from those --
 * rescan (degraded scan, older engine, or triage decisions to apply) and baseline (accept every current
 * finding so only new ones gate merges).
 */
import { useState } from "react";
import { authedFetch } from "@/lib/useRealData";
import { describeHealth, GAP_REASON_TEXT, languageName, type ScanHealth, type ScanTelemetry } from "@/lib/scanHealth";
import { STATUS_LABEL, type LifecycleSummary, type FixedFinding } from "@/lib/findingLifecycle";

interface Props {
  scanId: string;
  health?: ScanHealth | null;
  telemetry?: ScanTelemetry | null;
  currentEngineVersion?: string;
  lifecycle?: { summary: LifecycleSummary; fixed: FixedFinding[]; has_previous_scan: boolean };
  canTriage: boolean;
  /** Called after a baseline so the page can reload statuses. */
  onChanged: () => void;
}

const fmtMs = (ms: number) => (ms >= 1000 ? `${(ms / 1000).toFixed(1)}s` : `${ms}ms`);

const CHIP: Record<keyof LifecycleSummary, string> = {
  new: "text-sky-200 bg-sky-500/15 border-sky-400/30",
  reopened: "text-orange-200 bg-orange-500/15 border-orange-400/30",
  existing: "text-slate-300 bg-white/5 border-white/10",
  accepted: "text-violet-200 bg-violet-500/15 border-violet-400/30",
  false_positive: "text-slate-300 bg-slate-500/15 border-slate-400/30",
  fixed: "text-emerald-200 bg-emerald-500/15 border-emerald-400/30",
};

export default function ScanStatusPanel({ scanId, health, telemetry, currentEngineVersion, lifecycle, canTriage, onChanged }: Props) {
  const [busy, setBusy] = useState<"rescan" | "baseline" | null>(null);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [showGaps, setShowGaps] = useState(false);
  const [showFixed, setShowFixed] = useState(false);
  const [confirmBaseline, setConfirmBaseline] = useState(false);

  const olderEngine = !!health?.engine_version && !!currentEngineVersion && health.engine_version !== currentEngineVersion;
  const s = lifecycle?.summary;
  const openCount = s ? s.new + s.existing + s.reopened : 0;

  async function rescan() {
    setBusy("rescan"); setMsg(null);
    try {
      await authedFetch(`/api/scans/${scanId}/rescan`, { method: "POST" });
      setMsg({ ok: true, text: "Rescan queued. The new scan appears in Scan History and on the PR's check when it finishes (usually under a minute)." });
    } catch (e) {
      setMsg({ ok: false, text: e instanceof Error && e.message ? e.message : "Couldn't start the rescan." });
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

  if (!health && !telemetry && !lifecycle) return null;

  return (
    <div className="mt-4 space-y-2.5">
      {health && health.status !== "complete" && (
        <div className={`rounded-xl border px-4 py-2.5 ${health.status === "degraded" ? "border-amber-700/50 bg-amber-950/40" : "border-slate-700/60 bg-slate-800/40"}`}>
          <div className="flex items-start justify-between gap-3 flex-wrap">
            <p className={`text-xs leading-relaxed min-w-0 ${health.status === "degraded" ? "text-amber-200" : "text-slate-300"}`}>
              <span className="font-bold">{health.status === "degraded" ? "Incomplete scan: " : "Partial coverage: "}</span>
              {describeHealth(health)}
              {health.status === "degraded" && " A rescan normally fixes this."}
            </p>
            {health.gaps.length > 0 && (
              <button onClick={() => setShowGaps(v => !v)} className="shrink-0 text-[11px] font-semibold text-slate-300 hover:text-white underline underline-offset-2">
                {showGaps ? "Hide files" : "Which files?"}
              </button>
            )}
          </div>
          {showGaps && (
            <ul className="mt-2 space-y-1 max-h-48 overflow-auto">
              {health.gaps.map(g => (
                <li key={`${g.file}:${g.reason}`} className="text-[11px] flex gap-2 min-w-0">
                  <code className="font-mono text-slate-200 truncate">{g.file}</code>
                  <span className="text-slate-400 shrink-0">{languageName(g.language)} · {GAP_REASON_TEXT[g.reason]}</span>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      <div className="flex items-center gap-2 flex-wrap">
        {s && (
          <>
            <span className="text-[11px] text-slate-400 font-medium mr-0.5">{lifecycle?.has_previous_scan ? "Since the last push:" : "Findings:"}</span>
            {(["new", "reopened", "existing", "accepted", "false_positive"] as const).filter(k => s[k] > 0).map(k => (
              <span key={k} className={`text-[11px] font-semibold px-2 py-0.5 rounded-full border ${CHIP[k]}`}>{s[k]} {STATUS_LABEL[k].toLowerCase()}</span>
            ))}
            {s.fixed > 0 && (
              <button onClick={() => setShowFixed(v => !v)} className={`text-[11px] font-semibold px-2 py-0.5 rounded-full border ${CHIP.fixed}`}>
                {s.fixed} fixed {showFixed ? "▴" : "▾"}
              </button>
            )}
            {openCount === 0 && s.fixed === 0 && s.accepted + s.false_positive === 0 && <span className="text-[11px] text-slate-500">none</span>}
          </>
        )}
        <span className="flex-1" />
        {telemetry && (
          <span className="text-[11px] text-slate-500 tabular-nums" title={telemetry.slowest.length ? `Slowest: ${telemetry.slowest.map(x => `${x.file} (${fmtMs(x.ms)})`).join(", ")}` : undefined}>
            {fmtMs(telemetry.total_ms)} · {telemetry.files_analyzed} analyzed{telemetry.files_reused ? ` · ${telemetry.files_reused} reused` : ""}
          </span>
        )}
        {olderEngine && (
          <span className="text-[11px] font-semibold text-amber-200 bg-amber-500/10 border border-amber-400/30 px-2 py-0.5 rounded-full" title={`Scanned with engine ${health?.engine_version}; the current engine is ${currentEngineVersion}.`}>
            Older engine
          </span>
        )}
        <button onClick={rescan} disabled={busy !== null}
          className="text-[11px] font-bold text-indigo-100 bg-indigo-500/20 hover:bg-indigo-500/30 border border-indigo-400/30 rounded-lg px-2.5 py-1 disabled:opacity-50 transition-colors">
          {busy === "rescan" ? "Queuing…" : "Rescan"}
        </button>
        {canTriage && openCount > 0 && (
          confirmBaseline ? (
            <span className="flex items-center gap-1.5">
              <span className="text-[11px] text-slate-300">Accept all {openCount} open findings?</span>
              <button onClick={baseline} disabled={busy !== null} className="text-[11px] font-bold text-violet-100 bg-violet-500/30 hover:bg-violet-500/40 border border-violet-400/40 rounded-lg px-2.5 py-1">Accept as baseline</button>
              <button onClick={() => setConfirmBaseline(false)} className="text-[11px] text-slate-400 hover:text-slate-200 px-1">Cancel</button>
            </span>
          ) : (
            <button onClick={() => setConfirmBaseline(true)} disabled={busy !== null}
              className="text-[11px] font-bold text-slate-200 bg-white/5 hover:bg-white/10 border border-white/10 rounded-lg px-2.5 py-1 disabled:opacity-50 transition-colors"
              title="Accept every current finding in this PR, so only new findings block merges from now on.">
              {busy === "baseline" ? "Saving…" : "Baseline"}
            </button>
          )
        )}
      </div>

      {showFixed && lifecycle && lifecycle.fixed.length > 0 && (
        <ul className="rounded-xl border border-emerald-800/40 bg-emerald-950/30 px-4 py-2.5 space-y-1 max-h-48 overflow-auto">
          {lifecycle.fixed.map(f => (
            <li key={f.fingerprint} className="text-[11px] flex gap-2 min-w-0">
              <span className="text-emerald-300 font-semibold shrink-0">✓ {f.label}</span>
              <code className="font-mono text-slate-400 truncate">{f.file_path}{f.line ? `:${f.line}` : ""}</code>
            </li>
          ))}
        </ul>
      )}

      {msg && <p className={`text-[11px] ${msg.ok ? "text-emerald-300" : "text-rose-300"}`}>{msg.text}</p>}
    </div>
  );
}
