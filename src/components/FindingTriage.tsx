"use client";

/**
 * A finding's lifecycle status chip and its triage actions (accept risk / mark false positive / reopen),
 * backed by /api/findings/triage (see lib/findingLifecycle.ts). The PR page provides the repo, whether the
 * viewer may triage, and a callback that updates its copy of the scan -- through a context, so the code
 * viewer in between doesn't need new props. Outside that provider, nothing renders.
 */
import { createContext, useContext, useState } from "react";
import { authedFetch } from "@/lib/useRealData";
import { STATUS_LABEL, EXPIRY_CHOICES, isActive, type FindingStatus, type TriageDecision, type TriageStatus } from "@/lib/findingLifecycle";
import type { FileIndicator } from "@/types";

export interface FindingTriageContextValue {
  repo: string;
  canTriage: boolean;
  /** Record a decision (or its removal) locally after the API accepted it. */
  onDecision: (fingerprint: string, decision: TriageDecision | null) => void;
}

export const FindingTriageContext = createContext<FindingTriageContextValue | null>(null);

const CHIP = "inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[10px] font-semibold ring-1 whitespace-nowrap";
const STATUS_STYLE: Record<FindingStatus, string> = {
  new: "bg-sky-500/15 text-sky-200 ring-sky-400/30",
  reopened: "bg-orange-500/15 text-orange-200 ring-orange-400/30",
  existing: "bg-white/5 text-slate-300 ring-white/10",
  accepted: "bg-violet-500/15 text-violet-200 ring-violet-400/30",
  false_positive: "bg-slate-500/20 text-slate-200 ring-slate-400/30",
};
const STATUS_DESC: Record<FindingStatus, string> = {
  new: "Not in this PR's previous push",
  reopened: "Came back after it had disappeared, or its accepted-risk decision expired",
  existing: "Also in this PR's previous push",
  accepted: "Risk accepted: recorded, but doesn't block merges",
  false_positive: "Marked as a false positive: recorded, but doesn't block merges",
};

const fmtDate = (iso: string) => new Date(iso).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });

/** Is this finding currently suppressed by a decision? */
export function isSuppressedFinding(ind: FileIndicator): boolean {
  return isActive(ind.triage);
}

export function FindingStatusChip({ ind }: { ind: FileIndicator }) {
  const ctx = useContext(FindingTriageContext);
  const status = ind.lifecycle_status;
  if (!ctx || !status) return null;
  const d = ind.triage;
  const title = d && isActive(d)
    ? `${STATUS_DESC[status]}. ${d.reason ? `“${d.reason}”` : ""}${d.set_by_email ? ` — ${d.set_by_email}` : ""}${d.expires_at ? `, until ${fmtDate(d.expires_at)}` : ""}`
    : STATUS_DESC[status];
  return <span className={`${CHIP} ${STATUS_STYLE[status]}`} title={title}>{STATUS_LABEL[status]}</span>;
}

/** The triage panel for one finding: record a decision, or reopen one. */
export function FindingTriagePanel({ ind, filePath }: { ind: FileIndicator; filePath: string }) {
  const ctx = useContext(FindingTriageContext);
  const [status, setStatus] = useState<TriageStatus>("accepted");
  const [reason, setReason] = useState("");
  const [expiry, setExpiry] = useState<number | null>(90);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  if (!ctx || !ind.fingerprint) return null;
  const active = isActive(ind.triage) ? ind.triage : undefined;
  const idBase = `triage-${ind.fingerprint}`;

  if (!ctx.canTriage) {
    return <p className="text-[11px] text-slate-400">Only security reviewers and admins can accept risk or mark false positives.</p>;
  }

  async function save() {
    if (reason.trim().length < 3) { setErr("Give a short reason, so the decision makes sense later."); return; }
    setBusy(true); setErr(null);
    try {
      const r = await authedFetch<{ decision: { status: TriageStatus; reason: string; expires_at: string | null; set_by_email: string | null } }>("/api/findings/triage", {
        method: "POST",
        body: JSON.stringify({ repo: ctx!.repo, fingerprint: ind.fingerprint, rule_id: ind.id, file_path: filePath, status, reason: reason.trim(), expires_in_days: expiry }),
      });
      ctx!.onDecision(ind.fingerprint!, { ...r.decision, set_at: new Date().toISOString() });
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Couldn't save the decision.");
    } finally { setBusy(false); }
  }

  async function reopen() {
    setBusy(true); setErr(null);
    try {
      await authedFetch("/api/findings/triage", { method: "DELETE", body: JSON.stringify({ repo: ctx!.repo, fingerprint: ind.fingerprint }) });
      ctx!.onDecision(ind.fingerprint!, null);
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Couldn't reopen the finding.");
    } finally { setBusy(false); }
  }

  if (active) {
    return (
      <div className="space-y-2">
        <p className="text-[12px] text-slate-300">
          {active.status === "accepted" ? "Risk accepted" : "Marked as a false positive"}
          {active.set_by_email ? <> by <span className="text-slate-100">{active.set_by_email}</span></> : null} on {fmtDate(active.set_at)}
          {active.expires_at ? <>, until {fmtDate(active.expires_at)}</> : <>, with no expiry</>}.
        </p>
        {active.reason && <p className="text-[12px] text-slate-400 italic">“{active.reason}”</p>}
        <p className="text-[11px] text-slate-500">It stays visible here but doesn&apos;t block merges. It applies to the merge check from the next scan.</p>
        <button onClick={reopen} disabled={busy}
          className="text-[11px] font-bold text-orange-100 bg-orange-500/20 hover:bg-orange-500/30 ring-1 ring-orange-400/30 rounded-lg px-2.5 py-1 disabled:opacity-50">
          {busy ? "Reopening…" : "Reopen"}
        </button>
        {err && <p className="text-[11px] text-rose-300">{err}</p>}
      </div>
    );
  }

  return (
    <div className="space-y-2.5">
      <div className="flex flex-wrap gap-1.5" role="radiogroup" aria-label="Decision">
        {(["accepted", "false_positive"] as const).map(s => (
          <button key={s} role="radio" aria-checked={status === s} onClick={() => setStatus(s)}
            className={`text-[11px] font-semibold rounded-lg px-2.5 py-1 ring-1 transition-colors ${status === s ? "bg-violet-500/25 text-violet-100 ring-violet-400/40" : "bg-white/5 text-slate-300 ring-white/10 hover:bg-white/10"}`}>
            {s === "accepted" ? "Accept risk" : "False positive"}
          </button>
        ))}
      </div>
      <label htmlFor={`${idBase}-reason`} className="block text-[11px] text-slate-400">Reason</label>
      <textarea id={`${idBase}-reason`} value={reason} onChange={e => setReason(e.target.value)} rows={2} maxLength={2000}
        placeholder={status === "accepted" ? "e.g. Internal admin tool, only reachable from the VPN" : "e.g. The value is an enum validated by the router"}
        className="w-full rounded-lg bg-slate-950/60 ring-1 ring-white/10 px-2.5 py-1.5 text-[12px] text-slate-100 placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-violet-400/50" />
      <div className="flex flex-wrap items-center gap-2">
        <label htmlFor={`${idBase}-expiry`} className="text-[11px] text-slate-400">Expires</label>
        <select id={`${idBase}-expiry`} value={expiry ?? ""} onChange={e => setExpiry(e.target.value ? Number(e.target.value) : null)}
          className="rounded-lg bg-slate-950/60 ring-1 ring-white/10 px-2 py-1 text-[11px] text-slate-100">
          {EXPIRY_CHOICES.map(c => <option key={c.label} value={c.days ?? ""}>{c.label}</option>)}
        </select>
        <span className="flex-1" />
        <button onClick={save} disabled={busy}
          className="text-[11px] font-bold text-violet-100 bg-violet-500/30 hover:bg-violet-500/40 ring-1 ring-violet-400/40 rounded-lg px-3 py-1 disabled:opacity-50">
          {busy ? "Saving…" : "Save decision"}
        </button>
      </div>
      <p className="text-[11px] text-slate-500">The finding stays visible, stops blocking merges from the next scan, and comes back as reopened when the decision expires.</p>
      {err && <p className="text-[11px] text-rose-300">{err}</p>}
    </div>
  );
}

/** Whether a Triage toggle should appear at all (inside the provider, on a fingerprinted finding). */
export function useCanShowTriage(ind: FileIndicator): boolean {
  const ctx = useContext(FindingTriageContext);
  return !!ctx && !!ind.fingerprint;
}
