"use client";

/**
 * Compliance "Owners & gaps" tab: for one framework, each control's status from verified evidence, the evidence still
 * missing / expired / unverified, who owns it, and the remediation items (the exception register) that respond to it.
 * Also assigns owners and downloads the signed auditor export.
 *
 * Complete evidence is not compliance, and this says so: it shows what TrustLedger has collected, never that a control is met.
 */
import { useCallback, useEffect, useState } from "react";
import { authedFetch, getAuthHeader } from "@/lib/useRealData";

type Status = "satisfied" | "partial" | "missing" | "expired";
type Flag = "no_owner" | "gap_untracked" | "remediation_overdue" | "resolved_but_gap_remains" | "risk_accepted";
interface Gap { evidence_type: string; kind: "missing" | "expired" | "unverified" }
interface Remediation { id: string; title: string; status: string; owner_email: string | null; due_date: string | null; risk_accepted: boolean; overdue: boolean }
interface ControlRow { control_id: string; control_name: string; status: Status; owner: string | null; gaps: Gap[]; remediations: Remediation[]; flags: Flag[] }
interface Report {
  framework_id: string; mapping_version: string; scope_disclaimer: string;
  summary: { controls: number; with_gaps: number; unowned: number; untracked_gaps: number; overdue: number; resolved_but_gap_remains: number };
  controls: ControlRow[];
}

const STATUS: Record<Status, { label: string; cls: string }> = {
  satisfied: { label: "Evidence on file", cls: "bg-emerald-50 text-emerald-700 border-emerald-200" },
  partial: { label: "Partly evidenced", cls: "bg-amber-50 text-amber-800 border-amber-200" },
  missing: { label: "No evidence", cls: "bg-rose-50 text-rose-700 border-rose-200" },
  expired: { label: "Evidence expired", cls: "bg-orange-50 text-orange-800 border-orange-200" },
};
const FLAG: Record<Flag, { text: string; cls: string }> = {
  no_owner: { text: "No owner", cls: "bg-gray-100 text-gray-700" },
  gap_untracked: { text: "Gap nobody is working on", cls: "bg-rose-50 text-rose-700" },
  remediation_overdue: { text: "Remediation overdue", cls: "bg-rose-50 text-rose-700" },
  resolved_but_gap_remains: { text: "Marked resolved, but the evidence is still missing", cls: "bg-amber-50 text-amber-800" },
  risk_accepted: { text: "Risk accepted", cls: "bg-sky-50 text-sky-700" },
};
const GAP: Record<Gap["kind"], { label: string; cls: string }> = {
  missing: { label: "missing", cls: "bg-rose-50 text-rose-700" },
  expired: { label: "expired", cls: "bg-orange-50 text-orange-800" },
  unverified: { label: "failed verification", cls: "bg-rose-100 text-rose-800" },
};
const humanize = (s: string) => s.replace(/_/g, " ").replace(/\bpr\b/g, "PR").replace(/^./, c => c.toUpperCase());
const fmtDue = (iso: string | null) => (iso ? new Date(iso + "T00:00:00Z").toLocaleDateString("en-GB", { day: "numeric", month: "short", year: "numeric", timeZone: "UTC" }) : "no due date");

export default function ControlGaps({ framework, frameworkName, color, members, canEdit, canExport, currentEmail }: {
  framework: string; frameworkName: string; color: string; members: string[]; canEdit: boolean; canExport: boolean;
  /** The signed-in user, so the controls they own can be pointed out and filtered to. Nobody is notified. */
  currentEmail?: string | null;
}) {
  const [onlyMine, setOnlyMine] = useState(false);
  const [report, setReport] = useState<Report | null>(null);
  const [failed, setFailed] = useState(false);
  const [denied, setDenied] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState<string | null>(null);
  const [downloading, setDownloading] = useState(false);

  const load = useCallback(async () => {
    setFailed(false); setDenied(false);
    try { setReport(await authedFetch<Report>(`/api/evidence/gaps?framework=${encodeURIComponent(framework)}`)); }
    catch (e) {
      // 403: not a glitch to retry. The report lists owners and remediation, which needs the "Export data" permission.
      if ((e as { status?: number } | null)?.status === 403) setDenied(true); else setFailed(true);
    }
  }, [framework]);
  useEffect(() => { setReport(null); load(); }, [load]);

  async function setOwner(controlId: string, email: string) {
    setSaving(controlId); setError(null);
    try {
      if (email) await authedFetch("/api/evidence/controls", { method: "PUT", body: JSON.stringify({ framework, control_id: controlId, owner_email: email }) });
      else await authedFetch(`/api/evidence/controls?framework=${encodeURIComponent(framework)}&control_id=${encodeURIComponent(controlId)}`, { method: "DELETE" });
      await load();
    } catch (e) { setError(e instanceof Error ? e.message : "The owner couldn't be saved. Please try again."); }
    setSaving(null);
  }

  async function download() {
    setDownloading(true); setError(null);
    try {
      const res = await fetch(`/api/evidence/export?framework=${encodeURIComponent(framework)}`, { headers: await getAuthHeader() });
      if (!res.ok) throw new Error();
      const url = URL.createObjectURL(await res.blob());
      Object.assign(document.createElement("a"), { href: url, download: `evidence-export-${framework}.json` }).click();
      setTimeout(() => URL.revokeObjectURL(url), 1000);
    } catch { setError("The auditor export couldn't be downloaded. Please try again."); }
    setDownloading(false);
  }

  if (denied) return <div role="alert" className="section-card p-5 text-sm text-gray-700">You don&apos;t have permission to view control owners and gaps. It needs the &ldquo;Export data&rdquo; permission: ask an admin of your organisation.</div>;
  if (failed) return <div className="section-card p-5 text-sm text-rose-700">Couldn&apos;t load owners and gaps. <button onClick={load} className="font-bold underline">Try again</button></div>;
  if (!report) return <div className="section-card h-48 animate-pulse" aria-label="Loading owners and gaps" />;
  const s = report.summary;
  const ownerChoices = (current: string | null) => [...new Set([...(current ? [current] : []), ...members])].sort();
  const me = currentEmail?.trim().toLowerCase() || null;
  const mine = me ? report.controls.filter(c => c.owner?.toLowerCase() === me) : [];
  const needAttention = mine.filter(c => c.gaps.length > 0 || c.flags.includes("remediation_overdue"));
  const shown = onlyMine ? mine : report.controls;

  return (
    <div className="animate-fade-up space-y-4">
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div className="max-w-2xl">
          <p className="text-sm font-bold text-gray-900">Owners and gaps · {frameworkName}</p>
          <p className="text-xs text-gray-500 mt-0.5">
            Who is responsible for each control, what evidence is still missing, and who is working on it. This counts the evidence records collected for
            each control (not the live scan measurements on the other tabs), and only records whose hash still verifies. Mapping version {report.mapping_version}.
          </p>
        </div>
        {canExport && (
          <button onClick={download} disabled={downloading} className="px-3 py-2 text-xs font-bold text-indigo-700 bg-indigo-50 border border-indigo-200 rounded-xl hover:bg-indigo-100 disabled:opacity-50"
            title="A signed JSON package for your auditor. Verify it offline with scripts/verify-evidence-export.cjs.">
            {downloading ? "Preparing…" : "Download signed auditor export"}
          </button>
        )}
      </div>

      <div role="note" className="rounded-xl border px-4 py-3 text-xs text-gray-700 leading-relaxed" style={{ borderColor: `${color}40`, background: `${color}0d` }}>
        <strong>This is not a compliance verdict.</strong> Evidence on file means TrustLedger has collected the supporting records; it does not mean a control is met. {report.scope_disclaimer}
      </div>

      {error && <p role="alert" className="text-xs text-rose-700 bg-rose-50 border border-rose-200 rounded-xl px-4 py-2.5">{error}</p>}

      <dl className="grid grid-cols-2 sm:grid-cols-5 gap-3" aria-label="Summary">
        {([["Controls", s.controls], ["With evidence gaps", s.with_gaps], ["No owner", s.unowned], ["Gaps nobody is working on", s.untracked_gaps], ["Remediation overdue", s.overdue]] as const).map(([label, n]) => (
          <div key={label} className="section-card px-4 py-3">
            <dt className="text-[10px] font-black uppercase tracking-widest text-gray-400">{label}</dt>
            <dd className="text-2xl font-black tabular-nums text-gray-900 mt-1">{n}</dd>
          </div>
        ))}
      </dl>

      {me && (mine.length > 0 || onlyMine) && (
        <section aria-label="Your controls" className="section-card px-5 py-3 flex flex-wrap items-center justify-between gap-3">
          <p className="text-xs text-gray-700">
            {mine.length === 0
              ? "You don't own any controls in this framework."
              : <>You own <strong>{mine.length}</strong> {mine.length === 1 ? "control" : "controls"}
                  {needAttention.length > 0
                    ? <>: <strong className="text-rose-700">{needAttention.length}</strong> {needAttention.length === 1 ? "needs" : "need"} attention (evidence gaps or overdue remediation).</>
                    : ", and none has evidence gaps or overdue remediation."}</>}
          </p>
          <div role="group" aria-label="Which controls to show" className="flex items-center gap-1 bg-gray-100 p-0.5 rounded-lg">
            {([[false, `All controls (${report.controls.length})`], [true, `Mine (${mine.length})`]] as const).map(([value, label]) => (
              <button key={label} aria-pressed={onlyMine === value} onClick={() => setOnlyMine(value)}
                className={`px-3 py-1.5 text-[11px] font-semibold rounded-md transition-all ${onlyMine === value ? "bg-white text-gray-900 shadow-sm" : "text-gray-500 hover:text-gray-700"}`}>{label}</button>
            ))}
          </div>
        </section>
      )}

      <div className="space-y-3">
        {shown.map(c => (
          <article key={c.control_id} className="section-card px-5 py-4" aria-label={`Control ${c.control_id}`}>
            <div className="flex items-start justify-between gap-3 flex-wrap">
              <div className="flex items-start gap-3 min-w-0">
                <span className="text-[11px] font-black font-mono px-2 py-1 rounded-lg shrink-0" style={{ background: `${color}12`, color, border: `1px solid ${color}30` }}>{c.control_id}</span>
                <div className="min-w-0">
                  <p className="text-sm font-bold text-gray-900 leading-snug">{c.control_name}</p>
                  <span className={`inline-block mt-1 text-[10px] font-bold px-2 py-0.5 rounded-full border ${STATUS[c.status].cls}`}>{STATUS[c.status].label}</span>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <label htmlFor={`owner-${c.control_id}`} className="text-[10px] font-semibold text-gray-500">Owner</label>
                {canEdit ? (
                  <select id={`owner-${c.control_id}`} value={c.owner ?? ""} disabled={saving === c.control_id} onChange={e => setOwner(c.control_id, e.target.value)}
                    className="text-xs border border-gray-200 rounded-lg px-2 py-1.5 text-gray-700 bg-white max-w-[14rem] disabled:opacity-50">
                    <option value="">Unassigned</option>
                    {ownerChoices(c.owner).map(m => <option key={m} value={m}>{m}</option>)}
                  </select>
                ) : (
                  <span id={`owner-${c.control_id}`} className="text-xs text-gray-700">{c.owner ?? "Unassigned"}</span>
                )}
              </div>
            </div>

            {c.gaps.length > 0 && (
              <ul aria-label="Evidence gaps" className="flex flex-wrap gap-1.5 mt-3">
                {c.gaps.map(g => (
                  <li key={`${g.evidence_type}-${g.kind}`} className={`text-[11px] font-semibold px-2 py-0.5 rounded-full ${GAP[g.kind].cls}`}>{humanize(g.evidence_type)}: {GAP[g.kind].label}</li>
                ))}
              </ul>
            )}

            {c.flags.filter(f => f !== "no_owner").length > 0 && (
              <ul aria-label="Attention" className="flex flex-wrap gap-1.5 mt-2">
                {c.flags.filter(f => f !== "no_owner").map(f => <li key={f} className={`text-[11px] font-bold px-2 py-0.5 rounded-full ${FLAG[f].cls}`}>{FLAG[f].text}</li>)}
              </ul>
            )}

            {c.remediations.length > 0 && (
              <ul aria-label="Remediation" className="mt-3 divide-y divide-gray-100 border-t border-gray-100">
                {c.remediations.map(r => (
                  <li key={r.id} className="py-2 flex flex-wrap items-center justify-between gap-2 text-xs">
                    <span className="font-semibold text-gray-800">{r.title}</span>
                    <span className="text-gray-500">
                      {r.status.replace("-", " ")} · {r.owner_email ?? "no owner"} · due {fmtDue(r.due_date)}
                      {r.overdue && <strong className="text-rose-600"> · overdue</strong>}
                      {r.risk_accepted && <strong className="text-sky-700"> · risk accepted</strong>}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </article>
        ))}
      </div>
    </div>
  );
}
