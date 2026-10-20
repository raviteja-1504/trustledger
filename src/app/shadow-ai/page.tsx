"use client";

/**
 * Shadow AI: which AI coding tools the team actually uses, against the org's approved-tools policy.
 *
 * Everything here is server-backed (/api/shadow-ai): detections come from stored scan evidence, and the policy,
 * triage status and notes are saved per organisation and audit-logged. Only EXPLICIT evidence of an unapproved
 * tool is a violation; style-based guesses are shown as hints. See lib/shadowAi.ts.
 */

import { useState, useEffect, useMemo, useCallback } from "react";
import AuthGuard from "@/components/AuthGuard";
import PageSkeleton from "@/components/PageSkeleton";
import InfoTooltip from "@/components/InfoTooltip";
import { authedFetch, isSeedMode } from "@/lib/useRealData";
import { useAuth } from "@/lib/auth";
import { relativeTime, formatDateOnly, useTimezone } from "@/lib/timezone";
import { AI_TOOLS, type AiTool } from "@/lib/aiTools";
import { buildDetections, summarize, approvalOf, type Detection, type ShadowSummary, type ShadowStatus, type ScanRow } from "@/lib/shadowAi";

interface Policy { allowed: string[]; updated_at?: string; updated_by?: string | null }
interface ShadowResponse { policy: Policy | null; tools: AiTool[]; detections: Detection[]; summary: ShadowSummary; window_days: number; scope: "own" | "org"; truncated?: boolean }

const STATUS_STYLE: Record<ShadowStatus, { bg: string; text: string; border: string; label: string }> = {
  open:          { bg: "#fef2f2", text: "#be123c", border: "#fecdd3", label: "Open" },
  investigating: { bg: "#fffbeb", text: "#b45309", border: "#fde68a", label: "Investigating" },
  acceptable:    { bg: "#f0f9ff", text: "#0369a1", border: "#bae6fd", label: "Accepted" },
  resolved:      { bg: "#f0fdf4", text: "#15803d", border: "#bbf7d0", label: "Resolved" },
};
const APPROVAL_STYLE = {
  approved:     { cls: "bg-green-50 text-green-700 border-green-200", label: "Approved" },
  unapproved:   { cls: "bg-rose-50 text-rose-700 border-rose-200", label: "Not approved" },
  unreviewed:   { cls: "bg-gray-50 text-gray-600 border-gray-200", label: "Not reviewed" },
  unidentified: { cls: "bg-amber-50 text-amber-700 border-amber-200", label: "Unidentified" },
} as const;

// ── Demo data (seed mode only) ──────────────────────────────────────────────────
function demoResponse(): ShadowResponse {
  const day = (n: number) => new Date(Date.now() - n * 86400_000).toISOString();
  const scans: ScanRow[] = [
    { id: "d1", repo_full_name: "acme/payments-api", pr_number: 482, pr_author: "priya-dev", created_at: day(1), ai_tooling: [{ tool: "Cursor", file: ".cursorrules", label: "Cursor AI agent rules file" }, { tool: "cursor", file: "commit:9f2c1a4", label: "Cursor co-author trailer on commit" }] },
    { id: "d2", repo_full_name: "acme/auth-service", pr_number: 345, pr_author: "sam-eng", created_at: day(2), ai_tooling: [{ tool: "GitHub Copilot", file: ".github/copilot-instructions.md", label: "Copilot custom instructions" }] },
    { id: "d3", repo_full_name: "acme/fraud-detection", pr_number: 219, pr_author: "lee-ml", created_at: day(3), ai_tooling: [{ tool: "claude", file: "commit:3b7e0d2", label: "Claude co-author trailer on commit" }, { tool: "AI Agents", file: "AGENTS.md", label: "Generic AI agent instructions" }] },
  ];
  const policy = { allowed: ["github-copilot", "claude"] };
  const detections = buildDetections(scans, [{ scan_id: "d2", file_path: "src/token.ts", attribution: { model: "chatgpt", confidence: 0.72 } }], policy.allowed, new Map());
  return { policy, tools: [...AI_TOOLS], detections, summary: summarize(detections, policy.allowed), window_days: 30, scope: "org" };
}

export default function ShadowAIPage() {
  const tz = useTimezone();
  const { profile } = useAuth();
  const canEditPolicy = !!profile?.permissions?.can_manage_policies;
  const canTriage = !!profile?.permissions?.can_resolve_violations;
  const demo = isSeedMode();

  const [days, setDays] = useState(30);
  const [data, setData] = useState<ShadowResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState<string[]>([]);
  const [saving, setSaving] = useState(false);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [noteInput, setNoteInput] = useState<Record<string, string>>({});
  const [statusFilter, setStatusFilter] = useState<ShadowStatus | "all">("all");
  const [showHints, setShowHints] = useState(false);

  const load = useCallback(async () => {
    setLoading(true); setError(null);
    if (demo) { setData(demoResponse()); setLoading(false); return; }
    try { setData(await authedFetch<ShadowResponse>(`/api/shadow-ai?days=${days}`)); }
    catch (e) { setError((e as Error).message || "We couldn't load Shadow AI data. Please try again."); }
    finally { setLoading(false); }
  }, [days, demo]);
  useEffect(() => { void load(); }, [load]);

  const detections = useMemo(() => data?.detections ?? [], [data]);
  const violations = useMemo(() => detections.filter(d => d.violation && (statusFilter === "all" || d.status === statusFilter)), [detections, statusFilter]);
  const needsReview = useMemo(() => detections.filter(d => d.tier === "explicit" && (d.approval === "unidentified" || d.approval === "unreviewed")), [detections]);
  const approved = useMemo(() => detections.filter(d => d.tier === "explicit" && d.approval === "approved"), [detections]);
  const hints = useMemo(() => detections.filter(d => d.tier === "hint"), [detections]);
  const s = data?.summary;

  async function savePolicy() {
    setSaving(true); setError(null);
    try {
      if (demo) {
        if (data) {
          const det = data.detections.map(d => {
            const approval = approvalOf(d.tool, draft);
            return { ...d, approval, violation: d.tier === "explicit" && approval === "unapproved" };
          });
          setData({ ...data, policy: { allowed: draft }, detections: det, summary: summarize(det, draft) });
        }
        setEditing(false);
        return;
      }
      await authedFetch("/api/shadow-ai", { method: "PUT", body: JSON.stringify({ allowed: draft }) });
      setEditing(false);
      await load();
    } catch (e) { setError((e as Error).message || "Saving the policy failed."); }
    finally { setSaving(false); }
  }

  async function triage(key: string, patch: { status?: ShadowStatus; note?: string }) {
    if (demo) return;
    try {
      const res = await authedFetch<{ status: ShadowStatus; notes: Detection["notes"] }>("/api/shadow-ai", { method: "PATCH", body: JSON.stringify({ key, ...patch }) });
      setData(prev => prev && ({ ...prev, detections: prev.detections.map(d => d.key === key ? { ...d, status: res.status, notes: res.notes, reopened: false } : d) }));
      if (patch.note) setNoteInput(p => ({ ...p, [key]: "" }));
    } catch (e) { setError((e as Error).message || "Saving failed."); }
  }

  function exportCSV() {
    const rows = [["Tool", "Approval", "Evidence type", "Repository", "Location", "Developers", "Pull requests", "First seen", "Last seen", "Status", "Evidence"],
      ...detections.map(d => [d.tool_label, d.approval, d.tier, d.repo, d.location, d.developers.join(" "), d.pull_requests.join(" "), d.first_seen, d.last_seen, d.status, d.evidence.join("; ")])];
    const csv = rows.map(r => r.map(c => `"${String(c).replace(/"/g, '""')}"`).join(",")).join("\n");
    Object.assign(document.createElement("a"), { href: URL.createObjectURL(new Blob([csv], { type: "text/csv" })), download: `shadow-ai-${days}d.csv` }).click();
  }

  if (loading && !data) return <AuthGuard><PageSkeleton loading label="AI tool usage" rows={4} cards={5} /></AuthGuard>;

  const policy = data?.policy ?? null;
  const pct = (v: number | null | undefined) => v == null ? "—" : `${Math.round(v * 100)}%`;

  return (
    <AuthGuard>
      <div className="max-w-7xl mx-auto space-y-5 pb-10">

        {/* Header */}
        <div className="animate-fade-up flex items-start justify-between gap-4 flex-wrap">
          <div>
            <div className="flex items-center gap-2.5 mb-1">
              <h1 className="text-xl font-black text-gray-900 tracking-tight">Shadow AI</h1>
              {!!s?.open_violations && <span className="text-xs font-black text-white bg-rose-500 px-2 py-0.5 rounded-full">{s.open_violations} open</span>}
              {demo && <span className="text-[10px] font-bold text-amber-700 bg-amber-50 border border-amber-200 px-2 py-0.5 rounded-full">Demo data</span>}
            </div>
            <p className="text-sm text-gray-500 max-w-2xl">
              AI coding tools your team actually uses, from evidence in pull requests: tool config files, attribution markers in code, and AI-signed commits.
              {data?.scope === "own" && " You are seeing your own pull requests only."}
            </p>
          </div>
          <div className="flex items-center gap-2">
            <div className="flex items-center gap-0.5 bg-gray-100 p-0.5 rounded-xl">
              {[7, 30, 90].map(n => (
                <button key={n} onClick={() => setDays(n)}
                  className={`px-3 py-1.5 text-xs font-semibold rounded-lg ${days === n ? "bg-white text-gray-900 shadow-sm" : "text-gray-500 hover:text-gray-700"}`}>{n} days</button>
              ))}
            </div>
            <button onClick={exportCSV} disabled={!detections.length}
              className="px-3 py-2 text-xs font-semibold text-gray-600 bg-white border border-gray-200 rounded-xl hover:bg-gray-50 disabled:opacity-40 shadow-sm">Export CSV</button>
            {canEditPolicy && (
              <button onClick={() => { setDraft(policy?.allowed ?? []); setEditing(true); }}
                className="px-4 py-2 text-xs font-bold rounded-xl bg-indigo-600 text-white hover:bg-indigo-700 shadow-sm">Approved tools</button>
            )}
          </div>
        </div>

        {error && <div className="bg-rose-50 border border-rose-200 text-rose-700 text-xs font-semibold rounded-xl px-4 py-2.5">{error}</div>}

        {/* No policy yet */}
        {!policy && !editing && (
          <div className="animate-fade-up bg-indigo-50 border border-indigo-200 rounded-2xl p-5 flex items-center justify-between gap-4 flex-wrap">
            <div>
              <p className="font-bold text-indigo-900 text-sm">No approved-tools policy yet</p>
              <p className="text-xs text-indigo-700 mt-0.5">Nothing is flagged as Shadow AI until your organisation chooses which AI tools are approved.
                {!canEditPolicy && " Ask someone who can manage policies to set it."}</p>
            </div>
            {canEditPolicy && <button onClick={() => { setDraft([]); setEditing(true); }} className="px-4 py-2 text-xs font-bold rounded-xl bg-indigo-600 text-white hover:bg-indigo-700">Choose approved tools</button>}
          </div>
        )}

        {/* Policy editor */}
        {editing && (
          <div className="animate-fade-up bg-white border border-indigo-200 rounded-2xl p-5">
            <p className="font-bold text-gray-900 mb-1">Approved AI tools</p>
            <p className="text-xs text-gray-500 mb-4">Explicit evidence of any other tool will be flagged as Shadow AI. Pull requests get a warning on their check; merges are not blocked. Changes are recorded in the audit log.</p>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2.5 mb-4">
              {(data?.tools ?? AI_TOOLS).map(t => (
                <label key={t.id} className={`flex items-center gap-3 p-3 rounded-xl cursor-pointer border ${draft.includes(t.id) ? "bg-indigo-50 border-indigo-300" : "bg-white border-gray-200"}`}>
                  <input type="checkbox" checked={draft.includes(t.id)} onChange={e => setDraft(p => e.target.checked ? [...p, t.id] : p.filter(x => x !== t.id))} className="w-4 h-4 accent-indigo-600" />
                  <div><div className="font-bold text-sm text-gray-900">{t.label}</div><div className="text-xs text-gray-500">{t.vendor}</div></div>
                </label>
              ))}
            </div>
            <div className="flex gap-3">
              <button onClick={savePolicy} disabled={saving} className="px-4 py-2 bg-indigo-600 text-white text-sm font-bold rounded-xl hover:bg-indigo-700 disabled:opacity-50">{saving ? "Saving…" : "Save policy"}</button>
              <button onClick={() => setEditing(false)} className="px-4 py-2 bg-white border border-gray-200 text-sm font-bold rounded-xl hover:bg-gray-50">Cancel</button>
            </div>
          </div>
        )}

        {/* Stats */}
        {s && (
          <div className="animate-fade-up grid grid-cols-2 sm:grid-cols-5 gap-3">
            {[
              { label: "Open violations", value: s.open_violations, color: s.open_violations ? "#dc2626" : "#16a34a", info: "Explicit evidence of an unapproved tool, still open or under investigation." },
              { label: "Policy compliance", value: pct(s.compliance), color: "#4338ca", info: "Share of explicit AI-tool evidence that is for approved tools. Accepted and resolved violations are excluded." },
              { label: "Tools in use", value: s.by_tool.filter(t => t.detections > 0).length, color: "#0f766e", info: "Distinct AI tools with evidence in this window, including hints." },
              { label: "Developers affected", value: s.developers_with_violations, color: "#b45309", info: "Pull request authors with at least one open violation." },
              { label: "Needs review", value: s.unidentified + (s.policy_configured ? 0 : s.unreviewed), color: "#92400e", info: "AI use with no identifiable tool (e.g. AGENTS.md), or tools nobody has approved or rejected yet." },
            ].map(c => (
              <div key={c.label} className="rounded-2xl p-4 border border-gray-200 bg-white">
                <p className="text-2xl font-black tabular-nums" style={{ color: c.color }}>{c.value}</p>
                <div className="flex items-center gap-1.5 mt-1"><p className="text-xs font-semibold text-gray-500">{c.label}</p><InfoTooltip title={c.label} description={c.info} position="top" /></div>
              </div>
            ))}
          </div>
        )}

        {/* Tools in use */}
        {s && s.by_tool.length > 0 && (
          <div className="animate-fade-up section-card overflow-hidden">
            <div className="px-5 py-3 border-b border-gray-100 bg-gray-50"><p className="text-xs font-black text-gray-700 uppercase tracking-wider">AI tools in use · last {data?.window_days} days</p></div>
            <table className="w-full text-sm">
              <thead><tr className="text-left text-xs text-gray-500 border-b border-gray-100"><th className="px-5 py-2 font-semibold">Tool</th><th className="px-3 py-2 font-semibold">Policy</th><th className="px-3 py-2 font-semibold text-right">Detections</th><th className="px-5 py-2 font-semibold text-right">Violations</th></tr></thead>
              <tbody>
                {s.by_tool.map(t => (
                  <tr key={t.tool} className="border-b border-gray-50 last:border-0">
                    <td className="px-5 py-2.5 font-bold text-gray-900">{t.label}</td>
                    <td className="px-3 py-2.5"><span className={`text-[11px] font-bold px-2 py-0.5 rounded-full border ${APPROVAL_STYLE[t.approval].cls}`}>{APPROVAL_STYLE[t.approval].label}</span></td>
                    <td className="px-3 py-2.5 text-right tabular-nums text-gray-700">{t.detections}</td>
                    <td className={`px-5 py-2.5 text-right tabular-nums font-bold ${t.violations ? "text-rose-600" : "text-gray-400"}`}>{t.violations}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Violations */}
        {detections.some(d => d.violation) && (
          <div className="animate-fade-up section-card overflow-hidden border-2 border-rose-200">
            <div className="px-5 py-3 border-b border-rose-100 bg-rose-50 flex items-center justify-between gap-3 flex-wrap">
              <p className="text-xs font-black text-rose-700 uppercase tracking-wider">Unapproved AI tools</p>
              <select value={statusFilter} onChange={e => setStatusFilter(e.target.value as ShadowStatus | "all")}
                className="text-xs font-semibold text-gray-600 bg-white border border-gray-200 rounded-lg px-2.5 py-1.5">
                <option value="all">All statuses</option>
                {(Object.keys(STATUS_STYLE) as ShadowStatus[]).map(k => <option key={k} value={k}>{STATUS_STYLE[k].label}</option>)}
              </select>
            </div>
            {violations.length === 0 ? <p className="py-8 text-center text-sm text-gray-500">No violations with this status</p> : (
              <div className="divide-y divide-gray-50">
                {violations.map(d => <DetectionRow key={d.key} d={d} tz={tz} open={expanded === d.key} onToggle={() => setExpanded(expanded === d.key ? null : d.key)}
                  canTriage={canTriage && !demo} onTriage={triage} note={noteInput[d.key] ?? ""} setNote={v => setNoteInput(p => ({ ...p, [d.key]: v }))} />)}
              </div>
            )}
          </div>
        )}

        {/* Needs review */}
        {needsReview.length > 0 && (
          <div className="animate-fade-up section-card overflow-hidden">
            <div className="px-5 py-3 border-b border-gray-100 bg-amber-50"><p className="text-xs font-black text-amber-800 uppercase tracking-wider">Needs review · {needsReview.length}</p></div>
            <div className="divide-y divide-gray-50">
              {needsReview.map(d => <DetectionRow key={d.key} d={d} tz={tz} open={expanded === d.key} onToggle={() => setExpanded(expanded === d.key ? null : d.key)}
                canTriage={canTriage && !demo} onTriage={triage} note={noteInput[d.key] ?? ""} setNote={v => setNoteInput(p => ({ ...p, [d.key]: v }))} />)}
            </div>
          </div>
        )}

        {/* Approved usage */}
        {approved.length > 0 && (
          <div className="animate-fade-up section-card overflow-hidden">
            <div className="px-5 py-3 border-b border-gray-100 bg-gray-50 flex items-center justify-between">
              <p className="text-xs font-black text-gray-700 uppercase tracking-wider">Approved AI usage</p>
              <span className="text-xs bg-green-100 text-green-700 px-2 py-0.5 rounded-full font-bold">{approved.length}</span>
            </div>
            <div className="divide-y divide-gray-50">
              {approved.slice(0, 10).map(d => (
                <div key={d.key} className="px-5 py-2.5 flex items-center gap-3 text-xs">
                  <span className="font-bold text-gray-900 w-44 shrink-0">{d.tool_label}</span>
                  <span className="font-mono text-gray-500 truncate flex-1">{d.repo} · {d.location}</span>
                  <span className="text-gray-400 shrink-0">{relativeTime(d.last_seen, tz)}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Hints */}
        {hints.length > 0 && (
          <div className="animate-fade-up section-card overflow-hidden">
            <button onClick={() => setShowHints(v => !v)} className="w-full px-5 py-3 border-b border-gray-100 bg-gray-50 flex items-center justify-between text-left">
              <span className="text-xs font-black text-gray-500 uppercase tracking-wider">Style-based hints · {hints.length}</span>
              <span className="text-xs text-gray-400">{showHints ? "Hide" : "Show"}</span>
            </button>
            {showHints && (
              <>
                <p className="px-5 pt-3 text-xs text-gray-500">The scanner's guess at which tool's style a file resembles. Style-based attribution is unreliable, so hints are never violations. Use them as a starting point for a conversation, not as proof.</p>
                <div className="divide-y divide-gray-50 mt-2">
                  {hints.map(d => (
                    <div key={d.key} className="px-5 py-2.5 flex items-center gap-3 text-xs">
                      <span className="font-semibold text-gray-700 w-44 shrink-0">{d.tool_label}</span>
                      <span className="text-gray-400 w-12 shrink-0 tabular-nums">{Math.round(d.confidence * 100)}%</span>
                      <span className="font-mono text-gray-500 truncate flex-1">{d.repo} · {d.location}</span>
                    </div>
                  ))}
                </div>
              </>
            )}
          </div>
        )}

        {data && detections.length === 0 && (
          <div className="animate-fade-up section-card py-14 text-center space-y-1">
            <p className="text-sm font-bold text-gray-600">No AI tool evidence in the last {data.window_days} days</p>
            <p className="text-xs text-gray-400">Evidence appears here as pull requests are scanned: tool config files, attribution markers in code, and AI-signed commits.</p>
          </div>
        )}

        {policy?.updated_at && (
          <p className="text-[11px] text-gray-400">Policy last changed {formatDateOnly(policy.updated_at, tz)}{policy.updated_by ? ` by ${policy.updated_by}` : ""}.</p>
        )}
        {data?.truncated && <p className="text-[11px] text-amber-600">Showing the most recent 1,000 scans in this window.</p>}
      </div>
    </AuthGuard>
  );
}

function DetectionRow({ d, tz, open, onToggle, canTriage, onTriage, note, setNote }: {
  d: Detection; tz: string; open: boolean; onToggle: () => void; canTriage: boolean;
  onTriage: (key: string, patch: { status?: ShadowStatus; note?: string }) => void; note: string; setNote: (v: string) => void;
}) {
  const st = STATUS_STYLE[d.status];
  const ap = APPROVAL_STYLE[d.approval];
  const isCommit = d.location.startsWith("commit:");
  return (
    <div>
      <div className="flex items-center gap-4 px-5 py-3.5 cursor-pointer hover:bg-gray-50/60" onClick={onToggle}>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-bold text-gray-900">{d.tool_label}</span>
            <span className={`text-[11px] font-bold px-2 py-0.5 rounded-full border ${ap.cls}`}>{ap.label}</span>
            {d.violation && <span className="text-[10px] font-bold px-2 py-0.5 rounded-full border" style={{ background: st.bg, color: st.text, borderColor: st.border }}>{st.label}</span>}
            {d.reopened && <span className="text-[10px] font-bold text-rose-600">Seen again after it was resolved</span>}
            {d.notes.length > 0 && <span className="text-[10px] text-gray-400">{d.notes.length} note{d.notes.length > 1 ? "s" : ""}</span>}
          </div>
          <div className="text-xs text-gray-500 font-mono mt-0.5 truncate">{d.repo} · {isCommit ? `commit ${d.location.slice(7)}` : d.location}</div>
          <div className="text-xs text-gray-400 mt-0.5">
            {d.developers.length ? d.developers.join(", ") : "Unknown author"} · last seen {relativeTime(d.last_seen, tz)} · {d.scans} scan{d.scans > 1 ? "s" : ""}
          </div>
        </div>
        <svg className="shrink-0 text-gray-300" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" style={{ transform: open ? "rotate(180deg)" : "none" }}><polyline points="6 9 12 15 18 9" /></svg>
      </div>
      {open && (
        <div className="border-t border-gray-100 px-5 py-4 space-y-3 bg-gray-50/60">
          <div>
            <p className="text-[10px] font-black uppercase tracking-widest text-gray-400 mb-1">Evidence</p>
            <ul className="text-xs text-gray-700 list-disc pl-4 space-y-0.5">{d.evidence.map(e => <li key={e}>{e}</li>)}</ul>
            <p className="text-[11px] text-gray-400 mt-1.5">
              First seen {formatDateOnly(d.first_seen, tz)}{d.pull_requests.length ? ` · pull request${d.pull_requests.length > 1 ? "s" : ""} ${d.pull_requests.map(n => `#${n}`).join(", ")}` : ""}
            </p>
          </div>
          {canTriage && d.violation && (
            <div className="flex items-end gap-3">
              <div>
                <p className="text-[10px] font-black uppercase tracking-widest text-gray-400 mb-1">Status</p>
                <select value={d.status} onChange={e => onTriage(d.key, { status: e.target.value as ShadowStatus })}
                  className="text-xs border border-gray-200 rounded-lg px-2.5 py-1.5 bg-white">
                  {(Object.keys(STATUS_STYLE) as ShadowStatus[]).map(k => <option key={k} value={k}>{STATUS_STYLE[k].label}</option>)}
                </select>
              </div>
            </div>
          )}
          <div>
            <p className="text-[10px] font-black uppercase tracking-widest text-gray-400 mb-2">Notes</p>
            {d.notes.map((n, i) => (
              <div key={i} className="text-[11px] text-gray-600 bg-white rounded-lg px-3 py-2 border border-gray-100 mb-1.5">
                <span className="text-gray-400">{formatDateOnly(n.at, tz)}{n.by ? ` · ${n.by}` : ""}: </span>{n.text}
              </div>
            ))}
            {canTriage ? (
              <div className="flex gap-2">
                <input value={note} onChange={e => setNote(e.target.value)} onKeyDown={e => { if (e.key === "Enter" && note.trim()) onTriage(d.key, { note }); }}
                  placeholder="Add a note (Enter to save)…" className="flex-1 text-xs border border-gray-200 rounded-lg px-3 py-2 bg-white" />
                <button onClick={() => note.trim() && onTriage(d.key, { note })} className="text-xs font-bold text-indigo-700 bg-indigo-50 border border-indigo-200 px-3 py-2 rounded-lg hover:bg-indigo-100">Save</button>
              </div>
            ) : d.notes.length === 0 && <p className="text-[11px] text-gray-400">No notes.</p>}
          </div>
        </div>
      )}
    </div>
  );
}
