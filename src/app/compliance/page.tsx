"use client";

/**
 * Compliance evidence: per framework, what TrustLedger's own records prove for each control in scope, the gaps,
 * and the exception register for gaps you have formally accepted or are remediating.
 *
 * Everything shown is measured (lib/controlEvidence.ts via GET /api/evidence/collect). There are no compliance
 * percentages, invented audit dates, owners or "last tested" dates: a status describes the evidence, and only an
 * auditor can conclude a control is effective.
 */

import { useState, useMemo, useEffect, useCallback } from "react";
import Link from "next/link";
import AuthGuard from "@/components/AuthGuard";
import PageSkeleton from "@/components/PageSkeleton";
import { authedFetch, isSeedMode } from "@/lib/useRealData";
import { useAuth } from "@/lib/auth";
import { useRole } from "@/lib/roles";
import { useToastHelpers } from "@/lib/toast";
import {
  CHECK_INFO, FRAMEWORKS, STATUS_LABEL, countStatuses, evaluateChecks, evaluateFramework, normalizeFrameworkId,
  type CheckKey, type ComplianceFacts, type EvidenceStatus, type FrameworkDef,
} from "@/lib/controlEvidence";

type FrameworkId = FrameworkDef["id"];
type PageTab = "controls" | "map" | "exceptions";

interface Exception {
  id: string;
  control_id: string;
  framework_id: string;
  title: string;
  description: string;
  risk_accepted: boolean;
  owner: string;
  due_date: string;
  remediation: string;
  created_at: string;
  status: "open" | "in-progress" | "resolved";
}
interface ExceptionRow {
  id: string; control_id: string; framework_id: string; title: string;
  description: string | null; risk_accepted: boolean; owner_email: string | null;
  due_date: string | null; remediation: string | null;
  status: "open" | "in-progress" | "resolved"; created_at: string;
}
function rowToException(r: ExceptionRow): Exception {
  return {
    id: r.id, control_id: r.control_id, framework_id: r.framework_id, title: r.title,
    description: r.description ?? "", risk_accepted: r.risk_accepted, owner: r.owner_email ?? "",
    due_date: r.due_date ?? "", remediation: r.remediation ?? "",
    created_at: r.created_at.split("T")[0], status: r.status,
  };
}

const PERIODS = [30, 90, 180] as const;
const REPORT_FW: Record<FrameworkId, string> = { soc2: "SOC2", iso27001: "ISO27001", pcidss: "PCIDSS", aigov: "AIGOV" };
const FW_COLOR: Record<FrameworkId, string> = { soc2: "#6366f1", iso27001: "#8b5cf6", pcidss: "#10b981", aigov: "#0ea5e9" };
const STATUS_STYLE: Record<EvidenceStatus, { text: string; bg: string; border: string; dot: string }> = {
  pass:       { text: "#065f46", bg: "#ecfdf5", border: "#a7f3d0", dot: "#10b981" },
  partial:    { text: "#78350f", bg: "#fffbeb", border: "#fde68a", dot: "#f59e0b" },
  fail:       { text: "#9f1239", bg: "#fff1f2", border: "#fecdd3", dot: "#f43f5e" },
  not_tested: { text: "#475569", bg: "#f8fafc", border: "#e2e8f0", dot: "#cbd5e1" },
};
const ORDER: EvidenceStatus[] = ["pass", "partial", "fail", "not_tested"];

function daysUntil(iso: string) { return Math.ceil((new Date(iso).getTime() - Date.now()) / 86400000); }
function fmtDate(iso?: string) {
  if (!iso) return "—";
  const d = new Date(iso);
  return `${d.getDate()} ${["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"][d.getMonth()]} ${d.getFullYear()}`;
}

function StatusBadge({ status }: { status: EvidenceStatus }) {
  const s = STATUS_STYLE[status];
  return (
    <span className="inline-flex items-center gap-1 text-[10px] font-bold px-2 py-0.5 rounded-full border whitespace-nowrap"
      style={{ background: s.bg, color: s.text, borderColor: s.border }}>
      <span className="w-1.5 h-1.5 rounded-full" style={{ background: s.dot }} />
      {STATUS_LABEL[status]}
    </span>
  );
}

export default function CompliancePage() {
  const { profile } = useAuth();
  const { permissions } = useRole();
  const { error: toastError } = useToastHelpers();
  const orgName = profile?.org_name || profile?.org_slug || "your organisation";
  const offline = isSeedMode() && !profile?.org_id;

  const [activeFw, setActiveFw] = useState<FrameworkId>("soc2");
  const [tab, setTab] = useState<PageTab>("controls");
  const [periodDays, setPeriodDays] = useState<(typeof PERIODS)[number]>(90);
  const [pciApplicable, setPciApplicable] = useState(false);
  const [facts, setFacts] = useState<ComplianceFacts | null>(null);
  const [factsFailed, setFactsFailed] = useState(false);
  const [refreshKey, setRefreshKey] = useState(0);
  const [exceptions, setExceptions] = useState<Exception[]>([]);
  const [teamMembers, setTeamMembers] = useState<{ email: string }[]>([]);
  const [showExcForm, setShowExcForm] = useState(false);
  const emptyForm = { title: "", description: "", control_id: "", owner: profile?.email ?? "", due_date: "", remediation: "", risk_accepted: false };
  const [excForm, setExcForm] = useState(emptyForm);

  // One load gives the facts; every framework's controls are evaluated from them here (same code as the server).
  useEffect(() => {
    if (offline || !profile?.org_id) return;
    let live = true;
    setFacts(null); setFactsFailed(false);
    const q = new URLSearchParams({
      framework: "soc2",
      period_start: new Date(Date.now() - periodDays * 86400_000).toISOString(),
      period_end: new Date().toISOString(),
    });
    authedFetch<{ facts?: ComplianceFacts }>(`/api/evidence/collect?${q}`)
      .then(p => { if (!live) return; if (p?.facts) setFacts(p.facts); else setFactsFailed(true); })
      .catch(() => { if (live) setFactsFailed(true); });
    return () => { live = false; };
  }, [offline, profile?.org_id, periodDays, refreshKey]);

  useEffect(() => {
    if (!profile?.org_id) return;
    authedFetch<{ org: { pci_applicable?: boolean } }>("/api/settings")
      .then(res => setPciApplicable(!!res.org?.pci_applicable)).catch(() => {});
    authedFetch<{ exceptions: ExceptionRow[] }>("/api/compliance-exceptions")
      .then(res => setExceptions((res.exceptions ?? []).map(rowToException))).catch(() => {});
    authedFetch<{ members: { email: string }[] }>("/api/team")
      .then(res => setTeamMembers(res.members ?? [])).catch(() => {});
  }, [profile?.org_id]);

  const visible = useMemo(() => FRAMEWORKS.filter(f => f.id !== "pcidss" || pciApplicable), [pciApplicable]);
  useEffect(() => { if (!visible.some(f => f.id === activeFw)) setActiveFw("soc2"); }, [visible, activeFw]);
  const fw = visible.find(f => f.id === activeFw) ?? visible[0];
  const color = FW_COLOR[fw.id];

  const checks = useMemo(() => facts ? evaluateChecks(facts) : null, [facts]);
  const results = useMemo(
    () => checks ? Object.fromEntries(visible.map(f => [f.id, evaluateFramework(f, checks)])) as Record<FrameworkId, ReturnType<typeof evaluateFramework>> : null,
    [checks, visible]);
  const controls = results?.[fw.id] ?? null;

  const openExceptions = (fwId: FrameworkId, controlId?: string) =>
    exceptions.filter(e => normalizeFrameworkId(e.framework_id) === fwId && e.status !== "resolved" && (!controlId || e.control_id === controlId));
  const fwExceptions = exceptions.filter(e => normalizeFrameworkId(e.framework_id) === fw.id);

  const startException = useCallback((controlId: string) => {
    setExcForm({ ...emptyForm, control_id: controlId });
    setShowExcForm(true);
    setTab("exceptions");
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [profile?.email]);

  async function addException() {
    if (!excForm.title || !excForm.control_id) return;
    try {
      const res = await authedFetch<{ exception: ExceptionRow }>("/api/compliance-exceptions", {
        method: "POST",
        body: JSON.stringify({
          control_id: excForm.control_id, framework_id: fw.id, title: excForm.title, description: excForm.description,
          risk_accepted: excForm.risk_accepted, owner_email: excForm.owner, due_date: excForm.due_date, remediation: excForm.remediation,
        }),
      });
      setExceptions(prev => [rowToException(res.exception), ...prev]);
      setShowExcForm(false);
      setExcForm(emptyForm);
    } catch (err) {
      toastError("Couldn't log exception", err instanceof Error ? err.message : undefined);
    }
  }

  async function closeException(id: string) {
    const prev = exceptions;
    setExceptions(exceptions.map(e => e.id === id ? { ...e, status: "resolved" as const } : e));
    try {
      await authedFetch("/api/compliance-exceptions", { method: "PATCH", body: JSON.stringify({ id, status: "resolved" }) });
    } catch (err) {
      setExceptions(prev);
      toastError("Couldn't resolve exception", err instanceof Error ? err.message : undefined);
    }
  }

  // Auditor package: the measured evidence for this framework and period, plus its exception register.
  function exportAuditorPackage() {
    if (!facts || !controls) return;
    const pkg = {
      type: "TrustLedger control evidence",
      generated_at: new Date().toISOString(),
      organisation: orgName,
      framework: fw.name, standard: fw.standard, scope: fw.scope,
      period: { start: facts.period_start, end: facts.period_end },
      controls: controls.map(c => ({
        id: c.control_id, name: c.control_name, status: STATUS_LABEL[c.status],
        checks: c.checks.map(k => ({ check: k.label, status: STATUS_LABEL[k.status], measured: k.summary, gaps: k.gaps })),
        open_exceptions: openExceptions(fw.id, c.control_id).map(e => e.title),
      })),
      exceptions: fwExceptions,
      facts,
      note: "Unsigned working copy. For a signed report, use Reports > Generate signed report.",
    };
    const blob = new Blob([JSON.stringify(pkg, null, 2)], { type: "application/json" });
    const a = Object.assign(document.createElement("a"), {
      href: URL.createObjectURL(blob),
      download: `control-evidence-${fw.id}-${new Date().toISOString().split("T")[0]}.json`,
    });
    a.click();
    URL.revokeObjectURL(a.href);
  }

  // Control map: each TrustLedger check, and the control it supports in every framework.
  const checkKeys = useMemo(() => {
    const seen: CheckKey[] = [];
    for (const f of visible) for (const c of f.controls) for (const k of c.checks) if (!seen.includes(k)) seen.push(k);
    return seen;
  }, [visible]);

  return (
    <AuthGuard>
      <PageSkeleton loading={!offline && !!profile?.org_id && !facts && !factsFailed} label="compliance evidence" rows={4} cards={3}>
      <div className="max-w-7xl mx-auto space-y-5 pb-10">

        {/* ── Header ── */}
        <div className="animate-fade-up flex items-start justify-between gap-4 flex-wrap">
          <div>
            <h1 className="text-xl font-black text-gray-900 tracking-tight">Compliance evidence</h1>
            <p className="text-sm text-gray-500 mt-0.5 max-w-2xl">
              What your scans, reviews and audit log prove for each framework&apos;s code-change controls. Evidence for
              your auditor, not a certification.
            </p>
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            <div className="flex gap-0.5 bg-gray-100 p-0.5 rounded-lg" role="group" aria-label="Period">
              {PERIODS.map(d => (
                <button key={d} onClick={() => setPeriodDays(d)} aria-pressed={periodDays === d}
                  className={`px-2.5 py-1.5 text-xs font-semibold rounded-md transition-all ${periodDays === d ? "bg-white text-gray-900 shadow-sm" : "text-gray-500 hover:text-gray-700"}`}>
                  {d}d
                </button>
              ))}
            </div>
            <button onClick={() => setRefreshKey(k => k + 1)}
              className="px-3 py-2 text-xs font-semibold text-gray-600 bg-white border border-gray-200 rounded-xl hover:bg-gray-50 transition-all shadow-sm">
              Refresh
            </button>
            <button onClick={exportAuditorPackage} disabled={!controls}
              className="px-3 py-2 text-xs font-bold text-emerald-700 bg-emerald-50 border border-emerald-200 rounded-xl hover:bg-emerald-100 disabled:opacity-40 transition-all shadow-sm">
              Download evidence (JSON)
            </button>
            <Link href={`/reports?fw=${REPORT_FW[fw.id]}`}
              className="px-4 py-2 text-xs font-bold text-white rounded-xl transition-all shadow-sm"
              style={{ background: "linear-gradient(135deg,#6366f1,#7c3aed)" }}>
              Signed report
            </Link>
          </div>
        </div>

        {offline && (
          <div className="section-card p-6 text-sm text-gray-600">
            Connect a repository to start collecting evidence. Nothing is shown in demo mode rather than invented numbers.
          </div>
        )}

        {!offline && (<>
        {/* ── Frameworks ── */}
        <div className={`animate-fade-up grid grid-cols-1 sm:grid-cols-2 gap-3 ${visible.length === 3 ? "lg:grid-cols-3" : "lg:grid-cols-4"}`}>
          {visible.map(f => {
            const r = results?.[f.id];
            const counts = r ? countStatuses(r) : null;
            const exc = openExceptions(f.id).length;
            const active = f.id === fw.id;
            return (
              <button key={f.id} onClick={() => setActiveFw(f.id)} aria-pressed={active}
                className="text-left rounded-2xl border-2 bg-white p-4 transition-all"
                style={{ borderColor: active ? FW_COLOR[f.id] : "rgba(226,232,240,0.9)", boxShadow: active ? `0 4px 18px ${FW_COLOR[f.id]}22` : "none" }}>
                <p className="text-sm font-bold text-gray-900">{f.name}</p>
                <p className="text-[11px] text-gray-400 truncate">{f.standard}</p>
                {counts ? (
                  <>
                    <p className="text-xs text-gray-600 mt-2.5">
                      <span className="text-lg font-black tabular-nums text-gray-900">{counts.pass}</span> of {r!.length} controls with evidence
                    </p>
                    <div className="mt-2 flex h-1.5 rounded-full overflow-hidden bg-gray-100" aria-hidden="true">
                      {ORDER.map(s => counts[s] > 0 && <div key={s} style={{ width: `${(counts[s] / r!.length) * 100}%`, background: STATUS_STYLE[s].dot }} />)}
                    </div>
                    <p className="text-[10px] text-gray-500 mt-1.5">
                      {[counts.partial && `${counts.partial} with gaps`, counts.fail && `${counts.fail} failing`, counts.not_tested && `${counts.not_tested} no evidence yet`, exc && `${exc} exception${exc === 1 ? "" : "s"}`].filter(Boolean).join(" · ") || "No gaps"}
                    </p>
                  </>
                ) : (
                  <p className="text-xs text-gray-400 mt-3">{factsFailed ? "Couldn't load" : "Collecting evidence…"}</p>
                )}
              </button>
            );
          })}
        </div>

        {/* ── Scope ── */}
        <div className="animate-fade-up rounded-xl border px-5 py-3.5" style={{ borderColor: `${color}40`, background: `${color}0d` }}>
          <p className="text-[10px] font-black uppercase tracking-widest mb-1" style={{ color }}>Scope of this evidence · {fw.name}</p>
          <p className="text-xs text-gray-700 leading-relaxed">{fw.scope}</p>
        </div>

        {/* ── Tabs ── */}
        <div className="animate-fade-up flex items-center gap-1 bg-gray-100 p-0.5 rounded-xl w-fit" role="tablist">
          {([["controls", "Controls"], ["map", "Control map"], ["exceptions", `Exceptions (${fwExceptions.filter(e => e.status !== "resolved").length})`]] as const).map(([t, label]) => (
            <button key={t} role="tab" aria-selected={tab === t} onClick={() => setTab(t)}
              className={`px-4 py-2 text-xs font-semibold rounded-lg transition-all ${tab === t ? "bg-white text-gray-900 shadow-sm" : "text-gray-500 hover:text-gray-700"}`}>
              {label}
            </button>
          ))}
        </div>

        {factsFailed && tab !== "exceptions" && (
          <div className="section-card p-5 text-sm text-rose-700">
            Couldn&apos;t collect evidence right now. <button onClick={() => setRefreshKey(k => k + 1)} className="font-bold underline">Try again</button>
          </div>
        )}

        {/* ══ CONTROLS ══ */}
        {tab === "controls" && !factsFailed && (
          !controls ? <div className="section-card h-48 animate-pulse" aria-label="Collecting evidence" /> : (
          <div className="animate-fade-up grid grid-cols-1 lg:grid-cols-2 gap-4">
            {controls.map(c => {
              const exc = openExceptions(fw.id, c.control_id);
              return (
                <div key={c.control_id} className="section-card overflow-hidden">
                  <div className="flex items-start justify-between gap-3 px-5 py-4 border-b border-gray-100">
                    <div className="flex items-start gap-3 min-w-0">
                      <span className="text-[11px] font-black font-mono px-2 py-1 rounded-lg shrink-0"
                        style={{ background: `${color}12`, color, border: `1px solid ${color}30` }}>{c.control_id}</span>
                      <div className="min-w-0">
                        <p className="text-sm font-bold text-gray-900 leading-snug">{c.control_name}</p>
                        {exc.length > 0 && (
                          <p className="text-[10px] font-bold text-amber-700 mt-0.5">{exc.length} open exception{exc.length === 1 ? "" : "s"}: {exc.map(e => e.title).join("; ")}</p>
                        )}
                      </div>
                    </div>
                    <StatusBadge status={c.status} />
                  </div>
                  <div className="px-5 py-3.5 space-y-3">
                    {c.checks.map(k => (
                      <div key={k.key}>
                        <div className="flex items-center justify-between gap-2">
                          <p className="text-xs font-bold text-gray-800">{k.label}</p>
                          <span className="text-[10px] font-semibold" style={{ color: STATUS_STYLE[k.status].text }}>{STATUS_LABEL[k.status]}</span>
                        </div>
                        <p className="text-xs text-gray-600 leading-relaxed mt-0.5">{k.summary}</p>
                        {k.gaps.map(g => <p key={g} className="text-xs font-semibold text-amber-800 mt-1">Gap: {g}</p>)}
                      </div>
                    ))}
                  </div>
                  {(c.status === "partial" || c.status === "fail") && permissions.canTriage && exc.length === 0 && (
                    <div className="px-5 py-2.5 border-t border-gray-50 bg-gray-50/50">
                      <button onClick={() => startException(c.control_id)} className="text-[11px] font-semibold text-indigo-600 hover:text-indigo-800">
                        Log an exception for this gap →
                      </button>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        ))}

        {/* ══ CONTROL MAP ══ */}
        {tab === "map" && !factsFailed && (
          <div className="animate-fade-up section-card overflow-hidden">
            <div className="px-5 py-4 border-b border-gray-100">
              <p className="text-sm font-bold text-gray-900">Control map</p>
              <p className="text-xs text-gray-400 mt-0.5">Each check TrustLedger measures, and the control it is evidence for in each framework. One check, several controls.</p>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full min-w-[720px]">
                <thead>
                  <tr className="border-b border-gray-100 bg-gray-50/60">
                    <th className="px-5 py-3 text-left text-[10px] font-black uppercase tracking-wider text-gray-400">Check</th>
                    <th className="px-4 py-3 text-left text-[10px] font-black uppercase tracking-wider text-gray-400">Now</th>
                    {visible.map(f => (
                      <th key={f.id} className="px-4 py-3 text-left text-[10px] font-black uppercase tracking-wider" style={{ color: FW_COLOR[f.id] }}>{f.short}</th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-50">
                  {checkKeys.map(k => (
                    <tr key={k} className="align-top">
                      <td className="px-5 py-3.5 max-w-sm">
                        <p className="text-xs font-bold text-gray-900">{CHECK_INFO[k].label}</p>
                        <p className="text-[11px] text-gray-500 mt-0.5 leading-snug">{CHECK_INFO[k].measures}</p>
                      </td>
                      <td className="px-4 py-3.5">{checks ? <StatusBadge status={checks[k].status} /> : <span className="text-gray-300 text-xs">…</span>}</td>
                      {visible.map(f => {
                        const ids = f.controls.filter(c => c.checks.includes(k)).map(c => c.id);
                        return (
                          <td key={f.id} className="px-4 py-3.5">
                            {ids.length ? (
                              <div className="flex flex-wrap gap-1">
                                {ids.map(id => (
                                  <span key={id} className="text-[10px] font-black font-mono px-1.5 py-0.5 rounded"
                                    style={{ background: `${FW_COLOR[f.id]}12`, color: FW_COLOR[f.id] }}>{id}</span>
                                ))}
                              </div>
                            ) : <span className="text-gray-300 text-xs">—</span>}
                          </td>
                        );
                      })}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ══ EXCEPTIONS ══ */}
        {tab === "exceptions" && (
          <div className="animate-fade-up space-y-4">
            <div className="flex items-center justify-between gap-3 flex-wrap">
              <div>
                <p className="text-sm font-bold text-gray-900">Exception register · {fw.name}</p>
                <p className="text-xs text-gray-400 mt-0.5">Gaps you have formally accepted or are remediating, with an owner and a due date. Every change is audit-logged.</p>
              </div>
              {permissions.canTriage && (
                <button onClick={() => { setExcForm(emptyForm); setShowExcForm(v => !v); }}
                  className="px-3 py-2 text-xs font-bold text-indigo-700 bg-indigo-50 border border-indigo-200 rounded-xl hover:bg-indigo-100 transition-colors">
                  Log exception
                </button>
              )}
            </div>

            {showExcForm && (
              <div className="section-card p-5 space-y-4 border-2 border-indigo-200">
                <p className="text-sm font-bold text-gray-900">New exception</p>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div className="sm:col-span-2">
                    <label htmlFor="exc-title" className="block text-[10px] font-semibold text-gray-500 mb-1">Title *</label>
                    <input id="exc-title" value={excForm.title} onChange={e => setExcForm(p => ({ ...p, title: e.target.value }))}
                      placeholder="e.g. Legacy repo not yet connected to scanning"
                      className="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm text-gray-700 focus:outline-none focus:ring-2 focus:ring-indigo-400" />
                  </div>
                  <div>
                    <label htmlFor="exc-control" className="block text-[10px] font-semibold text-gray-500 mb-1">Control *</label>
                    <select id="exc-control" value={excForm.control_id} onChange={e => setExcForm(p => ({ ...p, control_id: e.target.value }))}
                      className="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm text-gray-700 focus:outline-none">
                      <option value="">Select control</option>
                      {fw.controls.map(c => <option key={c.id} value={c.id}>{c.id} · {c.name}</option>)}
                    </select>
                  </div>
                  <div>
                    <label htmlFor="exc-owner" className="block text-[10px] font-semibold text-gray-500 mb-1">Owner</label>
                    <select id="exc-owner" value={excForm.owner} onChange={e => setExcForm(p => ({ ...p, owner: e.target.value }))}
                      className="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm text-gray-700 focus:outline-none">
                      {(teamMembers.length ? teamMembers.map(m => m.email) : [profile?.email ?? ""]).map(em => (
                        <option key={em} value={em}>{em}</option>
                      ))}
                    </select>
                  </div>
                  <div className="sm:col-span-2">
                    <label htmlFor="exc-desc" className="block text-[10px] font-semibold text-gray-500 mb-1">Why the gap exists</label>
                    <textarea id="exc-desc" value={excForm.description} onChange={e => setExcForm(p => ({ ...p, description: e.target.value }))} rows={2}
                      className="w-full border border-gray-200 rounded-lg px-3 py-2 text-xs text-gray-700 focus:outline-none focus:ring-2 focus:ring-indigo-400 resize-none" />
                  </div>
                  <div>
                    <label htmlFor="exc-due" className="block text-[10px] font-semibold text-gray-500 mb-1">Due date</label>
                    <input id="exc-due" type="date" value={excForm.due_date} onChange={e => setExcForm(p => ({ ...p, due_date: e.target.value }))}
                      className="w-full border border-gray-200 rounded-lg px-3 py-2 text-xs text-gray-700 focus:outline-none" />
                  </div>
                  <label className="flex items-center gap-2 text-xs text-gray-600 font-semibold self-end pb-2">
                    <input type="checkbox" checked={excForm.risk_accepted} onChange={e => setExcForm(p => ({ ...p, risk_accepted: e.target.checked }))}
                      className="w-4 h-4 accent-amber-500" />
                    Risk formally accepted
                  </label>
                  <div className="sm:col-span-2">
                    <label htmlFor="exc-rem" className="block text-[10px] font-semibold text-gray-500 mb-1">Remediation plan</label>
                    <textarea id="exc-rem" value={excForm.remediation} onChange={e => setExcForm(p => ({ ...p, remediation: e.target.value }))} rows={2}
                      className="w-full border border-gray-200 rounded-lg px-3 py-2 text-xs text-gray-700 focus:outline-none focus:ring-2 focus:ring-indigo-400 resize-none" />
                  </div>
                </div>
                <div className="flex gap-2">
                  <button onClick={addException} disabled={!excForm.title || !excForm.control_id}
                    className="px-4 py-2 text-sm font-bold text-white rounded-xl disabled:opacity-40" style={{ background: "linear-gradient(135deg,#6366f1,#7c3aed)" }}>
                    Log exception
                  </button>
                  <button onClick={() => setShowExcForm(false)} className="px-4 py-2 text-sm font-semibold text-gray-500 rounded-xl hover:bg-gray-50">Cancel</button>
                </div>
              </div>
            )}

            {fwExceptions.length === 0 ? (
              <div className="section-card py-12 text-center">
                <p className="text-sm font-bold text-gray-700">No exceptions logged for {fw.name}</p>
                <p className="text-xs text-gray-400 mt-1">Log one when a gap is accepted or has a remediation plan, so your auditor sees it was handled.</p>
              </div>
            ) : fwExceptions.map(exc => {
              const ctrl = fw.controls.find(c => c.id === exc.control_id);
              const days = exc.due_date ? daysUntil(exc.due_date) : null;
              const st = exc.status === "resolved" ? { label: "Resolved", s: STATUS_STYLE.pass }
                : exc.status === "in-progress" ? { label: "In progress", s: STATUS_STYLE.partial } : { label: "Open", s: STATUS_STYLE.fail };
              return (
                <div key={exc.id} className="section-card overflow-hidden border-l-4" style={{ borderLeftColor: exc.risk_accepted ? "#f59e0b" : "#f43f5e" }}>
                  <div className="flex items-start gap-4 p-5">
                    <div className="flex-1 min-w-0 space-y-1.5">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-[10px] font-black font-mono px-2 py-0.5 rounded" style={{ background: `${color}12`, color }}>{exc.control_id}</span>
                        {!ctrl && <span className="text-[10px] text-gray-400">control no longer in the {fw.short} set</span>}
                        <span className="text-[10px] font-bold px-2 py-0.5 rounded-full border" style={{ background: st.s.bg, color: st.s.text, borderColor: st.s.border }}>{st.label}</span>
                        {exc.risk_accepted && <span className="text-[10px] font-bold text-amber-700 bg-amber-50 px-2 py-0.5 rounded border border-amber-200">Risk accepted</span>}
                      </div>
                      <p className="text-sm font-bold text-gray-900">{exc.title}</p>
                      {exc.description && <p className="text-xs text-gray-500 leading-relaxed">{exc.description}</p>}
                      <div className="flex items-center gap-4 text-[11px] text-gray-400 flex-wrap">
                        {exc.owner && <span>Owner: <strong className="text-gray-600">{exc.owner}</strong></span>}
                        {exc.due_date && (
                          <span className={days !== null && days < 0 && exc.status !== "resolved" ? "text-rose-600 font-bold" : ""}>
                            Due {fmtDate(exc.due_date)}{days !== null && days < 0 && exc.status !== "resolved" ? ` (${Math.abs(days)}d overdue)` : ""}
                          </span>
                        )}
                        <span>Logged {fmtDate(exc.created_at)}</span>
                      </div>
                      {exc.remediation && <p className="text-[11px] text-indigo-700 bg-indigo-50 border border-indigo-100 rounded-lg px-3 py-2"><span className="font-bold">Remediation:</span> {exc.remediation}</p>}
                    </div>
                    {exc.status !== "resolved" && permissions.canTriage && (
                      <button onClick={() => closeException(exc.id)}
                        className="shrink-0 text-[11px] font-bold text-emerald-700 bg-emerald-50 border border-emerald-200 px-3 py-1.5 rounded-lg hover:bg-emerald-100 whitespace-nowrap">
                        Mark resolved
                      </button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        )}
        </>)}

        {/* ── Related ── */}
        <div className="animate-fade-up grid grid-cols-1 sm:grid-cols-3 gap-3">
          {[
            { label: "Signed evidence report", sub: `PDF for ${fw.name}, signed over its contents`, href: `/reports?fw=${REPORT_FW[fw.id]}` },
            { label: "Risk register", sub: "Likelihood × impact risk log", href: "/risk-register" },
            { label: "Audit trail", sub: "Every sign-off, exception and setting change", href: "/audit" },
          ].map(a => (
            <Link key={a.label} href={a.href} className="section-card p-4 flex flex-col gap-1 hover:shadow-md transition-all group">
              <p className="text-xs font-bold text-indigo-700 flex items-center justify-between">{a.label}<span className="group-hover:translate-x-0.5 transition-transform">→</span></p>
              <p className="text-[11px] text-gray-400 leading-snug">{a.sub}</p>
            </Link>
          ))}
        </div>

      </div>
      </PageSkeleton>
    </AuthGuard>
  );
}
