"use client";

import { useEffect, useMemo, useState } from "react";
import AuthGuard from "@/components/AuthGuard";
import { authedFetch } from "@/lib/useRealData";
import { CONFIDENCE_LABEL, CONFIDENCE_DESC, type ConfidenceLevel } from "@/lib/confidence";
import type { CatalogRule, RuleDetection } from "@/lib/ruleCatalog";

const DETECTION_LABEL: Record<RuleDetection, string> = { "data-flow": "Data flow", configuration: "Configuration", pattern: "Pattern" };
const DETECTION_DESC: Record<RuleDetection, string> = {
  "data-flow": "Traces a value from where it enters (a request, a parameter) to where it is used, across files.",
  configuration: "Reads infrastructure, container and API configuration: Kubernetes, cloud templates, Dockerfiles, OpenAPI.",
  pattern: "Matches a specific code or text pattern on a line (secrets, weak settings, AI-provenance signals).",
};
const SEV_STYLE: Record<string, string> = {
  critical: "bg-rose-50 text-rose-700 border-rose-200", high: "bg-orange-50 text-orange-700 border-orange-200",
  medium: "bg-amber-50 text-amber-700 border-amber-200", low: "bg-slate-50 text-slate-600 border-slate-200",
};
const SEVERITY_DESC: Array<[string, string]> = [
  ["critical", "Exploitable for full compromise (code execution, data theft) with little effort. Fix before merging."],
  ["high", "Serious and plausibly exploitable. Fix before release."],
  ["medium", "Real weakness that needs a specific condition or combination to exploit. Plan a fix."],
  ["low", "Hardening or hygiene issue. Fix when convenient."],
];

export default function RulesPage() {
  const [rules, setRules] = useState<CatalogRule[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [q, setQ] = useState("");
  const [kind, setKind] = useState<RuleDetection | "all">("all");
  const [open, setOpen] = useState<string | null>(null);

  useEffect(() => {
    authedFetch<{ rules: CatalogRule[] }>("/api/rules").then(r => setRules(r.rules)).catch(e => setErr(e instanceof Error ? e.message : "Couldn't load the rules."));
  }, []);

  const shown = useMemo(() => (rules ?? []).filter(r => {
    if (kind !== "all" && r.detection !== kind) return false;
    if (!q) return true;
    const s = q.toLowerCase();
    return [r.id, r.title, r.cwe ?? "", r.description, ...r.appliesTo].join(" ").toLowerCase().includes(s);
  }), [rules, q, kind]);
  const counts = useMemo(() => {
    const c: Record<RuleDetection, number> = { "data-flow": 0, configuration: 0, pattern: 0 };
    for (const r of rules ?? []) c[r.detection]++;
    return c;
  }, [rules]);

  return (
    <AuthGuard>
      <div className="max-w-6xl mx-auto space-y-5 pb-10">
        <div>
          <h1 className="text-xl font-black text-gray-900 tracking-tight">Rule catalog</h1>
          <p className="text-sm text-gray-500 mt-1 max-w-3xl">
            Every rule the scanner can report: its id (as it appears in SARIF and the API), CWE, typical severity, how it&apos;s
            detected, where it applies, and the fix it recommends.
          </p>
        </div>

        <div className="grid gap-3 md:grid-cols-2">
          <div className="rounded-2xl border border-gray-100 bg-white px-4 py-3.5">
            <p className="text-[10px] font-black uppercase tracking-widest text-gray-400 mb-2">Confidence levels</p>
            <dl className="space-y-1.5">
              {(Object.keys(CONFIDENCE_LABEL) as ConfidenceLevel[]).map(l => (
                <div key={l} className="flex gap-2 text-xs">
                  <dt className="w-24 shrink-0 font-bold text-gray-800">{CONFIDENCE_LABEL[l]}</dt>
                  <dd className="text-gray-600">{CONFIDENCE_DESC[l]}</dd>
                </div>
              ))}
            </dl>
          </div>
          <div className="rounded-2xl border border-gray-100 bg-white px-4 py-3.5">
            <p className="text-[10px] font-black uppercase tracking-widest text-gray-400 mb-2">Severity</p>
            <dl className="space-y-1.5">
              {SEVERITY_DESC.map(([s, d]) => (
                <div key={s} className="flex gap-2 text-xs">
                  <dt className="w-24 shrink-0"><span className={`inline-block text-[10px] font-bold uppercase px-1.5 py-0.5 rounded border ${SEV_STYLE[s]}`}>{s}</span></dt>
                  <dd className="text-gray-600">{d}</dd>
                </div>
              ))}
            </dl>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <label htmlFor="rule-search" className="sr-only">Search rules</label>
          <input id="rule-search" value={q} onChange={e => setQ(e.target.value)} placeholder="Search id, title, CWE, language…"
            className="text-sm px-3 py-2 rounded-xl border border-gray-200 bg-white w-72 max-w-full focus:outline-none focus:ring-2 focus:ring-indigo-200" />
          {(["all", "data-flow", "configuration", "pattern"] as const).map(k => (
            <button key={k} onClick={() => setKind(k)} title={k === "all" ? undefined : DETECTION_DESC[k]}
              className={`text-xs font-semibold px-3 py-1.5 rounded-lg border transition-colors ${kind === k ? "bg-indigo-600 text-white border-indigo-600" : "bg-white text-gray-600 border-gray-200 hover:bg-gray-50"}`}>
              {k === "all" ? `All (${rules?.length ?? 0})` : `${DETECTION_LABEL[k]} (${counts[k]})`}
            </button>
          ))}
        </div>

        {err && <p className="text-sm text-rose-600">{err}</p>}
        {!rules && !err && <p className="text-sm text-gray-400">Loading…</p>}

        {rules && (
          <div className="rounded-2xl border border-gray-100 bg-white overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="text-[10px] font-black uppercase tracking-widest text-gray-400 bg-gray-50/70">
                    <th className="text-left px-4 py-2.5">Rule</th>
                    <th className="text-left px-2 py-2.5">CWE</th>
                    <th className="text-left px-2 py-2.5">Severity</th>
                    <th className="text-left px-2 py-2.5">Detection</th>
                    <th className="text-left px-2 py-2.5">Applies to</th>
                  </tr>
                </thead>
                <tbody>
                  {shown.map(r => (
                    <RuleRow key={r.id} rule={r} open={open === r.id} onToggle={() => setOpen(open === r.id ? null : r.id)} />
                  ))}
                  {shown.length === 0 && <tr><td colSpan={5} className="px-4 py-8 text-center text-gray-400">No rules match.</td></tr>}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </AuthGuard>
  );
}

function RuleRow({ rule: r, open, onToggle }: { rule: CatalogRule; open: boolean; onToggle: () => void }) {
  const cweNum = r.cwe?.match(/\d+/)?.[0];
  return (
    <>
      <tr className="border-t border-gray-50 hover:bg-gray-50/60 cursor-pointer align-top" onClick={onToggle} aria-expanded={open}>
        <td className="px-4 py-2.5 min-w-[220px]">
          <p className="font-semibold text-gray-900">{r.title}</p>
          <code className="text-[10.5px] text-gray-400 font-mono">{r.id}</code>
        </td>
        <td className="px-2 py-2.5 whitespace-nowrap">
          {r.cwe ? (cweNum
            ? <a href={`https://cwe.mitre.org/data/definitions/${cweNum}.html`} target="_blank" rel="noopener noreferrer" onClick={e => e.stopPropagation()} className="font-mono text-indigo-600 hover:underline">{r.cwe}</a>
            : <span className="font-mono text-gray-600">{r.cwe}</span>) : <span className="text-gray-300">—</span>}
        </td>
        <td className="px-2 py-2.5">
          {r.severity ? <span className={`inline-block text-[10px] font-bold uppercase px-1.5 py-0.5 rounded border ${SEV_STYLE[r.severity]}`}>{r.severity}</span> : <span className="text-gray-400" title="Depends on the finding">varies</span>}
        </td>
        <td className="px-2 py-2.5 whitespace-nowrap text-gray-600" title={DETECTION_DESC[r.detection]}>{DETECTION_LABEL[r.detection]}</td>
        <td className="px-2 py-2.5 text-gray-600">{r.appliesTo.length ? r.appliesTo.join(", ") : <span className="text-gray-400">All scanned files</span>}</td>
      </tr>
      {open && (
        <tr className="bg-gray-50/50">
          <td colSpan={5} className="px-4 pb-4 pt-1">
            <div className="grid gap-4 md:grid-cols-2">
              <div className="min-w-0">
                <p className="text-[10px] font-black uppercase tracking-widest text-gray-400 mb-1">What it finds</p>
                <p className="text-xs text-gray-700 leading-relaxed">{r.description}</p>
                <p className="text-[11px] text-gray-500 mt-2">{DETECTION_DESC[r.detection]}</p>
              </div>
              <div className="min-w-0">
                <p className="text-[10px] font-black uppercase tracking-widest text-gray-400 mb-1">Remediation</p>
                {r.fix ? (
                  <>
                    <p className="text-xs font-semibold text-gray-800">{r.fix.title}</p>
                    <p className="text-xs text-gray-600 leading-relaxed mt-0.5">{r.fix.description}</p>
                    {(r.fix.code_before || r.fix.code_after) && (
                      <div className="grid gap-2 mt-2">
                        {r.fix.code_before && <pre className="text-[10.5px] font-mono bg-rose-50/70 text-rose-900 rounded-lg px-2.5 py-1.5 overflow-x-auto whitespace-pre">{r.fix.code_before}</pre>}
                        {r.fix.code_after && <pre className="text-[10.5px] font-mono bg-emerald-50/70 text-emerald-900 rounded-lg px-2.5 py-1.5 overflow-x-auto whitespace-pre">{r.fix.code_after}</pre>}
                      </div>
                    )}
                  </>
                ) : <p className="text-xs text-gray-400">No specific remediation recorded for this rule.</p>}
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}
