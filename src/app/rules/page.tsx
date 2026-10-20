"use client";

/**
 * Rule catalog: every rule the scanner can report (id as in SARIF and the API, CWE, severity, how it's detected,
 * where it applies, the fix), and -- from the latest scan of each repository -- where each one fires in your code
 * right now (/api/rules?usage=1, lib/ruleUsage.ts). Filter, sort, and link straight to a rule with #<rule-id>.
 */

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import AuthGuard from "@/components/AuthGuard";
import { authedFetch } from "@/lib/useRealData";
import { CONFIDENCE_LABEL, CONFIDENCE_DESC, type ConfidenceLevel } from "@/lib/confidence";
import type { CatalogRule, RuleDetection } from "@/lib/ruleCatalog";
import { appliesToOptions, DEFAULT_VIEW, viewRules, type RuleUsage, type RuleView } from "@/lib/ruleUsage";

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
const SELECT = "text-xs font-semibold text-gray-700 bg-white border border-gray-200 rounded-lg px-2.5 py-1.5 focus:outline-none focus:ring-2 focus:ring-indigo-200 max-w-[13rem]";
const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

export default function RulesPage() {
  const [rules, setRules] = useState<CatalogRule[] | null>(null);
  const [usage, setUsage] = useState<Record<string, RuleUsage> | null>(null);
  const [scope, setScope] = useState<"org" | "own">("org");
  const [err, setErr] = useState<string | null>(null);
  const [view, setView] = useState<RuleView>(DEFAULT_VIEW);
  const [open, setOpen] = useState<string | null>(null);
  const set = <K extends keyof RuleView>(k: K, v: RuleView[K]) => setView(p => ({ ...p, [k]: v }));

  useEffect(() => {
    // The catalog alone first (fast, static); then where each rule fires. If counting fails, the catalog still works.
    authedFetch<{ rules: CatalogRule[] }>("/api/rules").then(r => setRules(r.rules)).catch(e => setErr(e instanceof Error ? e.message : "Couldn't load the rules."));
    authedFetch<{ usage?: Record<string, RuleUsage>; scope?: "org" | "own" }>("/api/rules?usage=1")
      .then(r => { setUsage(r.usage ?? {}); setScope(r.scope ?? "org"); }, () => setUsage(null));
  }, []);

  // Deep link: /rules#sql-injection opens that rule and scrolls to it.
  useEffect(() => {
    if (!rules) return;
    const id = decodeURIComponent(window.location.hash.slice(1));
    if (!id || !rules.some(r => r.id === id)) return;
    setOpen(id);
    requestAnimationFrame(() => document.getElementById(`rule-${id}`)?.scrollIntoView?.({ block: "center" }));
  }, [rules]);

  const u = useMemo(() => usage ?? {}, [usage]);
  const shown = useMemo(() => viewRules(rules ?? [], u, view), [rules, u, view]);
  const applies = useMemo(() => appliesToOptions(rules ?? []), [rules]);
  const stats = useMemo(() => {
    const all = rules ?? [];
    const firing = all.filter(r => (u[r.id]?.files ?? 0) > 0);
    return {
      total: all.length,
      byDetection: (["data-flow", "configuration", "pattern"] as const).map(k => [k, all.filter(r => r.detection === k).length] as const),
      firing: firing.length,
      firingCritical: firing.filter(r => r.severity === "critical").length,
    };
  }, [rules, u]);
  const narrowed = JSON.stringify(view) !== JSON.stringify({ ...DEFAULT_VIEW, sort: view.sort });

  return (
    <AuthGuard>
      <div className="max-w-6xl mx-auto space-y-5 pb-10">
        <div>
          <h1 className="text-xl font-black text-gray-900 tracking-tight">Rule catalog</h1>
          <p className="text-sm text-gray-500 mt-1 max-w-3xl">
            Every rule the scanner can report: its id (as it appears in SARIF and the API), CWE, typical severity, how it&apos;s
            detected, where it applies, the fix it recommends — and where it fires in your code right now.
          </p>
        </div>

        {rules && (
          <section aria-label="Catalog summary" className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <Stat label="Rules" value={String(stats.total)} sub={stats.byDetection.map(([k, n]) => `${n} ${DETECTION_LABEL[k].toLowerCase()}`).join(" · ")} />
            <Stat label="Firing in your code" value={usage ? String(stats.firing) : "—"}
              sub={usage ? `${scope === "own" ? "Your pull requests' latest scans" : "Latest scan of each repository"}` : "Couldn't count"} tone={stats.firing ? "warn" : undefined} />
            <Stat label="Critical rules firing" value={usage ? String(stats.firingCritical) : "—"} sub="Fix before merging" tone={stats.firingCritical ? "bad" : undefined} />
            <Stat label="Data-flow languages" value={String(new Set(rules.filter(r => r.detection === "data-flow").flatMap(r => r.appliesTo)).size)} sub="Traced across files" />
          </section>
        )}

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
          <input id="rule-search" value={view.q} onChange={e => set("q", e.target.value)} placeholder="Search id, title, CWE, language…"
            className="text-sm px-3 py-2 rounded-xl border border-gray-200 bg-white w-72 max-w-full focus:outline-none focus:ring-2 focus:ring-indigo-200" />
          {(["all", "data-flow", "configuration", "pattern"] as const).map(k => (
            <button key={k} onClick={() => set("detection", k)} title={k === "all" ? undefined : DETECTION_DESC[k]} aria-pressed={view.detection === k}
              className={`text-xs font-semibold px-3 py-1.5 rounded-lg border transition-colors ${view.detection === k ? "bg-indigo-600 text-white border-indigo-600" : "bg-white text-gray-600 border-gray-200 hover:bg-gray-50"}`}>
              {k === "all" ? `All (${rules?.length ?? 0})` : `${DETECTION_LABEL[k]} (${stats.byDetection.find(([d]) => d === k)?.[1] ?? 0})`}
            </button>
          ))}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <select aria-label="Severity" value={view.severity} onChange={e => set("severity", e.target.value)} className={SELECT}>
            <option value="all">Any severity</option>
            {["critical", "high", "medium", "low"].map(s => <option key={s} value={s}>{s[0].toUpperCase() + s.slice(1)}</option>)}
            <option value="varies">Varies by finding</option>
          </select>
          <select aria-label="Applies to" value={view.appliesTo} onChange={e => set("appliesTo", e.target.value)} className={SELECT}>
            <option value="all">Any language or format</option>
            {applies.map(a => <option key={a} value={a}>{a}</option>)}
          </select>
          <select aria-label="Sort" value={view.sort} onChange={e => set("sort", e.target.value as RuleView["sort"])} className={SELECT}>
            <option value="relevance">Sort: firing in your code first</option>
            <option value="findings">Sort: most files</option>
            <option value="severity">Sort: severity</option>
            <option value="name">Sort: name</option>
          </select>
          <label className={`flex items-center gap-1.5 text-xs font-semibold ${usage ? "text-gray-700" : "text-gray-300"}`}>
            <input type="checkbox" checked={view.firingOnly} disabled={!usage} onChange={e => set("firingOnly", e.target.checked)} className="accent-indigo-600" />
            Only rules firing in my code
          </label>
          {narrowed && <button onClick={() => setView(p => ({ ...DEFAULT_VIEW, sort: p.sort }))} className="text-xs font-bold text-rose-600 hover:text-rose-800 px-2 py-1 rounded-lg hover:bg-rose-50">Clear filters</button>}
          {rules && <span className="text-xs text-gray-400 ml-auto">{shown.length} of {rules.length}</span>}
        </div>

        {err && <p role="alert" className="text-sm text-rose-600">{err}</p>}
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
                    <th className="text-right px-4 py-2.5">In your code</th>
                  </tr>
                </thead>
                <tbody>
                  {shown.map(r => (
                    <RuleRow key={r.id} rule={r} usage={usage ? u[r.id] ?? { files: 0, repos: 0 } : null} open={open === r.id} onToggle={() => setOpen(open === r.id ? null : r.id)} />
                  ))}
                  {shown.length === 0 && <tr><td colSpan={6} className="px-4 py-8 text-center text-gray-400">No rules match.</td></tr>}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </AuthGuard>
  );
}

function Stat({ label, value, sub, tone }: { label: string; value: string; sub: string; tone?: "warn" | "bad" }) {
  return (
    <div className="rounded-2xl border border-gray-100 bg-white px-4 py-3">
      <p className="text-[10px] font-black uppercase tracking-widest text-gray-400">{label}</p>
      <p className={`text-2xl font-black tabular-nums mt-1 ${tone === "bad" ? "text-rose-600" : tone === "warn" ? "text-amber-600" : "text-gray-900"}`}>{value}</p>
      <p className="text-[11px] text-gray-500 mt-0.5 leading-snug">{sub}</p>
    </div>
  );
}

function RuleRow({ rule: r, usage, open, onToggle }: { rule: CatalogRule; usage: RuleUsage | null; open: boolean; onToggle: () => void }) {
  const cweNum = r.cwe?.match(/\d+/)?.[0];
  const [copied, setCopied] = useState(false);
  const copy = (e: React.MouseEvent) => {
    e.stopPropagation();
    const link = `${window.location.origin}/rules#${encodeURIComponent(r.id)}`;
    navigator.clipboard?.writeText(link).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1500); }, () => {});
  };
  return (
    <>
      <tr id={`rule-${r.id}`} className={`border-t border-gray-50 hover:bg-gray-50/60 cursor-pointer align-top ${open ? "bg-indigo-50/30" : ""}`} onClick={onToggle} aria-expanded={open}>
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
        <td className="px-4 py-2.5 text-right whitespace-nowrap">
          {usage == null ? <span className="text-gray-300">—</span>
            : usage.files > 0
              ? <span className="font-bold text-amber-700" title={`${plural(usage.files, "file")} in ${plural(usage.repos, "repository", "repositories")}`}>{plural(usage.files, "file")}<span className="font-normal text-gray-400"> · {plural(usage.repos, "repo")}</span></span>
              : <span className="text-gray-400">None</span>}
        </td>
      </tr>
      {open && (
        <tr className="bg-gray-50/50">
          <td colSpan={6} className="px-4 pb-4 pt-1">
            <div className="grid gap-4 md:grid-cols-2">
              <div className="min-w-0">
                <p className="text-[10px] font-black uppercase tracking-widest text-gray-400 mb-1">What it finds</p>
                <p className="text-xs text-gray-700 leading-relaxed">{r.description}</p>
                <p className="text-[11px] text-gray-500 mt-2">{DETECTION_DESC[r.detection]}</p>
                {usage && usage.files > 0 && (usage.where?.length ?? 0) > 0 && (
                  <div className="mt-3">
                    <p className="text-[10px] font-black uppercase tracking-widest text-gray-400 mb-1">Where it fires</p>
                    <ul className="space-y-0.5">
                      {usage.where!.map(l => (
                        <li key={`${l.repo}::${l.file_path}`} className="text-xs">
                          <Link href={`/pr/${l.scan_id}`} onClick={e => e.stopPropagation()} className="text-indigo-600 hover:text-indigo-800 break-all">
                            <span className="text-gray-500">{l.repo.split("/").pop()}</span> · <span className="font-mono">{l.file_path}</span>
                          </Link>
                        </li>
                      ))}
                    </ul>
                    {usage.files > usage.where!.length && <p className="text-[11px] text-gray-400 mt-1">and {usage.files - usage.where!.length} more</p>}
                  </div>
                )}
                <button onClick={copy} className="mt-3 text-xs font-semibold text-gray-500 hover:text-gray-800">{copied ? "Link copied ✓" : "Copy link to this rule"}</button>
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
