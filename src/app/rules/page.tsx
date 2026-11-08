"use client";

/**
 * Rule catalog: every rule the scanner can report (id as in SARIF and the API, CWE, severity, how it's detected,
 * where it applies, the fix), and -- from the latest scan of each repository -- where each one fires in your code
 * right now, what is NEW since the previous scan and what was fixed (/api/rules?usage=1, lib/ruleUsage.ts).
 * A rule opens into where it fires (every file, on request) and a full remediation (lib/ruleGuidance.ts).
 * Filter, sort, and link straight to a rule with #<rule-id>.
 */

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import AuthGuard from "@/components/AuthGuard";
import Tip from "@/components/Tip";
import { CapNotice } from "@/components/Limits";
import { authedFetch } from "@/lib/useRealData";
import { CONFIDENCE_LABEL, CONFIDENCE_DESC, type ConfidenceLevel } from "@/lib/confidence";
import type { CatalogRule, RuleDetection } from "@/lib/ruleCatalog";
import { appliesToOptions, DEFAULT_VIEW, fileHref, groupByRepo, viewRules, type RuleLocation, type RuleUsage, type RuleView } from "@/lib/ruleUsage";
import { cweUrl, EFFORT_LABEL, fixSteps, guidanceFor, relatedRules, SEVERITY_GUIDANCE, verifySteps } from "@/lib/ruleGuidance";

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
const SELECT = "text-xs font-semibold text-gray-700 bg-white border border-gray-200 rounded-lg px-2.5 py-1.5 focus:outline-none focus:ring-2 focus:ring-indigo-200 max-w-[13rem]";
const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

type All = { status: "loading" } | { status: "error"; message: string } | { status: "done"; locations: RuleLocation[]; total: number; truncated: boolean };

export default function RulesPage() {
  const [rules, setRules] = useState<CatalogRule[] | null>(null);
  const [usage, setUsage] = useState<Record<string, RuleUsage> | null>(null);
  const [scope, setScope] = useState<"org" | "own">("org");
  const [err, setErr] = useState<string | null>(null);
  const [view, setView] = useState<RuleView>(DEFAULT_VIEW);
  const [newOnly, setNewOnly] = useState(false);
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
  const shown = useMemo(() => viewRules(rules ?? [], u, view).filter(r => !newOnly || (u[r.id]?.new ?? 0) > 0), [rules, u, view, newOnly]);
  const applies = useMemo(() => appliesToOptions(rules ?? []), [rules]);
  const stats = useMemo(() => {
    const all = rules ?? [];
    const firing = all.filter(r => (u[r.id]?.files ?? 0) > 0);
    const withNew = all.filter(r => (u[r.id]?.new ?? 0) > 0);
    return {
      total: all.length,
      byDetection: (["data-flow", "configuration", "pattern"] as const).map(k => [k, all.filter(r => r.detection === k).length] as const),
      firing: firing.length,
      firingCritical: firing.filter(r => r.severity === "critical").length,
      rulesWithNew: withNew.length,
      newFiles: withNew.reduce((n, r) => n + (u[r.id]?.new ?? 0), 0),
      newCritical: withNew.filter(r => r.severity === "critical" || r.severity === "high").length,
      fixedFiles: all.reduce((n, r) => n + (u[r.id]?.fixed ?? 0), 0),
      compared: all.some(r => u[r.id]?.compared),
    };
  }, [rules, u]);
  const narrowed = JSON.stringify(view) !== JSON.stringify({ ...DEFAULT_VIEW, sort: view.sort }) || newOnly;

  return (
    <AuthGuard>
      <div className="max-w-6xl mx-auto space-y-5 pb-10">
        <div>
          <h1 className="text-xl font-black text-gray-900 tracking-tight">Rule catalog</h1>
          <p className="text-sm text-gray-500 mt-1 max-w-3xl">
            Every rule the scanner can report: its id (as it appears in SARIF and the API), CWE, typical severity, how it&apos;s
            detected, where it applies, the fix it recommends. And where it fires in your code right now, what is new since the previous scan, and what was fixed.
          </p>
        </div>

        {rules && (
          <section aria-label="Catalog summary" className="grid grid-cols-2 md:grid-cols-5 gap-3">
            <Stat label="Rules" value={String(stats.total)} sub={stats.byDetection.map(([k, n]) => `${n} ${DETECTION_LABEL[k].toLowerCase()}`).join(" · ")} tip="Every rule the scanner can report, by how it detects problems." />
            <Stat label="Firing in your code" value={usage ? String(stats.firing) : "—"}
              sub={usage ? `${scope === "own" ? "Your pull requests' latest scans" : "Latest scan of each repository"}` : "Couldn't count"} tone={stats.firing ? "warn" : undefined}
              tip="Rules that report at least one file in the latest scan of a repository." />
            <Stat label="Critical rules firing" value={usage ? String(stats.firingCritical) : "—"} sub="Fix before merging" tone={stats.firingCritical ? "bad" : undefined} tip="Critical-severity rules firing somewhere right now: the ones to deal with first." />
            <Stat label="New since last scan" value={usage ? (stats.compared ? String(stats.newFiles) : "—") : "—"}
              sub={!usage ? "Couldn't count" : !stats.compared ? "No earlier scan to compare with" : stats.newFiles ? `files in ${plural(stats.rulesWithNew, "rule")}${stats.newCritical ? ` · ${stats.newCritical} critical or high` : ""}` : "Nothing new"}
              tone={stats.newFiles ? "bad" : undefined} tip="Files where a rule fires now and did not in the repository's previous scan. A repository with only one scan has nothing to compare with." />
            <Stat label="Fixed since last scan" value={usage ? (stats.compared ? String(stats.fixedFiles) : "—") : "—"} sub={stats.compared ? "files no longer flagged" : "No earlier scan to compare with"} tone={stats.fixedFiles ? "good" : undefined}
              tip="Files where a rule fired in the previous scan and no longer fires." />
          </section>
        )}

        <details className="rounded-2xl border border-gray-100 bg-white px-4 py-3">
          <summary className="cursor-pointer text-xs font-bold text-gray-700">How to read severity, confidence and detection</summary>
          <div className="mt-3 grid gap-4 md:grid-cols-3">
            <div>
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
            <div>
              <p className="text-[10px] font-black uppercase tracking-widest text-gray-400 mb-2">Severity: when to fix</p>
              <dl className="space-y-1.5">
                {(["critical", "high", "medium", "low"] as const).map(s => (
                  <div key={s} className="flex gap-2 text-xs">
                    <dt className="w-24 shrink-0"><span className={`inline-block text-[10px] font-bold uppercase px-1.5 py-0.5 rounded border ${SEV_STYLE[s]}`}>{s}</span></dt>
                    <dd className="text-gray-600">{SEVERITY_GUIDANCE[s].when} <span className="font-semibold text-gray-700">{SEVERITY_GUIDANCE[s].sla}.</span></dd>
                  </div>
                ))}
              </dl>
            </div>
            <div>
              <p className="text-[10px] font-black uppercase tracking-widest text-gray-400 mb-2">How a rule detects</p>
              <dl className="space-y-1.5">
                {(Object.keys(DETECTION_LABEL) as RuleDetection[]).map(k => (
                  <div key={k} className="text-xs"><dt className="font-bold text-gray-800">{DETECTION_LABEL[k]}</dt><dd className="text-gray-600">{DETECTION_DESC[k]}</dd></div>
                ))}
              </dl>
            </div>
          </div>
        </details>

        <div className="flex flex-wrap items-center gap-2">
          <label htmlFor="rule-search" className="sr-only">Search rules</label>
          <input id="rule-search" value={view.q} onChange={e => set("q", e.target.value)} placeholder="Search id, title, CWE, language…"
            className="text-sm px-3 py-2 rounded-xl border border-gray-200 bg-white w-72 max-w-full focus:outline-none focus:ring-2 focus:ring-indigo-200" />
          {(["all", "data-flow", "configuration", "pattern"] as const).map(k => (
            <Tip key={k} tip={k === "all" ? "Every rule." : DETECTION_DESC[k]}>
              <button onClick={() => set("detection", k)} aria-pressed={view.detection === k}
                className={`text-xs font-semibold px-3 py-1.5 rounded-lg border transition-colors ${view.detection === k ? "bg-indigo-600 text-white border-indigo-600" : "bg-white text-gray-600 border-gray-200 hover:bg-gray-50"}`}>
                {k === "all" ? `All (${rules?.length ?? 0})` : `${DETECTION_LABEL[k]} (${stats.byDetection.find(([d]) => d === k)?.[1] ?? 0})`}
              </button>
            </Tip>
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
            <option value="new">Sort: newest findings first</option>
            <option value="findings">Sort: most files</option>
            <option value="severity">Sort: severity</option>
            <option value="name">Sort: name</option>
          </select>
          <label className={`flex items-center gap-1.5 text-xs font-semibold ${usage ? "text-gray-700" : "text-gray-300"}`}>
            <input type="checkbox" checked={view.firingOnly} disabled={!usage} onChange={e => set("firingOnly", e.target.checked)} className="accent-indigo-600" />
            Only rules firing in my code
          </label>
          <label className={`flex items-center gap-1.5 text-xs font-semibold ${usage && stats.compared ? "text-gray-700" : "text-gray-300"}`}>
            <input type="checkbox" checked={newOnly} disabled={!usage || !stats.compared} onChange={e => setNewOnly(e.target.checked)} className="accent-indigo-600" />
            Only rules with new findings
          </label>
          {narrowed && <button onClick={() => { setView(p => ({ ...DEFAULT_VIEW, sort: p.sort })); setNewOnly(false); }} className="text-xs font-bold text-rose-600 hover:text-rose-800 px-2 py-1 rounded-lg hover:bg-rose-50">Clear filters</button>}
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
                    <RuleRow key={r.id} rule={r} rules={rules} usage={usage ? u[r.id] ?? { files: 0, repos: 0 } : null} open={open === r.id} onToggle={() => setOpen(open === r.id ? null : r.id)} onOpenRule={id => { setOpen(id); requestAnimationFrame(() => document.getElementById(`rule-${id}`)?.scrollIntoView?.({ block: "center" })); }} />
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

function Stat({ label, value, sub, tone, tip }: { label: string; value: string; sub: string; tone?: "warn" | "bad" | "good"; tip: string }) {
  return (
    <Tip tip={tip} className="flex">
      <div tabIndex={0} className="w-full cursor-help rounded-2xl border border-gray-100 bg-white px-4 py-3 focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-200">
        <p className="text-[10px] font-black uppercase tracking-widest text-gray-400">{label}</p>
        <p className={`text-2xl font-black tabular-nums mt-1 ${tone === "bad" ? "text-rose-600" : tone === "warn" ? "text-amber-600" : tone === "good" ? "text-emerald-600" : "text-gray-900"}`}>{value}</p>
        <p className="text-[11px] text-gray-500 mt-0.5 leading-snug">{sub}</p>
      </div>
    </Tip>
  );
}

function CopyButton({ text, label }: { text: string; label: string }) {
  const [done, setDone] = useState(false);
  return (
    <button type="button" aria-label={label} onClick={e => { e.stopPropagation(); navigator.clipboard?.writeText(text).then(() => { setDone(true); setTimeout(() => setDone(false), 1500); }, () => {}); }}
      className="rounded px-1.5 py-0.5 text-[10px] font-bold text-gray-500 hover:bg-white hover:text-gray-800">{done ? "Copied ✓" : "Copy"}</button>
  );
}

/** Where a rule fires: the first few files, and on request every one, grouped by repository. */
function WhereItFires({ rule, usage }: { rule: CatalogRule; usage: RuleUsage }) {
  const [all, setAll] = useState<All | null>(null);
  const [repo, setRepo] = useState("all");
  const [q, setQ] = useState("");
  const first = usage.where ?? [];
  const more = usage.files - first.length;

  async function showAll() {
    setAll({ status: "loading" });
    try {
      const r = await authedFetch<{ locations: RuleLocation[]; total: number; truncated: boolean }>(`/api/rules?rule=${encodeURIComponent(rule.id)}`);
      setAll({ status: "done", locations: r.locations, total: r.total, truncated: r.truncated });
    } catch (e) { setAll({ status: "error", message: e instanceof Error ? e.message : "Couldn't load the files." }); }
  }

  const done = all?.status === "done" ? all : null;
  const list = done ? done.locations.filter(l => (repo === "all" || l.repo === repo) && (!q.trim() || l.file_path.toLowerCase().includes(q.trim().toLowerCase()))) : first;
  const groups = groupByRepo(list);
  const repos = done ? groupByRepo(done.locations) : [];

  return (
    <div className="mt-3" data-testid="where-it-fires">
      <p className="text-[10px] font-black uppercase tracking-widest text-gray-400 mb-1">
        Where it fires <span className="font-bold normal-case tracking-normal text-gray-500">({plural(usage.files, "file")} in {plural(usage.repos, "repository", "repositories")})</span>
      </p>
      {done && (repos.length > 1 || done.total > 15) && (
        <div className="mb-2 flex flex-wrap items-center gap-2">
          {repos.length > 1 && (
            <select aria-label="Repository" value={repo} onChange={e => setRepo(e.target.value)} className={SELECT}>
              <option value="all">All repositories ({repos.length})</option>
              {repos.map(g => <option key={g.repo} value={g.repo}>{g.repo} ({g.files.length})</option>)}
            </select>
          )}
          <input aria-label="Filter files" value={q} onChange={e => setQ(e.target.value)} placeholder="Filter by path…" className="w-48 max-w-full rounded-lg border border-gray-200 px-2.5 py-1.5 text-xs focus:outline-none focus:ring-2 focus:ring-indigo-200" />
          <span className="text-[11px] text-gray-400">{list.length} shown</span>
        </div>
      )}
      <div className={done ? "max-h-72 overflow-y-auto pr-1" : ""}>
        {groups.map(g => (
          <div key={g.repo} className="mb-1.5">
            <p className="text-[11px] font-bold text-gray-600">{g.repo.split("/").pop()} <span className="font-normal text-gray-400">· {plural(g.files.length, "file")}</span></p>
            <ul className="space-y-0.5">
              {g.files.map(l => (
                <li key={`${l.repo}::${l.file_path}`} className="text-xs">
                  <Link href={fileHref(l)} onClick={e => e.stopPropagation()} className="break-all text-indigo-600 hover:text-indigo-800">
                    <span className="font-mono">{l.file_path}</span>
                  </Link>
                </li>
              ))}
            </ul>
          </div>
        ))}
        {done && list.length === 0 && <p className="text-xs text-gray-400">No file matches.</p>}
      </div>
      {!all && more > 0 && (
        <button onClick={e => { e.stopPropagation(); void showAll(); }} className="mt-1 text-xs font-bold text-indigo-600 hover:text-indigo-800">Show all {usage.files} files →</button>
      )}
      {all?.status === "loading" && <p className="mt-1 text-xs text-gray-400" role="status">Loading every file…</p>}
      {all?.status === "error" && <p className="mt-1 text-xs text-rose-600" role="alert">{all.message} <button onClick={e => { e.stopPropagation(); void showAll(); }} className="font-bold underline">Try again</button></p>}
      {done && (
        <div className="mt-2 space-y-1.5">
          <CapNotice cap="ruleLocations" shown={done.locations.length} total={done.truncated ? done.total : null} noun="files" />
          {done.locations.length > first.length && <button onClick={e => { e.stopPropagation(); setAll(null); setRepo("all"); setQ(""); }} className="text-xs font-semibold text-gray-500 hover:text-gray-800">Show fewer</button>}
        </div>
      )}
    </div>
  );
}

function Remediation({ rule: r, rules, onOpenRule }: { rule: CatalogRule; rules: CatalogRule[]; onOpenRule: (id: string) => void }) {
  const g = guidanceFor(r.severity);
  const steps = r.fix ? fixSteps(r.fix.description) : [];
  const related = relatedRules(r, rules);
  const cwe = cweUrl(r.cwe);
  return (
    <div className="min-w-0 space-y-3" data-testid="remediation">
      <p className="text-[10px] font-black uppercase tracking-widest text-gray-400">Remediation</p>
      {g && (
        <div className={`rounded-lg border px-3 py-2 ${SEV_STYLE[r.severity!]}`}>
          <p className="text-xs font-bold">Priority: {g.sla}</p>
          <p className="text-[11px] leading-snug">{g.when}</p>
        </div>
      )}
      {r.fix ? (
        <>
          <div>
            <p className="text-xs font-semibold text-gray-800">{r.fix.title}</p>
            {r.fix.effort && <p className="mt-0.5 text-[11px] text-gray-500"><span className="font-semibold">Effort:</span> {EFFORT_LABEL[r.fix.effort]}</p>}
          </div>
          <div>
            <p className="text-[10px] font-black uppercase tracking-widest text-gray-400 mb-1">How to fix</p>
            <ol className="list-decimal space-y-1 pl-4 text-xs leading-relaxed text-gray-700 marker:font-bold marker:text-gray-400">
              {steps.map((s, i) => <li key={i}>{s}</li>)}
            </ol>
          </div>
          {(r.fix.code_before || r.fix.code_after) && (
            <div className="grid gap-2">
              {r.fix.code_before && (
                <div className="overflow-hidden rounded-lg ring-1 ring-rose-200">
                  <div className="flex items-center justify-between bg-rose-100/70 px-2.5 py-1"><span className="text-[10px] font-black uppercase tracking-wider text-rose-800">Vulnerable</span><CopyButton text={r.fix.code_before} label="Copy the vulnerable example" /></div>
                  <pre className="overflow-x-auto whitespace-pre bg-rose-50/70 px-2.5 py-1.5 font-mono text-[10.5px] text-rose-900">{r.fix.code_before}</pre>
                </div>
              )}
              {r.fix.code_after && (
                <div className="overflow-hidden rounded-lg ring-1 ring-emerald-200">
                  <div className="flex items-center justify-between bg-emerald-100/70 px-2.5 py-1"><span className="text-[10px] font-black uppercase tracking-wider text-emerald-800">Fixed</span><CopyButton text={r.fix.code_after} label="Copy the fixed example" /></div>
                  <pre className="overflow-x-auto whitespace-pre bg-emerald-50/70 px-2.5 py-1.5 font-mono text-[10.5px] text-emerald-900">{r.fix.code_after}</pre>
                </div>
              )}
            </div>
          )}
        </>
      ) : <p className="text-xs text-gray-400">No specific fix is recorded for this rule. The description says what it flags; the CWE page below covers the general remedy.</p>}
      <div>
        <p className="text-[10px] font-black uppercase tracking-widest text-gray-400 mb-1">How to verify</p>
        <ol className="list-decimal space-y-1 pl-4 text-xs leading-relaxed text-gray-700 marker:font-bold marker:text-gray-400">
          {verifySteps(r.detection).map((s, i) => <li key={i}>{s}</li>)}
        </ol>
      </div>
      {(related.length > 0 || cwe) && (
        <div className="space-y-1">
          {related.length > 0 && (
            <p className="text-[11px] text-gray-500"><span className="font-semibold">Related ({r.cwe}):</span>{" "}
              {related.map((x, i) => <span key={x.id}>{i > 0 && ", "}<button onClick={e => { e.stopPropagation(); onOpenRule(x.id); }} className="font-semibold text-indigo-600 hover:underline">{x.title}</button></span>)}
            </p>
          )}
          {cwe && <p className="text-[11px]"><a href={cwe} target="_blank" rel="noopener noreferrer" onClick={e => e.stopPropagation()} className="font-semibold text-indigo-600 hover:underline">Read about {r.cwe} on MITRE ↗</a></p>}
        </div>
      )}
    </div>
  );
}

function UsageCell({ usage, repoCount }: { usage: RuleUsage | null; repoCount?: number }) {
  void repoCount;
  if (usage == null) return <span className="text-gray-300">—</span>;
  return (
    <div className="flex flex-col items-end gap-0.5">
      {usage.files > 0
        ? <span className="font-bold text-amber-700" title={`${plural(usage.files, "file")} in ${plural(usage.repos, "repository", "repositories")}`}>{plural(usage.files, "file")}<span className="font-normal text-gray-400"> · {plural(usage.repos, "repo")}</span></span>
        : <span className="text-gray-400">None</span>}
      {(usage.new ?? 0) > 0 && <Tip tip="Files where this rule fires now and did not in the previous scan."><span tabIndex={0} className="cursor-help rounded-full bg-rose-50 px-1.5 py-px text-[10px] font-bold text-rose-700 ring-1 ring-rose-200 focus:outline-none focus-visible:ring-2">▲ {usage.new} new</span></Tip>}
      {(usage.fixed ?? 0) > 0 && <Tip tip="Files where this rule fired in the previous scan and no longer does."><span tabIndex={0} className="cursor-help rounded-full bg-emerald-50 px-1.5 py-px text-[10px] font-bold text-emerald-700 ring-1 ring-emerald-200 focus:outline-none focus-visible:ring-2">✓ {usage.fixed} fixed</span></Tip>}
    </div>
  );
}

function RuleRow({ rule: r, rules, usage, open, onToggle, onOpenRule }: { rule: CatalogRule; rules: CatalogRule[]; usage: RuleUsage | null; open: boolean; onToggle: () => void; onOpenRule: (id: string) => void }) {
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
        <td className="px-4 py-2.5 text-right whitespace-nowrap"><UsageCell usage={usage} /></td>
      </tr>
      {open && (
        <tr className="bg-gray-50/50">
          <td colSpan={6} className="px-4 pb-4 pt-1">
            <div className="grid gap-5 md:grid-cols-2">
              <div className="min-w-0">
                <p className="text-[10px] font-black uppercase tracking-widest text-gray-400 mb-1">What it finds</p>
                <p className="text-xs text-gray-700 leading-relaxed">{r.description}</p>
                <p className="text-[11px] text-gray-500 mt-2">{DETECTION_DESC[r.detection]}</p>
                {usage && usage.files > 0 && <WhereItFires rule={r} usage={usage} />}
                {usage && usage.files === 0 && (usage.fixed ?? 0) > 0 && <p className="mt-3 text-xs font-semibold text-emerald-700">✓ Fixed in {plural(usage.fixed!, "file")} since the previous scan. It no longer fires anywhere.</p>}
                {usage && usage.files === 0 && !(usage.fixed ?? 0) && <p className="mt-3 text-xs text-gray-400">It does not fire in the latest scans.</p>}
                <button onClick={copy} className="mt-3 text-xs font-semibold text-gray-500 hover:text-gray-800">{copied ? "Link copied ✓" : "Copy link to this rule"}</button>
              </div>
              <Remediation rule={r} rules={rules} onOpenRule={onOpenRule} />
            </div>
          </td>
        </tr>
      )}
    </>
  );
}
