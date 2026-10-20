"use client";

/**
 * Threat intel: published advisories that actually affect your code. Every row is a real finding from the latest scan
 * of each repository (/api/dependencies, lib/dependencyScan.ts): a package version with a known vulnerability
 * (advisory id, CVSS, public exploit, whether the vulnerable code is reachable, fixed version), or a supply-chain risk
 * (a package that doesn't exist, a likely typosquat). There is no static catalogue of threats -- an advisory appears
 * here only when one of your repositories uses the affected package.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import AuthGuard from "@/components/AuthGuard";
import { authedFetch, isSeedMode } from "@/lib/useRealData";
import { useAuth } from "@/lib/auth";
import { useScansRealtime } from "@/lib/realtime";
import { buildAdvisories, filterFindings, filterOptions, NO_FILTERS, type Advisory, type AdvisoryFinding, type ThreatFilters } from "@/lib/threatIntel";
import { LoadingBlock } from "@/components/Loading";

const SELECT = "text-xs font-semibold text-gray-700 bg-white border border-gray-200 rounded-lg px-2.5 py-1.5 focus:outline-none focus:ring-2 focus:ring-indigo-300 max-w-[14rem]";

const SEV: Record<string, string> = {
  CRITICAL: "bg-violet-100 text-violet-700", HIGH: "bg-orange-100 text-orange-700", MEDIUM: "bg-amber-100 text-amber-800", LOW: "bg-gray-100 text-gray-600",
};

function advisoryUrl(id: string | undefined) {
  if (!id) return null;
  if (/^CVE-\d{4}-\d+$/i.test(id)) return `https://nvd.nist.gov/vuln/detail/${id.toUpperCase()}`;
  if (/^GHSA-/i.test(id)) return `https://github.com/advisories/${id}`;
  return `https://osv.dev/vulnerability/${encodeURIComponent(id)}`;
}

function Stat({ label, value, sub, tone }: { label: string; value: number; sub: string; tone?: "bad" }) {
  return (
    <div className="bg-white rounded-2xl border border-gray-100 p-5 shadow-[0_1px_2px_rgba(15,23,42,0.05)]">
      <p className="text-[11px] font-semibold uppercase tracking-wide text-gray-500">{label}</p>
      <p className={`mt-2 text-3xl font-black tabular-nums leading-none ${tone === "bad" && value > 0 ? "text-rose-600" : "text-gray-900"}`}>{value}</p>
      <p className="mt-2 text-xs text-gray-500 leading-snug">{sub}</p>
    </div>
  );
}

export default function ThreatIntelPage() {
  const { profile } = useAuth();
  const offline = isSeedMode() && !profile?.org_id;
  const [findings, setFindings] = useState<AdvisoryFinding[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<"all" | "exploit" | "reachable">("all");
  const [q, setQ] = useState("");
  const [sel, setSel] = useState<ThreatFilters>(NO_FILTERS);

  const load = useCallback(async () => {
    if (offline) return;
    try {
      const r = await authedFetch<{ findings: AdvisoryFinding[] }>("/api/dependencies");
      setFindings(r.findings ?? []); setError(null);
    } catch (e) { setError(e instanceof Error ? e.message : "Couldn't load advisories"); }
  }, [offline]);

  useEffect(() => { load(); }, [load]);
  useScansRealtime(profile?.org_id, () => { load(); });
  useEffect(() => {
    const onFocus = () => { if (!document.hidden) load(); };
    window.addEventListener("focus", onFocus);
    return () => window.removeEventListener("focus", onFocus);
  }, [load]);

  const options = useMemo(() => filterOptions(findings ?? []), [findings]);
  // A repo/ecosystem that's gone from the data (e.g. after a rescan) falls back to "all" instead of showing nothing.
  const repo = sel.repo !== "all" && !options.repos.includes(sel.repo) ? "all" : sel.repo;
  const ecosystem = sel.ecosystem !== "all" && !options.ecosystems.includes(sel.ecosystem) ? "all" : sel.ecosystem;
  const { advisories, supplyChain, stats } = useMemo(() => buildAdvisories(filterFindings(findings ?? [], { repo, ecosystem })), [findings, repo, ecosystem]);
  const shown = advisories.filter(a =>
    (filter === "all" || (filter === "exploit" ? a.exploit_public : a.reachable === true)) &&
    (sel.severity === "all" || a.risk === sel.severity) &&
    (!q || `${a.id ?? ""} ${a.package_name} ${a.description} ${a.repos.join(" ")}`.toLowerCase().includes(q.toLowerCase())));
  const narrowed = repo !== "all" || ecosystem !== "all" || sel.severity !== "all" || filter !== "all" || q !== "";

  return (
    <AuthGuard>
      <div className="max-w-[1400px] mx-auto space-y-8 pb-16">
        <header className="animate-fade-up flex flex-wrap items-end justify-between gap-4">
          <div>
            <h1 className="text-2xl font-black text-gray-900 tracking-tight">Threat intel</h1>
            <p className="text-sm text-gray-500 mt-0.5 max-w-2xl">
              Published advisories that affect packages your repositories actually use, from the latest scan of each repository.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Link href="/dependencies" className="px-3 py-2 text-xs font-semibold text-indigo-700 bg-indigo-50 border border-indigo-100 rounded-xl hover:bg-indigo-100">All dependencies →</Link>
            <button onClick={load} className="px-3 py-2 text-xs font-semibold text-gray-600 bg-white border border-gray-200 rounded-xl hover:bg-gray-50 shadow-sm">Refresh</button>
          </div>
        </header>

        {offline && <div className="section-card p-6 text-sm text-gray-600">Connect a repository to see the advisories that affect it.</div>}
        {error && !findings && (
          <div role="alert" className="flex items-center justify-between gap-3 bg-rose-50 border border-rose-200 text-rose-800 px-4 py-3 rounded-xl text-sm">
            <span>Couldn&apos;t load advisories. {error}</span>
            <button onClick={load} className="font-bold text-xs">Retry</button>
          </div>
        )}
        {!offline && !findings && !error && <LoadingBlock label="advisories" rows={4} />}

        {findings && (
          <>
            {/* Scope: applies to the stats, the advisories and the supply-chain list alike. */}
            <div className="animate-fade-up flex flex-wrap items-center gap-2" role="group" aria-label="Scope">
              <select aria-label="Repository" value={repo} onChange={e => setSel(s => ({ ...s, repo: e.target.value }))} className={SELECT}>
                <option value="all">All repositories ({options.repos.length})</option>
                {options.repos.map(r => <option key={r} value={r}>{r}</option>)}
              </select>
              <select aria-label="Ecosystem" value={ecosystem} onChange={e => setSel(s => ({ ...s, ecosystem: e.target.value }))} className={SELECT}>
                <option value="all">All ecosystems</option>
                {options.ecosystems.map(x => <option key={x} value={x}>{x}</option>)}
              </select>
              <select aria-label="Severity" value={sel.severity} onChange={e => setSel(s => ({ ...s, severity: e.target.value }))} className={SELECT}>
                <option value="all">Any severity</option>
                {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map(x => <option key={x} value={x}>{x[0] + x.slice(1).toLowerCase()}</option>)}
              </select>
              {narrowed && (
                <button onClick={() => { setSel(NO_FILTERS); setFilter("all"); setQ(""); }}
                  className="text-xs font-bold text-rose-600 hover:text-rose-800 px-2 py-1 rounded-lg hover:bg-rose-50">Clear filters</button>
              )}
            </div>

            <div className="animate-fade-up grid grid-cols-1 min-[420px]:grid-cols-2 lg:grid-cols-4 gap-4">
              <Stat label="Advisories affecting you" value={stats.advisories} sub={`${stats.packages} package version${stats.packages === 1 ? "" : "s"} across ${stats.repos} repo${stats.repos === 1 ? "" : "s"}`} />
              <Stat label="Public exploit available" value={stats.exploits} sub="Exploit code is published" tone="bad" />
              <Stat label="Reachable from your code" value={stats.reachable} sub="The vulnerable code is called" tone="bad" />
              <Stat label="Supply-chain risks" value={supplyChain.length} sub="Packages that don't exist or look like typosquats" tone="bad" />
            </div>

            <section aria-label="Advisories" className="animate-fade-up section-card overflow-hidden">
              <div className="flex flex-wrap items-center justify-between gap-3 px-6 pt-5 pb-4 border-b border-gray-100">
                <div>
                  <h2 className="text-sm font-bold text-gray-900">Known vulnerabilities in your dependencies</h2>
                  <p className="text-xs text-gray-400 mt-0.5">
                    {narrowed ? `${shown.length} of ${advisories.length} shown · ` : ""}Exploitable and reachable first, then by severity
                  </p>
                </div>
                <div className="flex items-center gap-2 flex-wrap">
                  <div className="flex gap-0.5 bg-gray-100 p-1 rounded-xl" role="group" aria-label="Filter">
                    {([["all", "All"], ["exploit", "Public exploit"], ["reachable", "Reachable"]] as const).map(([k, l]) => (
                      <button key={k} onClick={() => setFilter(k)} aria-pressed={filter === k}
                        className={`px-3 py-1.5 text-xs font-semibold rounded-lg ${filter === k ? "bg-white text-gray-900 shadow-sm" : "text-gray-500 hover:text-gray-700"}`}>{l}</button>
                    ))}
                  </div>
                  <input value={q} onChange={e => setQ(e.target.value)} placeholder="Search" aria-label="Search advisories"
                    className="w-40 text-xs border border-gray-200 rounded-lg px-2.5 py-1.5 focus:outline-none focus:ring-2 focus:ring-indigo-300" />
                </div>
              </div>
              {shown.length === 0 ? (
                <p className="px-6 py-12 text-center text-sm text-gray-500">
                  {advisories.length === 0 ? "No known vulnerabilities in the packages your repositories use." : "No advisories match this filter."}
                </p>
              ) : (
                <ul className="divide-y divide-gray-100">
                  {shown.map((a: Advisory) => {
                    const url = advisoryUrl(a.id);
                    return (
                      <li key={a.key} className="px-6 py-5 flex flex-col lg:flex-row lg:items-start gap-4">
                        <div className="min-w-0 flex-1">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className={`text-[11px] font-black px-2 py-0.5 rounded ${SEV[a.risk] ?? SEV.LOW}`}>{a.risk}</span>
                            {a.cvss != null && <span className="text-xs font-bold text-gray-700">CVSS {a.cvss.toFixed(1)}</span>}
                            {a.exploit_public && <span className="text-[11px] font-bold text-rose-700 bg-rose-50 px-2 py-0.5 rounded">Public exploit</span>}
                            {a.reachable === true && <span className="text-[11px] font-bold text-rose-700 bg-rose-50 px-2 py-0.5 rounded">Reachable</span>}
                            {a.reachable === false && <span className="text-[11px] font-semibold text-gray-500 bg-gray-100 px-2 py-0.5 rounded">Not reachable</span>}
                            {url
                              ? <a href={url} target="_blank" rel="noreferrer" className="text-xs font-mono font-bold text-indigo-600 hover:underline">{a.id}</a>
                              : <span className="text-xs text-gray-400">no advisory id</span>}
                          </div>
                          <p className="mt-2 text-sm font-bold text-gray-900">
                            <span className="font-mono">{a.package_name}@{a.version_used}</span>
                            <span className="text-gray-400 font-normal"> · {a.ecosystem}</span>
                          </p>
                          <p className="mt-1 text-sm text-gray-600 leading-relaxed">{a.description}</p>
                          {a.exploit_detail && <p className="mt-1 text-xs text-rose-700">{a.exploit_detail}</p>}
                        </div>
                        <div className="lg:w-72 shrink-0 space-y-2">
                          <p className="text-xs text-gray-500">Used in <strong className="text-gray-800">{a.repos.length}</strong> repo{a.repos.length === 1 ? "" : "s"}:</p>
                          <div className="flex flex-wrap gap-1.5">
                            {a.repos.map(r => <Link key={r} href={`/repo/${r}`} className="text-xs font-semibold text-gray-700 bg-gray-50 ring-1 ring-gray-200 rounded-lg px-2 py-0.5 hover:bg-indigo-50 break-all">{r}</Link>)}
                          </div>
                          {a.fix && <p className="text-xs text-emerald-700"><strong>Fix:</strong> {a.fix}</p>}
                        </div>
                      </li>
                    );
                  })}
                </ul>
              )}
            </section>

            <section aria-label="Supply-chain risks" className="animate-fade-up section-card p-6">
              <h2 className="text-sm font-bold text-gray-900">Supply-chain risks</h2>
              <p className="text-xs text-gray-400 mt-0.5 mb-4">Imported packages that don&apos;t exist in their registry (often suggested by AI tools) or look like typosquats of popular ones</p>
              {supplyChain.length === 0 ? <p className="text-sm text-gray-500">None found.</p> : (
                <ul className="divide-y divide-gray-100">
                  {supplyChain.map(f => (
                    <li key={f.id} className="py-3 flex flex-wrap items-start justify-between gap-3">
                      <div className="min-w-0">
                        <p className="text-sm font-bold text-gray-900"><span className="font-mono break-all">{f.package_name}</span>
                          <span className={`ml-2 text-[11px] font-bold px-2 py-0.5 rounded ${f.type === "hallucinated" ? "bg-rose-50 text-rose-700" : "bg-amber-50 text-amber-800"}`}>{f.type === "hallucinated" ? "Doesn't exist" : "Possible typosquat"}</span>
                        </p>
                        <p className="text-xs text-gray-600 mt-1">{f.description}</p>
                      </div>
                      <Link href={`/pr/${f.scan_id}`} className="text-xs font-semibold text-indigo-600 hover:text-indigo-800 break-all">{f.repo} · {f.file_path}</Link>
                    </li>
                  ))}
                </ul>
              )}
            </section>
          </>
        )}
      </div>
    </AuthGuard>
  );
}
