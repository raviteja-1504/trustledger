"use client";

/**
 * API Security: every endpoint your code and OpenAPI specs declare (latest scan of each repository), the
 * authentication visible for each, and API findings -- from /api/api-security (lib/api/apiSecurityReport.ts).
 * One repository filter scopes the whole page; every finding and endpoint links to the scan it comes from.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import AuthGuard from "@/components/AuthGuard";
import { isSeedMode, authedFetch } from "@/lib/useRealData";
import { useAuth } from "@/lib/auth";
import { useScansRealtime } from "@/lib/realtime";
import { relativeTime, useTimezone } from "@/lib/timezone";
import { buildApiSecurityReport, type ApiSecurityReport, type InventoryEndpoint } from "@/lib/api/apiSecurityReport";

const METHOD_STYLE: Record<string, string> = {
  GET: "bg-sky-100 text-sky-700", POST: "bg-emerald-100 text-emerald-700", PUT: "bg-amber-100 text-amber-800", PATCH: "bg-amber-100 text-amber-800",
  DELETE: "bg-rose-100 text-rose-700", ANY: "bg-slate-100 text-slate-600",
};
const SEV_STYLE: Record<string, string> = {
  critical: "bg-rose-50 text-rose-700 border-rose-200", high: "bg-orange-50 text-orange-700 border-orange-200",
  medium: "bg-amber-50 text-amber-800 border-amber-200", low: "bg-slate-50 text-slate-600 border-slate-200", info: "bg-slate-50 text-slate-500 border-slate-200",
};
const AUTH_STYLE: Record<InventoryEndpoint["auth"], { label: string; cls: string; help: string }> = {
  required: { label: "Auth required", cls: "bg-emerald-50 text-emerald-700 border-emerald-200", help: "A check is applied to this route in the same file or spec" },
  public:   { label: "Explicitly public", cls: "bg-blue-50 text-blue-700 border-blue-200", help: "Marked public on purpose (e.g. security: [] in the spec)" },
  none:     { label: "No auth visible", cls: "bg-amber-50 text-amber-800 border-amber-200", help: "Nothing in this file protects it; auth applied globally elsewhere wouldn't show here" },
};
const FINDINGS_SHOWN = 50, ENDPOINTS_SHOWN = 200;
const SELECT = "text-xs font-semibold text-gray-700 bg-white border border-gray-200 rounded-lg px-2.5 py-1.5 max-w-[14rem]";
const pct = (n: number, d: number) => (d ? `${Math.round((n / d) * 100)}%` : "—");

// Offline demo only: the real report builder over sample files.
function makeOffline(): ApiSecurityReport {
  return buildApiSecurityReport([{
    repo: "acme/storefront", scan_id: "demo",
    files: [
      { file_path: "src/routes/orders.ts", content: `const router = express.Router();\nrouter.get("/orders", requireUser, listOrders);\nrouter.get("/orders/:id", requireUser, getOrder);\nrouter.post("/orders", requireUser, createOrder);\nrouter.delete("/orders/:id", deleteOrder);\nrouter.post("/login", login);\n` },
      { file_path: "api/openapi.yaml", content: `openapi: 3.0.3\ninfo: { title: Storefront, version: "1" }\nservers:\n  - url: http://api.storefront.example\ncomponents:\n  securitySchemes:\n    key: { type: apiKey, in: query, name: api_key }\npaths:\n  /products:\n    get:\n      security:\n        - key: []\n  /admin/refunds:\n    post:\n      responses: {}\n` },
    ],
  }]);
}

export default function ApiSecurityPage() {
  const { profile } = useAuth();
  const tz = useTimezone();
  const demo = isSeedMode() && !profile?.org_id;
  const [report, setReport] = useState<ApiSecurityReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [repo, setRepo] = useState("all");
  const [sev, setSev] = useState("all");
  const [auth, setAuth] = useState<InventoryEndpoint["auth"] | "flagged" | "all">("all");
  const [method, setMethod] = useState("all");
  const [source, setSource] = useState<"all" | "code" | "spec">("all");
  const [search, setSearch] = useState("");
  const [open, setOpen] = useState<string | null>(null);
  const [allFindings, setAllFindings] = useState(false);
  const [allEndpoints, setAllEndpoints] = useState(false);

  const load = useCallback(async (spinner = false) => {
    if (demo) { setReport(makeOffline()); return; }
    if (spinner) setRefreshing(true);
    try { setReport(await authedFetch<ApiSecurityReport>("/api/api-security")); setError(null); }
    catch (e) { setError(e instanceof Error ? e.message : "Couldn't load the API security report."); }
    finally { setRefreshing(false); }
  }, [demo]);

  useEffect(() => { load(); }, [load]);
  useScansRealtime(profile?.org_id, () => { load(); });
  useEffect(() => {
    const onFocus = () => { if (!document.hidden) load(); };
    window.addEventListener("focus", onFocus);
    return () => window.removeEventListener("focus", onFocus);
  }, [load]);

  const repos = report?.repos ?? [];
  const scope = repo === "all" ? null : repos.find(r => r.repo === repo) ?? null;
  const c = scope ?? report?.counts;
  const findings = useMemo(() => (report?.findings ?? []).filter(f => (repo === "all" || f.repo === repo) && (sev === "all" || f.severity === sev)), [report, repo, sev]);
  const methods = useMemo(() => [...new Set((report?.endpoints ?? []).map(e => e.method))].sort(), [report]);
  const endpoints = useMemo(() => (report?.endpoints ?? []).filter(e => {
    if (repo !== "all" && e.repo !== repo) return false;
    if (auth === "flagged" ? !e.flagged : auth !== "all" && e.auth !== auth) return false;
    if (method !== "all" && e.method !== method) return false;
    if (source !== "all" && e.source !== source) return false;
    const q = search.trim().toLowerCase();
    return !q || [e.method, e.path, e.file, e.repo, e.framework].join(" ").toLowerCase().includes(q);
  }), [report, repo, auth, method, source, search]);
  const narrowed = repo !== "all" || sev !== "all" || auth !== "all" || method !== "all" || source !== "all" || search !== "";

  return (
    <AuthGuard>
      <div className="max-w-7xl mx-auto space-y-5 pb-10">
        <header className="flex items-start justify-between gap-4 flex-wrap">
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-xl font-black text-gray-900 tracking-tight">API Security</h1>
              {!!report?.counts.flagged && <span className="text-xs font-black text-white bg-rose-600 px-2 py-0.5 rounded-full">{report.counts.flagged} missing auth</span>}
              {demo && <span className="text-[10px] font-bold text-amber-700 bg-amber-50 border border-amber-200 px-2 py-0.5 rounded-full">Demo data</span>}
            </div>
            <p className="text-sm text-gray-500 mt-0.5 max-w-3xl">Every endpoint your code and OpenAPI specs declare, the authentication visible for each, and API misconfigurations — from the latest scan of each repository.</p>
          </div>
          <button onClick={() => load(true)} disabled={refreshing} className="px-3 py-2 text-xs font-bold rounded-xl border border-gray-200 bg-white text-gray-600 hover:bg-gray-50 disabled:opacity-50">
            {refreshing ? "Refreshing…" : "Refresh"}
          </button>
        </header>

        {error && (
          <div role="alert" className="flex items-center justify-between gap-3 bg-rose-50 border border-rose-200 text-rose-800 px-4 py-3 rounded-xl text-sm">
            <span>Couldn&apos;t load the API security report. {error}</span>
            <button onClick={() => load(true)} className="font-bold text-xs">Retry</button>
          </div>
        )}
        {!report && !error && <div className="h-40 rounded-2xl bg-white border border-gray-100 animate-pulse" aria-label="Loading API security" />}

        {report && c && (
          <>
            <section aria-label="API summary" className="grid grid-cols-2 lg:grid-cols-5 gap-3">
              {[
                { k: "Endpoints", v: String(c.endpoints), s: `${c.specs} OpenAPI spec${c.specs === 1 ? "" : "s"}`, t: "" },
                { k: "Auth coverage", v: pct(c.authRequired + c.explicitlyPublic, c.endpoints), s: `${c.authRequired} protected · ${c.explicitlyPublic} public on purpose`, t: "text-emerald-700" },
                { k: "No auth visible", v: String(c.noAuthVisible), s: "may be protected globally", t: c.noAuthVisible ? "text-amber-700" : "" },
                { k: "Missing auth", v: String(c.flagged), s: "unprotected while the rest of the file is", t: c.flagged ? "text-rose-700" : "" },
                { k: "Findings", v: String(c.findings), s: scope ? `in ${scope.repo}` : `across ${repos.length} repositor${repos.length === 1 ? "y" : "ies"}`, t: c.findings ? "text-rose-700" : "" },
              ].map(x => (
                <div key={x.k} className="section-card px-4 py-3.5">
                  <p className="text-[10px] font-black uppercase tracking-widest text-gray-400">{x.k}</p>
                  <p className={`text-2xl font-black tabular-nums mt-1 ${x.t || "text-gray-900"}`}>{x.v}</p>
                  <p className="text-[11px] text-gray-500 mt-0.5 leading-snug">{x.s}</p>
                </div>
              ))}
            </section>

            {repos.length > 0 && (
              <section aria-label="Repositories" className="section-card overflow-hidden">
                <div className="px-5 py-3.5 border-b border-gray-100 flex flex-wrap items-center justify-between gap-2">
                  <p className="text-sm font-black text-gray-900">By repository</p>
                  <p className="text-[11px] text-gray-400">Click a repository to scope the page to it</p>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead><tr className="text-[10px] font-black uppercase tracking-widest text-gray-400 bg-gray-50/60 text-left">
                      <th className="px-5 py-2">Repository</th><th className="px-2 py-2 text-right">Endpoints</th><th className="px-2 py-2 text-right">Auth coverage</th>
                      <th className="px-2 py-2 text-right">Missing auth</th><th className="px-2 py-2 text-right">Findings</th><th className="px-5 py-2 text-right">Scanned</th>
                    </tr></thead>
                    <tbody>
                      {repos.map(r => (
                        <tr key={r.repo} onClick={() => setRepo(repo === r.repo ? "all" : r.repo)} aria-selected={repo === r.repo}
                          className={`border-t border-gray-50 cursor-pointer hover:bg-gray-50/70 ${repo === r.repo ? "bg-indigo-50/50" : ""}`}>
                          <td className="px-5 py-2.5 font-mono text-gray-800">{r.repo}</td>
                          <td className="px-2 py-2.5 text-right tabular-nums">{r.endpoints}</td>
                          <td className="px-2 py-2.5 text-right tabular-nums">{pct(r.authRequired + r.explicitlyPublic, r.endpoints)}</td>
                          <td className={`px-2 py-2.5 text-right tabular-nums ${r.flagged ? "text-rose-600 font-bold" : "text-gray-400"}`}>{r.flagged}</td>
                          <td className={`px-2 py-2.5 text-right tabular-nums ${r.findings ? "text-rose-600 font-bold" : "text-gray-400"}`}>{r.findings}</td>
                          <td className="px-5 py-2.5 text-right text-gray-500">
                            {r.scan_id !== "demo" ? <Link href={`/pr/${r.scan_id}`} onClick={e => e.stopPropagation()} className="hover:text-indigo-700">{r.scanned_at ? relativeTime(r.scanned_at, tz) : "latest scan"} →</Link> : "sample"}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </section>
            )}

            <div className="flex flex-wrap items-center gap-2">
              <select aria-label="Repository" value={repo} onChange={e => setRepo(e.target.value)} className={SELECT}>
                <option value="all">All repositories ({repos.length})</option>
                {repos.map(r => <option key={r.repo} value={r.repo}>{r.repo}</option>)}
              </select>
              {narrowed && <button onClick={() => { setRepo("all"); setSev("all"); setAuth("all"); setMethod("all"); setSource("all"); setSearch(""); }} className="text-xs font-bold text-rose-600 hover:text-rose-800 px-2 py-1 rounded-lg hover:bg-rose-50">Clear filters</button>}
            </div>

            <section aria-label="Findings" className="section-card overflow-hidden">
              <div className="px-5 py-3.5 border-b border-gray-100 flex flex-wrap items-center gap-2">
                <p className="text-sm font-black text-gray-900 mr-auto">Findings <span className="text-gray-400 font-bold">({findings.length})</span></p>
                <select aria-label="Severity" value={sev} onChange={e => setSev(e.target.value)} className={SELECT}>
                  <option value="all">Any severity</option>
                  {["critical", "high", "medium", "low", "info"].map(s => <option key={s} value={s}>{s[0].toUpperCase() + s.slice(1)}</option>)}
                </select>
              </div>
              {findings.length === 0 ? <p className="px-5 py-8 text-center text-sm text-gray-500">No API security findings{repo !== "all" ? " in this repository" : ""} in the latest scans.</p> : (
                <ul className="divide-y divide-gray-50">
                  {(allFindings ? findings : findings.slice(0, FINDINGS_SHOWN)).map(f => {
                    const key = `${f.repo}:${f.file}:${f.line}:${f.id}`;
                    const isOpen = open === key;
                    const cwe = f.cwe.match(/\d+/)?.[0];
                    return (
                      <li key={key}>
                        <button onClick={() => setOpen(isOpen ? null : key)} aria-expanded={isOpen} className="w-full text-left px-5 py-3 hover:bg-gray-50/70 flex items-start gap-3">
                          <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border shrink-0 uppercase ${SEV_STYLE[f.severity] ?? SEV_STYLE.medium}`}>{f.severity}</span>
                          <div className="min-w-0 flex-1">
                            <p className="text-xs font-bold text-gray-900">{f.title}</p>
                            <p className="text-[11px] text-gray-500 mt-0.5 break-words">{f.detail}</p>
                            <p className="text-[10px] font-mono text-gray-400 mt-1 break-all">{f.repo} · {f.file}:{f.line}</p>
                          </div>
                        </button>
                        {isOpen && (
                          <div className="px-5 pb-4 pl-[4.75rem] space-y-2">
                            {f.fix && <p className="text-xs text-gray-700 leading-relaxed"><span className="font-bold text-emerald-700">Fix: </span>{f.fix}</p>}
                            <div className="flex flex-wrap gap-3 text-xs font-semibold">
                              {f.scan_id !== "demo" && <Link href={`/pr/${f.scan_id}`} className="text-indigo-600 hover:text-indigo-800">Open in the scan →</Link>}
                              <Link href={`/rules#${encodeURIComponent(f.id)}`} className="text-indigo-600 hover:text-indigo-800">Rule <span className="font-mono">{f.id}</span></Link>
                              {cwe && <a href={`https://cwe.mitre.org/data/definitions/${cwe}.html`} target="_blank" rel="noreferrer" className="text-indigo-600 hover:text-indigo-800">{f.cwe} ↗</a>}
                            </div>
                          </div>
                        )}
                      </li>
                    );
                  })}
                </ul>
              )}
              {findings.length > FINDINGS_SHOWN && (
                <button onClick={() => setAllFindings(v => !v)} className="w-full py-2.5 text-xs font-semibold text-indigo-600 hover:bg-indigo-50 border-t border-gray-100">
                  {allFindings ? "Show fewer" : `Show all ${findings.length} findings`}
                </button>
              )}
            </section>

            <section aria-label="Endpoint inventory" className="section-card overflow-hidden">
              <div className="px-5 py-3.5 border-b border-gray-100 flex items-center gap-2 flex-wrap">
                <p className="text-sm font-black text-gray-900 mr-auto">Endpoint inventory <span className="text-gray-400 font-bold">({endpoints.length})</span></p>
                <input aria-label="Search endpoints" value={search} onChange={e => setSearch(e.target.value)} placeholder="Search path, file, framework…"
                  className="text-xs px-3 py-1.5 rounded-lg border border-gray-200 w-52 max-w-full focus:outline-none focus:ring-2 focus:ring-sky-200" />
                <select aria-label="Authentication" value={auth} onChange={e => setAuth(e.target.value as typeof auth)} className={SELECT}>
                  <option value="all">Any authentication</option>
                  <option value="flagged">Missing auth</option>
                  <option value="none">No auth visible</option>
                  <option value="required">Auth required</option>
                  <option value="public">Explicitly public</option>
                </select>
                <select aria-label="Method" value={method} onChange={e => setMethod(e.target.value)} className={SELECT}>
                  <option value="all">Any method</option>
                  {methods.map(m => <option key={m} value={m}>{m}</option>)}
                </select>
                <select aria-label="Declared in" value={source} onChange={e => setSource(e.target.value as typeof source)} className={SELECT}>
                  <option value="all">Code and specs</option><option value="code">Code</option><option value="spec">OpenAPI specs</option>
                </select>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead><tr className="text-[10px] font-black uppercase tracking-widest text-gray-400 bg-gray-50/60 text-left">
                    <th className="px-5 py-2 w-20">Method</th><th className="px-2 py-2">Path</th><th className="px-2 py-2">Authentication</th><th className="px-2 py-2">Declared in</th>
                  </tr></thead>
                  <tbody>
                    {endpoints.length === 0 ? <tr><td colSpan={4} className="px-5 py-8 text-center text-gray-500">No endpoints match.</td></tr>
                      : (allEndpoints ? endpoints : endpoints.slice(0, ENDPOINTS_SHOWN)).map(e => {
                        const a = AUTH_STYLE[e.auth];
                        return (
                          <tr key={`${e.repo}:${e.file}:${e.line}:${e.method}:${e.path}`} className={`border-t border-gray-50 ${e.flagged ? "bg-rose-50/40" : ""}`}>
                            <td className="px-5 py-2"><span className={`text-[10px] font-black px-1.5 py-0.5 rounded ${METHOD_STYLE[e.method] ?? METHOD_STYLE.ANY}`}>{e.method}</span></td>
                            <td className="px-2 py-2 font-mono text-gray-800 break-all">{e.path}</td>
                            <td className="px-2 py-2">
                              <div className="flex items-center gap-1.5 flex-wrap">
                                <span title={a.help} className={`text-[10px] font-bold px-1.5 py-0.5 rounded border whitespace-nowrap ${a.cls}`}>{a.label}</span>
                                {e.flagged && <span className="text-[10px] font-black px-1.5 py-0.5 rounded bg-rose-600 text-white whitespace-nowrap">Missing auth</span>}
                                {e.authEvidence && <code className="text-[10px] text-gray-500 truncate max-w-[14rem]">{e.authEvidence}</code>}
                              </div>
                            </td>
                            <td className="px-2 py-2 text-[10px] font-mono text-gray-500">
                              {e.scan_id !== "demo"
                                ? <Link href={`/pr/${e.scan_id}`} className="hover:text-indigo-700 break-all">{e.repo.split("/").pop()} · {e.file}:{e.line}</Link>
                                : <span>{e.repo.split("/").pop()} · {e.file}:{e.line}</span>}
                              <span className="ml-1.5 text-gray-400">({e.source === "spec" ? "OpenAPI" : e.framework})</span>
                            </td>
                          </tr>
                        );
                      })}
                  </tbody>
                </table>
              </div>
              {endpoints.length > ENDPOINTS_SHOWN && (
                <button onClick={() => setAllEndpoints(v => !v)} className="w-full py-2.5 text-xs font-semibold text-indigo-600 hover:bg-indigo-50 border-t border-gray-100">
                  {allEndpoints ? "Show fewer" : `Show all ${endpoints.length} endpoints`}
                </button>
              )}
              {report.truncated && <p className="px-5 py-2 text-[11px] text-gray-500 border-t border-gray-50">The list carries the first {report.endpoints.length.toLocaleString()} endpoints (missing auth first); the counts above include all {report.counts.endpoints.toLocaleString()}.</p>}
            </section>

            <div className="flex items-start gap-3 bg-sky-50 border border-sky-100 rounded-xl px-4 py-3">
              <p className="text-xs text-sky-900 leading-relaxed">
                <span className="font-bold">How it works:</span> endpoints are read from the latest scan of each repository — Express/Next.js, Flask/FastAPI, Spring,
                ASP.NET, Go (net/http, gin, echo, chi) and Laravel routes, plus OpenAPI/Swagger specs. <strong>Auth coverage</strong> is the share of endpoints that are
                protected or deliberately public. <strong>No auth visible</strong> means nothing in that file protects the route — auth applied globally (app-wide
                middleware, Spring Security config) isn&apos;t visible here. <strong>Missing auth</strong> is stricter: other endpoints in the same file are protected and
                this one is not.
              </p>
            </div>
          </>
        )}
      </div>
    </AuthGuard>
  );
}
