"use client";

/**
 * API Security: every endpoint your code and OpenAPI specs declare (latest scan of each repository), the
 * authentication visible for each, and API findings -- from /api/api-security (lib/api/apiSecurityReport.ts).
 *
 * The filter bar at the top (repository, search, open / resolved) scopes the whole page. An endpoint or finding
 * that is dealt with -- auth applied by a gateway, public on purpose, a scanner mistake -- is RESOLVED with a
 * reason and an expiry (lib/api/apiResolution.ts): it leaves the working list, stays on record, and comes back
 * when the decision expires.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import AuthGuard from "@/components/AuthGuard";
import Tip from "@/components/Tip";
import { CapNotice } from "@/components/Limits";
import { isSeedMode, authedFetch } from "@/lib/useRealData";
import { useAuth } from "@/lib/auth";
import { useRole } from "@/lib/roles";
import { useScansRealtime } from "@/lib/realtime";
import { relativeTime, useTimezone } from "@/lib/timezone";
import { EXPIRY_CHOICES } from "@/lib/findingLifecycle";
import { buildApiSecurityReport, type ApiSecurityFinding, type ApiSecurityReport, type InventoryEndpoint } from "@/lib/api/apiSecurityReport";
import { apiInsights, choicesFor, RESOLUTION_CHOICES, type ApiResolutionChoice, type Resolution } from "@/lib/api/apiResolution";
import { LoadingBlock } from "@/components/Loading";

const METHOD_STYLE: Record<string, string> = {
  GET: "bg-sky-100 text-sky-700", POST: "bg-emerald-100 text-emerald-700", PUT: "bg-amber-100 text-amber-800", PATCH: "bg-amber-100 text-amber-800",
  DELETE: "bg-rose-100 text-rose-700", ANY: "bg-slate-100 text-slate-600",
};
const SEV_STYLE: Record<string, string> = {
  critical: "bg-rose-50 text-rose-700 border-rose-200", high: "bg-orange-50 text-orange-700 border-orange-200",
  medium: "bg-amber-50 text-amber-800 border-amber-200", low: "bg-slate-50 text-slate-600 border-slate-200", info: "bg-slate-50 text-slate-500 border-slate-200",
};
const AUTH_STYLE: Record<InventoryEndpoint["auth"], { label: string; cls: string; help: string }> = {
  required: { label: "Auth required", cls: "bg-emerald-50 text-emerald-700 border-emerald-200", help: "A check is applied to this route in the same file or spec." },
  public:   { label: "Explicitly public", cls: "bg-blue-50 text-blue-700 border-blue-200", help: "Marked public on purpose (for example security: [] in the spec)." },
  none:     { label: "No auth visible", cls: "bg-amber-50 text-amber-800 border-amber-200", help: "Nothing in this file protects it. Auth applied globally elsewhere would not show here." },
};
const WRITE_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);
const FINDINGS_SHOWN = 50, ENDPOINTS_SHOWN = 200;
const SELECT = "text-xs font-semibold text-gray-700 bg-white border border-gray-200 rounded-lg px-2.5 py-1.5 max-w-[14rem]";
const pct = (n: number, d: number) => (d ? `${Math.round((n / d) * 100)}%` : "—");
const fmtDate = (iso: string) => new Date(iso).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });

type Show = "open" | "resolved" | "all";
const SHOW_LABEL: Record<Show, string> = { open: "Open", resolved: "Resolved", all: "All" };

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

/** Record a decision on one endpoint or finding: what kind, why, and until when. */
function ResolvePanel({ target, repo, keyId, file, noun, onSaved, onCancel }: {
  target: "endpoint" | "finding"; repo: string; keyId: string; file: string; noun: string; onSaved: () => void; onCancel: () => void;
}) {
  const choices = choicesFor(target);
  const [kind, setKind] = useState<ApiResolutionChoice["kind"]>(choices[0].kind);
  const [reason, setReason] = useState("");
  const [expiry, setExpiry] = useState<number | null>(90);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const chosen = choices.find(c => c.kind === kind) ?? choices[0];

  async function save() {
    if (reason.trim().length < 3) { setErr("Give a short reason, so the decision makes sense later."); return; }
    setBusy(true); setErr(null);
    try {
      await authedFetch("/api/findings/triage", { method: "POST", body: JSON.stringify({ repo, fingerprint: keyId, rule_id: chosen.ruleId, file_path: file, status: chosen.status, reason: reason.trim(), expires_in_days: expiry }) });
      onSaved();
    } catch (e) { setErr(e instanceof Error ? e.message : "Couldn't save the decision."); setBusy(false); }
  }

  return (
    <div className="space-y-3 rounded-xl border border-indigo-100 bg-indigo-50/40 p-4" data-testid="resolve-panel">
      <p className="text-xs font-bold text-gray-900">Resolve this {noun}</p>
      <div role="radiogroup" aria-label="Resolution" className="grid gap-2 sm:grid-cols-2">
        {choices.map(c => (
          <button key={c.kind} role="radio" aria-checked={kind === c.kind} onClick={() => setKind(c.kind)}
            className={`rounded-lg border px-3 py-2 text-left transition-colors ${kind === c.kind ? "border-indigo-400 bg-white ring-1 ring-indigo-300" : "border-gray-200 bg-white/70 hover:bg-white"}`}>
            <span className="block text-xs font-bold text-gray-900">{c.label}</span>
            <span className="mt-0.5 block text-[11px] leading-snug text-gray-500">{c.help}</span>
          </button>
        ))}
      </div>
      <label className="block text-[11px] font-semibold text-gray-600">Reason
        <textarea value={reason} onChange={e => setReason(e.target.value)} rows={2} maxLength={2000}
          placeholder={kind === "auth-elsewhere" ? "e.g. The API gateway requires a valid JWT on every /orders route" : "Say why, so the next reviewer understands"}
          className="mt-1 w-full rounded-lg border border-gray-200 bg-white px-2.5 py-1.5 text-xs font-normal text-gray-800 focus:outline-none focus:ring-2 focus:ring-indigo-300" />
      </label>
      <div className="flex flex-wrap items-center gap-2">
        <label className="text-[11px] font-semibold text-gray-600">Review again after
          <select value={expiry ?? ""} onChange={e => setExpiry(e.target.value ? Number(e.target.value) : null)} className={`${SELECT} ml-2`}>
            {EXPIRY_CHOICES.map(c => <option key={c.label} value={c.days ?? ""}>{c.label}</option>)}
          </select>
        </label>
        <span className="flex-1" />
        <button onClick={onCancel} className="text-xs font-semibold text-gray-500 hover:text-gray-700">Cancel</button>
        <button onClick={save} disabled={busy} className="rounded-lg bg-indigo-600 px-3.5 py-1.5 text-xs font-bold text-white hover:bg-indigo-700 disabled:opacity-60">{busy ? "Saving…" : "Save resolution"}</button>
      </div>
      <p className="text-[11px] text-gray-500">It stays on record, leaves the open list, and comes back when it expires. Reopen it any time from the Resolved view.</p>
      {err && <p role="alert" className="text-xs font-semibold text-rose-600">{err}</p>}
    </div>
  );
}

function ResolvedBadge({ r }: { r: Resolution }) {
  const label = RESOLUTION_CHOICES.find(c => c.kind === r.kind)?.label ?? "Resolved";
  const tip = `${label}${r.reason ? `: “${r.reason}”` : ""}${r.set_by_email ? `. By ${r.set_by_email}` : ""}${r.expires_at ? `, review again after ${fmtDate(r.expires_at)}` : ", no expiry"}.`;
  return (
    <Tip tip={tip}>
      <span tabIndex={0} className="cursor-help whitespace-nowrap rounded border border-violet-200 bg-violet-50 px-1.5 py-0.5 text-[10px] font-bold text-violet-700 focus:outline-none focus-visible:ring-2 focus-visible:ring-violet-300">Resolved · {label}</span>
    </Tip>
  );
}

export default function ApiSecurityPage() {
  const { profile } = useAuth();
  const { permissions } = useRole();
  const canResolve = !!permissions?.canTriage;
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
  const [show, setShow] = useState<Show>("open");
  const [open, setOpen] = useState<string | null>(null);
  const [resolving, setResolving] = useState<string | null>(null);
  const [reopenError, setReopenError] = useState<string | null>(null);
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

  async function reopen(r: string, key: string) {
    setReopenError(null);
    try { await authedFetch("/api/findings/triage", { method: "DELETE", body: JSON.stringify({ repo: r, fingerprint: key }) }); await load(); }
    catch (e) { setReopenError(e instanceof Error ? e.message : "Couldn't reopen it."); }
  }
  const saved = () => { setResolving(null); void load(); };

  const repos = report?.repos ?? [];
  const scope = repo === "all" ? null : repos.find(r => r.repo === repo) ?? null;
  const c = scope ?? report?.counts;
  const resolvedCount = scope ? scope.resolved ?? 0 : report?.counts.resolvedEndpoints ?? 0;
  const showOk = (resolution?: Resolution) => show === "all" || (show === "resolved" ? !!resolution : !resolution);
  const findings = useMemo(() => (report?.findings ?? []).filter(f => (repo === "all" || f.repo === repo) && (sev === "all" || f.severity === sev) && showOk(f.resolution)), [report, repo, sev, show]); // eslint-disable-line react-hooks/exhaustive-deps
  const methods = useMemo(() => [...new Set((report?.endpoints ?? []).map(e => e.method))].sort(), [report]);
  const endpoints = useMemo(() => (report?.endpoints ?? []).filter(e => {
    if (repo !== "all" && e.repo !== repo) return false;
    if (!showOk(e.resolution)) return false;
    if (auth === "flagged" ? !e.flagged : auth !== "all" && e.auth !== auth) return false;
    if (method === "writes" ? !WRITE_METHODS.has(e.method) : method !== "all" && e.method !== method) return false;
    if (source !== "all" && e.source !== source) return false;
    const q = search.trim().toLowerCase();
    return !q || [e.method, e.path, e.file, e.repo, e.framework].join(" ").toLowerCase().includes(q);
  }), [report, repo, auth, method, source, search, show]); // eslint-disable-line react-hooks/exhaustive-deps
  const insights = useMemo(() => (report ? apiInsights(scope ? { ...report, endpoints: report.endpoints.filter(e => e.repo === repo), repos: [scope] } : report) : null), [report, scope, repo]);
  const endpointKeys = useMemo(() => new Set((report?.endpoints ?? []).map(e => e.key).filter(Boolean)), [report]);
  const narrowed = repo !== "all" || sev !== "all" || auth !== "all" || method !== "all" || source !== "all" || search !== "" || show !== "open";
  const clear = () => { setRepo("all"); setSev("all"); setAuth("all"); setMethod("all"); setSource("all"); setSearch(""); setShow("open"); };

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
            <p className="text-sm text-gray-500 mt-0.5 max-w-3xl">Every endpoint your code and OpenAPI specs declare, the authentication visible for each, and API misconfigurations, from the latest scan of each repository. Resolve what you have dealt with so what is left needs a decision.</p>
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
        {!report && !error && <LoadingBlock label="API endpoints" rows={5} cards={4} />}

        {report && c && (
          <>
            {/* ── Filter bar: scopes everything below ─────────────────────── */}
            <div className="section-card flex flex-wrap items-center gap-2 px-4 py-3" role="search" aria-label="Filters">
              <select aria-label="Repository" value={repo} onChange={e => setRepo(e.target.value)} className={`${SELECT} font-bold`}>
                <option value="all">All repositories ({repos.length})</option>
                {repos.map(r => <option key={r.repo} value={r.repo}>{r.repo}</option>)}
              </select>
              <input aria-label="Search endpoints" value={search} onChange={e => setSearch(e.target.value)} placeholder="Search path, file, framework…"
                className="text-xs px-3 py-1.5 rounded-lg border border-gray-200 w-56 max-w-full focus:outline-none focus:ring-2 focus:ring-sky-200" />
              <div className="flex items-center gap-0.5 rounded-lg bg-gray-100 p-0.5" role="group" aria-label="Show">
                {(["open", "resolved", "all"] as const).map(s => (
                  <Tip key={s} tip={s === "open" ? "Endpoints and findings that still need a decision or are fine as they are." : s === "resolved" ? "Ones a reviewer has dealt with. Reopen any of them here." : "Everything, resolved or not."}>
                    <button onClick={() => setShow(s)} aria-pressed={show === s}
                      className={`rounded-md px-2.5 py-1 text-xs font-semibold transition-all ${show === s ? "bg-white text-gray-900 shadow-sm" : "text-gray-500 hover:text-gray-700"}`}>
                      {SHOW_LABEL[s]}{s === "resolved" && resolvedCount > 0 ? <span className="ml-1 tabular-nums text-gray-400">{resolvedCount}</span> : null}
                    </button>
                  </Tip>
                ))}
              </div>
              {scope && <span className="rounded-full border border-indigo-200 bg-indigo-50 px-2.5 py-1 text-[11px] font-bold text-indigo-700">Scoped to {scope.repo}</span>}
              {narrowed && <button onClick={clear} className="ml-auto text-xs font-bold text-rose-600 hover:text-rose-800 px-2 py-1 rounded-lg hover:bg-rose-50">Clear filters</button>}
            </div>

            <section aria-label="API summary" className="grid grid-cols-2 lg:grid-cols-5 gap-3">
              {[
                { k: "Endpoints", v: String(c.endpoints), s: `${c.specs} OpenAPI spec${c.specs === 1 ? "" : "s"}`, t: "", tip: "Every endpoint found in the latest scan of the repository (or repositories in scope)." },
                { k: "Auth coverage", v: pct(c.authRequired + c.explicitlyPublic, c.endpoints), s: `${c.authRequired} protected · ${c.explicitlyPublic} public on purpose`, t: "text-emerald-700", tip: "The share of endpoints that are protected or deliberately public." },
                { k: "No auth visible", v: String(c.noAuthVisible), s: "may be protected globally", t: c.noAuthVisible ? "text-amber-700" : "", tip: "Nothing in the file protects the route. Auth applied app-wide is not visible here: resolve those that are covered elsewhere." },
                { k: "Missing auth", v: String(c.flagged), s: resolvedCount ? `${resolvedCount} resolved · unprotected while the rest of the file is` : "unprotected while the rest of the file is", t: c.flagged ? "text-rose-700" : "", tip: "Stricter than no auth visible: the other endpoints in the same file are protected and this one is not. Still open, so it needs a decision." },
                { k: "Findings", v: String(c.findings), s: scope ? `in ${scope.repo}` : `across ${repos.length} repositor${repos.length === 1 ? "y" : "ies"}`, t: c.findings ? "text-rose-700" : "", tip: "API misconfigurations still open: operations without auth, weak spec security schemes, and endpoints missing the auth their siblings have." },
              ].map(x => (
                <Tip key={x.k} tip={x.tip} className="flex">
                  <div tabIndex={0} className="section-card w-full cursor-help px-4 py-3.5 focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300">
                    <p className="text-[10px] font-black uppercase tracking-widest text-gray-400">{x.k}</p>
                    <p className={`text-2xl font-black tabular-nums mt-1 ${x.t || "text-gray-900"}`}>{x.v}</p>
                    <p className="text-[11px] text-gray-500 mt-0.5 leading-snug">{x.s}</p>
                  </div>
                </Tip>
              ))}
            </section>

            {insights && (insights.unprotectedWrites.length > 0 || insights.weakestRepo || insights.needDecision > 0) && (
              <section aria-label="What to look at first" className="grid gap-3 md:grid-cols-3">
                {insights.unprotectedWrites.length > 0 && (
                  <div className="section-card border-l-4 border-l-rose-400 px-4 py-3">
                    <p className="text-xs font-black text-gray-900">{insights.unprotectedWrites.length} data-changing endpoint{insights.unprotectedWrites.length === 1 ? "" : "s"} with no auth visible</p>
                    <p className="mt-1 text-[11px] leading-snug text-gray-500 font-mono break-all">{insights.unprotectedWrites.slice(0, 3).map(e => `${e.method} ${e.path}`).join(" · ")}{insights.unprotectedWrites.length > 3 ? ` +${insights.unprotectedWrites.length - 3} more` : ""}</p>
                    <button onClick={() => { setAuth("none"); setMethod("writes"); setShow("open"); }} className="mt-2 text-xs font-bold text-indigo-600 hover:text-indigo-800">Show them →</button>
                  </div>
                )}
                {insights.needDecision > 0 && (
                  <div className="section-card border-l-4 border-l-amber-400 px-4 py-3">
                    <p className="text-xs font-black text-gray-900">{insights.needDecision} endpoint{insights.needDecision === 1 ? "" : "s"} missing the auth their siblings have</p>
                    <p className="mt-1 text-[11px] leading-snug text-gray-500">Add the check, or resolve each one if auth is handled elsewhere or it is public on purpose.</p>
                    <button onClick={() => { setAuth("flagged"); setMethod("all"); setShow("open"); }} className="mt-2 text-xs font-bold text-indigo-600 hover:text-indigo-800">Review them →</button>
                  </div>
                )}
                {insights.weakestRepo && repo === "all" && (
                  <div className="section-card border-l-4 border-l-sky-400 px-4 py-3">
                    <p className="text-xs font-black text-gray-900">Weakest coverage: <span className="font-mono">{insights.weakestRepo.repo}</span></p>
                    <p className="mt-1 text-[11px] leading-snug text-gray-500">{insights.weakestRepo.coverage}% of its {insights.weakestRepo.endpoints} endpoints are protected or public on purpose.</p>
                    <button onClick={() => setRepo(insights.weakestRepo!.repo)} className="mt-2 text-xs font-bold text-indigo-600 hover:text-indigo-800">Open this repository →</button>
                  </div>
                )}
              </section>
            )}

            <CapNotice cap="apiSecurityEndpoints" shown={report.endpoints.length} total={report.truncated ? report.counts.endpoints : null} noun="endpoints" />

            {repos.length > 0 && (
              <section aria-label="Repositories" className="section-card overflow-hidden">
                <div className="px-5 py-3.5 border-b border-gray-100 flex flex-wrap items-center justify-between gap-2">
                  <p className="text-sm font-black text-gray-900">By repository</p>
                  <p className="text-[11px] text-gray-400">Click a repository to scope the page to it</p>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead><tr className="text-[10px] font-black uppercase tracking-widest text-gray-400 bg-gray-50/60 text-left">
                      <th className="px-5 py-2">Repository</th><th className="px-2 py-2 text-right">Endpoints</th><th className="px-2 py-2">Auth coverage</th>
                      <th className="px-2 py-2 text-right">Missing auth</th><th className="px-2 py-2 text-right">Findings</th><th className="px-5 py-2 text-right">Scanned</th>
                    </tr></thead>
                    <tbody>
                      {repos.map(r => {
                        const cov = r.endpoints ? Math.round(((r.authRequired + r.explicitlyPublic) / r.endpoints) * 100) : null;
                        return (
                          <tr key={r.repo} onClick={() => setRepo(repo === r.repo ? "all" : r.repo)} aria-selected={repo === r.repo}
                            className={`border-t border-gray-50 cursor-pointer hover:bg-gray-50/70 ${repo === r.repo ? "bg-indigo-50/50" : ""}`}>
                            <td className="px-5 py-2.5 font-mono text-gray-800">{r.repo}</td>
                            <td className="px-2 py-2.5 text-right tabular-nums">{r.endpoints}</td>
                            <td className="px-2 py-2.5">
                              <div className="flex items-center gap-2">
                                <span className="h-1.5 w-20 overflow-hidden rounded-full bg-gray-100" aria-hidden><span className={`block h-full rounded-full ${cov === null ? "" : cov >= 90 ? "bg-emerald-500" : cov >= 60 ? "bg-amber-500" : "bg-rose-500"}`} style={{ width: `${cov ?? 0}%` }} /></span>
                                <span className="tabular-nums">{pct(r.authRequired + r.explicitlyPublic, r.endpoints)}</span>
                              </div>
                            </td>
                            <td className={`px-2 py-2.5 text-right tabular-nums ${r.flagged ? "text-rose-600 font-bold" : "text-gray-400"}`}>{r.flagged}{r.resolved ? <span className="ml-1 font-normal text-violet-500">+{r.resolved} resolved</span> : null}</td>
                            <td className={`px-2 py-2.5 text-right tabular-nums ${r.findings ? "text-rose-600 font-bold" : "text-gray-400"}`}>{r.findings}</td>
                            <td className="px-5 py-2.5 text-right text-gray-500">
                              {r.scan_id !== "demo" ? <Link href={`/pr/${r.scan_id}`} onClick={e => e.stopPropagation()} className="hover:text-indigo-700">{r.scanned_at ? relativeTime(r.scanned_at, tz) : "latest scan"} →</Link> : "sample"}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </section>
            )}

            {reopenError && <p role="alert" className="text-xs font-semibold text-rose-600">{reopenError}</p>}

            <section aria-label="Findings" className="section-card overflow-hidden">
              <div className="px-5 py-3.5 border-b border-gray-100 flex flex-wrap items-center gap-2">
                <p className="text-sm font-black text-gray-900 mr-auto">Findings <span className="text-gray-400 font-bold">({findings.length})</span></p>
                <select aria-label="Severity" value={sev} onChange={e => setSev(e.target.value)} className={SELECT}>
                  <option value="all">Any severity</option>
                  {["critical", "high", "medium", "low", "info"].map(s => <option key={s} value={s}>{s[0].toUpperCase() + s.slice(1)}</option>)}
                </select>
              </div>
              {findings.length === 0 ? (
                <p className="px-5 py-8 text-center text-sm text-gray-500">
                  {show === "resolved" ? "No resolved findings." : `No open API security findings${repo !== "all" ? " in this repository" : ""} in the latest scans.`}
                  {show === "open" && (report.counts.resolvedFindings ?? 0) > 0 && <> <button onClick={() => setShow("resolved")} className="font-semibold text-indigo-600 underline">{report.counts.resolvedFindings} resolved</button></>}
                </p>
              ) : (
                <ul className="divide-y divide-gray-50">
                  {(allFindings ? findings : findings.slice(0, FINDINGS_SHOWN)).map((f: ApiSecurityFinding) => {
                    const key = `${f.repo}:${f.file}:${f.line}:${f.id}`;
                    const isOpen = open === key;
                    const cwe = f.cwe.match(/\d+/)?.[0];
                    const target = endpointKeys.has(f.key) ? "endpoint" : "finding";
                    return (
                      <li key={key} className={f.resolution ? "bg-gray-50/50" : ""}>
                        <button onClick={() => setOpen(isOpen ? null : key)} aria-expanded={isOpen} className="w-full text-left px-5 py-3 hover:bg-gray-50/70 flex items-start gap-3">
                          <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full border shrink-0 uppercase ${SEV_STYLE[f.severity] ?? SEV_STYLE.medium}`}>{f.severity}</span>
                          <div className="min-w-0 flex-1">
                            <p className="text-xs font-bold text-gray-900">{f.title} {f.resolution && <ResolvedBadge r={f.resolution} />}</p>
                            <p className="text-[11px] text-gray-500 mt-0.5 break-words">{f.detail}</p>
                            <p className="text-[10px] font-mono text-gray-400 mt-1 break-all">{f.repo} · {f.file}:{f.line}</p>
                          </div>
                        </button>
                        {isOpen && (
                          <div className="px-5 pb-4 pl-[4.75rem] space-y-3">
                            {f.fix && <p className="text-xs text-gray-700 leading-relaxed"><span className="font-bold text-emerald-700">Fix: </span>{f.fix}</p>}
                            <div className="flex flex-wrap items-center gap-3 text-xs font-semibold">
                              {f.scan_id !== "demo" && <Link href={`/pr/${f.scan_id}`} className="text-indigo-600 hover:text-indigo-800">Open in the scan →</Link>}
                              <Link href={`/rules#${encodeURIComponent(f.id)}`} className="text-indigo-600 hover:text-indigo-800">Rule <span className="font-mono">{f.id}</span></Link>
                              {cwe && <a href={`https://cwe.mitre.org/data/definitions/${cwe}.html`} target="_blank" rel="noreferrer" className="text-indigo-600 hover:text-indigo-800">{f.cwe} ↗</a>}
                              {f.key && canResolve && !f.resolution && resolving !== `f:${key}` && (
                                <button onClick={() => setResolving(`f:${key}`)} className="rounded-lg bg-indigo-600 px-2.5 py-1 text-white hover:bg-indigo-700">Resolve…</button>
                              )}
                              {f.key && canResolve && f.resolution && <button onClick={() => reopen(f.repo, f.key)} className="rounded-lg bg-orange-50 px-2.5 py-1 text-orange-700 ring-1 ring-orange-200 hover:bg-orange-100">Reopen</button>}
                            </div>
                            {f.key && !canResolve && !f.resolution && <p className="text-[11px] text-gray-400">Only security reviewers and admins can resolve findings.</p>}
                            {resolving === `f:${key}` && <ResolvePanel target={target} repo={f.repo} keyId={f.key} file={f.file} noun={target === "endpoint" ? "endpoint" : "finding"} onSaved={saved} onCancel={() => setResolving(null)} />}
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
                <select aria-label="Authentication" value={auth} onChange={e => setAuth(e.target.value as typeof auth)} className={SELECT}>
                  <option value="all">Any authentication</option>
                  <option value="flagged">Missing auth</option>
                  <option value="none">No auth visible</option>
                  <option value="required">Auth required</option>
                  <option value="public">Explicitly public</option>
                </select>
                <select aria-label="Method" value={method} onChange={e => setMethod(e.target.value)} className={SELECT}>
                  <option value="all">Any method</option>
                  <option value="writes">Data-changing (POST, PUT, PATCH, DELETE)</option>
                  {methods.map(m => <option key={m} value={m}>{m}</option>)}
                </select>
                <select aria-label="Declared in" value={source} onChange={e => setSource(e.target.value as typeof source)} className={SELECT}>
                  <option value="all">Code and specs</option><option value="code">Code</option><option value="spec">OpenAPI specs</option>
                </select>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead><tr className="text-[10px] font-black uppercase tracking-widest text-gray-400 bg-gray-50/60 text-left">
                    <th className="px-5 py-2 w-20">Method</th><th className="px-2 py-2">Path</th><th className="px-2 py-2">Authentication</th><th className="px-2 py-2">Declared in</th><th className="px-5 py-2 text-right">Decision</th>
                  </tr></thead>
                  <tbody>
                    {endpoints.length === 0 ? (
                      <tr><td colSpan={5} className="px-5 py-8 text-center text-gray-500">
                        {show === "open" && narrowed ? "No open endpoints match." : show === "resolved" ? "No resolved endpoints." : "No endpoints match."}
                      </td></tr>
                    ) : (allEndpoints ? endpoints : endpoints.slice(0, ENDPOINTS_SHOWN)).flatMap(e => {
                      const a = AUTH_STYLE[e.auth];
                      const rowKey = `${e.repo}:${e.file}:${e.line}:${e.method}:${e.path}`;
                      const needsDecision = !e.resolution && (e.flagged || e.auth === "none");
                      const rows = [(
                        <tr key={rowKey} className={`border-t border-gray-50 ${e.resolution ? "bg-gray-50/50 text-gray-500" : e.flagged ? "bg-rose-50/40" : ""}`}>
                          <td className="px-5 py-2"><span className={`text-[10px] font-black px-1.5 py-0.5 rounded ${METHOD_STYLE[e.method] ?? METHOD_STYLE.ANY}`}>{e.method}</span></td>
                          <td className="px-2 py-2 font-mono text-gray-800 break-all">{e.path}</td>
                          <td className="px-2 py-2">
                            <div className="flex items-center gap-1.5 flex-wrap">
                              <Tip tip={a.help}><span tabIndex={0} className={`cursor-help text-[10px] font-bold px-1.5 py-0.5 rounded border whitespace-nowrap focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300 ${a.cls}`}>{a.label}</span></Tip>
                              {e.flagged && !e.resolution && <span className="text-[10px] font-black px-1.5 py-0.5 rounded bg-rose-600 text-white whitespace-nowrap">Missing auth</span>}
                              {e.resolution && <ResolvedBadge r={e.resolution} />}
                              {e.authEvidence && <code className="text-[10px] text-gray-500 truncate max-w-[14rem]">{e.authEvidence}</code>}
                            </div>
                          </td>
                          <td className="px-2 py-2 text-[10px] font-mono text-gray-500">
                            {e.scan_id !== "demo"
                              ? <Link href={`/pr/${e.scan_id}`} className="hover:text-indigo-700 break-all">{e.repo.split("/").pop()} · {e.file}:{e.line}</Link>
                              : <span>{e.repo.split("/").pop()} · {e.file}:{e.line}</span>}
                            <span className="ml-1.5 text-gray-400">({e.source === "spec" ? "OpenAPI" : e.framework})</span>
                          </td>
                          <td className="px-5 py-2 text-right whitespace-nowrap">
                            {e.key && e.resolution && canResolve && <button onClick={() => reopen(e.repo, e.key)} className="text-[11px] font-bold text-orange-700 hover:text-orange-900">Reopen</button>}
                            {e.key && needsDecision && canResolve && (
                              <Tip tip="Record why this is fine, or that it isn't an endpoint. It leaves the open list and comes back when the decision expires.">
                                <button onClick={() => setResolving(resolving === rowKey ? null : rowKey)} aria-label={`Resolve ${e.method} ${e.path}`} className="rounded-lg bg-indigo-600 px-2.5 py-1 text-[11px] font-bold text-white hover:bg-indigo-700">Resolve…</button>
                              </Tip>
                            )}
                            {needsDecision && !canResolve && <span className="text-[11px] text-gray-400">Needs a reviewer</span>}
                          </td>
                        </tr>
                      )];
                      if (resolving === rowKey && e.key) rows.push(
                        <tr key={`${rowKey}:resolve`} className="border-t border-gray-50 bg-indigo-50/20">
                          <td colSpan={5} className="px-5 py-3"><ResolvePanel target="endpoint" repo={e.repo} keyId={e.key} file={e.file} noun="endpoint" onSaved={saved} onCancel={() => setResolving(null)} /></td>
                        </tr>,
                      );
                      return rows;
                    })}
                  </tbody>
                </table>
              </div>
              {endpoints.length > ENDPOINTS_SHOWN && (
                <button onClick={() => setAllEndpoints(v => !v)} className="w-full py-2.5 text-xs font-semibold text-indigo-600 hover:bg-indigo-50 border-t border-gray-100">
                  {allEndpoints ? "Show fewer" : `Show all ${endpoints.length} endpoints`}
                </button>
              )}
            </section>

            <div className="flex items-start gap-3 bg-sky-50 border border-sky-100 rounded-xl px-4 py-3">
              <p className="text-xs text-sky-900 leading-relaxed">
                <span className="font-bold">How it works:</span> endpoints are read from the latest scan of each repository: Express/Next.js, Flask/FastAPI, Spring,
                ASP.NET, Go (net/http, gin, echo, chi) and Laravel routes, plus OpenAPI/Swagger specs. <strong>Auth coverage</strong> is the share of endpoints that are
                protected or deliberately public. <strong>No auth visible</strong> means nothing in that file protects the route; auth applied globally (app-wide
                middleware, Spring Security config) isn&apos;t visible here, so <strong>resolve</strong> the ones that are covered elsewhere. <strong>Missing auth</strong> is stricter: other endpoints in the same file are protected and
                this one is not. A resolution is recorded with who, why and until when, and the endpoint returns to the open list when it expires.
              </p>
            </div>
          </>
        )}
      </div>
    </AuthGuard>
  );
}
