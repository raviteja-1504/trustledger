"use client";

import { useState, useEffect, useCallback, useMemo } from "react";
import AuthGuard from "@/components/AuthGuard";
import PageSkeleton from "@/components/PageSkeleton";
import { isSeedMode, authedFetch } from "@/lib/useRealData";
import { useAuth } from "@/lib/auth";
import { buildApiSecurityReport, type ApiSecurityReport, type InventoryEndpoint } from "@/lib/api/apiSecurityReport";

// ── Presentational styles ─────────────────────────────────────────────────────

const METHOD_STYLE: Record<string, { bg: string; text: string }> = {
  GET:    { bg: "#e0f2fe", text: "#0369a1" },
  POST:   { bg: "#dcfce7", text: "#15803d" },
  PUT:    { bg: "#fef3c7", text: "#a16207" },
  PATCH:  { bg: "#fef3c7", text: "#a16207" },
  DELETE: { bg: "#fee2e2", text: "#b91c1c" },
  ANY:    { bg: "#f1f5f9", text: "#475569" },
};
const SEV_STYLE: Record<string, { bg: string; text: string; border: string }> = {
  critical: { bg: "#fef2f2", text: "#be123c", border: "#fecdd3" },
  high:     { bg: "#fff7ed", text: "#c2410c", border: "#fed7aa" },
  medium:   { bg: "#fffbeb", text: "#a16207", border: "#fde68a" },
  low:      { bg: "#f8fafc", text: "#475569", border: "#e2e8f0" },
  info:     { bg: "#f8fafc", text: "#64748b", border: "#e2e8f0" },
};
const AUTH_STYLE: Record<InventoryEndpoint["auth"], { label: string; bg: string; text: string; border: string }> = {
  required: { label: "Auth required", bg: "#f0fdf4", text: "#15803d", border: "#bbf7d0" },
  public:   { label: "Explicitly public", bg: "#eff6ff", text: "#1d4ed8", border: "#bfdbfe" },
  none:     { label: "No auth visible", bg: "#fffbeb", text: "#a16207", border: "#fde68a" },
};

// ── Offline/demo fallback: the real report builder over sample files ──────────

function makeOffline(): ApiSecurityReport {
  return buildApiSecurityReport([{
    repo: "acme/storefront", scan_id: "demo",
    files: [
      { file_path: "src/routes/orders.ts", content: `const router = express.Router();\nrouter.get("/orders", requireUser, listOrders);\nrouter.get("/orders/:id", requireUser, getOrder);\nrouter.post("/orders", requireUser, createOrder);\nrouter.delete("/orders/:id", deleteOrder);\nrouter.post("/login", login);\n` },
      { file_path: "api/openapi.yaml", content: `openapi: 3.0.3\ninfo: { title: Storefront, version: "1" }\nservers:\n  - url: http://api.storefront.example\ncomponents:\n  securitySchemes:\n    key: { type: apiKey, in: query, name: api_key }\npaths:\n  /products:\n    get:\n      security:\n        - key: []\n  /admin/refunds:\n    post:\n      responses: {}\n` },
      { file_path: "app/views.py", content: `@app.route("/account", methods=["GET"])\n@login_required\ndef account():\n    pass\n` },
    ],
  }]);
}

export default function ApiSecurityPage() {
  const { profile } = useAuth();
  const [report, setReport] = useState<ApiSecurityReport | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [filterAuth, setFilterAuth] = useState<InventoryEndpoint["auth"] | "flagged" | "all">("all");
  const [filterRepo, setFilterRepo] = useState("all");
  const [search, setSearch] = useState("");
  const [expanded, setExpanded] = useState<number | null>(null);

  const load = useCallback(async (spinner = false) => {
    if (spinner) setRefreshing(true);
    try {
      setReport(await authedFetch<ApiSecurityReport>("/api/api-security"));
    } catch {
      if (isSeedMode() && !profile?.org_id) setReport(makeOffline());
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [profile?.org_id]);

  useEffect(() => { load(); }, [load]);

  const endpoints = useMemo(() => report?.endpoints ?? [], [report]);
  const repos = useMemo(() => Array.from(new Set(endpoints.map(e => e.repo))), [endpoints]);
  const visible = useMemo(() => endpoints.filter(e => {
    if (filterRepo !== "all" && e.repo !== filterRepo) return false;
    if (filterAuth === "flagged" ? !e.flagged : filterAuth !== "all" && e.auth !== filterAuth) return false;
    if (search) {
      const q = search.toLowerCase();
      if (![e.method, e.path, e.file, e.repo, e.framework].join(" ").toLowerCase().includes(q)) return false;
    }
    return true;
  }), [endpoints, filterRepo, filterAuth, search]);

  const c = report?.counts;
  const findings = report?.findings ?? [];

  return (
    <AuthGuard>
      <PageSkeleton rows={6} cards={4}>
      <div className="max-w-7xl mx-auto space-y-5 pb-10">

        {/* Header */}
        <div className="animate-fade-up flex items-start justify-between gap-4 flex-wrap">
          <div>
            <div className="flex items-center gap-2.5 mb-1">
              <div className="w-8 h-8 rounded-xl flex items-center justify-center" style={{ background: "rgba(14,165,233,0.1)", border: "1px solid rgba(14,165,233,0.25)" }}>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#0284c7" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M4 7h16M4 12h10M4 17h7" /><circle cx="18" cy="16" r="3" /><path d="M20.2 18.2 22 20" />
                </svg>
              </div>
              <h1 className="text-xl font-black text-gray-900 tracking-tight">API Security</h1>
              {!!c?.flagged && <span className="text-xs font-black text-white bg-rose-600 px-2 py-0.5 rounded-full">{c.flagged} missing auth</span>}
            </div>
            <p className="text-sm text-gray-400">
              Every endpoint your code and OpenAPI specs declare · the authentication visible for each · OpenAPI spec misconfigurations
            </p>
          </div>
          <button onClick={() => load(true)} disabled={refreshing}
            className="flex items-center gap-1.5 px-3 py-2 text-xs font-bold rounded-xl border border-gray-200 bg-white text-gray-600 hover:bg-gray-50 shadow-sm disabled:opacity-50">
            <svg className={refreshing ? "animate-spin" : ""} width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="23 4 23 10 17 10" /><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10" /></svg>
            Refresh
          </button>
        </div>

        {/* Stats */}
        <div className="animate-fade-up grid grid-cols-2 lg:grid-cols-4 gap-3">
          {[
            { label: "Endpoints", value: c?.endpoints ?? 0, sub: `${c?.specs ?? 0} OpenAPI spec${c?.specs === 1 ? "" : "s"}`, color: "#0f172a" },
            { label: "Auth required", value: c?.authRequired ?? 0, sub: `${c?.explicitlyPublic ?? 0} explicitly public`, color: "#15803d" },
            { label: "No auth visible", value: c?.noAuthVisible ?? 0, sub: "may be applied globally", color: "#a16207" },
            { label: "Missing auth", value: c?.flagged ?? 0, sub: "siblings are protected", color: "#be123c" },
          ].map(s => (
            <div key={s.label} className="bg-white border border-gray-100 rounded-2xl px-4 py-3.5 shadow-sm">
              <p className="text-[10px] font-black uppercase tracking-widest text-gray-400">{s.label}</p>
              <p className="text-2xl font-black mt-1 tabular-nums" style={{ color: s.color }}>{loading ? "–" : s.value}</p>
              <p className="text-[10px] text-gray-400 mt-0.5">{s.sub}</p>
            </div>
          ))}
        </div>

        {/* Findings */}
        <div className="animate-fade-up bg-white border border-gray-100 rounded-2xl shadow-sm overflow-hidden">
          <div className="px-5 py-3.5 border-b border-gray-100 flex items-center justify-between">
            <p className="text-sm font-black text-gray-900">Findings</p>
            <span className="text-[10px] font-bold text-gray-400">{findings.length} total</span>
          </div>
          {findings.length === 0 ? (
            <p className="px-5 py-8 text-center text-sm text-gray-400">{loading ? "Loading…" : "No API security findings in the latest scans."}</p>
          ) : findings.slice(0, 200).map((f, i) => {
            const sev = SEV_STYLE[f.severity] ?? SEV_STYLE.medium;
            const open = expanded === i;
            return (
              <div key={`${f.repo}:${f.file}:${f.line}:${f.id}`} className="border-b border-gray-50 last:border-0">
                <button onClick={() => setExpanded(open ? null : i)} className="w-full text-left px-5 py-3 hover:bg-gray-50/70 flex items-start gap-3">
                  <span className="text-[10px] font-bold px-2 py-0.5 rounded-full border shrink-0 uppercase" style={{ background: sev.bg, color: sev.text, borderColor: sev.border }}>{f.severity}</span>
                  <div className="min-w-0 flex-1">
                    <p className="text-xs font-bold text-gray-900">{f.title}</p>
                    <p className="text-[11px] text-gray-500 mt-0.5 break-words">{f.detail}</p>
                    <p className="text-[10px] font-mono text-gray-400 mt-1 truncate">{f.repo.split("/").pop()} · {f.file}:{f.line}{f.cwe ? ` · ${f.cwe}` : ""}</p>
                  </div>
                </button>
                {open && f.fix && (
                  <div className="px-5 pb-3.5 -mt-1 ml-[4.5rem]">
                    <p className="text-[10px] font-black uppercase tracking-widest text-emerald-600 mb-1">Fix</p>
                    <p className="text-xs text-gray-600 leading-relaxed">{f.fix}</p>
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {/* Inventory */}
        <div className="animate-fade-up bg-white border border-gray-100 rounded-2xl shadow-sm overflow-hidden">
          <div className="px-5 py-3.5 border-b border-gray-100 flex items-center gap-2 flex-wrap">
            <p className="text-sm font-black text-gray-900 mr-auto">Endpoint inventory</p>
            <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search path, file, framework…"
              className="text-xs px-3 py-1.5 rounded-lg border border-gray-200 w-52 max-w-full focus:outline-none focus:ring-2 focus:ring-sky-200" />
            <select value={filterAuth} onChange={e => setFilterAuth(e.target.value as typeof filterAuth)} className="text-xs px-2 py-1.5 rounded-lg border border-gray-200 bg-white">
              <option value="all">All auth states</option>
              <option value="flagged">Missing auth (flagged)</option>
              <option value="none">No auth visible</option>
              <option value="required">Auth required</option>
              <option value="public">Explicitly public</option>
            </select>
            {repos.length > 1 && (
              <select value={filterRepo} onChange={e => setFilterRepo(e.target.value)} className="text-xs px-2 py-1.5 rounded-lg border border-gray-200 bg-white">
                <option value="all">All repos</option>
                {repos.map(r => <option key={r} value={r}>{r}</option>)}
              </select>
            )}
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-[10px] font-black uppercase tracking-widest text-gray-400 bg-gray-50/60">
                  <th className="text-left px-5 py-2 w-20">Method</th>
                  <th className="text-left px-2 py-2">Path</th>
                  <th className="text-left px-2 py-2">Authentication</th>
                  <th className="text-left px-2 py-2">Declared in</th>
                </tr>
              </thead>
              <tbody>
                {visible.length === 0 ? (
                  <tr><td colSpan={4} className="px-5 py-8 text-center text-gray-400">{loading ? "Loading…" : "No endpoints match."}</td></tr>
                ) : visible.slice(0, 500).map(e => {
                  const m = METHOD_STYLE[e.method] ?? METHOD_STYLE.ANY;
                  const a = AUTH_STYLE[e.auth];
                  return (
                    <tr key={`${e.repo}:${e.file}:${e.line}:${e.method}:${e.path}`} className={`border-t border-gray-50 ${e.flagged ? "bg-rose-50/40" : ""}`}>
                      <td className="px-5 py-2"><span className="text-[10px] font-black px-1.5 py-0.5 rounded" style={{ background: m.bg, color: m.text }}>{e.method}</span></td>
                      <td className="px-2 py-2 font-mono text-gray-800 break-all">{e.path}</td>
                      <td className="px-2 py-2">
                        <div className="flex items-center gap-1.5 flex-wrap">
                          <span className="text-[10px] font-bold px-1.5 py-0.5 rounded border whitespace-nowrap" style={{ background: a.bg, color: a.text, borderColor: a.border }}>{a.label}</span>
                          {e.flagged && <span className="text-[10px] font-black px-1.5 py-0.5 rounded bg-rose-600 text-white whitespace-nowrap">Missing auth</span>}
                          {e.authEvidence && <code className="text-[10px] text-gray-400 truncate max-w-[14rem]">{e.authEvidence}</code>}
                        </div>
                      </td>
                      <td className="px-2 py-2 text-[10px] font-mono text-gray-500">
                        <span className="text-gray-400">{e.repo.split("/").pop()} · </span>{e.file}:{e.line}
                        <span className="ml-1.5 text-gray-400">({e.source === "spec" ? "OpenAPI" : e.framework})</span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          {visible.length > 500 && <p className="px-5 py-2 text-[10px] text-gray-400 border-t border-gray-50">Showing 500 of {visible.length}; narrow with the filters.</p>}
        </div>

        {/* How it works */}
        <div className="animate-fade-up flex items-start gap-3 bg-sky-50 border border-sky-100 rounded-xl px-4 py-3">
          <svg className="shrink-0 mt-0.5 text-sky-500" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="12" cy="12" r="10" /><line x1="12" y1="8" x2="12" y2="12" /><line x1="12" y1="16" x2="12.01" y2="16" />
          </svg>
          <p className="text-xs text-sky-900 leading-relaxed">
            <span className="font-bold">How it works:</span> Endpoints are read from the latest scan of each repo — Express/Next.js, Flask/FastAPI, Spring, ASP.NET, Go (net/http, gin, echo, chi) and Laravel routes, plus OpenAPI/Swagger specs.
            &ldquo;No auth visible&rdquo; means nothing in that file protects the route; auth applied globally elsewhere (an app-wide middleware, Spring Security config) is not visible here.
            &ldquo;Missing auth&rdquo; is stricter: other endpoints in the same file are protected and this one is not.
          </p>
        </div>
      </div>
      </PageSkeleton>
    </AuthGuard>
  );
}
