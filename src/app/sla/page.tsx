"use client";

import { useEffect, useState, useMemo, useCallback } from "react";
import Link from "next/link";
import AuthGuard from "@/components/AuthGuard";
import PageSkeleton from "@/components/PageSkeleton";
import InfoTooltip from "@/components/InfoTooltip";
import { authedFetch, isSeedMode } from "@/lib/useRealData";
import { useAuth } from "@/lib/auth";

interface SLAViolation {
  id:           string;
  file_path:    string;
  risk_score:   string;
  status:       string;
  scan_id:      string;
  sla_deadline: string;
  created_at:   string;
  repo?:        string;
  pr_number?:   number;
  assigned_email?: string;
  hours_overdue: number;
}

const ORG = process.env.NEXT_PUBLIC_ORG ?? "novapay";

const RISK_COLOR: Record<string, string> = {
  CRITICAL:"#7c3aed", HIGH:"#ea580c", MEDIUM:"#d97706", LOW:"#15803d",
};

const SLA_HOURS: Record<string, number> = {
  CRITICAL:24, HIGH:48, MEDIUM:72, LOW:168,
};

function urgencyLabel(h: number): { label: string; color: string; bg: string } {
  if (h > 24) return { label:"Severely overdue",   color:"#be123c", bg:"#fff1f2" };
  if (h > 0)  return { label:"Overdue",             color:"#ea580c", bg:"#fff7ed" };
  if (h > -4) return { label:"Due very soon",       color:"#d97706", bg:"#fffbeb" };
  if (h > -24)return { label:"Due today",           color:"#2563eb", bg:"#eff6ff" };
  return              { label:"On track",            color:"#15803d", bg:"#f0fdf4" };
}

function fmtDate(iso: string) {
  const d = new Date(iso);
  return `${d.getDate()} ${["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"][d.getMonth()]} ${d.getFullYear()}`;
}

export default function SLAPage() {
  const { profile } = useAuth();
  const [items,   setItems]   = useState<SLAViolation[]>([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [lastRefreshed, setLastRefreshed] = useState<Date | null>(null);
  const [filter,  setFilter]  = useState<"all"|"overdue"|"due_today"|"on_track">("all");
  const [riskFilter, setRiskFilter] = useState<string>("all");
  const [repoFilter, setRepoFilter] = useState<string>("all");
  const [search, setSearch] = useState("");
  const [sortBy, setSortBy] = useState<"urgency"|"risk"|"repo">("urgency");

  const fetchData = useCallback(async (spinner = false) => {
    if (spinner) setRefreshing(true); else setLoading(true);
    if (isSeedMode() && !profile?.org_id) {
      const now = Date.now();
      const demo: SLAViolation[] = [
        { id:"v1", file_path:"src/processors/card_validator.py", risk_score:"CRITICAL", status:"open",     scan_id:"sc_mock_001", sla_deadline:new Date(now - 26*3600_000).toISOString(), created_at:new Date(now-50*3600_000).toISOString(), repo:`${ORG}/payments-api`,    assigned_email:`alice@${ORG}.io`, hours_overdue:26 },
        { id:"v2", file_path:"models/risk_scorer.ts",            risk_score:"CRITICAL", status:"open",     scan_id:"sc_mock_003", sla_deadline:new Date(now - 2*3600_000).toISOString(),  created_at:new Date(now-26*3600_000).toISOString(), repo:`${ORG}/fraud-detection`, assigned_email:`carol@${ORG}.io`, hours_overdue:2  },
        { id:"v3", file_path:"src/gateway/stripe_client.py",     risk_score:"HIGH",     status:"in_review",scan_id:"sc_mock_001", sla_deadline:new Date(now + 3*3600_000).toISOString(),  created_at:new Date(now-45*3600_000).toISOString(), repo:`${ORG}/payments-api`,    assigned_email:`alice@${ORG}.io`, hours_overdue:-3 },
        { id:"v4", file_path:"src/models/inference_engine.py",   risk_score:"CRITICAL", status:"open",     scan_id:"sc_mock_006", sla_deadline:new Date(now + 20*3600_000).toISOString(), created_at:new Date(now-4*3600_000).toISOString(),  repo:`${ORG}/ml-platform`,    hours_overdue:-20},
        { id:"v5", file_path:"src/training/data_pipeline.py",    risk_score:"HIGH",     status:"open",     scan_id:"sc_mock_006", sla_deadline:new Date(now + 48*3600_000).toISOString(), created_at:new Date(now-0).toISOString(),           repo:`${ORG}/ml-platform`,    hours_overdue:-48},
      ];
      setItems(demo);
      setLastRefreshed(new Date());
      setLoading(false); setRefreshing(false);
      return;
    }
    if (!profile?.org_id) { setLoading(false); setRefreshing(false); return; }
    try {
      // "unresolved" = open + in_review — matches the dashboard's SLA breach
      // count, which includes in_review violations whose deadline has passed.
      const res = await authedFetch<{ violations: Array<Record<string, unknown>> }>("/api/violations?status=unresolved&limit=500");
      const now = Date.now();
      const mapped = (res.violations ?? [])
        .filter(v => v.sla_deadline)
        .map(v => {
          const scans = v.scans as { repo_full_name?: string; pr_number?: number } | { repo_full_name?: string; pr_number?: number }[] | null;
          const scan  = Array.isArray(scans) ? scans[0] : scans;
          return {
            id:           v.id as string,
            file_path:    v.file_path as string,
            risk_score:   v.risk_score as string,
            status:       v.status as string,
            scan_id:      v.scan_id as string,
            sla_deadline: v.sla_deadline as string,
            created_at:   v.created_at as string,
            repo:         scan?.repo_full_name,
            pr_number:    scan?.pr_number,
            assigned_email: v.assigned_email as string | undefined,
            hours_overdue: (now - new Date(v.sla_deadline as string).getTime()) / 3600_000,
          };
        })
        .sort((a, b) => b.hours_overdue - a.hours_overdue);
      setItems(mapped);
      setLastRefreshed(new Date());
    } catch { setItems([]); }
    setLoading(false); setRefreshing(false);
  }, [profile?.org_id]);

  useEffect(() => {
    fetchData();
    const id = setInterval(() => fetchData(true), 30_000);
    return () => clearInterval(id);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [profile?.org_id]);

  const repos = useMemo(() => Array.from(new Set(items.map(i => i.repo).filter((r): r is string => !!r))).sort(), [items]);

  const filtered = useMemo(() => {
    let list = items;
    if (filter === "overdue")   list = list.filter(i => i.hours_overdue > 0);
    if (filter === "due_today") list = list.filter(i => i.hours_overdue <= 0 && i.hours_overdue > -24);
    if (filter === "on_track")  list = list.filter(i => i.hours_overdue <= -24);
    if (riskFilter !== "all")   list = list.filter(i => i.risk_score === riskFilter);
    if (repoFilter !== "all")   list = list.filter(i => i.repo === repoFilter);
    if (search) {
      const q = search.toLowerCase();
      list = list.filter(i => i.file_path.toLowerCase().includes(q) || (i.repo ?? "").toLowerCase().includes(q));
    }
    return [...list].sort((a, b) => {
      if (sortBy === "risk")  return (SLA_HOURS[a.risk_score] ?? 99) - (SLA_HOURS[b.risk_score] ?? 99) || b.hours_overdue - a.hours_overdue;
      if (sortBy === "repo")  return (a.repo ?? "").localeCompare(b.repo ?? "") || b.hours_overdue - a.hours_overdue;
      return b.hours_overdue - a.hours_overdue;
    });
  }, [items, filter, riskFilter, repoFilter, search, sortBy]);

  const overdue  = items.filter(i => i.hours_overdue > 0);
  const dueToday = items.filter(i => i.hours_overdue <= 0 && i.hours_overdue > -24);
  const onTrack  = items.filter(i => i.hours_overdue <= -24);
  const compliance = items.length > 0 ? Math.round((onTrack.length / items.length) * 100) : 100;
  const avgOverdueHrs = overdue.length > 0 ? Math.round(overdue.reduce((s,i)=>s+i.hours_overdue,0) / overdue.length) : 0;
  const severelyOverdue = items.filter(i => i.hours_overdue > 24).length;

  function exportCSV() {
    const rows = [
      ["File","Repo","PR","Risk","Status","Assigned","SLA Deadline","Hours Overdue"],
      ...filtered.map(i => [i.file_path, i.repo ?? "", i.pr_number ?? "", i.risk_score, i.status, i.assigned_email ?? "", i.sla_deadline, Math.round(i.hours_overdue)]),
    ];
    const blob = new Blob([rows.map(r=>r.map(c=>`"${c}"`).join(",")).join("\n")], { type:"text/csv" });
    Object.assign(document.createElement("a"), { href:URL.createObjectURL(blob), download:"sla-dashboard.csv" }).click();
  }

  const refreshAgo = lastRefreshed ? (() => { const s=Math.floor((Date.now()-lastRefreshed.getTime())/1000); return s<10?"just now":s<60?`${s}s ago`:`${Math.floor(s/60)}m ago`; })() : "";

  if (loading) return <AuthGuard><PageSkeleton rows={4} cards={5}><div /></PageSkeleton></AuthGuard>;

  return (
    <AuthGuard>
      <div className="max-w-7xl mx-auto space-y-5 pb-10">

        {/* Header */}
        <div className="animate-fade-up flex items-start justify-between gap-4 flex-wrap">
          <div>
            <div className="flex items-center gap-2.5 mb-1">
              <div className="w-8 h-8 rounded-xl flex items-center justify-center"
                style={{ background:"rgba(99,102,241,0.1)", border:"1px solid rgba(99,102,241,0.2)" }}>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#6366f1" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>
                </svg>
              </div>
              <h1 className="text-xl font-black text-gray-900 tracking-tight">SLA Dashboard</h1>
              {overdue.length>0 && <span className="text-xs font-black text-white bg-rose-500 px-2 py-0.5 rounded-full">{overdue.length} overdue</span>}
            </div>
            <p className="text-sm text-gray-400">
              Attestation SLA status — CRITICAL files within 24h, HIGH within 48h · auto-refreshes every 30s
            </p>
          </div>
          <div className="flex flex-col items-end gap-0.5">
            <div className="flex items-center gap-2">
              <button onClick={exportCSV}
                className="flex items-center gap-1.5 px-3 py-2 text-xs font-semibold text-gray-600 bg-white border border-gray-200 rounded-xl hover:bg-gray-50 transition-all shadow-sm">
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                Export
              </button>
              <button onClick={() => fetchData(true)} disabled={refreshing}
                className="flex items-center gap-1.5 px-3 py-2 text-xs font-semibold text-gray-600 bg-white border border-gray-200 rounded-xl hover:bg-gray-50 disabled:opacity-50 transition-all shadow-sm">
                <svg className={refreshing?"animate-spin":""} width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/></svg>
                Refresh
              </button>
            </div>
            {refreshAgo && <span className="text-[9px] text-gray-400">Updated {refreshAgo}</span>}
          </div>
        </div>

        {/* Summary */}
        <div className="animate-fade-up grid grid-cols-2 sm:grid-cols-5 gap-3">
          {[
            { label:"Overdue",    count:overdue.length,  color:"#ef4444", bg:"#fef2f2", filter:"overdue"   as const,
              info:{ title:"Overdue", description:"Open CRITICAL/HIGH files past their attestation SLA deadline. These need immediate reviewer attention." } },
            { label:"Severely overdue", count:severelyOverdue, color:"#be123c", bg:"#fff1f2", filter:"overdue" as const,
              info:{ title:"Severely Overdue", description:"Items more than 24 hours past their SLA deadline — highest escalation priority." } },
            { label:"Due today",  count:dueToday.length, color:"#f59e0b", bg:"#fffbeb", filter:"due_today" as const,
              info:{ title:"Due Today", description:"Items whose SLA deadline falls within the next 24 hours." } },
            { label:"On track",   count:onTrack.length,  color:"#22c55e", bg:"#f0fdf4", filter:"on_track"  as const,
              info:{ title:"On Track", description:"Items with more than 24 hours remaining before their SLA deadline." } },
            { label:"Compliance", count:`${compliance}%`, color:"#0369a1", bg:"#f0f9ff", filter:"all" as const,
              info:{ title:"SLA Compliance", description:"Share of tracked items currently on track (>24h remaining).", formula:"on_track ÷ total × 100" } },
          ].map(s => (
            <button key={s.label} onClick={() => setFilter(s.filter === filter ? "all" : s.filter)}
              className={`rounded-2xl p-4 border-2 text-left transition-all ${filter === s.filter ? "" : "border-transparent hover:border-gray-200"}`}
              style={{ background:s.bg, borderColor: filter === s.filter ? s.color : undefined }}>
              <p className="text-2xl font-black tabular-nums" style={{ color: s.color }}>{s.count}</p>
              <div className="flex items-center gap-1.5 mt-1">
                <p className="text-xs font-semibold text-gray-500">{s.label}</p>
                <InfoTooltip title={s.info.title} description={s.info.description} formula={(s.info as { formula?: string }).formula} position="top" />
              </div>
            </button>
          ))}
        </div>

        {avgOverdueHrs > 0 && (
          <div className="animate-fade-up flex items-center gap-2 bg-rose-50 border border-rose-200 rounded-xl px-4 py-2.5 text-xs font-semibold text-rose-700">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
            Average overdue item is {avgOverdueHrs}h past its SLA deadline
          </div>
        )}

        {/* Filters */}
        <div className="animate-fade-up flex flex-wrap items-center gap-2">
          <div className="flex items-center rounded-xl border border-gray-200 bg-white overflow-hidden">
            <svg className="ml-3 text-gray-400 shrink-0" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
            <input value={search} onChange={e=>setSearch(e.target.value)} placeholder="Search files, repos…"
              className="px-3 py-2 text-xs text-gray-700 bg-transparent outline-none w-44" />
            {search && <button onClick={()=>setSearch("")} className="pr-2 text-gray-400 hover:text-gray-600 text-xs">✕</button>}
          </div>
          <div className="flex items-center gap-0.5 bg-gray-100 p-0.5 rounded-xl">
            {(["all","overdue","due_today","on_track"] as const).map(f => (
              <button key={f} onClick={() => setFilter(f)}
                className={`px-3 py-1.5 text-xs font-semibold rounded-lg transition-all ${filter===f ? "bg-white text-gray-900 shadow-sm" : "text-gray-500 hover:text-gray-700"}`}>
                {f === "all" ? `All (${items.length})` : f === "overdue" ? `Overdue (${overdue.length})` : f === "due_today" ? `Due today (${dueToday.length})` : `On track (${onTrack.length})`}
              </button>
            ))}
          </div>
          <select value={riskFilter} onChange={e=>setRiskFilter(e.target.value)}
            className="text-xs font-semibold text-gray-600 bg-white border border-gray-200 rounded-xl px-3 py-2 focus:outline-none">
            <option value="all">All Risk Levels</option>
            {(["CRITICAL","HIGH","MEDIUM","LOW"]).map(r => <option key={r} value={r}>{r}</option>)}
          </select>
          {repos.length > 0 && (
            <select value={repoFilter} onChange={e=>setRepoFilter(e.target.value)}
              className="text-xs font-semibold text-gray-600 bg-white border border-gray-200 rounded-xl px-3 py-2 focus:outline-none">
              <option value="all">All Repos</option>
              {repos.map(r => <option key={r} value={r}>{r.split("/")[1] ?? r}</option>)}
            </select>
          )}
          <div className="flex items-center gap-0.5 bg-gray-100 p-0.5 rounded-xl">
            {(["urgency","risk","repo"] as const).map(s => (
              <button key={s} onClick={()=>setSortBy(s)}
                className={`px-3 py-1.5 text-xs font-semibold rounded-lg transition-all ${sortBy===s ? "bg-white text-gray-900 shadow-sm" : "text-gray-500 hover:text-gray-700"}`}>
                {s === "urgency" ? "Sort: Urgency" : s === "risk" ? "Sort: Risk" : "Sort: Repo"}
              </button>
            ))}
          </div>
          {(search || filter!=="all" || riskFilter!=="all" || repoFilter!=="all") && (
            <button onClick={() => { setSearch(""); setFilter("all"); setRiskFilter("all"); setRepoFilter("all"); }}
              className="text-xs font-bold text-rose-600 hover:text-rose-800 px-2 py-1 rounded-lg hover:bg-rose-50 transition-colors">
              Clear all
            </button>
          )}
          <span className="text-xs text-gray-400 ml-auto">{filtered.length} item{filtered.length!==1?"s":""}</span>
        </div>

        {/* SLA items */}
        <div className="animate-fade-up bg-white rounded-2xl border border-gray-200 shadow-sm overflow-hidden">
          {filtered.length === 0 ? (
            <div className="py-16 text-center">
              <p className="text-2xl mb-2">🎉</p>
              <p className="text-sm font-bold text-gray-700">No matching SLA items</p>
              <p className="text-xs text-gray-400 mt-1">
                {items.length === 0 ? "All CRITICAL and HIGH files are within their attestation SLA" : "Try a different filter or search term"}
              </p>
            </div>
          ) : (
            <div className="divide-y divide-gray-50">
              {filtered.map(item => {
                const u = urgencyLabel(item.hours_overdue);
                const hoursAbs = Math.abs(Math.round(item.hours_overdue));
                const timeLabel = item.hours_overdue > 0
                  ? `${hoursAbs}h overdue`
                  : item.hours_overdue > -1
                    ? "Due in < 1h"
                    : `Due in ${hoursAbs}h`;
                return (
                  <div key={item.id} className="flex items-start gap-4 px-5 py-4">
                    <div className="w-2 h-2 rounded-full shrink-0 mt-1.5" style={{ background: RISK_COLOR[item.risk_score] ?? "#94a3b8" }} />
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-semibold text-gray-900 truncate">{item.file_path.split("/").pop()}</p>
                      <p className="text-xs text-gray-400 truncate">{item.file_path} {item.repo ? `· ${item.repo.split("/")[1] ?? item.repo}` : ""}{item.pr_number ? ` · PR #${item.pr_number}` : ""}</p>
                      <div className="flex items-center gap-3 mt-1 flex-wrap text-[10px] text-gray-400">
                        <span>SLA deadline {fmtDate(item.sla_deadline)} ({SLA_HOURS[item.risk_score] ?? "—"}h policy)</span>
                        {item.assigned_email && (
                          <span className="flex items-center gap-1">
                            <svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                            {item.assigned_email.split("@")[0]}
                          </span>
                        )}
                      </div>
                    </div>
                    <div className="shrink-0 text-right">
                      <span className="text-[10px] font-bold px-2.5 py-1 rounded-full"
                        style={{ background: u.bg, color: u.color }}>
                        {timeLabel}
                      </span>
                      <p className="text-[9px] text-gray-400 mt-0.5">{u.label}</p>
                    </div>
                    <div className="shrink-0 flex items-center gap-2">
                      <span className="text-[9px] font-bold px-2 py-0.5 rounded-full"
                        style={{ background:`${RISK_COLOR[item.risk_score]}18`, color: RISK_COLOR[item.risk_score] }}>
                        {item.risk_score}
                      </span>
                      <Link href={`/pr/${item.scan_id}`}
                        className="text-xs font-semibold text-indigo-600 hover:text-indigo-800 whitespace-nowrap">
                        Review →
                      </Link>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>

      </div>
    </AuthGuard>
  );
}
