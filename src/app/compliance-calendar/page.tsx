"use client";

import { useState, useMemo, useEffect, useCallback } from "react";
import Link from "next/link";
import AuthGuard from "@/components/AuthGuard";
import { authedFetch, isSeedMode } from "@/lib/useRealData";

interface AuditEvent {
  id:         string;
  title:      string;
  framework:  string;
  type:       "audit" | "deadline" | "review" | "cert-expiry" | "reminder";
  date:       string;         // ISO date
  status:     "upcoming" | "overdue" | "completed" | "in-progress";
  owner?:     string;
  notes?:     string;
  link?:      string;
}

const TYPE_META = {
  audit:       { label:"Audit",        color:"#6366f1", bg:"#eef2ff"  },
  deadline:    { label:"Deadline",     color:"#ef4444", bg:"#fff1f2"  },
  review:      { label:"Review",       color:"#f59e0b", bg:"#fffbeb"  },
  "cert-expiry":{ label:"Cert Expiry", color:"#7c3aed", bg:"#ede9fe"  },
  reminder:    { label:"Reminder",     color:"#10b981", bg:"#f0fdf4"  },
};

const STATUS_META = {
  upcoming:    { label:"Upcoming",    color:"#6366f1" },
  overdue:     { label:"Overdue",     color:"#ef4444" },
  completed:   { label:"Completed",   color:"#10b981" },
  "in-progress":{ label:"In Progress",color:"#f59e0b" },
};

// Default events (replaced by real org schedule in production)
const DEFAULT_EVENTS: AuditEvent[] = [
  // SOC 2
  { id:"soc2-prep",    title:"SOC 2 Type II Audit Preparation",     framework:"SOC 2",    type:"review",      date:"2026-07-01", status:"upcoming",     owner:"alice@org.io",  notes:"Gather evidence for all TSCs" },
  { id:"soc2-audit",   title:"SOC 2 Type II Audit Window Opens",     framework:"SOC 2",    type:"audit",       date:"2026-08-01", status:"upcoming",     owner:"alice@org.io",  link:"/compliance" },
  { id:"soc2-report",  title:"SOC 2 Report Delivery Deadline",       framework:"SOC 2",    type:"deadline",    date:"2026-08-20", status:"upcoming",     owner:"alice@org.io" },
  // EU AI Act
  { id:"euai-review",  title:"EU AI Act High-Risk Assessment Review", framework:"EU AI Act",type:"review",      date:"2026-07-15", status:"upcoming",     owner:"bob@org.io" },
  { id:"euai-deadline","title":"EU AI Act Compliance Deadline",       framework:"EU AI Act",type:"deadline",    date:"2026-08-01", status:"upcoming",     link:"/compliance" },
  // PCI-DSS
  { id:"pci-q2",       title:"PCI-DSS Quarterly Scan Review",        framework:"PCI-DSS",  type:"review",      date:"2026-06-30", status:"upcoming",     owner:"alice@org.io" },
  { id:"pci-cert",     title:"PCI-DSS Certificate Expiry",           framework:"PCI-DSS",  type:"cert-expiry", date:"2026-08-22", status:"upcoming",     notes:"Renew with SecurityMetrics QSA" },
  { id:"pci-audit",    title:"PCI-DSS Annual QSA Assessment",        framework:"PCI-DSS",  type:"audit",       date:"2026-09-01", status:"upcoming" },
  // Internal
  { id:"int-policy",   title:"Security Policy Annual Review",        framework:"Internal", type:"review",      date:"2026-06-30", status:"in-progress",  owner:"alice@org.io" },
  { id:"int-training", title:"Security Awareness Training Deadline", framework:"Internal", type:"deadline",    date:"2026-07-15", status:"upcoming" },
  { id:"int-pentest",  title:"Annual Penetration Test",              framework:"Internal", type:"audit",       date:"2026-10-01", status:"upcoming" },
  // Already done
  { id:"done-soc1",    title:"SOC 2 Type I Audit Completed",         framework:"SOC 2",    type:"audit",       date:"2026-02-28", status:"completed",    notes:"Clean opinion received" },
  { id:"done-pci-q1",  title:"PCI-DSS Q1 Scan Review",              framework:"PCI-DSS",  type:"review",      date:"2026-03-31", status:"completed" },
];

const MONTHS = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];

function daysUntil(dateStr: string): number {
  return Math.ceil((new Date(dateStr).getTime() - Date.now()) / 86400_000);
}

const CAL_KEY = "tl_compliance_calendar";

export default function ComplianceCalendarPage() {
  const [view,        setView]        = useState<"timeline" | "list">("timeline");
  const [filter,      setFilter]      = useState<string>("all");
  const [events,      setEvents]      = useState<AuditEvent[]>([]);
  const [showAdd,     setShowAdd]     = useState(false);
  const [newEvent,    setNewEvent]    = useState<Partial<AuditEvent>>({ type:"reminder", status:"upcoming", framework:"Internal" });

  // Load: seed key → API → DEFAULT_EVENTS fallback
  useEffect(() => {
    // Seed mode: read from tl_compliance_calendar
    if (isSeedMode()) {
      try {
        const raw = localStorage.getItem(CAL_KEY);
        if (raw) { setEvents(JSON.parse(raw) as AuditEvent[]); return; }
      } catch {}
      setEvents(DEFAULT_EVENTS);
      return;
    }
    // Live mode: try API, then localStorage cache, then defaults
    authedFetch<AuditEvent[]>("/api/compliance-calendar")
      .then(data => { setEvents(data); localStorage.setItem(CAL_KEY, JSON.stringify(data)); })
      .catch(() => {
        try {
          const cached = localStorage.getItem(CAL_KEY);
          if (cached) { setEvents(JSON.parse(cached) as AuditEvent[]); return; }
        } catch {}
        setEvents(DEFAULT_EVENTS);
      });
  }, []);

  // Persist event list to localStorage whenever it changes (so user-added events survive refresh)
  const persistEvents = useCallback((updated: AuditEvent[]) => {
    setEvents(updated);
    try { localStorage.setItem(CAL_KEY, JSON.stringify(updated)); } catch {}
  }, []);

  const frameworks = ["all", ...Array.from(new Set(events.map(e => e.framework)))];
  const filtered   = events.filter(e => filter === "all" || e.framework === filter)
    .sort((a, b) => new Date(a.date).getTime() - new Date(b.date).getTime());

  const upcomingCount = events.filter(e => e.status === "upcoming" || e.status === "in-progress").length;
  const overdueCount  = events.filter(e => daysUntil(e.date) < 0 && e.status !== "completed").length;
  const nextEvent     = filtered.find(e => daysUntil(e.date) >= 0 && e.status !== "completed");

  // Group events by month for timeline view
  const byMonth = useMemo(() => {
    const map: Record<string, AuditEvent[]> = {};
    filtered.forEach(e => {
      const d = new Date(e.date);
      const k = `${d.getFullYear()}-${String(d.getMonth()+1).padStart(2,"0")}`;
      if (!map[k]) map[k] = [];
      map[k].push(e);
    });
    return Object.entries(map).sort(([a],[b]) => a.localeCompare(b));
  }, [filtered]);

  function addEvent() {
    if (!newEvent.title || !newEvent.date) return;
    const ev: AuditEvent = {
      id:        `custom-${Date.now()}`,
      title:     newEvent.title!,
      framework: newEvent.framework ?? "Internal",
      type:      newEvent.type as AuditEvent["type"] ?? "reminder",
      date:      newEvent.date!,
      status:    "upcoming",
      owner:     newEvent.owner,
      notes:     newEvent.notes,
    };
    persistEvents([...events, ev].sort((a,b) => new Date(a.date).getTime()-new Date(b.date).getTime()));
    setNewEvent({ type:"reminder", status:"upcoming", framework:"Internal" });
    setShowAdd(false);
  }

  function toggleComplete(id: string) {
    persistEvents(events.map(e => e.id === id
      ? { ...e, status: (e.status === "completed" ? "upcoming" : "completed") as AuditEvent["status"] }
      : e
    ));
  }

  return (
    <AuthGuard>
      <div className="max-w-4xl mx-auto space-y-5 pb-10">

        {/* Header */}
        <div className="flex items-start justify-between gap-4 flex-wrap pt-1">
          <div>
            <h1 className="text-xl font-black text-gray-900">Compliance Calendar</h1>
            <p className="text-sm text-gray-400 mt-0.5">Track audit deadlines, cert renewals, and policy reviews</p>
          </div>
          <div className="flex items-center gap-2">
            <div className="flex items-center gap-1 bg-gray-100 p-0.5 rounded-xl">
              {(["timeline","list"] as const).map(v => (
                <button key={v} onClick={() => setView(v)}
                  className={`px-3 py-1.5 text-xs font-semibold rounded-lg transition-all ${view===v?"bg-white text-gray-900 shadow-sm":"text-gray-500 hover:text-gray-700"}`}>
                  {v === "timeline" ? "Timeline" : "List"}
                </button>
              ))}
            </div>
            <button onClick={() => setShowAdd(v=>!v)}
              className="px-4 py-2 text-sm font-bold rounded-xl bg-indigo-600 text-white hover:bg-indigo-700 transition-colors">
              + Add event
            </button>
          </div>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-3 gap-4">
          {[
            { label:"Upcoming events", value:upcomingCount,    color:"#6366f1" },
            { label:"Overdue",         value:overdueCount,     color:overdueCount > 0 ? "#ef4444" : "#22c55e" },
            { label:"Days to next",    value:nextEvent ? Math.max(0, daysUntil(nextEvent.date)) : "—", color:"#f59e0b" },
          ].map(s => (
            <div key={s.label} className="bg-white rounded-2xl border border-gray-200 p-5 text-center shadow-sm">
              <p className="text-2xl font-black" style={{ color: s.color }}>{s.value}</p>
              <p className="text-xs text-gray-400 mt-1">{s.label}</p>
              {s.label === "Days to next" && nextEvent && (
                <p className="text-[10px] text-gray-500 mt-0.5 truncate">{nextEvent.title}</p>
              )}
            </div>
          ))}
        </div>

        {/* Framework filter */}
        <div className="flex items-center gap-2 flex-wrap">
          {frameworks.map(fw => (
            <button key={fw} onClick={() => setFilter(fw)}
              className={`px-3 py-1.5 text-xs font-semibold rounded-xl transition-all ${
                filter === fw ? "bg-indigo-600 text-white" : "bg-gray-100 text-gray-600 hover:bg-gray-200"
              }`}>
              {fw === "all" ? "All frameworks" : fw}
            </button>
          ))}
        </div>

        {/* Add event form */}
        {showAdd && (
          <div className="bg-white rounded-2xl border border-gray-200 p-5 shadow-sm space-y-4">
            <p className="text-sm font-bold text-gray-900">Add compliance event</p>
            <div className="grid grid-cols-2 gap-3">
              <label className="block col-span-2">
                <span className="text-xs font-semibold text-gray-600 block mb-1">Title *</span>
                <input value={newEvent.title ?? ""} onChange={e => setNewEvent(p=>({...p,title:e.target.value}))}
                  placeholder="e.g. SOC 2 Evidence Collection Deadline"
                  className="w-full text-sm border border-gray-200 rounded-xl px-3.5 py-2.5 focus:outline-none focus:ring-2 focus:ring-indigo-400" />
              </label>
              <label className="block">
                <span className="text-xs font-semibold text-gray-600 block mb-1">Date *</span>
                <input type="date" value={newEvent.date ?? ""} onChange={e => setNewEvent(p=>({...p,date:e.target.value}))}
                  className="w-full text-sm border border-gray-200 rounded-xl px-3.5 py-2.5 focus:outline-none focus:ring-2 focus:ring-indigo-400" />
              </label>
              <label className="block">
                <span className="text-xs font-semibold text-gray-600 block mb-1">Type</span>
                <select value={newEvent.type} onChange={e => setNewEvent(p=>({...p,type:e.target.value as AuditEvent["type"]}))}
                  className="w-full text-sm border border-gray-200 rounded-xl px-3.5 py-2.5 focus:outline-none focus:ring-2 focus:ring-indigo-400 bg-white">
                  {Object.entries(TYPE_META).map(([k,v]) => <option key={k} value={k}>{v.label}</option>)}
                </select>
              </label>
              <label className="block">
                <span className="text-xs font-semibold text-gray-600 block mb-1">Framework</span>
                <input value={newEvent.framework ?? ""} onChange={e => setNewEvent(p=>({...p,framework:e.target.value}))}
                  placeholder="SOC 2 / PCI-DSS / Internal"
                  className="w-full text-sm border border-gray-200 rounded-xl px-3.5 py-2.5 focus:outline-none focus:ring-2 focus:ring-indigo-400" />
              </label>
              <label className="block">
                <span className="text-xs font-semibold text-gray-600 block mb-1">Owner email</span>
                <input value={newEvent.owner ?? ""} onChange={e => setNewEvent(p=>({...p,owner:e.target.value}))}
                  placeholder="alice@company.com" type="email"
                  className="w-full text-sm border border-gray-200 rounded-xl px-3.5 py-2.5 focus:outline-none focus:ring-2 focus:ring-indigo-400" />
              </label>
            </div>
            <div className="flex gap-3">
              <button onClick={addEvent} disabled={!newEvent.title || !newEvent.date}
                className="px-5 py-2 text-sm font-bold rounded-xl bg-indigo-600 text-white hover:bg-indigo-700 disabled:opacity-60 transition-colors">
                Add event
              </button>
              <button onClick={() => setShowAdd(false)} className="text-sm text-gray-400 hover:text-gray-600">Cancel</button>
            </div>
          </div>
        )}

        {/* Timeline view */}
        {view === "timeline" && (
          <div className="space-y-6">
            {byMonth.map(([monthKey, monthEvents]) => {
              const [year, month] = monthKey.split("-");
              const label = `${MONTHS[parseInt(month)-1]} ${year}`;
              return (
                <div key={monthKey}>
                  <p className="text-xs font-black text-gray-400 uppercase tracking-wider mb-3">{label}</p>
                  <div className="space-y-2">
                    {monthEvents.map(ev => <EventRow key={ev.id} event={ev} onToggle={toggleComplete} />)}
                  </div>
                </div>
              );
            })}
          </div>
        )}

        {/* List view */}
        {view === "list" && (
          <div className="bg-white rounded-2xl border border-gray-200 overflow-hidden shadow-sm">
            <div className="divide-y divide-gray-50">
              {filtered.map(ev => <EventRow key={ev.id} event={ev} onToggle={toggleComplete} listMode />)}
            </div>
          </div>
        )}

      </div>
    </AuthGuard>
  );
}

function EventRow({ event: ev, onToggle, listMode = false }: {
  event: AuditEvent;
  onToggle: (id: string) => void;
  listMode?: boolean;
}) {
  const typeMeta   = TYPE_META[ev.type];
  const statusMeta = STATUS_META[ev.status];
  const days       = daysUntil(ev.date);
  const isOverdue  = days < 0 && ev.status !== "completed";
  const urgency    = days >= 0 && days <= 7 && ev.status !== "completed";

  return (
    <div className={`flex items-start gap-4 p-4 rounded-2xl border transition-all ${
      listMode ? "border-transparent hover:bg-gray-50" :
      ev.status === "completed" ? "bg-gray-50 border-gray-100 opacity-60" :
      isOverdue ? "bg-rose-50 border-rose-200" :
      urgency   ? "bg-amber-50 border-amber-200" :
      "bg-white border-gray-200"
    }`}>
      {/* Checkbox */}
      <button onClick={() => onToggle(ev.id)}
        className={`mt-0.5 w-5 h-5 rounded-lg border-2 flex items-center justify-center shrink-0 transition-all ${
          ev.status === "completed" ? "bg-emerald-500 border-emerald-500" : "border-gray-300 hover:border-indigo-400"
        }`}>
        {ev.status === "completed" && (
          <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="3.5" strokeLinecap="round" strokeLinejoin="round">
            <polyline points="20 6 9 17 4 12"/>
          </svg>
        )}
      </button>

      {/* Content */}
      <div className="flex-1 min-w-0">
        <div className="flex items-start gap-2 flex-wrap">
          <p className={`text-sm font-bold ${ev.status === "completed" ? "line-through text-gray-400" : "text-gray-900"}`}>
            {ev.title}
          </p>
          <span className="text-[9px] font-bold px-2 py-0.5 rounded-full shrink-0"
            style={{ background: typeMeta.bg, color: typeMeta.color }}>
            {typeMeta.label}
          </span>
          {isOverdue && (
            <span className="text-[9px] font-bold px-2 py-0.5 rounded-full bg-rose-100 text-rose-700 shrink-0">Overdue</span>
          )}
        </div>
        <div className="flex items-center gap-3 mt-1 flex-wrap">
          <span className="text-[11px] text-gray-400">{ev.framework}</span>
          {ev.owner && <span className="text-[11px] text-gray-400">{ev.owner}</span>}
          {ev.notes && <span className="text-[11px] text-gray-400 italic">{ev.notes}</span>}
        </div>
      </div>

      {/* Date + status */}
      <div className="shrink-0 text-right">
        <p className={`text-sm font-black tabular-nums ${isOverdue ? "text-rose-600" : urgency ? "text-amber-600" : "text-gray-700"}`}>
          {new Date(ev.date).toLocaleDateString("en-GB", { day:"numeric", month:"short" })}
        </p>
        <p className="text-[10px] mt-0.5" style={{ color: statusMeta.color }}>
          {ev.status === "completed" ? "Done" : days === 0 ? "Today" : days > 0 ? `${days}d away` : `${Math.abs(days)}d ago`}
        </p>
        {ev.link && (
          <Link href={ev.link} className="text-[10px] text-indigo-500 hover:text-indigo-700 font-semibold mt-0.5 block">
            View →
          </Link>
        )}
      </div>
    </div>
  );
}
