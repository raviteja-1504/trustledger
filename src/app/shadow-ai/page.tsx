"use client";

/**
 * Shadow AI Detector
 *
 * Catches when developers use AI tools your organisation hasn't approved.
 * E.g. company policy says "Copilot only" but code patterns show ChatGPT or Gemini.
 *
 * This is the AI governance equivalent of Shadow IT detection.
 */

import { useState, useEffect, useMemo, useCallback } from "react";
import AuthGuard from "@/components/AuthGuard";
import PageSkeleton from "@/components/PageSkeleton";
import InfoTooltip from "@/components/InfoTooltip";

// ── Policy config (in production this comes from /api/settings) ───────────────

const ALLOWED_TOOLS_KEY = "tl_allowed_ai_tools";
const OVERRIDES_KEY     = "tl_shadow_ai_overrides";

const ALL_TOOLS = [
  { id:"github-copilot",  label:"GitHub Copilot",   icon:"🤖", vendor:"Microsoft/GitHub" },
  { id:"chatgpt",         label:"ChatGPT",           icon:"💬", vendor:"OpenAI" },
  { id:"gemini",          label:"Gemini",            icon:"✨", vendor:"Google" },
  { id:"claude",          label:"Claude",            icon:"🔮", vendor:"Anthropic" },
  { id:"codewhisperer",   label:"CodeWhisperer",     icon:"☁️", vendor:"AWS" },
  { id:"cursor",          label:"Cursor AI",         icon:"⚡", vendor:"Cursor" },
  { id:"tabnine",         label:"Tabnine",           icon:"🔷", vendor:"Tabnine" },
];

function getPolicy(): string[] {
  if (typeof window === "undefined") return ["github-copilot"];
  try {
    const stored = localStorage.getItem(ALLOWED_TOOLS_KEY);
    return stored ? JSON.parse(stored) as string[] : ["github-copilot"];
  } catch { return ["github-copilot"]; }
}

function savePolicy(tools: string[]) {
  localStorage.setItem(ALLOWED_TOOLS_KEY, JSON.stringify(tools));
}

// ── Per-detection overrides (status / notes / notified) ────────────────────────

type DetectionStatus = "open" | "investigating" | "acceptable" | "resolved";

interface DetectionOverride {
  status?:      DetectionStatus;
  notes?:       string[];
  notified_at?: string;
}

const STATUS_STYLE: Record<DetectionStatus, { bg:string; text:string; border:string; label:string }> = {
  open:          { bg:"#fef2f2", text:"#be123c", border:"#fecdd3", label:"Open"          },
  investigating: { bg:"#fffbeb", text:"#b45309", border:"#fde68a", label:"Investigating" },
  acceptable:    { bg:"#f0f9ff", text:"#0369a1", border:"#bae6fd", label:"Accepted"      },
  resolved:      { bg:"#f0fdf4", text:"#15803d", border:"#bbf7d0", label:"Resolved"      },
};

function loadOverrides(): Record<string, DetectionOverride> {
  try { return JSON.parse(localStorage.getItem(OVERRIDES_KEY) ?? "{}"); } catch { return {}; }
}
function saveOverrides(o: Record<string, DetectionOverride>) {
  localStorage.setItem(OVERRIDES_KEY, JSON.stringify(o));
}
function detectionId(d: { repo:string; file:string; date:string }) {
  return `${d.repo}|${d.file}|${d.date}`;
}

function buildDetections(
  rawDetections: Array<{ repo: string; file: string; tool: string; confidence: number; dev: string; date: string }>,
  allowed: string[],
) {
  return rawDetections.map(s => ({ ...s, allowed: allowed.includes(s.tool) }));
}

function fmtDateTime(iso: string) {
  const d = new Date(iso);
  return `${d.getDate()} ${["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"][d.getMonth()]} ${d.getFullYear()} ${String(d.getHours()).padStart(2,"0")}:${String(d.getMinutes()).padStart(2,"0")}`;
}
function timeAgo(iso: string) {
  const s = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s/60)}m ago`;
  if (s < 86400) return `${Math.floor(s/3600)}h ago`;
  return `${Math.floor(s/86400)}d ago`;
}

// ── Stats ──────────────────────────────────────────────────────────────────────

export default function ShadowAIPage() {
  const [rawDetections, setRawDetections] = useState<Array<{ repo:string; file:string; tool:string; confidence:number; dev:string; date:string }>>([]);
  const [allowed, setAllowed] = useState<string[]>(["github-copilot"]);
  const [editing, setEditing] = useState(false);
  const [draft,   setDraft]   = useState<string[]>([]);
  const [overrides, setOverrides] = useState<Record<string, DetectionOverride>>({});
  const [loading, setLoading] = useState(true);

  // Filters
  const [search,       setSearch]       = useState("");
  const [toolFilter,   setToolFilter]   = useState("all");
  const [statusFilter, setStatusFilter] = useState<DetectionStatus | "all">("all");
  const [minConfidence, setMinConfidence] = useState(0);
  const [sortBy,       setSortBy]       = useState<"date" | "confidence" | "dev">("date");
  const [expanded,     setExpanded]     = useState<string | null>(null);
  const [noteInput,    setNoteInput]    = useState<Record<string,string>>({});

  const load = useCallback(() => {
    setAllowed(getPolicy());
    setOverrides(loadOverrides());
    // 1. Seed mode — load from tl_shadow_ai_detections
    try {
      const raw = localStorage.getItem("tl_shadow_ai_detections");
      if (raw) { setRawDetections(JSON.parse(raw)); setLoading(false); return; }
    } catch {}
    // 2. Live mode — fetch from API
    fetch("/api/shadow-ai?days=30")
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(d => setRawDetections(Array.isArray(d) ? d : d.detections ?? []))
      .catch(() => setRawDetections([]))
      .finally(() => setLoading(false));
  }, []);

  useEffect(() => { load(); }, [load]);

  function updateOverride(id: string, patch: Partial<DetectionOverride>) {
    setOverrides(prev => {
      const next = { ...prev, [id]: { ...prev[id], ...patch } };
      saveOverrides(next);
      return next;
    });
  }

  function addNote(id: string) {
    const text = noteInput[id]?.trim();
    if (!text) return;
    const existing = overrides[id]?.notes ?? [];
    const date = new Date().toLocaleDateString("en-GB",{day:"2-digit",month:"short",year:"numeric"});
    updateOverride(id, { notes:[...existing, `${date}: ${text}`] });
    setNoteInput(p=>({...p,[id]:""}));
  }

  function notify(id: string) {
    updateOverride(id, { notified_at: new Date().toISOString() });
  }

  const detections = useMemo(() => buildDetections(rawDetections, allowed).map(d => {
    const id = detectionId(d);
    const ov = overrides[id] ?? {};
    return { ...d, id, status: ov.status ?? "open", notes: ov.notes ?? [], notified_at: ov.notified_at };
  }), [rawDetections, allowed, overrides]);

  const violations = detections.filter(d => !d.allowed);
  const compliant  = detections.filter(d => d.allowed);
  const highConfidence = violations.filter(d => d.confidence >= 0.8).length;
  const resolvedCount  = violations.filter(d => d.status === "resolved").length;

  const toolCounts = detections.reduce<Record<string, number>>((acc, d) => {
    acc[d.tool] = (acc[d.tool] ?? 0) + 1;
    return acc;
  }, {});

  const devViolations = violations.reduce<Record<string, number>>((acc, d) => {
    acc[d.dev] = (acc[d.dev] ?? 0) + 1;
    return acc;
  }, {});

  const filteredViolations = useMemo(() => {
    let list = violations;
    if (toolFilter !== "all")   list = list.filter(d => d.tool === toolFilter);
    if (statusFilter !== "all") list = list.filter(d => d.status === statusFilter);
    if (minConfidence > 0)      list = list.filter(d => d.confidence >= minConfidence);
    if (search) {
      const q = search.toLowerCase();
      list = list.filter(d => d.repo.toLowerCase().includes(q) || d.file.toLowerCase().includes(q) || d.dev.toLowerCase().includes(q));
    }
    return [...list].sort((a,b) => {
      if (sortBy === "confidence") return b.confidence - a.confidence;
      if (sortBy === "dev")        return a.dev.localeCompare(b.dev);
      return new Date(b.date).getTime() - new Date(a.date).getTime();
    });
  }, [violations, toolFilter, statusFilter, minConfidence, search, sortBy]);

  function startEdit() { setDraft([...allowed]); setEditing(true); }
  function saveEdit()  { savePolicy(draft); setAllowed(draft); setEditing(false); }

  function exportCSV() {
    const rows = [
      ["Repo","File","Tool","Confidence","Developer","Date","Allowed","Status"],
      ...detections.map(d => [d.repo, d.file, d.tool, d.confidence, d.dev, d.date, d.allowed?"yes":"no", d.status]),
    ];
    const blob = new Blob([rows.map(r=>r.map(c=>`"${c}"`).join(",")).join("\n")], { type:"text/csv" });
    Object.assign(document.createElement("a"), { href:URL.createObjectURL(blob), download:"shadow-ai.csv" }).click();
  }

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
                  <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
                </svg>
              </div>
              <h1 className="text-xl font-black text-gray-900 tracking-tight">Shadow AI Detector</h1>
              {violations.length>0 && <span className="text-xs font-black text-white bg-rose-500 px-2 py-0.5 rounded-full">{violations.length} unapproved</span>}
            </div>
            <p className="text-sm text-gray-400">
              Catches unauthorised AI tools — the AI governance equivalent of Shadow IT
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button onClick={exportCSV}
              className="flex items-center gap-1.5 px-3 py-2 text-xs font-semibold text-gray-600 bg-white border border-gray-200 rounded-xl hover:bg-gray-50 transition-all shadow-sm">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
              Export
            </button>
            <button onClick={startEdit}
              className="flex items-center gap-1.5 px-4 py-2 text-xs font-bold rounded-xl bg-indigo-600 text-white hover:bg-indigo-700 transition-colors shadow-sm">
              ⚙️ Edit Allowed Tools
            </button>
          </div>
        </div>

        {/* ── Policy editor ── */}
        {editing && (
          <div className="animate-fade-up bg-indigo-50 border border-indigo-200 rounded-2xl p-5">
            <p className="font-bold text-indigo-900 mb-4">Approved AI Tools Policy</p>
            <div className="grid grid-cols-2 gap-3 mb-4">
              {ALL_TOOLS.map(t => (
                <label key={t.id} className={`flex items-center gap-3 p-3 rounded-xl cursor-pointer border transition-colors ${draft.includes(t.id) ? "bg-white border-indigo-300" : "bg-indigo-50/50 border-indigo-100"}`}>
                  <input type="checkbox" checked={draft.includes(t.id)} onChange={e => setDraft(p => e.target.checked ? [...p, t.id] : p.filter(x => x !== t.id))} className="w-4 h-4 accent-indigo-600" />
                  <span className="text-lg">{t.icon}</span>
                  <div>
                    <div className="font-bold text-sm text-gray-900">{t.label}</div>
                    <div className="text-xs text-gray-500">{t.vendor}</div>
                  </div>
                </label>
              ))}
            </div>
            <div className="flex gap-3">
              <button onClick={saveEdit} className="px-4 py-2 bg-indigo-600 text-white text-sm font-bold rounded-xl hover:bg-indigo-700">Save Policy</button>
              <button onClick={() => setEditing(false)} className="px-4 py-2 bg-white border border-gray-200 text-sm font-bold rounded-xl hover:bg-gray-50">Cancel</button>
            </div>
          </div>
        )}

        {/* ── Stats row ── */}
        <div className="animate-fade-up grid grid-cols-2 sm:grid-cols-5 gap-3">
          {[
            { label:"Approved Tools", value: allowed.length, color:"#16a34a", bg:"#f0fdf4",
              info:{ title:"Approved Tools", description:"Number of AI coding tools currently allowed under your organisation's policy." } },
            { label:"Total Detections", value: detections.length, color:"#6366f1", bg:"#eef2ff",
              info:{ title:"Total Detections", description:"All AI-tool usage signatures detected across scanned repositories in the selected window." } },
            { label:"Shadow AI Events", value: violations.length, color: violations.length > 0 ? "#dc2626" : "#16a34a", bg: violations.length > 0 ? "#fff1f2" : "#f0fdf4",
              info:{ title:"Shadow AI Events", description:"Detections using a tool that is not on the approved-tools policy list." } },
            { label:"High Confidence", value: highConfidence, color:"#b45309", bg:"#fffbeb",
              info:{ title:"High Confidence Events", description:"Shadow AI events detected with ≥80% confidence — most likely to be true positives." } },
            { label:"Affected Developers", value: Object.keys(devViolations).length, color:"#d97706", bg:"#fffbeb",
              info:{ title:"Affected Developers", description:"Number of distinct developers with at least one unapproved-tool detection." } },
          ].map(s => (
            <div key={s.label} className="rounded-2xl p-4 border border-gray-200" style={{ background:s.bg }}>
              <p className="text-2xl font-black tabular-nums" style={{ color: s.color }}>{s.value}</p>
              <div className="flex items-center gap-1.5 mt-1">
                <p className="text-xs font-semibold text-gray-500">{s.label}</p>
                <InfoTooltip title={s.info.title} description={s.info.description} position="top" />
              </div>
            </div>
          ))}
        </div>

        {resolvedCount > 0 && (
          <div className="animate-fade-up flex items-center gap-2 bg-emerald-50 border border-emerald-200 rounded-xl px-4 py-2.5 text-xs font-semibold text-emerald-700">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
            {resolvedCount} of {violations.length} shadow AI events marked resolved
          </div>
        )}

        {/* ── Allowed tools ── */}
        <div className="animate-fade-up section-card overflow-hidden">
          <div className="px-5 py-3 border-b border-gray-100 bg-gray-50">
            <p className="text-xs font-black text-gray-700 uppercase tracking-wider">Current Policy — Approved Tools</p>
          </div>
          <div className="p-4 flex flex-wrap gap-3">
            {ALL_TOOLS.map(t => {
              const isAllowed = allowed.includes(t.id);
              const count = toolCounts[t.id] ?? 0;
              return (
                <div key={t.id} className={`flex items-center gap-2.5 px-4 py-2.5 rounded-xl border text-sm font-bold ${isAllowed ? "bg-green-50 border-green-200 text-green-800" : "bg-gray-50 border-gray-200 text-gray-400"}`}>
                  <span className="text-base">{t.icon}</span>
                  <span>{t.label}</span>
                  {count > 0 && <span className={`text-xs px-1.5 py-0.5 rounded-full font-bold ${isAllowed ? "bg-green-200 text-green-800" : "bg-red-100 text-red-600"}`}>{count}</span>}
                  {isAllowed ? <span className="text-green-600 text-xs">✓ Allowed</span> : <span className="text-red-400 text-xs">✗ Blocked</span>}
                </div>
              );
            })}
          </div>
        </div>

        {/* ── Filters ── */}
        {violations.length > 0 && (
          <div className="animate-fade-up flex flex-wrap items-center gap-2">
            <div className="flex items-center rounded-xl border border-gray-200 bg-white overflow-hidden">
              <svg className="ml-3 text-gray-400 shrink-0" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
              <input value={search} onChange={e=>setSearch(e.target.value)} placeholder="Search repo, file, developer…"
                className="px-3 py-2 text-xs text-gray-700 bg-transparent outline-none w-48" />
              {search && <button onClick={()=>setSearch("")} className="pr-2 text-gray-400 hover:text-gray-600 text-xs">✕</button>}
            </div>
            <select value={toolFilter} onChange={e=>setToolFilter(e.target.value)}
              className="text-xs font-semibold text-gray-600 bg-white border border-gray-200 rounded-xl px-3 py-2 focus:outline-none">
              <option value="all">All Tools</option>
              {Array.from(new Set(violations.map(v=>v.tool))).map(t => {
                const tool = ALL_TOOLS.find(x=>x.id===t);
                return <option key={t} value={t}>{tool?.label ?? t}</option>;
              })}
            </select>
            <select value={statusFilter} onChange={e=>setStatusFilter(e.target.value as DetectionStatus|"all")}
              className="text-xs font-semibold text-gray-600 bg-white border border-gray-200 rounded-xl px-3 py-2 focus:outline-none">
              <option value="all">All Statuses</option>
              {(["open","investigating","acceptable","resolved"] as const).map(s=><option key={s} value={s}>{STATUS_STYLE[s].label}</option>)}
            </select>
            <select value={minConfidence} onChange={e=>setMinConfidence(Number(e.target.value))}
              className="text-xs font-semibold text-gray-600 bg-white border border-gray-200 rounded-xl px-3 py-2 focus:outline-none">
              <option value={0}>Any confidence</option>
              <option value={0.6}>≥ 60%</option>
              <option value={0.7}>≥ 70%</option>
              <option value={0.8}>≥ 80%</option>
              <option value={0.9}>≥ 90%</option>
            </select>
            <div className="flex items-center gap-0.5 bg-gray-100 p-0.5 rounded-xl">
              {(["date","confidence","dev"] as const).map(s => (
                <button key={s} onClick={()=>setSortBy(s)}
                  className={`px-3 py-1.5 text-xs font-semibold rounded-lg transition-all ${sortBy===s ? "bg-white text-gray-900 shadow-sm" : "text-gray-500 hover:text-gray-700"}`}>
                  {s === "date" ? "Sort: Date" : s === "confidence" ? "Sort: Confidence" : "Sort: Developer"}
                </button>
              ))}
            </div>
            {(search||toolFilter!=="all"||statusFilter!=="all"||minConfidence>0)&&(
              <button onClick={()=>{setSearch("");setToolFilter("all");setStatusFilter("all");setMinConfidence(0);}}
                className="text-xs font-bold text-rose-600 hover:text-rose-800 px-2 py-1 rounded-lg hover:bg-rose-50 transition-colors">
                Clear all
              </button>
            )}
            <span className="text-xs text-gray-400 ml-auto">{filteredViolations.length} of {violations.length} events</span>
          </div>
        )}

        {/* ── Shadow AI events ── */}
        {violations.length > 0 && (
          <div className="animate-fade-up section-card overflow-hidden border-2 border-red-200">
            <div className="px-5 py-3 border-b border-red-100 bg-red-50 flex items-center justify-between">
              <p className="text-xs font-black text-red-700 uppercase tracking-wider">🚨 Shadow AI Violations</p>
              <span className="text-xs bg-red-600 text-white px-2 py-0.5 rounded-full font-bold">{filteredViolations.length} events</span>
            </div>
            {filteredViolations.length === 0 ? (
              <div className="py-10 text-center">
                <p className="text-sm font-bold text-gray-500">No events match this filter</p>
              </div>
            ) : (
            <div className="divide-y divide-gray-50">
              {filteredViolations.map(v => {
                const tool = ALL_TOOLS.find(t => t.id === v.tool);
                const stat = STATUS_STYLE[v.status];
                const open = expanded === v.id;
                return (
                  <div key={v.id}>
                    <div className="flex items-center gap-4 px-5 py-3.5 cursor-pointer hover:bg-gray-50/50 transition-colors"
                      onClick={()=>setExpanded(open?null:v.id)}>
                      <span className="text-xl shrink-0">{tool?.icon ?? "❓"}</span>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="text-sm font-bold text-gray-900">{tool?.label ?? v.tool}</span>
                          <span className="text-xs bg-red-100 text-red-700 px-2 py-0.5 rounded-full font-bold">Not approved</span>
                          <span className="text-xs text-gray-400">{Math.round(v.confidence * 100)}% confidence</span>
                          <span className="text-[10px] font-bold px-2 py-0.5 rounded-full border" style={{ background:stat.bg, color:stat.text, borderColor:stat.border }}>{stat.label}</span>
                          {v.notes.length>0 && <span className="text-[9px] text-gray-400">💬 {v.notes.length}</span>}
                          {v.notified_at && <span className="text-[9px] text-indigo-500 font-semibold">📨 notified {timeAgo(v.notified_at)}</span>}
                        </div>
                        <div className="text-xs text-gray-500 font-mono mt-0.5 truncate">{v.repo} · {v.file}</div>
                        <div className="text-xs text-gray-400 mt-0.5">{v.dev} · {fmtDateTime(v.date)}</div>
                      </div>
                      <svg className="shrink-0 text-gray-300" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"
                        style={{ transform:open?"rotate(180deg)":"none", transition:"transform 0.2s" }}>
                        <polyline points="6 9 12 15 18 9"/>
                      </svg>
                    </div>

                    {open && (
                      <div className="border-t border-gray-100 px-5 py-4 space-y-3" style={{ background:"rgba(248,250,252,0.8)" }}>
                        <div className="flex flex-wrap items-center gap-3">
                          <div>
                            <p className="text-[9px] font-black uppercase tracking-widest text-gray-400 mb-1">Status</p>
                            <select value={v.status} onChange={e=>updateOverride(v.id,{status:e.target.value as DetectionStatus})}
                              className="text-xs border border-gray-200 rounded-lg px-2.5 py-1.5 focus:outline-none focus:ring-2 focus:ring-indigo-400">
                              {(["open","investigating","acceptable","resolved"] as const).map(s=><option key={s} value={s}>{STATUS_STYLE[s].label}</option>)}
                            </select>
                          </div>
                          <button onClick={()=>notify(v.id)}
                            className="text-xs font-bold text-indigo-700 bg-indigo-50 border border-indigo-200 px-3 py-1.5 rounded-lg hover:bg-indigo-100 transition-colors self-end">
                            {v.notified_at ? `Re-notify ${v.dev.split("@")[0]}` : `Notify ${v.dev.split("@")[0]}`}
                          </button>
                        </div>
                        <div>
                          <p className="text-[10px] font-black uppercase tracking-widest text-gray-400 mb-2">Notes</p>
                          {v.notes.length>0 && (
                            <div className="space-y-1.5 mb-2">
                              {v.notes.map((n,i)=>(
                                <div key={i} className="text-[11px] text-gray-600 bg-white rounded-lg px-3 py-2 border border-gray-100">{n}</div>
                              ))}
                            </div>
                          )}
                          <div className="flex gap-2">
                            <input value={noteInput[v.id]??""} onChange={e=>setNoteInput(p=>({...p,[v.id]:e.target.value}))}
                              onKeyDown={e=>{if(e.key==="Enter")addNote(v.id);}}
                              placeholder="Add a note (Enter to save)…"
                              className="flex-1 text-xs border border-gray-200 rounded-lg px-3 py-2 focus:outline-none focus:ring-2 focus:ring-indigo-400 bg-white" />
                            <button onClick={()=>addNote(v.id)}
                              className="text-xs font-bold text-indigo-700 bg-indigo-50 border border-indigo-200 px-3 py-2 rounded-lg hover:bg-indigo-100 transition-colors">
                              Save
                            </button>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
            )}
          </div>
        )}

        {/* ── Developer breakdown ── */}
        {Object.keys(devViolations).length > 0 && (
          <div className="animate-fade-up section-card overflow-hidden">
            <div className="px-5 py-3 border-b border-gray-100 bg-gray-50">
              <p className="text-xs font-black text-gray-700 uppercase tracking-wider">Developers Using Unapproved Tools</p>
            </div>
            <div className="p-5 space-y-3">
              {Object.entries(devViolations).sort(([,a],[,b]) => b - a).map(([dev, count]) => (
                <div key={dev} className="flex items-center gap-3">
                  <div className="w-8 h-8 rounded-full bg-rose-100 flex items-center justify-center text-rose-700 font-bold text-sm shrink-0">
                    {dev[0].toUpperCase()}
                  </div>
                  <div className="flex-1">
                    <div className="flex justify-between mb-1">
                      <span className="text-sm font-bold text-gray-900">{dev}</span>
                      <span className="text-xs font-bold text-red-600">{count} event{count > 1 ? "s" : ""}</span>
                    </div>
                    <div className="h-2 bg-gray-100 rounded-full overflow-hidden">
                      <div className="h-full bg-rose-500 rounded-full"
                        style={{ width:`${Math.min(100, count * 20)}%` }} />
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {compliant.length > 0 && (
          <div className="animate-fade-up section-card overflow-hidden">
            <div className="px-5 py-3 border-b border-gray-100 bg-gray-50 flex items-center justify-between">
              <p className="text-xs font-black text-gray-700 uppercase tracking-wider">Compliant AI Usage</p>
              <span className="text-xs bg-green-100 text-green-700 px-2 py-0.5 rounded-full font-bold">{compliant.length} events</span>
            </div>
          </div>
        )}

        {violations.length === 0 && rawDetections.length > 0 && (
          <div className="animate-fade-up bg-green-50 border border-green-200 rounded-2xl p-8 text-center">
            <div className="text-4xl mb-3">✅</div>
            <div className="font-black text-green-800 text-lg mb-2">No Shadow AI Detected</div>
            <div className="text-sm text-green-600">All AI tool usage matches your approved policy. Keep monitoring as team AI tool usage evolves.</div>
          </div>
        )}

        {rawDetections.length === 0 && (
          <div className="animate-fade-up section-card py-14 text-center space-y-1">
            <p className="text-sm font-bold text-gray-600">No AI tool detections yet</p>
            <p className="text-xs text-gray-400">Once scans run for this organization, detected AI coding tools will appear here.</p>
          </div>
        )}

      </div>
    </AuthGuard>
  );
}
