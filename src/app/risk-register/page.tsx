"use client";

/**
 * Risk Register (ISO 31000 style): the risks derived from your latest scans, plus the ones you add, with owners, due
 * dates, treatment and notes.
 *
 * One request (GET /api/risk-register) returns the whole register, derived on the server from the real attestation
 * data, so it matches the PR pages and the merge check; the page used to chain a cached dashboard payload, one scan
 * fetch per repository and a sync call, which was slow and could disagree with what had been attested.
 */
import { useState, useMemo, useEffect, useCallback, useRef } from "react";
import Link from "next/link";
import AuthGuard from "@/components/AuthGuard";
import InfoTooltip from "@/components/InfoTooltip";
import PageSkeleton from "@/components/PageSkeleton";
import { CapNotice, LimitMeter } from "@/components/Limits";
import { api } from "@/lib/api";
import { readSeed } from "@/lib/offlineData";
import { authedFetch, isSeedMode } from "@/lib/useRealData";
import { useAuth } from "@/lib/auth";
import { useRole } from "@/lib/roles";
import { useToastHelpers } from "@/lib/toast";
import { CAPS, limitStatus } from "@/lib/limits";
import { patchDataWithAttestations } from "@/lib/trustScore";
import { deriveRisks, mergeRisks, riskPatchToDb, type PersistedRisk, type RiskCategory, type RiskItem, type RiskStatus, type TreatmentType } from "@/lib/riskRegister";
import { computeInsights, daysUntil, inherent, levelOf, residual, type FocusItem, type RiskLevel } from "@/lib/riskInsights";

interface Basis { repos: number; highCriticalFiles: number; attestedFiles: number; closedWithoutAttestation: number; waitingFiles: number; latestScanAt: string | null }
interface Register {
  risks: RiskItem[];
  basis: Basis | null;
  sync: { inserted: number; updated: number; reopened: number; closed: number } | null;
  syncError: string | null;
  capped: { shown: number; total: number } | null;
  canEdit: boolean;
  generatedAt: string;
}

// ── Look ─────────────────────────────────────────────────────────────────────

const LEVEL: Record<RiskLevel, { bg: string; text: string; border: string }> = {
  CRITICAL: { bg: "#ede9fe", text: "#5b21b6", border: "#c4b5fd" },
  HIGH:     { bg: "#ffedd5", text: "#7c2d12", border: "#fed7aa" },
  MEDIUM:   { bg: "#fef3c7", text: "#78350f", border: "#fde68a" },
  LOW:      { bg: "#f0fdf4", text: "#15803d", border: "#bbf7d0" },
};
const STATUS: Record<RiskStatus, { bg: string; text: string; border: string; label: string }> = {
  open:       { bg: "#fef2f2", text: "#be123c", border: "#fecdd3", label: "Open" },
  mitigating: { bg: "#fffbeb", text: "#b45309", border: "#fde68a", label: "Mitigating" },
  accepted:   { bg: "#f0f9ff", text: "#0369a1", border: "#bae6fd", label: "Accepted" },
  closed:     { bg: "#f0fdf4", text: "#15803d", border: "#bbf7d0", label: "Closed" },
};
const TREATMENT: Record<TreatmentType, string> = { mitigate: "Mitigate", accept: "Accept", transfer: "Transfer", avoid: "Avoid" };
const CATEGORY: Record<RiskCategory, string> = {
  "ai-code": "AI Code", "supply-chain": "Supply Chain", secrets: "Credentials", compliance: "Compliance", access: "Access Control", infrastructure: "Infrastructure",
};
const ownerLabel = (o: string) => (o === "unassigned" ? "Unassigned" : o.split("@")[0]);
const shortRepo = (r: string) => r.split("/").pop() ?? r;

function ago(iso: string | null | undefined, now = Date.now()): string {
  if (!iso) return "never";
  const s = Math.max(0, Math.floor((now - new Date(iso).getTime()) / 1000));
  return s < 10 ? "just now" : s < 60 ? `${s}s ago` : s < 3600 ? `${Math.floor(s / 60)}m ago` : s < 86400 ? `${Math.floor(s / 3600)}h ago` : `${Math.floor(s / 86400)}d ago`;
}
const plural = (n: number, one: string, many = `${one}s`) => `${n.toLocaleString("en-US")} ${n === 1 ? one : many}`;
/** A CSV cell: quoted, quotes doubled, and a leading = + - @ neutralised so a spreadsheet can't run it as a formula. */
const csvCell = (v: unknown) => { const s = String(v ?? ""); return `"${(/^[=+\-@\t\r]/.test(s) ? `'${s}` : s).replace(/"/g, '""')}"`; };

// ── Pieces ───────────────────────────────────────────────────────────────────

function Tile({ label, value, sub, tone, info }: { label: string; value: string | number; sub?: string; tone: string; info: { title: string; description: string; formula?: string } }) {
  return (
    <div className="rounded-2xl border p-4" style={{ background: tone + "10", borderColor: tone + "30" }}>
      <p className="text-2xl font-black tabular-nums" style={{ color: tone }}>{value}</p>
      <div className="mt-1 flex items-center gap-1.5">
        <p className="text-xs font-semibold text-gray-600">{label}</p>
        <InfoTooltip title={info.title} description={info.description} formula={info.formula} position="top" />
      </div>
      {sub && <p className="mt-0.5 text-[11px] text-gray-500">{sub}</p>}
    </div>
  );
}

function HeatMap({ risks, selected, onPick }: { risks: RiskItem[]; selected: [number, number] | null; onPick: (l: number, i: number) => void }) {
  return (
    <div className="space-y-2">
      <div className="flex items-center gap-1">
        <div className="flex h-full shrink-0 flex-col items-center justify-between">
          {[5, 4, 3, 2, 1].map(l => <span key={l} className="w-4 py-1 text-right text-[8px] font-bold leading-none text-gray-400">{l}</span>)}
        </div>
        <div className="flex-1 space-y-1">
          <div className="grid grid-cols-5 gap-1">
            {[5, 4, 3, 2, 1].flatMap(l => [1, 2, 3, 4, 5].map(i => {
              const n = risks.filter(r => r.status !== "closed" && r.likelihood === l && r.impact === i).length;
              const c = LEVEL[levelOf(l * i)];
              const on = selected?.[0] === l && selected?.[1] === i;
              return (
                <button key={`${l}-${i}`} disabled={n === 0} onClick={() => onPick(l, i)} aria-pressed={on}
                  aria-label={`Likelihood ${l}, impact ${i}: ${n} active risk${n === 1 ? "" : "s"}`}
                  className={`flex aspect-square items-center justify-center rounded-lg text-[11px] font-black transition-all ${n ? "hover:scale-105" : "cursor-default"} ${on ? "ring-2 ring-indigo-500 ring-offset-1" : ""}`}
                  style={{ background: n ? c.bg : "#f1f5f9", color: n ? c.text : "#94a3b8" }}>
                  {n || ""}
                </button>
              );
            }))}
          </div>
          <div className="grid grid-cols-5 gap-1">
            {[1, 2, 3, 4, 5].map(i => <span key={i} className="text-center text-[8px] font-bold text-gray-400">{i}</span>)}
          </div>
        </div>
      </div>
      <p className="pl-5 text-[9px] text-gray-400">Impact → across, Likelihood ↑ up. Click a cell to filter the list.</p>
    </div>
  );
}

function ExposureBars({ title, rows, label, onPick }: { title: string; rows: Array<{ key: string; active: number; critical: number; score: number }>; label: (k: string) => string; onPick: (k: string) => void }) {
  const max = Math.max(1, ...rows.map(r => r.score));
  return (
    <div>
      <p className="mb-2 text-[10px] font-black uppercase tracking-widest text-gray-400">{title}</p>
      {rows.length === 0 ? <p className="text-xs text-gray-400">Nothing active.</p> : (
        <ul className="space-y-1.5">
          {rows.map(r => (
            <li key={r.key}>
              <button onClick={() => onPick(r.key)} className="group w-full text-left" title={`Filter to ${label(r.key)}`}>
                <div className="flex items-baseline justify-between gap-2 text-xs">
                  <span className="truncate font-semibold text-gray-700 group-hover:text-indigo-700">{label(r.key)}</span>
                  <span className="shrink-0 tabular-nums text-gray-500">{plural(r.active, "risk")}{r.critical > 0 && <span className="font-bold text-violet-700"> · {r.critical} critical</span>}</span>
                </div>
                <div className="mt-0.5 h-1.5 overflow-hidden rounded-full bg-gray-100"><div className="h-full rounded-full bg-indigo-500" style={{ width: `${Math.max(4, (r.score / max) * 100)}%` }} /></div>
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function FocusList({ items, onOpen }: { items: FocusItem[]; onOpen: (id: string) => void }) {
  return (
    <section aria-label="Act on first" className="section-card p-5">
      <div className="mb-3 flex items-center gap-2">
        <h2 className="text-sm font-black text-gray-900">Act on first</h2>
        <InfoTooltip title="Act on first" description="Active risks ranked by what is late, how severe they are and whether anyone owns them. Overdue risks lead, then critical and high ones, then those due within a week." position="right" size="sm" />
      </div>
      {items.length === 0 ? <p className="text-sm text-gray-500">Nothing urgent: no overdue, critical or unowned risks.</p> : (
        <ol className="space-y-2">
          {items.map(f => {
            const c = LEVEL[f.level];
            return (
              <li key={f.id}>
                <button onClick={() => onOpen(f.id)} className="flex w-full items-start gap-3 rounded-xl border border-gray-100 p-3 text-left transition-colors hover:bg-gray-50">
                  <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg border text-sm font-black" style={{ background: c.bg, color: c.text, borderColor: c.border }}>{f.score}</span>
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-sm font-bold text-gray-900">{f.title}</span>
                    <span className="mt-0.5 flex flex-wrap gap-1.5">
                      {f.reasons.map(r => <span key={r} className={`rounded-full px-2 py-0.5 text-[10px] font-bold ${r.startsWith("Overdue") ? "bg-rose-50 text-rose-700" : r === "Nobody owns it" ? "bg-amber-50 text-amber-700" : "bg-gray-100 text-gray-600"}`}>{r}</span>)}
                    </span>
                  </span>
                </button>
              </li>
            );
          })}
        </ol>
      )}
    </section>
  );
}

interface NewRisk { title: string; description: string; category: RiskCategory; likelihood: number; impact: number; owner: string; due_date: string; mitigation: string; treatment: TreatmentType; related_cve: string }
const BLANK: NewRisk = { title: "", description: "", category: "ai-code", likelihood: 3, impact: 3, owner: "unassigned", due_date: "", mitigation: "", treatment: "mitigate", related_cve: "" };

// ── Page ─────────────────────────────────────────────────────────────────────

type StatusFilter = "active" | RiskStatus | "all";

export default function RiskRegisterPage() {
  const { profile } = useAuth();
  const { permissions } = useRole();
  const { error: toastError } = useToastHelpers();
  const orgId = profile?.org_id;

  const [reg, setReg] = useState<Register | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [owners, setOwners] = useState<string[]>([]);
  const [status, setStatus] = useState<StatusFilter>("active");
  const [category, setCategory] = useState<RiskCategory | "all">("all");
  const [owner, setOwner] = useState("all");
  const [repo, setRepo] = useState("all");
  const [cell, setCell] = useState<[number, number] | null>(null);
  const [search, setSearch] = useState("");
  const [sortBy, setSortBy] = useState<"score" | "due">("score");
  const [expanded, setExpanded] = useState<string | null>(null);
  const [showAdd, setShowAdd] = useState(false);
  const [newRisk, setNewRisk] = useState<NewRisk>(BLANK);
  const [noteInput, setNoteInput] = useState<Record<string, string>>({});
  const loadedAt = useRef(0);
  const listRef = useRef<HTMLDivElement>(null);

  const load = useCallback(async (spinner = false) => {
    if (spinner) setRefreshing(true);
    try {
      if (isSeedMode() && !orgId) {
        const seed = readSeed();
        const derived = seed ? deriveRisks(patchDataWithAttestations(seed), []) : [];
        setReg(prev => ({ risks: mergeRisks(derived, { overrides: {}, manuals: prev?.risks.filter(r => !r.auto_derived).map(r => ({ ...r, _manual: true as const })) ?? [] }), basis: null, sync: null, syncError: null, capped: null, canEdit: true, generatedAt: new Date().toISOString() }));
        setLoadError(null);
      } else if (orgId) {
        setReg(await authedFetch<Register>("/api/risk-register"));
        setLoadError(null);
      } else return;
      loadedAt.current = Date.now();
    } catch (e) {
      setLoadError(e instanceof Error ? e.message : "We couldn't load the risk register.");
    } finally {
      setLoading(false);
      if (spinner) setRefreshing(false);
    }
  }, [orgId]);

  useEffect(() => { void load(); }, [load]);
  useEffect(() => {
    const onFocus = () => { if (Date.now() - loadedAt.current > 60_000) void load(); };   // not on every focus: the register is already live
    window.addEventListener("focus", onFocus);
    return () => window.removeEventListener("focus", onFocus);
  }, [load]);
  useEffect(() => {
    let live = true;
    api.settings().then(s => { if (live) setOwners((s?.members ?? []).map(m => m.email).filter(Boolean)); }).catch(() => undefined);
    return () => { live = false; };
  }, []);

  const risks = useMemo(() => reg?.risks ?? [], [reg]);
  const canEdit = reg ? reg.canEdit : permissions.canTriage;
  const ins = useMemo(() => computeInsights(risks), [risks]);
  const ownerChoices = useMemo(() => [...new Set(["unassigned", ...owners, ...risks.map(r => r.owner)])], [owners, risks]);
  const repos = useMemo(() => [...new Set(risks.map(r => r.repo).filter((r): r is string => !!r))].sort(), [risks]);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    const list = risks.filter(r =>
      (status === "all" || (status === "active" ? r.status !== "closed" : r.status === status))
      && (category === "all" || r.category === category)
      && (owner === "all" || r.owner === owner)
      && (repo === "all" || r.repo === repo)
      && (!cell || (r.likelihood === cell[0] && r.impact === cell[1]))
      && (!q || [r.title, r.description, r.id, r.related_cve ?? "", r.related_cwe ?? "", r.repo ?? ""].join(" ").toLowerCase().includes(q)));
    const now = new Date();
    return list.sort((a, b) => {
      if (sortBy === "due") {
        const da = daysUntil(a.due_date, now), db = daysUntil(b.due_date, now);
        if (da == null && db == null) return inherent(b) - inherent(a);
        if (da == null) return 1;
        if (db == null) return -1;
        return da - db;
      }
      return inherent(b) - inherent(a) || a.id.localeCompare(b.id);
    });
  }, [risks, status, category, owner, repo, cell, search, sortBy]);

  const filtersOn = status !== "active" || category !== "all" || owner !== "all" || repo !== "all" || cell != null || search !== "";
  const clearFilters = () => { setStatus("active"); setCategory("all"); setOwner("all"); setRepo("all"); setCell(null); setSearch(""); };

  /** Change a risk: shown at once, saved, and put back with a message if it can't be saved. */
  async function edit(id: string, patch: Partial<PersistedRisk>) {
    const before = reg;
    setReg(r => (r ? { ...r, risks: r.risks.map(x => (x.id === id ? { ...x, ...(patch as Partial<RiskItem>) } : x)) } : r));
    if (isSeedMode() && !orgId) return;
    try {
      await authedFetch("/api/risk-register/state", { method: "PATCH", body: JSON.stringify({ external_id: id, patch: riskPatchToDb(patch) }) });
    } catch (err) {
      setReg(before);
      toastError("Couldn't update risk", err instanceof Error ? err.message : undefined);
    }
  }

  function addNote(r: RiskItem) {
    const text = noteInput[r.id]?.trim();
    if (!text) return;
    const date = new Date().toLocaleDateString("en-GB", { day: "2-digit", month: "short", year: "numeric" });
    void edit(r.id, { notes: [...r.notes, `${date}: ${text}`] });
    setNoteInput(p => ({ ...p, [r.id]: "" }));
  }

  async function addManual() {
    if (!newRisk.title.trim()) return;
    const id = `MR-${Date.now()}`;
    const item: RiskItem = {
      id, auto_derived: false, title: newRisk.title.trim(), description: newRisk.description.trim(), category: newRisk.category,
      likelihood: newRisk.likelihood as RiskItem["likelihood"], impact: newRisk.impact as RiskItem["impact"], status: "open", treatment: newRisk.treatment,
      owner: newRisk.owner, due_date: newRisk.due_date || undefined, mitigation: newRisk.mitigation.trim(), related_cve: newRisk.related_cve.trim() || undefined,
      identified_at: new Date().toISOString().split("T")[0], notes: [],
    };
    if (!(isSeedMode() && !orgId)) {
      try {
        await authedFetch("/api/risk-register/state", { method: "POST", body: JSON.stringify({
          external_id: id, title: item.title, description: item.description, category: item.category, likelihood: item.likelihood, impact: item.impact,
          treatment: item.treatment, owner_email: item.owner === "unassigned" ? undefined : item.owner, due_date: item.due_date, mitigation: item.mitigation, related_cve: item.related_cve,
        }) });
      } catch (err) { toastError("Couldn't add risk", err instanceof Error ? err.message : undefined); return; }
    }
    setReg(r => (r ? { ...r, risks: [item, ...r.risks] } : r));
    setNewRisk(BLANK); setShowAdd(false);
  }

  async function deleteManual(id: string) {
    const before = reg;
    setReg(r => (r ? { ...r, risks: r.risks.filter(x => x.id !== id) } : r));
    if (isSeedMode() && !orgId) return;
    try { await authedFetch("/api/risk-register/state", { method: "DELETE", body: JSON.stringify({ external_id: id }) }); }
    catch (err) { setReg(before); toastError("Couldn't remove risk", err instanceof Error ? err.message : undefined); }
  }

  function openRisk(id: string) {
    setStatus("all"); setExpanded(id);
    setTimeout(() => document.getElementById(`risk-${id}`)?.scrollIntoView?.({ behavior: "smooth", block: "center" }), 50);
  }

  function exportCSV() {
    const head = ["ID", "Title", "Repository", "Category", "Likelihood", "Impact", "Score", "Level", "Residual score", "Status", "Treatment", "Owner", "Due", "CVE", "CWE", "Identified", "Source"];
    const rows = filtered.map(r => [r.id, r.title, r.repo ?? "", CATEGORY[r.category] ?? r.category, r.likelihood, r.impact, inherent(r), levelOf(inherent(r)), residual(r) ?? "", r.status, r.treatment, r.owner, r.due_date ?? "", r.related_cve ?? "", r.related_cwe ?? "", r.identified_at, r.auto_derived ? "Derived from scans" : "Added manually"]);
    const blob = new Blob([[head, ...rows].map(r => r.map(csvCell).join(",")).join("\n")], { type: "text/csv" });
    Object.assign(document.createElement("a"), { href: URL.createObjectURL(blob), download: "risk-register.csv" }).click();
  }

  const basis = reg?.basis;
  const meter = limitStatus(risks.length, CAPS.riskRegisterSync.value);
  const sync = reg?.sync;
  const syncParts = sync ? [sync.inserted && `${sync.inserted} new`, sync.closed && `${sync.closed} closed because their files are now attested or fixed`, sync.reopened && `${sync.reopened} reopened`].filter(Boolean) : [];

  return (
    <AuthGuard>
      <PageSkeleton loading={loading} label="risks" rows={5} cards={4}>
        <div className="mx-auto max-w-7xl space-y-5 pb-10">

          {/* Header */}
          <div className="animate-fade-up flex flex-wrap items-start justify-between gap-4">
            <div>
              <div className="mb-1 flex items-center gap-2.5">
                <h1 className="text-xl font-black tracking-tight text-gray-900">Risk Register</h1>
                {ins.open > 0 && <span className="rounded-full bg-rose-500 px-2 py-0.5 text-xs font-black text-white">{ins.open} open</span>}
              </div>
              <p className="text-sm text-gray-400">ISO 31000 risk log. Derived from your latest scans and attestations, plus risks you add.</p>
            </div>
            <div className="flex items-center gap-2">
              {canEdit && (
                <button onClick={() => setShowAdd(v => !v)} aria-expanded={showAdd}
                  className={`rounded-xl border px-3 py-2 text-xs font-bold shadow-sm transition-all ${showAdd ? "border-indigo-300 bg-indigo-100 text-indigo-800" : "border-indigo-200 bg-indigo-50 text-indigo-700 hover:bg-indigo-100"}`}>+ Add Risk</button>
              )}
              <button onClick={exportCSV} className="rounded-xl border border-gray-200 bg-white px-3 py-2 text-xs font-semibold text-gray-600 shadow-sm hover:bg-gray-50">Export</button>
              <button onClick={() => void load(true)} disabled={refreshing} className="rounded-xl border border-gray-200 bg-white px-3 py-2 text-xs font-semibold text-gray-600 shadow-sm hover:bg-gray-50 disabled:opacity-50">
                {refreshing ? "Refreshing…" : "Refresh"}
              </button>
            </div>
          </div>

          {/* Where this comes from: so the register can be checked against the attestation data */}
          {loadError && (
            <div role="alert" className="flex items-center gap-3 rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-800">
              <span className="flex-1">{loadError}{reg ? " Showing the last loaded register." : ""}</span>
              <button onClick={() => void load(true)} className="font-bold underline">Try again</button>
            </div>
          )}
          {basis && (
            <div className="animate-fade-up rounded-xl border border-gray-200 bg-white px-4 py-3 text-xs leading-relaxed text-gray-600" data-testid="register-basis">
              <p>
                <strong className="text-gray-800">Live from your scans.</strong> {plural(basis.repos, "repository", "repositories")}, latest scan {ago(basis.latestScanAt)}.{" "}
                Of {plural(basis.highCriticalFiles, "high/critical file")}: <strong>{basis.attestedFiles} attested</strong>
                {basis.closedWithoutAttestation > 0 && <>, {basis.closedWithoutAttestation} closed without a sign-off</>}, <strong>{basis.waitingFiles} waiting</strong>.{" "}
                Attesting a file closes its risk the next time this page loads.
              </p>
              {syncParts.length > 0 && <p className="mt-1 text-gray-500">Register updated: {syncParts.join(", ")}.</p>}
            </div>
          )}
          {reg?.syncError && <div role="status" className="rounded-xl border border-amber-200 bg-amber-50 px-4 py-2.5 text-xs text-amber-900">{reg.syncError}</div>}
          {reg && !reg.canEdit && <div role="status" className="rounded-xl border border-gray-200 bg-gray-50 px-4 py-2.5 text-xs text-gray-600">You can view the register. Changing risks needs the security reviewer role or above.</div>}
          {reg?.capped && <CapNotice cap="riskRegisterSync" shown={reg.capped.shown} total={reg.capped.total} noun="risks" />}
          {meter.level !== "ok" && meter.level !== "unlimited" && !reg?.capped && (
            <div className="rounded-xl border border-gray-200 bg-white px-4 py-3"><LimitMeter label="Risks in the register" noun="risks" used={risks.length} limit={CAPS.riskRegisterSync.value} upgradeHref={null} compact /></div>
          )}

          {/* Add risk */}
          {showAdd && canEdit && (
            <div className="animate-fade-up section-card space-y-4 p-5">
              <p className="text-sm font-bold text-gray-900">Add Manual Risk</p>
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <label className="sm:col-span-2 text-[10px] font-semibold text-gray-500">Title *
                  <input value={newRisk.title} onChange={e => setNewRisk(p => ({ ...p, title: e.target.value }))} placeholder="Brief risk title" className="mt-1 w-full rounded-lg border border-gray-200 px-3 py-2 text-sm text-gray-700 focus:outline-none focus:ring-2 focus:ring-indigo-400" /></label>
                <label className="sm:col-span-2 text-[10px] font-semibold text-gray-500">Description
                  <textarea value={newRisk.description} onChange={e => setNewRisk(p => ({ ...p, description: e.target.value }))} rows={2} className="mt-1 w-full resize-none rounded-lg border border-gray-200 px-3 py-2 text-xs text-gray-700 focus:outline-none focus:ring-2 focus:ring-indigo-400" /></label>
                <label className="text-[10px] font-semibold text-gray-500">Category
                  <select value={newRisk.category} onChange={e => setNewRisk(p => ({ ...p, category: e.target.value as RiskCategory }))} className="mt-1 w-full rounded-lg border border-gray-200 px-3 py-2 text-xs text-gray-700">
                    {(Object.keys(CATEGORY) as RiskCategory[]).map(c => <option key={c} value={c}>{CATEGORY[c]}</option>)}</select></label>
                <label className="text-[10px] font-semibold text-gray-500">Treatment (ISO 31000)
                  <select value={newRisk.treatment} onChange={e => setNewRisk(p => ({ ...p, treatment: e.target.value as TreatmentType }))} className="mt-1 w-full rounded-lg border border-gray-200 px-3 py-2 text-xs text-gray-700">
                    {(Object.keys(TREATMENT) as TreatmentType[]).map(t => <option key={t} value={t}>{TREATMENT[t]}</option>)}</select></label>
                <label className="text-[10px] font-semibold text-gray-500">Owner
                  <select value={newRisk.owner} onChange={e => setNewRisk(p => ({ ...p, owner: e.target.value }))} className="mt-1 w-full rounded-lg border border-gray-200 px-3 py-2 text-xs text-gray-700">
                    {ownerChoices.map(o => <option key={o} value={o}>{ownerLabel(o)}</option>)}</select></label>
                <label className="text-[10px] font-semibold text-gray-500">Due date
                  <input type="date" value={newRisk.due_date} onChange={e => setNewRisk(p => ({ ...p, due_date: e.target.value }))} className="mt-1 w-full rounded-lg border border-gray-200 px-3 py-2 text-xs text-gray-700" /></label>
                <label className="text-[10px] font-semibold text-gray-500">Likelihood (1–5)
                  <input type="range" min={1} max={5} value={newRisk.likelihood} onChange={e => setNewRisk(p => ({ ...p, likelihood: Number(e.target.value) }))} className="w-full" />
                  <span className="flex justify-between text-[9px] text-gray-400"><span>Rare</span><span className="font-bold text-gray-700">{newRisk.likelihood}</span><span>Certain</span></span></label>
                <label className="text-[10px] font-semibold text-gray-500">Impact (1–5)
                  <input type="range" min={1} max={5} value={newRisk.impact} onChange={e => setNewRisk(p => ({ ...p, impact: Number(e.target.value) }))} className="w-full" />
                  <span className="flex justify-between text-[9px] text-gray-400"><span>Minor</span><span className="font-bold text-gray-700">{newRisk.impact}</span><span>Critical</span></span></label>
                <label className="sm:col-span-2 text-[10px] font-semibold text-gray-500">Mitigation plan
                  <textarea value={newRisk.mitigation} onChange={e => setNewRisk(p => ({ ...p, mitigation: e.target.value }))} rows={2} placeholder="The plan, or why the risk is accepted" className="mt-1 w-full resize-none rounded-lg border border-gray-200 px-3 py-2 text-xs text-gray-700 focus:outline-none focus:ring-2 focus:ring-indigo-400" /></label>
                <label className="text-[10px] font-semibold text-gray-500">Related CVE (optional)
                  <input value={newRisk.related_cve} onChange={e => setNewRisk(p => ({ ...p, related_cve: e.target.value }))} placeholder="CVE-2023-XXXXX" className="mt-1 w-full rounded-lg border border-gray-200 px-3 py-2 text-xs text-gray-700" /></label>
              </div>
              <div className="flex items-center gap-2">
                <span className="rounded-lg border border-gray-200 bg-gray-50 px-3 py-1.5 text-xs text-gray-500">Score: <strong style={{ color: LEVEL[levelOf(newRisk.likelihood * newRisk.impact)].text }}>{newRisk.likelihood * newRisk.impact} · {levelOf(newRisk.likelihood * newRisk.impact)}</strong></span>
                <button onClick={() => void addManual()} disabled={!newRisk.title.trim()} className="rounded-xl bg-indigo-600 px-4 py-2 text-sm font-bold text-white disabled:opacity-40">Add to Register</button>
                <button onClick={() => { setShowAdd(false); setNewRisk(BLANK); }} className="px-4 py-2 text-sm font-semibold text-gray-500 hover:text-gray-700">Cancel</button>
              </div>
            </div>
          )}

          {/* Numbers that matter */}
          <div className="animate-fade-up grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6" role="region" aria-label="Register summary">
            <Tile label="Open Risks" value={ins.open} sub={ins.mitigating ? `${ins.mitigating} mitigating` : undefined} tone="#ef4444" info={{ title: "Open Risks", description: "Risks identified but not yet being mitigated, accepted or closed. This is the action list." }} />
            <Tile label="Critical" value={ins.critical} sub={ins.high ? `${ins.high} high` : undefined} tone="#7c3aed" info={{ title: "Critical risks", description: "Active risks scoring 20 or more (Likelihood × Impact). High is 12 to 19.", formula: "Score = Likelihood × Impact" }} />
            <Tile label="Overdue" value={ins.overdue} sub={ins.dueSoon ? `${ins.dueSoon} due within 7 days` : undefined} tone="#be123c" info={{ title: "Overdue", description: "Active risks whose due date has passed. Each needs its owner to act, or the due date to be moved on purpose." }} />
            <Tile label="Unassigned" value={ins.unassigned} sub={ins.highWithoutDueDate ? `${ins.highWithoutDueDate} high+ with no due date` : undefined} tone="#d97706" info={{ title: "Unassigned", description: "Active risks nobody owns. Derived risks start unassigned: owners and due dates are decisions, never guessed." }} />
            <Tile label="Avg inherent" value={ins.avgInherent ?? "—"} sub={ins.avgAgeDays != null ? `avg age ${Math.round(ins.avgAgeDays)}d` : undefined} tone="#f97316" info={{ title: "Average inherent risk", description: "Average score before controls, across active risks.", formula: "sum(Likelihood × Impact) ÷ active risks" }} />
            <Tile label="Avg residual" value={ins.avgResidual ?? "—"} sub={ins.reductionPct != null ? `${ins.reductionPct}% lower than inherent` : "none recorded"} tone="#10b981" info={{ title: "Average residual risk", description: "Average score after controls, over active risks that have a residual score recorded. Set it on a risk once its mitigation is in place." }} />
          </div>
          {ins.acceptedUnexplained > 0 && (
            <p className="text-xs text-amber-800" role="note">⚠ {plural(ins.acceptedUnexplained, "accepted risk")} {ins.acceptedUnexplained === 1 ? "has" : "have"} no note saying why. Accepting a risk should leave a reason.</p>
          )}

          {/* What to do, and where the exposure is */}
          <div className="animate-fade-up grid grid-cols-1 gap-5 lg:grid-cols-[1.4fr_1fr]">
            <FocusList items={ins.focus} onOpen={openRisk} />
            <div className="section-card space-y-5 p-5">
              <div>
                <div className="mb-2 flex items-center gap-1.5">
                  <p className="text-[10px] font-black uppercase tracking-widest text-gray-400">Risk Heat Map</p>
                  <InfoTooltip title="Risk Heat Map" description="Each cell counts the active risks at that Likelihood × Impact. Click one to filter the list. Green is low, amber medium, orange high, violet critical." formula={"LOW < 6 · MEDIUM 6–11\nHIGH 12–19 · CRITICAL ≥ 20"} position="right" size="sm" />
                </div>
                <HeatMap risks={risks} selected={cell} onPick={(l, i) => { setCell(c => (c?.[0] === l && c?.[1] === i ? null : [l, i])); listRef.current?.scrollIntoView?.({ behavior: "smooth", block: "start" }); }} />
              </div>
            </div>
          </div>
          <div className="animate-fade-up section-card grid grid-cols-1 gap-6 p-5 md:grid-cols-2">
            <ExposureBars title="Exposure by repository" rows={ins.byRepo} label={shortRepo} onPick={k => setRepo(k)} />
            <ExposureBars title="Exposure by category" rows={ins.byCategory} label={k => CATEGORY[k as RiskCategory] ?? k} onPick={k => setCategory(k as RiskCategory)} />
          </div>

          {/* Filters */}
          <div ref={listRef} className="animate-fade-up flex flex-wrap items-center gap-2" role="search" aria-label="Filters">
            <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search risks, repos, CVEs…" aria-label="Search risks" className="w-52 rounded-xl border border-gray-200 bg-white px-3 py-2 text-xs text-gray-700 outline-none" />
            <div className="flex items-center gap-0.5 rounded-xl bg-gray-100 p-0.5">
              {(["active", "open", "mitigating", "accepted", "closed", "all"] as const).map(s => {
                const n = s === "all" ? risks.length : s === "active" ? ins.active : risks.filter(r => r.status === s).length;
                return (
                  <button key={s} onClick={() => setStatus(s)} aria-pressed={status === s}
                    className={`flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-semibold ${status === s ? "bg-white text-gray-900 shadow-sm" : "text-gray-500 hover:text-gray-700"}`}>
                    {s === "all" ? "All" : s === "active" ? "Active" : STATUS[s].label}
                    <span className="rounded-full bg-gray-200/80 px-1 py-0.5 text-[9px] font-black text-gray-600">{n}</span>
                  </button>
                );
              })}
            </div>
            <select value={category} onChange={e => setCategory(e.target.value as RiskCategory | "all")} aria-label="Category" className="rounded-xl border border-gray-200 bg-white px-3 py-2 text-xs font-semibold text-gray-600">
              <option value="all">All categories</option>{(Object.keys(CATEGORY) as RiskCategory[]).map(c => <option key={c} value={c}>{CATEGORY[c]}</option>)}
            </select>
            <select value={owner} onChange={e => setOwner(e.target.value)} aria-label="Owner" className="rounded-xl border border-gray-200 bg-white px-3 py-2 text-xs font-semibold text-gray-600">
              <option value="all">All owners</option>{ownerChoices.map(o => <option key={o} value={o}>{ownerLabel(o)}</option>)}
            </select>
            {repos.length > 1 && (
              <select value={repo} onChange={e => setRepo(e.target.value)} aria-label="Repository" className="rounded-xl border border-gray-200 bg-white px-3 py-2 text-xs font-semibold text-gray-600">
                <option value="all">All repositories</option>{repos.map(r => <option key={r} value={r}>{shortRepo(r)}</option>)}
              </select>
            )}
            <select value={sortBy} onChange={e => setSortBy(e.target.value as "score" | "due")} aria-label="Sort" className="rounded-xl border border-gray-200 bg-white px-3 py-2 text-xs font-semibold text-gray-600">
              <option value="score">Sort: risk score</option><option value="due">Sort: due date</option>
            </select>
            {filtersOn && <button onClick={clearFilters} className="rounded-lg px-2 py-1 text-xs font-bold text-rose-600 hover:bg-rose-50">Clear filters</button>}
            <span className="ml-auto text-xs text-gray-400">{plural(filtered.length, "risk")}{cell ? ` at L${cell[0]} × I${cell[1]}` : ""}</span>
          </div>

          {/* Risks */}
          <div className="animate-fade-up space-y-2.5">
            {filtered.length === 0 ? (
              <div className="section-card py-14 text-center">
                <p className="text-sm font-bold text-gray-600">No risks match this filter</p>
                {risks.length === 0 && basis && <p className="mt-1 text-xs text-gray-400">Every high/critical file is attested and no risk patterns were found. Nothing to track.</p>}
              </div>
            ) : filtered.map(r => {
              const score = inherent(r), lv = levelOf(score), c = LEVEL[lv], res = residual(r), st = STATUS[r.status] ?? STATUS.open;
              const open = expanded === r.id;
              const d = daysUntil(r.due_date, new Date());
              return (
                <div key={r.id} id={`risk-${r.id}`} className="section-card overflow-hidden border-l-4" style={{ borderLeftColor: c.text, opacity: r.status === "closed" ? 0.75 : 1 }}>
                  <button className="flex w-full items-start gap-4 px-5 py-4 text-left" aria-expanded={open} onClick={() => setExpanded(open ? null : r.id)}>
                    <span className="flex shrink-0 flex-col items-center gap-1">
                      <span className="flex h-12 w-12 items-center justify-center rounded-xl border text-lg font-black" style={{ background: c.bg, color: c.text, borderColor: c.border }}>{score}</span>
                      <span className="text-[8px] font-black uppercase tracking-wider" style={{ color: c.text }}>{lv}</span>
                      {res != null && <span className="text-[9px] font-bold text-emerald-700">→ {res}</span>}
                    </span>
                    <span className="min-w-0 flex-1">
                      <span className="mb-1 flex flex-wrap items-center gap-2">
                        <span className="rounded bg-gray-100 px-2 py-0.5 font-mono text-[10px] font-black text-gray-400">{r.id}</span>
                        <span className="rounded-full border px-2 py-0.5 text-[10px] font-bold" style={{ background: st.bg, color: st.text, borderColor: st.border }}>{st.label}</span>
                        <span className="rounded border border-gray-200 bg-gray-50 px-2 py-0.5 text-[10px] font-semibold text-gray-500">{CATEGORY[r.category] ?? r.category}</span>
                        {r.auto_derived && <span className="rounded border border-indigo-100 bg-indigo-50 px-1.5 py-0.5 text-[8px] font-bold text-indigo-600">AUTO</span>}
                        {r.notes.length > 0 && <span className="text-[10px] text-gray-400">💬 {r.notes.length}</span>}
                      </span>
                      <span className="block text-sm font-bold text-gray-900">{r.title}</span>
                      {!open && <span className="mt-0.5 block truncate text-xs text-gray-500">{r.description}</span>}
                      <span className="mt-1.5 flex flex-wrap items-center gap-3 text-[10px] text-gray-500">
                        <span>{ownerLabel(r.owner)}</span>
                        {r.repo && <span className="font-mono">{shortRepo(r.repo)}</span>}
                        {d != null && r.status !== "closed" && <span className={`font-bold ${d < 0 ? "text-rose-600" : d <= 3 ? "text-orange-600" : "text-gray-400"}`}>{d < 0 ? `${-d}d overdue` : d === 0 ? "Due today" : `Due in ${d}d`}</span>}
                        {r.related_cwe && <span className="font-mono text-violet-600">{r.related_cwe.split(" — ")[0]}</span>}
                        <span className="text-gray-400">L{r.likelihood} × I{r.impact}</span>
                      </span>
                    </span>
                    <span aria-hidden className="shrink-0 text-gray-300">{open ? "▲" : "▼"}</span>
                  </button>

                  {open && (
                    <div className="space-y-4 border-t border-gray-100 bg-slate-50/80 px-5 py-5">
                      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                        <div><p className="mb-1.5 text-[10px] font-black uppercase tracking-widest text-gray-400">Description</p><p className="text-xs leading-relaxed text-gray-600">{r.description || "—"}</p></div>
                        <div><p className="mb-1.5 text-[10px] font-black uppercase tracking-widest text-gray-400">Mitigation plan</p><p className="text-xs leading-relaxed text-gray-600">{r.mitigation || "—"}</p></div>
                      </div>
                      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
                        {([
                          ["Status", <select key="s" aria-label="Status" value={r.status} disabled={!canEdit} onChange={e => void edit(r.id, { status: e.target.value as RiskStatus })} className="w-full rounded-lg border border-gray-200 px-2.5 py-1.5 text-xs disabled:opacity-60">{(Object.keys(STATUS) as RiskStatus[]).map(s => <option key={s} value={s}>{STATUS[s].label}</option>)}</select>],
                          ["Treatment", <select key="t" aria-label="Treatment" value={r.treatment} disabled={!canEdit} onChange={e => void edit(r.id, { treatment: e.target.value as TreatmentType })} className="w-full rounded-lg border border-gray-200 px-2.5 py-1.5 text-xs disabled:opacity-60">{(Object.keys(TREATMENT) as TreatmentType[]).map(t => <option key={t} value={t}>{TREATMENT[t]}</option>)}</select>],
                          ["Owner", <select key="o" aria-label="Owner" value={r.owner} disabled={!canEdit} onChange={e => void edit(r.id, { owner: e.target.value })} className="w-full rounded-lg border border-gray-200 px-2.5 py-1.5 text-xs disabled:opacity-60">{ownerChoices.map(o => <option key={o} value={o}>{ownerLabel(o)}</option>)}</select>],
                          ["Due date", <input key="d" aria-label="Due date" type="date" value={r.due_date ?? ""} disabled={!canEdit} onChange={e => void edit(r.id, { due_date: e.target.value })} className="w-full rounded-lg border border-gray-200 px-2.5 py-1.5 text-xs disabled:opacity-60" />],
                          ["Residual likelihood", <input key="rl" aria-label="Residual likelihood" type="number" min={1} max={5} value={r.residual_likelihood ?? ""} disabled={!canEdit} placeholder="1–5" onChange={e => { const v = Number(e.target.value); if (v >= 1 && v <= 5) void edit(r.id, { residual_likelihood: v as 1 | 2 | 3 | 4 | 5 }); }} className="w-full rounded-lg border border-gray-200 px-2.5 py-1.5 text-xs disabled:opacity-60" />],
                          ["Residual impact", <input key="ri" aria-label="Residual impact" type="number" min={1} max={5} value={r.residual_impact ?? ""} disabled={!canEdit} placeholder="1–5" onChange={e => { const v = Number(e.target.value); if (v >= 1 && v <= 5) void edit(r.id, { residual_impact: v as 1 | 2 | 3 | 4 | 5 }); }} className="w-full rounded-lg border border-gray-200 px-2.5 py-1.5 text-xs disabled:opacity-60" />],
                        ] as Array<[string, React.ReactNode]>).map(([label, control]) => (
                          <div key={label}><p className="mb-1 text-[9px] font-black uppercase tracking-widest text-gray-400">{label}</p>{control}</div>
                        ))}
                      </div>

                      <div>
                        <p className="mb-2 text-[10px] font-black uppercase tracking-widest text-gray-400">Notes</p>
                        {r.notes.length > 0 && <div className="mb-2 space-y-1.5">{r.notes.map((n, i) => <div key={i} className="rounded-lg border border-gray-100 bg-white px-3 py-2 text-[11px] text-gray-600">{n}</div>)}</div>}
                        {canEdit && (
                          <div className="flex gap-2">
                            <input value={noteInput[r.id] ?? ""} onChange={e => setNoteInput(p => ({ ...p, [r.id]: e.target.value }))} onKeyDown={e => { if (e.key === "Enter") addNote(r); }}
                              aria-label="Add a note" placeholder="Add a note (Enter to save)…" className="flex-1 rounded-lg border border-gray-200 bg-white px-3 py-2 text-xs focus:outline-none focus:ring-2 focus:ring-indigo-400" />
                            <button onClick={() => addNote(r)} className="rounded-lg border border-indigo-200 bg-indigo-50 px-3 py-2 text-xs font-bold text-indigo-700 hover:bg-indigo-100">Save</button>
                          </div>
                        )}
                      </div>

                      <div className="flex flex-wrap items-center gap-3 border-t border-gray-100 pt-3">
                        {r.related_link && <Link href={r.related_link} className="rounded-lg border border-gray-200 bg-white px-2.5 py-1 text-[10px] font-bold text-gray-700 hover:bg-gray-50">View evidence ↗</Link>}
                        {r.related_cwe && <a href={`https://cwe.mitre.org/data/definitions/${r.related_cwe.split(" — ")[0].replace("CWE-", "")}.html`} target="_blank" rel="noopener noreferrer" className="rounded-lg border border-violet-100 bg-violet-50 px-2.5 py-1 text-[10px] font-bold text-violet-700">{r.related_cwe} ↗</a>}
                        {r.related_cve && <span className="font-mono text-[10px] text-indigo-600">{r.related_cve}</span>}
                        <span className="ml-auto text-[10px] text-gray-400">Identified {r.identified_at}</span>
                        {!r.auto_derived && canEdit && (
                          <button onClick={() => { if (confirm("Delete this risk?")) void deleteManual(r.id); }} className="rounded-lg px-2.5 py-1 text-[10px] font-bold text-rose-600 hover:bg-rose-50">Delete</button>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      </PageSkeleton>
    </AuthGuard>
  );
}
