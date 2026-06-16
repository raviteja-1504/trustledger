"use client";

import { useState, useMemo, useEffect, useCallback, useRef } from "react";
import Link from "next/link";
import AuthGuard from "@/components/AuthGuard";
import { api } from "@/lib/api";
import { EVENT_CONFIG as DEFAULT_EVENT_CONFIG, EVENT_SOC2 as DEFAULT_EVENT_SOC2 } from "@/lib/auditConfig";
import type { AuditEventConfig } from "@/lib/auditConfig";
import type { ActivityEvent } from "@/types";
import { authedFetch } from "@/lib/useRealData";
import { useAuth } from "@/lib/auth";

// ── Types ──────────────────────────────────────────────────────────────────────

type AuditEventType =
  | "scan_complete" | "attestation"   | "merge_blocked"
  | "policy_violation" | "policy_change" | "secret_detected"
  | "integration_connected" | "user_added" | "sla_breach";

interface AuditEvent {
  id: string;
  type: AuditEventType;
  timestamp: string;
  repo?: string;
  actor?: string;
  description: string;
  detail?: string;
  metadata?: Record<string, string>;
  scan_id?: string;
  pr_number?: number;
  severity: "info" | "warning" | "critical";
}

const ORG = process.env.NEXT_PUBLIC_ORG ?? "novapay";

const EVENT_CONFIG = DEFAULT_EVENT_CONFIG as Record<AuditEventType, AuditEventConfig>;
const EVENT_SOC2_FALLBACK = DEFAULT_EVENT_SOC2 as Partial<Record<AuditEventType, string[]>>;

const SEV_COLOR: Record<AuditEvent["severity"], string> = {
  critical:"#ef4444", warning:"#f59e0b", info:"#6366f1",
};

// ── Real SHA-256 hash chain (Web Crypto) ───────────────────────────────────────

async function sha256Hex(input: string): Promise<string> {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
}

const GENESIS_HASH = "0".repeat(64);

function eventPayload(e: AuditEvent): string {
  return JSON.stringify({ id:e.id, type:e.type, ts:e.timestamp, desc:e.description, actor:e.actor ?? null, repo:e.repo ?? null });
}

/** Recompute a SHA-256 hash chain over events ordered oldest-first. Returns hash + prevHash per event id, plus the final head hash. */
async function buildHashChain(orderedOldestFirst: AuditEvent[]): Promise<{ hashes: Record<string,string>; prevHashes: Record<string,string>; head: string }> {
  let prev = GENESIS_HASH;
  const hashes: Record<string,string> = {};
  const prevHashes: Record<string,string> = {};
  for (const e of orderedOldestFirst) {
    const h = await sha256Hex(`${prev}:${eventPayload(e)}`);
    hashes[e.id] = h;
    prevHashes[e.id] = prev;
    prev = h;
  }
  return { hashes, prevHashes, head: prev };
}

const ACTOR_PALETTE: Record<string, { bg:string; text:string }> = {
  [`alice@${ORG}.io`]: { bg:"#ede9fe", text:"#6d28d9" },
  [`bob@${ORG}.io`]:   { bg:"#dbeafe", text:"#1d4ed8" },
  [`carol@${ORG}.io`]: { bg:"#d1fae5", text:"#065f46" },
  [`admin@${ORG}.io`]: { bg:"#fef3c7", text:"#92400e" },
};

// ── Small components ────────────────────────────────────────────────────────────

function EventIcon({ type }: { type: AuditEventType }) {
  const cfg = EVENT_CONFIG[type];
  const I = (d: string) => <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" dangerouslySetInnerHTML={{ __html: d }} />;
  const icons: Record<string, JSX.Element> = {
    scan:   <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>,
    check:  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3"   strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>,
    block:  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/></svg>,
    warn:   <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>,
    clock:  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>,
    gear:   <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>,
    secret: <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>,
    plug:   <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><polyline points="15 3 21 3 21 9"/><line x1="10" y1="14" x2="21" y2="3"/></svg>,
    user:   <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>,
  };
  return (
    <div className="w-8 h-8 rounded-xl flex items-center justify-center shrink-0 border"
      style={{ background:cfg.bg, borderColor:cfg.border, color:cfg.text }}>
      {icons[cfg.icon]}
    </div>
  );
}

function ActorAvatar({ email }: { email: string }) {
  const initials = email.split("@")[0].slice(0,2).toUpperCase();
  const pal = ACTOR_PALETTE[email] ?? { bg:"#f1f5f9", text:"#475569" };
  return (
    <div className="w-5 h-5 rounded-full flex items-center justify-center text-[8px] font-black shrink-0"
      style={{ background:pal.bg, color:pal.text }}>
      {initials}
    </div>
  );
}

const MONTHS   = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
const MONTHS_L  = ["January","February","March","April","May","June","July","August","September","October","November","December"];
const WEEKDAYS  = ["Sunday","Monday","Tuesday","Wednesday","Thursday","Friday","Saturday"];

function pad2(n: number) { return String(n).padStart(2,"0"); }

// Audit timestamps are displayed in UTC (matches the hash-chain panel and
// the underlying audit_log.created_at) so they're unambiguous regardless
// of the viewer's local timezone.
function formatTime(iso: string) {
  const d = new Date(iso);
  return `${pad2(d.getUTCHours())}:${pad2(d.getUTCMinutes())}:${pad2(d.getUTCSeconds())} UTC`;
}

function relTime(iso: string) {
  // Clamp to 0 so future-dated timestamps (e.g. mock events generated for
  // "today") never display as negative durations.
  const s = Math.max(0, Math.floor((Date.now() - new Date(iso).getTime()) / 1000));
  if (s < 60)    return "just now";
  if (s < 3600)  return `${Math.floor(s/60)}m ago`;
  if (s < 86400) return `${Math.floor(s/3600)}h ago`;
  return `${Math.floor(s/86400)}d ago`;
}

function formatDate(iso: string) {
  const d = new Date(iso);
  const today     = new Date();
  const yesterday = new Date(today);
  yesterday.setDate(yesterday.getDate() - 1);
  if (d.toDateString() === today.toDateString())     return "Today";
  if (d.toDateString() === yesterday.toDateString()) return "Yesterday";
  // Locale-independent: "Tuesday 26 May"
  return `${WEEKDAYS[d.getDay()]} ${d.getDate()} ${MONTHS_L[d.getMonth()]}`;
}

function fmtShortDate(iso: string) {
  const d = new Date(iso);
  return `${pad2(d.getDate())} ${MONTHS[d.getMonth()]}`;
}

function groupByDate(events: AuditEvent[]) {
  const groups: Record<string, AuditEvent[]> = {};
  events.forEach(e => {
    const key = new Date(e.timestamp).toDateString();
    if (!groups[key]) groups[key] = [];
    groups[key].push(e);
  });
  return Object.entries(groups).map(([key, evts]) => ({
    label: formatDate(evts[0].timestamp), key, events: evts,
    hasCritical: evts.some(e => e.severity === "critical"),
  }));
}

// ── Activity frequency bars ────────────────────────────────────────────────────

function ActivityBars({ events }: { events: AuditEvent[] }) {
  const counts: Record<string, number> = {};
  events.forEach(e => {
    const d = new Date(e.timestamp).toDateString();
    counts[d] = (counts[d] ?? 0) + 1;
  });
  const days = Object.keys(counts).reverse();
  const max  = Math.max(...Object.values(counts), 1);
  return (
    <div className="flex items-end gap-0.5 h-8">
      {days.map(d => (
        <div key={d} title={`${d}: ${counts[d]} events`}
          className="flex-1 rounded-sm min-w-[3px] transition-all hover:opacity-80"
          style={{ height:`${Math.max(15, (counts[d]/max)*100)}%`,
            background: counts[d] >= 5 ? "#ef4444" : counts[d] >= 3 ? "#f59e0b" : "#6366f1" }} />
      ))}
    </div>
  );
}

// ── Convert API ActivityEvent → AuditEvent ────────────────────────────────────

function activityToAuditEvent(a: ActivityEvent, idx: number): AuditEvent {
  const risk     = (a.overall_risk || "LOW") as string;
  const severity: AuditEvent["severity"] =
    risk === "CRITICAL" ? "critical" : risk === "HIGH" ? "warning" : "info";

  // Normalise empty strings → undefined so filters / avatars behave correctly
  const actor    = a.reviewer_email?.trim() || undefined;
  const filePath = a.file_path?.trim()      || undefined;
  const scanId   = a.scan_id?.trim()        || undefined;
  const repoShort = a.repo?.split("/").pop() ?? a.repo;

  if (a.type === "attestation") {
    const actorShort = actor ? actor.split("@")[0] : undefined;
    return {
      id:          `api-attest-${idx}-${a.timestamp}`,
      type:        "attestation",
      timestamp:   a.timestamp,
      repo:        a.repo,
      actor,
      severity:    "info",
      scan_id:     scanId,
      pr_number:   a.pr_number,
      description: filePath
        ? `File attested${actorShort ? ` by ${actorShort}` : ""}`
        : `PR #${a.pr_number} attested${actorShort ? ` by ${actorShort}` : ""}`,
      detail: filePath
        ? `${filePath.split("/").pop() || filePath} in ${repoShort} · PR #${a.pr_number}${actor ? ` · by ${actor}` : ""}`
        : `All files in PR #${a.pr_number} reviewed${actor ? ` · by ${actor}` : ""}`,
      metadata: {
        ...(filePath ? { File: filePath.split("/").pop() || filePath } : {}),
        Repository: repoShort,
        PR:         `#${a.pr_number}`,
        ...(actor ? { Reviewer: actor } : {}),
        "AI%":      `${(a.total_ai_pct * 100).toFixed(1)}%`,
      },
    };
  }

  // scan_complete
  return {
    id:          `api-scan-${idx}-${a.timestamp}`,
    type:        "scan_complete",
    timestamp:   a.timestamp,
    repo:        a.repo,
    severity,
    scan_id:     scanId,
    pr_number:   a.pr_number,
    description: `Scan completed — PR #${a.pr_number}`,
    detail:      `${a.file_count} file${a.file_count !== 1 ? "s" : ""} · ${risk} risk · ${(a.total_ai_pct * 100).toFixed(0)}% avg AI content`,
    metadata: {
      Files:      String(a.file_count),
      Risk:       risk,
      "Avg AI%":  `${(a.total_ai_pct * 100).toFixed(1)}%`,
      Repository: repoShort,
    },
  };
}

// ── Convert raw /api/audit row → AuditEvent ───────────────────────────────────

interface AuditLogRow {
  id: number;
  event_type: string;
  actor_email: string | null;
  resource_type?: string;
  resource_id?: string;
  payload: Record<string, unknown> | null;
  created_at: string;
}

// Server-side event types (src/lib/audit.ts AuditEventType) are a superset of
// the page's display AuditEventType — map each onto the closest display type
// so EVENT_CONFIG/EVENT_SOC2 lookups never miss.
const RAW_TYPE_MAP: Record<string, AuditEventType> = {
  scan_complete:         "scan_complete",
  attestation:           "attestation",
  merge_blocked:         "merge_blocked",
  merge_allowed:         "attestation",
  policy_violation:      "policy_violation",
  policy_change:         "policy_change",
  secret_detected:       "secret_detected",
  integration_connected: "integration_connected",
  user_added:            "user_added",
  user_removed:          "user_added",
  sla_breach:            "sla_breach",
  alert_fired:           "policy_violation",
  alert_resolved:        "policy_change",
  incident_created:      "merge_blocked",
  incident_resolved:     "policy_change",
  api_key_created:       "integration_connected",
  api_key_revoked:       "integration_connected",
  violation_resolved:    "policy_change",
  violation_escalated:   "policy_violation",
  report_generated:      "policy_change",
  org_settings_changed:  "policy_change",
};

const SEVERITY_BY_TYPE: Partial<Record<AuditEventType, AuditEvent["severity"]>> = {
  merge_blocked:    "critical",
  policy_violation: "critical",
  secret_detected:  "critical",
  sla_breach:       "critical",
  policy_change:    "warning",
};

function auditLogToAuditEvent(row: AuditLogRow): AuditEvent {
  const type    = RAW_TYPE_MAP[row.event_type] ?? "policy_change";
  const payload = row.payload ?? {};
  const repo    = typeof payload.repo === "string" ? payload.repo : undefined;
  const scanId  = typeof payload.scan_id === "string" ? payload.scan_id : undefined;
  const filePath = typeof payload.file_path === "string" ? payload.file_path : undefined;
  const prNumber = typeof payload.pr_number === "number" ? payload.pr_number : undefined;
  const actor   = row.actor_email?.trim() || undefined;
  const repoShort = repo?.split("/").pop() ?? repo;

  let description: string;
  let detail: string | undefined;
  let severity: AuditEvent["severity"] | undefined;
  switch (row.event_type) {
    case "scan_complete": {
      description = `Scan completed${prNumber ? ` — PR #${prNumber}` : ""}`;
      detail = [payload.file_count ? `${payload.file_count} files` : null, payload.overall_risk ? `${payload.overall_risk} risk` : null, repoShort]
        .filter(Boolean).join(" · ");
      const risk = typeof payload.overall_risk === "string" ? payload.overall_risk : "";
      severity = risk === "CRITICAL" ? "critical" : risk === "HIGH" ? "warning" : "info";
      break;
    }
    case "attestation":
      description = filePath ? "File attested" : `PR #${prNumber} attested`;
      detail = [filePath?.split("/").pop(), repoShort, actor ? `by ${actor}` : null].filter(Boolean).join(" · ");
      break;
    case "api_key_created":
      description = `API key created${payload.name ? ` — ${payload.name}` : ""}`;
      break;
    case "api_key_revoked":
      description = `API key revoked${payload.name ? ` — ${payload.name}` : ""}`;
      break;
    default:
      description = row.event_type.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase());
      detail = repoShort ?? (row.resource_id ? `resource ${row.resource_id}` : undefined);
  }

  return {
    id:          `audit-${row.id}`,
    type,
    timestamp:   row.created_at,
    repo,
    actor,
    severity:    severity ?? SEVERITY_BY_TYPE[type] ?? "info",
    scan_id:     scanId,
    pr_number:   prNumber,
    description,
    detail,
  };
}

// ── Page ───────────────────────────────────────────────────────────────────────

export default function AuditPage() {
  const { profile } = useAuth();
  const [eventSoc2,    setEventSoc2]    = useState<Partial<Record<AuditEventType, string[]>>>(EVENT_SOC2_FALLBACK);
  const [search,       setSearch]       = useState("");
  const [filterType,   setFilterType]   = useState<AuditEventType | "all">("all");
  const [filterSev,    setFilterSev]    = useState<AuditEvent["severity"] | "all">("all");
  const [liveEvents,    setLiveEvents]    = useState<AuditEvent[]>([]);
  const [refreshing,    setRefreshing]    = useState(false);
  const [lastRefreshed, setLastRefreshed] = useState<Date | null>(null);
  const [refreshAgo,    setRefreshAgo]    = useState("");
  const [filterRepo,    setFilterRepo]    = useState("all");
  const [filterActor,   setFilterActor]   = useState("all");
  const [expanded,      setExpanded]      = useState<string | null>(null);
  const [showExport,    setShowExport]    = useState(false);
  const [chainHashes,   setChainHashes]   = useState<Record<string,string>>({});
  const [chainPrevHashes, setChainPrevHashes] = useState<Record<string,string>>({});
  const [chainHead,     setChainHead]     = useState<string>("");
  const [chainCount,    setChainCount]    = useState(8);
  const [verifyState,   setVerifyState]   = useState<"idle"|"checking"|"valid"|"invalid">("idle");
  const [verifyDetail,  setVerifyDetail]  = useState<string>("");
  const [copiedHash,    setCopiedHash]    = useState<string | null>(null);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Fetch audit config from API — updates SOC 2 mappings and mock events dynamically
  useEffect(() => {
    api.auditConfig(ORG)
      .then(res => {
        if (res?.eventSoc2) setEventSoc2(res.eventSoc2 as Partial<Record<AuditEventType, string[]>>);
      })
      .catch(() => { /* keep EVENT_SOC2_FALLBACK */ });
  }, []);

  const fetchActivity = useCallback(async (showSpinner = false) => {
    if (showSpinner) setRefreshing(true);

    // Local attestation events from PR page
    const localRaw = (() => { try { return JSON.parse(localStorage.getItem("tl_local_activity") ?? "[]") as ActivityEvent[]; } catch { return [] as ActivityEvent[]; } })();
    const localEvents = localRaw.map((a, i) => activityToAuditEvent(a, 10000 + i));

    // Try real audit log from Supabase — a real org_id takes precedence over
    // a stale tl_force_seed flag, so real orgs always see their actual log.
    if (profile?.org_id) {
      try {
        const res = await authedFetch<{ events: AuditLogRow[]; total: number }>("/api/audit?limit=200");
        const remoteEvents = res.events.map(auditLogToAuditEvent);
        const merged = [...localEvents, ...remoteEvents].filter((e, i, arr) =>
          arr.findIndex(x => x.id === e.id) === i
        );
        setLiveEvents(merged);
        setLastRefreshed(new Date());
        if (showSpinner) setRefreshing(false);
        return;
      } catch { /* fall through to activity API */ }
    }

    try {
      const r = await api.activity(ORG, 100);
      const apiEvents = r.events.map(activityToAuditEvent);
      const seen: Record<string, boolean> = {};
      const merged = [...localEvents, ...apiEvents].filter(e => {
        const k = `${e.scan_id ?? ""}::${e.timestamp}`;
        if (seen[k]) return false; seen[k] = true; return true;
      });
      setLiveEvents(merged);
      setLastRefreshed(new Date());
    } catch {
      if (localEvents.length > 0) setLiveEvents(localEvents);
    } finally {
      if (showSpinner) setRefreshing(false);
    }
  }, [profile?.org_id]);

  // Initial fetch + auto-poll every 30 s
  useEffect(() => {
    fetchActivity();
    timerRef.current = setInterval(() => fetchActivity(), 30_000);
    return () => { if (timerRef.current) clearInterval(timerRef.current); };
  }, [fetchActivity]);

  // Refresh-ago ticker
  useEffect(() => {
    function tick() {
      if (!lastRefreshed) { setRefreshAgo(""); return; }
      const s = Math.floor((Date.now() - lastRefreshed.getTime()) / 1000);
      setRefreshAgo(s < 10 ? "just now" : s < 60 ? `${s}s ago` : `${Math.floor(s/60)}m ago`);
    }
    tick();
    const id = setInterval(tick, 5000);
    return () => clearInterval(id);
  }, [lastRefreshed]);

  // Sort live events newest-first. Seed mode populates liveEvents from
  // tl_local_activity; real orgs get liveEvents from the audit/activity API.
  const allEvents = useMemo<AuditEvent[]>(() => {
    return [...liveEvents]
      .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
  }, [liveEvents]);

  const repos  = useMemo(() => Array.from(new Set(allEvents.filter(e => e.repo).map(e => e.repo!))), [allEvents]);
  const actors = useMemo(() => Array.from(new Set(allEvents.filter(e => e.actor).map(e => e.actor!))), [allEvents]);

  const filtered = useMemo(() => allEvents.filter(e => {
    if (filterType  !== "all" && e.type     !== filterType)  return false;
    if (filterSev   !== "all" && e.severity !== filterSev)   return false;
    if (filterRepo  !== "all" && e.repo     !== filterRepo)  return false;
    if (filterActor !== "all" && e.actor    !== filterActor) return false;
    if (search) {
      const q = search.toLowerCase();
      const haystack = [e.description, e.detail ?? "", e.actor ?? "", e.repo ?? ""].join(" ").toLowerCase();
      if (!haystack.includes(q)) return false;
    }
    return true;
  }), [allEvents, filterType, filterSev, filterRepo, filterActor, search]);

  const grouped = useMemo(() => groupByDate(filtered), [filtered]);

  // Recent critical events (last 24h) — from merged live + mock
  const recentCritical = allEvents.filter(e =>
    e.severity === "critical" &&
    Date.now() - new Date(e.timestamp).getTime() < 86400000
  );

  // Recompute the real SHA-256 hash chain (oldest → newest) whenever the event set changes
  useEffect(() => {
    let cancelled = false;
    const ordered = [...allEvents].sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
    buildHashChain(ordered).then(({ hashes, prevHashes, head }) => {
      if (cancelled) return;
      setChainHashes(hashes);
      setChainPrevHashes(prevHashes);
      setChainHead(head);
      // Any prior verification result is now stale
      setVerifyState("idle");
      setVerifyDetail("");
    });
    return () => { cancelled = true; };
  }, [allEvents]);

  // Verify chain integrity: live mode hits the server-side audit_log chain (entry_hash/prev_hash);
  // seed/demo mode recomputes the client-side SHA-256 chain from scratch and compares to the cached result.
  const verifyChain = useCallback(async () => {
    setVerifyState("checking");
    if (profile?.org_id) {
      try {
        const res = await authedFetch<{ valid: boolean; broken_at?: number; total: number }>("/api/audit", { method: "POST" });
        setVerifyState(res.valid ? "valid" : "invalid");
        setVerifyDetail(res.valid
          ? `${res.total} server-side entries verified — chain intact`
          : `Chain broken at entry #${res.broken_at} of ${res.total}`);
        return;
      } catch { /* fall through to client-side recompute */ }
    }
    const ordered = [...allEvents].sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
    const { hashes, head } = await buildHashChain(ordered);
    const matches = ordered.length > 0 && ordered.every(e => hashes[e.id] === chainHashes[e.id]) && head === chainHead;
    setVerifyState(matches ? "valid" : "invalid");
    setVerifyDetail(matches
      ? `${ordered.length} events recomputed — SHA-256 chain intact`
      : `Hash mismatch detected across ${ordered.length} events — possible tampering`);
  }, [allEvents, chainHashes, chainHead, profile?.org_id]);

  function copyHash(hash: string) {
    navigator.clipboard.writeText(hash).then(() => {
      setCopiedHash(hash);
      setTimeout(() => setCopiedHash(c => c === hash ? null : c), 1500);
    }).catch(() => {});
  }

  function downloadBlob(content: string, type: string, filename: string) {
    const url = URL.createObjectURL(new Blob([content], { type }));
    Object.assign(document.createElement("a"), { href:url, download:filename }).click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  // Proper CSV cell escaping: wrap in quotes (and double embedded quotes) only when needed
  function csvCell(v: unknown): string {
    const str = String(v ?? "");
    return /[",\n\r]/.test(str) ? `"${str.replace(/"/g,'""')}"` : str;
  }

  function exportData(fmt: "csv" | "json") {
    setShowExport(false);
    if (fmt === "csv") {
      const rows = [
        ["Timestamp","Event","Severity","Description","Repository","Actor","Detail","Hash","PrevHash"],
        ...filtered.map(e => [
          e.timestamp, EVENT_CONFIG[e.type].label, e.severity, e.description, e.repo??"", e.actor??"", e.detail??"",
          chainHashes[e.id] ?? "", chainPrevHashes[e.id] ?? "",
        ]),
      ];
      downloadBlob(rows.map(r => r.map(csvCell).join(",")).join("\r\n"), "text/csv", "audit-trail.csv");
    } else {
      const data = filtered.map(e => ({ ...e, hash: chainHashes[e.id] ?? null, prev_hash: chainPrevHashes[e.id] ?? null }));
      downloadBlob(JSON.stringify(data, null, 2), "application/json", "audit-trail.json");
    }
  }


  const activeFilters = [search, filterType!=="all", filterSev!=="all", filterRepo!=="all", filterActor!=="all"].filter(Boolean).length;

  return (
    <AuthGuard>
      <div className="max-w-5xl mx-auto space-y-5 pb-10">

        {/* ── Header ── */}
        <div className="animate-fade-up relative z-30 flex items-start justify-between gap-4 flex-wrap">
          <div>
            <div className="flex items-center gap-2.5 mb-1">
              <div className="w-8 h-8 rounded-xl flex items-center justify-center"
                style={{ background:"rgba(99,102,241,0.1)", border:"1px solid rgba(99,102,241,0.2)" }}>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#6366f1" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M9 11l3 3L22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/>
                </svg>
              </div>
              <h1 className="text-xl font-black text-gray-900 tracking-tight">Audit Trail</h1>
              <span className="text-xs font-semibold text-gray-400 bg-gray-100 px-2 py-0.5 rounded-full">
                {allEvents.length} events
              </span>
              {/* Live badge */}
              <span className="flex items-center gap-1.5 text-[10px] font-bold text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded-full ring-1 ring-emerald-200">
                <span className="relative flex w-1.5 h-1.5">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                  <span className="relative inline-flex rounded-full w-1.5 h-1.5 bg-emerald-500" />
                </span>
                Live
              </span>
            </div>
            <p className="text-sm text-gray-400">
              Immutable chronological security event log · tamper-evident · cryptographically chained
            </p>
          </div>
          {/* Refresh + Export */}
          <div className="flex items-center gap-2">
            {/* Refresh button */}
            <div className="flex flex-col items-end gap-0.5">
              <button
                onClick={() => fetchActivity(true)}
                disabled={refreshing}
                className="flex items-center gap-1.5 px-3 py-2 text-sm font-semibold text-indigo-600 bg-indigo-50 border border-indigo-200 rounded-xl hover:bg-indigo-100 disabled:opacity-50 transition-all shadow-sm"
              >
                <svg className={refreshing ? "animate-spin" : ""} width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                  <polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>
                </svg>
                {refreshing ? "Refreshing…" : "Refresh"}
              </button>
              {refreshAgo && (
                <span className="text-[9px] text-gray-400 tabular-nums">Updated {refreshAgo}</span>
              )}
            </div>
          {/* Export dropdown */}
          <div className="relative">
            <button onClick={() => setShowExport(v => !v)}
              className="flex items-center gap-1.5 px-3 py-2 text-sm font-semibold text-gray-600 bg-white border border-gray-200 rounded-xl hover:bg-gray-50 transition-all shadow-sm">
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>
              </svg>
              Export
              <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><polyline points="6 9 12 15 18 9"/></svg>
            </button>
            {showExport && (
              <div className="absolute right-0 top-full mt-1 w-44 bg-white border border-gray-200 rounded-xl shadow-lg z-20 overflow-hidden">
                <button onClick={() => exportData("csv")}
                  className="w-full text-left px-3.5 py-2.5 text-xs font-semibold text-gray-700 hover:bg-gray-50 transition-colors flex items-center gap-2">
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="3" width="18" height="18" rx="2"/><line x1="3" y1="9" x2="21" y2="9"/><line x1="9" y1="21" x2="9" y2="9"/></svg>
                  Export CSV
                </button>
                <button onClick={() => exportData("json")}
                  className="w-full text-left px-3.5 py-2.5 text-xs font-semibold text-gray-700 hover:bg-gray-50 transition-colors border-t border-gray-50 flex items-center gap-2">
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/></svg>
                  Export JSON
                </button>
              </div>
            )}
          </div>
          </div>{/* close Refresh + Export wrapper */}
        </div>

        {/* ── Critical alert banner ── */}
        {recentCritical.length > 0 && (
          <div className="animate-fade-up rounded-2xl border overflow-hidden"
            style={{ background:"rgba(254,226,226,0.5)", borderColor:"#fca5a5" }}>
            <div className="flex items-start gap-3 px-4 py-3">
              <svg className="shrink-0 mt-0.5 text-rose-600" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                <path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
                <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
              </svg>
              <p className="text-sm font-bold text-rose-800">
                {recentCritical.length} critical event{recentCritical.length !== 1 ? "s" : ""} in the last 24 hours
              </p>
            </div>
            <div className="border-t border-rose-200/60 divide-y divide-rose-200/60">
              {recentCritical.slice(0, 5).map(e => {
                const cfg = EVENT_CONFIG[e.type];
                return (
                  <button key={e.id} onClick={() => {
                    setExpanded(e.id);
                    requestAnimationFrame(() => document.getElementById(`event-${e.id}`)?.scrollIntoView({ behavior:"smooth", block:"center" }));
                  }} className="w-full text-left px-4 py-2.5 hover:bg-rose-50/60 transition-colors">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-[10px] font-bold px-1.5 py-0.5 rounded-md" style={{ background:cfg.bg, color:cfg.text }}>{cfg.label}</span>
                      <span className="text-xs font-semibold text-rose-900">{e.description}</span>
                      {e.repo && <span className="text-[10px] text-rose-500 bg-white px-1.5 py-0.5 rounded font-mono">{e.repo.split("/").pop()}</span>}
                      <span className="text-[10px] text-rose-400 ml-auto shrink-0">{relTime(e.timestamp)} · {formatTime(e.timestamp)}</span>
                    </div>
                    {e.detail && <p className="text-[11px] text-rose-600/90 mt-1 leading-relaxed">{e.detail}</p>}
                  </button>
                );
              })}
              {recentCritical.length > 5 && (
                <p className="px-4 py-2 text-[11px] font-semibold text-rose-500">+{recentCritical.length - 5} more critical event{recentCritical.length - 5 !== 1 ? "s" : ""}</p>
              )}
            </div>
          </div>
        )}

        {/* ── Summary + activity bars ── */}
        <div className="animate-fade-up grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[
            { label:"Critical",       value:allEvents.filter(e=>e.severity==="critical").length, color:"#ef4444", bg:"#fef2f2" },
            { label:"Merges Blocked", value:allEvents.filter(e=>e.type==="merge_blocked").length, color:"#be123c", bg:"#fff1f2" },
            { label:"Secrets Found",  value:allEvents.filter(e=>e.type==="secret_detected").length, color:"#7c3aed", bg:"#ede9fe" },
            { label:"Attestations",   value:allEvents.filter(e=>e.type==="attestation").length, color:"#15803d", bg:"#f0fdf4" },
          ].map(s => (
            <div key={s.label} className="rounded-2xl p-4 border" style={{ background:s.bg, borderColor:s.color+"30" }}>
              <p className="text-2xl font-black tabular-nums" style={{ color:s.color }}>{s.value}</p>
              <p className="text-xs font-semibold text-gray-500 mt-1">{s.label}</p>
            </div>
          ))}
        </div>

        {/* ── Activity frequency ── */}
        <div className="animate-fade-up section-card px-5 py-4">
          <div className="flex items-center justify-between mb-3">
            <p className="text-[10px] font-black uppercase tracking-widest text-gray-400">Event Frequency</p>
            <p className="text-[9px] text-gray-400">Last {Object.keys(allEvents.reduce((a,e) => ({...a,[new Date(e.timestamp).toDateString()]:1}),{})).length} days</p>
          </div>
          <ActivityBars events={allEvents} />
          <div className="flex justify-between mt-1.5">
            <span className="text-[8px] text-gray-400">{allEvents.length > 0 ? fmtShortDate(allEvents[allEvents.length-1].timestamp) : ""}</span>
            <span className="text-[8px] text-gray-400">{allEvents.length > 0 ? fmtShortDate(allEvents[0].timestamp) : ""}</span>
          </div>
        </div>

        {/* ── Filters ── */}
        <div className="animate-fade-up space-y-2">
          {/* Search */}
          <div className="flex items-center gap-2 bg-white border border-gray-200 rounded-xl px-3.5 py-2.5 shadow-sm focus-within:ring-2 focus-within:ring-indigo-400 focus-within:border-transparent transition-all">
            <svg className="text-gray-400 shrink-0" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
              <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
            </svg>
            <input value={search} onChange={e => setSearch(e.target.value)}
              placeholder="Search events, files, actors, repos…"
              className="flex-1 text-sm text-gray-700 placeholder-gray-400 outline-none bg-transparent" />
            {search && (
              <button onClick={() => setSearch("")}
                className="text-gray-400 hover:text-gray-600 text-xs font-bold">✕</button>
            )}
          </div>

          {/* Filter chips */}
          <div className="flex flex-wrap items-center gap-2">
            <div className="flex items-center gap-0.5 bg-gray-100 p-0.5 rounded-xl">
              {(["all","critical","warning","info"] as const).map(s => (
                <button key={s} onClick={() => setFilterSev(s)}
                  className={`px-3 py-1.5 text-xs font-semibold rounded-lg transition-all ${filterSev===s?"bg-white text-gray-900 shadow-sm":"text-gray-500 hover:text-gray-700"}`}>
                  {s==="all" ? "All" : s.charAt(0).toUpperCase()+s.slice(1)}
                </button>
              ))}
            </div>

            <select value={filterType} onChange={e => setFilterType(e.target.value as AuditEventType | "all")}
              className="text-xs font-semibold text-gray-600 bg-white border border-gray-200 rounded-xl px-3 py-2 focus:outline-none focus:ring-2 focus:ring-indigo-400">
              <option value="all">All Event Types</option>
              {(Object.keys(EVENT_CONFIG) as AuditEventType[]).map(t => (
                <option key={t} value={t}>{EVENT_CONFIG[t].label}</option>
              ))}
            </select>

            <select value={filterRepo} onChange={e => setFilterRepo(e.target.value)}
              className="text-xs font-semibold text-gray-600 bg-white border border-gray-200 rounded-xl px-3 py-2 focus:outline-none focus:ring-2 focus:ring-indigo-400">
              <option value="all">All Repos</option>
              {repos.map(r => <option key={r} value={r}>{r.split("/").pop()}</option>)}
            </select>

            <select value={filterActor} onChange={e => setFilterActor(e.target.value)}
              className="text-xs font-semibold text-gray-600 bg-white border border-gray-200 rounded-xl px-3 py-2 focus:outline-none focus:ring-2 focus:ring-indigo-400">
              <option value="all">All Actors</option>
              {actors.map(a => <option key={a} value={a}>{a.split("@")[0]}</option>)}
            </select>

            {activeFilters > 0 && (
              <button onClick={() => { setSearch(""); setFilterType("all"); setFilterSev("all"); setFilterRepo("all"); setFilterActor("all"); }}
                className="text-xs font-bold text-rose-600 hover:text-rose-800 px-2 py-1 rounded-lg hover:bg-rose-50 transition-colors">
                Clear {activeFilters} filter{activeFilters!==1?"s":""}
              </button>
            )}

            <span className="text-xs text-gray-400 ml-auto">{filtered.length} event{filtered.length!==1?"s":""}</span>
          </div>
        </div>

        {/* ── Timeline ── */}
        <div className="animate-fade-up space-y-6">
          {grouped.length === 0 ? (
            <div className="section-card py-16 text-center">
              <div className="w-12 h-12 rounded-2xl bg-gray-50 flex items-center justify-center text-gray-400 mx-auto mb-3">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
              </div>
              {allEvents.length === 0 ? (
                <>
                  <p className="text-sm font-bold text-gray-600">No audit events yet</p>
                  <p className="text-xs text-gray-400 mt-1">Once scans, attestations, or policy actions occur, they&apos;ll appear here.</p>
                </>
              ) : (
                <>
                  <p className="text-sm font-bold text-gray-600">No events match your filters</p>
                  <p className="text-xs text-gray-400 mt-1">Try adjusting the search or filter criteria</p>
                </>
              )}
            </div>
          ) : grouped.map(group => (
            <div key={group.key}>
              {/* Date divider */}
              <div className="flex items-center gap-3 mb-3">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-black text-gray-700 uppercase tracking-widest">{group.label}</span>
                  {group.hasCritical && (
                    <span className="text-[9px] font-black text-rose-600 bg-rose-50 px-1.5 py-0.5 rounded-full border border-rose-200">CRITICAL</span>
                  )}
                </div>
                <div className="flex-1 h-px bg-gray-100" />
                <span className="text-[10px] text-gray-400 shrink-0">
                  {group.events.length} event{group.events.length!==1?"s":""}
                </span>
              </div>

              {/* Events with timeline line */}
              <div className="section-card overflow-hidden">
                {group.events.map((e, idx) => {
                  const cfg  = EVENT_CONFIG[e.type];
                  const open = expanded === e.id;
                  const isLast = idx === group.events.length - 1;

                  return (
                    <div key={e.id} id={`event-${e.id}`} className={`border-b border-gray-50 last:border-0 ${open?"bg-gray-50/50":""}`}>
                      {/* Main row */}
                      <div
                        className="flex items-start gap-3 px-5 py-3.5 cursor-pointer hover:bg-gray-50/60 transition-colors group"
                        onClick={() => setExpanded(open ? null : e.id)}>

                        {/* Timeline column */}
                        <div className="flex flex-col items-center shrink-0 w-8">
                          <EventIcon type={e.type} />
                          {!isLast && <div className="w-px flex-1 bg-gray-100 mt-1.5 min-h-[8px]" />}
                        </div>

                        {/* Content */}
                        <div className="flex-1 min-w-0 pb-1">
                          <div className="flex items-center gap-2 flex-wrap">
                            {/* Severity dot */}
                            <span className="w-1.5 h-1.5 rounded-full shrink-0 mt-0.5" style={{ background:SEV_COLOR[e.severity] }} />
                            {/* Type badge */}
                            <span className="text-[10px] font-bold px-1.5 py-0.5 rounded-md"
                              style={{ background:cfg.bg, color:cfg.text }}>
                              {cfg.label}
                            </span>
                            {/* Description */}
                            <span className="text-xs font-semibold text-gray-800">{e.description}</span>
                            {/* Repo */}
                            {e.repo && (
                              <span className="text-[10px] text-gray-400 bg-gray-100 px-1.5 py-0.5 rounded font-mono">
                                {e.repo.split("/").pop()}
                              </span>
                            )}
                            {/* Actor */}
                            {e.actor && (
                              <span className="flex items-center gap-1 text-[10px] text-gray-500">
                                <ActorAvatar email={e.actor} />
                                {e.actor.split("@")[0]}
                              </span>
                            )}
                          </div>

                          {/* Detail preview (collapsed) */}
                          {!open && e.detail && (
                            <p className="text-[10px] text-gray-400 mt-0.5 truncate ml-3.5">{e.detail}</p>
                          )}
                        </div>

                        {/* Right: time + expand */}
                        <div className="flex items-center gap-2 shrink-0">
                          <div className="text-right">
                            <p className="text-[10px] font-mono text-gray-500 tabular-nums">{formatTime(e.timestamp)}</p>
                            <p className="text-[9px] text-gray-400">{relTime(e.timestamp)}</p>
                          </div>
                          <svg className="text-gray-300 group-hover:text-gray-500 transition-all" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"
                            style={{ transform:open?"rotate(180deg)":"none", transition:"transform 0.2s" }}>
                            <polyline points="6 9 12 15 18 9"/>
                          </svg>
                        </div>
                      </div>

                      {/* Expanded detail panel */}
                      {open && (
                        <div className="px-5 pb-4 ml-11 space-y-3">
                          {/* Full detail */}
                          <div className="bg-white rounded-xl px-4 py-3 border border-gray-100">
                            <p className="text-[9px] font-black uppercase tracking-widest text-gray-400 mb-1.5">Event Detail</p>
                            <p className="text-xs text-gray-700 leading-relaxed">{e.detail}</p>
                          </div>

                          {/* Metadata grid */}
                          {e.metadata && Object.keys(e.metadata).length > 0 && (
                            <div className="grid grid-cols-2 sm:grid-cols-3 gap-2">
                              {Object.entries(e.metadata).map(([k,v]) => (
                                <div key={k} className="bg-gray-50 rounded-lg px-3 py-2 border border-gray-100">
                                  <p className="text-[9px] font-bold text-gray-400 uppercase tracking-wide">{k}</p>
                                  <p className="text-[11px] font-semibold text-gray-700 mt-0.5 truncate font-mono">{v}</p>
                                </div>
                              ))}
                            </div>
                          )}

                          {/* SOC 2 evidence mapping */}
                          {eventSoc2[e.type] && (
                            <div className="flex items-center gap-2 flex-wrap">
                              <span className="text-[9px] font-black uppercase tracking-widest text-indigo-400 shrink-0">SOC 2 Evidence:</span>
                              {eventSoc2[e.type]!.map(ctrl => (
                                <span key={ctrl} className="text-[9px] font-black font-mono text-indigo-700 bg-indigo-50 px-2 py-0.5 rounded border border-indigo-200">{ctrl}</span>
                              ))}
                            </div>
                          )}

                          {/* Actions */}
                          <div className="flex items-center gap-3 flex-wrap">
                            {e.pr_number && e.scan_id && (
                              <Link href={`/pr/${e.scan_id}`}
                                className="flex items-center gap-1.5 text-xs font-bold text-indigo-600 bg-indigo-50 hover:bg-indigo-100 px-3 py-1.5 rounded-lg border border-indigo-100 transition-colors">
                                <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><circle cx="18" cy="18" r="3"/><circle cx="6" cy="6" r="3"/><path d="M13 6h3a2 2 0 0 1 2 2v7"/><line x1="6" y1="9" x2="6" y2="21"/></svg>
                                View PR #{e.pr_number}
                              </Link>
                            )}
                            <button
                              onClick={() => navigator.clipboard.writeText(JSON.stringify({ ...e, hash:chainHashes[e.id] ?? null, prev_hash:chainPrevHashes[e.id] ?? null }, null, 2)).catch(() => {})}
                              className="flex items-center gap-1.5 text-xs font-semibold text-gray-500 hover:text-gray-700 bg-gray-50 hover:bg-gray-100 px-3 py-1.5 rounded-lg border border-gray-200 transition-colors">
                              <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                              Copy JSON
                            </button>
                            {chainHashes[e.id] && (
                              <button
                                onClick={() => copyHash(chainHashes[e.id])}
                                className="flex items-center gap-1.5 text-xs font-semibold text-gray-500 hover:text-gray-700 bg-gray-50 hover:bg-gray-100 px-3 py-1.5 rounded-lg border border-gray-200 transition-colors font-mono">
                                <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>
                                {copiedHash === chainHashes[e.id] ? "Copied!" : `${chainHashes[e.id].slice(0,10)}…`}
                              </button>
                            )}
                            <span className="text-[9px] font-mono text-gray-400 ml-auto">
                              ID: {e.id} · {e.timestamp}
                            </span>
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
              </div>
            </div>
          ))}
        </div>

        {/* ── Tamper-evidence ── */}
        <div className="animate-fade-up flex items-start gap-3 bg-indigo-50 border border-indigo-100 rounded-xl px-4 py-3">
          <svg className="shrink-0 mt-0.5 text-indigo-500" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
          </svg>
          <p className="text-xs text-indigo-800 leading-relaxed">
            <span className="font-bold">Tamper-evident audit log.</span>{" "}
            Every event is cryptographically chained — deletions and retroactive modifications are detectable.
            Satisfies SOC 2 CC7.2 (monitoring) and CC8.1 (change management) evidence requirements.
          </p>
        </div>

        {/* ── Hash chain integrity ── */}
        <div className="animate-fade-up section-card overflow-hidden">
          <div className="flex items-center gap-3 px-5 py-3.5 border-b border-gray-100 flex-wrap">
            <svg className="text-indigo-400 shrink-0" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/>
              <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>
            </svg>
            <p className="text-sm font-bold text-gray-900">Hash Chain Integrity</p>
            {verifyState === "valid" && (
              <span className="text-[9px] font-black text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded-full border border-emerald-200">✓ Verified</span>
            )}
            {verifyState === "invalid" && (
              <span className="text-[9px] font-black text-rose-700 bg-rose-50 px-2 py-0.5 rounded-full border border-rose-200">✗ Tampered</span>
            )}
            {verifyState === "checking" && (
              <span className="text-[9px] font-black text-indigo-700 bg-indigo-50 px-2 py-0.5 rounded-full border border-indigo-200 animate-pulse">Verifying…</span>
            )}
            {verifyState === "idle" && (
              <span className="text-[9px] font-black text-gray-500 bg-gray-50 px-2 py-0.5 rounded-full border border-gray-200">SHA-256 chained</span>
            )}
            <button onClick={verifyChain} disabled={verifyState==="checking"}
              className="text-[10px] font-bold text-indigo-600 bg-indigo-50 hover:bg-indigo-100 border border-indigo-200 rounded-full px-2.5 py-0.5 transition-colors disabled:opacity-50">
              Verify Chain
            </button>
            <p className="text-[10px] text-gray-400 ml-auto">SHA-256 · {allEvents.length} events</p>
          </div>
          {verifyDetail && (
            <div className={`px-5 py-2 text-[10px] font-mono border-b ${verifyState==="invalid" ? "bg-rose-50 text-rose-700 border-rose-100" : "bg-emerald-50 text-emerald-700 border-emerald-100"}`}>
              {verifyDetail}
            </div>
          )}
          <div className="px-5 py-4 overflow-x-auto">
            <div className="flex items-center gap-0 min-w-max">
              {(() => {
                const orderedAsc = [...allEvents].sort((a,b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());
                const slice = orderedAsc.slice(-chainCount);
                const hiddenBefore = orderedAsc.length - slice.length;
                return (
                  <>
                    {hiddenBefore > 0 && (
                      <button onClick={() => setChainCount(c => c + 8)}
                        className="text-[10px] text-indigo-500 hover:text-indigo-700 font-semibold mr-3 shrink-0 underline">
                        ··· +{hiddenBefore} earlier
                      </button>
                    )}
                    {slice.map((e, idx) => {
                      const hash = chainHashes[e.id];
                      const cfg  = EVENT_CONFIG[e.type];
                      return (
                        <div key={e.id} className="flex items-center gap-0">
                          {idx > 0 && (
                            <div className="flex items-center mx-2 text-gray-300">
                              <div className="w-4 h-px bg-gray-300" />
                              <svg width="8" height="8" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><polyline points="9 18 15 12 9 6"/></svg>
                            </div>
                          )}
                          <button onClick={() => hash && copyHash(hash)}
                            className="rounded-xl px-3 py-2.5 border min-w-[155px] text-left hover:ring-2 hover:ring-indigo-200 transition-all"
                            style={{ background:cfg.bg, borderColor:cfg.border }}>
                            <div className="flex items-center gap-1.5 mb-1">
                              <span className="text-[9px] font-black uppercase tracking-wider" style={{ color:cfg.text }}>{cfg.label}</span>
                              <span className="text-[8px] text-gray-400 font-mono ml-auto">{e.id.slice(0,10)}</span>
                            </div>
                            <p className="text-[8px] font-mono text-gray-500 leading-relaxed break-all">
                              {hash ? (copiedHash === hash ? "Copied!" : hash) : "computing…"}
                            </p>
                            <p className="text-[8px] text-gray-400 mt-0.5">{new Date(e.timestamp).toISOString().slice(11,19)} UTC</p>
                          </button>
                        </div>
                      );
                    })}
                  </>
                );
              })()}
            </div>
          </div>
        </div>

      </div>
    </AuthGuard>
  );
}
