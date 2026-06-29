"use client";

import { useState, useMemo, useEffect, useCallback, useRef } from "react";
import Link from "next/link";
import InfoTooltip from "@/components/InfoTooltip";
import { useToastHelpers } from "@/lib/toast";
import AuthGuard from "@/components/AuthGuard";
import { formatDateTime, formatDateOnly, relativeTime, useTimezone } from "@/lib/timezone";
import PageSkeleton from "@/components/PageSkeleton";
import { api } from "@/lib/api";
import { readSeed } from "@/lib/offlineData";
import { authedFetch } from "@/lib/useRealData";
import { useAlertsRealtime } from "@/lib/realtime";
import { useAuth } from "@/lib/auth";
import { patchDataWithAttestations } from "@/lib/trustScore";
import type { DashboardData } from "@/types";

// ── Types ──────────────────────────────────────────────────────────────────────

type AlertSeverity = "P1" | "P2" | "P3" | "P4";
type AlertStatus   = "firing" | "acknowledged" | "snoozed" | "resolved";
type AlertSource   = "scan" | "policy" | "secret" | "dependency" | "sla" | "anomaly" | "exploit";

interface AlertHistoryEntry {
  action: string;
  by?: string;
  at: string;
  note?: string;
}

interface Alert {
  id: string;
  title: string;
  body: string;
  severity: AlertSeverity;
  source: AlertSource;
  status: AlertStatus;
  repo?: string;
  scan_id?: string;
  pr_number?: number;
  fired_at: string;
  acknowledged_by?: string;
  snooze_until?: string;
  resolved_at?: string;
  channel: "slack" | "email" | "webhook" | "in-app";
  runbook?: string;
  escalation?: string[];    // who gets paged if SLA breaches
  group_id?: string;        // alerts with same group_id are related
  notes: string[];          // reviewer notes
  history: AlertHistoryEntry[];
}


function getReviewerEmail(currentUserEmail?: string): string {
  if (currentUserEmail) return currentUserEmail;
  try { const m = JSON.parse(localStorage.getItem("tl_team_members") ?? "[]"); if (m[0]?.email) return m[0].email; } catch { /* */ }
  return "unknown";
}

// ── SLA per priority ────────────────────────────────────────────────────────────

const SLA_MS: Record<AlertSeverity, number> = {
  P1: 1 * 3600_000,   // 1 h
  P2: 4 * 3600_000,   // 4 h
  P3: 24 * 3600_000,  // 24 h
  P4: 72 * 3600_000,  // 72 h
};

// ── Persistence ────────────────────────────────────────────────────────────────

const PERSIST_KEY = "tl_alerts_state";

interface PersistedState {
  statuses:  Record<string, AlertStatus>;
  ackBy:     Record<string, string>;
  snoozeUntil: Record<string, string>;
  resolvedAt:  Record<string, string>;
  notes:     Record<string, string[]>;
  history:   Record<string, AlertHistoryEntry[]>;
}

const EMPTY_STATE: PersistedState = { statuses:{}, ackBy:{}, snoozeUntil:{}, resolvedAt:{}, notes:{}, history:{} };

function loadState(): PersistedState {
  try {
    const raw = JSON.parse(localStorage.getItem(PERSIST_KEY) ?? "null");
    if (!raw) return EMPTY_STATE;
    // Normalise both camelCase (app format) and snake_case (seed/dev format)
    return {
      statuses:   raw.statuses    ?? {},
      ackBy:      raw.ackBy       ?? {},
      snoozeUntil:raw.snoozeUntil ?? raw.snooze_until ?? {},
      resolvedAt: raw.resolvedAt  ?? {},
      notes:      raw.notes       ?? {},
      history:    raw.history     ?? {},
    };
  } catch { return EMPTY_STATE; }
}
function saveState(s: PersistedState) { localStorage.setItem(PERSIST_KEY, JSON.stringify(s)); }

// ── Derive alerts from DashboardData ──────────────────────────────────────────

function deriveAlerts(data: DashboardData): Alert[] {
  const alerts: Alert[] = [];
  const now = Date.now();
  const h = (seed: string, hoursAgo: number): string => {
    let v = 0; for (let i = 0; i < seed.length; i++) v = (v * 31 + seed.charCodeAt(i)) & 0x7fffffff;
    return new Date(now - hoursAgo * 3_600_000 - (v % (hoursAgo * 60_000 + 1))).toISOString();
  };

  // P1 — hardcoded secrets
  data.top_risk_files.filter(f => !f.attested && f.risk_score === "CRITICAL").slice(0, 3).forEach(f => {
    alerts.push({
      id:`secret-${f.scan_id}-${f.file_path}`, group_id:`pr-${f.pr_number}`,
      severity:"P1", source:"secret", status:"firing", channel:"slack",
      repo:f.repo, scan_id:f.scan_id, pr_number:f.pr_number,
      fired_at: h(f.file_path, 2),
      title:`CRITICAL file unattested — ${f.file_path.split("/").pop()}`,
      body:`${f.file_path} in ${f.repo.split("/").pop()} is ${(f.ai_pct*100).toFixed(0)}% AI and flagged CRITICAL. Merge is blocked until attested.`,
      escalation:["security@trustledger.local"],
      runbook:"/audit",
      notes:[], history:[{ action:"Alert created", at: h(f.file_path, 2) }],
    });
  });

  // P1 — deploy blocked
  if (data.unattested_deploy_count > 0) {
    alerts.push({
      id:"deploy-blocked", group_id:"deploygate",
      severity:"P1", source:"policy", status:"firing", channel:"in-app",
      fired_at: h("deploy", 3),
      title:`${data.unattested_deploy_count} deploy${data.unattested_deploy_count>1?"s":""} blocked by policy gate`,
      body:`${data.unattested_deploy_count} deployment${data.unattested_deploy_count>1?"s":""} are blocked. Attest all CRITICAL and HIGH files to unblock merges.`,
      escalation:["devops@trustledger.local"],
      notes:[], history:[{ action:"Alert created", at: h("deploy", 3) }],
    });
  }

  // P1 — AI threshold critical repos
  data.repos.filter(r => r.ai_pct > 0.85).forEach(r => {
    alerts.push({
      id:`ai-critical-${r.repo}`, group_id:`repo-${r.repo}`,
      severity:"P1", source:"anomaly", status:"firing", channel:"slack",
      repo:r.repo, fired_at: h(r.repo, 6),
      title:`Critical AI threshold — ${r.repo.split("/").pop()} at ${(r.ai_pct*100).toFixed(0)}%`,
      body:`${r.repo.split("/").pop()} average AI content (${(r.ai_pct*100).toFixed(0)}%) exceeds the critical 85% threshold. Immediate governance review required.`,
      escalation:["ciso@trustledger.local","security@trustledger.local"],
      notes:[], history:[{ action:"Alert created", at: h(r.repo, 6) }],
    });
  });

  // P2 — HIGH unattested files
  data.top_risk_files.filter(f => !f.attested && f.risk_score === "HIGH").slice(0, 3).forEach(f => {
    alerts.push({
      id:`high-${f.scan_id}-${f.file_path}`, group_id:`pr-${f.pr_number}`,
      severity:"P2", source:"policy", status:"firing", channel:"email",
      repo:f.repo, scan_id:f.scan_id, pr_number:f.pr_number,
      fired_at: h(f.file_path+"high", 12),
      title:`HIGH-risk file awaiting attestation — ${f.file_path.split("/").pop()}`,
      body:`${f.file_path.split("/").pop()} (HIGH, ${(f.ai_pct*100).toFixed(0)}% AI) has not been attested. 48h SLA window.`,
      escalation:["team-lead@trustledger.local"],
      notes:[], history:[{ action:"Alert created", at: h(f.file_path+"high", 12) }],
    });
  });

  // P2 — SLA breach
  data.top_risk_files.filter(f => !f.attested && f.risk_score === "CRITICAL").slice(0,2).forEach(f => {
    const firedMs = now - 50 * 3600_000;
    alerts.push({
      id:`sla-${f.scan_id}-${f.file_path}`, group_id:`pr-${f.pr_number}`,
      severity:"P2", source:"sla", status:"firing", channel:"slack",
      repo:f.repo, scan_id:f.scan_id, pr_number:f.pr_number,
      fired_at: new Date(firedMs).toISOString(),
      title:`SLA breach — ${f.file_path.split("/").pop()} unattested 50+ hours`,
      body:`${f.file_path.split("/").pop()} (CRITICAL) has exceeded the 24h attestation SLA. Escalating to security lead.`,
      escalation:["security@trustledger.local","ciso@trustledger.local"],
      notes:[], history:[{ action:"Alert created", at: new Date(firedMs).toISOString() }],
    });
  });

  // P2 — AI content spike
  data.repos.filter(r => r.ai_pct > 0.7 && r.ai_pct <= 0.85).forEach(r => {
    alerts.push({
      id:`ai-spike-${r.repo}`, group_id:`repo-${r.repo}`,
      severity:"P2", source:"anomaly", status:"firing", channel:"email",
      repo:r.repo, fired_at: h(r.repo+"spike", 8),
      title:`AI content spike — ${r.repo.split("/").pop()} at ${(r.ai_pct*100).toFixed(0)}%`,
      body:`${r.repo.split("/").pop()} crossed the 70% AI content threshold. Additional human oversight recommended before next release.`,
      notes:[], history:[{ action:"Alert created", at: h(r.repo+"spike", 8) }],
    });
  });

  // P3 — Low attestation coverage
  data.repos.filter(r => r.attestation_rate < 0.6 && r.scan_count > 0).forEach(r => {
    alerts.push({
      id:`low-att-${r.repo}`, group_id:`repo-${r.repo}`,
      severity:"P3", source:"policy", status:"firing", channel:"in-app",
      repo:r.repo, fired_at: h(r.repo+"att", 24),
      title:`Low attestation coverage — ${r.repo.split("/").pop()} at ${Math.round(r.attestation_rate*100)}%`,
      body:`${r.repo.split("/").pop()} attestation rate (${Math.round(r.attestation_rate*100)}%) is below the 60% minimum. Assign reviewers to clear the backlog.`,
      notes:[], history:[{ action:"Alert created", at: h(r.repo+"att", 24) }],
    });
  });

  // P4 — repo connected / healthy
  data.repos.filter(r => r.attestation_rate >= 0.9).forEach(r => {
    alerts.push({
      id:`healthy-${r.repo}`,
      severity:"P4", source:"scan", status:"resolved", channel:"in-app",
      repo:r.repo, fired_at: h(r.repo+"ok", 48),
      resolved_at: h(r.repo+"ok-res", 46),
      title:`${r.repo.split("/").pop()} — attestation target met`,
      body:`${r.repo.split("/").pop()} has reached ${Math.round(r.attestation_rate*100)}% attestation coverage. No action required.`,
      notes:[], history:[
        { action:"Alert created",  at: h(r.repo+"ok", 48) },
        { action:"Auto-resolved",  at: h(r.repo+"ok-res", 46) },
      ],
    });
  });

  return alerts;
}


// ── Styles ─────────────────────────────────────────────────────────────────────

const SEV_STYLE: Record<AlertSeverity, { bg:string; text:string; border:string; dot:string; ring:string }> = {
  P1: { bg:"#fef2f2", text:"#be123c", border:"#fecdd3", dot:"#ef4444", ring:"rgba(239,68,68,0.2)" },
  P2: { bg:"#fffbeb", text:"#b45309", border:"#fde68a", dot:"#f59e0b", ring:"rgba(245,158,11,0.2)" },
  P3: { bg:"#eff6ff", text:"#1d4ed8", border:"#bfdbfe", dot:"#3b82f6", ring:"rgba(59,130,246,0.2)" },
  P4: { bg:"#f0fdf4", text:"#15803d", border:"#bbf7d0", dot:"#22c55e", ring:"rgba(34,197,94,0.2)"  },
};

const STATUS_STYLE: Record<AlertStatus, { bg:string; text:string; border:string; label:string }> = {
  firing:       { bg:"#fef2f2", text:"#be123c", border:"#fecdd3", label:"Firing"       },
  acknowledged: { bg:"#fffbeb", text:"#b45309", border:"#fde68a", label:"Acknowledged" },
  snoozed:      { bg:"#f0f9ff", text:"#0369a1", border:"#bae6fd", label:"Snoozed"      },
  resolved:     { bg:"#f0fdf4", text:"#15803d", border:"#bbf7d0", label:"Resolved"     },
};

const SOURCE_ICON: Record<AlertSource, JSX.Element> = {
  scan:    <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>,
  policy:  <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>,
  secret:  <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>,
  dependency:<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/></svg>,
  sla:     <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>,
  anomaly: <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>,
  exploit: <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>,
};

const CH_COLOR: Record<Alert["channel"], string> = {
  slack:"#4A154B", email:"#1d4ed8", webhook:"#475569", "in-app":"#6366f1",
};

const SNOOZE_OPTIONS = [
  { label:"1 hour",   ms: 1 * 3600_000 },
  { label:"4 hours",  ms: 4 * 3600_000 },
  { label:"24 hours", ms: 24 * 3600_000 },
  { label:"72 hours", ms: 72 * 3600_000 },
];

const SOURCE_LABEL: Record<AlertSource, string> = {
  scan: "Scan", policy: "Policy", secret: "Secret", dependency: "Dependency",
  sla: "SLA Breach", anomaly: "Anomaly", exploit: "Exploit",
};

// ── SLA countdown ──────────────────────────────────────────────────────────────

function SLAClock({ firedAt, severity, status }: { firedAt: string; severity: AlertSeverity; status: AlertStatus }) {
  const [now, setNow] = useState<number | null>(null);
  useEffect(() => {
    setNow(Date.now());
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, []);
  if (status === "resolved" || now === null) return null;
  const elapsed = now - new Date(firedAt).getTime();
  const sla     = SLA_MS[severity];
  const left    = sla - elapsed;
  const over    = left < 0;
  const abs     = Math.abs(left);
  const h       = Math.floor(abs / 3600_000);
  const m       = Math.floor((abs % 3600_000) / 60_000);
  const s       = Math.floor((abs % 60_000) / 1000);
  const display = h > 0 ? `${h}h ${m}m` : `${m}m ${s}s`;
  const urgent  = !over && left < sla * 0.2;
  return (
    <span className={`inline-flex items-center gap-1 text-[10px] font-black px-2 py-0.5 rounded-full tabular-nums ${
      over   ? "text-rose-700 bg-rose-50 border border-rose-200 animate-pulse" :
      urgent ? "text-orange-700 bg-orange-50 border border-orange-200" :
               "text-gray-500 bg-gray-50 border border-gray-200"
    }`}>
      <svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">
        <circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>
      </svg>
      SLA: {over ? `${display} over` : display}
    </span>
  );
}

// ── Page ───────────────────────────────────────────────────────────────────────

export default function AlertsPage() {
    const tz = useTimezone();
  const { success, info, warning } = useToastHelpers();
  const { profile } = useAuth();
  const [baseAlerts,  setBaseAlerts]  = useState<Alert[]>([]);
  const [loadError,   setLoadError]   = useState<string | null>(null);
  const [persisted,   setPersisted]   = useState<PersistedState>({ statuses:{}, ackBy:{}, snoozeUntil:{}, resolvedAt:{}, notes:{}, history:{} });
  const [refreshing,  setRefreshing]  = useState(false);
  const [lastRefreshed, setLastRefreshed] = useState<Date | null>(null);
  const [filterSev,   setFilterSev]   = useState<AlertSeverity | "all">("all");
  const [filterStat,  setFilterStat]  = useState<AlertStatus | "all">("all");
  const [filterSrc,   setFilterSrc]   = useState<AlertSource | "all">("all");
  const [search,      setSearch]      = useState("");
  const [expanded,    setExpanded]    = useState<string | null>(null);
  const [selected,    setSelected]    = useState<Set<string>>(new Set());
  const [noteInput,   setNoteInput]   = useState<Record<string, string>>({});
  const [snoozeMenu,  setSnoozeMenu]  = useState<string | null>(null);
  const snoozeRef = useRef<HTMLDivElement>(null);

  // Load persisted state
  useEffect(() => { setPersisted(loadState()); }, []);

  // Click outside to close snooze menu
  useEffect(() => {
    const fn = (e: MouseEvent) => { if (snoozeRef.current && !snoozeRef.current.contains(e.target as Node)) setSnoozeMenu(null); };
    document.addEventListener("mousedown", fn);
    return () => document.removeEventListener("mousedown", fn);
  }, []);

  const fetchAlerts = useCallback(async (spinner = false) => {
    if (spinner) setRefreshing(true);
    const orgSlug = profile?.org_slug || "";

    // Try real API first when authenticated
    if (profile?.org_id) {
      try {
        const res = await authedFetch<{ alerts: Alert[] }>("/api/alerts?limit=200");
        if (res.alerts.length > 0) {
          // Deduplicate: for the same scan + alert_type, keep only the most recent.
          // This collapses the N duplicate SLA breach alerts (one per cron run) into one.
          const deduped = new Map<string, Alert>();
          for (const a of res.alerts) {
            const key = a.scan_id ? `${a.scan_id}::${a.source}` : a.id;
            const prev = deduped.get(key);
            if (!prev || new Date(a.fired_at) > new Date(prev.fired_at)) {
              deduped.set(key, a);
            }
          }
          setBaseAlerts(Array.from(deduped.values()));
          setLoadError(null);
          setLastRefreshed(new Date());
          if (spinner) setRefreshing(false);
          return;
        }
      } catch { /* fall through to derived */ }
    }

    // No fired alerts on record — derive from risk state.
    const seed = readSeed();
    const data = seed ?? await api.dashboard(orgSlug || "org", 90).catch(() => null);
    if (data) {
      // If we're authenticated, fetch the REAL open violation count from the DB.
      // This is authoritative — if the DB says 0 open violations, patch the
      // dashboard data so no false-positive alerts fire (catches cases where
      // localStorage was cleared but attestations are persisted in Supabase).
      let patchedData = patchDataWithAttestations(data);

      if (profile?.org_id) {
        try {
          const { violations: openViolations } = await authedFetch<{ violations: { file_path: string; risk_score: string; scan_id: string }[] }>(
            "/api/violations?status=open&limit=200"
          );
          const openSet = new Set(
            (openViolations ?? []).map(v => `${v.scan_id}::${v.file_path}`)
          );
          // If DB says 0 open violations, mark all top_risk_files as attested
          // so deriveAlerts produces no firing alerts for unattested files.
          if (openSet.size === 0) {
            patchedData = {
              ...patchedData,
              unattested_deploy_count: 0,
              top_risk_files: patchedData.top_risk_files.map(f => ({ ...f, attested: true })),
            };
          } else {
            // Partial patch: only mark files NOT in the open set as attested
            patchedData = {
              ...patchedData,
              unattested_deploy_count: openSet.size > 0 ? data.unattested_deploy_count : 0,
              top_risk_files: patchedData.top_risk_files.map(f => {
                const key = `${f.scan_id}::${f.file_path}`;
                return openSet.has(key) ? f : { ...f, attested: true };
              }),
            };
          }
        } catch { /* if violations API fails, use patched data as-is */ }
      }

      setBaseAlerts(deriveAlerts(patchedData));
      setLoadError(null);
      setLastRefreshed(new Date());
    } else if (profile?.org_id) {
      setBaseAlerts([]);
      setLoadError("Unable to load alerts. Check your connection and try again.");
    }
    if (spinner) setRefreshing(false);
  }, [profile?.org_id, profile?.org_slug]);

  useEffect(() => {
    fetchAlerts();
    const id = setInterval(() => fetchAlerts(), 30_000);

    // Re-derive immediately when violation statuses change (cross-tab or same-tab)
    const onStorage = (e: StorageEvent | Event) => {
      const key = (e as StorageEvent).key;
      if (!key || key === "tl_violation_statuses") fetchAlerts(false);
    };
    window.addEventListener("storage", onStorage);
    window.addEventListener("tl:attestation", onStorage);
    // Immediate refresh when PR page attestAll() completes
    const onAttestComplete = () => fetchAlerts(false);
    window.addEventListener("tl:attest-complete", onAttestComplete);

    return () => {
      clearInterval(id);
      window.removeEventListener("storage", onStorage);
      window.removeEventListener("tl:attestation", onStorage);
      window.removeEventListener("tl:attest-complete", onAttestComplete);
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [profile?.org_id]);

  // Realtime — refresh when alerts change in DB
  useAlertsRealtime(profile?.org_id, () => fetchAlerts(false));

  // Merge base alerts with persisted overrides
  const alerts = useMemo<Alert[]>(() =>
    baseAlerts.map(a => ({
      ...a,
      status:       persisted.statuses[a.id]   ?? a.status,
      acknowledged_by: persisted.ackBy[a.id]  ?? a.acknowledged_by,
      snooze_until: persisted.snoozeUntil[a.id]?? a.snooze_until,
      resolved_at:  persisted.resolvedAt[a.id] ?? a.resolved_at,
      notes:        persisted.notes[a.id]      ?? a.notes,
      history:      persisted.history[a.id]    ?? a.history,
    })),
  [baseAlerts, persisted]);

  function updatePersisted(id: string, patch: Partial<PersistedState>) {
    setPersisted(prev => {
      const next: PersistedState = {
        statuses:    { ...prev.statuses,    ...(patch.statuses    ?? {}) },
        ackBy:       { ...prev.ackBy,       ...(patch.ackBy       ?? {}) },
        snoozeUntil: { ...prev.snoozeUntil, ...(patch.snoozeUntil ?? {}) },
        resolvedAt:  { ...prev.resolvedAt,  ...(patch.resolvedAt  ?? {}) },
        notes:       { ...prev.notes,       ...(patch.notes       ?? {}) },
        history:     { ...prev.history,     ...(patch.history     ?? {}) },
      };
      saveState(next);
      return next;
    });
  }

  function addHistory(id: string, action: string, note?: string) {
    const a = alerts.find(x => x.id === id);
    const prev = a?.history ?? [];
    const entry: AlertHistoryEntry = { action, by: getReviewerEmail(profile?.email), at: new Date().toISOString(), note };
    updatePersisted(id, { history:{ [id]: [...prev, entry] } });
  }

  function act(ids: string[], status: AlertStatus, snoozeMs?: number, note?: string) {
    // Skip alerts already in the target status to prevent duplicate history entries
    const activeIds = ids.filter(id => {
      const cur = persisted.statuses[id] ?? alerts.find(a => a.id === id)?.status ?? "firing";
      return cur !== status;
    });
    if (activeIds.length === 0) return;

    const now = new Date().toISOString();
    activeIds.forEach(id => {
      const statuses    = { [id]: status };
      const ackBy       = status === "acknowledged"                       ? { [id]: getReviewerEmail(profile?.email) } : {};
      const snoozeUntil = status === "snoozed" && snoozeMs               ? { [id]: new Date(Date.now() + snoozeMs).toISOString() } : {};
      const resolvedAt  = status === "resolved"                           ? { [id]: now } : {};
      updatePersisted(id, { statuses, ackBy, snoozeUntil, resolvedAt });
      const label = status === "snoozed" && snoozeMs
        ? `Snoozed ${SNOOZE_OPTIONS.find(o => o.ms === snoozeMs)?.label ?? ""}`
        : status.charAt(0).toUpperCase() + status.slice(1);
      addHistory(id, label, note);
    });

    // For real DB alerts (UUID format), call PATCH /api/alerts so the
    // resolved status persists in Supabase and doesn't come back on refresh.
    if (profile?.org_id) {
      const isUUID = (id: string) => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id);
      activeIds.filter(isUUID).forEach(id => {
        const snoozeHours = snoozeMs ? Math.round(snoozeMs / 3600_000) : undefined;
        authedFetch("/api/alerts", {
          method: "PATCH",
          body: JSON.stringify({ id, status, ...(snoozeHours ? { snooze_hours: snoozeHours } : {}), note }),
        }).catch(() => { /* non-fatal — localStorage state is source of truth for UI */ });
      });
    }
    setSelected(new Set());
    setSnoozeMenu(null);

    // If viewing the "firing" tab, switch to "all" so the state change is visible.
    // Without this, acknowledged/resolved alerts silently vanish, making it look like nothing happened.
    if (filterStat === "firing" && (status === "acknowledged" || status === "snoozed")) {
      setFilterStat("all");
    }
    if (filterStat === "firing" && status === "resolved") {
      setFilterStat("resolved");
    }
    // Expand a single acknowledged alert so the Resolve button is immediately visible
    if (activeIds.length === 1 && status === "acknowledged") {
      setExpanded(activeIds[0]);
    }

    // Toast feedback
    const count = activeIds.length;
    const label = status === "snoozed" && snoozeMs
      ? `Snoozed ${SNOOZE_OPTIONS.find(o => o.ms === snoozeMs)?.label ?? ""}`
      : status;
    if (status === "resolved")          success(`${count > 1 ? count + " alerts" : "Alert"} resolved`, "Moved to resolved status");
    else if (status === "acknowledged") info(`${count > 1 ? count + " alerts" : "Alert"} acknowledged`, "Resolve it when the underlying issue is fixed");
    else if (status === "snoozed")      warning(`${count > 1 ? count + " alerts" : "Alert"} snoozed`, label);
    else if (status === "firing")       info("Alert re-fired", "Back in the active queue");
  }

  function addNote(id: string) {
    const text = noteInput[id]?.trim();
    if (!text) return;
    const a = alerts.find(x => x.id === id);
    const prev = a?.notes ?? [];
    updatePersisted(id, { notes: { [id]: [...prev, `${getReviewerEmail(profile?.email)}: ${text}`] } });
    addHistory(id, "Note added", text);
    success("Note saved", text.slice(0, 50));
    setNoteInput(p => ({ ...p, [id]:"" }));
  }

  const filtered = useMemo(() => alerts.filter(a => {
    if (filterSev  !== "all" && a.severity !== filterSev)  return false;
    if (filterStat !== "all" && a.status   !== filterStat) return false;
    if (filterSrc  !== "all" && a.source   !== filterSrc)  return false;
    if (search) { const q = search.toLowerCase(); if (![a.title, a.body, a.repo ?? ""].join(" ").toLowerCase().includes(q)) return false; }
    return true;
  }), [alerts, filterSev, filterStat, filterSrc, search]);

  // Group related alerts
  const grouped = useMemo(() => {
    const groups: Map<string, Alert[]> = new Map();
    const ungrouped: Alert[] = [];
    filtered.forEach(a => {
      if (a.group_id) { if (!groups.has(a.group_id)) groups.set(a.group_id, []); groups.get(a.group_id)!.push(a); }
      else ungrouped.push(a);
    });
    return { groups, ungrouped };
  }, [filtered]);

  const firing   = alerts.filter(a => a.status === "firing").length;
  const p1       = alerts.filter(a => a.severity === "P1" && a.status === "firing").length;
  const acked    = alerts.filter(a => a.status === "acknowledged").length;
  const snoozed  = alerts.filter(a => a.status === "snoozed").length;
  const resolvedToday = alerts.filter(a => { if (!a.resolved_at) return false; const d = new Date(a.resolved_at); const n = new Date(); return d.toDateString() === n.toDateString(); }).length;

  const allFilteredIds = filtered.map(a => a.id);
  const allSelected    = allFilteredIds.length > 0 && allFilteredIds.every(id => selected.has(id));
  const someSelected   = selected.size > 0;

  const refreshAgo = lastRefreshed ? (() => { const s = Math.floor((Date.now()-lastRefreshed.getTime())/1000); return s<10?"just now":s<60?`${s}s ago`:`${Math.floor(s/60)}m ago`; })() : "";

  function renderAlert(alert: Alert) {
    const sev  = SEV_STYLE[alert.severity];
    const stat = STATUS_STYLE[alert.status];
    const open = expanded === alert.id;
    const isSel = selected.has(alert.id);

    const snoozedUntil = alert.status === "snoozed" && alert.snooze_until
      ? (() => {
          const diff = new Date(alert.snooze_until).getTime() - Date.now();
          if (diff <= 0) return "snooze expired";
          const h = Math.floor(diff / 3600000);
          const m = Math.floor((diff % 3600000) / 60000);
          return h > 0 ? `until ${h}h ${m}m` : `until ${m}m`;
        })()
      : null;

    return (
      <div key={alert.id}
        className={`overflow-hidden rounded-xl transition-all ${isSel ? "ring-2 ring-indigo-300" : ""}`}
        style={{ boxShadow: "0 1px 5px rgba(0,0,0,0.06)" }}>
        <div className="flex">
          {/* Left severity accent */}
          <div className="w-1 shrink-0 rounded-l-xl" style={{ background: sev.dot, opacity: alert.status === "resolved" ? 0.35 : 1 }} />

          {/* Card body */}
          <div className={`flex-1 flex items-start gap-3 px-5 py-4 transition-colors ${open ? "bg-gray-50/60" : "bg-white hover:bg-gray-50/50"}`}>
            {/* Checkbox */}
            <input type="checkbox" checked={isSel} onChange={e => {
              setSelected(prev => { const n = new Set(prev); e.target.checked ? n.add(alert.id) : n.delete(alert.id); return n; });
            }} className="mt-1 shrink-0 w-3.5 h-3.5 rounded accent-indigo-600 cursor-pointer" />

            {/* Source icon */}
            <div className="w-8 h-8 rounded-xl flex items-center justify-center shrink-0 mt-0.5 border"
              style={{ background: sev.bg, color: sev.dot, borderColor: sev.border }}>
              {SOURCE_ICON[alert.source]}
            </div>

            {/* Content */}
            <div className="flex-1 min-w-0 space-y-1.5 cursor-pointer" onClick={() => setExpanded(open ? null : alert.id)}>
              <div className="flex items-center gap-1.5 flex-wrap">
                <span className="text-[9px] font-black px-1.5 py-0.5 rounded-full text-white" style={{ background: sev.dot }}>
                  {alert.severity}
                </span>
                <span className="text-[9px] font-bold px-2 py-0.5 rounded-full border"
                  style={{ background: stat.bg, color: stat.text, borderColor: stat.border }}>
                  {stat.label}
                </span>
                <span className="text-[9px] font-semibold text-gray-400 bg-gray-50 px-1.5 py-0.5 rounded border border-gray-100">
                  {SOURCE_LABEL[alert.source]}
                </span>
                {alert.channel !== "in-app" && (
                  <span className="text-[9px] font-bold px-1.5 py-0.5 rounded text-white" style={{ background: CH_COLOR[alert.channel] }}>
                    {alert.channel}
                  </span>
                )}
                {snoozedUntil && (
                  <span className="text-[9px] font-semibold text-sky-700 bg-sky-50 border border-sky-200 px-1.5 py-0.5 rounded">
                    ⏸ {snoozedUntil}
                  </span>
                )}
              </div>

              <p className="text-sm font-bold text-gray-900 leading-snug">{alert.title}</p>

              {!open && <p className="text-xs text-gray-500 truncate">{alert.body}</p>}

              <div className="flex items-center gap-3 flex-wrap">
                {alert.repo && (
                  <span className="text-[10px] font-mono text-indigo-600 bg-indigo-50 border border-indigo-100 px-1.5 py-0.5 rounded">
                    {alert.repo.split("/").pop()}
                  </span>
                )}
                {alert.pr_number && alert.scan_id && (
                  <Link href={`/pr/${alert.scan_id}`} onClick={e => e.stopPropagation()}
                    className="text-[10px] font-bold text-indigo-600 hover:text-indigo-800">PR #{alert.pr_number} →</Link>
                )}
                {alert.acknowledged_by && (
                  <span className="text-[10px] text-gray-500 flex items-center gap-1">
                    <svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                    ack&apos;d by {alert.acknowledged_by.split("@")[0]}
                  </span>
                )}
                <span suppressHydrationWarning className="text-[10px] text-gray-400">
                  {(() => { const s = Math.floor((Date.now()-new Date(alert.fired_at).getTime())/1000); return s<3600?`${Math.floor(s/60)}m ago`:s<86400?`${Math.floor(s/3600)}h ago`:`${Math.floor(s/86400)}d ago`; })()}
                </span>
                {alert.notes.length > 0 && (
                  <span className="text-[9px] font-semibold text-gray-500 bg-gray-100 border border-gray-200 px-1.5 py-0.5 rounded">
                    💬 {alert.notes.length} note{alert.notes.length !== 1 ? "s" : ""}
                  </span>
                )}
              </div>
            </div>

            {/* SLA + Actions */}
            <div className="shrink-0 flex flex-col items-end gap-2" onClick={e => e.stopPropagation()}>
              <SLAClock firedAt={alert.fired_at} severity={alert.severity} status={alert.status} />
              <div className="flex items-center gap-1.5 flex-wrap justify-end">
                {alert.status === "firing" && (
                  <>
                    <button onClick={() => act([alert.id], "acknowledged")}
                      className="text-[10px] font-bold text-amber-700 bg-amber-50 border border-amber-200 px-2.5 py-1 rounded-lg hover:bg-amber-100 transition-colors whitespace-nowrap">
                      Acknowledge
                    </button>
                    <div className="relative" ref={snoozeMenu === alert.id ? snoozeRef : null}>
                      <button onClick={() => setSnoozeMenu(snoozeMenu === alert.id ? null : alert.id)}
                        className="text-[10px] font-bold text-sky-700 bg-sky-50 border border-sky-200 px-2.5 py-1 rounded-lg hover:bg-sky-100 transition-colors whitespace-nowrap flex items-center gap-1">
                        Snooze
                        <svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><polyline points="6 9 12 15 18 9"/></svg>
                      </button>
                      {snoozeMenu === alert.id && (
                        <div className="absolute right-0 top-full mt-1 bg-white border border-gray-200 rounded-xl shadow-lg z-20 overflow-hidden w-32">
                          {SNOOZE_OPTIONS.map(o => (
                            <button key={o.label} onClick={() => act([alert.id], "snoozed", o.ms)}
                              className="w-full text-left px-3 py-2 text-xs font-semibold text-gray-700 hover:bg-gray-50 transition-colors border-b border-gray-50 last:border-0">
                              {o.label}
                            </button>
                          ))}
                        </div>
                      )}
                    </div>
                  </>
                )}
                {alert.status === "acknowledged" && (
                  <button onClick={() => act([alert.id], "resolved")}
                    className="text-[10px] font-bold text-emerald-700 bg-emerald-50 border border-emerald-200 px-2.5 py-1 rounded-lg hover:bg-emerald-100 transition-colors whitespace-nowrap">
                    Resolve
                  </button>
                )}
                {alert.status === "snoozed" && (
                  <button onClick={() => act([alert.id], "firing")}
                    className="text-[10px] font-semibold text-gray-600 bg-gray-50 border border-gray-200 px-2.5 py-1 rounded-lg hover:bg-gray-100 transition-colors whitespace-nowrap">
                    Un-snooze
                  </button>
                )}
                {alert.status === "resolved" && (
                  <button onClick={() => act([alert.id], "firing")}
                    className="text-[10px] font-semibold text-gray-400 hover:text-rose-600 px-2.5 py-1 rounded-lg hover:bg-rose-50 transition-colors whitespace-nowrap">
                    Re-fire
                  </button>
                )}
                <button onClick={() => setExpanded(open ? null : alert.id)}
                  className="text-gray-300 hover:text-gray-500 p-1">
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"
                    style={{ transform: open ? "rotate(180deg)" : "none", transition: "transform 0.2s" }}>
                    <polyline points="6 9 12 15 18 9"/>
                  </svg>
                </button>
              </div>
            </div>
          </div>
        </div>

        {/* Expanded panel */}
        {open && (
          <div className="border-t border-gray-100 space-y-4 px-5 py-4" style={{ background:"rgba(248,250,252,0.8)" }}>
            {/* Full body */}
            <div>
              <p className="text-[10px] font-black uppercase tracking-widest text-gray-400 mb-1.5">Alert Details</p>
              <p className="text-xs text-gray-700 leading-relaxed">{alert.body}</p>
            </div>

            {/* Escalation + runbook */}
            {(alert.escalation || alert.runbook) && (
              <div className="flex items-start gap-6 flex-wrap">
                {alert.escalation && alert.escalation.length > 0 && (
                  <div>
                    <p className="text-[9px] font-black uppercase tracking-widest text-gray-400 mb-2">Escalation Path</p>
                    <div className="flex gap-1.5 flex-wrap">
                      {alert.escalation.map(e => {
                        const name    = e.split("@")[0];
                        const initial = name.charAt(0).toUpperCase();
                        const colors  = ["#6366f1","#8b5cf6","#ec4899","#0891b2","#ef4444","#10b981"];
                        const color   = colors[name.charCodeAt(0) % colors.length];
                        return (
                          <div key={e} className="flex items-center gap-1.5 bg-white border border-gray-100 rounded-lg px-2 py-1">
                            <div className="w-5 h-5 rounded-full flex items-center justify-center text-[9px] font-black text-white shrink-0"
                              style={{ background: color }}>{initial}</div>
                            <span className="text-[10px] font-semibold text-gray-700">{name}</span>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}
                {alert.runbook && (
                  <div>
                    <p className="text-[9px] font-black uppercase tracking-widest text-gray-400 mb-2">Runbook</p>
                    <a href={alert.runbook} target="_blank" rel="noopener noreferrer"
                      className="flex items-center gap-1.5 text-[10px] font-bold text-indigo-600 hover:text-indigo-800 bg-indigo-50 border border-indigo-100 rounded-lg px-2.5 py-1.5 w-fit">
                      <svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M2 3h6a4 4 0 0 1 4 4v14a3 3 0 0 0-3-3H2z"/><path d="M22 3h-6a4 4 0 0 0-4 4v14a3 3 0 0 1 3-3h7z"/>
                      </svg>
                      {alert.runbook.replace("https://","").split("/").pop()} ↗
                    </a>
                  </div>
                )}
              </div>
            )}

            {/* Notes */}
            <div>
              <p className="text-[10px] font-black uppercase tracking-widest text-gray-400 mb-2">Notes</p>
              {alert.notes.length > 0 && (
                <div className="space-y-1.5 mb-2">
                  {alert.notes.map((n, i) => {
                    const colonIdx = n.indexOf(": ");
                    const author   = colonIdx > 0 ? n.slice(0, colonIdx) : "";
                    const text     = colonIdx > 0 ? n.slice(colonIdx + 2) : n;
                    const initial  = author ? author.charAt(0).toUpperCase() : "?";
                    return (
                      <div key={i} className="flex items-start gap-2 bg-white rounded-lg px-3 py-2 border border-gray-100">
                        {author && (
                          <div className="w-5 h-5 rounded-full bg-indigo-500 flex items-center justify-center text-[9px] font-black text-white shrink-0 mt-0.5">
                            {initial}
                          </div>
                        )}
                        <div className="min-w-0">
                          {author && <p className="text-[9px] font-bold text-indigo-600 mb-0.5">{author.split("@")[0]}</p>}
                          <p className="text-[11px] text-gray-600">{text}</p>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
              <div className="flex gap-2">
                <input value={noteInput[alert.id] ?? ""} onChange={e => setNoteInput(p => ({...p,[alert.id]:e.target.value}))}
                  onKeyDown={e => { if (e.key === "Enter") addNote(alert.id); }}
                  placeholder="Add a note (Enter to save)…"
                  className="flex-1 text-xs border border-gray-200 rounded-lg px-3 py-2 focus:outline-none focus:ring-2 focus:ring-indigo-400 bg-white" />
                <button onClick={() => addNote(alert.id)}
                  className="text-xs font-bold text-indigo-700 bg-indigo-50 border border-indigo-200 px-3 py-2 rounded-lg hover:bg-indigo-100 transition-colors">
                  Save
                </button>
              </div>
            </div>

            {/* Timeline */}
            <div>
              <p className="text-[10px] font-black uppercase tracking-widest text-gray-400 mb-2">Timeline</p>
              <div className="relative">
                {alert.history.length > 1 && (
                  <div className="absolute left-[4px] top-3 bottom-3 w-px bg-gray-100" />
                )}
                <div className="space-y-2.5">
                  {[...alert.history].reverse().map((h, i) => {
                    const isLatest = i === 0;
                    return (
                      <div key={i} className="flex items-start gap-2.5">
                        <div className={`w-2.5 h-2.5 rounded-full shrink-0 mt-0.5 z-10 border-2 ${isLatest ? "border-indigo-500 bg-indigo-500" : "border-gray-300 bg-white"}`} />
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="text-[9px] font-mono text-gray-400">
                              {new Date(h.at).toLocaleTimeString("en-GB",{hour:"2-digit",minute:"2-digit"})}
                            </span>
                            <span className={`text-[10px] font-semibold ${isLatest ? "text-gray-800" : "text-gray-600"}`}>{h.action}</span>
                            {h.by && <span className="text-[9px] text-gray-400 ml-auto">{h.by.split("@")[0]}</span>}
                          </div>
                          {h.note && <p className="text-[10px] text-gray-500 italic mt-0.5">&quot;{h.note}&quot;</p>}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>

            {/* Snooze info */}
            {alert.status === "snoozed" && alert.snooze_until && (
              <div className="flex items-center gap-2 text-[10px] text-sky-700 bg-sky-50 border border-sky-200 rounded-xl px-3 py-2">
                <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                  <rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
                </svg>
                Snoozed until {formatDateTime(new Date(alert.snooze_until), tz)}
              </div>
            )}
          </div>
        )}
      </div>
    );
  }

  return (
    <AuthGuard>
      <PageSkeleton rows={6} cards={4}>
      <div className="max-w-5xl mx-auto space-y-5 pb-10">

        {/* Header */}
        <div className="animate-fade-up flex items-start justify-between gap-4 flex-wrap">
          <div>
            <div className="flex items-center gap-2.5 mb-1">
              <div className="w-8 h-8 rounded-xl flex items-center justify-center relative"
                style={{ background:"rgba(239,68,68,0.1)", border:"1px solid rgba(239,68,68,0.2)" }}>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#ef4444" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/>
                  <path d="M13.73 21a2 2 0 0 1-3.46 0"/>
                </svg>
                {firing > 0 && (
                  <span className="absolute -top-1 -right-1 w-4 h-4 rounded-full bg-rose-500 text-[8px] font-black text-white flex items-center justify-center">
                    {firing > 9 ? "9+" : firing}
                  </span>
                )}
              </div>
              <h1 className="text-xl font-black text-gray-900 tracking-tight">Security Alerts</h1>
              {p1 > 0 && <span className="text-xs font-black text-white bg-rose-500 px-2 py-0.5 rounded-full animate-pulse">{p1} P1 firing</span>}
            </div>
            <p className="text-sm text-gray-400">Real-time incident management · live SLA countdowns · derived from scan data · auto-refreshes every 30 s</p>
          </div>
          <div className="flex flex-col items-end gap-0.5">
            <button onClick={() => fetchAlerts(true)} disabled={refreshing}
              className="flex items-center gap-1.5 px-3 py-2 text-xs font-semibold text-indigo-600 bg-indigo-50 border border-indigo-200 rounded-xl hover:bg-indigo-100 disabled:opacity-50 transition-all shadow-sm">
              <svg className={refreshing?"animate-spin":""} width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                <polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>
              </svg>
              {refreshing?"Refreshing…":"Refresh"}
            </button>
            {refreshAgo && <span className="text-[9px] text-gray-400">Updated {refreshAgo}</span>}
          </div>
        </div>

        {/* Summary — clickable */}
        <div className="animate-fade-up grid grid-cols-2 sm:grid-cols-4 gap-3">
          {([
            { label:"Firing",       value:firing,  color:"#ef4444", bg:"#fef2f2",
              active: filterStat==="firing" && filterSev==="all",
              onClick: () => { setFilterStat("firing"); setFilterSev("all"); },
              pulse: firing > 0,
              info:{ title:"Firing Alerts", description:"Alerts currently active and requiring attention. Auto-derived from scan data — new critical files or SLA breaches automatically create firing alerts." } },
            { label:"P1 Firing",   value:p1,      color:"#7c3aed", bg:"#ede9fe",
              active: filterSev==="P1" && filterStat==="firing",
              onClick: () => { setFilterSev("P1"); setFilterStat("firing"); },
              pulse: p1 > 0,
              info:{ title:"P1 — Critical", description:"P1 is the highest priority. These alerts have a 1-hour SLA and indicate immediate security risk (exposed secrets, hallucinated packages, CRITICAL unattested files)." } },
            { label:"Acknowledged", value:acked,  color:"#f59e0b", bg:"#fffbeb",
              active: filterStat==="acknowledged",
              onClick: () => { setFilterStat("acknowledged"); setFilterSev("all"); },
              pulse: false,
              info:{ title:"Acknowledged", description:"Alerts a reviewer has seen and is actively working on. Acknowledging does not resolve — the underlying issue still needs fixing." } },
            { label:"Snoozed",     value:snoozed, color:"#0891b2", bg:"#f0f9ff",
              active: filterStat==="snoozed",
              onClick: () => { setFilterStat("snoozed"); setFilterSev("all"); },
              pulse: false,
              info:{ title:"Snoozed", description:"Alerts temporarily silenced. Snoozed alerts are not resolved — they will re-fire when the snooze window expires." } },
          ]).map(s => (
            <button key={s.label} onClick={s.onClick}
              className="rounded-2xl p-4 border text-left transition-all hover:-translate-y-0.5 hover:shadow-md"
              style={{ background:s.bg, borderColor:s.active ? s.color : s.color+"30", boxShadow: s.active ? `0 0 0 2px ${s.color}40` : undefined }}>
              <div className="flex items-center gap-2">
                <p className="text-2xl font-black tabular-nums" style={{ color:s.color }}>{s.value}</p>
                {s.pulse && s.value > 0 && <span className="w-2 h-2 rounded-full animate-pulse shrink-0" style={{ background:s.color }} />}
              </div>
              <div className="flex items-center gap-1.5 mt-1">
                <p className="text-xs font-semibold text-gray-500">{s.label}</p>
                <InfoTooltip title={s.info.title} description={s.info.description} position="top" />
              </div>
            </button>
          ))}
        </div>

        {/* Bulk actions */}
        {someSelected && (
          <div className="animate-fade-up flex items-center gap-2 bg-indigo-50 border border-indigo-200 rounded-xl px-4 py-2.5">
            <span className="text-xs font-bold text-indigo-700">{selected.size} selected</span>
            <div className="h-4 w-px bg-indigo-200" />
            <button onClick={() => act(Array.from(selected), "acknowledged")}
              className="text-xs font-bold text-amber-700 bg-amber-50 border border-amber-200 px-2.5 py-1 rounded-lg hover:bg-amber-100 transition-colors">
              Bulk Acknowledge
            </button>
            <button onClick={() => act(Array.from(selected), "resolved")}
              className="text-xs font-bold text-emerald-700 bg-emerald-50 border border-emerald-200 px-2.5 py-1 rounded-lg hover:bg-emerald-100 transition-colors">
              Bulk Resolve
            </button>
            <button onClick={() => act(Array.from(selected), "snoozed", 4*3600_000)}
              className="text-xs font-bold text-sky-700 bg-sky-50 border border-sky-200 px-2.5 py-1 rounded-lg hover:bg-sky-100 transition-colors">
              Snooze 4h
            </button>
            <button onClick={() => setSelected(new Set())}
              className="ml-auto text-xs text-gray-400 hover:text-gray-600">
              Clear ✕
            </button>
          </div>
        )}

        {/* Filters */}
        <div className="animate-fade-up flex flex-wrap items-center gap-2">
          {/* Search */}
          <div className="flex items-center rounded-xl border border-gray-200 bg-white overflow-hidden">
            <svg className="ml-3 text-gray-400 shrink-0" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
            <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search alerts…"
              className="px-3 py-2 text-xs text-gray-700 bg-transparent outline-none w-44" />
            {search && <button onClick={() => setSearch("")} className="pr-2 text-gray-400 hover:text-gray-600 text-xs">✕</button>}
          </div>

          {/* Status tabs with live counts */}
          <div className="flex items-center gap-0.5 bg-gray-100 p-0.5 rounded-xl">
            {(["all","firing","acknowledged","snoozed","resolved"] as const).map(s => {
              const c = s === "all" ? alerts.length : alerts.filter(a => a.status === s).length;
              return (
                <button key={s} onClick={() => setFilterStat(s)}
                  className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg transition-all ${filterStat===s?"bg-white text-gray-900 shadow-sm":"text-gray-500 hover:text-gray-700"}`}>
                  {s==="all"?"All":s.charAt(0).toUpperCase()+s.slice(1)}
                  {c > 0 && <span className={`text-[9px] font-black px-1.5 py-0.5 rounded-full ${filterStat===s?"bg-gray-200 text-gray-700":"bg-gray-200/70 text-gray-500"}`}>{c}</span>}
                </button>
              );
            })}
          </div>

          {/* Priority */}
          <div className="flex items-center gap-0.5 bg-gray-100 p-0.5 rounded-xl">
            {(["all","P1","P2","P3","P4"] as const).map(p => (
              <button key={p} onClick={() => setFilterSev(p)}
                className={`px-3 py-1.5 text-xs font-semibold rounded-lg transition-all ${filterSev===p?"bg-white text-gray-900 shadow-sm":"text-gray-500 hover:text-gray-700"}`}>
                {p==="all"?"All":p}
              </button>
            ))}
          </div>

          {/* Source */}
          <select value={filterSrc} onChange={e => setFilterSrc(e.target.value as AlertSource | "all")}
            className="text-xs font-semibold text-gray-600 bg-white border border-gray-200 rounded-xl px-3 py-2 focus:outline-none">
            <option value="all">All Sources</option>
            {(["scan","policy","secret","dependency","sla","anomaly","exploit"] as AlertSource[]).map(s => (
              <option key={s} value={s}>{s.charAt(0).toUpperCase()+s.slice(1)}</option>
            ))}
          </select>

          {/* Select all */}
          <label className="flex items-center gap-1.5 text-xs text-gray-500 cursor-pointer ml-auto">
            <input type="checkbox" checked={allSelected} onChange={e => setSelected(e.target.checked ? new Set(allFilteredIds) : new Set())}
              className="w-3.5 h-3.5 rounded accent-indigo-600" />
            Select all
          </label>

          <span className="text-xs text-gray-400">{filtered.length} alerts</span>
        </div>

        {/* Load error banner */}
        {loadError && (
          <div className="animate-fade-up flex items-center justify-between gap-3 bg-rose-50 border border-rose-200 text-rose-800 px-4 py-3 rounded-xl text-sm font-medium">
            <span><span className="font-bold">Couldn&apos;t load alerts.</span> {loadError}</span>
            <button onClick={() => fetchAlerts(true)} className="shrink-0 text-rose-600 hover:text-rose-900 font-bold text-xs">Retry</button>
          </div>
        )}

        {/* Alert list */}
        <div className="animate-fade-up space-y-3">
          {filtered.length === 0 ? (
            <div className="section-card py-16 text-center">
              <div className="w-12 h-12 rounded-2xl bg-emerald-50 flex items-center justify-center text-emerald-500 mx-auto mb-3">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>
                </svg>
              </div>
              <p className="text-sm font-bold text-gray-700">No alerts match this filter</p>
              <button onClick={() => { setSearch(""); setFilterSev("all"); setFilterStat("all"); setFilterSrc("all"); }}
                className="mt-2 text-xs font-bold text-indigo-600 hover:text-indigo-800">Clear filters →</button>
            </div>
          ) : (
            <>
              {/* Grouped alerts */}
              {Array.from(grouped.groups.entries()).map(([gid, galerts]) => {
                const SEV_ORDER: AlertSeverity[] = ["P1","P2","P3","P4"];
                const maxSev = galerts.reduce<AlertSeverity>((m, a) => SEV_ORDER.indexOf(a.severity) < SEV_ORDER.indexOf(m) ? a.severity : m, "P4");
                const firingCount = galerts.filter(a => a.status === "firing").length;
                const groupType = gid.startsWith("pr-") ? "PR" : gid.startsWith("repo-") ? "Repo" : gid.startsWith("deploy") ? "Deploy" : "Group";
                const maxSevStyle = SEV_STYLE[maxSev];
                return (
                  <div key={gid} className="section-card overflow-hidden divide-y divide-gray-50">
                    <div className="flex items-center gap-2 px-5 py-2.5 border-b border-gray-100" style={{ background:"rgba(248,250,252,0.7)" }}>
                      <div className="w-5 h-5 rounded-full flex items-center justify-center text-[8px] font-black text-white shrink-0"
                        style={{ background: maxSevStyle.dot }}>{maxSev}</div>
                      <span className="text-[9px] font-bold text-gray-400">{groupType}</span>
                      <span className="text-[10px] font-bold font-mono text-gray-600 bg-white px-2 py-0.5 rounded border border-gray-200">#{gid}</span>
                      <span className="text-[9px] text-gray-400">{galerts.length} alert{galerts.length!==1?"s":""}</span>
                      {firingCount > 0 && (
                        <span className="text-[9px] font-black text-rose-600 bg-rose-50 border border-rose-200 px-1.5 py-0.5 rounded animate-pulse">
                          {firingCount} firing
                        </span>
                      )}
                      {firingCount > 1 && (
                        <button onClick={() => act(galerts.filter(a => a.status === "firing").map(a => a.id), "acknowledged")}
                          className="ml-auto text-[9px] font-bold text-amber-700 bg-amber-50 border border-amber-200 px-2 py-0.5 rounded-lg hover:bg-amber-100 transition-colors whitespace-nowrap">
                          Ack all {firingCount}
                        </button>
                      )}
                    </div>
                    {galerts.map(renderAlert)}
                  </div>
                );
              })}

              {/* Ungrouped alerts */}
              {grouped.ungrouped.length > 0 && (
                <div className="section-card overflow-hidden divide-y divide-gray-50">
                  {grouped.ungrouped.map(renderAlert)}
                </div>
              )}
            </>
          )}
        </div>

      </div>
      </PageSkeleton>
    </AuthGuard>
  );
}
