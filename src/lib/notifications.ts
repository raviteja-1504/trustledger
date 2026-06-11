"use client";

import { useState, useEffect, useCallback, useRef } from "react";
import type { DashboardData } from "@/types";

export type NotifLevel = "critical" | "high" | "warning" | "info" | "success";

export interface Notification {
  id: string;
  level: NotifLevel;
  title: string;
  body: string;
  time: number;
  read: boolean;
  href?: string;
}

const STORE_KEY  = "tl_notifications";
const SNAP_KEY   = "tl_notif_snapshot";
const POLL_MS    = 30_000;
const MAX_STORED = 50;

function load(): Notification[] {
  if (typeof window === "undefined") return [];
  try { return JSON.parse(localStorage.getItem(STORE_KEY) ?? "[]"); } catch { return []; }
}

function save(ns: Notification[]) {
  localStorage.setItem(STORE_KEY, JSON.stringify(ns.slice(0, MAX_STORED)));
}

function loadSnap(): DashboardData | null {
  if (typeof window === "undefined") return null;
  try { return JSON.parse(localStorage.getItem(SNAP_KEY) ?? "null"); } catch { return null; }
}

function saveSnap(d: DashboardData) {
  localStorage.setItem(SNAP_KEY, JSON.stringify(d));
}

function uid() {
  return `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
}

function resolvedViolationCount(): number {
  if (typeof window === "undefined") return 0;
  try {
    const s = JSON.parse(localStorage.getItem("tl_violation_statuses") ?? "{}") as Record<string,string>;
    // Key format: "{pfx}::{scan_id}::{file_path}" — count unique scan IDs with resolved files
    // to match the deploy-level granularity of unattested_deploy_count
    const resolvedScanIds = new Set(
      Object.entries(s)
        .filter(([, v]) => v === "resolved")
        .map(([k]) => k.split("::")[1])
        .filter(Boolean)
    );
    return resolvedScanIds.size;
  } catch { return 0; }
}

function calcHealth(d: DashboardData): number {
  if (d.repos.length === 0) return 100;
  const effectiveUnattested = Math.max(0, d.unattested_deploy_count - resolvedViolationCount());
  return Math.round(Math.min(100,
    d.attestation_rate * 60 +
    (1 - Math.min(d.overall_ai_pct, 1)) * 25 +
    Math.max(0, 15 - effectiveUnattested * 3),
  ));
}

// Generate notifications from absolute state (first load or session refresh).
// IDs are derived from stable content (not the current timestamp) so that
// re-running this on every new session doesn't pile up duplicate unread
// notifications for the same underlying condition.
function stateNotifications(data: DashboardData): Notification[] {
  const notes: Notification[] = [];
  const now = Date.now();
  const today = new Date(now).toISOString().slice(0, 10);
  const resolved = resolvedViolationCount();

  // Connected banner — once per day
  notes.push({
    id: `connected-${today}`, level: "info", read: false, time: now,
    title: "TrustLedger monitoring active",
    body: `${data.repos.length} repos · ${data.file_count} files · health ${calcHealth(data)}`,
  });

  // CRITICAL unattested files → individual notifications, one per file
  const crit = data.top_risk_files.filter(f => f.risk_score === "CRITICAL" && !f.attested);
  crit.slice(0, 5).forEach((f, i) => {
    notes.push({
      id: `crit-${f.scan_id}-${f.file_path}`, level: "critical", read: false,
      time: now - i * 1000,
      title: "CRITICAL file needs attestation",
      body: `${f.file_path.split("/").pop()} in ${f.repo.split("/").pop()} · ${(f.ai_pct * 100).toFixed(0)}% AI`,
      href: `/pr/${f.scan_id}`,
    });
  });

  // HIGH unattested files (batched) — once per day
  const high = data.top_risk_files.filter(f => f.risk_score === "HIGH" && !f.attested);
  if (high.length > 0) {
    notes.push({
      id: `high-${today}`, level: "high", read: false, time: now - 6000,
      title: `${high.length} HIGH-risk file${high.length > 1 ? "s" : ""} awaiting attestation`,
      body: high.slice(0, 3).map(f => f.file_path.split("/").pop()).join(", ") + (high.length > 3 ? ` +${high.length - 3} more` : ""),
      href: "/violations",
    });
  }

  // Deploys blocked — once per day
  const effectiveBlocked = Math.max(0, data.unattested_deploy_count - resolved);
  if (effectiveBlocked > 0) {
    notes.push({
      id: `deploys-${today}`, level: "warning", read: false, time: now - 10000,
      title: `${effectiveBlocked} deploy${effectiveBlocked > 1 ? "s" : ""} pending attestation`,
      body: "Merge gate is blocking deploys until CRITICAL and HIGH files are reviewed.",
      href: "/dashboard",
    });
  }

  // Repos with AI content above 80% — once per day
  const highAiRepos = data.repos.filter(r => r.ai_pct > 0.8);
  if (highAiRepos.length > 0) {
    notes.push({
      id: `ai-threshold-${today}`, level: "warning", read: false, time: now - 15000,
      title: `${highAiRepos.length} repo${highAiRepos.length > 1 ? "s" : ""} exceed AI content threshold`,
      body: highAiRepos.map(r => `${r.repo.split("/").pop()} (${(r.ai_pct * 100).toFixed(0)}%)`).join(", "),
      href: "/posture",
    });
  }

  // Low attestation coverage — once per day
  const lowAttest = data.repos.filter(r => r.attestation_rate < 0.6);
  if (lowAttest.length > 0) {
    notes.push({
      id: `low-attest-${today}`, level: "high", read: false, time: now - 20000,
      title: `${lowAttest.length} repo${lowAttest.length > 1 ? "s" : ""} below 60% attestation`,
      body: lowAttest.map(r => `${r.repo.split("/").pop()} ${Math.round(r.attestation_rate * 100)}%`).join(", "),
      href: "/posture",
    });
  }

  return notes;
}

function diff(prev: DashboardData | null, next: DashboardData): Notification[] {
  const notes: Notification[] = [];
  const now = Date.now();

  if (!prev) {
    // First load — generate full state-based notification set
    return stateNotifications(next);
  }

  // Health score drop ≥ 5
  const prevHealth = calcHealth(prev);
  const nextHealth = calcHealth(next);
  if (nextHealth <= prevHealth - 5) {
    notes.push({
      id: uid(), level: "critical", read: false, time: now,
      title: "Health score dropped",
      body: `Score fell from ${prevHealth} → ${nextHealth}. Review unattested critical files.`,
      href: "/dashboard",
    });
  }

  // New CRITICAL unattested files
  const prevCritIds = new Set(
    prev.top_risk_files
      .filter(f => f.risk_score === "CRITICAL" && !f.attested)
      .map(f => f.file_path)
  );
  const newCrit = next.top_risk_files.filter(
    f => f.risk_score === "CRITICAL" && !f.attested && !prevCritIds.has(f.file_path)
  );
  if (newCrit.length > 0) {
    newCrit.forEach(f => {
      notes.push({
        id: uid(), level: "critical", read: false, time: now,
        title: "CRITICAL file needs attestation",
        body: `${f.file_path.split("/").pop()} in ${f.repo.split("/").pop()} · ${(f.ai_pct * 100).toFixed(0)}% AI content`,
        href: `/pr/${f.scan_id}`,
      });
    });
  }

  // New HIGH unattested files (batch)
  const prevHighIds = new Set(
    prev.top_risk_files
      .filter(f => f.risk_score === "HIGH" && !f.attested)
      .map(f => f.file_path)
  );
  const newHigh = next.top_risk_files.filter(
    f => f.risk_score === "HIGH" && !f.attested && !prevHighIds.has(f.file_path)
  );
  if (newHigh.length > 0) {
    notes.push({
      id: uid(), level: "high", read: false, time: now,
      title: `${newHigh.length} new HIGH-risk file${newHigh.length > 1 ? "s" : ""}`,
      body: newHigh.map(f => f.file_path.split("/").pop()).join(", "),
      href: "/dashboard",
    });
  }

  // Attestation rate improved ≥ 10%
  if (next.attestation_rate >= prev.attestation_rate + 0.1) {
    notes.push({
      id: uid(), level: "success", read: false, time: now,
      title: "Attestation coverage improved",
      body: `Coverage rose to ${Math.round(next.attestation_rate * 100)}% (+${Math.round((next.attestation_rate - prev.attestation_rate) * 100)}pp)`,
      href: "/dashboard",
    });
  }

  // Overall AI content spike ≥ 10%
  if (next.overall_ai_pct >= prev.overall_ai_pct + 0.1) {
    notes.push({
      id: uid(), level: "warning", read: false, time: now,
      title: "AI content spike detected",
      body: `Overall AI% rose to ${(next.overall_ai_pct * 100).toFixed(1)}% across all repos`,
      href: "/dashboard",
    });
  }

  // New repos added
  const newRepos = next.repos.length - prev.repos.length;
  if (newRepos > 0) {
    notes.push({
      id: uid(), level: "info", read: false, time: now,
      title: `${newRepos} new repo${newRepos > 1 ? "s" : ""} connected`,
      body: `Total repositories: ${next.repos.length}`,
    });
  }

  // Unattested deploys spike (check effective count, accounting for locally resolved violations)
  const resolved = resolvedViolationCount();
  const effectiveNext = Math.max(0, next.unattested_deploy_count - resolved);
  const effectivePrev = Math.max(0, prev.unattested_deploy_count - resolved);
  if (effectiveNext > effectivePrev + 2) {
    notes.push({
      id: uid(), level: "warning", read: false, time: now,
      title: "Unattested deploys increased",
      body: `${effectiveNext} unattested deploys pending review (was ${effectivePrev})`,
      href: "/dashboard",
    });
  }

  return notes;
}

const BASE_URL = "";
const ORG = process.env.NEXT_PUBLIC_ORG ?? "novapay";

// Fallback data used when the backend is unreachable, so notifications still fire
function makeOfflineData(): DashboardData {
  const o = ORG;
  return {
    repos: [
      { repo:`${o}/payments-api`,    ai_pct:0.71, attestation_rate:0.80, last_scan:"2026-05-30", scan_count:34, file_count:214, latest_scan_id:"sc_mock_001" },
      { repo:`${o}/auth-service`,    ai_pct:0.44, attestation_rate:0.88, last_scan:"2026-05-30", scan_count:28, file_count:167, latest_scan_id:"sc_mock_002" },
      { repo:`${o}/fraud-detection`, ai_pct:0.63, attestation_rate:0.67, last_scan:"2026-05-29", scan_count:21, file_count:143, latest_scan_id:"sc_mock_003" },
      { repo:`${o}/risk-engine`,     ai_pct:0.38, attestation_rate:0.91, last_scan:"2026-05-28", scan_count:15, file_count:98,  latest_scan_id:"sc_mock_004" },
      { repo:`${o}/data-platform`,   ai_pct:0.67, attestation_rate:0.52, last_scan:"2026-05-27", scan_count:19, file_count:134, latest_scan_id:"sc_mock_005" },
      { repo:`${o}/ml-platform`,     ai_pct:0.79, attestation_rate:0.45, last_scan:"2026-05-29", scan_count:11, file_count:112, latest_scan_id:"sc_mock_006" },
      { repo:`${o}/api-gateway`,     ai_pct:0.52, attestation_rate:0.74, last_scan:"2026-05-30", scan_count:19, file_count:124, latest_scan_id:"sc_mock_007" },
    ],
    overall_ai_pct: 0.67,
    attestation_rate: 0.72,
    unattested_deploy_count: 5,
    scan_count: 147,
    file_count: 992,
    risk_trend: [
      { date:"2026-03-01", high_count:22, critical_count:8,  medium_count:31 },
      { date:"2026-03-15", high_count:19, critical_count:7,  medium_count:27 },
      { date:"2026-04-01", high_count:17, critical_count:6,  medium_count:23 },
      { date:"2026-04-15", high_count:14, critical_count:5,  medium_count:19 },
      { date:"2026-05-01", high_count:11, critical_count:4,  medium_count:15 },
      { date:"2026-05-15", high_count:8,  critical_count:3,  medium_count:11 },
      { date:"2026-05-30", high_count:6,  critical_count:2,  medium_count:8  },
    ],
    top_risk_files: [
      { repo:`${o}/payments-api`,    file_path:"src/processors/card_validator.py",   ai_pct:0.94, risk_score:"CRITICAL", attested:false, scan_id:"sc_mock_001", pr_number:512 },
      { repo:`${o}/ml-platform`,     file_path:"src/models/inference_engine.py",     ai_pct:0.91, risk_score:"CRITICAL", attested:false, scan_id:"sc_mock_006", pr_number:88  },
      { repo:`${o}/fraud-detection`, file_path:"models/risk_scorer.ts",              ai_pct:0.88, risk_score:"CRITICAL", attested:false, scan_id:"sc_mock_003", pr_number:247 },
      { repo:`${o}/auth-service`,    file_path:"src/auth/token_service.py",          ai_pct:0.76, risk_score:"HIGH",     attested:false, scan_id:"sc_mock_002", pr_number:371 },
      { repo:`${o}/data-platform`,   file_path:"src/connectors/bigquery_writer.ts",  ai_pct:0.83, risk_score:"HIGH",     attested:false, scan_id:"sc_mock_005", pr_number:118 },
    ],
  };
}
const OFFLINE_DATA: DashboardData = makeOfflineData();

async function fetchDashboard(): Promise<DashboardData> {
  // When seed is forced, use the seeded snapshot — never overwrite it with OFFLINE_DATA
  if (typeof window !== "undefined" && localStorage.getItem("tl_force_seed") === "1") {
    const seeded = loadSnap();
    if (seeded?.repos?.length) return seeded;
  }
  try {
    const token = localStorage.getItem("tl_token");
    const res = await fetch(`${BASE_URL}/api/dashboard`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    });
    if (!res.ok) return loadSnap() ?? OFFLINE_DATA;
    const data = await res.json() as DashboardData;
    // Only save snap when using live data (not when seed is active)
    return data;
  } catch {
    return loadSnap() ?? OFFLINE_DATA;
  }
}

// Session key — stateNotifications run once per browser session
const SESSION_KEY = "tl_notif_session";
function isNewSession(): boolean {
  if (typeof window === "undefined") return false;
  const key = sessionStorage.getItem(SESSION_KEY);
  if (key) return false;
  sessionStorage.setItem(SESSION_KEY, "1");
  return true;
}

export function useNotifications() {
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const addNew = useCallback((incoming: Notification[]) => {
    if (!incoming.length) return;
    setNotifications(prev => {
      // Deduplicate by id so re-renders don't duplicate
      const existingIds = new Set(prev.map(n => n.id));
      const deduped = incoming.filter(n => !existingIds.has(n.id));
      if (!deduped.length) return prev;
      const merged = [...deduped, ...prev].slice(0, MAX_STORED);
      save(merged);
      return merged;
    });
  }, []);

  const poll = useCallback(async () => {
    const data  = await fetchDashboard();
    const snap  = loadSnap();
    // On a fresh session, always regenerate state-based notifications
    const fresh = isNewSession() ? stateNotifications(data) : diff(snap, data);
    // Never overwrite the seed snapshot — only save live API data
    if (typeof window === "undefined" || localStorage.getItem("tl_force_seed") !== "1") {
      saveSnap(data);
    }
    addNew(fresh);
  }, [addNew]);

  // Boot: load persisted + first poll
  useEffect(() => {
    setNotifications(load());
    poll();
    timerRef.current = setInterval(poll, POLL_MS);
    return () => { if (timerRef.current) clearInterval(timerRef.current); };
  }, [poll]);

  // Supabase Realtime — supplement polling with live alerts when connected
  useEffect(() => {
    if (typeof window === "undefined") return;
    // Dynamically import to avoid SSR issues
    import("@supabase/supabase-js").then(() => {
      import("./supabase").then(({ supabase }) => {
        supabase.auth.getSession().then(({ data: { session } }) => {
          if (!session) return; // Not authenticated — polling handles offline/demo
          // Subscribe to new P1/P2 alerts in realtime
          import("./realtime").then(({ useLiveAlertNotifications: _ }) => {
            // Realtime used via hook in Nav — no direct subscription needed here
          });
        });
      });
    }).catch(() => { /* ignore if Supabase not configured */ });
  }, []);

  const markRead = useCallback((id: string) => {
    setNotifications(prev => {
      const updated = prev.map(n => n.id === id ? { ...n, read: true } : n);
      save(updated);
      return updated;
    });
  }, []);

  const markAllRead = useCallback(() => {
    setNotifications(prev => {
      const updated = prev.map(n => ({ ...n, read: true }));
      save(updated);
      return updated;
    });
  }, []);

  const dismiss = useCallback((id: string) => {
    setNotifications(prev => {
      const updated = prev.filter(n => n.id !== id);
      save(updated);
      return updated;
    });
  }, []);

  const dismissAll = useCallback(() => {
    setNotifications([]);
    save([]);
  }, []);

  const unread = notifications.filter(n => !n.read).length;

  // Exposed so Realtime hooks can inject live DB alerts directly
  const addFromRealtime = useCallback((n: Notification) => {
    addNew([n]);
  }, [addNew]);

  return { notifications, unread, markRead, markAllRead, dismiss, dismissAll, addFromRealtime };
}
