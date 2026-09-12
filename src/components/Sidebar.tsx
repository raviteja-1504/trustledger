"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useState, useEffect } from "react";
import clsx from "clsx";
import { useRole, ROLE_LABELS, ROLE_COLORS, type UserRole } from "@/lib/roles";
import { useSidebar } from "@/lib/sidebar";
import { useAuth } from "@/lib/auth";
import { isSeedMode, authedFetch } from "@/lib/useRealData";
import { countOpenViolations } from "@/lib/violations";
import { patchDataWithAttestations } from "@/lib/trustScore";
import { api } from "@/lib/api";
import type { DashboardData } from "@/types";

// ── Icons ─────────────────────────────────────────────────────────────────────

function ShieldIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
      <path d="M12 1.5L3 6v6c0 5.55 3.84 10.74 9 12 5.16-1.26 9-6.45 9-12V6L12 1.5z" />
    </svg>
  );
}

function OverviewIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="3" width="7" height="7" rx="1.5"/>
      <rect x="14" y="3" width="7" height="7" rx="1.5"/>
      <rect x="3" y="14" width="7" height="7" rx="1.5"/>
      <rect x="14" y="14" width="7" height="7" rx="1.5"/>
    </svg>
  );
}

function ReportsIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
      <polyline points="14 2 14 8 20 8"/>
      <line x1="16" y1="13" x2="8" y2="13"/>
      <line x1="16" y1="17" x2="8" y2="17"/>
    </svg>
  );
}

function SecretsIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="11" width="18" height="11" rx="2"/>
      <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
    </svg>
  );
}

function AuditIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M9 11l3 3L22 4"/>
      <path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/>
    </svg>
  );
}

function SettingsIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="3"/>
      <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>
    </svg>
  );
}

function LockIcon() {
  return (
    <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
      <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
    </svg>
  );
}

// ── Nav links ─────────────────────────────────────────────────────────────────

function ViolationsIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/>
    </svg>
  );
}
function DepsIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/>
      <polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" y1="22.08" x2="12" y2="12"/>
    </svg>
  );
}
function BellAlertIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/>
      <path d="M13.73 21a2 2 0 0 1-3.46 0"/>
    </svg>
  );
}
function RiskRegIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      <line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
    </svg>
  );
}
function EvidenceIcon2() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/>
      <line x1="12" y1="11" x2="12" y2="17"/><line x1="9" y1="14" x2="15" y2="14"/>
    </svg>
  );
}
function ComplianceIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/>
    </svg>
  );
}
function ScansNavIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M3 7V5a2 2 0 0 1 2-2h2"/><path d="M17 3h2a2 2 0 0 1 2 2v2"/>
      <path d="M21 17v2a2 2 0 0 1-2 2h-2"/><path d="M7 21H5a2 2 0 0 1-2-2v-2"/>
      <rect x="7" y="7" width="10" height="10" rx="1"/>
    </svg>
  );
}
function VulnIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
      <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
    </svg>
  );
}

function ThreatIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/>
    </svg>
  );
}
function IncidentIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10"/>
      <path d="M8 12l2.5 2.5L16 8.5"/>
    </svg>
  );
}
function PostureIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 2a10 10 0 1 0 10 10"/><path d="M12 6v6l4 2"/><circle cx="18" cy="6" r="3" fill="currentColor" stroke="none"/>
    </svg>
  );
}
function AnalyticsIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
    </svg>
  );
}
function NotifPageIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/>
      <path d="M13.73 21a2 2 0 0 1-3.46 0"/>
      <line x1="12" y1="2" x2="12" y2="4"/>
    </svg>
  );
}

// roles: which roles can see this link (undefined = all roles)
const ALL_LINKS: Array<{
  href: string; label: string; icon: () => JSX.Element;
  permission: "canManageSettings" | null;
  roles?: UserRole[];
}> = [
  // Overview
  { href: "/dashboard",       label: "Overview",        icon: OverviewIcon,    permission: null                         },
  { href: "/analytics",       label: "Analytics",       icon: AnalyticsIcon,   permission: null,  roles: ["admin","security_reviewer"] },
  { href: "/posture",         label: "Security Posture",icon: PostureIcon,     permission: null,  roles: ["admin","security_reviewer"] },
  // Threats
  { href: "/violations",      label: "Violations",      icon: ViolationsIcon,  permission: null                         },
  { href: "/alerts",          label: "Alerts",          icon: BellAlertIcon,   permission: null,  roles: ["admin","security_reviewer"] },
  { href: "/incidents",       label: "Incidents",       icon: IncidentIcon,    permission: null,  roles: ["admin","security_reviewer"] },
  { href: "/threat-intel",    label: "Threat Intel",    icon: ThreatIcon,      permission: null,  roles: ["admin","security_reviewer"] },
  // Code Risk
  { href: "/scans",           label: "Scan History",    icon: ScansNavIcon,    permission: null                         },
  { href: "/secrets",         label: "Secrets",         icon: SecretsIcon,     permission: null,  roles: ["admin","security_reviewer"] },
  { href: "/dependencies",    label: "Dependencies",    icon: DepsIcon,        permission: null,  roles: ["admin","security_reviewer"] },
  { href: "/vulnerabilities", label: "Vulnerabilities", icon: VulnIcon,        permission: null,  roles: ["admin","security_reviewer"] },
  // Compliance
  { href: "/compliance",      label: "Compliance",      icon: ComplianceIcon,  permission: null,  roles: ["admin","security_reviewer"] },
  { href: "/sla",             label: "SLA Dashboard",   icon: PostureIcon,     permission: null,  roles: ["admin","security_reviewer"] },
  { href: "/risk-register",   label: "Risk Register",   icon: RiskRegIcon,     permission: null,  roles: ["admin","security_reviewer"] },
  { href: "/evidence",        label: "Evidence",        icon: EvidenceIcon2,   permission: null,  roles: ["admin","security_reviewer"] },
  // Audit
  { href: "/audit",           label: "Audit Trail",     icon: AuditIcon,       permission: null,  roles: ["admin","security_reviewer"] },
  { href: "/aibom",           label: "AIBOM",           icon: ReportsIcon,     permission: null,  roles: ["admin","security_reviewer"] },
  { href: "/reports",         label: "Reports",         icon: ReportsIcon,     permission: null                         },
  // AI Intel
  { href: "/trust-score",     label: "TrustScore™",     icon: PostureIcon,     permission: null,  roles: ["admin","security_reviewer"] },
  { href: "/shadow-ai",       label: "Shadow AI",       icon: VulnIcon,        permission: "canManageSettings" as const },
  // Config
  { href: "/settings/team",   label: "Team",            icon: OverviewIcon,    permission: null                         },
  { href: "/orgs",            label: "Organisations",   icon: OverviewIcon,    permission: "canManageSettings" as const },
  { href: "/profile",         label: "My Profile",      icon: OverviewIcon,    permission: null                         },
  { href: "/notifications",   label: "Notifications",   icon: NotifPageIcon,   permission: null                         },
  { href: "/settings",        label: "Settings",        icon: SettingsIcon,    permission: "canManageSettings" as const },
  { href: "/billing",         label: "Billing & Usage", icon: AnalyticsIcon,   permission: "canManageSettings" as const },
];

function syncedLabel(at: Date): string {
  const s = Math.round((Date.now() - at.getTime()) / 1000);
  if (s < 5)    return "just now";
  if (s < 60)   return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  return `${Math.floor(s / 3600)}h ago`;
}

// ── Component ─────────────────────────────────────────────────────────────────

export default function Sidebar() {
  const pathname   = usePathname() ?? "/";
  const router     = useRouter();
  const { role, setRole, permissions, isDemo } = useRole();
  const roleColor  = ROLE_COLORS[role];
  const { collapsed, toggle } = useSidebar();
  const { signOut, profile } = useAuth();
  const [pendingCount,    setPendingCount]    = useState(0);
  const [openSecrets,     setOpenSecrets]     = useState(0);
  const [openViolations,  setOpenViolations]  = useState(0);
  const [firingAlerts,    setFiringAlerts]    = useState(0);
  const [activeIncidents, setActiveIncidents] = useState(0);
  const [vulnDeps,        setVulnDeps]        = useState(0);
  const [syncing,         setSyncing]         = useState(false);
  const [lastSynced,      setLastSynced]      = useState<Date | null>(null);

  // Every badge below reads live, server-authoritative data on every refresh —
  // nothing is derived from a localStorage snapshot or a locally-owned status
  // map. That's a deliberate fix: violation/secret resolution used to be
  // tracked ONLY in localStorage (tl_violation_statuses / tl_secret_status),
  // so resolving something on one device never showed up on another, and a
  // badge could sit wrong until whichever page repopulated its own cache was
  // visited. Now every consumer of those two statuses (this sidebar, the
  // Violations/Secrets pages, the dashboard's own widgets) reads the same
  // /api/violation-status and /api/secrets endpoints, so they can't drift
  // from each other or from reality.
  useEffect(() => {
    let cancelled = false;

    async function refreshAll(showSpinner: boolean) {
      if (!profile?.org_id) return;
      if (showSpinner) setSyncing(true);

      if (isSeedMode()) {
        refreshSeedMode();
        if (showSpinner) setSyncing(false);
        return;
      }

      // Each source is fetched and applied independently — a failure in one
      // (e.g. a slow/flaky dashboard aggregate query) must not blank out
      // badges whose own fetch succeeded fine. Previously these were all in
      // one Promise.all with only one of the five calls actually caught, so
      // any hiccup in that one call silently zeroed every badge at once even
      // though the DB had real, correct data the whole time.
      const results = await Promise.allSettled([
        api.dashboard(profile.org_slug || "org", 90),
        authedFetch<{ overrides: Record<string, { status: string }> }>("/api/violation-status"),
        authedFetch<{ findings: { status: string }[] }>("/api/secrets?status=open"),
        authedFetch<{ incidents: { status: string }[] }>("/api/incidents"),
        authedFetch<{ alerts: { id: string; status: string; scan_id?: string; source?: string }[] }>("/api/alerts?status=firing&limit=200"),
        authedFetch<{ counts: { vulnerable: number } }>("/api/dependencies"),
      ]);
      if (cancelled) return;
      const [dashRes, overridesRes, secretsRes, incidentsRes, alertsRes, depsRes] = results;

      if (dashRes.status === "fulfilled") {
        const dashData = dashRes.value;
        try { localStorage.setItem("tl_notif_snapshot", JSON.stringify(dashData)); } catch { /* e.g. private-mode storage quota */ }

        const statuses: Record<string, string> = {};
        if (overridesRes.status === "fulfilled") {
          for (const [id, o] of Object.entries(overridesRes.value.overrides ?? {})) statuses[id] = o.status;
        }

        // Reports: CRITICAL/HIGH files still pending attestation and not
        // marked resolved/in_review via a violation override.
        const resolvedFiles = new Set<string>();
        for (const [key, status] of Object.entries(statuses)) {
          if (status === "resolved" || status === "in_review") {
            const first  = key.indexOf("::");
            const second = key.indexOf("::", first + 2);
            if (second !== -1) resolvedFiles.add(key.slice(second + 2));
          }
        }
        const riskFiles = dashData.top_risk_files ?? [];
        const pending = riskFiles.filter(f =>
          (f.risk_score === "CRITICAL" || f.risk_score === "HIGH") && !f.attested && !resolvedFiles.has(f.file_path)
        ).length;
        setPendingCount(pending);

        // Violations: single source of truth shared with /violations and the
        // dashboard's own "Needs attention" strip (src/lib/violations.ts).
        setOpenViolations(countOpenViolations(patchDataWithAttestations(dashData), statuses));
      }
      // else: leave pendingCount/openViolations as they were — a failed
      // dashboard fetch shouldn't reset them to 0.

      if (secretsRes.status === "fulfilled") {
        // Secrets: exact server-side open count — same query the /secrets
        // page itself runs, no client-side re-derivation.
        setOpenSecrets((secretsRes.value.findings ?? []).length);
      }

      if (incidentsRes.status === "fulfilled") {
        // Incidents: active + contained.
        setActiveIncidents((incidentsRes.value.incidents ?? []).filter(i =>
          i.status === "active" || i.status === "contained"
        ).length);
      }

      if (alertsRes.status === "fulfilled") {
        // Alerts: dedupe same as the /alerts page (latest per scan_id+source).
        const deduped = new Map<string, string>();
        for (const a of (alertsRes.value.alerts ?? [])) {
          const key = a.scan_id ? `${a.scan_id}::${a.source ?? "policy"}` : a.id;
          if (!deduped.has(key)) deduped.set(key, a.id);
        }
        setFiringAlerts(deduped.size);
      }

      if (depsRes.status === "fulfilled") {
        // Dependencies: exact server-computed "Vulnerable" count — same
        // derivation the /dependencies page itself now calls, cached
        // server-side (api/dependencies/route.ts) instead of a stale,
        // session-only localStorage number.
        setVulnDeps(depsRes.value.counts?.vulnerable ?? 0);
      } else {
        // Fall back to whatever the /dependencies page last cached this
        // session, in case the live endpoint is briefly unavailable.
        const depCount = parseInt(localStorage.getItem("tl_dep_badge_count") ?? "0", 10);
        setVulnDeps(isNaN(depCount) ? 0 : depCount);
      }

      if (results.some(r => r.status === "fulfilled")) setLastSynced(new Date());
      if (showSpinner) setSyncing(false);
    }

    function refreshSeedMode() {
      try {
        const snap = JSON.parse(localStorage.getItem("tl_notif_snapshot") ?? "null") as DashboardData | null;
        if (!snap) return;
        const riskFiles = snap.top_risk_files ?? [];
        const critUnatt = riskFiles.filter(f => f.risk_score === "CRITICAL" && !f.attested);
        const highUnatt = riskFiles.filter(f => f.risk_score === "HIGH"     && !f.attested);
        setPendingCount(critUnatt.length + highUnatt.length);
        setOpenViolations(countOpenViolations(patchDataWithAttestations(snap), {}));
        setOpenSecrets(parseInt(localStorage.getItem("tl_secret_total") ?? "8", 10) || 0);
        const aiCritRepos    = (snap.repos ?? []).filter(r => r.ai_pct > 0.85).length;
        const aiSpikeRepos   = (snap.repos ?? []).filter(r => r.ai_pct > 0.7 && r.ai_pct <= 0.85).length;
        const lowAttestRepos = (snap.repos ?? []).filter(r => r.attestation_rate < 0.6 && r.scan_count > 0).length;
        setFiringAlerts(Math.min(critUnatt.length, 3) + aiCritRepos + Math.min(highUnatt.length, 3) + aiSpikeRepos + lowAttestRepos);
        const rawIncidents = JSON.parse(localStorage.getItem("tl_incidents") ?? "null");
        setActiveIncidents(Array.isArray(rawIncidents)
          ? rawIncidents.filter((i: { status: string }) => i.status === "active" || i.status === "contained").length
          : 0);
        setVulnDeps(parseInt(localStorage.getItem("tl_dep_badge_count") ?? "0", 10) || 0);
        setLastSynced(new Date());
      } catch { /* no-op */ }
    }

    refreshAll(true);
    // 30s safety-net poll (matches the /violations page's own poll interval)
    // plus event-driven refresh for instant updates right after an action.
    const id = setInterval(() => refreshAll(false), 30_000);
    const onEvent = () => refreshAll(false);
    window.addEventListener("focus",              onEvent);
    window.addEventListener("tl:badge",            onEvent);
    window.addEventListener("tl:attest-complete",  onEvent);
    document.addEventListener("visibilitychange",  onEvent);
    return () => {
      cancelled = true;
      clearInterval(id);
      window.removeEventListener("focus",              onEvent);
      window.removeEventListener("tl:badge",            onEvent);
      window.removeEventListener("tl:attest-complete",  onEvent);
      document.removeEventListener("visibilitychange",  onEvent);
    };
  // Re-run when org_id becomes available so the API calls fire after login
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [profile?.org_id]);

  const visibleLinks = ALL_LINKS.filter(l =>
    (l.permission === null || permissions[l.permission]) &&
    (!l.roles || l.roles.includes(role))
  );

  async function handleSignOut() {
    await signOut();
    router.push("/login");
  }

  // Every count behind this is now a live, exact server value (see the
  // refreshAll effect above) — so the badge shows the real number, not a
  // "9+" truncation, and doesn't render at all until the first sync
  // actually lands (a neutral placeholder dot instead of a misleading "0"
  // while that's in flight). `ready` gates all badges together so they pop
  // in as one coherent batch rather than trickling in independently.
  const ready = lastSynced !== null;

  function badge(count: number, accent: string, pulse = false): JSX.Element {
    if (!ready) {
      return (
        <span className="ml-auto shrink-0 w-3 h-3 rounded-full"
          style={{ background: "rgba(255,255,255,0.08)" }}
          aria-hidden="true" />
      );
    }
    if (!Number.isFinite(count) || count <= 0) return <></>;
    return (
      <span
        className="ml-auto shrink-0 inline-flex items-center gap-1 h-[18px] px-1.5 rounded-md text-[10px] font-bold tabular-nums"
        style={{ background: `${accent}22`, color: accent, border: `1px solid ${accent}40` }}
        title={pulse ? "Needs attention now" : undefined}
      >
        {pulse && <span className="w-1.5 h-1.5 rounded-full shrink-0 animate-pulse" style={{ background: accent }} />}
        {count > 999 ? "999+" : count}
      </span>
    );
  }

  const BADGE_COUNT: Record<string, number> = {
    "/violations":   openViolations,
    "/alerts":       firingAlerts,
    "/secrets":      openSecrets,
    "/reports":      pendingCount,
    "/incidents":    activeIncidents,
    "/dependencies": vulnDeps,
  };

  const BADGE_STYLE: Record<string, { accent: string; pulse: boolean }> = {
    "/violations":   { accent: "#f87171", pulse: false },
    "/alerts":       { accent: "#fb923c", pulse: true  },
    "/secrets":      { accent: "#a78bfa", pulse: false },
    "/reports":      { accent: "#fbbf24", pulse: false },
    "/incidents":    { accent: "#e11d48", pulse: true  },
    "/dependencies": { accent: "#38bdf8", pulse: false },
  };

  const BADGE: Record<string, JSX.Element> = {
    "/violations":   badge(openViolations,  "#f87171"),
    "/alerts":       badge(firingAlerts,    "#fb923c", true),
    "/secrets":      badge(openSecrets,     "#a78bfa"),
    "/reports":      badge(pendingCount,    "#fbbf24"),
    "/incidents":    badge(activeIncidents, "#e11d48", true),
    "/dependencies": badge(vulnDeps,        "#38bdf8"),
  };

  return (
    <aside
      className="shrink-0 flex flex-col select-none h-full"
      style={{
        background: "linear-gradient(160deg, #0a0f1e 0%, #0f172a 45%, #1a1040 100%)",
        width: collapsed ? "60px" : "240px",
        minWidth: collapsed ? "60px" : "240px",
        transition: "width 0.25s cubic-bezier(0.4,0,0.2,1)",
        overflow: "hidden",
        willChange: "width",
      }}
    >
      {/* Logo + collapse toggle */}
      <div className="h-14 flex items-center shrink-0 px-3 gap-2"
        style={{ borderBottom: "1px solid rgba(255,255,255,0.06)" }}>
        <div className="w-9 h-9 rounded-xl flex items-center justify-center text-white shrink-0"
          style={{ background:"linear-gradient(135deg,#6366f1,#7c3aed)", boxShadow:"0 4px 16px rgba(99,102,241,0.45)" }}>
          <ShieldIcon />
        </div>
        {!collapsed && (
          <div className="leading-tight flex-1 min-w-0">
            <p className="font-bold text-white text-sm tracking-tight truncate">TrustLedger</p>
            <p className="text-[10px] font-medium truncate" style={{ color:"rgba(165,180,252,0.7)" }}>AI Provenance</p>
          </div>
        )}
        <button
          onClick={toggle}
          aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          className="shrink-0 w-7 h-7 rounded-lg flex items-center justify-center transition-colors hover:bg-white/[0.08] ml-auto"
          style={{ color:"rgba(255,255,255,0.35)" }}>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"
            style={{ transform: collapsed ? "rotate(180deg)" : "none", transition:"transform 0.25s" }}>
            <polyline points="15 18 9 12 15 6"/>
          </svg>
        </button>
      </div>

      {/* Nav */}
      <nav className={clsx("flex-1 py-3 overflow-y-auto overflow-x-hidden min-h-0", collapsed ? "px-1.5" : "px-3")}
        style={{ scrollbarWidth:"thin", scrollbarColor:"rgba(99,102,241,0.3) transparent" }}>
        {[
          { label:"Overview",    hrefs:["/dashboard","/analytics","/posture"] },
          { label:"Threats",     hrefs:["/violations","/alerts","/incidents","/threat-intel"] },
          { label:"Code Risk",   hrefs:["/scans","/secrets","/dependencies","/vulnerabilities"] },
          { label:"Compliance",  hrefs:["/compliance","/sla","/risk-register","/evidence"] },
          { label:"Audit",       hrefs:["/audit","/aibom","/reports"] },
          { label:"AI Intel",    hrefs:["/trust-score","/shadow-ai"] },
          { label:"Config",      hrefs:["/settings/team","/orgs","/profile","/notifications","/settings","/billing"] },
        ].map(group => {
          const groupLinks = visibleLinks.filter(l => group.hrefs.includes(l.href));
          if (groupLinks.length === 0) return null;
          return (
            <div key={group.label} className="mb-3">
              {!collapsed && (
                <p className="text-[9px] font-black uppercase tracking-widest px-3 mb-1.5"
                  style={{ color:"rgba(255,255,255,0.2)" }}>
                  {group.label}
                </p>
              )}
              {collapsed && <div className="h-px bg-white/[0.06] mb-1.5" />}
              <div className="space-y-0.5">
                {groupLinks.map(({ href, label, icon: Icon }) => {
                  const active   = pathname === href || pathname.startsWith(href + "/");
                  const badge    = BADGE[href] ?? null;
                  const hasCount = ready && (BADGE_COUNT[href] ?? 0) > 0;
                  const style    = BADGE_STYLE[href];
                  return (
                    <Link
                      key={href}
                      href={href}
                      title={collapsed ? label : undefined}
                      className={clsx(
                        "relative flex items-center rounded-xl text-sm font-medium transition-all duration-150",
                        collapsed ? "justify-center p-2.5" : "gap-3 px-3 py-2.5",
                        active ? "text-white" : "hover:text-white/80 hover:bg-white/[0.04]",
                      )}
                      style={active ? {
                        background:"linear-gradient(135deg,rgba(99,102,241,0.8),rgba(124,58,237,0.7))",
                        boxShadow:"0 4px 16px rgba(99,102,241,0.35), inset 0 1px 0 rgba(255,255,255,0.12)",
                      } : { color:"rgba(255,255,255,0.42)" }}
                    >
                      {active && !collapsed && (
                        <span className="absolute left-0 inset-y-2.5 w-0.5 rounded-full"
                          style={{ background:"rgba(196,181,253,0.8)" }} />
                      )}
                      {/* Icon + optional dot badge when collapsed */}
                      <span className={clsx("shrink-0 relative", active ? "text-white" : "text-white/35")}>
                        <Icon />
                        {collapsed && hasCount && style && (
                          <span
                            className={clsx("absolute -top-1 -right-1 w-2 h-2 rounded-full ring-2", style.pulse && "animate-pulse")}
                            style={{ background: style.accent, "--tw-ring-color": "#0f172a" } as React.CSSProperties}
                          />
                        )}
                      </span>
                      {!collapsed && <span className="flex-1 truncate">{label}</span>}
                      {!collapsed && badge}
                      {active && !collapsed && (
                        <span className="ml-auto w-1.5 h-1.5 rounded-full bg-indigo-300/80 shrink-0" />
                      )}
                    </Link>
                  );
                })}
              </div>
            </div>
          );
        })}
        {!collapsed && !permissions.canManageSettings && (
          <div className="flex items-center gap-2.5 px-3 py-2.5 rounded-xl" style={{ color:"rgba(255,255,255,0.18)" }}>
            <span className="shrink-0"><LockIcon /></span>
            <span className="text-sm font-medium">Settings</span>
            <span className="ml-auto text-[9px] uppercase tracking-wide font-semibold" style={{ color:"rgba(255,255,255,0.2)" }}>Admin</span>
          </div>
        )}
      </nav>

      {/* Footer */}
      <div className={clsx("space-y-2", collapsed ? "p-2" : "p-4")} style={{ borderTop:"1px solid rgba(255,255,255,0.06)" }}>
        {!collapsed && (
          <div className="flex items-center gap-2.5 px-1">
            <div
              className={clsx("w-2 h-2 rounded-full shrink-0", syncing ? "bg-amber-400" : "bg-emerald-400", !syncing && "animate-glow-pulse")}
              style={{ boxShadow: syncing ? "0 0 6px rgba(251,191,36,0.6)" : "0 0 6px rgba(52,211,153,0.6)" }}
              title={syncing ? "Syncing badge counts…" : lastSynced ? `Badges synced ${syncedLabel(lastSynced)}` : undefined}
            />
            <p className="text-xs font-medium truncate" style={{ color:"rgba(255,255,255,0.38)" }}>{profile?.org_id ? (profile.org_name || profile.org_slug || (process.env.NEXT_PUBLIC_ORG ?? "novapay")) : (process.env.NEXT_PUBLIC_ORG ?? "novapay")}</p>
            <span className="ml-auto text-[9px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded-md"
              style={{ color:"rgba(165,180,252,0.7)", background:"rgba(99,102,241,0.15)" }}>
              v1.0
            </span>
          </div>
        )}
        {collapsed ? (
          /* Collapsed: role dot + sign-out icon */
          <div className="flex flex-col items-center gap-2">
            <span className={clsx("w-2 h-2 rounded-full", roleColor.dot)} title={ROLE_LABELS[role]} />
            <button
              onClick={handleSignOut}
              title="Sign out"
              aria-label="Sign out"
              className="w-7 h-7 rounded-lg flex items-center justify-center transition-colors hover:bg-white/[0.08]"
              style={{ color: "rgba(255,255,255,0.35)" }}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/>
              </svg>
            </button>
          </div>
        ) : isDemo ? (
            /* Demo mode — keep the role switcher so devs can preview views */
            <div className="relative rounded-xl overflow-hidden"
              style={{ background:"rgba(255,255,255,0.06)", border:"1px solid rgba(255,255,255,0.08)" }}>
              <div className="flex items-center gap-2 px-2.5 py-1.5 pointer-events-none">
                <span className={clsx("w-1.5 h-1.5 rounded-full shrink-0", roleColor.dot)} />
                <span className="text-[11px] font-semibold truncate" style={{ color:"rgba(255,255,255,0.58)" }}>
                  {ROLE_LABELS[role]}
                </span>
                <span className="ml-auto text-[9px] font-bold tracking-wide px-1 rounded" style={{ color:"rgba(255,200,50,0.7)", background:"rgba(255,200,50,0.1)" }}>DEMO</span>
                <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"
                  className="shrink-0" style={{ color:"rgba(255,255,255,0.25)" }}>
                  <polyline points="6 9 12 15 18 9"/>
                </svg>
              </div>
              <select value={role} onChange={e => setRole(e.target.value as UserRole)} title="Switch role (demo)"
                className="absolute inset-0 w-full h-full opacity-0 cursor-pointer">
                <option value="developer">Developer</option>
                <option value="security_reviewer">Security Reviewer</option>
                <option value="admin">Admin</option>
              </select>
            </div>
        ) : (
            /* Production — role is set by admin, read-only */
            <div className="flex items-center gap-2 px-2.5 py-2 rounded-xl"
              style={{ background:"rgba(255,255,255,0.06)", border:"1px solid rgba(255,255,255,0.08)" }}>
              <span className={clsx("w-1.5 h-1.5 rounded-full shrink-0", roleColor.dot)} />
              <span className="text-[11px] font-semibold truncate" style={{ color:"rgba(255,255,255,0.58)" }}>
                {ROLE_LABELS[role]}
              </span>
              {!permissions.canAttest && (
                <span className="ml-auto text-[9px] font-semibold" style={{ color:"rgba(255,255,255,0.22)" }}>view only</span>
              )}
              {profile?.email && (
                <span className="ml-auto text-[9px] truncate max-w-[80px]" style={{ color:"rgba(255,255,255,0.28)" }} title={profile.email}>
                  {profile.email.split("@")[0]}
                </span>
              )}
            </div>
        )}
        {!collapsed && (
          <button
            onClick={handleSignOut}
            className="w-full flex items-center gap-2.5 px-3 py-2 rounded-xl text-xs font-semibold transition-colors hover:bg-white/[0.06] hover:text-white"
            style={{ color: "rgba(255,255,255,0.42)" }}>
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round" className="shrink-0">
              <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/>
            </svg>
            Sign out
          </button>
        )}
      </div>
    </aside>
  );
}
