"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState, useEffect } from "react";
import clsx from "clsx";
import { useRole, ROLE_LABELS, ROLE_COLORS, type UserRole } from "@/lib/roles";
import { useSidebar } from "@/lib/sidebar";

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
function ChangelogIcon() {
  return (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/>
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

const ALL_LINKS = [
  // Overview
  { href: "/dashboard",       label: "Overview",        icon: OverviewIcon,    permission: null                         },
  { href: "/analytics",       label: "Analytics",       icon: AnalyticsIcon,   permission: null                         },
  { href: "/posture",         label: "Security Posture",icon: PostureIcon,     permission: null                         },
  // Threats
  { href: "/violations",      label: "Violations",      icon: ViolationsIcon,  permission: null                         },
  { href: "/alerts",          label: "Alerts",          icon: BellAlertIcon,   permission: null                         },
  { href: "/incidents",       label: "Incidents",       icon: IncidentIcon,    permission: null                         },
  { href: "/threat-intel",    label: "Threat Intel",    icon: ThreatIcon,      permission: null                         },
  // Code Risk
  { href: "/scans",           label: "Scan History",    icon: ScansNavIcon,    permission: null                         },
  { href: "/secrets",         label: "Secrets",         icon: SecretsIcon,     permission: null                         },
  { href: "/dependencies",    label: "Dependencies",    icon: DepsIcon,        permission: null                         },
  { href: "/vulnerabilities", label: "Vulnerabilities", icon: VulnIcon,        permission: null                         },
  // Compliance
  { href: "/compliance",           label: "Compliance",          icon: ComplianceIcon,  permission: null },
  { href: "/compliance-calendar",  label: "Compliance Calendar", icon: ComplianceIcon,  permission: null },
  { href: "/sla",                  label: "SLA Dashboard",       icon: PostureIcon,     permission: null },
  { href: "/risk-register",   label: "Risk Register",   icon: RiskRegIcon,     permission: null                         },
  { href: "/evidence",        label: "Evidence",        icon: EvidenceIcon2,   permission: null                         },
  // Audit
  { href: "/audit",           label: "Audit Trail",     icon: AuditIcon,       permission: null                         },
  { href: "/aibom",           label: "AIBOM",           icon: ReportsIcon,     permission: null                         },
  { href: "/orgs",            label: "Organisations",   icon: OverviewIcon,    permission: "canManageSettings" as const  },
  { href: "/reports",         label: "Reports",         icon: ReportsIcon,     permission: null                         },
  // AI Intelligence (new features)
  { href: "/trust-score",     label: "TrustScore™",      icon: PostureIcon,     permission: null                         },
  { href: "/shadow-ai",       label: "Shadow AI",        icon: VulnIcon,        permission: "canManageSettings" as const },
  { href: "/phantom-deps",    label: "Phantom Deps",     icon: DepsIcon,        permission: null                         },
  { href: "/ai-debt",         label: "AI Debt Clock",    icon: AnalyticsIcon,   permission: null                         },
  // Config
  { href: "/profile",         label: "My Profile",      icon: OverviewIcon,    permission: null                         },
  { href: "/roi",             label: "ROI Dashboard",   icon: AnalyticsIcon,   permission: "canManageSettings" as const },
  { href: "/settings",        label: "Settings",        icon: SettingsIcon,    permission: "canManageSettings" as const },
  { href: "/billing",         label: "Billing & Usage", icon: AnalyticsIcon,   permission: "canManageSettings" as const },
  { href: "/status",          label: "System Status",   icon: PostureIcon,     permission: null                         },
  { href: "/docs",            label: "API Docs",         icon: ReportsIcon,     permission: null                         },
  { href: "/admin/go-live",   label: "Go-Live Checklist",icon: PostureIcon,     permission: "canManageSettings" as const },
  { href: "/notifications",  label: "Notifications",    icon: NotifPageIcon,   permission: null                         },
  { href: "/changelog",      label: "Changelog",        icon: ChangelogIcon,   permission: null                         },
];

// ── Component ─────────────────────────────────────────────────────────────────

export default function Sidebar() {
  const pathname   = usePathname() ?? "/";
  const { role, setRole, permissions } = useRole();
  const roleColor  = ROLE_COLORS[role];
  const { collapsed, toggle } = useSidebar();
  const [pendingCount,    setPendingCount]    = useState(0);
  const [openSecrets,     setOpenSecrets]     = useState(0);
  const [openViolations,  setOpenViolations]  = useState(0);
  const [firingAlerts,    setFiringAlerts]    = useState(0);
  const [activeIncidents, setActiveIncidents] = useState(0);
  const [vulnDeps,        setVulnDeps]        = useState(0);

  useEffect(() => {
    function refresh() {
      try {
        type RiskFile = { attested: boolean; risk_score: string; file_path: string; scan_id: string; repo: string };
        type RepoRow  = { ai_pct: number };
        const snap = JSON.parse(localStorage.getItem("tl_notif_snapshot") ?? "null") as {
          top_risk_files?: RiskFile[];
          repos?: RepoRow[];
          unattested_deploy_count?: number;
        } | null;

        // ── Build resolved-file set from tl_violation_statuses ──────────────
        // Key format: "{pfx}::{scan_id}::{file_path}"
        const vstats = JSON.parse(localStorage.getItem("tl_violation_statuses") ?? "{}") as Record<string, string>;
        const resolvedFiles = new Set<string>();
        for (const [key, status] of Object.entries(vstats)) {
          if (status === "resolved" || status === "in_review") {
            const first  = key.indexOf("::");
            const second = key.indexOf("::", first + 2);
            if (second !== -1) resolvedFiles.add(key.slice(second + 2));
          }
        }

        // ── Risk file counts (excluding attested + resolved) ─────────────────
        const riskFiles = snap?.top_risk_files ?? [];
        const critUnatt = riskFiles.filter(f => f.risk_score === "CRITICAL" && !f.attested && !resolvedFiles.has(f.file_path));
        const highUnatt = riskFiles.filter(f => f.risk_score === "HIGH"     && !f.attested && !resolvedFiles.has(f.file_path));
        const openCount = critUnatt.length + highUnatt.length;

        // Violations: unresolved CRITICAL + HIGH files
        setOpenViolations(openCount);

        // Reports: files pending attestation (same set)
        setPendingCount(openCount);

        // ── Secrets ──────────────────────────────────────────────────────────
        const secretStatuses = JSON.parse(localStorage.getItem("tl_secret_status") ?? "{}") as Record<string, string>;
        const resolvedSecrets = Object.values(secretStatuses).filter(v => v === "resolved").length;
        const rawSecretTotal = parseInt(localStorage.getItem("tl_secret_total") ?? "8", 10);
        const secretTotal = isNaN(rawSecretTotal) ? 8 : rawSecretTotal;
        setOpenSecrets(Math.max(0, secretTotal - resolvedSecrets));

        // ── Alerts: derive firing count from snapshot ─────────────────────
        // "firing" is default — tl_alerts_state only stores explicit overrides
        if (snap) {
          // Mirror dashboard logic: a repo clears once ALL its CRIT/HIGH files are attested
          const unresolvedDeployRepos = new Set(
            riskFiles
              .filter(f => !f.attested && (f.risk_score === "CRITICAL" || f.risk_score === "HIGH") && !resolvedFiles.has(f.file_path))
              .map(f => f.repo)
          );
          const deployBlocked = unresolvedDeployRepos.size === 0
            ? 0
            : Math.min(snap.unattested_deploy_count ?? 0, unresolvedDeployRepos.size);
          const aiCritRepos   = (snap.repos ?? []).filter(r => r.ai_pct > 0.85).length;
          // P1: each CRIT file + deploy gate + AI-threshold repos
          // P2: HIGH files batched (1 notification per 3 files, capped) + SLA breaches for CRITs
          let baseFiring = critUnatt.length
            + (deployBlocked > 0 ? 1 : 0)
            + aiCritRepos
            + Math.ceil(highUnatt.length / 3)       // batch HIGH files
            + Math.min(critUnatt.length, 2);         // SLA breach alerts for crits

          // Subtract alerts already actioned (non-firing overrides in tl_alerts_state)
          const alertState = JSON.parse(localStorage.getItem("tl_alerts_state") ?? "null") as {
            statuses?: Record<string, string>;
          } | null;
          const actioned = alertState?.statuses
            ? Object.values(alertState.statuses).filter(s => s !== "firing").length
            : 0;

          setFiringAlerts(Math.max(0, baseFiring - actioned));
        } else {
          setFiringAlerts(0);
        }

        // ── Incidents: active + contained ─────────────────────────────────
        const rawIncidents = JSON.parse(localStorage.getItem("tl_incidents") ?? "null");
        if (Array.isArray(rawIncidents) && rawIncidents.length > 0) {
          setActiveIncidents(rawIncidents.filter((i: { status: string }) =>
            i.status === "active" || i.status === "contained"
          ).length);
        } else if (!rawIncidents) {
          // No incidents persisted yet — use DEFAULT_INCIDENTS baseline (2 active in seed)
          setActiveIncidents(2);
        } else {
          setActiveIncidents(0);
        }

        // ── Dependencies: vulnerable package count ────────────────────────
        const depCount = parseInt(localStorage.getItem("tl_dep_vuln_count") ?? "0", 10);
        setVulnDeps(isNaN(depCount) ? 0 : depCount);

      } catch { /* no-op */ }
    }

    refresh();
    // Interval as safety net; tl:badge event gives instant updates
    const id = setInterval(refresh, 5_000);
    window.addEventListener("focus",            refresh);
    window.addEventListener("tl:badge",         refresh);
    document.addEventListener("visibilitychange", refresh);
    return () => {
      clearInterval(id);
      window.removeEventListener("focus",            refresh);
      window.removeEventListener("tl:badge",         refresh);
      document.removeEventListener("visibilitychange", refresh);
    };
  }, []);

  const visibleLinks = ALL_LINKS.filter(l => l.permission === null || permissions[l.permission]);

  function badge(count: number, color: string, pulse = false): JSX.Element | null {
    if (!Number.isFinite(count) || count <= 0) return null;
    return (
      <span
        className={`min-w-[16px] h-4 rounded-full flex items-center justify-center text-[8px] font-black text-white px-0.5 tabular-nums ml-auto${pulse ? " animate-pulse" : ""}`}
        style={{ background: color }}
      >
        {count > 9 ? "9+" : count}
      </span>
    );
  }

  const BADGE: Record<string, JSX.Element | null> = {
    "/violations":   badge(openViolations,  "linear-gradient(135deg,#ef4444,#dc2626)"),
    "/alerts":       badge(firingAlerts,    "linear-gradient(135deg,#f97316,#ea580c)", true),
    "/secrets":      badge(openSecrets,     "linear-gradient(135deg,#a78bfa,#7c3aed)"),
    "/reports":      badge(pendingCount,    "linear-gradient(135deg,#f87171,#ef4444)"),
    "/incidents":    badge(activeIncidents, "linear-gradient(135deg,#ef4444,#b91c1c)", true),
    "/dependencies": badge(vulnDeps,        "linear-gradient(135deg,#f59e0b,#d97706)"),
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
          { label:"Overview",       hrefs:["/dashboard","/analytics","/posture"] },
          { label:"Threats",        hrefs:["/violations","/alerts","/incidents","/threat-intel"] },
          { label:"Code Risk",      hrefs:["/scans","/secrets","/dependencies","/vulnerabilities"] },
          { label:"AI Intel",       hrefs:["/trust-score","/shadow-ai","/phantom-deps","/ai-debt"] },
          { label:"Compliance",     hrefs:["/compliance","/compliance-calendar","/sla","/risk-register","/evidence"] },
          { label:"Audit",          hrefs:["/audit","/aibom","/reports"] },
          { label:"Config",         hrefs:["/profile","/settings","/billing","/roi","/orgs","/status","/docs","/admin/go-live","/notifications","/changelog"] },
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
                  const active = pathname === href || pathname.startsWith(href + "/");
                  const badge  = BADGE[href] ?? null;
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
                        {collapsed && badge && (
                          <span className="absolute -top-1 -right-1 w-2 h-2 rounded-full bg-rose-500" />
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
            <div className="w-2 h-2 rounded-full bg-emerald-400 shrink-0 animate-glow-pulse"
              style={{ boxShadow:"0 0 6px rgba(52,211,153,0.6)" }} />
            <p className="text-xs font-medium truncate" style={{ color:"rgba(255,255,255,0.38)" }}>{process.env.NEXT_PUBLIC_ORG ?? "novapay"}</p>
            <span className="ml-auto text-[9px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded-md"
              style={{ color:"rgba(165,180,252,0.7)", background:"rgba(99,102,241,0.15)" }}>
              v1.0
            </span>
          </div>
        )}
        {collapsed ? (
          /* Collapsed: just a color dot */
          <div className="flex justify-center">
            <span className={clsx("w-2 h-2 rounded-full", roleColor.dot)} title={ROLE_LABELS[role]} />
          </div>
        ) : (
          <div className="relative rounded-xl overflow-hidden"
            style={{ background:"rgba(255,255,255,0.06)", border:"1px solid rgba(255,255,255,0.08)" }}>
            <div className="flex items-center gap-2 px-2.5 py-1.5 pointer-events-none">
              <span className={clsx("w-1.5 h-1.5 rounded-full shrink-0", roleColor.dot)} />
              <span className="text-[11px] font-semibold truncate" style={{ color:"rgba(255,255,255,0.58)" }}>
                {ROLE_LABELS[role]}
              </span>
              {!permissions.canAttest && (
                <span className="ml-auto text-[9px] font-semibold tracking-wide" style={{ color:"rgba(255,255,255,0.22)" }}>view only</span>
              )}
              <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"
                className={clsx("shrink-0", !permissions.canAttest ? "" : "ml-auto")}
                style={{ color:"rgba(255,255,255,0.25)" }}>
                <polyline points="6 9 12 15 18 9"/>
              </svg>
            </div>
            <select value={role} onChange={e => setRole(e.target.value as UserRole)} title="Switch role"
              className="absolute inset-0 w-full h-full opacity-0 cursor-pointer">
              <option value="developer">Developer</option>
              <option value="security_reviewer">Security Reviewer</option>
              <option value="admin">Admin</option>
            </select>
          </div>
        )}
      </div>
    </aside>
  );
}
