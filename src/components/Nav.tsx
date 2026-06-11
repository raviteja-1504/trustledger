"use client";

import type { ReactNode } from "react";
import { useState, useEffect, useRef } from "react";
import { usePathname } from "next/navigation";
import Link from "next/link";
import { useNotifications, type Notification, type NotifLevel } from "@/lib/notifications";
import { useLiveAlertNotifications, type LiveNotification } from "@/lib/realtime";
import { analytics } from "@/lib/analytics";

// ── Icons ─────────────────────────────────────────────────────────────────────

function GridIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/>
      <rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/>
    </svg>
  );
}
function DocIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
      <polyline points="14 2 14 8 20 8"/>
      <line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/>
    </svg>
  );
}
function GearIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="3"/>
      <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>
    </svg>
  );
}
function BellIcon() {
  return (
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/>
      <path d="M13.73 21a2 2 0 0 1-3.46 0"/>
    </svg>
  );
}
function XIcon() {
  return (
    <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
    </svg>
  );
}

// ── Level config ──────────────────────────────────────────────────────────────

const LEVEL: Record<NotifLevel, { dot: string; bg: string; border: string; label: string }> = {
  critical: { dot: "#7c3aed", bg: "rgba(237,233,254,0.7)",  border: "rgba(167,139,250,0.3)", label: "CRITICAL" },
  high:     { dot: "#f97316", bg: "rgba(255,237,213,0.6)",  border: "rgba(251,146,60,0.3)",  label: "HIGH"     },
  warning:  { dot: "#f59e0b", bg: "rgba(254,243,199,0.6)",  border: "rgba(252,211,77,0.3)",  label: "WARN"     },
  info:     { dot: "#6366f1", bg: "rgba(238,242,255,0.6)",  border: "rgba(165,180,252,0.3)", label: "INFO"     },
  success:  { dot: "#10b981", bg: "rgba(209,250,229,0.6)",  border: "rgba(110,231,183,0.3)", label: "OK"       },
};

// ── Time-ago ──────────────────────────────────────────────────────────────────

function timeAgo(ms: number): string {
  const s = Math.floor((Date.now() - ms) / 1000);
  if (s < 60)  return "just now";
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return `${Math.floor(s / 86400)}d ago`;
}

// ── Notification item ─────────────────────────────────────────────────────────

function NotifItem({
  n, onRead, onDismiss,
}: {
  n: Notification;
  onRead: (id: string) => void;
  onDismiss: (id: string) => void;
}) {
  const cfg = LEVEL[n.level];
  return (
    <div
      className="relative group/item px-4 py-3 transition-colors"
      style={{
        background: n.read ? "transparent" : cfg.bg,
        borderLeft: n.read ? "3px solid transparent" : `3px solid ${cfg.dot}`,
      }}
    >
      <div className="flex items-start gap-2.5">
        {/* Level dot */}
        <span className="mt-1 w-2 h-2 rounded-full shrink-0" style={{ background: cfg.dot }} />

        {/* Content */}
        <div className="flex-1 min-w-0" onClick={() => onRead(n.id)} style={{ cursor: n.href ? "pointer" : "default" }}>
          {n.href ? (
            <Link href={n.href} onClick={() => onRead(n.id)}>
              <p className="text-xs font-bold text-gray-800 leading-snug">{n.title}</p>
            </Link>
          ) : (
            <p className="text-xs font-bold text-gray-800 leading-snug">{n.title}</p>
          )}
          <p className="text-[11px] text-gray-500 mt-0.5 leading-relaxed">{n.body}</p>
          <p className="text-[10px] text-gray-400 mt-1 tabular-nums">{timeAgo(n.time)}</p>
        </div>

        {/* Dismiss */}
        <button
          className="opacity-0 group-hover/item:opacity-100 transition-opacity text-gray-400 hover:text-gray-600 shrink-0 mt-0.5 p-0.5"
          onClick={() => onDismiss(n.id)}
          aria-label="Dismiss"
        >
          <XIcon />
        </button>
      </div>
    </div>
  );
}

// ── Notification dropdown ─────────────────────────────────────────────────────

interface DropdownProps {
  onClose: () => void;
  notifications: import("@/lib/notifications").Notification[];
  unread: number;
  markRead: (id: string) => void;
  markAllRead: () => void;
  dismiss: (id: string) => void;
}

function NotificationDropdown({ onClose, notifications, unread, markRead, markAllRead, dismiss }: DropdownProps) {
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    function handler(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) onClose();
    }
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [onClose]);

  return (
    <div
      ref={ref}
      className="absolute right-0 top-full mt-2 w-[360px] rounded-2xl overflow-hidden z-50"
      style={{
        background: "rgba(255,255,255,0.97)",
        backdropFilter: "blur(20px) saturate(180%)",
        WebkitBackdropFilter: "blur(20px) saturate(180%)",
        border: "1px solid rgba(226,232,240,0.8)",
        boxShadow: "0 8px 32px rgba(0,0,0,0.12), 0 2px 8px rgba(0,0,0,0.06)",
      }}
    >
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-gray-100">
        <div className="flex items-center gap-2">
          <span className="text-sm font-bold text-gray-900">Notifications</span>
          {unread > 0 && (
            <span className="text-[10px] font-black text-white bg-rose-500 px-1.5 py-0.5 rounded-full leading-none tabular-nums">
              {unread}
            </span>
          )}
        </div>
        <div className="flex items-center gap-3">
          {/* Live pulse */}
          <span className="flex items-center gap-1 text-[10px] text-emerald-600 font-semibold">
            <span className="relative flex w-1.5 h-1.5">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
              <span className="relative inline-flex rounded-full w-1.5 h-1.5 bg-emerald-500" />
            </span>
            Live
          </span>
          {unread > 0 && (
            <button
              className="text-[11px] font-semibold text-indigo-600 hover:text-indigo-800 transition-colors"
              onClick={markAllRead}
            >
              Mark all read
            </button>
          )}
        </div>
      </div>

      {/* List */}
      <div className="max-h-[420px] overflow-y-auto divide-y divide-gray-50">
        {notifications.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-12 gap-3">
            <div className="w-12 h-12 rounded-2xl bg-emerald-50 flex items-center justify-center text-emerald-500"
              style={{ boxShadow: "0 4px 16px rgba(16,185,129,0.12)" }}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>
              </svg>
            </div>
            <p className="text-sm font-bold text-gray-700">All clear</p>
            <p className="text-xs text-gray-400">No notifications yet</p>
          </div>
        ) : (
          notifications.map(n => (
            <NotifItem key={n.id} n={n} onRead={markRead} onDismiss={dismiss} />
          ))
        )}
      </div>

      {/* Footer */}
        <div className="px-4 py-2.5 border-t border-gray-100 flex items-center justify-between"
          style={{ background: "rgba(248,250,252,0.8)" }}>
          <Link href="/notifications" className="text-[10px] text-indigo-500 hover:text-indigo-700 font-semibold transition-colors">
            View all →
          </Link>
          <button
            className="text-[11px] font-semibold text-gray-400 hover:text-rose-500 transition-colors"
            onClick={() => notifications.forEach(n => dismiss(n.id))}
          >
            Clear all
          </button>
        </div>
    </div>
  );
}

// ── Bell button ───────────────────────────────────────────────────────────────

function BellButton() {
  // Single hook instance — badge and dropdown share the same state
  const { notifications, unread, markRead, markAllRead, dismiss, addFromRealtime } = useNotifications();
  const [open, setOpen] = useState(false);

  // Wire Supabase Realtime alerts → notification bell (P1/P2 only)
  useLiveAlertNotifications((n: LiveNotification) => {
    addFromRealtime?.({
      id: n.id, level: n.level, title: n.title,
      body: n.body, time: n.time, read: false, href: n.href,
    });
  });

  return (
    <div className="relative">
      <button
        onClick={() => setOpen(v => !v)}
        className="relative w-9 h-9 rounded-xl flex items-center justify-center transition-all"
        style={{
          color: open ? "#6366f1" : "#94a3b8",
          background: open ? "rgba(238,242,255,0.9)" : "transparent",
        }}
        onMouseEnter={e => {
          if (!open) (e.currentTarget as HTMLElement).style.background = "rgba(248,250,252,0.9)";
          (e.currentTarget as HTMLElement).style.color = "#6366f1";
        }}
        onMouseLeave={e => {
          if (!open) {
            (e.currentTarget as HTMLElement).style.background = "transparent";
            (e.currentTarget as HTMLElement).style.color = "#94a3b8";
          }
        }}
        aria-label="Notifications"
      >
        <BellIcon />
        {unread > 0 && (
          <span
            className="absolute top-1 right-1 min-w-[16px] h-4 rounded-full flex items-center justify-center text-[9px] font-black text-white leading-none px-0.5 tabular-nums"
            style={{ background: "linear-gradient(135deg, #f87171, #ef4444)", boxShadow: "0 1px 4px rgba(239,68,68,0.5)" }}
          >
            {unread > 9 ? "9+" : unread}
          </span>
        )}
      </button>

      {open && (
        <NotificationDropdown
          onClose={() => setOpen(false)}
          notifications={notifications}
          unread={unread}
          markRead={markRead}
          markAllRead={markAllRead}
          dismiss={dismiss}
        />
      )}
    </div>
  );
}

// ── Page config ───────────────────────────────────────────────────────────────

function LockIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/>
    </svg>
  );
}
function ListIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M9 11l3 3L22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/>
    </svg>
  );
}

function ShieldCheckIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><polyline points="9 12 11 14 15 10"/>
    </svg>
  );
}
function WarnIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
      <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
    </svg>
  );
}

function BlockIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/>
    </svg>
  );
}
function BoxIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/>
    </svg>
  );
}
function BellNavIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"/>
      <path d="M13.73 21a2 2 0 0 1-3.46 0"/>
    </svg>
  );
}

const PAGE_TITLES: Record<string, { title: string; sub: string; icon: ReactNode }> = {
  "/dashboard":            { title: "Overview",                sub: "AI code provenance metrics",                  icon: <GridIcon />       },
  "/analytics":            { title: "Analytics",               sub: "Trends, velocity and team performance",        icon: <GridIcon />       },
  "/threat-intel":         { title: "Threat Intelligence",     sub: "AI-specific CVEs and emerging patterns",       icon: <WarnIcon />       },
  "/incidents":            { title: "Incident Response",       sub: "Structured IR playbooks and timeline",         icon: <BlockIcon />      },
  "/posture":              { title: "Security Posture",        sub: "Real-time security health score and trend",    icon: <GridIcon />       },
  "/compliance":           { title: "Compliance Center",       sub: "SOC 2 · EU AI Act · PCI-DSS",                 icon: <ShieldCheckIcon />},
  "/compliance-calendar":  { title: "Compliance Calendar",     sub: "Audit deadlines and review schedule",          icon: <ListIcon />       },
  "/sla":                  { title: "SLA Dashboard",           sub: "Violation SLA tracking and breach alerts",     icon: <WarnIcon />       },
  "/risk-register":        { title: "Risk Register",           sub: "Likelihood × impact risk log",                 icon: <WarnIcon />       },
  "/evidence":             { title: "Evidence Locker",         sub: "Compliance evidence by framework",             icon: <DocIcon />        },
  "/vulnerabilities":      { title: "Vulnerability Intelligence", sub: "CVE mapping for AI patterns",              icon: <WarnIcon />       },
  "/violations":           { title: "Policy Violations",       sub: "Active violations requiring remediation",      icon: <BlockIcon />      },
  "/alerts":               { title: "Security Alerts",         sub: "Real-time security incident management",       icon: <BellNavIcon />    },
  "/secrets":              { title: "Secret Scanner",          sub: "Hardcoded credential detection",               icon: <LockIcon />       },
  "/dependencies":         { title: "Dependency Scanner",      sub: "AI-introduced package risk assessment",        icon: <BoxIcon />        },
  "/phantom-deps":         { title: "Phantom Dependencies",    sub: "Hallucinated package detection",               icon: <BoxIcon />        },
  "/scans":                { title: "Scan History",            sub: "All scan runs across repositories",            icon: <ListIcon />       },
  "/reports":              { title: "Audit Reports",           sub: "Compliance report generation",                 icon: <DocIcon />        },
  "/audit":                { title: "Audit Trail",             sub: "Tamper-evident security event log",            icon: <ListIcon />       },
  "/aibom":                { title: "AI Bill of Materials",    sub: "AI component inventory and export",            icon: <DocIcon />        },
  "/trust-score":          { title: "TrustScore™",            sub: "Governance credit score 0–1000",               icon: <ShieldCheckIcon />},
  "/shadow-ai":            { title: "Shadow AI Detection",     sub: "Unauthorised AI tool discovery",               icon: <WarnIcon />       },
  "/ai-debt":              { title: "AI Debt Clock",           sub: "Accumulated AI code risk over time",           icon: <GridIcon />       },
  "/roi":                  { title: "ROI Dashboard",           sub: "Cost savings and risk reduction metrics",      icon: <GridIcon />       },
  "/profile":              { title: "My Profile",              sub: "Account details and security settings",        icon: <LockIcon />       },
  "/settings":             { title: "Settings",                sub: "Policy, team & integrations",                  icon: <GearIcon />       },
  "/billing":              { title: "Billing & Usage",         sub: "Plans, usage meters and invoices",             icon: <DocIcon />        },
  "/orgs":                 { title: "Organisations",           sub: "Multi-org management",                         icon: <GridIcon />       },
  "/notifications":        { title: "Notifications",           sub: "All alerts and system messages",               icon: <BellNavIcon />    },
  "/changelog":            { title: "API Changelog",           sub: "Public API version history",                   icon: <DocIcon />        },
  "/status":               { title: "System Status",           sub: "Service health and uptime",                    icon: <ShieldCheckIcon />},
  "/docs":                 { title: "API Documentation",       sub: "Interactive OpenAPI reference",                icon: <DocIcon />        },
  "/admin/go-live":        { title: "Go-Live Checklist",       sub: "Production readiness verification",            icon: <ShieldCheckIcon />},
  "/onboarding":           { title: "Onboarding",              sub: "Connect your first repository",                icon: <GridIcon />       },
};

const DYNAMIC_PAGE_TITLES: Array<[string, { title: string; sub: string; icon: ReactNode }]> = [
  ["/pr/",   { title: "PR Scan Details",       sub: "File-level AI and security findings",  icon: <DocIcon />   }],
  ["/repo/", { title: "Repository Detail",     sub: "Scan history for this repository",     icon: <ListIcon />  }],
];

function resolvePageTitle(pathname: string) {
  if (PAGE_TITLES[pathname]) return PAGE_TITLES[pathname];
  for (const [prefix, cfg] of DYNAMIC_PAGE_TITLES) {
    if (pathname.startsWith(prefix)) return cfg;
  }
  return { title: "TrustLedger", sub: "", icon: <GridIcon /> };
}

// ── Nav ───────────────────────────────────────────────────────────────────────

export default function Nav({
  onMobileMenuToggle,
  mobileNavOpen = false,
}: {
  onMobileMenuToggle?: () => void;
  mobileNavOpen?: boolean;
} = {}) {
  const pathname = usePathname() ?? "/";
  const page = resolvePageTitle(pathname);

  useEffect(() => {
    analytics.pageViewed(pathname);
  }, [pathname]);

  return (
    <header
      className="h-14 shrink-0 z-10 relative flex items-center justify-between px-3 sm:px-6"
      style={{
        background: "rgba(255,255,255,0.95)",
        backdropFilter: "blur(12px) saturate(150%)",
        WebkitBackdropFilter: "blur(12px) saturate(150%)",
        borderBottom: "1px solid rgba(226,232,240,0.7)",
        boxShadow: "0 1px 0 rgba(255,255,255,0.8), 0 1px 6px rgba(0,0,0,0.04)",
      }}
    >
      {/* Mobile menu button */}
      {onMobileMenuToggle && (
        <button
          onClick={onMobileMenuToggle}
          className="md:hidden w-8 h-8 rounded-lg flex items-center justify-center text-gray-500 hover:bg-gray-100 transition-colors mr-2 shrink-0"
          aria-label="Toggle sidebar"
        >
          {mobileNavOpen ? (
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
              <line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/>
            </svg>
          ) : (
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
              <line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="18" x2="21" y2="18"/>
            </svg>
          )}
        </button>
      )}

      {/* Left: page breadcrumb */}
      <div className="flex items-center gap-3 flex-1 min-w-0">
        <div
          className="w-7 h-7 rounded-lg flex items-center justify-center text-white shrink-0"
          style={{
            background: "linear-gradient(135deg, #6366f1, #7c3aed)",
            boxShadow: "0 2px 8px rgba(99,102,241,0.35)",
          }}
        >
          {page.icon}
        </div>
        <div className="flex items-center gap-1.5 text-xs">
          <span className="text-gray-400 font-medium">TrustLedger</span>
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="text-gray-300">
            <polyline points="9 18 15 12 9 6"/>
          </svg>
          <span className="font-semibold text-gray-700">{page.title}</span>
        </div>
        {page.sub && (
          <>
            <div className="hidden lg:block w-px h-4 bg-gray-200" />
            <span className="hidden lg:block text-[11px] text-gray-400">{page.sub}</span>
          </>
        )}
      </div>

      {/* Right: search hint + bell */}
      <div className="flex items-center gap-2">
        <button
          onClick={() => {
            const ev = new KeyboardEvent("keydown", { key:"k", metaKey:true, bubbles:true });
            window.dispatchEvent(ev);
          }}
          className="hidden sm:flex items-center gap-2 px-3 py-1.5 text-xs text-gray-400 hover:text-gray-600 bg-gray-50 hover:bg-gray-100 border border-gray-200 rounded-lg transition-colors"
        >
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
            <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
          </svg>
          <span>Search</span>
          <kbd className="font-mono text-[10px] bg-white border border-gray-200 px-1 py-0.5 rounded">⌘K</kbd>
        </button>
        <DarkModeToggle />
        <BellButton />
      </div>
    </header>
  );
}

function DarkModeToggle() {
  const [theme, setTheme] = useState<"light"|"dark"|"system">("system");

  useEffect(() => {
    const saved = localStorage.getItem("tl_theme") as "light"|"dark"|"system" | null;
    const t = saved ?? "system";
    setTheme(t);
    document.documentElement.setAttribute("data-theme", t);
  }, []);

  function toggle() {
    const next = theme === "dark" ? "light" : "dark";
    setTheme(next);
    document.documentElement.setAttribute("data-theme", next);
    localStorage.setItem("tl_theme", next);
  }

  return (
    <button onClick={toggle}
      className="w-9 h-9 rounded-xl flex items-center justify-center transition-all text-gray-400 hover:text-gray-600"
      style={{ background:"transparent" }}
      onMouseEnter={e => { (e.currentTarget as HTMLElement).style.background = "rgba(248,250,252,0.9)"; (e.currentTarget as HTMLElement).style.color = "#6366f1"; }}
      onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = "transparent"; (e.currentTarget as HTMLElement).style.color = "#94a3b8"; }}
      aria-label="Toggle dark mode">
      {theme === "dark" ? (
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/>
          <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/>
          <line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/>
          <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>
        </svg>
      ) : (
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
          <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>
        </svg>
      )}
    </button>
  );
}
