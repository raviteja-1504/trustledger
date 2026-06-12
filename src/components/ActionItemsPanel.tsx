"use client";

import { useState, useEffect, useMemo } from "react";
import Link from "next/link";
import { useRole } from "@/lib/roles";
import { api } from "@/lib/api";
import type { DashboardData, ScanResult } from "@/types";

interface Props {
  data: DashboardData;
  violationStatuses?: Record<string, string>;
}

type Priority = "critical" | "high" | "medium" | "info" | "done";

interface ActionItem {
  id: string;
  priority: Priority;
  icon: React.ReactNode;
  label: string;
  detail: string;
  href: string;
  cta: string;
  sla?: { remainingH: number; overdue: boolean };
}

const PRIORITY_STYLE: Record<Priority, { accent: string; iconBg: string; iconColor: string; bg: string; label: string; labelColor: string }> = {
  critical: { accent: "#7c3aed", iconBg: "#ede9fe", iconColor: "#6d28d9", bg: "rgba(237,233,254,0.25)", label: "CRITICAL", labelColor: "#6d28d9" },
  high:     { accent: "#ef4444", iconBg: "#fef2f2", iconColor: "#dc2626", bg: "rgba(254,242,242,0.25)", label: "HIGH",     labelColor: "#dc2626" },
  medium:   { accent: "#f59e0b", iconBg: "#fffbeb", iconColor: "#d97706", bg: "rgba(255,251,235,0.25)", label: "MEDIUM",   labelColor: "#d97706" },
  info:     { accent: "#38bdf8", iconBg: "#f0f9ff", iconColor: "#0284c7", bg: "rgba(240,249,255,0.25)", label: "INFO",     labelColor: "#0284c7" },
  done:     { accent: "#10b981", iconBg: "#f0fdf4", iconColor: "#059669", bg: "rgba(240,253,244,0.25)", label: "CLEAR",    labelColor: "#059669" },
};

function ShieldIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
    </svg>
  );
}
function EyeIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/>
      <circle cx="12" cy="12" r="3"/>
    </svg>
  );
}
function UsersIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/>
      <circle cx="9" cy="7" r="4"/>
      <path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>
    </svg>
  );
}
function ClockIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>
    </svg>
  );
}
function CheckIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="20 6 9 17 4 12"/>
    </svg>
  );
}
function ArrowIcon() {
  return (
    <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/>
    </svg>
  );
}

// ── AI Pattern Breakdown ─────────────────────────────────────────────────────

const PATTERN_CATS = [
  { key: "sql-injection",   label: "SQL Injection",  color: "#7c3aed", bg: "#f5f3ff", border: "#ddd6fe" },
  { key: "hardcoded-secret", label: "Hardcoded Keys", color: "#ef4444", bg: "#fef2f2", border: "#fecdd3" },
  { key: "jwt-none-alg",    label: "JWT Bypass",     color: "#f97316", bg: "#fff7ed", border: "#fed7aa" },
  { key: "eval-exec",       label: "Eval / Exec",    color: "#f59e0b", bg: "#fffbeb", border: "#fde68a" },
  { key: "access-control",  label: "Access Control", color: "#6366f1", bg: "#eef2ff", border: "#c7d2fe" },
] as const;

// Indicators that don't have a dedicated bucket above roll up into "Access Control"
// (cookie/session/auth-adjacent and other misc findings).
function bucketFor(indicator: string): typeof PATTERN_CATS[number]["key"] {
  if (indicator === "sql-injection") return "sql-injection";
  if (indicator === "hardcoded-secret" || indicator === "high-entropy-secret") return "hardcoded-secret";
  if (indicator === "jwt-none-alg") return "jwt-none-alg";
  if (indicator === "eval-exec") return "eval-exec";
  return "access-control";
}

function computePatternBreakdown(scans: ScanResult[]) {
  const counts: Record<string, number> = {};
  let total = 0;
  scans.forEach(s => s.files.forEach(f => f.risk_indicators.forEach(ind => {
    const bucket = bucketFor(ind);
    counts[bucket] = (counts[bucket] ?? 0) + 1;
    total++;
  })));
  if (total === 0) return [];
  return PATTERN_CATS
    .map(c => ({ ...c, pct: Math.round(((counts[c.key] ?? 0) / total) * 100) }))
    .filter(c => c.pct > 0)
    .sort((a, b) => b.pct - a.pct);
}

function computeSla(repos: DashboardData["repos"], affectedRepos: string[], slaHours: number) {
  const matched = repos.filter(r => affectedRepos.includes(r.repo) && r.last_scan);
  if (!matched.length) return null;
  const oldest = matched.reduce((a, b) =>
    new Date(a.last_scan).getTime() < new Date(b.last_scan).getTime() ? a : b
  );
  const elapsedH = (Date.now() - new Date(oldest.last_scan).getTime()) / 3600000;
  const remainingH = slaHours - elapsedH;
  return { remainingH: Math.abs(remainingH), overdue: remainingH < 0 };
}

function SlaChip({ sla }: { sla: { remainingH: number; overdue: boolean } }) {
  if (sla.overdue) {
    return (
      <span className="inline-flex items-center gap-0.5 text-[9px] font-black text-white bg-red-500 px-1.5 py-0.5 rounded-md uppercase tracking-wide whitespace-nowrap">
        <span className="w-1 h-1 rounded-full bg-white animate-ping inline-block" />
        Overdue
      </span>
    );
  }
  const h = Math.floor(sla.remainingH);
  const label = h < 24 ? `${h}h left` : `${Math.floor(h / 24)}d ${h % 24}h left`;
  const color = h < 6 ? { bg: "#fef2f2", text: "#dc2626" } : h < 24 ? { bg: "#fff7ed", text: "#c2410c" } : { bg: "#fffbeb", text: "#92400e" };
  return (
    <span className="text-[9px] font-bold px-1.5 py-0.5 rounded-md whitespace-nowrap"
      style={{ background: color.bg, color: color.text }}>
      {label}
    </span>
  );
}

export default function ActionItemsPanel({ data, violationStatuses = {} }: Props) {
  const { role, permissions } = useRole();

  const [scans, setScans] = useState<ScanResult[]>([]);
  useEffect(() => {
    let cancelled = false;
    const scanIds = [...new Set(data.repos.filter(r => r.latest_scan_id).map(r => r.latest_scan_id))];
    Promise.all(scanIds.map(id => api.getScan(id).catch(() => null))).then(results => {
      if (!cancelled) setScans(results.filter((s): s is ScanResult => s !== null));
    });
    return () => { cancelled = true; };
  }, [data.repos]);

  const patterns = useMemo(() => computePatternBreakdown(scans), [scans]);

  const unattested  = data.top_risk_files.filter(f => !f.attested);
  const critUnatt   = unattested.filter(f => f.risk_score === "CRITICAL");
  const highUnatt   = unattested.filter(f => f.risk_score === "HIGH");
  const staleRepos  = data.repos.filter(r =>
    !r.last_scan || Date.now() - new Date(r.last_scan).getTime() > 7 * 86400000
  );
  const lowCovRepos = data.repos.filter(r => r.attestation_rate < 0.5);

  const sessionResolved = Object.values(violationStatuses).filter(v => v === "resolved").length;

  const critSla = critUnatt.length > 0
    ? computeSla(data.repos, [...new Set(critUnatt.map(f => f.repo))], 24)
    : null;
  const highSla = highUnatt.length > 0
    ? computeSla(data.repos, [...new Set(highUnatt.map(f => f.repo))], 72)
    : null;

  const critRepos = [...new Set(critUnatt.map(f => f.repo.split("/").pop()))];
  const highRepos = [...new Set(highUnatt.map(f => f.repo.split("/").pop()))];

  const items: ActionItem[] = [];

  if (permissions.canAttest && critUnatt.length > 0) {
    items.push({
      id: "crit-attest",
      priority: "critical",
      icon: <ShieldIcon />,
      label: `${critUnatt.length} critical file${critUnatt.length > 1 ? "s" : ""} unreviewed`,
      detail: critRepos.slice(0, 3).join(" · "),
      href: `/pr/${critUnatt[0].scan_id}`,
      cta: "Review now",
      sla: critSla ?? undefined,
    });
  }

  if (permissions.canAttest && highUnatt.length > 0) {
    items.push({
      id: "high-attest",
      priority: "high",
      icon: <EyeIcon />,
      label: `${highUnatt.length} high-risk file${highUnatt.length > 1 ? "s" : ""} need review`,
      detail: highRepos.slice(0, 3).join(" · "),
      href: `/pr/${highUnatt[0].scan_id}`,
      cta: "Review files",
      sla: highSla ?? undefined,
    });
  }

  if (permissions.canManageUsers && lowCovRepos.length > 0) {
    items.push({
      id: "low-cov",
      priority: "medium",
      icon: <UsersIcon />,
      label: `${lowCovRepos.length} repo${lowCovRepos.length > 1 ? "s" : ""} below 50% coverage`,
      detail: lowCovRepos.slice(0, 2).map(r => r.repo.split("/").pop()).join(" · "),
      href: `/repo/${lowCovRepos[0].repo}`,
      cta: "View repo",
    });
  }

  if (permissions.canScan && staleRepos.length > 0) {
    items.push({
      id: "stale-scan",
      priority: "info",
      icon: <ClockIcon />,
      label: `${staleRepos.length} repo${staleRepos.length > 1 ? "s" : ""} not scanned in 7 days`,
      detail: staleRepos.slice(0, 2).map(r => r.repo.split("/").pop()).join(" · "),
      href: "/dashboard",
      cta: "View repos",
    });
  }

  if (items.length === 0) {
    items.push({
      id: "all-clear",
      priority: "done",
      icon: <CheckIcon />,
      label: "All deploys clean",
      detail: `Attestation ${Math.round(data.attestation_rate * 100)}% · no SLA breaches`,
      href: "/dashboard",
      cta: "",
    });
  }

  const openCount = items.filter(i => i.priority !== "done").length;

  return (
    <div className="section-card overflow-hidden flex flex-col h-full">

      {/* ── Header ── */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-gray-100"
        style={{ background: "linear-gradient(90deg,rgba(248,250,252,0.95),rgba(248,250,252,0.4))" }}>
        <div className="flex items-center gap-2">
          <div className="w-6 h-6 rounded-lg flex items-center justify-center"
            style={{ background: openCount > 0 ? "#ede9fe" : "#f0fdf4" }}>
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none"
              stroke={openCount > 0 ? "#7c3aed" : "#10b981"} strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M9 11l3 3L22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/>
            </svg>
          </div>
          <span className="text-[11px] font-black text-gray-800 tracking-wide">My Actions</span>
          {openCount > 0 && (
            <span className="inline-flex items-center justify-center min-w-[18px] h-[18px] text-[9px] font-black bg-rose-500 text-white rounded-full px-1">
              {openCount}
            </span>
          )}
        </div>
        <span className="text-[9px] font-semibold text-gray-400 bg-gray-100 px-2 py-0.5 rounded-full capitalize">
          {role.replace("_", " ")}
        </span>
      </div>

      {/* ── Session progress ── */}
      {sessionResolved > 0 && (
        <div className="flex items-center gap-2 px-4 py-1.5 border-b border-emerald-100"
          style={{ background: "rgba(240,253,244,0.6)" }}>
          <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="#10b981" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">
            <polyline points="20 6 9 17 4 12"/>
          </svg>
          <span className="text-[10px] font-semibold text-emerald-700">
            {sessionResolved} file{sessionResolved > 1 ? "s" : ""} attested this session
          </span>
        </div>
      )}

      {/* ── Action cards ── */}
      <div className="flex flex-col gap-0 divide-y divide-gray-100/80">
        {items.map(item => {
          const s = PRIORITY_STYLE[item.priority];
          return (
            <div
              key={item.id}
              className="flex items-start gap-3 px-4 py-3 transition-colors group"
              style={{
                background: s.bg,
                borderLeft: `3px solid ${s.accent}`,
              }}
            >
              {/* Icon */}
              <div className="w-7 h-7 rounded-lg flex items-center justify-center shrink-0 mt-0.5"
                style={{ background: s.iconBg, color: s.iconColor }}>
                {item.icon}
              </div>

              {/* Content */}
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-1.5 flex-wrap mb-0.5">
                  <span className="text-[9px] font-black tracking-widest uppercase"
                    style={{ color: s.labelColor }}>
                    {s.label}
                  </span>
                  {item.sla && <SlaChip sla={item.sla} />}
                </div>
                <p className="text-[12px] font-bold text-gray-800 leading-snug truncate">
                  {item.label}
                </p>
                <p className="text-[10px] text-gray-400 truncate leading-snug mt-0.5">
                  {item.detail}
                </p>
              </div>

              {/* CTA */}
              {item.cta ? (
                <Link
                  href={item.href}
                  className="shrink-0 inline-flex items-center gap-1 text-[10px] font-bold px-2.5 py-1.5 rounded-lg transition-colors mt-0.5 whitespace-nowrap"
                  style={{
                    color: s.iconColor,
                    background: s.iconBg,
                  }}
                >
                  {item.cta}
                  <ArrowIcon />
                </Link>
              ) : (
                <div className="shrink-0 w-7 h-7 rounded-lg flex items-center justify-center mt-0.5"
                  style={{ background: "#f0fdf4", color: "#10b981" }}>
                  <CheckIcon />
                </div>
              )}
            </div>
          );
        })}
      </div>

      {/* ── Repos at a Glance ── */}
      <div className="border-t border-gray-100 px-3 pt-2.5 pb-2.5">
        <div className="flex items-center justify-between mb-2 px-1">
          <p className="text-[9px] font-black uppercase tracking-widest text-gray-400">Repos at a Glance</p>
          <Link href="/dashboard" className="text-[9px] font-semibold text-indigo-500 hover:text-indigo-700">All →</Link>
        </div>
        <div className="grid grid-cols-2 gap-1.5">
          {data.repos.slice(0, 4).map(r => {
            const name     = r.repo.split("/").pop() ?? r.repo;
            const aiPct    = Math.round(r.ai_pct * 100);
            const good     = r.attestation_rate >= 0.8;
            const warn     = r.attestation_rate >= 0.5 && !good;
            const dotColor = good ? "#10b981" : warn ? "#f59e0b" : "#ef4444";
            const barColor = r.ai_pct > 0.7 ? "#ef4444" : r.ai_pct > 0.4 ? "#f59e0b" : "#22c55e";
            const bg       = good ? "#f0fdf4" : warn ? "#fffbeb" : "#fef2f2";
            const border   = good ? "#bbf7d0" : warn ? "#fde68a" : "#fecdd3";
            return (
              <Link key={r.repo} href={`/pr/${r.latest_scan_id}`}
                className="rounded-lg px-2.5 py-2 border hover:shadow-sm hover:-translate-y-px transition-all flex flex-col gap-1.5"
                style={{ background: bg, borderColor: border }}>
                <div className="flex items-center gap-1.5">
                  <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: dotColor }} />
                  <span className="text-[10px] font-bold text-gray-700 truncate leading-none">
                    {name.length > 10 ? name.slice(0, 10) + "…" : name}
                  </span>
                </div>
                <div className="h-1 rounded-full overflow-hidden bg-white/70">
                  <div className="h-full rounded-full" style={{ width: `${aiPct}%`, background: barColor }} />
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-[9px] font-bold tabular-nums" style={{ color: barColor }}>{aiPct}% AI</span>
                  <span className="text-[9px] font-semibold text-gray-400">{Math.round(r.attestation_rate * 100)}% att.</span>
                </div>
              </Link>
            );
          })}
        </div>
      </div>

      {/* ── AI Pattern Breakdown ── */}
      <div className="flex-1 flex flex-col border-t border-gray-100 px-3 pt-2 pb-3 min-h-0">
        <p className="text-[9px] font-black uppercase tracking-widest text-gray-400 mb-2 px-1">AI Pattern Breakdown</p>
        {patterns.length === 0 ? (
          <div className="flex-1 flex items-center justify-center">
            <p className="text-[10px] text-gray-400">No risk patterns detected in recent scans</p>
          </div>
        ) : (
          <>
            <div className="flex h-2 rounded-full overflow-hidden gap-px mb-3">
              {patterns.map(p => (
                <div key={p.label} className="h-full transition-all duration-700"
                  style={{ width: `${p.pct}%`, background: p.color }} />
              ))}
            </div>
            <div className="flex-1 grid grid-cols-2 gap-1.5" style={{ gridAutoRows: "1fr" }}>
              {patterns.map(p => (
                <div key={p.label}
                  className="rounded-xl px-2.5 py-2 border flex flex-col justify-between"
                  style={{ background: p.bg, borderColor: p.border }}>
                  <span className="text-lg font-black tabular-nums leading-none" style={{ color: p.color }}>{p.pct}%</span>
                  <div className="h-1 rounded-full overflow-hidden my-1.5" style={{ background: p.border }}>
                    <div className="h-full rounded-full" style={{ width: `${p.pct}%`, background: p.color }} />
                  </div>
                  <span className="text-[9px] font-bold leading-snug" style={{ color: p.color, opacity: 0.8 }}>{p.label}</span>
                </div>
              ))}
            </div>
          </>
        )}
      </div>

    </div>
  );
}
