"use client";

/**
 * Six headline numbers, each a different question and each a link to where it's handled. Tone (good / warn / bad)
 * comes from the number itself, never from a target the data doesn't support.
 */
import Link from "next/link";

export type KpiTone = "good" | "warn" | "bad" | "neutral";

export interface Kpi {
  key: string;
  label: string;
  value: string;
  sub: string;
  href: string;
  tone: KpiTone;
  /** 0-1 for a progress bar under the value (coverage-style metrics). */
  progress?: number;
}

const TONE: Record<KpiTone, { bar: string; value: string; icon: string; glow: string; status: string; label: string }> = {
  good:    { bar: "bg-emerald-500", value: "text-gray-900", icon: "bg-emerald-50 text-emerald-600 ring-emerald-100", glow: "from-emerald-400/70", status: "text-emerald-700 bg-emerald-50", label: "On track" },
  warn:    { bar: "bg-amber-400",   value: "text-gray-900", icon: "bg-amber-50 text-amber-600 ring-amber-100",       glow: "from-amber-400/80",   status: "text-amber-700 bg-amber-50",     label: "Needs work" },
  bad:     { bar: "bg-rose-500",    value: "text-rose-600", icon: "bg-rose-50 text-rose-600 ring-rose-100",          glow: "from-rose-500/80",    status: "text-rose-700 bg-rose-50",       label: "Act now" },
  neutral: { bar: "bg-indigo-500",  value: "text-gray-900", icon: "bg-indigo-50 text-indigo-600 ring-indigo-100",    glow: "from-indigo-300/60",  status: "text-gray-500 bg-gray-50",       label: "No data" },
};

function KpiIcon({ k }: { k: string }) {
  const p = { width: 16, height: 16, viewBox: "0 0 24 24", fill: "none", stroke: "currentColor", strokeWidth: 2, strokeLinecap: "round" as const, strokeLinejoin: "round" as const, "aria-hidden": true };
  switch (k) {
    case "unreviewed": return <svg {...p}><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><polyline points="14 2 14 8 20 8" /><line x1="12" y1="12" x2="12" y2="15" /><line x1="12" y1="18" x2="12.01" y2="18" /></svg>;
    case "signoff":    return <svg {...p}><rect x="3" y="11" width="18" height="11" rx="2" /><path d="M7 11V7a5 5 0 0 1 10 0v4" /></svg>;
    case "sla":        return <svg {...p}><circle cx="12" cy="12" r="9" /><polyline points="12 7 12 12 15 14" /></svg>;
    case "secrets":    return <svg {...p}><circle cx="8" cy="15" r="4" /><path d="M10.85 12.15 19 4" /><path d="m18 5 2 2" /><path d="m15 8 2 2" /></svg>;
    case "review":     return <svg {...p}><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /><polyline points="9 12 11 14 15 10" /></svg>;
    default:           return <svg {...p}><path d="M3 7V5a2 2 0 0 1 2-2h2M17 3h2a2 2 0 0 1 2 2v2M21 17v2a2 2 0 0 1-2 2h-2M7 21H5a2 2 0 0 1-2-2v-2" /><rect x="7" y="7" width="10" height="10" rx="1" /></svg>;
  }
}

export interface KpiInput {
  unreviewedHighRisk: number;
  unreviewedCritical: number;
  awaitingSignoffRepos: number;
  slaBreaches: number;
  openSecrets: number | null;
  openCriticalSecrets: number | null;
  reviewCoverage: number | null;
  reviewedFiles: number | null;
  totalHighRiskFiles: number | null;
  scanCoverage: number;
  reposScanned7d: number;
  reposConnected: number;
}

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

export function buildKpis(k: KpiInput): Kpi[] {
  return [
    {
      key: "unreviewed", label: "Unreviewed high-risk", value: String(k.unreviewedHighRisk),
      sub: k.unreviewedHighRisk ? `${k.unreviewedCritical} critical · need sign-off` : "Every HIGH/CRITICAL file signed off",
      href: "/violations", tone: k.unreviewedCritical ? "bad" : k.unreviewedHighRisk ? "warn" : "good",
    },
    {
      key: "signoff", label: "Repos awaiting sign-off", value: String(k.awaitingSignoffRepos),
      sub: k.awaitingSignoffRepos ? "Merges held by the gate" : "No merges held",
      href: "/violations", tone: k.awaitingSignoffRepos ? "warn" : "good",
    },
    {
      key: "sla", label: "Past fix deadline", value: String(k.slaBreaches),
      sub: k.slaBreaches ? "HIGH/CRITICAL beyond SLA" : "All within deadline",
      href: "/sla", tone: k.slaBreaches ? "bad" : "good",
    },
    {
      key: "secrets", label: "Open secrets", value: k.openSecrets == null ? "—" : String(k.openSecrets),
      sub: k.openSecrets == null ? "Loading…" : k.openSecrets ? `${k.openCriticalSecrets ?? 0} critical · rotate & resolve` : "No leaked credentials open",
      href: "/secrets", tone: k.openSecrets == null ? "neutral" : k.openCriticalSecrets ? "bad" : k.openSecrets ? "warn" : "good",
    },
    {
      key: "review", label: "High-risk reviewed",
      value: k.reviewCoverage == null ? "—" : `${Math.round(k.reviewCoverage * 100)}%`,
      sub: k.totalHighRiskFiles ? `${k.reviewedFiles ?? 0} of ${plural(k.totalHighRiskFiles, "file")}` : "No high-risk files in this period",
      href: "/violations", progress: k.reviewCoverage ?? undefined,
      tone: k.reviewCoverage == null || !k.totalHighRiskFiles ? "neutral" : k.reviewCoverage >= 0.9 ? "good" : k.reviewCoverage >= 0.5 ? "warn" : "bad",
    },
    {
      key: "coverage", label: "Scanned in 7 days", value: `${Math.round(k.scanCoverage * 100)}%`,
      sub: `${k.reposScanned7d} of ${plural(k.reposConnected, "repo")}`,
      href: "/scans", progress: k.scanCoverage,
      tone: !k.reposConnected ? "neutral" : k.scanCoverage >= 0.8 ? "good" : k.scanCoverage >= 0.5 ? "warn" : "bad",
    },
  ];
}

export default function KpiStrip({ kpis }: { kpis: readonly Kpi[] }) {
  return (
    <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-3">
      {kpis.map(k => {
        const t = TONE[k.tone];
        return (
          <Link key={k.key} href={k.href}
            className="group relative overflow-hidden bg-white rounded-2xl border border-gray-100 p-4 shadow-[0_1px_2px_rgba(15,23,42,0.05)] transition-all hover:-translate-y-0.5 hover:shadow-lg hover:border-gray-200">
            <span className={`absolute inset-x-0 top-0 h-0.5 bg-gradient-to-r ${t.glow} to-transparent`} aria-hidden="true" />
            <div className="flex items-start justify-between gap-2">
              <span className={`w-9 h-9 rounded-xl ring-1 flex items-center justify-center ${t.icon}`}><KpiIcon k={k.key} /></span>
              <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${t.status}`}>{t.label}</span>
            </div>
            <p className="mt-3 text-[11px] font-semibold uppercase tracking-wide text-gray-400 truncate">{k.label}</p>
            <p className={`mt-0.5 text-3xl leading-none font-black tabular-nums tracking-tight ${t.value}`}>{k.value}</p>
            {k.progress != null && (
              <div className="mt-2.5 h-1.5 rounded-full bg-gray-100 overflow-hidden">
                <div className={`h-full rounded-full ${t.bar}`} style={{ width: `${Math.round(Math.max(0, Math.min(1, k.progress)) * 100)}%` }} />
              </div>
            )}
            <p className="mt-2 pr-4 text-[11px] text-gray-500 leading-snug line-clamp-2">{k.sub}</p>
            <span className="absolute bottom-3 right-3 text-gray-300 group-hover:text-indigo-500 transition-colors" aria-hidden="true">→</span>
          </Link>
        );
      })}
    </div>
  );
}
