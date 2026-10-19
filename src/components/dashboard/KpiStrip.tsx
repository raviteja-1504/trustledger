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

const TONE: Record<KpiTone, { dot: string; bar: string; value: string; ring: string }> = {
  good:    { dot: "bg-emerald-500", bar: "bg-emerald-500", value: "text-gray-900", ring: "hover:ring-emerald-200" },
  warn:    { dot: "bg-amber-400",   bar: "bg-amber-400",   value: "text-gray-900", ring: "hover:ring-amber-200" },
  bad:     { dot: "bg-rose-500",    bar: "bg-rose-500",    value: "text-rose-600", ring: "hover:ring-rose-200" },
  neutral: { dot: "bg-slate-300",   bar: "bg-indigo-500",  value: "text-gray-900", ring: "hover:ring-indigo-200" },
};

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
            className={`group bg-white rounded-2xl border border-gray-100 p-4 shadow-sm ring-1 ring-transparent transition-all hover:shadow-md ${t.ring}`}>
            <div className="flex items-center gap-1.5">
              <span className={`w-1.5 h-1.5 rounded-full ${t.dot}`} />
              <p className="text-[11px] font-semibold text-gray-500 truncate">{k.label}</p>
            </div>
            <p className={`mt-1.5 text-[28px] leading-none font-black tabular-nums ${t.value}`}>{k.value}</p>
            {k.progress != null && (
              <div className="mt-2 h-1 rounded-full bg-gray-100 overflow-hidden">
                <div className={`h-full rounded-full ${t.bar}`} style={{ width: `${Math.round(Math.max(0, Math.min(1, k.progress)) * 100)}%` }} />
              </div>
            )}
            <p className="mt-2 text-[11px] text-gray-400 leading-snug line-clamp-2">{k.sub}</p>
          </Link>
        );
      })}
    </div>
  );
}
