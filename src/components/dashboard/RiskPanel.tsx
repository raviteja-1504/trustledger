"use client";

/**
 * Risk over the selected period: weekly CRITICAL/HIGH/MEDIUM flagged files (RiskTrendChart), exact period totals,
 * and the direction of actionable (CRITICAL+HIGH) risk -- second half of the period vs the first.
 */
import dynamic from "next/dynamic";
import type { DashboardData, RiskTrendPoint } from "@/types";

const RiskTrendChart = dynamic(() => import("@/components/RiskTrendChart"), { ssr: false, loading: () => <div className="h-[220px] rounded-xl bg-gray-50 animate-pulse" /> });

export function riskDirection(trend: readonly RiskTrendPoint[]): { pct: number; dir: "up" | "down" | "flat" } | null {
  if (trend.length < 4) return null;
  const half = Math.floor(trend.length / 2);
  const avg = (pts: readonly RiskTrendPoint[]) => pts.reduce((s, p) => s + p.critical_count + p.high_count, 0) / pts.length;
  const a = avg(trend.slice(0, half)), b = avg(trend.slice(half));
  if (a === 0) return b === 0 ? { pct: 0, dir: "flat" } : null;
  const pct = Math.round(((b - a) / a) * 100);
  return { pct: Math.abs(pct), dir: pct > 5 ? "up" : pct < -5 ? "down" : "flat" };
}

export default function RiskPanel({ data, periodLabel }: { data: Pick<DashboardData, "risk_trend" | "risk_totals">; periodLabel: string }) {
  const totals = data.risk_totals ?? data.risk_trend.reduce(
    (t, p) => ({ critical_count: t.critical_count + p.critical_count, high_count: t.high_count + p.high_count, medium_count: t.medium_count + p.medium_count }),
    { critical_count: 0, high_count: 0, medium_count: 0 });
  const dir = riskDirection(data.risk_trend);
  const stats = [
    { k: "Critical", n: totals.critical_count, c: "bg-violet-600" },
    { k: "High", n: totals.high_count, c: "bg-orange-500" },
    { k: "Medium", n: totals.medium_count, c: "bg-amber-400" },
  ];
  return (
    <section aria-label="Risk trend" className="section-card p-5 min-w-0">
      <div className="flex flex-wrap items-start justify-between gap-3 mb-4">
        <div>
          <h2 className="text-sm font-bold text-gray-900">Risk trend</h2>
          <p className="text-xs text-gray-400 mt-0.5">Flagged files by week · {periodLabel}</p>
        </div>
        <div className="flex items-center gap-4">
          {stats.map(s => (
            <div key={s.k} className="text-right">
              <p className="flex items-center justify-end gap-1.5 text-[10px] font-semibold text-gray-500"><span className={`w-2 h-2 rounded-sm ${s.c}`} />{s.k}</p>
              <p className="text-lg font-black tabular-nums text-gray-900 leading-tight">{s.n}</p>
            </div>
          ))}
          {dir && (
            <span className={`text-[11px] font-bold px-2.5 py-1 rounded-full ring-1 ${
              dir.dir === "up" ? "bg-rose-50 text-rose-700 ring-rose-200" : dir.dir === "down" ? "bg-emerald-50 text-emerald-700 ring-emerald-200" : "bg-gray-50 text-gray-600 ring-gray-200"}`}
              title="Average weekly CRITICAL+HIGH, second half of the period vs the first">
              {dir.dir === "up" ? "▲" : dir.dir === "down" ? "▼" : "■"} {dir.pct}% critical/high
            </span>
          )}
        </div>
      </div>
      {data.risk_trend.length ? <RiskTrendChart data={[...data.risk_trend]} /> : (
        <p className="h-[220px] flex items-center justify-center text-xs text-gray-400">No flagged files in this period.</p>
      )}
    </section>
  );
}
