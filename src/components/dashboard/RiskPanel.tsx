"use client";

/**
 * Risk over the selected period: weekly CRITICAL/HIGH/MEDIUM flagged files (RiskTrendChart), exact period totals,
 * and the direction of actionable (CRITICAL+HIGH) risk -- second half of the period vs the first.
 */
import dynamic from "next/dynamic";
import type { DashboardData, RiskTrendPoint } from "@/types";

const RiskTrendChart = dynamic(() => import("@/components/RiskTrendChart"), { ssr: false, loading: () => <div className="h-[220px] rounded-xl bg-gray-50 animate-pulse" /> });

export interface TrendWeek extends RiskTrendPoint {
  /** Axis label: the week's Monday ("Jul 21"), or "Today" for the week in progress. */
  label: string;
  /** Tooltip: the days the point covers, clipped to the period ("Oct 13 – Oct 19"). */
  range: string;
}

const DAY = 86400_000;
const fmt = (ms: number) => new Date(ms).toLocaleDateString("en-US", { month: "short", day: "numeric", timeZone: "UTC" });
const mondayOf = (ms: number) => { const d = new Date(ms); const dow = d.getUTCDay(); return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate()) - ((dow + 6) % 7) * DAY; };

/**
 * Every week of the period, start to end (today), weeks with nothing flagged included as zeros -- so the chart covers
 * the whole "last 90 days" instead of stopping at the last week that had findings. Rows are keyed by their week's
 * Monday (the server may relabel the current week with today's date; that still falls in the same week).
 */
export function fillTrendWeeks(trend: readonly RiskTrendPoint[], period?: { start: string; end: string }, now = Date.now()): TrendWeek[] {
  if (!period && trend.length === 0) return [];
  const startMs = period ? Date.parse(period.start) : Math.min(...trend.map(t => Date.parse(t.date)));
  const endMs = Math.min(period ? Date.parse(period.end) : now, now);
  const byWeek = new Map<number, RiskTrendPoint>();
  for (const t of trend) {
    const k = mondayOf(Date.parse(t.date));
    const cur = byWeek.get(k);
    byWeek.set(k, cur
      ? { ...cur, critical_count: cur.critical_count + t.critical_count, high_count: cur.high_count + t.high_count, medium_count: cur.medium_count + t.medium_count }
      : t);
  }
  const out: TrendWeek[] = [];
  const lastMonday = mondayOf(endMs);
  for (let m = mondayOf(startMs); m <= lastMonday; m += 7 * DAY) {
    const t = byWeek.get(m);
    const from = Math.max(m, startMs), to = Math.min(m + 6 * DAY, endMs);
    const current = m === mondayOf(now);
    out.push({
      date: new Date(m).toISOString().slice(0, 10),
      critical_count: t?.critical_count ?? 0, high_count: t?.high_count ?? 0, medium_count: t?.medium_count ?? 0,
      label: current ? "Today" : fmt(m),
      range: from === to ? fmt(from) : `${fmt(from)} – ${fmt(to)}${current ? " (so far)" : ""}`,
    });
  }
  return out;
}

export function riskDirection(trend: readonly RiskTrendPoint[]): { pct: number; dir: "up" | "down" | "flat" } | null {
  if (trend.length < 4) return null;
  const half = Math.floor(trend.length / 2);
  const avg = (pts: readonly RiskTrendPoint[]) => pts.reduce((s, p) => s + p.critical_count + p.high_count, 0) / pts.length;
  const a = avg(trend.slice(0, half)), b = avg(trend.slice(half));
  if (a === 0) return b === 0 ? { pct: 0, dir: "flat" } : null;
  const pct = Math.round(((b - a) / a) * 100);
  return { pct: Math.abs(pct), dir: pct > 5 ? "up" : pct < -5 ? "down" : "flat" };
}

export default function RiskPanel({ data, periodLabel }: { data: Pick<DashboardData, "risk_trend" | "risk_totals" | "period">; periodLabel: string }) {
  const weeks = fillTrendWeeks(data.risk_trend, data.period);
  const totals = data.risk_totals ?? data.risk_trend.reduce(
    (t, p) => ({ critical_count: t.critical_count + p.critical_count, high_count: t.high_count + p.high_count, medium_count: t.medium_count + p.medium_count }),
    { critical_count: 0, high_count: 0, medium_count: 0 });
  const dir = riskDirection(weeks);
  const stats = [
    { k: "Critical", n: totals.critical_count, c: "bg-violet-600" },
    { k: "High", n: totals.high_count, c: "bg-orange-500" },
    { k: "Medium", n: totals.medium_count, c: "bg-amber-400" },
  ];
  return (
    <section aria-label="Risk trend" className="section-card p-6 min-w-0">
      <div className="flex flex-wrap items-start justify-between gap-3 mb-6">
        <div>
          <h2 className="text-sm font-bold text-gray-900">Risk trend</h2>
          <p className="text-xs text-gray-400 mt-0.5">
            Flagged files per week · {periodLabel}{weeks.length > 0 && <> · {weeks[0].range.split(" – ")[0]} to today</>}
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
          {stats.map(s => (
            <div key={s.k} className="text-right">
              <p className="flex items-center justify-end gap-1.5 text-[11px] font-semibold text-gray-500 whitespace-nowrap"><span className={`w-2 h-2 rounded-sm ${s.c}`} />{s.k}</p>
              <p className="text-lg font-black tabular-nums text-gray-900 leading-tight">{s.n}</p>
            </div>
          ))}
          {dir && (
            <span className={`text-[11px] font-bold px-2.5 py-1 rounded-full ring-1 whitespace-nowrap ${
              dir.dir === "up" ? "bg-rose-50 text-rose-700 ring-rose-200" : dir.dir === "down" ? "bg-emerald-50 text-emerald-700 ring-emerald-200" : "bg-gray-50 text-gray-600 ring-gray-200"}`}
              title="Average weekly CRITICAL+HIGH, second half of the period vs the first">
              {dir.dir === "up" ? "▲" : dir.dir === "down" ? "▼" : "■"} {dir.pct}% critical/high
            </span>
          )}
        </div>
      </div>
      {weeks.some(w => w.critical_count + w.high_count + w.medium_count > 0) ? <RiskTrendChart data={weeks} /> : (
        <p className="h-[220px] flex items-center justify-center text-xs text-gray-400">No flagged files in this period.</p>
      )}
    </section>
  );
}
