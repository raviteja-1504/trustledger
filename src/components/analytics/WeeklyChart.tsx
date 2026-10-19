"use client";

/** Weekly findings opened (by severity) vs closed, with sign-offs, from /api/analytics weeks. */
import { Bar, CartesianGrid, Legend, Line, ComposedChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import type { AnalyticsWeek } from "@/lib/orgAnalytics";

function Tip({ active, payload }: { active?: boolean; payload?: Array<{ name: string; value: number; color: string; payload: AnalyticsWeek }> }) {
  if (!active || !payload?.length) return null;
  const w = payload[0].payload;
  return (
    <div className="rounded-xl bg-white/95 border border-gray-200 shadow-lg px-3.5 py-2.5 text-xs">
      <p className="font-bold text-gray-800 mb-1.5">{w.range}</p>
      <p className="text-gray-600">Opened <strong className="text-gray-900">{w.opened.total}</strong> <span className="text-gray-400">({w.opened.critical} critical · {w.opened.high} high · {w.opened.medium} medium)</span></p>
      <p className="text-gray-600">Closed <strong className="text-gray-900">{w.closed}</strong></p>
      <p className="text-gray-600">Sign-offs <strong className="text-gray-900">{w.signoffs}</strong></p>
      <p className="text-gray-600">Scans <strong className="text-gray-900">{w.scans}</strong></p>
    </div>
  );
}

export default function WeeklyChart({ weeks }: { weeks: readonly AnalyticsWeek[] }) {
  const rows = weeks.map(w => ({ ...w, critical: w.opened.critical, high: w.opened.high, medium: w.opened.medium }));
  if (!rows.some(r => r.opened.total || r.closed || r.signoffs)) {
    return <p className="h-[260px] flex items-center justify-center text-sm text-gray-400">No findings or sign-offs in this period.</p>;
  }
  return (
    <ResponsiveContainer width="100%" height={280}>
      <ComposedChart data={rows} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
        <CartesianGrid strokeDasharray="2 4" stroke="rgba(226,232,240,0.8)" vertical={false} />
        <XAxis dataKey="label" tick={{ fontSize: 11, fill: "#94a3b8" }} tickLine={false} axisLine={false} interval="preserveStartEnd" minTickGap={16} />
        <YAxis tick={{ fontSize: 11, fill: "#94a3b8" }} tickLine={false} axisLine={false} allowDecimals={false} width={34} />
        <Tooltip content={<Tip />} cursor={{ fill: "rgba(99,102,241,0.06)" }} />
        <Legend wrapperStyle={{ fontSize: 11 }} iconType="circle" />
        <Bar dataKey="critical" name="Opened · critical" stackId="o" fill="#7c3aed" radius={[0, 0, 0, 0]} />
        <Bar dataKey="high" name="Opened · high" stackId="o" fill="#f97316" />
        <Bar dataKey="medium" name="Opened · medium" stackId="o" fill="#fbbf24" radius={[4, 4, 0, 0]} />
        <Bar dataKey="closed" name="Closed" fill="#10b981" radius={[4, 4, 0, 0]} />
        <Line type="monotone" dataKey="signoffs" name="Sign-offs" stroke="#6366f1" strokeWidth={2} dot={{ r: 2 }} />
      </ComposedChart>
    </ResponsiveContainer>
  );
}
