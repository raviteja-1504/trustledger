"use client";

import {
  ComposedChart, Bar, Line, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer,
} from "recharts";

export interface SLATrendPoint {
  date: string;
  breaches: number;
  avg_resolve_hours: number | null;
}

function CustomTooltip({ active, payload, label }: {
  active?: boolean;
  payload?: { name: string; value: number; color: string; dataKey: string }[];
  label?: string;
}) {
  if (!active || !payload?.length) return null;
  return (
    <div
      className="px-4 py-3 text-sm"
      style={{
        background: "rgba(255,255,255,0.95)",
        border: "1px solid rgba(226,232,240,0.8)",
        borderRadius: "16px",
        boxShadow: "0 8px 32px rgba(0,0,0,0.10), 0 2px 8px rgba(0,0,0,0.06)",
        backdropFilter: "blur(12px)",
      }}
    >
      <p className="font-bold text-gray-800 mb-2.5 text-xs uppercase tracking-wide">{label}</p>
      <div className="space-y-1.5">
        {payload.map(p => (
          <div key={p.dataKey} className="flex items-center gap-2.5">
            <div className="w-0.5 h-4 rounded-full shrink-0" style={{ background: p.color }} />
            <span className="text-xs text-gray-500 w-28">{p.name}</span>
            <span className="font-black text-gray-900 tabular-nums ml-auto pl-3">
              {p.dataKey === "avg_resolve_hours" ? (p.value != null ? `${p.value}h` : "—") : p.value}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function SLATrendChart({ data }: { data: SLATrendPoint[] }) {
  if (!data.length) {
    return (
      <div className="flex flex-col items-center justify-center h-48 gap-3 text-gray-300">
        <svg width="36" height="36" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
          <circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>
        </svg>
        <p className="text-sm font-medium text-gray-400">No SLA history yet</p>
      </div>
    );
  }

  return (
    <ResponsiveContainer width="100%" height={220}>
      <ComposedChart data={data} margin={{ top: 8, right: 8, left: 0, bottom: 0 }}>
        <CartesianGrid strokeDasharray="2 4" stroke="rgba(226,232,240,0.8)" vertical={false} />

        <XAxis
          dataKey="date"
          tick={{ fontSize: 10, fill: "#94a3b8", fontWeight: 500 }}
          tickLine={false}
          axisLine={false}
          tickFormatter={(v: string) => v.slice(5)}
          dy={4}
        />
        <YAxis
          yAxisId="breaches"
          tick={{ fontSize: 10, fill: "#94a3b8", fontWeight: 500 }}
          tickLine={false}
          axisLine={false}
          allowDecimals={false}
          width={28}
        />
        <YAxis
          yAxisId="hours"
          orientation="right"
          tick={{ fontSize: 10, fill: "#94a3b8", fontWeight: 500 }}
          tickLine={false}
          axisLine={false}
          width={32}
        />
        <Tooltip content={<CustomTooltip />} cursor={{ fill: "rgba(99,102,241,0.06)" }} />

        <Bar
          yAxisId="breaches" dataKey="breaches" name="SLA Breaches"
          fill="#f97316" radius={[4, 4, 0, 0]} maxBarSize={22}
        />
        <Line
          yAxisId="hours" type="monotone" dataKey="avg_resolve_hours" name="Avg Resolve Time"
          stroke="#6366f1" strokeWidth={2.5} dot={{ r: 3, fill: "#6366f1" }}
          activeDot={{ r: 5, fill: "#6366f1", stroke: "white", strokeWidth: 2 }}
          connectNulls
        />
      </ComposedChart>
    </ResponsiveContainer>
  );
}
