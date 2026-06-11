"use client";

import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer, ReferenceLine,
} from "recharts";
import type { RiskTrendPoint } from "@/types";

function CustomTooltip({ active, payload, label }: {
  active?: boolean;
  payload?: { name: string; value: number; color: string }[];
  label?: string;
}) {
  if (!active || !payload?.length) return null;
  const total = payload.reduce((s, p) => s + p.value, 0);
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
          <div key={p.name} className="flex items-center gap-2.5">
            <div className="w-0.5 h-4 rounded-full shrink-0" style={{ background: p.color }} />
            <span className="text-xs text-gray-500 w-16">{p.name}</span>
            <span className="font-black text-gray-900 tabular-nums ml-auto pl-3">{p.value}</span>
          </div>
        ))}
      </div>
      {total > 0 && (
        <div className="mt-2.5 pt-2.5 border-t border-gray-100 flex items-center justify-between">
          <span className="text-xs text-gray-400">Total</span>
          <span className="text-xs font-black text-gray-700 tabular-nums">{total}</span>
        </div>
      )}
    </div>
  );
}

export default function RiskTrendChart({ data }: { data: RiskTrendPoint[] }) {
  if (!data.length) {
    return (
      <div className="flex flex-col items-center justify-center h-56 gap-3 text-gray-300">
        <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
          <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
        </svg>
        <p className="text-sm font-medium text-gray-400">No trend data yet</p>
      </div>
    );
  }

  const hasMedium = data.some(d => (d.medium_count ?? 0) > 0);
  const maxVal = Math.max(...data.map(d => Math.max(d.critical_count, d.high_count, d.medium_count ?? 0)));

  return (
    <ResponsiveContainer width="100%" height={252}>
      <AreaChart data={data} margin={{ top: 8, right: 8, left: -12, bottom: 0 }}>
        <defs>
          <linearGradient id="gradMedium" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%"  stopColor="#f59e0b" stopOpacity={0.22} />
            <stop offset="95%" stopColor="#f59e0b" stopOpacity={0.01} />
          </linearGradient>
          <linearGradient id="gradHigh" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%"  stopColor="#f97316" stopOpacity={0.26} />
            <stop offset="95%" stopColor="#f97316" stopOpacity={0.01} />
          </linearGradient>
          <linearGradient id="gradCritical" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%"  stopColor="#7c3aed" stopOpacity={0.26} />
            <stop offset="95%" stopColor="#7c3aed" stopOpacity={0.01} />
          </linearGradient>
        </defs>

        <CartesianGrid strokeDasharray="2 4" stroke="rgba(226,232,240,0.8)" vertical={false} />

        {maxVal > 0 && (
          <ReferenceLine y={maxVal} stroke="rgba(226,232,240,0.5)" strokeDasharray="4 4" />
        )}

        <XAxis
          dataKey="date"
          tick={{ fontSize: 10, fill: "#94a3b8", fontWeight: 500 }}
          tickLine={false}
          axisLine={false}
          tickFormatter={(v: string) => v.slice(5)}
          dy={4}
        />
        <YAxis
          tick={{ fontSize: 10, fill: "#94a3b8", fontWeight: 500 }}
          tickLine={false}
          axisLine={false}
          allowDecimals={false}
          width={28}
        />
        <Tooltip content={<CustomTooltip />} cursor={{ stroke: "rgba(99,102,241,0.15)", strokeWidth: 1.5, strokeDasharray: "3 3" }} />

        {hasMedium && (
          <Area
            type="monotone" dataKey="medium_count" name="MEDIUM"
            stroke="#f59e0b" strokeWidth={1.5}
            fill="url(#gradMedium)"
            dot={false}
            activeDot={{ r: 4, fill: "#f59e0b", stroke: "white", strokeWidth: 2 }}
          />
        )}
        <Area
          type="monotone" dataKey="high_count" name="HIGH"
          stroke="#f97316" strokeWidth={2.5}
          fill="url(#gradHigh)"
          dot={false}
          activeDot={{ r: 5, fill: "#f97316", stroke: "white", strokeWidth: 2 }}
        />
        <Area
          type="monotone" dataKey="critical_count" name="CRITICAL"
          stroke="#7c3aed" strokeWidth={2.5}
          fill="url(#gradCritical)"
          dot={false}
          activeDot={{ r: 5, fill: "#7c3aed", stroke: "white", strokeWidth: 2 }}
        />
      </AreaChart>
    </ResponsiveContainer>
  );
}
