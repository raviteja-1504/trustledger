"use client";

import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from "recharts";
import type { RiskTrendPoint } from "@/types";

interface Props {
  data: RiskTrendPoint[];
  attestationRate: number;
}

function CustomTooltip({ active, payload }: { active?: boolean; payload?: { name: string; value: number }[] }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="px-3 py-2 text-xs font-semibold"
      style={{
        background: "rgba(255,255,255,0.95)",
        border: "1px solid rgba(226,232,240,0.8)",
        borderRadius: "12px",
        boxShadow: "0 4px 16px rgba(0,0,0,0.10)",
        backdropFilter: "blur(8px)",
      }}>
      {payload[0].name}: <span className="font-black">{payload[0].value}</span> files
    </div>
  );
}

const SEGMENTS = [
  { key: "critical_count", name: "CRITICAL", color: "#7c3aed", gradient: "from-violet-500 to-purple-600" },
  { key: "high_count",     name: "HIGH",     color: "#f97316", gradient: "from-orange-400 to-orange-600" },
  { key: "medium_count",   name: "MEDIUM",   color: "#f59e0b", gradient: "from-amber-400 to-amber-500"   },
] as const;

function AttestBar({ pct }: { pct: number }) {
  const gradient =
    pct >= 80 ? "linear-gradient(90deg, #34d399, #10b981, #0d9488)"
    : pct >= 50 ? "linear-gradient(90deg, #fbbf24, #f59e0b)"
    : "linear-gradient(90deg, #f87171, #f43f5e)";
  const color = pct >= 80 ? "#10b981" : pct >= 50 ? "#f59e0b" : "#f43f5e";

  return (
    <div className="w-full px-1 pt-3 border-t border-gray-100">
      <div className="flex items-center justify-between mb-1.5">
        <span className="text-xs font-semibold text-gray-600">Attestation coverage</span>
        <span className="text-sm font-black tabular-nums" style={{ color }}>{pct}%</span>
      </div>
      <div className="h-2 rounded-full overflow-hidden" style={{ background: "rgba(226,232,240,0.6)" }}>
        <div
          className="h-full rounded-full transition-all duration-700"
          style={{ width: `${pct}%`, background: gradient }}
        />
      </div>
    </div>
  );
}

export default function RiskDonut({ data, attestationRate }: Props) {
  const totals = SEGMENTS.map(s => ({
    name:     s.name,
    color:    s.color,
    gradient: s.gradient,
    value:    data.reduce((sum, d) => sum + ((d[s.key] as number) ?? 0), 0),
  })).filter(d => d.value > 0);

  const total  = totals.reduce((s, d) => s + d.value, 0);
  const attPct = Math.round(attestationRate * 100);

  if (total === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-3 py-8">
        <div className="w-16 h-16 rounded-2xl bg-emerald-50 flex items-center justify-center"
          style={{ boxShadow: "0 4px 16px rgba(16,185,129,0.15)" }}>
          <svg className="text-emerald-500 w-8 h-8" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>
          </svg>
        </div>
        <p className="text-sm font-bold text-gray-700">All clear</p>
        <p className="text-xs text-gray-400">No risk files detected</p>
        <AttestBar pct={attPct} />
      </div>
    );
  }

  return (
    <div className="flex flex-col items-center gap-4">
      {/* Donut */}
      <div className="relative w-full" style={{ height: 196 }}>
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={totals}
              cx="50%" cy="50%"
              innerRadius={58} outerRadius={84}
              paddingAngle={3}
              dataKey="value"
              startAngle={90} endAngle={-270}
              style={{ filter: "drop-shadow(0 4px 12px rgba(0,0,0,0.08))" }}
            >
              {totals.map((entry, i) => (
                <Cell key={i} fill={entry.color} stroke="none" />
              ))}
            </Pie>
            <Tooltip content={<CustomTooltip />} />
          </PieChart>
        </ResponsiveContainer>
        {/* Center label */}
        <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
          <span className="text-3xl font-black text-gray-900 leading-none tabular-nums">{total}</span>
          <span className="text-[11px] text-gray-400 font-semibold mt-0.5 uppercase tracking-wide">risk files</span>
        </div>
      </div>

      {/* Legend */}
      <div className="w-full space-y-2.5 px-1">
        {totals.map(d => (
          <div key={d.name} className="flex items-center gap-2.5">
            <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ background: d.color }} />
            <span className="text-xs font-bold text-gray-700 w-16">{d.name}</span>
            <div className="flex-1 h-1.5 rounded-full overflow-hidden" style={{ background: "rgba(226,232,240,0.6)" }}>
              <div
                className="h-full rounded-full transition-all duration-700"
                style={{ width: `${(d.value / total) * 100}%`, background: d.color }}
              />
            </div>
            <span className="text-xs text-gray-400 tabular-nums w-6 text-right font-semibold">{d.value}</span>
            <span className="text-[10px] text-gray-300 tabular-nums w-10 text-right">
              {Math.round((d.value / total) * 100)}%
            </span>
          </div>
        ))}
      </div>

      <AttestBar pct={attPct} />
    </div>
  );
}
