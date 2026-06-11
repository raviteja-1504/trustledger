import { ReactNode } from "react";
import clsx from "clsx";
import InfoTooltip from "@/components/InfoTooltip";

type Color = "indigo" | "violet" | "emerald" | "rose" | "amber";

interface Trend {
  direction: "up" | "down" | "neutral";
  label: string;
}

interface Props {
  label: string;
  value: string | number;
  sub?: string;
  icon: ReactNode;
  color: Color;
  trend?: Trend;
  ringValue?: number;
  info?: { title: string; description: string; formula?: string };
}

const cfg: Record<Color, {
  bar:          string;
  iconBg:       string;
  iconText:     string;
  ringColor:    string;
  ringTrack:    string;
  trendUp:      string;
  trendDown:    string;
  trendNeutral: string;
  glowColor:    string;
  spotColor:    string;
}> = {
  indigo: {
    bar:          "bg-gradient-to-r from-indigo-400 via-indigo-500 to-violet-500",
    iconBg:       "bg-indigo-50",
    iconText:     "text-indigo-600",
    ringColor:    "#6366f1",
    ringTrack:    "#e0e7ff",
    trendUp:      "bg-emerald-50 text-emerald-700 ring-emerald-200/80",
    trendDown:    "bg-rose-50 text-rose-600 ring-rose-200/80",
    trendNeutral: "bg-gray-50 text-gray-500 ring-gray-200/80",
    glowColor:    "rgba(99,102,241,0.12)",
    spotColor:    "rgba(99,102,241,0.04)",
  },
  violet: {
    bar:          "bg-gradient-to-r from-violet-400 via-violet-500 to-purple-600",
    iconBg:       "bg-violet-50",
    iconText:     "text-violet-600",
    ringColor:    "#7c3aed",
    ringTrack:    "#ede9fe",
    trendUp:      "bg-rose-50 text-rose-600 ring-rose-200/80",
    trendDown:    "bg-emerald-50 text-emerald-700 ring-emerald-200/80",
    trendNeutral: "bg-gray-50 text-gray-500 ring-gray-200/80",
    glowColor:    "rgba(124,58,237,0.12)",
    spotColor:    "rgba(124,58,237,0.04)",
  },
  emerald: {
    bar:          "bg-gradient-to-r from-emerald-400 via-emerald-500 to-teal-500",
    iconBg:       "bg-emerald-50",
    iconText:     "text-emerald-600",
    ringColor:    "#10b981",
    ringTrack:    "#d1fae5",
    trendUp:      "bg-emerald-50 text-emerald-700 ring-emerald-200/80",
    trendDown:    "bg-rose-50 text-rose-600 ring-rose-200/80",
    trendNeutral: "bg-gray-50 text-gray-500 ring-gray-200/80",
    glowColor:    "rgba(16,185,129,0.12)",
    spotColor:    "rgba(16,185,129,0.04)",
  },
  rose: {
    bar:          "bg-gradient-to-r from-rose-400 via-rose-500 to-pink-500",
    iconBg:       "bg-rose-50",
    iconText:     "text-rose-600",
    ringColor:    "#f43f5e",
    ringTrack:    "#ffe4e6",
    trendUp:      "bg-rose-50 text-rose-600 ring-rose-200/80",
    trendDown:    "bg-emerald-50 text-emerald-700 ring-emerald-200/80",
    trendNeutral: "bg-gray-50 text-gray-500 ring-gray-200/80",
    glowColor:    "rgba(244,63,94,0.12)",
    spotColor:    "rgba(244,63,94,0.04)",
  },
  amber: {
    bar:          "bg-gradient-to-r from-amber-400 via-amber-500 to-orange-500",
    iconBg:       "bg-amber-50",
    iconText:     "text-amber-600",
    ringColor:    "#f59e0b",
    ringTrack:    "#fef3c7",
    trendUp:      "bg-amber-50 text-amber-700 ring-amber-200/80",
    trendDown:    "bg-emerald-50 text-emerald-700 ring-emerald-200/80",
    trendNeutral: "bg-gray-50 text-gray-500 ring-gray-200/80",
    glowColor:    "rgba(245,158,11,0.12)",
    spotColor:    "rgba(245,158,11,0.04)",
  },
};

// ── Mini ring ─────────────────────────────────────────────────────────────────

function MiniRing({ value, ringColor, trackColor, children }: {
  value: number; ringColor: string; trackColor: string; children: ReactNode;
}) {
  const r = 18;
  const circ = 2 * Math.PI * r;
  const filled = circ * Math.min(Math.max(value, 0), 1);

  return (
    <div className="relative w-12 h-12 shrink-0 flex items-center justify-center">
      <svg viewBox="0 0 44 44" width="48" height="48" className="absolute inset-0" style={{ transform: "rotate(-90deg)" }}>
        <circle cx="22" cy="22" r={r} fill="none" stroke={trackColor} strokeWidth="3.5" />
        <circle
          cx="22" cy="22" r={r}
          fill="none"
          stroke={ringColor}
          strokeWidth="3.5"
          strokeDasharray={`${filled} ${circ}`}
          strokeLinecap="round"
          style={{ transition: "stroke-dasharray 1s cubic-bezier(0.16,1,0.3,1)" }}
        />
      </svg>
      <span className="relative z-10">{children}</span>
    </div>
  );
}

// ── Component ─────────────────────────────────────────────────────────────────

export default function StatsCard({ label, value, sub, icon, color, trend, ringValue, info }: Props) {
  const c = cfg[color];

  const trendClass =
    trend?.direction === "up"   ? c.trendUp :
    trend?.direction === "down" ? c.trendDown :
    c.trendNeutral;

  const iconEl = ringValue !== undefined ? (
    <MiniRing value={ringValue} ringColor={c.ringColor} trackColor={c.ringTrack}>
      <span className={c.iconText}>{icon}</span>
    </MiniRing>
  ) : (
    <div className={clsx(
      "w-11 h-11 rounded-xl flex items-center justify-center shrink-0",
      c.iconBg, c.iconText,
    )}
      style={{ boxShadow: `0 2px 8px ${c.glowColor}` }}
    >
      {icon}
    </div>
  );

  return (
    <div
      className="relative bg-white rounded-2xl transition-all duration-200 hover:-translate-y-0.5 group"
      style={{
        border: "1px solid rgba(226,232,240,0.8)",
        boxShadow: "0 1px 2px rgba(0,0,0,0.04), 0 2px 8px rgba(0,0,0,0.04), inset 0 1px 0 rgba(255,255,255,1)",
        /* overflow-visible so tooltip can escape the card boundary */
      }}
      onMouseEnter={e => {
        (e.currentTarget as HTMLElement).style.boxShadow =
          `0 8px 24px ${c.glowColor}, 0 2px 8px rgba(0,0,0,0.06), inset 0 1px 0 rgba(255,255,255,1)`;
      }}
      onMouseLeave={e => {
        (e.currentTarget as HTMLElement).style.boxShadow =
          "0 1px 2px rgba(0,0,0,0.04), 0 2px 8px rgba(0,0,0,0.04), inset 0 1px 0 rgba(255,255,255,1)";
      }}
    >
      {/* Visual effects layer: clipped independently so tooltip can overflow */}
      <div className="absolute inset-0 rounded-2xl overflow-hidden pointer-events-none">
        {/* Gradient top bar */}
        <div className={clsx("h-[3px] w-full", c.bar)} />
        {/* Subtle corner spotlight */}
        <div
          className="absolute top-0 right-0 w-24 h-24 rounded-full"
          style={{
            background: `radial-gradient(circle at 80% 20%, ${c.spotColor} 0%, transparent 65%)`,
          }}
        />
      </div>

      <div className="relative p-4 pt-3.5 overflow-visible">
        {/* Label + info */}
        <div className="flex items-center gap-1.5 mb-2.5">
          <p className="text-[10px] font-bold uppercase tracking-[0.08em] text-gray-400 leading-none flex-1">
            {label}
          </p>
          {info && <InfoTooltip title={info.title} description={info.description} formula={info.formula} position="top" />}
        </div>

        {/* Value + icon */}
        <div className="flex items-start justify-between gap-3">
          <p className="text-[2.1rem] font-black text-gray-900 leading-none tracking-tighter tabular-nums">
            {value}
          </p>
          {iconEl}
        </div>

        {/* Footer */}
        <div className="mt-3.5 flex items-center gap-2 flex-wrap min-h-[22px]">
          {trend && (
            <span className={clsx(
              "inline-flex items-center gap-0.5 px-2.5 py-0.5 rounded-full text-[11px] font-semibold ring-1",
              trendClass,
            )}>
              <span className="text-[10px] leading-none">
                {trend.direction === "up" ? "↑" : trend.direction === "down" ? "↓" : "—"}
              </span>
              {trend.label}
            </span>
          )}
          {sub && (
            <span className="text-[11px] text-gray-400">{sub}</span>
          )}
        </div>
      </div>
    </div>
  );
}
