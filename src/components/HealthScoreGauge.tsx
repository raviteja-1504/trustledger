"use client";

import InfoTooltip from "@/components/InfoTooltip";

interface Props { score: number }

type Grade = { letter: string; color: string; trackColor: string; label: string; gradient: string };

function grade(score: number): Grade {
  if (score >= 90) return { letter: "A", color: "#10b981", trackColor: "#d1fae5", label: "Excellent",  gradient: "linear-gradient(135deg, #34d399, #10b981, #0d9488)" };
  if (score >= 75) return { letter: "B", color: "#6366f1", trackColor: "#e0e7ff", label: "Good",       gradient: "linear-gradient(135deg, #818cf8, #6366f1, #4f46e5)" };
  if (score >= 60) return { letter: "C", color: "#f59e0b", trackColor: "#fef3c7", label: "Fair",       gradient: "linear-gradient(135deg, #fcd34d, #f59e0b, #d97706)" };
  if (score >= 45) return { letter: "D", color: "#f97316", trackColor: "#ffedd5", label: "Poor",       gradient: "linear-gradient(135deg, #fb923c, #f97316, #ea580c)" };
  return               { letter: "F", color: "#ef4444", trackColor: "#fee2e2", label: "Critical",   gradient: "linear-gradient(135deg, #f87171, #ef4444, #dc2626)" };
}

export default function HealthScoreGauge({ score }: Props) {
  const clamped = Math.min(Math.max(score, 0), 100);
  const g = grade(clamped);

  const R       = 52;
  const cx      = 72;
  const cy      = 75;
  const circ    = 2 * Math.PI * R;
  const arcLen  = circ * 0.75;
  const filled  = arcLen * (clamped / 100);

  const factors = [
    { label: "Attestation",  pct: Math.round(Math.min(100, (clamped / 60) * 100)),                            color: g.color },
    { label: "AI content",   pct: Math.round(Math.max(0, Math.min(100, ((clamped - 35) / 25) * 100))),        color: "#f59e0b" },
    { label: "Clean deploys",pct: Math.round(Math.max(0, Math.min(100, ((clamped - 85) / 15) * 100))),        color: "#6366f1" },
  ];

  return (
    <div className="flex flex-col items-center gap-3 w-full">
      {/* Arc gauge */}
      <div className="relative" style={{ width: 144, height: 112 }}>
        <svg width="144" height="144" viewBox="0 0 144 144" style={{ position: "absolute", top: 0, left: 0 }}>
          <defs>
            <linearGradient id="arcGrad" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor={g.color} stopOpacity="0.6" />
              <stop offset="100%" stopColor={g.color} />
            </linearGradient>
          </defs>
          {/* Track */}
          <circle
            cx={cx} cy={cy} r={R}
            fill="none"
            stroke={g.trackColor}
            strokeWidth="10"
            strokeDasharray={`${arcLen} ${circ - arcLen}`}
            strokeLinecap="round"
            transform={`rotate(135 ${cx} ${cy})`}
          />
          {/* Value arc */}
          <circle
            cx={cx} cy={cy} r={R}
            fill="none"
            stroke="url(#arcGrad)"
            strokeWidth="10"
            strokeDasharray={`${filled} ${circ - filled}`}
            strokeLinecap="round"
            transform={`rotate(135 ${cx} ${cy})`}
            style={{ transition: "stroke-dasharray 1s cubic-bezier(0.16,1,0.3,1)" }}
          />
        </svg>
        {/* Centre */}
        <div className="absolute inset-0 flex flex-col items-center justify-center" style={{ top: -2 }}>
          <span className="text-[2.2rem] font-black leading-none tabular-nums" style={{ color: g.color }}>
            {clamped}
          </span>
          <span className="text-[9px] font-bold uppercase tracking-widest text-gray-400 mt-0.5">/ 100</span>
        </div>
      </div>

      {/* Grade pill */}
      <div className="flex items-center gap-2">
        <span
          className="text-xs font-black px-3 py-1 rounded-full tracking-wide text-white"
          style={{ background: g.gradient, boxShadow: `0 2px 10px ${g.color}40` }}
        >
          Grade {g.letter}
        </span>
        <span className="text-xs font-semibold text-gray-500">{g.label}</span>
        <InfoTooltip
          title="Health Score"
          description="Composite score (0–100) representing the overall security posture of your AI code governance."
          formula={"Attestation rate × 60\n+ (1 − AI%) × 25\n+ max(0, 15 − deploys_blocked × 3)"}
          position="top"
        />
      </div>

      {/* Factor bars */}
      <div className="w-full space-y-2 px-1">
        {factors.map(f => (
          <div key={f.label}>
            <div className="flex items-center justify-between mb-1">
              <span className="text-[10px] text-gray-400 font-medium">{f.label}</span>
              <span className="text-[10px] font-black tabular-nums" style={{ color: f.color }}>
                {Math.max(0, f.pct)}%
              </span>
            </div>
            <div className="h-1.5 w-full rounded-full overflow-hidden" style={{ background: "rgba(226,232,240,0.7)" }}>
              <div
                className="h-full rounded-full transition-all duration-1000"
                style={{
                  width: `${Math.max(0, f.pct)}%`,
                  background: f.color,
                  boxShadow: `0 0 6px ${f.color}60`,
                }}
              />
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
