"use client";

import InfoTooltip from "@/components/InfoTooltip";

/** The three inputs the score is built from (see healthScoreParts). */
export interface HealthInputs { attestation_rate: number; ai_pct: number; blocked_deploys: number }

interface Props { score: number; inputs: HealthInputs }

/** Points each input earns: attestation up to 60, human-written share up to 25, clean deploys up to 15. */
export function healthScoreParts(i: HealthInputs) {
  const attestation = Math.max(0, Math.min(1, i.attestation_rate)) * 60;
  const human       = (1 - Math.max(0, Math.min(1, i.ai_pct))) * 25;
  const deploys     = Math.max(0, 15 - i.blocked_deploys * 3);
  return { attestation, human, deploys, total: Math.round(Math.min(100, attestation + human + deploys)) };
}

type Grade = { letter: string; color: string; trackColor: string; label: string; gradient: string };

function grade(score: number): Grade {
  if (score >= 90) return { letter: "A", color: "#10b981", trackColor: "#d1fae5", label: "Excellent",  gradient: "linear-gradient(135deg, #34d399, #10b981, #0d9488)" };
  if (score >= 75) return { letter: "B", color: "#6366f1", trackColor: "#e0e7ff", label: "Good",       gradient: "linear-gradient(135deg, #818cf8, #6366f1, #4f46e5)" };
  if (score >= 60) return { letter: "C", color: "#f59e0b", trackColor: "#fef3c7", label: "Fair",       gradient: "linear-gradient(135deg, #fcd34d, #f59e0b, #d97706)" };
  if (score >= 45) return { letter: "D", color: "#f97316", trackColor: "#ffedd5", label: "Poor",       gradient: "linear-gradient(135deg, #fb923c, #f97316, #ea580c)" };
  return               { letter: "F", color: "#ef4444", trackColor: "#fee2e2", label: "Critical",   gradient: "linear-gradient(135deg, #f87171, #ef4444, #dc2626)" };
}

export default function HealthScoreGauge({ score, inputs }: Props) {
  const clamped = Math.min(Math.max(score, 0), 100);
  const g = grade(clamped);

  const R       = 52;
  const cx      = 72;
  const cy      = 75;
  const circ    = 2 * Math.PI * R;
  const arcLen  = circ * 0.75;
  const filled  = arcLen * (clamped / 100);

  // The real inputs, each with the points it earns toward the score (they used to be back-derived from the
  // total, so "Attestation 88%" could sit next to an actual attestation rate of 71%).
  const parts = healthScoreParts(inputs);
  const factors = [
    { label: "Attestation",   value: `${Math.round(inputs.attestation_rate * 100)}% attested`, points: parts.attestation, max: 60, color: g.color },
    { label: "Human-written", value: `${Math.round((1 - Math.min(1, inputs.ai_pct)) * 100)}% of code`, points: parts.human, max: 25, color: "#f59e0b" },
    { label: "Clean deploys", value: inputs.blocked_deploys === 0 ? "none blocked" : `${inputs.blocked_deploys} blocked`, points: parts.deploys, max: 15, color: "#6366f1" },
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
            <div className="flex items-center justify-between gap-2 mb-1">
              <span className="text-[11px] text-gray-500 font-medium">{f.label} <span className="text-gray-400">· {f.value}</span></span>
              <span className="text-[11px] font-black tabular-nums shrink-0" style={{ color: f.color }}>
                {Math.round(f.points)}/{f.max}
              </span>
            </div>
            <div className="h-1.5 w-full rounded-full overflow-hidden" style={{ background: "rgba(226,232,240,0.7)" }}>
              <div
                className="h-full rounded-full transition-all duration-1000"
                style={{
                  width: `${(f.points / f.max) * 100}%`,
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
