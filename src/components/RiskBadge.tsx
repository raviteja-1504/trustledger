import type { RiskLevel } from "@/types";
import clsx from "clsx";

const BADGE: Record<RiskLevel, string> = {
  CRITICAL: "bg-violet-50  text-violet-800  ring-violet-200",
  HIGH:     "bg-orange-50  text-orange-800  ring-orange-200",
  MEDIUM:   "bg-amber-50   text-amber-700   ring-amber-200",
  LOW:      "bg-emerald-50 text-emerald-700 ring-emerald-200",
  UNKNOWN:  "bg-gray-50    text-gray-500    ring-gray-200",
};

function AnimatedDot({ level }: { level: RiskLevel }) {
  if (level === "CRITICAL") {
    return (
      <span className="relative flex w-1.5 h-1.5 shrink-0">
        <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-violet-400 opacity-70" />
        <span className="relative inline-flex rounded-full w-1.5 h-1.5 bg-violet-600" />
      </span>
    );
  }
  if (level === "HIGH") {
    return (
      <span className="relative flex w-1.5 h-1.5 shrink-0">
        <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-orange-400 opacity-60" />
        <span className="relative inline-flex rounded-full w-1.5 h-1.5 bg-orange-500" />
      </span>
    );
  }
  const dotColor: Record<RiskLevel, string> = {
    CRITICAL: "bg-violet-500",
    HIGH:     "bg-orange-500",
    MEDIUM:   "bg-amber-400",
    LOW:      "bg-emerald-500",
    UNKNOWN:  "bg-gray-400",
  };
  return <span className={clsx("w-1.5 h-1.5 rounded-full shrink-0", dotColor[level])} />;
}

export default function RiskBadge({ level }: { level: RiskLevel }) {
  return (
    <span className={clsx(
      "inline-flex items-center gap-1.5 text-xs font-bold px-2.5 py-1 rounded-full ring-1 whitespace-nowrap",
      BADGE[level],
    )}>
      <AnimatedDot level={level} />
      {level}
    </span>
  );
}
