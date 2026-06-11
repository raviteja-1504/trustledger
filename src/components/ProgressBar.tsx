import clsx from "clsx";

interface Props {
  value: number;
  mode?: "ai" | "attest";
  showLabel?: boolean;
  height?: string;
}

function gradientColor(value: number, mode: "ai" | "attest"): string {
  if (mode === "ai") {
    if (value > 0.7) return "from-rose-400 to-rose-600";
    if (value > 0.4) return "from-amber-400 to-amber-500";
    return "from-emerald-400 to-emerald-500";
  }
  if (value >= 0.8) return "from-emerald-400 to-teal-500";
  if (value >= 0.4) return "from-amber-400 to-amber-500";
  return "from-rose-400 to-rose-500";
}

function labelColor(value: number, mode: "ai" | "attest"): string {
  if (mode === "ai") {
    if (value > 0.7) return "text-rose-600";
    if (value > 0.4) return "text-amber-600";
    return "text-emerald-600";
  }
  if (value >= 0.8) return "text-emerald-600";
  if (value >= 0.4) return "text-amber-600";
  return "text-rose-600";
}

export default function ProgressBar({ value, mode = "ai", showLabel = true, height = "h-1.5" }: Props) {
  const pct = Math.min(Math.max(value, 0), 1) * 100;
  const gradient = gradientColor(value, mode);
  const lc = labelColor(value, mode);

  return (
    <div className="flex items-center gap-2 w-full">
      <div className={clsx("flex-1 bg-gray-100/80 rounded-full overflow-hidden", height)}>
        <div
          className={clsx("h-full rounded-full bg-gradient-to-r transition-all duration-700", gradient)}
          style={{ width: `${pct}%` }}
        />
      </div>
      {showLabel && (
        <span className={clsx("text-xs tabular-nums font-semibold w-10 text-right shrink-0", lc)}>
          {pct.toFixed(1)}%
        </span>
      )}
    </div>
  );
}
