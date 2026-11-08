"use client";

/**
 * How limits show up in the UI (the numbers are lib/limits.ts):
 *  - LimitMeter: usage against a plan quota, with a warning from 80% and a clear message at and past the cap
 *  - CapNotice:  a list was cut at a cap -- says how many are shown, why, and what to do
 *  - CapNote:    a one-line reminder of a cap next to the control it limits ("Up to 5,000 findings at once")
 */
import Link from "next/link";
import { CAPS, isTruncated, limitMessage, limitStatus, type CapId, type LimitLevel } from "@/lib/limits";

const BAR: Record<LimitLevel, string> = { unlimited: "bg-gray-300", ok: "bg-emerald-500", warn: "bg-amber-500", full: "bg-orange-500", over: "bg-rose-600" };
const TEXT: Record<LimitLevel, string> = { unlimited: "text-gray-500", ok: "text-gray-700", warn: "text-amber-700", full: "text-orange-700", over: "text-rose-700" };
const fmt = (v: number) => v.toLocaleString("en-US");

export function LimitMeter({ label, noun, used, limit, upgradeHref = "/billing", compact = false }: {
  label: string;
  /** What is counted, for the sentence ("scans", "members"). */
  noun: string;
  used: number;
  /** -1 = unlimited. */
  limit: number;
  upgradeHref?: string | null;
  compact?: boolean;
}) {
  const s = limitStatus(used, limit);
  const msg = limitMessage(noun, s, { upgrade: upgradeHref !== null });
  return (
    <div className={compact ? "space-y-1" : "space-y-1.5"} data-level={s.level}>
      <div className="flex items-baseline justify-between gap-3">
        <span className="text-xs font-semibold text-gray-600">{label}</span>
        <span className={`text-xs font-bold tabular-nums ${TEXT[s.level]}`}>
          {fmt(s.used)} / {s.level === "unlimited" ? "∞" : fmt(s.limit)}
        </span>
      </div>
      <div className="h-1.5 w-full overflow-hidden rounded-full bg-gray-100" role="progressbar" aria-label={label}
        aria-valuemin={0} aria-valuemax={s.level === "unlimited" ? undefined : s.limit} aria-valuenow={s.used}
        aria-valuetext={s.level === "unlimited" ? `${fmt(s.used)}, unlimited` : `${fmt(s.used)} of ${fmt(s.limit)}`}>
        <div className={`h-full rounded-full transition-all ${BAR[s.level]}`} style={{ width: s.level === "unlimited" ? "0%" : `${s.pct}%` }} />
      </div>
      {msg && (
        <p className={`text-[11px] font-medium ${TEXT[s.level]}`}>
          {msg}{" "}
          {upgradeHref && <Link href={upgradeHref} className="font-bold underline underline-offset-2">See plans</Link>}
        </p>
      )}
    </div>
  );
}

/** Shown when a list stops at a cap: "Showing the first 1,000 of 1,432 incidents…". Renders nothing when nothing was cut. */
export function CapNotice({ cap, shown, total, noun }: {
  cap: CapId;
  shown: number;
  /** The real total when the API knows it. */
  total?: number | null;
  /** Plural noun for the sentence; defaults to the cap's own unit. */
  noun?: string;
}) {
  const c = CAPS[cap];
  if (!isTruncated(shown, c.value, total)) return null;
  const what = noun ?? c.unit;
  return (
    <div role="status" className="flex items-start gap-2.5 rounded-xl border border-amber-200 bg-amber-50 px-4 py-2.5 text-xs leading-relaxed text-amber-900" data-cap={cap}>
      <span aria-hidden className="mt-px">⚠</span>
      <p>
        <strong>{total != null ? `Showing ${fmt(shown)} of ${fmt(total)} ${what}.` : `Showing the first ${fmt(shown)} ${what}.`}</strong>{" "}
        {c.effect} {c.advice}
      </p>
    </div>
  );
}

/** A quiet reminder of a cap beside the control it limits. */
export function CapNote({ cap, className = "" }: { cap: CapId; className?: string }) {
  const c = CAPS[cap];
  return <p className={`text-[11px] text-gray-400 ${className}`} data-cap={cap}>{c.effect} {c.advice}</p>;
}
