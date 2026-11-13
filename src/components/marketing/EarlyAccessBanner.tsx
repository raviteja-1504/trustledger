import Link from "next/link";
import { planLimits } from "@/lib/limits";

const EMERALD = "#34d399";
const CYAN = "#22d3ee";

/** Height of the banner. Pages that show it add this to their top padding, because the bar it sits in is fixed. */
export const EARLY_ACCESS_BANNER_HEIGHT = "2.5rem";

/**
 * The offer, in one line at the top of the homepage: who it is for, what it costs, and what is in it. The numbers come from the plan itself
 * (lib/limits.ts), so the banner can never promise more than the free plan allows.
 */
export function EarlyAccessBanner() {
  const free = planLimits("free");
  const chips = [
    "No credit card",
    `${free.repos} ${free.repos === 1 ? "repository" : "repositories"}`,
    `${free.scans} scans a month`,
  ];
  return (
    <div role="region" aria-label="Free early access" className="border-b"
      style={{ height: EARLY_ACCESS_BANNER_HEIGHT, borderColor: "rgba(52,211,153,0.28)", background: `linear-gradient(90deg, ${EMERALD}26, ${CYAN}1f 55%, ${EMERALD}26)` }}>
      <div className="max-w-6xl mx-auto px-4 sm:px-5 h-full flex items-center justify-center gap-x-3 gap-y-0 text-[12px] sm:text-[13px] text-white/85 min-w-0">
        <span className="hidden sm:inline-flex items-center gap-1.5 shrink-0 rounded-full px-2.5 py-0.5 text-[10.5px] font-bold uppercase tracking-[0.14em] font-mono"
          style={{ color: EMERALD, background: `${EMERALD}1f`, border: `1px solid ${EMERALD}55` }}>
          <span className="w-1.5 h-1.5 rounded-full" style={{ background: EMERALD, boxShadow: `0 0 8px ${EMERALD}` }} aria-hidden />
          Free early access
        </span>
        <span className="font-semibold text-white min-w-0 truncate">
          <span className="sm:hidden">Free early access · No credit card</span>
          <span className="hidden sm:inline">Test TrustLedger on your own repository</span>
        </span>
        <ul className="hidden md:flex items-center gap-x-3 shrink-0 text-white/70">
          {chips.map(c => (
            <li key={c} className="flex items-center gap-1">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke={EMERALD} strokeWidth="3.2" strokeLinecap="round" strokeLinejoin="round" aria-hidden><polyline points="20 6 9 17 4 12" /></svg>
              {c}
            </li>
          ))}
        </ul>
        <Link href="/login?mode=signup" className="shrink-0 whitespace-nowrap font-bold rounded-md px-2.5 py-1 text-[#050810] text-[12px] sm:text-[12.5px]"
          style={{ background: `linear-gradient(135deg, #6ee7b7, ${EMERALD})` }}>
          Start free →
        </Link>
      </div>
    </div>
  );
}
