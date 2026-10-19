"use client";

/**
 * Dashboard hero: the Trust Score (lib/governanceScore.ts, computed by /api/trust-score), its 30-day history, the six
 * dimensions with their grades, and the actions worth the most points. Everything here is the server's score; in
 * demo mode only a total is known, so only the total is shown.
 */
import Link from "next/link";
import type { Dimension, GovernanceScore, ScoreAction } from "@/lib/governanceScore";

export interface TrustHistoryPoint { day: string; total: number }

const BAND_COLOR: Record<GovernanceScore["band"], string> = {
  Excellent: "#34d399", Good: "#4ade80", Fair: "#fbbf24", Poor: "#fb923c", Critical: "#f87171",
};
const GRADE_COLOR: Record<Dimension["grade"], string> = {
  A: "#34d399", B: "#a3e635", C: "#fbbf24", D: "#fb923c", F: "#f87171",
};

export function bandFor(total: number): GovernanceScore["band"] {
  return total >= 850 ? "Excellent" : total >= 700 ? "Good" : total >= 550 ? "Fair" : total >= 400 ? "Poor" : "Critical";
}

/** The top `n` actions across all dimensions, most points first; one per destination so the list isn't repetitive. */
export function topActions(dimensions: readonly Pick<Dimension, "actions">[], n = 3): ScoreAction[] {
  const all = dimensions.flatMap(d => d.actions).filter(a => a.gain > 0).sort((a, b) => b.gain - a.gain);
  const seen = new Set<string>();
  const out: ScoreAction[] = [];
  for (const a of all) {
    if (seen.has(a.label)) continue;
    seen.add(a.label); out.push(a);
    if (out.length === n) break;
  }
  return out;
}

/** Change over the history window: latest snapshot minus the one at least `days` back (null without enough history). */
export function scoreDelta(history: readonly TrustHistoryPoint[], days = 7): number | null {
  if (history.length < 2) return null;
  const last = history[history.length - 1];
  const cutoff = new Date(Date.parse(last.day) - days * 86400_000).toISOString().slice(0, 10);
  const base = [...history].reverse().find(p => p.day <= cutoff) ?? history[0];
  return base === last ? null : last.total - base.total;
}

function Ring({ total, color }: { total: number | null; color: string }) {
  const r = 52, c = 2 * Math.PI * r;
  const frac = total == null ? 0 : Math.max(0, Math.min(1, total / 1000));
  return (
    <svg width="132" height="132" viewBox="0 0 132 132" role="img" aria-label={total == null ? "Trust Score loading" : `Trust Score ${total} out of 1000`}>
      <circle cx="66" cy="66" r={r} fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth="10" />
      <circle cx="66" cy="66" r={r} fill="none" stroke={color} strokeWidth="10" strokeLinecap="round"
        strokeDasharray={`${c * frac} ${c}`} transform="rotate(-90 66 66)" style={{ transition: "stroke-dasharray 0.8s ease" }} />
      <text x="66" y="64" textAnchor="middle" fill="#fff" fontSize="32" fontWeight="900" style={{ fontVariantNumeric: "tabular-nums" }}>{total ?? "—"}</text>
      <text x="66" y="84" textAnchor="middle" fill="rgba(255,255,255,0.45)" fontSize="11" fontWeight="600">of 1000</text>
    </svg>
  );
}

function Sparkline({ points }: { points: readonly TrustHistoryPoint[] }) {
  if (points.length < 2) return <p className="text-[11px] text-white/40">History builds up daily.</p>;
  const W = 220, H = 44, pad = 3;
  const vals = points.map(p => p.total);
  const min = Math.min(...vals), max = Math.max(...vals), span = Math.max(max - min, 20);
  const x = (i: number) => pad + (i / (points.length - 1)) * (W - pad * 2);
  const y = (v: number) => H - pad - ((v - min) / span) * (H - pad * 2);
  const d = vals.map((v, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y(v).toFixed(1)}`).join(" ");
  return (
    <svg width="100%" height={H} viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" aria-hidden="true">
      <defs>
        <linearGradient id="trust-spark" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="#818cf8" stopOpacity="0.45" /><stop offset="1" stopColor="#818cf8" stopOpacity="0" />
        </linearGradient>
      </defs>
      <path d={`${d} L${x(vals.length - 1)},${H} L${x(0)},${H} Z`} fill="url(#trust-spark)" />
      <path d={d} fill="none" stroke="#a5b4fc" strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" />
      <circle cx={x(vals.length - 1)} cy={y(vals[vals.length - 1])} r="3" fill="#fff" />
    </svg>
  );
}

export default function TrustHero({ score, history, demoTotal, loading }: {
  score: GovernanceScore | null;
  history: readonly TrustHistoryPoint[];
  /** Demo mode: a local estimate of the total only. */
  demoTotal?: number | null;
  loading?: boolean;
}) {
  const total = score?.total ?? demoTotal ?? null;
  const band = score?.band ?? (total != null ? bandFor(total) : null);
  const color = band ? BAND_COLOR[band] : "#818cf8";
  const delta = scoreDelta(history);
  const actions = score ? topActions(score.dimensions) : [];

  return (
    <section aria-label="Trust Score" className="relative overflow-hidden rounded-3xl text-white"
      style={{ background: "radial-gradient(120% 140% at 0% 0%, #312e81 0%, #1e1b4b 38%, #0b1020 100%)" }}>
      <div className="absolute inset-0 pointer-events-none opacity-[0.07]"
        style={{ backgroundImage: "linear-gradient(rgba(255,255,255,0.6) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.6) 1px, transparent 1px)", backgroundSize: "28px 28px" }} />
      <div className="relative grid grid-cols-1 lg:grid-cols-[auto_1fr_minmax(260px,320px)] gap-6 lg:gap-8 p-5 sm:p-7">

        {/* Score */}
        <div className="flex items-center gap-5">
          <Ring total={loading ? null : total} color={color} />
          <div className="min-w-0 space-y-2">
            <p className="text-[11px] font-bold uppercase tracking-[0.14em] text-indigo-200/70">Trust Score</p>
            {band && <p className="text-2xl font-black leading-none" style={{ color }}>{band}</p>}
            {delta != null && (
              <p className={`text-xs font-semibold ${delta > 0 ? "text-emerald-300" : delta < 0 ? "text-rose-300" : "text-white/50"}`}>
                {delta > 0 ? "▲" : delta < 0 ? "▼" : "■"} {Math.abs(delta)} pts in 7 days
              </p>
            )}
            <div className="w-44"><Sparkline points={history} /></div>
            <Link href="/trust-score" className="inline-block text-xs font-semibold text-indigo-200 hover:text-white">How it&apos;s calculated →</Link>
          </div>
        </div>

        {/* Dimensions */}
        <div className="min-w-0">
          <p className="text-[11px] font-bold uppercase tracking-[0.14em] text-indigo-200/70 mb-3">What drives it</p>
          {score ? (
            <ul className="grid grid-cols-1 sm:grid-cols-2 gap-x-6 gap-y-3">
              {score.dimensions.map(d => (
                <li key={d.key} className="min-w-0">
                  <div className="flex items-baseline justify-between gap-2">
                    <span className="text-xs font-semibold text-white/85 truncate">{d.label}</span>
                    <span className="flex items-baseline gap-1.5 shrink-0">
                      <span className="text-[11px] tabular-nums text-white/45">{d.points}/{d.max_points}</span>
                      <span className="text-xs font-black w-4 text-right" style={{ color: GRADE_COLOR[d.grade] }}>{d.grade}</span>
                    </span>
                  </div>
                  <div className="mt-1.5 h-1.5 rounded-full bg-white/10 overflow-hidden">
                    <div className="h-full rounded-full" style={{ width: `${Math.round(d.value * 100)}%`, background: GRADE_COLOR[d.grade] }} />
                  </div>
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-sm text-white/55">
              {loading ? "Calculating from your scans, reviews, findings and AI tool usage…" : "Open risk, review of risky code, fix deadlines, approved AI tools, scan coverage and leaked secrets — each scored from your real data."}
            </p>
          )}
        </div>

        {/* Next actions */}
        <div className="rounded-2xl bg-white/[0.06] ring-1 ring-white/10 p-4">
          <p className="text-[11px] font-bold uppercase tracking-[0.14em] text-indigo-200/70 mb-2.5">Do next</p>
          {actions.length ? (
            <ol className="space-y-2">
              {actions.map((a, i) => (
                <li key={a.label}>
                  <Link href={a.href} className="group flex items-start gap-2.5 rounded-xl px-2 py-1.5 -mx-2 hover:bg-white/[0.06]">
                    <span className="mt-0.5 w-5 h-5 rounded-full bg-white/10 text-[10px] font-black flex items-center justify-center shrink-0">{i + 1}</span>
                    <span className="min-w-0 flex-1 text-xs text-white/85 leading-snug group-hover:text-white">{a.label}</span>
                    <span className="text-[11px] font-black text-emerald-300 tabular-nums shrink-0">+{a.gain}</span>
                  </Link>
                </li>
              ))}
            </ol>
          ) : (
            <p className="text-xs text-white/55 leading-relaxed">
              {score ? "Nothing to win back — every dimension is at full marks." : "Your highest-value fixes appear here once the score is calculated."}
            </p>
          )}
        </div>
      </div>
    </section>
  );
}
