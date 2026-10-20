"use client";

/**
 * Trust Score: how well this organisation governs its code, 0-1000, computed on the server from real data
 * (lib/governanceScore.ts), saved daily so the trend is real, and explained point by point: every dimension shows
 * its formula, the facts behind it, and what to fix to win points back. Using AI never lowers the score.
 *
 * Beside the score: dependencies, incidents and audit evidence (lib/trustSignals.ts), each from its own source.
 * Everything refreshes after a sign-off, on focus and every minute.
 */

import { useState, useEffect, useMemo, useCallback } from "react";
import Link from "next/link";
import AuthGuard from "@/components/AuthGuard";
import PageSkeleton from "@/components/PageSkeleton";
import { authedFetch, isSeedMode, getAuthHeader } from "@/lib/useRealData";
import { formatDateOnly, formatDateTime, relativeTime, useTimezone } from "@/lib/timezone";
import { scoreColor } from "@/lib/trustScore";
import { computeGovernanceScore, type GovernanceScore, type Dimension, type ScoreAction } from "@/lib/governanceScore";
import { buildTrustSignals, type SignalSources, type TrustSignal } from "@/lib/trustSignals";
import type { EvidenceOverview } from "@/lib/evidenceEngine";

const POLL_MS = 60_000;
const TONE: Record<TrustSignal["status"], { label: string; dot: string; chip: string; bar: string }> = {
  good:    { label: "Good",       dot: "bg-emerald-500", chip: "text-emerald-700 bg-emerald-50 ring-emerald-100", bar: "bg-emerald-500" },
  warn:    { label: "Needs work", dot: "bg-amber-400",   chip: "text-amber-700 bg-amber-50 ring-amber-100",       bar: "bg-amber-400" },
  bad:     { label: "At risk",    dot: "bg-rose-500",    chip: "text-rose-700 bg-rose-50 ring-rose-100",          bar: "bg-rose-500" },
  unknown: { label: "No data",    dot: "bg-gray-300",    chip: "text-gray-500 bg-gray-50 ring-gray-100",          bar: "bg-gray-300" },
};

interface HistoryPoint { day: string; total: number; dimensions: Record<string, number> }
interface ScoreResponse { score: GovernanceScore; history: HistoryPoint[]; history_available: boolean }

// ── Demo data (seed mode only) ──────────────────────────────────────────────────
function demoResponse(): ScoreResponse {
  const now = new Date();
  const ago = (d: number) => new Date(now.getTime() - d * 86400_000).toISOString();
  const score = computeGovernanceScore({
    now: now.toISOString(),
    repos: ["acme/payments-api", "acme/auth-service", "acme/fraud-detection", "acme/data-platform"],
    scans: [
      { id: "p1", repo: "acme/payments-api", pr_number: 482, created_at: ago(1) },
      { id: "a1", repo: "acme/auth-service", pr_number: 345, created_at: ago(2) },
      { id: "f1", repo: "acme/fraud-detection", pr_number: 219, created_at: ago(3) },
      { id: "d1", repo: "acme/data-platform", pr_number: 103, created_at: ago(19) },
    ],
    riskyFiles: [
      { scan_id: "p1", file_path: "src/card_validator.py", risk_score: "CRITICAL", ai_percentage: 0.91 },
      { scan_id: "p1", file_path: "src/stripe_client.py", risk_score: "HIGH", ai_percentage: 0.76 },
      { scan_id: "a1", file_path: "src/token_exchange.ts", risk_score: "HIGH", ai_percentage: 0.68 },
      { scan_id: "f1", file_path: "models/risk_scorer.ts", risk_score: "CRITICAL", ai_percentage: 0.83 },
    ],
    attested: [{ scan_id: "a1", file_path: "src/token_exchange.ts" }, { scan_id: "p1", file_path: "src/stripe_client.py" }],
    violations: [
      { scan_id: "p1", file_path: "src/card_validator.py", risk_score: "CRITICAL", status: "open", sla_deadline: ago(1) },
      { scan_id: "f1", file_path: "models/risk_scorer.ts", risk_score: "CRITICAL", status: "in_review", sla_deadline: ago(-2) },
    ],
    secrets: [{ scan_id: "d1", severity: "HIGH" }],
    shadow: { policy_configured: true, compliance: 0.75, open_violations: 1 },
  });
  const history = Array.from({ length: 30 }, (_, i) => ({
    day: ago(29 - i).slice(0, 10),
    total: Math.round(Math.min(score.total, 520 + i * 7 + (i % 5) * 6)),
    dimensions: {},
  }));
  history[history.length - 1].total = score.total;
  return { score, history, history_available: true };
}

const BAND_DESC: Record<GovernanceScore["band"], string> = {
  Excellent: "Risky code is reviewed, findings are fixed on time, and AI tools are governed.",
  Good: "A solid foundation. The actions below close the remaining gaps.",
  Fair: "Real governance gaps. Start with the biggest wins below.",
  Poor: "Significant ungoverned risk. Work through the biggest wins below.",
  Critical: "Most risk is ungoverned. Start with open critical findings and unreviewed risky code.",
};

export default function TrustScorePage() {
  const tz = useTimezone();
  const demo = isSeedMode();
  const [data, setData] = useState<ScoreResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [openDim, setOpenDim] = useState<string | null>(null);
  const [downloading, setDownloading] = useState(false);
  const [signalSrc, setSignalSrc] = useState<SignalSources>({ dependencies: null, incidents: null, evidence: null });

  const load = useCallback(async () => {
    if (demo) { setData(demoResponse()); return; }
    const settle = <T,>(p: Promise<T>) => p.then(v => v, () => "unavailable" as const);
    const [, deps, inc, ev] = await Promise.all([
      authedFetch<ScoreResponse>("/api/trust-score?history=90").then(d => { setData(d); setError(null); }, e => setError((e as Error).message || "We couldn't compute the Trust Score.")),
      settle(authedFetch<{ counts: NonNullable<Exclude<SignalSources["dependencies"], "unavailable">> }>("/api/dependencies")),
      settle(authedFetch<{ incidents: Array<{ status: string; severity: string }> }>("/api/incidents?status=active")),
      settle(authedFetch<EvidenceOverview>("/api/evidence/collect?overview=1")),
    ]);
    setSignalSrc({
      dependencies: deps === "unavailable" || !deps?.counts ? "unavailable" : deps.counts,
      incidents: inc === "unavailable" ? "unavailable" : inc.incidents ?? [],
      evidence: ev === "unavailable" || !Array.isArray(ev?.frameworks) ? "unavailable" : ev,
    });
  }, [demo]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    if (demo) return;
    const tick = () => { if (!document.hidden) load(); };
    const id = setInterval(tick, POLL_MS);
    window.addEventListener("tl:attestation", tick);
    window.addEventListener("tl:attest-complete", tick);
    window.addEventListener("focus", tick);
    return () => {
      clearInterval(id);
      window.removeEventListener("tl:attestation", tick); window.removeEventListener("tl:attest-complete", tick); window.removeEventListener("focus", tick);
    };
  }, [demo, load]);

  const signals = useMemo(() => buildTrustSignals(signalSrc), [signalSrc]);

  const score = data?.score;
  const history = useMemo(() => data?.history ?? [], [data]);
  const wins = useMemo(() => score
    ? score.dimensions.flatMap(d => d.actions.map(a => ({ ...a, dim: d.label }))).sort((a, b) => b.gain - a.gain).slice(0, 6)
    : [], [score]);
  const delta = useMemo(() => {
    if (!score || history.length < 2) return null;
    const target = new Date(Date.parse(score.computed_at) - 30 * 86400_000).toISOString().slice(0, 10);
    const past = history.find(h => h.day >= target) ?? history[0];
    return past.day === score.computed_at.slice(0, 10) ? null : { change: score.total - past.total, since: past.day };
  }, [score, history]);

  async function downloadReport() {
    if (demo) return;
    setDownloading(true);
    try {
      const res = await fetch("/api/trust-score?report=1", { headers: await getAuthHeader() });
      if (!res.ok) throw new Error();
      const url = URL.createObjectURL(await res.blob());
      Object.assign(document.createElement("a"), { href: url, download: `trust-score-${new Date().toISOString().slice(0, 10)}.json` }).click();
      URL.revokeObjectURL(url);
    } catch { setError("The report download failed. Please try again."); }
    finally { setDownloading(false); }
  }

  if (error && !score) return <AuthGuard><div className="max-w-4xl mx-auto"><div className="bg-rose-50 border border-rose-200 text-rose-700 text-sm rounded-xl px-4 py-3">{error}</div></div></AuthGuard>;
  if (!score) return <AuthGuard><PageSkeleton loading label="the Trust Score" rows={6} cards={3} /></AuthGuard>;

  const col = scoreColor(score.total);

  return (
    <AuthGuard>
      <div className="max-w-5xl mx-auto space-y-5 pb-10">

        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-xl font-black text-gray-900">Trust Score</h1>
              {demo && <span className="text-[10px] font-bold text-amber-700 bg-amber-50 border border-amber-200 px-2 py-0.5 rounded-full">Demo data</span>}
            </div>
            <p className="text-sm text-gray-500 mt-0.5 max-w-2xl">How well your organisation governs its code, from real scan data. Using AI never lowers the score; ungoverned risk does.</p>
          </div>
          {!demo && (
            <button onClick={downloadReport} disabled={downloading}
              className="px-4 py-2 rounded-xl text-xs font-bold bg-white border border-gray-200 text-gray-700 hover:bg-gray-50 shadow-sm disabled:opacity-50">
              {downloading ? "Preparing…" : "Download signed report"}
            </button>
          )}
        </div>
        {error && <div className="bg-rose-50 border border-rose-200 text-rose-700 text-xs rounded-xl px-4 py-2.5">{error}</div>}

        {/* Score + trend */}
        <div className="rounded-2xl border-2 p-6 grid grid-cols-1 md:grid-cols-[auto_1fr] gap-6 items-center" style={{ background: col.bg, borderColor: col.ring }}>
          <div>
            <div className="flex items-baseline gap-2">
              <span className="text-7xl font-black tabular-nums leading-none" style={{ color: col.text }}>{score.total}</span>
              <span className="text-2xl font-bold text-gray-400">/ 1000</span>
            </div>
            <div className="text-lg font-bold mt-2" style={{ color: col.text }}>{score.band}</div>
            {delta && (
              <p className={`text-xs font-semibold mt-1 ${delta.change > 0 ? "text-green-700" : delta.change < 0 ? "text-rose-700" : "text-gray-500"}`}>
                {delta.change > 0 ? "▲" : delta.change < 0 ? "▼" : "■"} {Math.abs(delta.change)} since {formatDateOnly(delta.since, tz)}
              </p>
            )}
            <p className="text-xs text-gray-500 mt-2 max-w-xs">{BAND_DESC[score.band]}</p>
            <p className="text-[11px] text-gray-400 mt-2">Computed {relativeTime(score.computed_at, tz)}</p>
          </div>
          <TrendChart history={history} tz={tz} historyAvailable={data?.history_available ?? false} />
        </div>

        {/* Biggest wins */}
        {wins.length > 0 && (
          <div className="bg-white rounded-2xl border border-gray-200 overflow-hidden">
            <div className="px-5 py-3 border-b border-gray-100 bg-gray-50 flex items-center justify-between">
              <p className="text-xs font-black text-gray-700 uppercase tracking-wider">Biggest wins</p>
              <p className="text-[11px] text-gray-400">Points each action would add</p>
            </div>
            <div className="divide-y divide-gray-50">
              {wins.map((w, i) => <WinRow key={i} w={w} />)}
            </div>
          </div>
        )}

        {/* Dimensions */}
        <div className="bg-white rounded-2xl border border-gray-200 overflow-hidden">
          <div className="px-5 py-3 border-b border-gray-100 bg-gray-50"><p className="text-xs font-black text-gray-700 uppercase tracking-wider">How the score is made</p></div>
          <div className="divide-y divide-gray-50">
            {score.dimensions.map(d => <DimensionRow key={d.key} d={d} open={openDim === d.key} onToggle={() => setOpenDim(openDim === d.key ? null : d.key)} />)}
          </div>
        </div>

        {/* Beside the score */}
        {!demo && (
          <section aria-label="Beside the score" className="space-y-3">
            <div className="px-1">
              <h2 className="text-xs font-black text-gray-700 uppercase tracking-wider">Beside the score</h2>
              <p className="text-[11px] text-gray-400 mt-0.5">Not counted in the 0–1000, but part of how far your code can be trusted</p>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {signals.map(s => <SignalCard key={s.key} s={s} />)}
            </div>
          </section>
        )}

        {/* Repositories */}
        {score.repos.length > 0 && (
          <div className="bg-white rounded-2xl border border-gray-200 overflow-hidden">
            <div className="px-5 py-3 border-b border-gray-100 bg-gray-50"><p className="text-xs font-black text-gray-700 uppercase tracking-wider">Repositories · weakest first</p></div>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead><tr className="text-left text-xs text-gray-500 border-b border-gray-100">
                  <th className="px-5 py-2 font-semibold">Repository</th><th className="px-3 py-2 font-semibold text-right">Score</th>
                  <th className="px-3 py-2 font-semibold text-right">Open critical</th><th className="px-3 py-2 font-semibold text-right">Open high</th>
                  <th className="px-3 py-2 font-semibold text-right">Risky code reviewed</th><th className="px-3 py-2 font-semibold text-right">Secrets</th>
                  <th className="px-5 py-2 font-semibold text-right">Last scan</th>
                </tr></thead>
                <tbody>
                  {score.repos.map(r => {
                    const c = scoreColor(r.score);
                    return (
                      <tr key={r.repo} className="border-b border-gray-50 last:border-0">
                        <td className="px-5 py-2.5 font-mono text-xs text-gray-800">{r.repo}</td>
                        <td className="px-3 py-2.5 text-right font-black tabular-nums" style={{ color: c.text }}>{r.score}</td>
                        <td className={`px-3 py-2.5 text-right tabular-nums ${r.open_critical ? "text-rose-600 font-bold" : "text-gray-400"}`}>{r.open_critical}</td>
                        <td className={`px-3 py-2.5 text-right tabular-nums ${r.open_high ? "text-amber-600 font-bold" : "text-gray-400"}`}>{r.open_high}</td>
                        <td className="px-3 py-2.5 text-right tabular-nums text-gray-700">{r.review_coverage == null ? "—" : `${Math.round(r.review_coverage * 100)}%`}</td>
                        <td className={`px-3 py-2.5 text-right tabular-nums ${r.open_secrets ? "text-rose-600 font-bold" : "text-gray-400"}`}>{r.open_secrets}</td>
                        <td className="px-5 py-2.5 text-right text-xs text-gray-500">{r.last_scan ? relativeTime(r.last_scan, tz) : "never"}</td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}

        <div className="text-[11px] text-gray-400 space-y-1">
          <p>The score looks at the last 90 days of scans. Scores are recorded daily, so the trend reflects real history.</p>
          {!demo && <p>The signed report can be verified by anyone with your public key: <a className="underline" href="/.well-known/trustledger-export-signing-key">/.well-known/trustledger-export-signing-key</a>.</p>}
          <p>Last updated {formatDateTime(score.computed_at, tz)}.</p>
        </div>
      </div>
    </AuthGuard>
  );
}

function SignalCard({ s }: { s: TrustSignal }) {
  const t = TONE[s.status];
  return (
    <Link href={s.href} aria-label={s.name}
      className="group bg-white rounded-2xl border border-gray-200 p-5 hover:shadow-md hover:-translate-y-0.5 transition-all flex flex-col">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="text-sm font-bold text-gray-900">{s.name}</p>
          <p className="text-xs text-gray-500 mt-0.5">{s.source}</p>
        </div>
        <span className={`text-[11px] font-bold px-2 py-0.5 rounded-full ring-1 whitespace-nowrap ${t.chip}`}>{t.label}</span>
      </div>
      <p className="mt-4 text-3xl font-black tabular-nums text-gray-900 leading-none">{s.headline}</p>
      <p className="text-xs text-gray-500 mt-1">{s.headlineLabel}</p>
      {s.value != null && (
        <div className="mt-3 h-1.5 rounded-full bg-gray-100 overflow-hidden"><div className={`h-full rounded-full ${t.bar}`} style={{ width: `${Math.round(s.value * 100)}%` }} /></div>
      )}
      {s.facts.length > 0 && (
        <ul className="mt-4 space-y-1.5">
          {s.facts.slice(0, 3).map(f => <li key={f} className="text-xs text-gray-600 leading-snug flex gap-2"><span className={`mt-1.5 w-1.5 h-1.5 rounded-full shrink-0 ${t.dot}`} />{f}</li>)}
        </ul>
      )}
      <p className="mt-auto pt-4 text-xs font-semibold text-indigo-600 group-hover:text-indigo-800">Open {s.cta} →</p>
    </Link>
  );
}

function WinRow({ w }: { w: ScoreAction & { dim: string } }) {
  return (
    <Link href={w.href} className="flex items-center gap-4 px-5 py-3 hover:bg-gray-50/70">
      <span className="w-14 shrink-0 text-right text-sm font-black text-green-700 tabular-nums">+{w.gain}</span>
      <div className="flex-1 min-w-0">
        <p className="text-sm font-semibold text-gray-900">{w.label}</p>
        <p className="text-[11px] text-gray-400">{w.dim}</p>
      </div>
      <span className="text-gray-300 text-sm">→</span>
    </Link>
  );
}

function DimensionRow({ d, open, onToggle }: { d: Dimension; open: boolean; onToggle: () => void }) {
  const c = d.value >= 0.85 ? "#15803d" : d.value >= 0.7 ? "#16a34a" : d.value >= 0.55 ? "#d97706" : d.value >= 0.4 ? "#ea580c" : "#dc2626";
  return (
    <div>
      <button onClick={onToggle} className="w-full text-left px-5 py-4 flex items-start gap-4 hover:bg-gray-50/60">
        <div className="w-9 h-9 rounded-xl flex items-center justify-center font-black shrink-0 bg-gray-50" style={{ color: c }}>{d.grade}</div>
        <div className="flex-1 min-w-0">
          <div className="flex justify-between gap-3 mb-1.5">
            <span className="text-sm font-bold text-gray-900">{d.label}</span>
            <span className="text-xs font-bold tabular-nums" style={{ color: c }}>{d.points}<span className="font-normal text-gray-400"> / {d.max_points}</span></span>
          </div>
          <div className="h-2 bg-gray-100 rounded-full overflow-hidden"><div className="h-full rounded-full" style={{ width: `${d.value * 100}%`, background: c }} /></div>
          <p className="text-xs text-gray-500 mt-1.5">{d.facts.join(" · ")}</p>
        </div>
        <span className="text-xs text-gray-400 shrink-0 w-14 text-right">{Math.round(d.weight * 100)}% weight</span>
      </button>
      {open && (
        <div className="px-5 pb-4 pl-[4.25rem] space-y-2">
          <p className="text-xs text-gray-600"><span className="font-semibold text-gray-700">How it's calculated: </span>{d.formula}</p>
          {d.actions.length > 0 ? (
            <ul className="space-y-1">
              {d.actions.map((a, i) => (
                <li key={i}><Link href={a.href} className="text-xs text-indigo-700 hover:underline">{a.label}</Link> <span className="text-xs text-green-700 font-semibold">+{a.gain}</span></li>
              ))}
            </ul>
          ) : <p className="text-xs text-green-700">Nothing to fix here.</p>}
        </div>
      )}
    </div>
  );
}

/** Score history, drawn to scale: x = date, y = 0-1000. */
function TrendChart({ history, tz, historyAvailable }: { history: HistoryPoint[]; tz: string; historyAvailable: boolean }) {
  if (history.length < 2) {
    return (
      <div className="h-40 rounded-xl bg-white/60 border border-black/5 flex items-center justify-center text-center px-6">
        <p className="text-xs text-gray-500">{historyAvailable ? "Your score is recorded every day. The trend appears here from tomorrow." : "Score history needs the 20261020_trust_score_history migration. The score itself is live."}</p>
      </div>
    );
  }
  const W = 560, H = 170, L = 36, R = 10, T = 10, B = 24;
  const t0 = Date.parse(history[0].day), t1 = Date.parse(history[history.length - 1].day);
  const x = (day: string) => L + (t1 === t0 ? 0 : (Date.parse(day) - t0) / (t1 - t0)) * (W - L - R);
  const y = (v: number) => T + (1 - v / 1000) * (H - T - B);
  const path = history.map((h, i) => `${i ? "L" : "M"}${x(h.day).toFixed(1)} ${y(h.total).toFixed(1)}`).join(" ");
  const last = history[history.length - 1];
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="w-full h-auto" role="img" aria-label="Trust Score over time">
      {[0, 250, 500, 750, 1000].map(v => (
        <g key={v}>
          <line x1={L} x2={W - R} y1={y(v)} y2={y(v)} stroke="currentColor" className="text-black/10" strokeWidth="1" />
          <text x={L - 6} y={y(v) + 3} textAnchor="end" fontSize="10" className="fill-gray-400">{v}</text>
        </g>
      ))}
      <path d={path} fill="none" stroke="#4f46e5" strokeWidth="2" strokeLinejoin="round" />
      <circle cx={x(last.day)} cy={y(last.total)} r="3.5" fill="#4f46e5" />
      <text x={L} y={H - 6} fontSize="10" className="fill-gray-400">{formatDateOnly(history[0].day, tz)}</text>
      <text x={W - R} y={H - 6} fontSize="10" textAnchor="end" className="fill-gray-400">{formatDateOnly(last.day, tz)}</text>
    </svg>
  );
}
