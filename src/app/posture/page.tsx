"use client";

/**
 * Security posture: every governance domain on one page, each from its real source -- the Trust Score's six
 * dimensions (/api/trust-score, with real daily history), dependency findings (/api/dependencies), open incidents
 * (/api/incidents) and audit evidence (/api/evidence/collect?overview=1). The overall number IS the Trust Score, so
 * the app has one governance number; nothing here is a default, a guess or read from browser storage.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import AuthGuard from "@/components/AuthGuard";
import { authedFetch, isSeedMode } from "@/lib/useRealData";
import { useAuth } from "@/lib/auth";
import { useScansRealtime } from "@/lib/realtime";
import { buildPostureDomains, type PostureDomain, type PostureSources } from "@/lib/posture";
import type { GovernanceScore } from "@/lib/governanceScore";
import type { EvidenceOverview } from "@/lib/evidenceEngine";

const POLL_MS = 60_000;
const TONE: Record<PostureDomain["status"], { label: string; dot: string; chip: string; bar: string }> = {
  good:    { label: "Good",       dot: "bg-emerald-500", chip: "text-emerald-700 bg-emerald-50 ring-emerald-100", bar: "bg-emerald-500" },
  warn:    { label: "Needs work", dot: "bg-amber-400",   chip: "text-amber-700 bg-amber-50 ring-amber-100",       bar: "bg-amber-400" },
  bad:     { label: "At risk",    dot: "bg-rose-500",    chip: "text-rose-700 bg-rose-50 ring-rose-100",          bar: "bg-rose-500" },
  unknown: { label: "No data",    dot: "bg-gray-300",    chip: "text-gray-500 bg-gray-50 ring-gray-100",          bar: "bg-gray-300" },
};

function History({ points }: { points: Array<{ day: string; total: number }> }) {
  if (points.length < 2) return <p className="text-sm text-white/55">The score is snapshotted daily; the trend appears after a couple of days.</p>;
  const W = 560, H = 120, pad = 6;
  const vals = points.map(p => p.total);
  const min = Math.min(...vals), max = Math.max(...vals), span = Math.max(max - min, 40);
  const x = (i: number) => pad + (i / (points.length - 1)) * (W - pad * 2);
  const y = (v: number) => H - pad - ((v - min) / span) * (H - pad * 2);
  const d = vals.map((v, i) => `${i ? "L" : "M"}${x(i).toFixed(1)},${y(v).toFixed(1)}`).join(" ");
  const fmt = (day: string) => new Date(`${day}T00:00:00Z`).toLocaleDateString("en-US", { month: "short", day: "numeric", timeZone: "UTC" });
  return (
    <div>
      <svg width="100%" height={H} viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" role="img" aria-label={`Trust Score from ${vals[0]} to ${vals[vals.length - 1]}`}>
        <defs><linearGradient id="posture-hist" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stopColor="#818cf8" stopOpacity="0.4" /><stop offset="1" stopColor="#818cf8" stopOpacity="0" /></linearGradient></defs>
        <path d={`${d} L${x(vals.length - 1)},${H} L${x(0)},${H} Z`} fill="url(#posture-hist)" />
        <path d={d} fill="none" stroke="#a5b4fc" strokeWidth="2.5" strokeLinejoin="round" />
      </svg>
      <div className="flex justify-between text-[11px] text-white/45 mt-1"><span>{fmt(points[0].day)} · {vals[0]}</span><span>{fmt(points[points.length - 1].day)} · {vals[vals.length - 1]}</span></div>
    </div>
  );
}

export default function PosturePage() {
  const { profile } = useAuth();
  const offline = isSeedMode() && !profile?.org_id;
  const [trust, setTrust] = useState<{ score: GovernanceScore; history: Array<{ day: string; total: number }> } | null | "unavailable">(null);
  const [src, setSrc] = useState<Omit<PostureSources, "score">>({ dependencies: null, incidents: null, evidence: null });
  const [updatedAt, setUpdatedAt] = useState<Date | null>(null);

  const load = useCallback(async () => {
    if (offline) return;
    const settle = <T,>(p: Promise<T>) => p.then(v => v, () => "unavailable" as const);
    const [t, deps, inc, ev] = await Promise.all([
      settle(authedFetch<{ score: GovernanceScore; history: Array<{ day: string; total: number }> }>("/api/trust-score?history=30")),
      settle(authedFetch<{ counts: NonNullable<Exclude<PostureSources["dependencies"], "unavailable">> }>("/api/dependencies")),
      settle(authedFetch<{ incidents: Array<{ status: string; severity: string }> }>("/api/incidents?status=active")),
      settle(authedFetch<EvidenceOverview>("/api/evidence/collect?overview=1")),
    ]);
    setTrust(t === "unavailable" || !t?.score ? "unavailable" : { score: t.score, history: t.history ?? [] });
    setSrc({
      dependencies: deps === "unavailable" ? "unavailable" : deps.counts,
      incidents: inc === "unavailable" ? "unavailable" : inc.incidents ?? [],
      evidence: ev === "unavailable" || !Array.isArray(ev?.frameworks) ? "unavailable" : ev,
    });
    setUpdatedAt(new Date());
  }, [offline]);

  useEffect(() => { load(); }, [load]);
  useScansRealtime(profile?.org_id, () => { load(); });
  useEffect(() => {
    const tick = () => { if (!document.hidden) load(); };
    const id = setInterval(tick, POLL_MS);
    window.addEventListener("tl:attestation", tick);
    window.addEventListener("focus", tick);
    return () => { clearInterval(id); window.removeEventListener("tl:attestation", tick); window.removeEventListener("focus", tick); };
  }, [load]);

  const score = trust && trust !== "unavailable" ? trust.score : null;
  const domains = useMemo(() => buildPostureDomains({ score, ...src }), [score, src]);
  const actions = score ? score.dimensions.flatMap(d => d.actions).filter(a => a.gain > 0).sort((a, b) => b.gain - a.gain).slice(0, 5) : [];
  const atRisk = domains.filter(d => d.status === "bad").length;

  return (
    <AuthGuard>
      <div className="max-w-[1400px] mx-auto space-y-8 pb-16">
        <header className="animate-fade-up flex flex-wrap items-end justify-between gap-4">
          <div>
            <h1 className="text-2xl font-black text-gray-900 tracking-tight">Security posture</h1>
            <p className="text-sm text-gray-500 mt-0.5">
              Every governance domain, measured from its source
              {updatedAt && <span className="text-gray-400"> · live, updated {updatedAt.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</span>}
            </p>
          </div>
          <button onClick={load} className="px-3 py-2 text-xs font-semibold text-gray-600 bg-white border border-gray-200 rounded-xl hover:bg-gray-50 shadow-sm">Refresh</button>
        </header>

        {offline && <div className="section-card p-6 text-sm text-gray-600">Connect a repository to see your posture. Nothing is shown in demo mode rather than invented numbers.</div>}

        {!offline && (
          <>
            {/* Overall = the Trust Score */}
            <section aria-label="Overall posture" className="animate-fade-up rounded-3xl text-white p-6 sm:p-8 grid grid-cols-1 lg:grid-cols-[auto_minmax(0,1fr)] gap-8"
              style={{ background: "radial-gradient(120% 140% at 0% 0%, #312e81 0%, #1e1b4b 40%, #0b1020 100%)" }}>
              <div>
                <p className="text-[11px] font-bold uppercase tracking-[0.14em] text-indigo-200/70">Overall · Trust Score</p>
                <p className="mt-2 text-6xl font-black tabular-nums leading-none">{score ? score.total : trust === null ? "…" : "—"}<span className="text-xl text-white/40 font-bold"> / 1000</span></p>
                {score && <p className="mt-2 text-lg font-bold text-indigo-100">{score.band}</p>}
                <p className="mt-3 text-sm text-white/70">
                  {domains.length ? `${domains.filter(d => d.status === "good").length} of ${domains.length} domains good${atRisk ? ` · ${atRisk} at risk` : ""}` : ""}
                </p>
                <Link href="/trust-score" className="mt-3 inline-block text-sm font-semibold text-indigo-200 hover:text-white">How the score is calculated →</Link>
              </div>
              <div className="min-w-0">
                <p className="text-[11px] font-bold uppercase tracking-[0.14em] text-indigo-200/70 mb-3">Last 30 days</p>
                {trust && trust !== "unavailable" ? <History points={trust.history} /> : <p className="text-sm text-white/55">{trust === null ? "Loading…" : "Couldn't load the score history."}</p>}
              </div>
            </section>

            {/* Domains */}
            <section aria-label="Domains" className="animate-fade-up space-y-4">
              <h2 className="text-base font-black text-gray-900 px-1">Domains</h2>
              <div className="grid grid-cols-1 md:grid-cols-2 2xl:grid-cols-3 gap-5">
                {domains.map(d => {
                  const t = TONE[d.status];
                  return (
                    <Link key={d.key} href={d.href} aria-label={d.name}
                      className="group bg-white rounded-2xl border border-gray-100 p-5 shadow-[0_1px_2px_rgba(15,23,42,0.05)] hover:shadow-lg hover:-translate-y-0.5 transition-all">
                      <div className="flex items-start justify-between gap-3">
                        <div className="min-w-0">
                          <p className="text-sm font-bold text-gray-900">{d.name}</p>
                          <p className="text-xs text-gray-500 mt-0.5">{d.source}</p>
                        </div>
                        <span className={`text-[11px] font-bold px-2 py-0.5 rounded-full ring-1 whitespace-nowrap ${t.chip}`}>{d.grade ? `${d.grade} · ` : ""}{t.label}</span>
                      </div>
                      <p className="mt-4 text-3xl font-black tabular-nums text-gray-900 leading-none">{d.headline}</p>
                      <p className="text-xs text-gray-500 mt-1">{d.headlineLabel}</p>
                      {d.value != null && (
                        <div className="mt-3 h-1.5 rounded-full bg-gray-100 overflow-hidden"><div className={`h-full rounded-full ${t.bar}`} style={{ width: `${Math.round(d.value * 100)}%` }} /></div>
                      )}
                      {d.facts.length > 0 && (
                        <ul className="mt-4 space-y-1.5">
                          {d.facts.slice(0, 3).map(f => <li key={f} className="text-xs text-gray-600 leading-snug flex gap-2"><span className={`mt-1.5 w-1.5 h-1.5 rounded-full shrink-0 ${t.dot}`} />{f}</li>)}
                        </ul>
                      )}
                      <p className="mt-4 text-xs font-semibold text-indigo-600 group-hover:text-indigo-800">Open {d.cta} →</p>
                    </Link>
                  );
                })}
              </div>
            </section>

            {/* What to do */}
            <section aria-label="What to fix first" className="animate-fade-up section-card p-6">
              <h2 className="text-sm font-bold text-gray-900">What to fix first</h2>
              <p className="text-xs text-gray-400 mt-0.5 mb-4">The actions worth the most Trust Score points, from the score&apos;s own breakdown</p>
              {actions.length === 0 ? <p className="text-sm text-gray-500">{score ? "Nothing to win back — every dimension is at full marks." : "Appears once the score is calculated."}</p> : (
                <ol className="divide-y divide-gray-100">
                  {actions.map((a, i) => (
                    <li key={a.label}>
                      <Link href={a.href} className="flex items-center gap-4 py-3 hover:bg-gray-50/60 -mx-2 px-2 rounded-lg">
                        <span className="w-7 h-7 rounded-full bg-indigo-50 text-indigo-700 text-xs font-black flex items-center justify-center shrink-0">{i + 1}</span>
                        <span className="min-w-0 flex-1 text-sm text-gray-800">{a.label}</span>
                        <span className="text-sm font-black text-emerald-600 tabular-nums whitespace-nowrap">+{a.gain} pts</span>
                      </Link>
                    </li>
                  ))}
                </ol>
              )}
            </section>
          </>
        )}
      </div>
    </AuthGuard>
  );
}
