"use client";

/**
 * Review debt clock: how long unreviewed HIGH/CRITICAL findings have really been waiting (lib/reviewDebt.ts), from
 * /api/violations (when each finding was opened) and /api/violation-status (findings resolved since). The counter
 * ticks at the measured rate -- the sum of the waiting findings' weights per hour -- and drops when one is signed off.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import Link from "next/link";
import AuthGuard from "@/components/AuthGuard";
import { authedFetch, isSeedMode } from "@/lib/useRealData";
import { useAuth } from "@/lib/auth";
import { useScansRealtime } from "@/lib/realtime";
import { computeReviewDebt, DEBT_WEIGHT, type DebtFinding } from "@/lib/reviewDebt";
import { LoadingBlock } from "@/components/Loading";

interface ApiViolation { id: string; file_path: string; risk_score: string; status: string; created_at: string; sla_deadline: string | null; scan_id: string;
  scans: { repo_full_name?: string; pr_number?: number | null } | Array<{ repo_full_name?: string; pr_number?: number | null }> | null }

const fmtHours = (h: number) => h < 1 ? `${Math.round(h * 60)}m` : h < 48 ? `${Math.round(h)}h` : `${Math.round(h / 24)}d`;

function Clock({ value, perHour }: { value: number; perHour: number }) {
  const [shown, setShown] = useState(value);
  const base = useRef({ value, at: Date.now() });
  useEffect(() => { base.current = { value, at: Date.now() }; setShown(value); }, [value]);
  useEffect(() => {
    if (!perHour) return;
    const id = setInterval(() => setShown(base.current.value + ((Date.now() - base.current.at) / 3600_000) * perHour), 1000);
    return () => clearInterval(id);
  }, [perHour]);
  return <p className="text-5xl sm:text-6xl font-black tabular-nums tracking-tight text-white">{Math.round(shown).toLocaleString("en-US")}</p>;
}

export default function ReviewDebtPage() {
  const { profile } = useAuth();
  const offline = isSeedMode() && !profile?.org_id;
  const [findings, setFindings] = useState<DebtFinding[] | null>(null);
  const [resolved, setResolved] = useState<Set<string>>(new Set());
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (offline) return;
    try {
      const [v, o] = await Promise.all([
        authedFetch<{ violations: ApiViolation[] }>("/api/violations?status=unresolved&limit=1000"),
        authedFetch<{ overrides: Record<string, { status: string }> }>("/api/violation-status").catch(() => ({ overrides: {} })),
      ]);
      setFindings((v.violations ?? []).map(x => {
        const scan = Array.isArray(x.scans) ? x.scans[0] : x.scans;
        return { id: x.id, file_path: x.file_path, risk_score: x.risk_score, status: x.status, created_at: x.created_at, sla_deadline: x.sla_deadline,
          scan_id: x.scan_id, repo: scan?.repo_full_name ?? "", pr_number: scan?.pr_number ?? null };
      }));
      setResolved(new Set(Object.entries(o.overrides ?? {}).filter(([, s]) => s.status === "resolved").map(([k]) => k)));
      setError(null);
    } catch (e) { setError(e instanceof Error ? e.message : "Couldn't load findings"); }
  }, [offline]);

  useEffect(() => { load(); }, [load]);
  useScansRealtime(profile?.org_id, () => { load(); });
  useEffect(() => {
    const tick = () => { if (!document.hidden) load(); };
    const id = setInterval(tick, 60_000);
    window.addEventListener("tl:attestation", tick);
    window.addEventListener("tl:attest-complete", tick);
    window.addEventListener("tl:badge", tick);
    window.addEventListener("focus", tick);
    return () => { clearInterval(id); ["tl:attestation", "tl:attest-complete", "tl:badge", "focus"].forEach(e => window.removeEventListener(e, tick)); };
  }, [load]);

  const debt = useMemo(() => computeReviewDebt(findings ?? [], resolved), [findings, resolved]);

  return (
    <AuthGuard>
      <div className="max-w-5xl mx-auto space-y-8 pb-16">
        <header>
          <h1 className="text-2xl font-black text-gray-900 tracking-tight">Review debt</h1>
          <p className="text-sm text-gray-500 mt-0.5">How long unreviewed HIGH and CRITICAL findings have been waiting · live</p>
        </header>

        {offline && <div className="section-card p-6 text-sm text-gray-600">Connect a repository to start measuring review debt.</div>}
        {error && !findings && (
          <div role="alert" className="flex items-center justify-between gap-3 bg-rose-50 border border-rose-200 text-rose-800 px-4 py-3 rounded-xl text-sm">
            <span>Couldn&apos;t load findings. {error}</span><button onClick={load} className="font-bold text-xs">Retry</button>
          </div>
        )}
        {!offline && !findings && !error && <LoadingBlock label="review debt" rows={4} />}

        {findings && (debt.items.length === 0 ? (
          <section aria-label="Review debt" className="rounded-3xl bg-gradient-to-r from-emerald-500 to-teal-500 text-white p-8">
            <p className="text-lg font-black">No review debt</p>
            <p className="text-sm text-white/85 mt-1">Every HIGH and CRITICAL finding has been signed off or resolved.</p>
          </section>
        ) : (
          <>
            <section aria-label="Review debt" className="rounded-3xl text-white p-6 sm:p-8" style={{ background: "radial-gradient(120% 140% at 0% 0%, #7f1d1d 0%, #450a0a 45%, #1c0606 100%)" }}>
              <p className="text-[11px] font-bold uppercase tracking-[0.14em] text-rose-200/80">Risk-hours waiting for review</p>
              <div className="mt-2"><Clock value={debt.total} perHour={debt.perHour} /></div>
              <p className="mt-2 text-sm text-rose-100/80">Growing by <strong className="text-white">{debt.perHour}</strong> every hour until these findings are signed off</p>
              <div className="mt-6 grid grid-cols-2 sm:grid-cols-4 gap-4">
                {[
                  { l: "Waiting", v: String(debt.items.length) },
                  { l: "Critical", v: String(debt.critical) },
                  { l: "Past deadline", v: String(debt.overdue) },
                  { l: "Oldest", v: fmtHours(debt.oldestHours) },
                ].map(s => (
                  <div key={s.l} className="rounded-2xl bg-white/[0.07] ring-1 ring-white/10 p-4">
                    <p className="text-2xl font-black tabular-nums">{s.v}</p>
                    <p className="text-xs text-rose-100/70 mt-1">{s.l}</p>
                  </div>
                ))}
              </div>
            </section>

            <section aria-label="How it's measured" className="section-card p-6">
              <h2 className="text-sm font-bold text-gray-900">How it&apos;s measured</h2>
              <p className="mt-2 font-mono text-sm text-gray-700 bg-gray-50 rounded-xl px-4 py-3">debt = Σ hours waiting × weight</p>
              <p className="mt-3 text-sm text-gray-600 leading-relaxed">
                Hours waiting run from when the finding was opened. CRITICAL findings weigh {DEBT_WEIGHT.CRITICAL}, HIGH {DEBT_WEIGHT.HIGH}. A finding stops counting
                the moment its file is signed off or the finding is resolved. MEDIUM and LOW findings don&apos;t block merges and aren&apos;t counted.
              </p>
            </section>

            <section aria-label="Findings" className="section-card overflow-hidden">
              <div className="flex items-center justify-between gap-3 px-6 pt-5 pb-4 border-b border-gray-100">
                <h2 className="text-sm font-bold text-gray-900">Largest first</h2>
                <Link href="/dashboard#review-queue" className="text-xs font-semibold text-indigo-600 hover:text-indigo-800">Review queue →</Link>
              </div>
              <ul className="divide-y divide-gray-50">
                {debt.items.map(i => (
                  <li key={i.id}>
                    <Link href={`/pr/${i.scan_id}?attest=${encodeURIComponent(i.file_path)}`} className="flex flex-wrap items-center gap-x-5 gap-y-1 px-6 py-4 hover:bg-gray-50/70">
                      <span className={`text-[11px] font-black px-2 py-0.5 rounded shrink-0 ${i.weight === DEBT_WEIGHT.CRITICAL ? "bg-violet-100 text-violet-700" : "bg-orange-100 text-orange-700"}`}>{i.risk_score.toUpperCase()}</span>
                      <span className="min-w-[200px] flex-1">
                        <span className="block text-sm font-bold font-mono text-gray-900 break-all">{i.file_path}</span>
                        <span className="block text-xs text-gray-500">{i.repo}{i.pr_number ? ` · PR #${i.pr_number}` : ""}</span>
                      </span>
                      <span className="shrink-0 text-xs text-gray-600">waiting <strong className="text-gray-900">{fmtHours(i.hours)}</strong>{i.overdue && <span className="ml-2 text-rose-600 font-bold">past deadline</span>}</span>
                      <span className="shrink-0 w-20 text-right text-sm font-black tabular-nums text-gray-900">{Math.round(i.debt).toLocaleString()}</span>
                    </Link>
                  </li>
                ))}
              </ul>
            </section>
          </>
        ))}
      </div>
    </AuthGuard>
  );
}
