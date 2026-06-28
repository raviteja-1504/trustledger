"use client";

/**
 * AI Code Debt Clock
 *
 * Like the US National Debt Clock, but for unattested AI-generated code.
 * Every hour that passes without human review of AI code is added to the
 * debt. Makes the risk visceral, urgent, and measurable.
 *
 * Debt = Σ (unattested_ai_lines × age_hours × risk_multiplier)
 */

import { useState, useEffect, useRef, useMemo } from "react";
import AuthGuard from "@/components/AuthGuard";
import { formatDateTime, formatDateOnly, relativeTime, useTimezone } from "@/lib/timezone";
import { api } from "@/lib/api";
import { readSeed } from "@/lib/offlineData";
import { patchDataWithAttestations } from "@/lib/trustScore";
import type { DashboardData } from "@/types";

const ORG = process.env.NEXT_PUBLIC_ORG ?? "novapay";

// ── Debt calculation ───────────────────────────────────────────────────────────

interface DebtItem {
  repo:           string;
  file:           string;
  aiLines:        number;
  ageHours:       number;
  riskMultiplier: number;
  debt:           number;  // debt units
}

// Risk multipliers: higher risk = debt accumulates faster
const RISK_MULTIPLIER: Record<string, number> = {
  CRITICAL: 10,
  HIGH:     4,
  MEDIUM:   2,
  LOW:      1,
};

function computeDebt(data: DashboardData): { total: number; items: DebtItem[]; hourlyRate: number } {
  const topRisk = data.top_risk_files ?? [];
  const now = Date.now();

  // Build repo → last_scan lookup so we can derive real age from scan timestamps
  const repoLastScan: Record<string, string> = Object.fromEntries(
    (data.repos ?? []).map(r => [r.repo, r.last_scan])
  );

  const items: DebtItem[] = topRisk
    .filter(f => !f.attested)
    .map((f, i) => {
      // Use the repo's real last_scan timestamp; fall back to index estimate if missing
      const lastScanIso = repoLastScan[f.repo];
      const ageHours = lastScanIso
        ? Math.max(1, Math.round((now - new Date(lastScanIso).getTime()) / 3_600_000))
        : Math.round(12 + i * 7.3);
      const mult = RISK_MULTIPLIER[f.risk_score ?? "MEDIUM"] ?? 2;
      const aiLines = Math.round(f.ai_pct * 80 + 20); // estimate
      const debt = aiLines * ageHours * mult;
      return {
        repo:           f.repo ?? "unknown",
        file:           f.file_path ?? "unknown",
        aiLines,
        ageHours,
        riskMultiplier: mult,
        debt,
      };
    });

  const total = items.reduce((s, i) => s + i.debt, 0);
  // Hourly rate = debt that accumulates each hour from current unattested files
  const hourlyRate = items.reduce((s, i) => s + i.aiLines * i.riskMultiplier, 0);

  return { total, items, hourlyRate };
}

// ── Animated debt clock ────────────────────────────────────────────────────────

function DebtClock({ value, hourlyRate }: { value: number; hourlyRate: number }) {
  const [current, setCurrent] = useState(value);
  const ref = useRef(value);

  useEffect(() => {
    ref.current = value;
    setCurrent(value);
  }, [value]);

  // Tick up in real time based on hourly rate
  useEffect(() => {
    if (hourlyRate === 0) return;
    const perMs = hourlyRate / 3600_000;
    const id = setInterval(() => {
      ref.current += perMs * 50;
      setCurrent(Math.round(ref.current));
    }, 50);
    return () => clearInterval(id);
  }, [hourlyRate]);

  const str = current.toLocaleString("en-US").padStart(12, " ");
  return (
    <div className="flex items-center justify-center gap-1">
      {str.split("").map((c, i) => (
        <span key={i} className={`inline-block text-center ${c === "," ? "w-3 text-4xl text-red-800" : c === " " ? "w-3" : "w-10 h-14 bg-red-800 rounded text-4xl font-black text-white leading-[56px]"}`}>
          {c !== " " ? c : ""}
        </span>
      ))}
    </div>
  );
}

// ── Page ───────────────────────────────────────────────────────────────────────

export default function AIDebtPage() {
    const tz = useTimezone();
  const [data,              setData]              = useState<DashboardData | null>(null);
  const [elapsed,           setElapsed]           = useState(0);
  const [violationStatuses, setViolationStatuses] = useState<Record<string,string>>({});

  useEffect(() => {
    const seed = readSeed();
    if (seed) { setData(seed); return; }
    api.dashboard(ORG, 30).then(setData).catch(() => {});
  }, []);

  useEffect(() => {
    const id = setInterval(() => setElapsed(e => e + 1), 1000);
    return () => clearInterval(id);
  }, []);

  useEffect(() => {
    function sync() {
      try {
        setViolationStatuses(JSON.parse(localStorage.getItem("tl_violation_statuses") ?? "{}") as Record<string,string>);
      } catch {}
    }
    function onVisible() { if (!document.hidden) sync(); }
    sync();
    window.addEventListener("focus",   sync);
    window.addEventListener("storage", sync);
    document.addEventListener("visibilitychange", onVisible);
    const id = setInterval(sync, 2_000);
    return () => {
      window.removeEventListener("focus",   sync);
      window.removeEventListener("storage", sync);
      document.removeEventListener("visibilitychange", onVisible);
      clearInterval(id);
    };
  }, []);

  const effectiveData = useMemo(
    () => data ? patchDataWithAttestations(data) : null,
    [data, violationStatuses], // eslint-disable-line react-hooks/exhaustive-deps
  );

  const { total, items, hourlyRate } = effectiveData
    ? computeDebt(effectiveData)
    : { total: 0, items: [], hourlyRate: 0 };

  const unattested = items.length;
  const totalAiLines = items.reduce((s, i) => s + i.aiLines, 0);
  const avgAge = items.length > 0
    ? Math.round(items.reduce((s, i) => s + i.ageHours, 0) / items.length)
    : 0;

  // How many hours until debt doubles
  const rawDouble = total > 0 && hourlyRate > 0 ? total / hourlyRate : null;
  const doubleHours = rawDouble !== null && isFinite(rawDouble) ? Math.round(rawDouble) : null;

  return (
    <AuthGuard>
      <div className="max-w-4xl mx-auto space-y-6 pb-10">

        <div className="pt-1">
          <h1 className="text-xl font-black text-gray-900">AI Code Debt Clock</h1>
          <p className="text-sm text-gray-400 mt-0.5">
            Every hour of unreviewed AI code adds to your governance debt — live counter
          </p>
        </div>

        {/* ── Main clock ── */}
        <div className="rounded-2xl overflow-hidden border-2 border-red-300"
          style={{ background: "linear-gradient(135deg, #1a0000 0%, #3d0000 100%)" }}>
          <div className="px-6 pt-6 pb-2 text-center">
            <p className="text-red-300 text-sm font-bold uppercase tracking-widest mb-1">AI Governance Debt Units</p>
            <DebtClock value={total} hourlyRate={hourlyRate} />
            <p className="text-red-500 text-xs mt-3 font-mono">
              +{hourlyRate.toLocaleString()} units / hour · Accumulating since {avgAge}h ago average
            </p>
          </div>

          {/* Stats row */}
          <div className="grid grid-cols-4 gap-0 border-t border-red-900 mt-4">
            {[
              { label: "Unattested Files",  value: unattested,          color: "#fca5a5" },
              { label: "Unreviewed AI Lines", value: totalAiLines.toLocaleString(), color: "#fca5a5" },
              { label: "Avg File Age",       value: `${avgAge}h`,         color: "#fbbf24" },
              { label: "Doubles in",         value: doubleHours !== null ? `${doubleHours}h` : "—", color: "#fca5a5" },
            ].map(s => (
              <div key={s.label} className="text-center py-4 border-r border-red-900 last:border-r-0">
                <div className="text-2xl font-black" style={{ color: s.color }}>{s.value}</div>
                <div className="text-xs text-red-400 mt-1">{s.label}</div>
              </div>
            ))}
          </div>
        </div>

        {/* ── What is debt? ── */}
        <div className="bg-white rounded-2xl border border-gray-200 p-5 shadow-sm">
          <h3 className="font-black text-gray-900 mb-3">How Debt is Calculated</h3>
          <div className="font-mono text-sm text-gray-700 bg-gray-50 rounded-xl p-4 mb-4">
            Debt = Σ ( AI lines × age in hours × risk multiplier )
          </div>
          <div className="grid grid-cols-4 gap-3">
            {[
              { risk:"CRITICAL", mult:"×10", bg:"#fff1f2", text:"#dc2626", desc:"Security vuln in unreviewed AI code" },
              { risk:"HIGH",     mult:"×4",  bg:"#fff7ed", text:"#c2410c", desc:"High-risk pattern, no human review" },
              { risk:"MEDIUM",   mult:"×2",  bg:"#fffbeb", text:"#b45309", desc:"Medium risk, still accumulating" },
              { risk:"LOW",      mult:"×1",  bg:"#f0fdf4", text:"#15803d", desc:"Low risk baseline accumulation" },
            ].map(r => (
              <div key={r.risk} className="rounded-xl p-3 text-center" style={{ background: r.bg }}>
                <div className="font-black text-lg" style={{ color: r.text }}>{r.mult}</div>
                <div className="text-xs font-bold mt-1" style={{ color: r.text }}>{r.risk}</div>
                <div className="text-xs text-gray-500 mt-1 leading-tight">{r.desc}</div>
              </div>
            ))}
          </div>
        </div>

        {/* ── Debt breakdown ── */}
        {items.length > 0 && (
          <div className="bg-white rounded-2xl border border-gray-200 shadow-sm overflow-hidden">
            <div className="px-5 py-3 border-b border-gray-100 bg-gray-50 flex justify-between items-center">
              <p className="text-xs font-black text-gray-700 uppercase tracking-wider">Debt Breakdown by File</p>
              <span className="text-xs text-gray-400">Sorted by debt contribution</span>
            </div>
            <div className="divide-y divide-gray-50">
              {[...items].sort((a,b) => b.debt - a.debt).map((item, i) => {
                const pct = total > 0 ? (item.debt / total * 100) : 0;
                const riskColor = { CRITICAL:"#dc2626", HIGH:"#ea580c", MEDIUM:"#d97706", LOW:"#16a34a" }[item.riskMultiplier === 10 ? "CRITICAL" : item.riskMultiplier === 4 ? "HIGH" : item.riskMultiplier === 2 ? "MEDIUM" : "LOW"] ?? "#64748b";
                return (
                  <div key={i} className="px-5 py-3.5">
                    <div className="flex items-center gap-3 mb-2">
                      <span className="text-xs font-mono font-bold text-gray-500 w-5 shrink-0">{i+1}</span>
                      <div className="flex-1 min-w-0">
                        <div className="text-sm font-bold text-gray-900 truncate">{item.file}</div>
                        <div className="text-xs text-gray-400 font-mono">{item.repo} · {item.aiLines} AI lines · {item.ageHours}h unreviewed</div>
                      </div>
                      <div className="text-right shrink-0">
                        <div className="text-sm font-black" style={{ color: riskColor }}>{item.debt.toLocaleString()}</div>
                        <div className="text-xs text-gray-400">{pct.toFixed(1)}% of debt</div>
                      </div>
                    </div>
                    <div className="h-1.5 bg-gray-100 rounded-full overflow-hidden ml-8">
                      <div className="h-full rounded-full" style={{ width:`${pct}%`, background: riskColor }} />
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Zero the debt CTA */}
            <div className="px-5 py-4 bg-indigo-50 border-t border-indigo-100 flex items-center justify-between gap-4">
              <div>
                <p className="font-bold text-indigo-900 text-sm">Zero the debt</p>
                <p className="text-xs text-indigo-600 mt-0.5">Attest all {unattested} files to bring debt to 0. Estimated time: ~{Math.round(unattested * 4)} minutes.</p>
              </div>
              <a href="/violations" className="px-4 py-2 bg-indigo-600 text-white text-sm font-bold rounded-xl hover:bg-indigo-700 transition-colors whitespace-nowrap">
                Start Attestation →
              </a>
            </div>
          </div>
        )}

        {items.length === 0 && effectiveData && (
          <div className="bg-green-50 border border-green-200 rounded-2xl p-8 text-center">
            <div className="text-4xl mb-3">🎉</div>
            <div className="font-black text-green-800 text-lg mb-2">Zero AI Code Debt</div>
            <div className="text-sm text-green-600">All AI-generated files have been reviewed and attested. Debt clock is at zero.</div>
          </div>
        )}

      </div>
    </AuthGuard>
  );
}
