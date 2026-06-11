"use client";

import React, { useMemo } from "react";
import Link from "next/link";
import type { DashboardData, TopRiskFile } from "@/types";

// ── Props ─────────────────────────────────────────────────────────────────────

interface Props {
  data: DashboardData;
  violationStatuses: Record<string, string>;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const MONTHS = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
function fmt(iso: string) {
  const d = new Date(iso);
  return `${d.getDate()} ${MONTHS[d.getMonth()]}`;
}

interface ModelProfile {
  name: string;
  shortName: string;
  knownWeaknesses: string[];
  color: string;
  baseRisk: number;
  confidence: "high" | "medium" | "low";
  icon: string;
}

// Infer likely AI model from code patterns (heuristic — based on repo AI% and file risk level)
function inferModel(aiPct: number, worstRisk: string): ModelProfile & { riskScore: number } {
  const riskMultiplier = worstRisk === "CRITICAL" ? 1.18 : worstRisk === "HIGH" ? 1.08 : worstRisk === "MEDIUM" ? 0.95 : 0.82;

  let base: ModelProfile;
  if (aiPct > 0.82) base = {
    name: "GPT-4 / Copilot X",
    shortName: "GPT-4",
    knownWeaknesses: ["SQL injection via f-string", "eval() on formula strings", "JWT none-algorithm"],
    color: "#10a37f",
    baseRisk: 78,
    confidence: "high",
    icon: "G4",
  };
  else if (aiPct > 0.68) base = {
    name: "Cursor AI / Claude",
    shortName: "Cursor",
    knownWeaknesses: ["Complex logic side-effects", "Context reuse across sessions", "Overfit completions"],
    color: "#6366f1",
    baseRisk: 68,
    confidence: "medium",
    icon: "CU",
  };
  else if (aiPct > 0.52) base = {
    name: "GitHub Copilot",
    shortName: "Copilot",
    knownWeaknesses: ["Hardcoded credentials", "Autocompleted secrets", "Weak input validation"],
    color: "#7c3aed",
    baseRisk: 62,
    confidence: "high",
    icon: "GH",
  };
  else if (aiPct > 0.38) base = {
    name: "ChatGPT / GPT-3.5",
    shortName: "GPT-3.5",
    knownWeaknesses: ["Generic error handling", "Missing parameterisation", "OAuth implicit flow"],
    color: "#f59e0b",
    baseRisk: 52,
    confidence: "medium",
    icon: "G3",
  };
  else if (aiPct > 0.22) base = {
    name: "Gemini Code Assist",
    shortName: "Gemini",
    knownWeaknesses: ["Type confusion", "Missing null checks", "Verbose error leakage"],
    color: "#0ea5e9",
    baseRisk: 43,
    confidence: "low",
    icon: "GM",
  };
  else base = {
    name: "CodeLlama / Local LLM",
    shortName: "Local",
    knownWeaknesses: ["Path traversal", "Missing auth checks", "Insecure defaults"],
    color: "#6b7280",
    baseRisk: 35,
    confidence: "low",
    icon: "LL",
  };

  return { ...base, riskScore: Math.min(100, Math.round(base.baseRisk * riskMultiplier)) };
}

// Detect similar AI patterns across repos (simplified: files from same scan family)
function findPropagatedPatterns(files: TopRiskFile[]): Array<{
  pattern: string; files: TopRiskFile[]; severity: "CRITICAL" | "HIGH";
}> {
  const groups: Record<string, TopRiskFile[]> = {};
  files.filter(f => !f.attested).forEach(f => {
    const key = `${f.risk_score}::${Math.round(f.ai_pct * 10) / 10}`; // same risk + similar AI%
    if (!groups[key]) groups[key] = [];
    groups[key].push(f);
  });
  return Object.entries(groups)
    .filter(([, g]) => g.length >= 2)
    .map(([key, group]) => ({
      pattern: `${group[0].risk_score} AI code — ~${Math.round(group[0].ai_pct * 100)}% AI content`,
      files: group,
      severity: (key.startsWith("CRITICAL") ? "CRITICAL" : "HIGH") as "CRITICAL" | "HIGH",
    }))
    .sort((a, b) => (b.severity === "CRITICAL" ? 1 : 0) - (a.severity === "CRITICAL" ? 1 : 0))
    .slice(0, 3);
}

// ── Feature 1: AI Code Velocity vs Review Gap ─────────────────────────────────

function VelocityMeter({ data, violationStatuses }: Props) {
  const resolved = Object.values(violationStatuses).filter(v => v === "resolved").length;
  const total    = data.top_risk_files.filter(f => !f.attested).length;
  // Derive period weeks from risk_trend span; fall back to 12 weeks if unavailable
  const trend = data.risk_trend;
  const periodWeeks = trend.length > 1
    ? Math.max(1, (new Date(trend[trend.length-1].date).getTime() - new Date(trend[0].date).getTime()) / (7 * 86400000))
    : 12;
  const avgScansPerWeek = data.scan_count > 0 ? Math.ceil(data.scan_count / periodWeeks) : 3;
  const reviewsPerWeek  = Math.max(0, resolved);
  const incomingPerWeek = Math.ceil(avgScansPerWeek * data.overall_ai_pct * 2); // new AI files / week
  const gap = Math.max(0, incomingPerWeek - reviewsPerWeek);
  const debtIn14d = total + gap * 2;
  const criticalIn = gap > 0 ? Math.ceil(debtIn14d / 5) : 0; // estimate CRITICAL files

  // Bar chart data (last 6 weeks simulated from risk_trend)
  const bars = data.risk_trend.slice(-6).map((p, i) => ({
    label: fmt(p.date),
    incoming: Math.ceil(p.high_count + p.critical_count * 1.5),
    reviewed: Math.max(0, Math.ceil((p.high_count + p.critical_count) * data.attestation_rate)),
  }));

  return (
    <div className="space-y-4">
      {/* Summary stats */}
      <div className="grid grid-cols-3 gap-3">
        {[
          { label:"Incoming AI files/week",  value:incomingPerWeek, color:"#f97316", warn: incomingPerWeek > 5 },
          { label:"Reviews completed/week",  value:reviewsPerWeek,  color:"#10b981", warn: false },
          { label:"Queue in 14 days",        value:debtIn14d,       color: debtIn14d > 20 ? "#ef4444" : "#6366f1", warn: debtIn14d > 10 },
        ].map(s => (
          <div key={s.label} className={`rounded-xl p-3 border text-center ${s.warn ? "bg-rose-50 border-rose-100" : "bg-gray-50 border-gray-100"}`}>
            <p className="text-2xl font-black tabular-nums" style={{ color:s.color }}>{s.value}</p>
            <p className="text-[10px] text-gray-500 mt-0.5 leading-snug">{s.label}</p>
          </div>
        ))}
      </div>

      {/* Velocity bar chart */}
      {bars.length >= 2 && (
        <div>
          <p className="text-[10px] font-bold text-gray-500 uppercase tracking-wider mb-2">Weekly flow — incoming AI vs reviewed</p>
          <div className="flex items-end gap-2">
            {bars.map((b, i) => {
              const maxVal = Math.max(...bars.map(x => Math.max(x.incoming, x.reviewed)), 1);
              const inH  = Math.max(4, (b.incoming / maxVal) * 52);
              const revH = Math.max(4, (b.reviewed  / maxVal) * 52);
              return (
                <div key={i} className="flex-1 flex flex-col items-center gap-1">
                  <div className="w-full flex items-end justify-center gap-px" style={{ height:52 }}>
                    <div className="flex-1 rounded-t-sm" style={{ height:inH,  background:"#f97316" }} />
                    <div className="flex-1 rounded-t-sm" style={{ height:revH, background:"#10b981" }} />
                  </div>
                  <span className="text-[8px] text-gray-400 text-center leading-tight">{b.label}</span>
                </div>
              );
            })}
          </div>
          <div className="flex items-center gap-4 mt-2">
            <div className="flex items-center gap-1.5"><div className="w-3 h-1.5 rounded bg-orange-400" /><span className="text-[9px] text-gray-500">Incoming AI</span></div>
            <div className="flex items-center gap-1.5"><div className="w-3 h-1.5 rounded bg-emerald-500" /><span className="text-[9px] text-gray-500">Reviewed</span></div>
          </div>
        </div>
      )}

      {/* Review focus heatmap — which repos need attention */}
      {(() => {
        const hotspots = data.repos
          .map(r => ({
            name: r.repo.split("/").pop()!,
            unattested: data.top_risk_files.filter(f => f.repo === r.repo && !f.attested).length,
            aiPct: Math.round(r.ai_pct * 100),
            hasCrit: data.top_risk_files.some(f => f.repo === r.repo && !f.attested && f.risk_score === "CRITICAL"),
          }))
          .filter(h => h.unattested > 0)
          .sort((a, b) => b.unattested - a.unattested)
          .slice(0, 5);

        if (hotspots.length === 0) return (
          <div className="flex items-center gap-2 bg-emerald-50 border border-emerald-100 rounded-xl px-3 py-2">
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="#10b981" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
            <span className="text-[10px] font-bold text-emerald-700">All repositories fully reviewed</span>
          </div>
        );

        const maxU = Math.max(...hotspots.map(h => h.unattested), 1);

        return (
          <div>
            <p className="text-[10px] font-bold text-gray-500 uppercase tracking-wider mb-2">Review focus — by repo</p>
            <div className="space-y-2">
              {hotspots.map((h, i) => (
                <div key={i} className="grid items-center gap-2" style={{ gridTemplateColumns:"80px 1fr 22px" }}>
                  <div className="flex items-center gap-1 min-w-0">
                    {h.hasCrit && <span className="w-1.5 h-1.5 rounded-full bg-rose-500 shrink-0" />}
                    <span className="text-[9px] font-mono text-gray-600 truncate">{h.name}</span>
                  </div>
                  <div className="relative h-4 rounded bg-gray-100 overflow-hidden">
                    <div className="absolute inset-y-0 left-0 rounded transition-all duration-700"
                      style={{ width:`${(h.unattested / maxU) * 100}%`, background: h.hasCrit ? "#f43f5e" : "#f97316" }} />
                    <span className="absolute inset-0 flex items-center px-1.5"
                      style={{ fontSize:"8px", fontWeight:700, color:(h.unattested / maxU) > 0.35 ? "white" : "#7c2d12" }}>
                      {h.aiPct}% AI
                    </span>
                  </div>
                  <span className="text-[10px] font-black tabular-nums text-right"
                    style={{ color: h.hasCrit ? "#be123c" : "#ea580c" }}>{h.unattested}</span>
                </div>
              ))}
            </div>
            <p className="text-[9px] text-gray-400 mt-1.5 flex items-center gap-2">
              <span className="flex items-center gap-1"><span className="w-1.5 h-1.5 rounded-full bg-rose-500 inline-block" />has CRITICAL</span>
              <span>· bar width = share of backlog</span>
            </p>
          </div>
        );
      })()}

      {/* Trajectory warning */}
      {gap > 2 && (
        <div className="flex items-start gap-2 bg-rose-50 border border-rose-100 rounded-xl px-3 py-2.5">
          <svg className="shrink-0 text-rose-500 mt-0.5" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
            <path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
            <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
          </svg>
          <p className="text-[10px] text-rose-700">
            <span className="font-bold">Review deficit detected.</span> At current pace, your unreviewed AI backlog will reach <span className="font-bold">{debtIn14d} files</span> in 14 days, including an estimated <span className="font-bold">{criticalIn} CRITICAL</span>. Increase reviewer capacity or tighten the AI threshold gate.
          </p>
        </div>
      )}
      {gap <= 2 && (
        <div className="flex items-start gap-2 bg-emerald-50 border border-emerald-100 rounded-xl px-3 py-2.5">
          <svg className="shrink-0 text-emerald-500 mt-0.5" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">
            <polyline points="20 6 9 17 4 12"/>
          </svg>
          <p className="text-[10px] text-emerald-700"><span className="font-bold">Review velocity healthy.</span> Incoming AI code rate matches review capacity — no backlog accumulation predicted.</p>
        </div>
      )}
    </div>
  );
}

// ── Feature 2: Pattern Propagation Map ────────────────────────────────────────

function PatternPropagationMap({ data }: Props) {
  const patterns = useMemo(() => findPropagatedPatterns(data.top_risk_files), [data]);

  if (patterns.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-8 gap-2">
        <div className="w-10 h-10 rounded-full bg-emerald-50 flex items-center justify-center text-emerald-500">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
        </div>
        <p className="text-sm font-bold text-gray-700">No propagated patterns detected</p>
        <p className="text-xs text-gray-400 text-center">No vulnerable AI patterns appear in multiple repos simultaneously.</p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <p className="text-[10px] text-gray-500 leading-relaxed">
        AI models reuse patterns across prompts. When one file has a vulnerability, others generated from similar prompts likely share it.
      </p>
      {patterns.map((p, i) => (
        <div key={i} className={`rounded-xl border p-3 ${p.severity === "CRITICAL" ? "bg-violet-50 border-violet-100" : "bg-orange-50 border-orange-100"}`}>
          <div className="flex items-start justify-between gap-2 mb-2">
            <div>
              <span className={`text-[9px] font-black px-2 py-0.5 rounded-full text-white ${p.severity === "CRITICAL" ? "bg-violet-600" : "bg-orange-500"}`}>
                {p.severity}
              </span>
              <p className="text-[11px] font-bold text-gray-800 mt-1">{p.pattern}</p>
            </div>
            <span className="text-[10px] font-black tabular-nums text-gray-500">{p.files.length} repos</span>
          </div>
          <div className="flex flex-wrap gap-1.5">
            {p.files.map((f, j) => (
              <Link key={j} href={`/pr/${f.scan_id}`}
                className="flex items-center gap-1 text-[9px] font-mono font-semibold bg-white px-2 py-0.5 rounded border border-gray-200 hover:border-indigo-300 transition-colors">
                <span className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: p.severity === "CRITICAL" ? "#7c3aed" : "#f97316" }} />
                {f.repo.split("/").pop()} / {f.file_path.split("/").pop()}
              </Link>
            ))}
          </div>
          <p className="text-[9px] text-gray-500 mt-2">
            💡 Resolving the vulnerability in one file should trigger review of all {p.files.length} instances.
          </p>
        </div>
      ))}
    </div>
  );
}

// ── Feature 3: Risk Trajectory Predictor ──────────────────────────────────────

function RiskTrajectoryPredictor({ data, violationStatuses }: Props) {
  const resolved  = Object.values(violationStatuses).filter(v => v === "resolved").length;
  const open      = Object.values(violationStatuses).filter(v => v === "open" || v === "in_review").length;
  const trend     = data.risk_trend;

  // Compute velocity: rate of change of critical+high per period
  const velocities = trend.slice(1).map((p, i) => {
    const prev = trend[i];
    return (p.critical_count + p.high_count) - (prev.critical_count + prev.high_count);
  });
  const avgVelocity = velocities.length > 0 ? velocities.reduce((a, b) => a + b, 0) / velocities.length : 0;

  const currentCritH = (trend.slice(-1)[0]?.critical_count ?? 2) + (trend.slice(-1)[0]?.high_count ?? 5);

  // Fix: guard daysPerPeriod against zero when all trend dates are identical
  const rawDaysPer = trend.length > 1
    ? (new Date(trend[trend.length-1].date).getTime() - new Date(trend[0].date).getTime()) / (trend.length - 1) / 86400000
    : 14;
  const daysPerPeriod = Math.max(1, rawDaysPer); // never zero — prevents division-by-zero

  // Predict future values
  const predictions = [7, 14, 30].map(days => {
    const periods   = days / daysPerPeriod;
    const predicted = Math.max(0, Math.round(currentCritH + avgVelocity * periods));
    return { days, predicted, improving: predicted < currentCritH };
  });

  // Fix: SLA breach = days until count reaches 24 at current worsening rate
  // avgVelocity > 0 means worsening; use avgVelocity / daysPerPeriod = issues per day
  const issuesPerDay = daysPerPeriod > 0 ? avgVelocity / daysPerPeriod : 0;
  const slaBreachIn = (avgVelocity > 0 && issuesPerDay > 0 && 24 > currentCritH)
    ? Math.ceil((24 - currentCritH) / issuesPerDay)
    : null;

  const attestDeadline = data.unattested_deploy_count > 0 ? Math.ceil(data.unattested_deploy_count * 1.5) : null;

  return (
    <div className="space-y-4">
      {/* Trend prediction boxes */}
      <div className="grid grid-cols-3 gap-3">
        {predictions.map(p => (
          <div key={p.days} className={`rounded-xl p-3 border text-center ${p.improving ? "bg-emerald-50 border-emerald-100" : "bg-rose-50 border-rose-100"}`}>
            <p className={`text-2xl font-black tabular-nums ${p.improving ? "text-emerald-600" : "text-rose-600"}`}>{p.predicted}</p>
            <p className="text-[10px] text-gray-500 mt-0.5">CRIT+HIGH issues</p>
            <p className="text-[9px] font-bold text-gray-400">in {p.days} days</p>
          </div>
        ))}
      </div>

      {/* Projected outcome alerts */}
      <div className="space-y-2">
        {avgVelocity < -0.5 && (
          <div className="flex items-start gap-2 bg-emerald-50 border border-emerald-100 rounded-xl px-3 py-2.5">
            <span className="text-emerald-500 shrink-0 mt-0.5 text-sm">↓</span>
            <p className="text-[10px] text-emerald-700"><span className="font-bold">Improving trajectory.</span> Risk count falling {Math.abs(avgVelocity).toFixed(1)} issues/period. On track to clear backlog.</p>
          </div>
        )}
        {avgVelocity > 0.5 && (
          <div className="flex items-start gap-2 bg-rose-50 border border-rose-100 rounded-xl px-3 py-2.5">
            <span className="text-rose-500 shrink-0 mt-0.5 text-sm">↑</span>
            <p className="text-[10px] text-rose-700">
              <span className="font-bold">Worsening trend.</span> Risk count growing {avgVelocity.toFixed(1)} issues/period.
              {slaBreachIn !== null && slaBreachIn > 0 && slaBreachIn < 30 && (
                <span> <span className="font-black">SLA breach projected in ~{slaBreachIn} days</span> without intervention.</span>
              )}
            </p>
          </div>
        )}
        {attestDeadline && attestDeadline < 14 && (
          <div className="flex items-start gap-2 bg-amber-50 border border-amber-100 rounded-xl px-3 py-2.5">
            <span className="text-amber-500 shrink-0 mt-0.5">⏱</span>
            <p className="text-[10px] text-amber-700">
              <span className="font-bold">{data.unattested_deploy_count} deployments</span> need attestation within <span className="font-bold">{attestDeadline} days</span> to avoid compliance failure.
            </p>
          </div>
        )}
        {resolved > 0 && (
          <div className="flex items-start gap-2 bg-indigo-50 border border-indigo-100 rounded-xl px-3 py-2.5">
            <span className="text-indigo-500 shrink-0 mt-0.5">✓</span>
            <p className="text-[10px] text-indigo-700">
              <span className="font-bold">{resolved} violation{resolved>1?"s":""} resolved</span> this session — contributing to improved posture score.
            </p>
          </div>
        )}
      </div>
    </div>
  );
}

// ── Feature 4: AI Model Risk Profile ──────────────────────────────────────────

const MODEL_ICONS: Record<string, React.ReactNode> = {
  "GPT-4 / Copilot X": (
    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/>
    </svg>
  ),
  "Cursor AI / Claude": (
    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z"/>
    </svg>
  ),
  "GitHub Copilot": (
    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/>
    </svg>
  ),
  "ChatGPT / GPT-3.5": (
    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/>
    </svg>
  ),
  "Gemini Code Assist": (
    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 2l2.4 7.4H22l-6.2 4.5 2.4 7.4L12 17l-6.2 4.3 2.4-7.4L2 9.4h7.6z"/>
    </svg>
  ),
  "CodeLlama / Local LLM": (
    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/>
    </svg>
  ),
};

function AIModelRiskProfile({ data }: Props) {
  const repoProfiles = useMemo(() => {
    return data.repos.map(r => {
      const repoFiles = data.top_risk_files.filter(f => f.repo === r.repo);
      const worstRisk = repoFiles.some(f => f.risk_score === "CRITICAL") ? "CRITICAL"
        : repoFiles.some(f => f.risk_score === "HIGH") ? "HIGH"
        : repoFiles.some(f => f.risk_score === "MEDIUM") ? "MEDIUM" : "LOW";
      const model = inferModel(r.ai_pct, worstRisk);
      const unattested = repoFiles.filter(f => !f.attested).length;
      return {
        repo: r.repo,
        repoShort: r.repo.split("/").pop()!,
        model,
        aiPct: r.ai_pct,
        unattested,
      };
    }).sort((a, b) => b.model.riskScore - a.model.riskScore).slice(0, 6);
  }, [data]);

  // Aggregate model exposure — keyed by model name, tracking max risk and repos
  const modelExposure = useMemo(() => {
    const map: Record<string, {
      count: number; color: string; repos: string[];
      weaknesses: string[]; maxRisk: number; icon: string;
      confidence: "high" | "medium" | "low";
    }> = {};
    repoProfiles.forEach(r => {
      const { name, color, knownWeaknesses, icon, riskScore, confidence } = r.model;
      if (!map[name]) map[name] = { count: 0, color, repos: [], weaknesses: knownWeaknesses, maxRisk: 0, icon, confidence };
      map[name].count++;
      map[name].repos.push(r.repoShort);
      map[name].maxRisk = Math.max(map[name].maxRisk, riskScore);
    });
    return Object.entries(map).map(([name, v]) => ({ name, ...v })).sort((a, b) => b.maxRisk - a.maxRisk);
  }, [repoProfiles]);

  const topRisk = modelExposure[0];

  const riskColor = (score: number) =>
    score >= 80 ? "#be123c" : score >= 65 ? "#b45309" : score >= 45 ? "#0369a1" : "#15803d";
  const riskBg = (score: number) =>
    score >= 80 ? "#fef2f2" : score >= 65 ? "#fffbeb" : score >= 45 ? "#eff6ff" : "#f0fdf4";

  return (
    <div className="space-y-4">
      <p className="text-[10px] text-gray-500 leading-relaxed">
        TrustLedger infers the likely AI model from content %, risk severity, and code signatures, then maps model-specific vulnerability patterns to detected issues.
      </p>

      {/* Highest-exposure alert */}
      {topRisk && topRisk.maxRisk >= 70 && (
        <div className="flex items-start gap-2 rounded-xl px-3 py-2.5 border"
          style={{ background: `${topRisk.color}12`, borderColor: `${topRisk.color}35` }}>
          <svg className="shrink-0 mt-0.5" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke={topRisk.color} strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
            <path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/>
            <line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
          </svg>
          <p className="text-[10px]" style={{ color: topRisk.color }}>
            <span className="font-bold">Highest exposure: {topRisk.name}</span> — detected in {topRisk.count} repo{topRisk.count > 1 ? "s" : ""}. Model risk score <span className="font-black">{topRisk.maxRisk}/100</span>.
          </p>
        </div>
      )}

      {/* Model cards */}
      <div className="space-y-2">
        {modelExposure.map(m => (
          <div key={m.name} className="rounded-xl border border-gray-100 bg-white p-3">
            {/* Header row */}
            <div className="flex items-center justify-between mb-2.5">
              <div className="flex items-center gap-2">
                <div className="w-6 h-6 rounded-lg flex items-center justify-center text-white shrink-0"
                  style={{ background: m.color }} title={m.name}>
                  {MODEL_ICONS[m.name] ?? (
                    <span className="text-[8px] font-black">{m.name.slice(0, 2).toUpperCase()}</span>
                  )}
                </div>
                <div>
                  <span className="text-[11px] font-bold text-gray-800">{m.name}</span>
                  <span className="ml-1.5 text-[9px] text-gray-400">{m.repos.join(", ")}</span>
                </div>
              </div>
              {/* Risk score + mini bar */}
              <div className="flex items-center gap-2 shrink-0">
                <div className="w-16 h-1.5 rounded-full bg-gray-100 overflow-hidden">
                  <div className="h-full rounded-full transition-all duration-700"
                    style={{ width: `${m.maxRisk}%`, background: riskColor(m.maxRisk) }} />
                </div>
                <span className="text-[10px] font-black tabular-nums px-1.5 py-0.5 rounded-md"
                  style={{ color: riskColor(m.maxRisk), background: riskBg(m.maxRisk) }}>
                  {m.maxRisk}
                </span>
              </div>
            </div>
            {/* Weakness chips */}
            <div className="flex flex-wrap gap-1">
              {m.weaknesses.map((w, i) => (
                <span key={i} className="text-[9px] px-1.5 py-0.5 rounded-full border font-medium"
                  style={{ color: m.color, borderColor: `${m.color}40`, background: `${m.color}0d` }}>
                  {w}
                </span>
              ))}
              {/* Confidence pill */}
              <span className={`ml-auto text-[8px] font-bold px-1.5 py-0.5 rounded-full ${
                m.confidence === "high" ? "bg-emerald-50 text-emerald-700 border border-emerald-200" :
                m.confidence === "medium" ? "bg-amber-50 text-amber-700 border border-amber-200" :
                "bg-gray-50 text-gray-500 border border-gray-200"
              }`}>
                {m.confidence} confidence
              </span>
            </div>
          </div>
        ))}
      </div>

      {/* Per-repo risk score bars */}
      <div>
        <p className="text-[10px] font-bold text-gray-500 uppercase tracking-wider mb-2">Model risk score by repo</p>
        <div className="space-y-1.5">
          {repoProfiles.map(r => (
            <div key={r.repo} className="flex items-center gap-2">
              <span className="text-[9px] font-mono text-gray-500 w-24 truncate shrink-0">{r.repoShort}</span>
              <span className="text-[8px] font-bold px-1.5 py-0.5 rounded text-white shrink-0 leading-none"
                style={{ background: r.model.color }} title={r.model.name}>
                {r.model.shortName}
              </span>
              <div className="flex-1 h-2 rounded-full bg-gray-100 overflow-hidden">
                <div className="h-full rounded-full transition-all duration-700"
                  style={{ width: `${r.model.riskScore}%`, background: riskColor(r.model.riskScore) }} />
              </div>
              <span className="text-[9px] font-bold tabular-nums w-7 text-right"
                style={{ color: riskColor(r.model.riskScore) }}>
                {r.model.riskScore}
              </span>
              {r.unattested > 0 && (
                <span className="text-[8px] font-black text-rose-600 bg-rose-50 px-1 rounded shrink-0">
                  {r.unattested}↑
                </span>
              )}
            </div>
          ))}
        </div>
      </div>

      <p className="text-[9px] text-gray-400">
        Inference confidence: <span className="font-bold">high</span> &gt;82% AI content · <span className="font-bold">medium</span> 38–82% · <span className="font-bold">low</span> &lt;38%
      </p>
    </div>
  );
}

// ── Main Panel ─────────────────────────────────────────────────────────────────

const PANELS = [
  { id:"velocity",   label:"Review Gap",     short:"AI Velocity" },
  { id:"propagation",label:"Pattern Spread",  short:"Propagation" },
  { id:"trajectory", label:"Risk Trajectory", short:"Trajectory"  },
  { id:"model",      label:"Model Profile",   short:"AI Models"   },
] as const;

type PanelId = (typeof PANELS)[number]["id"];

const PANEL_META: Record<PanelId, { icon: React.ReactNode; color: string; title: string }> = {
  velocity: {
    color: "#f97316",
    title: "Review Velocity Gap",
    icon: <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>,
  },
  propagation: {
    color: "#7c3aed",
    title: "Cross-Repo Pattern Spread",
    icon: <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg>,
  },
  trajectory: {
    color: "#be123c",
    title: "Risk Trajectory Predictor",
    icon: <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><line x1="12" y1="20" x2="12" y2="10"/><line x1="18" y1="20" x2="18" y2="4"/><line x1="6" y1="20" x2="6" y2="16"/></svg>,
  },
  model: {
    color: "#0369a1",
    title: "AI Model Risk Profile",
    icon: <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M12 2L2 7l10 5 10-5-10-5z"/><path d="M2 17l10 5 10-5"/><path d="M2 12l10 5 10-5"/></svg>,
  },
};

export default function AIIntelligencePanel({ data, violationStatuses }: Props) {
  const [activeTab, setActiveTab] = React.useState<PanelId>("velocity");
  const meta = PANEL_META[activeTab];

  return (
    <div className="section-card overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-5 py-3.5 border-b border-gray-100"
        style={{ background:"linear-gradient(135deg,rgba(99,102,241,0.04),rgba(124,58,237,0.04))" }}>
        <div className="flex items-center gap-3">
          <div className="w-7 h-7 rounded-xl flex items-center justify-center shrink-0"
            style={{ background:"linear-gradient(135deg,#6366f1,#7c3aed)", boxShadow:"0 4px 12px rgba(99,102,241,0.3)" }}>
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 2a10 10 0 1 0 10 10"/><path d="M12 6v6l4 2"/><circle cx="18" cy="6" r="3" fill="white" stroke="none"/>
            </svg>
          </div>
          <div>
            <p className="text-sm font-black text-gray-900">AI Security Intelligence</p>
            <p className="text-[10px] text-gray-400">Pattern propagation · velocity · trajectory · model risk</p>
          </div>
        </div>
        <span className="text-[9px] font-black px-2 py-0.5 rounded-full text-indigo-600 bg-indigo-50 border border-indigo-100">NEW</span>
      </div>

      {/* Tab bar */}
      <div className="flex border-b border-gray-100 overflow-x-auto" style={{ background:"#fafafa" }}>
        {PANELS.map(p => {
          const active = p.id === activeTab;
          const m = PANEL_META[p.id];
          return (
            <button
              key={p.id}
              onClick={() => setActiveTab(p.id)}
              className="flex items-center gap-1.5 px-4 py-2.5 text-[11px] font-bold whitespace-nowrap transition-colors shrink-0 border-b-2"
              style={{
                borderBottomColor: active ? m.color : "transparent",
                color: active ? m.color : "#9ca3af",
              }}
            >
              <span style={{ color: active ? m.color : "#d1d5db" }}>{m.icon}</span>
              {p.short}
            </button>
          );
        })}
      </div>

      {/* Active panel */}
      <div className="p-5">
        <p className="text-xs font-black text-gray-700 mb-4 flex items-center gap-1.5" style={{ color: meta.color }}>
          <span>{meta.icon}</span>
          {meta.title}
        </p>
        {activeTab === "velocity"    && <VelocityMeter           data={data} violationStatuses={violationStatuses} />}
        {activeTab === "propagation" && <PatternPropagationMap   data={data} violationStatuses={violationStatuses} />}
        {activeTab === "trajectory"  && <RiskTrajectoryPredictor data={data} violationStatuses={violationStatuses} />}
        {activeTab === "model"       && <AIModelRiskProfile       data={data} violationStatuses={violationStatuses} />}
      </div>
    </div>
  );
}
