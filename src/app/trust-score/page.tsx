"use client";

/**
 * TrustScore™ — AI Governance Credit Score
 *
 * A single 0–1000 score summarising your organisation's AI code governance
 * health. Like a credit score, it tells auditors, insurers, and board members
 * how trustworthy your AI-assisted development process is at a glance.
 */

import { useState, useEffect, useMemo } from "react";
import AuthGuard from "@/components/AuthGuard";
import { readSeed } from "@/lib/offlineData";
import { api } from "@/lib/api";
import { computeTrustScore, scoreColor, patchDataWithAttestations } from "@/lib/trustScore";
import type { DashboardData } from "@/types";

const ORG = process.env.NEXT_PUBLIC_ORG ?? "novapay";

function rd(daysBack: number): string {
  return new Date(Date.now() - daysBack * 86400000).toISOString().split("T")[0];
}

const FALLBACK: DashboardData = {
  repos: [
    { repo:`${ORG}/payments-api`,    ai_pct:0.71, attestation_rate:0.80, last_scan:rd(2), scan_count:18, file_count:142, latest_scan_id:"sc_mock_001" },
    { repo:`${ORG}/auth-service`,    ai_pct:0.44, attestation_rate:0.92, last_scan:rd(1), scan_count:12, file_count:98,  latest_scan_id:"sc_mock_002" },
    { repo:`${ORG}/fraud-detection`, ai_pct:0.58, attestation_rate:0.67, last_scan:rd(0), scan_count:9,  file_count:76,  latest_scan_id:"sc_mock_003" },
    { repo:`${ORG}/risk-engine`,     ai_pct:0.36, attestation_rate:0.95, last_scan:rd(3), scan_count:7,  file_count:54,  latest_scan_id:"sc_mock_004" },
    { repo:`${ORG}/data-platform`,   ai_pct:0.62, attestation_rate:0.55, last_scan:rd(4), scan_count:5,  file_count:61,  latest_scan_id:"sc_mock_005" },
  ],
  overall_ai_pct: 0.54,
  attestation_rate: 0.78,
  unattested_deploy_count: 3,
  scan_count: 51,
  file_count: 431,
  risk_trend: [
    { date:rd(35), high_count:5, critical_count:3, medium_count:9 },
    { date:rd(28), high_count:4, critical_count:2, medium_count:7 },
    { date:rd(21), high_count:6, critical_count:3, medium_count:8 },
    { date:rd(14), high_count:3, critical_count:1, medium_count:5 },
    { date:rd(7),  high_count:2, critical_count:1, medium_count:4 },
  ],
  top_risk_files: [
    { repo:`${ORG}/payments-api`,    file_path:"src/processors/card_validator.py",   ai_pct:0.91, risk_score:"CRITICAL", attested:false, scan_id:"sc_mock_001", pr_number:482 },
    { repo:`${ORG}/fraud-detection`, file_path:"models/risk_scorer.ts",              ai_pct:0.83, risk_score:"CRITICAL", attested:false, scan_id:"sc_mock_003", pr_number:219 },
    { repo:`${ORG}/payments-api`,    file_path:"src/gateway/stripe_client.py",       ai_pct:0.76, risk_score:"HIGH",     attested:false, scan_id:"sc_mock_001", pr_number:479 },
    { repo:`${ORG}/auth-service`,    file_path:"src/oauth/token_exchange.ts",        ai_pct:0.68, risk_score:"HIGH",     attested:true,  scan_id:"sc_mock_002", pr_number:341 },
    { repo:`${ORG}/fraud-detection`, file_path:"src/rules/velocity_check.py",        ai_pct:0.62, risk_score:"HIGH",     attested:true,  scan_id:"sc_mock_003", pr_number:218 },
    { repo:`${ORG}/payments-api`,    file_path:"src/api/refund_handler.py",          ai_pct:0.55, risk_score:"MEDIUM",   attested:true,  scan_id:"sc_mock_001", pr_number:477 },
    { repo:`${ORG}/auth-service`,    file_path:"src/middleware/rate_limiter.ts",     ai_pct:0.49, risk_score:"MEDIUM",   attested:true,  scan_id:"sc_mock_002", pr_number:338 },
    { repo:`${ORG}/data-platform`,   file_path:"src/pipelines/etl_runner.py",        ai_pct:0.65, risk_score:"HIGH",     attested:false, scan_id:"sc_mock_005", pr_number:103 },
    { repo:`${ORG}/risk-engine`,     file_path:"src/models/credit_score.ts",         ai_pct:0.41, risk_score:"MEDIUM",   attested:true,  scan_id:"sc_mock_004", pr_number:88  },
    { repo:`${ORG}/payments-api`,    file_path:"src/utils/currency_formatter.py",    ai_pct:0.22, risk_score:"LOW",      attested:true,  scan_id:"sc_mock_001", pr_number:471 },
  ],
};

// ── Industry benchmarks ────────────────────────────────────────────────────────

const BENCHMARKS = [
  { label:"Top 10%",  score:892, color:"#6366f1" },
  { label:"Average",  score:621, color:"#64748b" },
  { label:"Bottom 10%", score:312, color:"#dc2626" },
];

// ── Animated counter ───────────────────────────────────────────────────────────

function AnimatedScore({ target }: { target: number }) {
  const [displayed, setDisplayed] = useState(0);
  useEffect(() => {
    let start = 0;
    const step = Math.ceil(target / 60);
    const id = setInterval(() => {
      start = Math.min(start + step, target);
      setDisplayed(start);
      if (start >= target) clearInterval(id);
    }, 16);
    return () => clearInterval(id);
  }, [target]);
  return <>{displayed}</>;
}

// ── Certificate ────────────────────────────────────────────────────────────────

function downloadCertificate(score: number, org: string, label: string) {
  const date      = new Date().toLocaleDateString("en-US", { year:"numeric", month:"long", day:"numeric" });
  const validUntil = new Date(Date.now() + 90 * 86400_000).toLocaleDateString("en-US", { year:"numeric", month:"long", day:"numeric" });
  const certId    = `TL-${Date.now().toString(36).toUpperCase()}`;
  const accentColor = score >= 850 ? "#15803d" : score >= 700 ? "#16a34a" : score >= 550 ? "#d97706" : score >= 400 ? "#ea580c" : "#dc2626";
  const tickColor   = score >= 700 ? "#16a34a" : "#d97706";
  const tick        = score >= 700 ? "✓" : "◐";
  const components  = ["Attestation Coverage","Policy Compliance","Critical Risk Resolution","Cross-Repo Consistency","Scan Freshness"];

  const html = `<!DOCTYPE html>
<html><head><meta charset="utf-8">
<title>TrustLedger Certificate — ${org}</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  @page{size:A4 landscape;margin:0}
  body{font-family:Georgia,'Times New Roman',serif;background:#f8f8ff;display:flex;justify-content:center;align-items:center;min-height:100vh;padding:32px}
  .cert{width:860px;background:#fff;border:5px double #6366f1;padding:52px 64px;text-align:center;position:relative;box-shadow:0 8px 48px rgba(99,102,241,.15)}
  .corner{position:absolute;width:36px;height:36px;border-color:#a5b4fc;border-style:solid}
  .tl{top:14px;left:14px;border-width:3px 0 0 3px}
  .tr{top:14px;right:14px;border-width:3px 3px 0 0}
  .bl{bottom:14px;left:14px;border-width:0 0 3px 3px}
  .br{bottom:14px;right:14px;border-width:0 3px 3px 0}
  .brand{font-family:Arial,sans-serif;font-size:12px;letter-spacing:4px;text-transform:uppercase;color:#6366f1;font-weight:800;margin-bottom:4px}
  .title{font-size:26px;font-weight:bold;color:#1e1b4b;letter-spacing:2px;text-transform:uppercase;margin-bottom:30px}
  .sub{font-size:13px;color:#9ca3af;margin-bottom:6px}
  .org{font-size:34px;font-weight:bold;color:#1e1b4b;margin-bottom:2px}
  .org-label{font-size:11px;color:#d1d5db;letter-spacing:2px;text-transform:uppercase;margin-bottom:28px}
  .score-label{font-family:Arial,sans-serif;font-size:11px;letter-spacing:3px;text-transform:uppercase;color:#9ca3af;margin-bottom:4px}
  .score{font-family:Arial,sans-serif;font-size:100px;font-weight:900;line-height:1;color:${accentColor}}
  .denom{font-family:Arial,sans-serif;font-size:28px;color:#9ca3af}
  .score-name{font-family:Arial,sans-serif;font-size:17px;font-weight:700;color:${accentColor};margin:8px 0 28px}
  hr{border:none;border-top:1px solid #e5e7eb;margin:20px 0}
  .comps{display:flex;justify-content:center;gap:20px;flex-wrap:wrap;margin-bottom:20px}
  .comp{font-family:Arial,sans-serif;font-size:11px;color:#4b5563;display:flex;align-items:center;gap:5px}
  .ck{color:${tickColor};font-size:13px}
  .dates{font-size:12px;color:#9ca3af;margin-bottom:16px}
  .cert-id{font-family:'Courier New',monospace;font-size:11px;color:#d1d5db;letter-spacing:1px}
  .footer{margin-top:20px;font-family:Arial,sans-serif;font-size:11px;color:#c7c9d9}
  @media print{body{background:#fff;padding:0}.cert{box-shadow:none}}
</style></head>
<body>
<div class="cert">
  <div class="corner tl"></div><div class="corner tr"></div>
  <div class="corner bl"></div><div class="corner br"></div>
  <p class="brand">TrustLedger</p>
  <h1 class="title">AI Governance Certificate</h1>
  <p class="sub">This certifies that</p>
  <p class="org">${org}</p>
  <p class="org-label">Organisation</p>
  <p class="score-label">TrustScore™</p>
  <div><span class="score">${score}</span><span class="denom"> / 1000</span></div>
  <p class="score-name">${label}</p>
  <hr>
  <div class="comps">${components.map(c => `<span class="comp"><span class="ck">${tick}</span>${c}</span>`).join("")}</div>
  <p class="dates">Issued: ${date} &nbsp;·&nbsp; Valid until: ${validUntil}</p>
  <p class="cert-id">Certificate ID: ${certId} &nbsp;·&nbsp; trustledger.dev/verify</p>
  <hr>
  <p class="footer">Powered by TrustLedger — AI Code Governance Platform</p>
</div>
<script>window.onload=function(){window.print()}</script>
</body></html>`;

  const win = window.open("", "_blank", "width=1100,height=750");
  if (win) { win.document.write(html); win.document.close(); }
}

// ── Main page ──────────────────────────────────────────────────────────────────

export default function TrustScorePage() {
  const [data,      setData]      = useState<DashboardData>(FALLBACK);
  const [statuses,  setStatuses]  = useState<Record<string,string>>({});

  useEffect(() => {
    const seed = readSeed();
    if (seed) { setData(seed); } else {
      api.dashboard(ORG, 90).then(setData).catch(() => {});
    }
  }, []);

  // Keep violation statuses in sync with localStorage (same key the dashboard writes)
  useEffect(() => {
    function sync() {
      try {
        setStatuses(JSON.parse(localStorage.getItem("tl_violation_statuses") ?? "{}") as Record<string,string>);
      } catch {}
    }
    function onVisible() { if (!document.hidden) sync(); }
    sync();
    window.addEventListener("storage", sync);
    window.addEventListener("focus",   sync);
    document.addEventListener("visibilitychange", onVisible);
    const id = setInterval(sync, 2_000);
    return () => {
      window.removeEventListener("storage", sync);
      window.removeEventListener("focus",   sync);
      document.removeEventListener("visibilitychange", onVisible);
      clearInterval(id);
    };
  }, []);

  const effectiveData = useMemo(() => patchDataWithAttestations(data, statuses), [data, statuses]);

  const { total, dimensions } = useMemo(
    () => computeTrustScore(effectiveData),
    [effectiveData],
  );

  const col  = scoreColor(total);
  const org  = effectiveData?.repos?.[0]?.repo.split("/")[0] ?? "your-org";

  return (
    <AuthGuard>
      <div className="max-w-4xl mx-auto space-y-6 pb-10">

        <div className="pt-1">
          <h1 className="text-xl font-black text-gray-900">TrustScore™</h1>
          <p className="text-sm text-gray-400 mt-0.5">Your AI governance health score — like a credit score, but for code</p>
        </div>

        {/* ── Score card ── */}
        <div className="rounded-2xl border-2 p-6 sm:p-8"
          style={{ background: col.bg, borderColor: col.ring }}>

          {/* Top row: score + label + actions */}
          <div className="flex flex-wrap items-start justify-between gap-6 mb-6">
            {/* Big score */}
            <div>
              <div className="flex items-baseline gap-3">
                <span className="text-7xl sm:text-8xl font-black tabular-nums leading-none" style={{ color: col.text }}>
                  <AnimatedScore target={total} />
                </span>
                <span className="text-2xl sm:text-3xl font-bold text-gray-400 leading-none">/ 1000</span>
              </div>
              <div className="text-lg font-bold mt-2" style={{ color: col.text }}>{col.label}</div>
              <div className="text-xs text-gray-500 mt-0.5">AI Governance TrustScore™</div>
            </div>

            {/* Actions */}
            <div className="flex flex-col gap-3 shrink-0">
              <button onClick={() => downloadCertificate(total, org, col.label)}
                className="px-5 py-2.5 rounded-xl text-sm font-bold text-white transition-colors hover:opacity-90"
                style={{ background:"#6366f1" }}>
                Download Certificate PDF
              </button>
            </div>
          </div>

          {/* Gauge bar */}
          <div className="space-y-2">
            <div className="h-4 bg-black/10 rounded-full overflow-hidden">
              <div className="h-full rounded-full transition-all duration-1000"
                style={{ width: `${total / 10}%`, background: `linear-gradient(90deg, #dc2626, #d97706, #16a34a)` }} />
            </div>
            <div className="flex justify-between text-xs text-gray-400 font-medium">
              <span>0</span><span>250</span><span>500</span><span>750</span><span>1000</span>
            </div>
            <div className="flex gap-4 flex-wrap pt-1">
              {BENCHMARKS.map(b => (
                <div key={b.label} className="flex items-center gap-1.5">
                  <span className="w-2 h-2 rounded-full shrink-0" style={{ background: b.color }} />
                  <span className="text-xs text-gray-500">{b.label}: <strong>{b.score}</strong></span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* ── Score breakdown ── */}
        <div className="bg-white rounded-2xl border border-gray-200 shadow-sm overflow-hidden">
          <div className="px-5 py-3 border-b border-gray-100 bg-gray-50">
            <p className="text-xs font-black text-gray-700 uppercase tracking-wider">Score Breakdown</p>
          </div>
          <div className="divide-y divide-gray-50">
            {dimensions.map(d => {
              const pct = d.value; // 0–1
              const dc = {
                text: pct >= 0.85 ? "#15803d" : pct >= 0.70 ? "#16a34a" : pct >= 0.55 ? "#d97706" : pct >= 0.40 ? "#ea580c" : "#dc2626",
                bg:   pct >= 0.85 ? "#f0fdf4" : pct >= 0.70 ? "#f0fdf4" : pct >= 0.55 ? "#fffbeb" : pct >= 0.40 ? "#fff7ed" : "#fff1f2",
              };
              return (
                <div key={d.key} className="px-5 py-4 flex items-start gap-4">
                  {/* Grade badge */}
                  <div className="w-9 h-9 rounded-xl flex items-center justify-center font-black text-base shrink-0 mt-0.5"
                    style={{ background: dc.bg, color: dc.text }}>
                    {d.grade}
                  </div>
                  {/* Label + bar */}
                  <div className="flex-1 min-w-0">
                    <div className="flex justify-between mb-1.5">
                      <span className="text-sm font-bold text-gray-900">{d.label}</span>
                      <span className="text-xs font-bold tabular-nums" style={{ color: dc.text }}>
                        +{d.score}
                        <span className="font-normal text-gray-300"> / {Math.round(d.weight * 1000)} pts</span>
                      </span>
                    </div>
                    <div className="h-2 bg-gray-100 rounded-full overflow-hidden">
                      <div className="h-full rounded-full transition-all duration-700"
                        style={{ width:`${d.value * 100}%`, background: dc.text }} />
                    </div>
                    <p className="text-xs text-gray-400 mt-1.5">{d.detail}</p>

                    {/* Per-repo spread for consistency dimension */}
                    {d.key === "consistency" && effectiveData.repos.length > 0 && (
                      <div className="mt-3 space-y-1.5">
                        {[...effectiveData.repos]
                          .sort((a, b) => a.attestation_rate - b.attestation_rate)
                          .map(r => {
                            const name = r.repo.split("/").pop() ?? r.repo;
                            const att  = r.attestation_rate;
                            const rc = att >= 0.80 ? "#16a34a" : att >= 0.60 ? "#d97706" : "#dc2626";
                            return (
                              <div key={r.repo} className="flex items-center gap-2">
                                <span className="text-xs text-gray-500 w-32 truncate shrink-0">{name}</span>
                                <div className="flex-1 h-1.5 bg-gray-100 rounded-full overflow-hidden">
                                  <div className="h-full rounded-full transition-all duration-500"
                                    style={{ width:`${att * 100}%`, background: rc }} />
                                </div>
                                <span className="text-xs font-bold w-9 text-right shrink-0" style={{ color: rc }}>
                                  {Math.round(att * 100)}%
                                </span>
                                <span className="text-xs text-gray-400 w-20 shrink-0">
                                  AI: {Math.round(r.ai_pct * 100)}%
                                </span>
                              </div>
                            );
                          })}
                      </div>
                    )}
                  </div>
                  {/* Weight */}
                  <div className="text-xs text-gray-400 shrink-0 text-right w-12">
                    {Math.round(d.weight * 100)}%<br/>
                    <span className="text-gray-300">weight</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        {/* ── What your score means ── */}
        <div className="grid grid-cols-3 gap-4">
          {[
            { range:"850–1000", label:"Excellent",  bg:"#f0fdf4", text:"#15803d", border:"#bbf7d0",
              desc:"Audit-ready. Share with enterprise customers, insurers, and auditors as proof of AI governance maturity." },
            { range:"600–849",  label:"Good",        bg:"#eff6ff", text:"#1d4ed8", border:"#bfdbfe",
              desc:"Strong foundation. Address the lowest-scoring dimensions to reach excellence within 30 days." },
            { range:"0–599",    label:"Needs Work",  bg:"#fff1f2", text:"#be123c", border:"#fecaca",
              desc:"Governance gaps detected. Prioritise attestation coverage and critical risk resolution immediately." },
          ].map(r => (
            <div key={r.range} className="rounded-2xl p-5 border"
              style={{ background: r.bg, borderColor: r.border }}>
              <div className="text-lg font-black mb-1" style={{ color: r.text }}>{r.range}</div>
              <div className="text-sm font-bold mb-2" style={{ color: r.text }}>{r.label}</div>
              <p className="text-xs text-gray-600 leading-relaxed">{r.desc}</p>
            </div>
          ))}
        </div>

        {/* ── Use cases ── */}
        <div className="bg-gradient-to-r from-indigo-600 to-purple-600 rounded-2xl p-6 text-white">
          <h3 className="font-black text-lg mb-4">Who accepts TrustScore™</h3>
          <div className="grid grid-cols-2 gap-4">
            {[
              { icon:"🏦", title:"Cyber Insurance",  desc:"Show insurers your score to qualify for lower premiums on AI-related coverage" },
              { icon:"📋", title:"SOC 2 Auditors",    desc:"Pre-populate evidence packages with your score and dimension breakdown" },
              { icon:"🏢", title:"Enterprise Clients", desc:"Respond to vendor security assessments with a single shareable score" },
              { icon:"📊", title:"Board Reports",      desc:"Give CISOs a clear number to present to the board every quarter" },
            ].map(u => (
              <div key={u.title} className="flex gap-3">
                <span className="text-2xl shrink-0">{u.icon}</span>
                <div>
                  <div className="font-bold text-sm">{u.title}</div>
                  <div className="text-xs text-indigo-200 mt-0.5">{u.desc}</div>
                </div>
              </div>
            ))}
          </div>
        </div>

      </div>
    </AuthGuard>
  );
}
