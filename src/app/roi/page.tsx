"use client";

import { useState, useEffect, useMemo } from "react";
import AuthGuard from "@/components/AuthGuard";
import PageSkeleton from "@/components/PageSkeleton";
import { authedFetch, isSeedMode } from "@/lib/useRealData";
import { useAuth } from "@/lib/auth";

// ── ROI computation ─────────────────────────────────────────────────────────

const INDUSTRY_BENCHMARKS = {
  avgCostPerSecurityBreach:    4_450_000,  // IBM 2024 Cost of a Data Breach
  avgCostPerVulnerability:         6_000,  // Cost to fix post-production vs pre
  avgHoursPerManualReview:             2,  // Without TrustLedger
  avgHoursPerAttestation:           0.15,  // With TrustLedger
  avgEngineerHourlyCost:              85,  // USD
  avgComplianceAuditCost:        120_000,  // SOC 2 Type II
  avgFinePerGDPRBreach:          500_000,
  criticalBreachProbability:        0.15,  // 15% of exposed credentials lead to breach
};

interface ROIMetrics {
  totalScans:         number;
  totalFiles:         number;
  totalAttestations:  number;
  openViolations:     number;
  criticalCaught:     number;
  secretsCaught:      number;
  members:            number;
  period_days:        number;
}

function computeROI(m: ROIMetrics) {
  const b = INDUSTRY_BENCHMARKS;

  // Time saved: attestation automation
  const manualHours   = m.totalAttestations * b.avgHoursPerManualReview;
  const tledgerHours  = m.totalAttestations * b.avgHoursPerAttestation;
  const hoursSaved    = Math.max(0, manualHours - tledgerHours);
  const timeSavedUSD  = hoursSaved * b.avgEngineerHourlyCost;

  // Breach risk reduction from catching critical/secrets
  const breachesAverted   = (m.criticalCaught + m.secretsCaught) * b.criticalBreachProbability;
  const breachRiskReduced = breachesAverted * b.avgCostPerSecurityBreach;

  // Vulnerability cost avoidance (fix in PR vs post-production)
  const vulnCostAvoided = m.criticalCaught * b.avgCostPerVulnerability;

  // Compliance cost: automated evidence reduces audit prep time
  const auditSavingsPct = 0.35; // 35% reduction in audit prep
  const complianceSaved = b.avgComplianceAuditCost * auditSavingsPct;

  // Total ROI
  const totalBenefits = timeSavedUSD + breachRiskReduced + vulnCostAvoided + complianceSaved;

  // Estimated TrustLedger cost (Growth plan annualised)
  const tlCostAnnual = 999 * 12;
  const tlCostPeriod = tlCostAnnual * (m.period_days / 365);
  const roi = totalBenefits > 0 ? ((totalBenefits - tlCostPeriod) / tlCostPeriod) * 100 : 0;

  return {
    hoursSaved:        Math.round(hoursSaved),
    timeSavedUSD:      Math.round(timeSavedUSD),
    breachesAverted:   Math.round(breachesAverted * 10) / 10,
    breachRiskReduced: Math.round(breachRiskReduced),
    vulnCostAvoided:   Math.round(vulnCostAvoided),
    complianceSaved:   Math.round(complianceSaved),
    totalBenefits:     Math.round(totalBenefits),
    tlCostPeriod:      Math.round(tlCostPeriod),
    roi:               Math.round(roi),
  };
}

function fmt(n: number, prefix = "$"): string {
  if (n >= 1_000_000) return `${prefix}${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000)     return `${prefix}${(n / 1_000).toFixed(0)}K`;
  return `${prefix}${n.toLocaleString()}`;
}

function MetricCard({ label, value, sub, color = "#6366f1", icon }: {
  label: string; value: string; sub?: string; color?: string; icon?: string;
}) {
  return (
    <div className="bg-white rounded-2xl border border-gray-200 p-5 shadow-sm">
      <div className="flex items-start justify-between mb-3">
        <p className="text-xs font-semibold text-gray-500">{label}</p>
        {icon && <span className="text-xl">{icon}</span>}
      </div>
      <p className="text-2xl font-black" style={{ color }}>{value}</p>
      {sub && <p className="text-xs text-gray-400 mt-1">{sub}</p>}
    </div>
  );
}

export default function ROIDashboard() {
  const { profile } = useAuth();
  const [metrics,    setMetrics]    = useState<ROIMetrics | null>(null);
  const [loading,    setLoading]    = useState(true);
  const [period,     setPeriod]     = useState(90);
  const [exportMsg,  setExportMsg]  = useState("");

  useEffect(() => {
    async function load() {
      setLoading(true);

      if (isSeedMode()) {
        // Demo metrics
        setMetrics({
          totalScans: 171, totalFiles: 1067, totalAttestations: 384,
          openViolations: 12, criticalCaught: 8, secretsCaught: 8,
          members: 6, period_days: period,
        });
        setLoading(false);
        return;
      }

      if (!profile?.org_id) { setLoading(false); return; }

      try {
        const [dashboard, secrets, attests, orgSettings] = await Promise.all([
          authedFetch<{ scan_count: number; file_count: number; repos: unknown[] }>(`/api/dashboard?days=${period}`),
          authedFetch<{ total: number }>(`/api/export?type=secrets&format=json&days=${period}`).catch(() => ({ total: 0 })),
          authedFetch<{ violations: Array<{ risk_score: string }> }>(`/api/violations?status=resolved&limit=500`),
          authedFetch<{ members: unknown[] }>(`/api/settings`).catch(() => ({ members: [] })),
        ]);

        const critResolved = attests.violations?.filter(v => v.risk_score === "CRITICAL").length ?? 0;

        setMetrics({
          totalScans:        dashboard.scan_count ?? 0,
          totalFiles:        dashboard.file_count ?? 0,
          totalAttestations: attests.violations?.length ?? 0,
          openViolations:    0,
          criticalCaught:    critResolved,
          secretsCaught:     (secrets as {total?: number}).total ?? 0,
          members:           (orgSettings.members as unknown[]).length || 1,
          period_days:       period,
        });
      } catch { /* use zeros */ }
      setLoading(false);
    }
    load();
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [profile?.org_id, period]);

  const roi = useMemo(() => metrics ? computeROI(metrics) : null, [metrics]);

  if (loading) return <AuthGuard><PageSkeleton><div /></PageSkeleton></AuthGuard>;

  return (
    <AuthGuard>
      <div className="max-w-5xl mx-auto space-y-6 pb-10">

        {/* Header */}
        <div className="flex items-start justify-between gap-4 flex-wrap pt-1">
          <div>
            <h1 className="text-xl font-black text-gray-900">ROI Dashboard</h1>
            <p className="text-sm text-gray-400 mt-0.5">Value delivered by TrustLedger — measurable security outcomes</p>
          </div>
          <div className="flex items-center gap-1 bg-gray-100 p-0.5 rounded-xl">
            {[30, 90, 365].map(d => (
              <button key={d} onClick={() => setPeriod(d)}
                className={`px-4 py-1.5 text-xs font-semibold rounded-lg transition-all ${period === d ? "bg-white text-gray-900 shadow-sm" : "text-gray-500"}`}>
                {d === 365 ? "1 year" : `${d}d`}
              </button>
            ))}
          </div>
        </div>

        {/* ROI hero */}
        {roi && (
          <div className="rounded-3xl p-8 text-white"
            style={{ background:"linear-gradient(135deg,#0f172a 0%,#1e1040 60%,#0f172a 100%)" }}>
            <p className="text-sm font-bold text-white/50 uppercase tracking-widest mb-2">Estimated ROI</p>
            <div className="flex items-end gap-4 flex-wrap">
              <div>
                <p className="text-6xl font-black text-indigo-300">{roi.roi > 0 ? "+" : ""}{roi.roi}%</p>
                <p className="text-white/50 text-sm mt-1">Return on investment over {period} days</p>
              </div>
              <div className="ml-auto text-right">
                <p className="text-3xl font-black text-emerald-400">{fmt(roi.totalBenefits)}</p>
                <p className="text-white/40 text-xs mt-1">Total value delivered</p>
              </div>
            </div>
            <p className="text-xs text-white/30 mt-4">
              Based on IBM 2024 Cost of a Data Breach Report · Industry averages. Actual savings depend on your specific risk profile.
            </p>
          </div>
        )}

        {/* Activity metrics */}
        {metrics && (
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <MetricCard label="Scans Run"        value={metrics.totalScans.toLocaleString()}        sub="PRs analysed"             icon="🔍" color="#6366f1" />
            <MetricCard label="Files Scanned"    value={metrics.totalFiles.toLocaleString()}         sub="Source files checked"     icon="📄" color="#6366f1" />
            <MetricCard label="Attestations"     value={metrics.totalAttestations.toLocaleString()}  sub="Reviewer sign-offs"       icon="✅" color="#10b981" />
            <MetricCard label="Threats Caught"   value={(metrics.criticalCaught + metrics.secretsCaught).toLocaleString()} sub="Before production" icon="🛡️" color="#ef4444" />
          </div>
        )}

        {/* Value breakdown */}
        {roi && (
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div className="bg-white rounded-2xl border border-gray-200 p-6 shadow-sm space-y-4">
              <h3 className="text-sm font-black text-gray-900">Value Breakdown</h3>
              {[
                { label:"Engineer time saved",         value:roi.timeSavedUSD,       sub:`${roi.hoursSaved.toLocaleString()} hours × $${INDUSTRY_BENCHMARKS.avgEngineerHourlyCost}/hr`, color:"#6366f1" },
                { label:"Breach risk reduction",       value:roi.breachRiskReduced,  sub:`${roi.breachesAverted} potential breaches averted`,                                             color:"#ef4444" },
                { label:"Vulnerability cost avoidance",value:roi.vulnCostAvoided,    sub:`${metrics?.criticalCaught ?? 0} CRITICAL issues caught pre-production`,                        color:"#f59e0b" },
                { label:"Compliance cost savings",     value:roi.complianceSaved,    sub:"35% reduction in SOC 2 audit prep",                                                            color:"#10b981" },
              ].map(item => (
                <div key={item.label} className="flex items-start justify-between gap-3">
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-semibold text-gray-800">{item.label}</p>
                    <p className="text-[11px] text-gray-400 mt-0.5">{item.sub}</p>
                  </div>
                  <p className="text-sm font-black shrink-0" style={{ color: item.color }}>{fmt(item.value)}</p>
                </div>
              ))}
              <div className="border-t border-gray-100 pt-3 flex items-center justify-between">
                <p className="text-sm font-black text-gray-900">Total value</p>
                <p className="text-lg font-black text-emerald-600">{fmt(roi.totalBenefits)}</p>
              </div>
            </div>

            <div className="space-y-4">
              {/* CISO talking points */}
              <div className="bg-indigo-50 rounded-2xl border border-indigo-100 p-5">
                <p className="text-xs font-black text-indigo-800 uppercase tracking-widest mb-3">Board-Level Summary</p>
                <ul className="space-y-2.5">
                  {[
                    `Scanned ${metrics?.totalFiles?.toLocaleString() ?? 0} source files for AI-generated code`,
                    `Caught ${(metrics?.criticalCaught ?? 0) + (metrics?.secretsCaught ?? 0)} CRITICAL threats before production`,
                    `${metrics?.totalAttestations?.toLocaleString() ?? 0} signed attestations create tamper-evident audit trail`,
                    `SOC 2 audit evidence collected automatically — zero manual export`,
                    `Estimated ${roi.hoursSaved.toLocaleString()} engineering hours saved on security reviews`,
                  ].map((pt, i) => (
                    <li key={i} className="flex items-start gap-2 text-xs text-indigo-800">
                      <span className="shrink-0 mt-0.5 text-indigo-400 font-bold">✓</span>
                      {pt}
                    </li>
                  ))}
                </ul>
              </div>

              {/* Export CTA */}
              <div className="bg-gray-50 rounded-2xl border border-gray-200 p-5">
                <p className="text-sm font-bold text-gray-900 mb-1">Export for executive review</p>
                <p className="text-xs text-gray-500 mb-3">Download a one-page ROI summary as PDF to share with your CISO, CTO, or board.</p>
                <button
                  onClick={() => { setExportMsg("PDF export will be available once /api/report is connected."); setTimeout(() => setExportMsg(""), 3500); }}
                  className="px-4 py-2 text-sm font-bold rounded-xl bg-indigo-600 text-white hover:bg-indigo-700 transition-colors">
                  Export ROI report →
                </button>
                {exportMsg && (
                  <p className="text-xs text-indigo-600 mt-2">{exportMsg}</p>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Methodology */}
        <details className="bg-white rounded-2xl border border-gray-200 p-5 shadow-sm">
          <summary className="text-sm font-bold text-gray-700 cursor-pointer">Methodology &amp; assumptions</summary>
          <div className="mt-4 space-y-2 text-xs text-gray-500 leading-relaxed">
            <p><strong>Engineer time saved:</strong> Each attestation takes 2h manually vs 9min with TrustLedger. Based on internal surveys and industry benchmarks.</p>
            <p><strong>Breach risk reduction:</strong> IBM 2024 Cost of a Data Breach Report avg $4.45M. 15% of exposed credentials lead to a breach.</p>
            <p><strong>Vulnerability cost avoidance:</strong> NIST estimates fixing a vulnerability post-production costs 6-100× more than in development. We use $6,000 per CRITICAL finding.</p>
            <p><strong>Compliance savings:</strong> Average SOC 2 Type II audit costs $120K. TrustLedger automated evidence collection reduces audit prep by ~35%.</p>
            <p className="text-gray-400 italic">All figures are estimates based on published industry research. Your actual ROI will vary.</p>
          </div>
        </details>

      </div>
    </AuthGuard>
  );
}
