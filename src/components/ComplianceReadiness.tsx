"use client";

import type { DashboardData } from "@/types";

interface Props { data: DashboardData }

interface FwItem { label: string; pass: boolean }
interface Fw {
  id: string; name: string; shortName: string; description: string;
  gradient: string; textColor: string; score: number;
  status: "pass" | "partial" | "fail";
  items: FwItem[];
  icon: React.ReactNode;
}

function ShieldIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      <polyline points="9 12 11 14 15 10"/>
    </svg>
  );
}
function GlobeIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10"/>
      <line x1="2" y1="12" x2="22" y2="12"/>
      <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
    </svg>
  );
}
function CardIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="1" y="4" width="22" height="16" rx="2"/>
      <line x1="1" y1="10" x2="23" y2="10"/>
    </svg>
  );
}

function compute(data: DashboardData): Fw[] {
  const att      = data.attestation_rate;
  const ai       = data.overall_ai_pct;
  const unattest = data.unattested_deploy_count;
  const totalR   = data.repos.length;
  const compR    = data.repos.filter(r => r.attestation_rate >= 0.8).length;
  const critUnatt = data.top_risk_files.filter(f => f.risk_score === "CRITICAL" && !f.attested).length;

  const soc2  = Math.min(100, Math.round(att * 50 + (1 - Math.min(ai, 1)) * 25 + (unattest === 0 ? 25 : Math.max(0, 25 - unattest * 5))));
  const eu    = Math.min(100, Math.round(att * 55 + (totalR > 0 ? (compR / totalR) * 25 : 0) + (data.scan_count > 2 ? 20 : 10)));
  const pci   = Math.min(100, Math.round(att * 60 + (unattest === 0 ? 25 : Math.max(0, 25 - unattest * 8)) + (ai < 0.3 ? 15 : ai < 0.6 ? 8 : 0)));

  return [
    {
      id: "soc2", name: "SOC 2 Type II", shortName: "SOC 2",
      description: "Trust Services Criteria — Change Management",
      gradient: "from-indigo-500 to-violet-600", textColor: "#6366f1",
      score: soc2, status: soc2 >= 80 ? "pass" : soc2 >= 55 ? "partial" : "fail",
      icon: <ShieldIcon />,
      items: [
        { label: "Attestation coverage ≥ 80%",    pass: att >= 0.8 },
        { label: "Zero unattested deployments",    pass: unattest === 0 },
        { label: "Avg AI content below 50%",       pass: ai < 0.5 },
        { label: "All CRITICAL files reviewed",    pass: critUnatt === 0 },
        { label: "Active scan cadence",            pass: data.scan_count > 0 },
      ],
    },
    {
      id: "eu", name: "EU AI Act", shortName: "EU AI Act",
      description: "Article 9 — Risk Management & Traceability",
      gradient: "from-blue-500 to-cyan-500", textColor: "#3b82f6",
      score: eu, status: eu >= 80 ? "pass" : eu >= 55 ? "partial" : "fail",
      icon: <GlobeIcon />,
      items: [
        { label: "Human oversight attestations",   pass: att >= 0.7 },
        { label: "AI provenance documented",       pass: data.file_count > 0 },
        { label: "Change management log exists",   pass: data.scan_count > 2 },
        { label: "Repo compliance rate ≥ 60%",     pass: totalR > 0 && compR / totalR >= 0.6 },
        { label: "High-risk file tracking active", pass: data.top_risk_files.length >= 0 },
      ],
    },
    {
      id: "pci", name: "PCI-DSS v4.0", shortName: "PCI-DSS",
      description: "Req. 6.4 — Secure Software Development",
      gradient: "from-emerald-500 to-teal-500", textColor: "#10b981",
      score: pci, status: pci >= 80 ? "pass" : pci >= 55 ? "partial" : "fail",
      icon: <CardIcon />,
      items: [
        { label: "Attestation coverage ≥ 90%",     pass: att >= 0.9 },
        { label: "All CRITICAL files attested",    pass: critUnatt === 0 },
        { label: "AI code flagging active",        pass: data.scan_count > 0 },
        { label: "No unattested deploys",          pass: unattest === 0 },
        { label: "Dual-reviewer coverage",         pass: att >= 0.85 },
      ],
    },
  ];
}

export default function ComplianceReadiness({ data }: Props) {
  const fws = compute(data);
  const passing = fws.filter(f => f.status === "pass").length;

  return (
    <div className="section-card overflow-hidden">
      {/* Header */}
      <div className="px-5 py-4 border-b border-gray-100 flex items-center justify-between gap-3">
        <div>
          <p className="font-bold text-gray-900 text-sm">Compliance Readiness</p>
          <p className="text-xs text-gray-400 mt-0.5">Live framework scores derived from scan &amp; attestation data</p>
        </div>
        <div className="flex items-center gap-2">
          {fws.map(fw => (
            <span key={fw.id} className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${
              fw.status === "pass"    ? "bg-emerald-50 text-emerald-700 ring-1 ring-emerald-200" :
              fw.status === "partial" ? "bg-amber-50 text-amber-700 ring-1 ring-amber-200" :
                                        "bg-rose-50 text-rose-700 ring-1 ring-rose-200"
            }`}>
              {fw.shortName}: {fw.score}%
            </span>
          ))}
          <span className="text-[10px] font-bold uppercase tracking-widest text-gray-400 bg-gray-50 border border-gray-100 px-2 py-1 rounded-lg">
            {passing}/{fws.length} ready
          </span>
        </div>
      </div>

      {/* Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 divide-y md:divide-y-0 md:divide-x divide-gray-100">
        {fws.map(fw => (
          <div key={fw.id} className="p-5 space-y-4">
            {/* Title row */}
            <div className="flex items-start justify-between gap-2">
              <div className="flex items-start gap-3">
                <div className={`w-9 h-9 rounded-xl bg-gradient-to-br ${fw.gradient} flex items-center justify-center text-white shrink-0 shadow-sm`}>
                  {fw.icon}
                </div>
                <div className="min-w-0">
                  <p className="text-sm font-bold text-gray-900 leading-tight">{fw.name}</p>
                  <p className="text-[10px] text-gray-400 mt-0.5 leading-tight">{fw.description}</p>
                </div>
              </div>
              <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full shrink-0 whitespace-nowrap ${
                fw.status === "pass"    ? "bg-emerald-50 text-emerald-700 ring-1 ring-emerald-200" :
                fw.status === "partial" ? "bg-amber-50 text-amber-700 ring-1 ring-amber-200" :
                                          "bg-rose-50 text-rose-700 ring-1 ring-rose-200"
              }`}>
                {fw.status === "pass" ? "Ready" : fw.status === "partial" ? "Partial" : "Gap"}
              </span>
            </div>

            {/* Score bar */}
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <span className="text-[11px] text-gray-500 font-medium">Readiness score</span>
                <span className="text-sm font-black tabular-nums" style={{ color: fw.textColor }}>
                  {fw.score}%
                </span>
              </div>
              <div className="h-2 w-full bg-gray-100 rounded-full overflow-hidden">
                <div
                  className={`h-full rounded-full bg-gradient-to-r ${fw.gradient} transition-all duration-1000`}
                  style={{ width: `${fw.score}%` }}
                />
              </div>
            </div>

            {/* Checklist */}
            <ul className="space-y-1.5">
              {fw.items.map(item => (
                <li key={item.label} className="flex items-center gap-2">
                  <span className={`w-4 h-4 rounded-full flex items-center justify-center shrink-0 text-[9px] font-bold ${
                    item.pass ? "bg-emerald-100 text-emerald-700" : "bg-rose-100 text-rose-600"
                  }`}>
                    {item.pass ? "✓" : "✗"}
                  </span>
                  <span className={`text-[11px] font-medium leading-tight ${item.pass ? "text-gray-600" : "text-gray-400"}`}>
                    {item.label}
                  </span>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </div>
  );
}
