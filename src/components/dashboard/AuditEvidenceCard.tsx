"use client";

/**
 * Audit evidence: for each framework, how many of its controls TrustLedger has evidence for, and the gaps to close.
 * Built from real records by the evidence engine (GET /api/evidence/collect?overview=1, lib/controlEvidence.ts) --
 * statuses, never "% compliant": this is evidence for an auditor, not a certification.
 */
import { useEffect, useState } from "react";
import Link from "next/link";
import { authedFetch } from "@/lib/useRealData";
import type { EvidenceStatus } from "@/lib/controlEvidence";
import type { EvidenceOverview } from "@/lib/evidenceEngine";

const DOT: Record<EvidenceStatus, string> = {
  pass: "bg-emerald-500", partial: "bg-amber-400", fail: "bg-rose-500", not_tested: "bg-gray-300",
};
const ORDER: EvidenceStatus[] = ["pass", "partial", "fail", "not_tested"];
/** "<n> controls ..." -- the short form of STATUS_LABEL for counts. */
const COUNT_LABEL: Record<EvidenceStatus, string> = {
  pass: "with evidence", partial: "with gaps", fail: "failing", not_tested: "no evidence yet",
};
const REPORT_FW: Record<string, string> = { soc2: "SOC2", iso27001: "ISO27001", pcidss: "PCIDSS", aigov: "AIGOV" };

export function AuditEvidenceView({ overview }: { overview: EvidenceOverview }) {
  return (
    <section aria-label="Audit evidence" className="section-card p-5 space-y-4">
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div>
          <p className="font-bold text-gray-900 text-sm">Audit evidence</p>
          <p className="text-xs text-gray-400 mt-0.5">
            What your scans, reviews and audit log prove for each framework&apos;s code-change controls · last 90 days
          </p>
        </div>
        <Link href="/reports" className="text-xs font-semibold text-indigo-600 hover:text-indigo-800 bg-indigo-50 hover:bg-indigo-100 border border-indigo-100 px-2.5 py-1 rounded-lg transition-colors whitespace-nowrap">
          Evidence reports →
        </Link>
      </div>

      <div className={`grid grid-cols-1 sm:grid-cols-2 gap-3 ${overview.frameworks.length === 3 ? "lg:grid-cols-3" : "lg:grid-cols-4"}`}>
        {overview.frameworks.map(f => {
          const total = f.controls.length;
          return (
            <Link key={f.id} href={`/reports?fw=${REPORT_FW[f.id] ?? f.id}`}
              className="rounded-xl border border-gray-100 p-3.5 hover:border-indigo-200 hover:bg-indigo-50/30 transition-colors">
              <p className="text-xs font-bold text-gray-800">{f.name}</p>
              <p className="text-[11px] text-gray-500 mt-0.5">
                <span className="font-black text-gray-900 tabular-nums">{f.status_counts.pass}</span> of {total} controls with evidence
              </p>
              <div className="mt-2.5 flex h-1.5 rounded-full overflow-hidden bg-gray-100" aria-hidden="true">
                {ORDER.map(s => f.status_counts[s] > 0 && (
                  <div key={s} className={DOT[s]} style={{ width: `${(f.status_counts[s] / Math.max(total, 1)) * 100}%` }} />
                ))}
              </div>
              <ul className="mt-2 flex flex-wrap gap-x-2.5 gap-y-0.5">
                {ORDER.filter(s => s !== "pass" && f.status_counts[s] > 0).map(s => (
                  <li key={s} className="flex items-center gap-1 text-[10px] text-gray-500">
                    <span className={`w-1.5 h-1.5 rounded-full ${DOT[s]}`} />{f.status_counts[s]} {COUNT_LABEL[s]}
                  </li>
                ))}
              </ul>
            </Link>
          );
        })}
      </div>

      {overview.gaps.length > 0 ? (
        <div>
          <p className="text-[10px] font-bold uppercase tracking-wider text-gray-400 mb-1.5">Gaps to close</p>
          <ul className="space-y-1">
            {overview.gaps.slice(0, 4).flatMap(c => c.gaps.slice(0, 1).map(g => (
              <li key={c.key} className="flex items-start gap-2 text-xs text-gray-600">
                <span className={`mt-1.5 w-1.5 h-1.5 rounded-full shrink-0 ${DOT[c.status]}`} />
                <span><span className="font-semibold text-gray-800">{c.label}:</span> {g}</span>
              </li>
            )))}
          </ul>
        </div>
      ) : (
        <p className="text-xs text-emerald-700">No gaps found in the controls TrustLedger can evidence.</p>
      )}

      <p className="text-[10px] text-gray-400 leading-relaxed">
        Covers only the controls TrustLedger can measure from code changes. It is not a SOC 2 report, ISO certificate or
        PCI DSS assessment; those come from an auditor. The EU AI Act isn&apos;t assessed: it regulates AI systems, not
        teams that use AI coding tools.
      </p>
    </section>
  );
}

export default function AuditEvidenceCard() {
  const [overview, setOverview] = useState<EvidenceOverview | null>(null);
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    let live = true;
    authedFetch<EvidenceOverview>("/api/evidence/collect?overview=1")
      .then(o => { if (live) { if (Array.isArray(o?.frameworks)) setOverview(o); else setFailed(true); } })
      .catch(() => { if (live) setFailed(true); });
    return () => { live = false; };
  }, []);
  if (failed) return null;
  if (!overview) return <div className="section-card p-5 h-40 animate-pulse" aria-label="Loading audit evidence" />;
  return <AuditEvidenceView overview={overview} />;
}
