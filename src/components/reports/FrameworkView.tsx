"use client";

/**
 * Report section 4b: the framework's own working form (lib/frameworkViews.ts) -- ISO/IEC 27001 Statement of
 * Applicability input, PCI DSS 6.2.4 attack classes, or the AI governance mapping to ISO/IEC 42001 and NIST AI RMF.
 * The signed report carries the same view.
 */
import { STATUS_LABEL, type EvidenceStatus, type FrameworkDef } from "@/lib/controlEvidence";
import { FRAMEWORK_VIEW_TITLE, frameworkView, type ControlLike } from "@/lib/frameworkViews";

const STATUS_CLS: Record<EvidenceStatus, string> = {
  pass: "text-emerald-700", partial: "text-amber-700", fail: "text-rose-700", not_tested: "text-gray-400",
};
const TH = "px-3 py-2 text-left text-[9px] font-black uppercase tracking-widest text-gray-400";
const TD = "px-3 py-2.5 align-top text-[11px] text-gray-700";

export default function FrameworkView({ fw, controls }: { fw: FrameworkDef; controls: readonly ControlLike[] }) {
  const view = frameworkView(fw, controls);
  if (!view) return null;
  return (
    <div className="space-y-2">
      <p className="text-xs font-bold text-gray-700">4b. {FRAMEWORK_VIEW_TITLE[view.kind]}</p>

      {view.kind === "iso_soa" && (
        <>
          <p className="text-[11px] text-gray-500">
            For your Statement of Applicability. Applicability is your decision; TrustLedger supplies the implementation and
            evidence reference where it holds evidence, and says where it holds none.
          </p>
          <div className="rounded-xl border border-gray-200 overflow-x-auto">
            <table aria-label="Statement of Applicability input" className="w-full">
              <thead><tr className="bg-gray-50"><th className={TH}>Control</th><th className={TH}>Implementation</th><th className={TH}>Evidence reference</th><th className={TH}>Evidence</th></tr></thead>
              <tbody>
                {view.rows.map(r => (
                  <tr key={r.control} className={`border-t border-gray-100 ${r.evidenced ? "" : "bg-gray-50/60"}`}>
                    <td className={`${TD} min-w-[160px]`}><span className="font-mono font-bold text-gray-900">{r.control}</span><p className="text-[10px] text-gray-500">{r.title}</p></td>
                    <td className={`${TD} min-w-[260px] ${r.evidenced ? "" : "text-gray-500 italic"}`}>
                      {r.implementation}
                      {r.gaps.map(g => <p key={g} className="text-[10px] font-semibold text-amber-800 mt-1 not-italic">Gap: {g}</p>)}
                    </td>
                    <td className={`${TD} min-w-[140px]`}>{r.evidence_reference}</td>
                    <td className={`${TD} whitespace-nowrap font-bold ${r.status ? STATUS_CLS[r.status] : "text-gray-400"}`}>{r.status ? STATUS_LABEL[r.status] : "None"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {view.kind === "pci_624" && (
        <div className="rounded-xl border border-gray-200 overflow-x-auto">
          <table aria-label="Requirement 6.2.4 attack classes" className="w-full">
            <thead><tr className="bg-gray-50"><th className={TH}>Attack class</th><th className={TH}>TrustLedger rules</th><th className={TH}>Where scanning stops</th></tr></thead>
            <tbody>
              {view.classes.map(c => (
                <tr key={c.key} className="border-t border-gray-100">
                  <td className={`${TD} min-w-[200px] font-semibold text-gray-900`}>{c.title}</td>
                  <td className={`${TD} min-w-[220px]`}>
                    {c.rules.length === 0 ? <span className="text-gray-500">Tracked under 6.3.1</span> : (
                      <div className="flex flex-wrap gap-1">
                        {c.rules.map(r => <a key={r} href={`/rules#${encodeURIComponent(r)}`} className="text-[10px] font-mono bg-gray-100 hover:bg-indigo-50 px-1 rounded">{r}</a>)}
                      </div>
                    )}
                  </td>
                  <td className={`${TD} min-w-[200px] text-gray-500`}>{c.limits}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {view.kind === "ai_mapping" && (
        <>
          <p className="text-[11px] rounded-lg px-3 py-2 border border-amber-200 bg-amber-50 text-amber-900">{view.caveat}</p>
          <div className="rounded-xl border border-gray-200 overflow-x-auto">
            <table aria-label="AI governance mapping" className="w-full">
              <thead><tr className="bg-gray-50"><th className={TH}>Control</th><th className={TH}>ISO/IEC 42001 Annex A</th><th className={TH}>NIST AI RMF 1.0</th><th className={TH}>Note</th></tr></thead>
              <tbody>
                {view.rows.map(r => (
                  <tr key={r.control} className="border-t border-gray-100">
                    <td className={`${TD} min-w-[170px]`}>
                      <span className="font-mono font-bold text-gray-900">{r.control}</span> {r.name}
                      {r.status && <p className={`text-[10px] font-bold ${STATUS_CLS[r.status]}`}>{STATUS_LABEL[r.status]}</p>}
                    </td>
                    <td className={`${TD} min-w-[160px]`}>{r.iso42001.length ? r.iso42001.map(x => <p key={x.id}><span className="font-mono font-semibold">{x.id}</span> {x.title}</p>) : "—"}</td>
                    <td className={`${TD} min-w-[200px]`}>{r.nist_ai_rmf.length ? r.nist_ai_rmf.map(x => <p key={x.id}><span className="font-mono font-semibold">{x.id}</span>: {x.summary}</p>) : "—"}</td>
                    <td className={`${TD} min-w-[200px] text-gray-500`}>{r.note}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  );
}
