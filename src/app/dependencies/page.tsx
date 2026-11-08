"use client";

/**
 * Dependencies: one page for everything about the packages your code uses.
 *
 * "Threat intel" and "Dependencies" used to be two pages over the same data (/api/dependencies: the latest scan of each
 * repository): one ranked the known vulnerabilities and said what to upgrade first, the other listed every package with
 * its licence, reachability and SBOM. Two places for the same findings meant two counts to reconcile, so they are
 * now two views of one page. /threat-intel redirects to the Vulnerabilities view.
 */
import { useEffect, useState } from "react";
import AuthGuard from "@/components/AuthGuard";
import DependencyInventory from "@/components/DependencyInventory";
import ThreatIntelView from "@/components/ThreatIntelView";
import { CapNote } from "@/components/Limits";
import { viewFromLocation, type DependencyView } from "@/lib/dependencyViews";

type View = DependencyView;
const VIEWS: Array<{ id: View; label: string; hint: string }> = [
  { id: "packages", label: "All packages", hint: "Every package, licences, reachability and the SBOM" },
  { id: "advisories", label: "Vulnerabilities & fixes", hint: "Known advisories ranked by what to fix first, with one upgrade per package" },
];

export default function DependenciesPage() {
  const [view, setView] = useState<View>("packages");
  useEffect(() => { setView(viewFromLocation(window.location.search)); }, []);

  function pick(next: View) {
    setView(next);
    try {
      const url = new URL(window.location.href);
      if (next === "packages") url.searchParams.delete("view"); else url.searchParams.set("view", "advisories");
      window.history.replaceState(null, "", url);
    } catch { /* the view still switches */ }
  }

  return (
    <AuthGuard>
      <div className="mx-auto max-w-[1400px] space-y-5">
        <div role="tablist" aria-label="Dependencies" className="flex flex-wrap items-center gap-1 rounded-xl bg-gray-100 p-1 w-fit">
          {VIEWS.map(v => (
            <button key={v.id} role="tab" aria-selected={view === v.id} title={v.hint} onClick={() => pick(v.id)}
              className={`rounded-lg px-4 py-2 text-xs font-bold transition-all ${view === v.id ? "bg-white text-gray-900 shadow-sm" : "text-gray-500 hover:text-gray-700"}`}>
              {v.label}
            </button>
          ))}
        </div>
        <div role="tabpanel">
          {view === "advisories" ? <ThreatIntelView /> : <DependencyInventory />}
        </div>
        <CapNote cap="bulkRows" className="pb-6" />
      </div>
    </AuthGuard>
  );
}
