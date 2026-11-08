"use client";

/**
 * Threats: policy violations, security alerts and incidents on one page.
 *
 * They are three stages of one problem: a file is out of policy (a violation, the work queue), the team is told
 * (an alert, one per pull request, with live progress), and when it is not handled in time it is escalated (an
 * incident, with an owner, a timeline and a playbook). As three pages they had three counts for what is mostly the
 * same pull requests. The Overview counts each stage and says what to do first; each tab is the full view.
 * /violations, /alerts and /incidents redirect here and keep their query strings.
 */
import { useCallback, useEffect, useMemo, useState } from "react";
import AuthGuard from "@/components/AuthGuard";
import ViolationsView from "@/components/threats/ViolationsView";
import AlertsView from "@/components/threats/AlertsView";
import IncidentsView from "@/components/threats/IncidentsView";
import { CapNote } from "@/components/Limits";
import { api } from "@/lib/api";
import { readSeed } from "@/lib/offlineData";
import { authedFetch, isSeedMode } from "@/lib/useRealData";
import { useAuth } from "@/lib/auth";
import { fetchServerOverrides, statusesOf } from "@/lib/violationStatuses";
import { patchDataWithAttestations } from "@/lib/trustScore";
import { buildOverview, type FiringAlert, type ThreatOverview } from "@/lib/threatOverview";
import { tabFromSearch, THREAT_TABS, type ThreatTab } from "@/lib/threatRoutes";
import type { DashboardData } from "@/types";

const TAB: Record<ThreatTab, { label: string; role: string; detail: string }> = {
  overview: { label: "Overview", role: "What to do first", detail: "All three stages at a glance, with the things to do first." },
  violations: { label: "Violations", role: "Work queue", detail: "Each file or rule out of policy. Attest it (a signed review that unblocks the merge) or close it with a reason (no review: the merge stays blocked)." },
  alerts: { label: "Alerts", role: "Notifications", detail: "One per pull request waiting for sign-off, with live progress. Closes itself when the PR is clear or a newer push replaces it." },
  incidents: { label: "Incidents", role: "Escalations", detail: "Only when something went wrong: a CRITICAL file still unreviewed past its 24 h deadline. Has an owner, a timeline and a playbook." },
};
const TONE = { bad: "border-rose-200 bg-rose-50 text-rose-800", warn: "border-amber-200 bg-amber-50 text-amber-900", info: "border-sky-200 bg-sky-50 text-sky-900" } as const;

function Stage({ tab, count, headline, lines, onOpen, tone }: { tab: ThreatTab; count: number; headline: string; lines: string[]; onOpen: () => void; tone: string }) {
  return (
    <button onClick={onOpen} className="group flex-1 rounded-2xl border border-gray-200 bg-white p-5 text-left shadow-[0_1px_2px_rgba(15,23,42,0.05)] transition-colors hover:border-indigo-200">
      <p className="text-[10px] font-black uppercase tracking-widest text-gray-400">{TAB[tab].role}</p>
      <p className="mt-1 text-3xl font-black tabular-nums leading-none" style={{ color: count > 0 ? tone : "#16a34a" }}>{count}</p>
      <p className="mt-1.5 text-sm font-bold text-gray-900">{headline}</p>
      <ul className="mt-2 space-y-0.5 text-xs text-gray-500">{lines.map(l => <li key={l}>{l}</li>)}</ul>
      <p className="mt-3 text-xs font-bold text-indigo-600 group-hover:underline">Open {TAB[tab].label.toLowerCase()} →</p>
    </button>
  );
}

export default function ThreatsPage() {
  const { profile } = useAuth();
  const orgId = profile?.org_id;
  const [tab, setTab] = useState<ThreatTab>("overview");
  const [overview, setOverview] = useState<ThreatOverview | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => { setTab(tabFromSearch(window.location.search)); }, []);

  function pick(next: ThreatTab) {
    setTab(next);
    try {
      const url = new URL(window.location.href);
      url.search = "";
      if (next !== "overview") url.searchParams.set("tab", next);
      window.history.replaceState(null, "", url);
    } catch { /* the tab still switches */ }
  }

  // The same sources as the sidebar badges, so the numbers here are the numbers there.
  const load = useCallback(async () => {
    if (isSeedMode() && !orgId) {
      setOverview(buildOverview({ data: readSeed(), statuses: {}, alerts: [], incidentsOpen: 0 }));
      return;
    }
    if (!orgId) return;
    const [dash, overrides, alerts, incidents] = await Promise.allSettled([
      api.dashboard(profile?.org_slug || "org", 90),
      fetchServerOverrides(),
      authedFetch<{ alerts: FiringAlert[] }>("/api/alerts?status=firing&limit=200"),
      authedFetch<{ count: number }>("/api/incidents?count=open"),
    ]);
    if ([dash, alerts, incidents].every(r => r.status === "rejected")) { setFailed(true); return; }
    setFailed(false);
    const statuses = overrides.status === "fulfilled" ? statusesOf(overrides.value) : {};
    const data: DashboardData | null = dash.status === "fulfilled" ? patchDataWithAttestations(dash.value, statuses) : null;
    setOverview(buildOverview({
      data, statuses,
      alerts: alerts.status === "fulfilled" ? alerts.value.alerts ?? [] : [],
      incidentsOpen: incidents.status === "fulfilled" ? incidents.value.count ?? 0 : 0,
    }));
  }, [orgId, profile?.org_slug]);

  useEffect(() => { void load(); }, [load]);

  const counts = useMemo<Record<ThreatTab, number | null>>(() => ({
    overview: null,
    violations: overview?.violations.open ?? null,
    alerts: overview?.alerts.firing ?? null,
    incidents: overview?.incidents.open ?? null,
  }), [overview]);

  return (
    <AuthGuard>
      <div className="mx-auto max-w-7xl space-y-5 pb-10">
        <div>
          <h1 className="text-xl font-black tracking-tight text-gray-900">Threats</h1>
          <p className="mt-0.5 text-sm text-gray-400">Violations, alerts and incidents: what is out of policy, who has been told, and what was escalated.</p>
        </div>

        <div role="tablist" aria-label="Threats" className="flex flex-wrap items-center gap-1 rounded-xl bg-gray-100 p-1 w-fit">
          {THREAT_TABS.map(t => (
            <button key={t} role="tab" aria-selected={tab === t} title={TAB[t].detail} onClick={() => pick(t)}
              className={`flex items-center gap-2 rounded-lg px-4 py-2 text-xs font-bold transition-all ${tab === t ? "bg-white text-gray-900 shadow-sm" : "text-gray-500 hover:text-gray-700"}`}>
              {TAB[t].label}
              {counts[t] != null && counts[t]! > 0 && (
                <span className={`rounded-full px-1.5 py-0.5 text-[10px] font-black ${t === "incidents" ? "bg-rose-600 text-white" : t === "alerts" ? "bg-orange-100 text-orange-700" : "bg-rose-100 text-rose-700"}`}>{counts[t]}</span>
              )}
            </button>
          ))}
        </div>
        {tab !== "overview" && <p className="-mt-2 text-xs text-gray-500">{TAB[tab].detail}</p>}

        <div role="tabpanel" aria-label={TAB[tab].label}>
          {tab === "overview" && (
            <div className="space-y-5">
              {failed && <div role="alert" className="flex items-center gap-3 rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-800"><span className="flex-1">We couldn&apos;t load the overview.</span><button onClick={() => void load()} className="font-bold underline">Try again</button></div>}
              {!overview && !failed && <p className="text-sm text-gray-400">Loading…</p>}
              {overview && (
                <>
                  <div className="flex flex-col gap-3 md:flex-row md:items-stretch" aria-label="Stages">
                    <Stage tab="violations" count={overview.violations.open} tone="#dc2626" onOpen={() => pick("violations")}
                      headline={overview.violations.open === 1 ? "open violation" : "open violations"}
                      lines={[
                        `${overview.violations.critical} critical · ${overview.violations.high} high · ${overview.violations.medium} medium`,
                        `${overview.violations.slaBreached} past their deadline`,
                        ...(overview.violations.closedWithoutAttestation ? [`${overview.violations.closedWithoutAttestation} closed without a review`] : []),
                      ]} />
                    <span aria-hidden className="hidden self-center text-gray-300 md:block">→</span>
                    <Stage tab="alerts" count={overview.alerts.firing} tone="#ea580c" onOpen={() => pick("alerts")}
                      headline={overview.alerts.firing === 1 ? "alert firing" : "alerts firing"}
                      lines={[`${overview.alerts.p1} P1`, `${overview.alerts.unacknowledged} not yet acknowledged`]} />
                    <span aria-hidden className="hidden self-center text-gray-300 md:block">→</span>
                    <Stage tab="incidents" count={overview.incidents.open} tone="#be123c" onOpen={() => pick("incidents")}
                      headline={overview.incidents.open === 1 ? "open incident" : "open incidents"}
                      lines={[overview.incidents.open ? "Being handled, with an owner and a playbook" : "Nothing has been escalated"]} />
                  </div>

                  <section aria-label="Do first" className="section-card p-5">
                    <h2 className="mb-3 text-sm font-black text-gray-900">Do first</h2>
                    {overview.clear ? (
                      <p className="text-sm text-emerald-700">All clear: no open violations, firing alerts or incidents.</p>
                    ) : overview.actions.length === 0 ? (
                      <p className="text-sm text-gray-500">Nothing urgent. Open the tabs above for the full lists.</p>
                    ) : (
                      <ol className="space-y-2">
                        {overview.actions.map(a => (
                          <li key={a.key}>
                            <button onClick={() => pick(a.tab)} className={`w-full rounded-xl border px-4 py-3 text-left ${TONE[a.tone]}`}>
                              <span className="block text-sm font-bold">{a.text}</span>
                              <span className="mt-0.5 block text-xs opacity-90">{a.detail}</span>
                            </button>
                          </li>
                        ))}
                      </ol>
                    )}
                  </section>
                </>
              )}
            </div>
          )}
          {tab === "violations" && <ViolationsView />}
          {tab === "alerts" && <AlertsView />}
          {tab === "incidents" && (<><IncidentsView /><CapNote cap="incidents" className="pt-4" /></>)}
        </div>
      </div>
    </AuthGuard>
  );
}
