"use client";

/**
 * Organisations: how each organisation is doing, why it may need attention, and what it uses of its plan.
 *  - everyone sees their own organisation, with its real numbers and quick links to act on them
 *  - platform admins (MSP) also see every client organisation, and can create one
 * The reading of the numbers (health, reasons, trend, sorting) is lib/orgSummary.ts; the caps are lib/limits.ts.
 */
import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import AuthGuard from "@/components/AuthGuard";
import PageSkeleton from "@/components/PageSkeleton";
import Tip from "@/components/Tip";
import { CapNotice, LimitMeter } from "@/components/Limits";
import { formatDateOnly, relativeTime, useTimezone } from "@/lib/timezone";
import { authedFetch, isSeedMode } from "@/lib/useRealData";
import { useAuth } from "@/lib/auth";
import { planLimits } from "@/lib/limits";
import {
  HEALTH_LABEL, HEALTH_TIP, filterOrgs, orgAttention, orgHealth, portfolioTotals, scanTrend, sortOrgs,
  type ListedOrg, type OrgHealth, type OrgMetrics, type OrgSortKey,
} from "@/lib/orgSummary";

type ApiOrg = OrgMetrics & { id: string; slug: string; name: string; github_org: string | null; is_current?: boolean };
type OrgView = ListedOrg & { is_current: boolean };

const RISK_COLOR: Record<string, string> = { CRITICAL: "#ef4444", HIGH: "#f97316", MEDIUM: "#f59e0b", LOW: "#22c55e", UNKNOWN: "#94a3b8" };
const PLAN_BADGE: Record<string, { bg: string; text: string }> = {
  trial: { bg: "#fef3c7", text: "#92400e" }, starter: { bg: "#eff6ff", text: "#1d4ed8" },
  growth: { bg: "#f0fdf4", text: "#15803d" }, enterprise: { bg: "#ede9fe", text: "#6d28d9" },
};
const HEALTH_STYLE: Record<OrgHealth, string> = {
  at_risk: "bg-rose-50 text-rose-700 ring-rose-200", watch: "bg-amber-50 text-amber-800 ring-amber-200",
  healthy: "bg-emerald-50 text-emerald-700 ring-emerald-200", inactive: "bg-gray-100 text-gray-600 ring-gray-200", new: "bg-sky-50 text-sky-700 ring-sky-200",
};
const ATTENTION_STYLE = { critical: "bg-rose-50 text-rose-800 ring-rose-200", warning: "bg-amber-50 text-amber-800 ring-amber-200", info: "bg-sky-50 text-sky-800 ring-sky-200" } as const;
const SORTS: Array<[OrgSortKey, string]> = [["attention", "Needs attention first"], ["name", "Name"], ["risk", "Latest risk"], ["last_scan", "Last scan"], ["violations", "Open violations"]];
const FILTERS: Array<[OrgHealth | "all", string]> = [["all", "All"], ["at_risk", "At risk"], ["watch", "Needs a look"], ["healthy", "Healthy"], ["inactive", "Inactive"], ["new", "New"]];

function viewOf(o: ApiOrg, now: Date): OrgView {
  const attention = orgAttention(o, now);
  return { ...o, is_current: !!o.is_current, attention, health: orgHealth(o, attention, now) };
}

function Metric({ label, value, sub, tip, tone }: { label: string; value: React.ReactNode; sub?: React.ReactNode; tip: string; tone?: string }) {
  return (
    <Tip tip={tip}>
      <div tabIndex={0} className="cursor-help rounded-lg px-2 py-1 text-center focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300">
        <p className={`text-lg font-black leading-tight tabular-nums ${tone ?? "text-gray-900"}`}>{value}</p>
        <p className="text-[10px] text-gray-400">{label}</p>
        {sub && <p className="text-[10px] font-semibold leading-tight">{sub}</p>}
      </div>
    </Tip>
  );
}

function OrgCard({ org, tz }: { org: OrgView; tz: string }) {
  const plan = PLAN_BADGE[org.plan] ?? PLAN_BADGE.starter;
  const riskCol = RISK_COLOR[org.latest_risk] ?? "#94a3b8";
  const trend = scanTrend(org.scans_30d, org.scans_prev_30d);
  const lim = planLimits(org.plan);
  const lastScan = org.last_scan ? relativeTime(org.last_scan, tz) : "Never";

  return (
    <article data-testid={`org-${org.slug}`} className="overflow-hidden rounded-2xl border border-gray-200 bg-white shadow-sm">
      <div className="flex flex-wrap items-start gap-4 px-5 py-4">
        <div className="grid h-12 w-12 shrink-0 place-items-center rounded-2xl text-lg font-black"
          style={{ background: `${riskCol}22`, color: riskCol, border: `2px solid ${riskCol}33` }} aria-hidden>
          {org.name.slice(0, 1).toUpperCase()}
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <h2 className="text-base font-black text-gray-900">{org.name}</h2>
            {org.is_current && <span className="rounded-full bg-indigo-50 px-2 py-0.5 text-[10px] font-bold text-indigo-700 ring-1 ring-indigo-200">Your organisation</span>}
            <span className="rounded-full px-2 py-0.5 text-[10px] font-bold capitalize" style={{ background: plan.bg, color: plan.text }}>{org.plan}</span>
            <Tip tip={HEALTH_TIP[org.health]}>
              <span tabIndex={0} data-health={org.health} className={`cursor-help rounded-full px-2 py-0.5 text-[10px] font-bold ring-1 focus:outline-none focus-visible:ring-2 ${HEALTH_STYLE[org.health]}`}>{HEALTH_LABEL[org.health]}</span>
            </Tip>
          </div>
          <p className="mt-0.5 text-xs text-gray-400">
            {org.github_org ? <>github.com/{org.github_org} · </> : null}<span className="font-mono">{org.slug}</span> · created {formatDateOnly(new Date(org.created_at), tz)}
          </p>
        </div>

        <div className="flex flex-wrap items-start justify-end gap-x-1 gap-y-2">
          <Metric label="Scans (30d)" value={org.scans_30d} tip="Scans run in the last 30 days, compared with the 30 days before."
            sub={trend.pct === null ? undefined : <span className={trend.dir === "up" ? "text-emerald-600" : trend.dir === "down" ? "text-rose-600" : "text-gray-400"}>{trend.dir === "up" ? "▲" : trend.dir === "down" ? "▼" : "•"} {Math.abs(trend.pct)}%</span>} />
          <Metric label="Open violations" value={org.open_violations} tone={org.open_violations > 0 ? "text-rose-600" : "text-emerald-600"}
            tip="Violations still open or in review: files that need a reviewer's attention."
            sub={org.open_critical > 0 || org.overdue > 0 ? <span className="text-rose-600">{org.open_critical} critical{org.overdue > 0 ? ` · ${org.overdue} overdue` : ""}</span> : undefined} />
          <Metric label="Repositories" value={org.repo_count} tip="Repositories connected and scanned." />
          <Metric label="Members" value={org.member_count} tip="People with access to this organisation." />
          <Metric label="Latest AI share" value={`${Number.isFinite(org.latest_ai_pct) ? Math.round(org.latest_ai_pct * 100) : 0}%`} tip="The share of AI-written code estimated in the latest scan." />
          <Metric label="Last scan" value={<span className="text-sm">{lastScan}</span>} tip={org.last_scan ? `Latest scan: ${formatDateOnly(new Date(org.last_scan), tz)}. Rated ${org.latest_risk}.` : "No scan has run yet."}
            sub={org.latest_risk !== "UNKNOWN" ? <span style={{ color: riskCol }}>{org.latest_risk}</span> : undefined} />
        </div>
      </div>

      {org.attention.length > 0 && (
        <ul className="flex flex-wrap gap-2 border-t border-gray-100 px-5 py-3" aria-label={`${org.name}: why it needs attention`}>
          {org.attention.map(a => (
            <li key={a.text} className={`rounded-full px-2.5 py-1 text-[11px] font-semibold ring-1 ${ATTENTION_STYLE[a.level]}`}>{a.text}</li>
          ))}
        </ul>
      )}

      <div className="grid gap-4 border-t border-gray-100 bg-gray-50/60 px-5 py-3.5 sm:grid-cols-3" aria-label={`${org.name}: plan usage`}>
        <LimitMeter compact label="Scans this month" noun="scans" used={org.scans_this_month} limit={lim.scans} upgradeHref={org.is_current ? "/billing" : null} />
        <LimitMeter compact label="Repositories" noun="repositories" used={org.repo_count} limit={lim.repos} upgradeHref={org.is_current ? "/billing" : null} />
        <LimitMeter compact label="Members" noun="members" used={org.member_count} limit={lim.members} upgradeHref={org.is_current ? "/billing" : null} />
      </div>

      <div className="flex flex-wrap items-center gap-2 border-t border-gray-100 px-5 py-3">
        {org.is_current ? (
          <>
            <Link href="/dashboard" className="rounded-lg bg-indigo-600 px-3 py-1.5 text-xs font-bold text-white hover:bg-indigo-700">Open dashboard</Link>
            <Link href="/violations" className="rounded-lg bg-gray-100 px-3 py-1.5 text-xs font-semibold text-gray-700 hover:bg-gray-200">Open violations{org.open_violations > 0 ? ` (${org.open_violations})` : ""}</Link>
            <Link href="/settings/team" className="rounded-lg bg-gray-100 px-3 py-1.5 text-xs font-semibold text-gray-700 hover:bg-gray-200">Team</Link>
            <Link href="/billing" className="rounded-lg bg-gray-100 px-3 py-1.5 text-xs font-semibold text-gray-700 hover:bg-gray-200">Plan &amp; usage</Link>
            <Link href="/settings" className="rounded-lg bg-gray-100 px-3 py-1.5 text-xs font-semibold text-gray-700 hover:bg-gray-200">Settings</Link>
          </>
        ) : (
          <p className="text-xs text-gray-400">Overview only: a session belongs to one organisation, so this one's pages open when you sign in to it.</p>
        )}
      </div>
    </article>
  );
}

export default function OrgsPage() {
  const tz = useTimezone();
  const { profile } = useAuth();
  const [orgs, setOrgs] = useState<ApiOrg[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [health, setHealth] = useState<OrgHealth | "all">("all");
  const [sort, setSort] = useState<OrgSortKey>("attention");
  const [showNew, setShowNew] = useState(false);
  const [newOrg, setNewOrg] = useState({ slug: "", name: "", github_org: "", plan: "starter" });
  const [creating, setCreating] = useState(false);
  const [createError, setCreateError] = useState<string | null>(null);
  const isPlatformAdmin = profile?.role === "platform_admin";
  // primitives, not the profile object: a new reference on an auth refresh must not refetch
  const orgId = profile?.org_id, orgSlug = profile?.org_slug, orgName = profile?.org_name;

  const load = useCallback(async () => {
    setError(null);
    if (isSeedMode() && !orgId) {
      // Demo mode: the current organisation only
      if (orgSlug && orgName) {
        const o: ApiOrg = {
          id: orgId ?? "demo", slug: orgSlug, name: orgName, github_org: null, plan: "growth", is_current: true,
          created_at: new Date(Date.now() - 30 * 86_400_000).toISOString(), scans_30d: 171, scans_prev_30d: 140, scans_this_month: 96,
          open_violations: 12, open_critical: 2, overdue: 1, member_count: 6, repo_count: 9, latest_risk: "CRITICAL", latest_ai_pct: 0.61,
          last_scan: new Date(Date.now() - 3_600_000).toISOString(),
        };
        setOrgs([o]); setTotal(1);
      }
      setLoading(false);
      return;
    }
    try {
      const res = await authedFetch<{ orgs: ApiOrg[]; total?: number }>("/api/orgs");
      setOrgs(res.orgs ?? []); setTotal(res.total ?? (res.orgs ?? []).length);
    } catch (e) {
      setError(e instanceof Error ? e.message : "We couldn't load your organisations. Please try again.");
    } finally { setLoading(false); }
  }, [orgId, orgSlug, orgName]);

  useEffect(() => { void load(); }, [load]);

  async function createOrg() {
    if (!newOrg.slug || !newOrg.name) return;
    setCreating(true); setCreateError(null);
    try {
      await authedFetch("/api/orgs", { method: "POST", body: JSON.stringify(newOrg) });
      setShowNew(false);
      setNewOrg({ slug: "", name: "", github_org: "", plan: "starter" });
      await load();                                        // the new organisation, with its real (empty) numbers
    } catch (e) {
      setCreateError(e instanceof Error ? e.message : "We couldn't create that organisation. Please try again.");
    } finally { setCreating(false); }
  }

  const now = useMemo(() => new Date(), [orgs]);          // eslint-disable-line react-hooks/exhaustive-deps
  const views = useMemo(() => orgs.map(o => viewOf(o, now)), [orgs, now]);
  const shown = useMemo(() => sortOrgs(filterOrgs(views, search, health), sort) as OrgView[], [views, search, health, sort]);
  const totals = useMemo(() => portfolioTotals(views), [views]);
  const countOf = (h: OrgHealth | "all") => (h === "all" ? views.length : views.filter(v => v.health === h).length);

  if (loading) return <PageSkeleton loading label="organisations" />;

  const multi = views.length > 1 || isPlatformAdmin;

  return (
    <AuthGuard>
      <div className="mx-auto max-w-6xl space-y-5 pb-10">
        <div className="flex flex-wrap items-center justify-between gap-4 pt-1">
          <div>
            <h1 className="text-xl font-black tracking-tight text-gray-900">{multi ? "Organisations" : "Your organisation"}</h1>
            <p className="mt-0.5 text-sm text-gray-400">
              {multi ? `${total} organisation${total === 1 ? "" : "s"} under management` : "Its health, what needs attention, and what it uses of its plan."}
            </p>
          </div>
          {isPlatformAdmin && (
            <button onClick={() => setShowNew(v => !v)} className="rounded-xl bg-indigo-600 px-4 py-2 text-sm font-bold text-white transition-colors hover:bg-indigo-700">+ New organisation</button>
          )}
        </div>

        {error && (
          <div role="alert" className="flex items-center justify-between gap-3 rounded-xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm text-rose-700">
            <span>{error}</span>
            <button onClick={() => { setLoading(true); void load(); }} className="shrink-0 font-bold underline">Try again</button>
          </div>
        )}

        {multi && views.length > 0 && (
          <section aria-label="Across all organisations" className="grid grid-cols-2 gap-3 md:grid-cols-4">
            {([
              ["Organisations", totals.orgs, "text-gray-900", "How many organisations are listed."],
              ["Need attention", totals.needAttention, totals.needAttention > 0 ? "text-amber-600" : "text-emerald-600", "Organisations that are at risk or need a look."],
              ["Open critical", totals.openCritical, totals.openCritical > 0 ? "text-rose-600" : "text-emerald-600", "Critical violations still open, across all organisations."],
              ["Scans (30d)", totals.scans30d, "text-gray-900", "Scans run in the last 30 days, across all organisations."],
            ] as const).map(([label, value, tone, tip]) => (
              <Tip key={label} tip={tip} className="flex">
                <div tabIndex={0} className="w-full cursor-help rounded-2xl border border-gray-200 bg-white px-4 py-3 focus:outline-none focus-visible:ring-2 focus-visible:ring-indigo-300">
                  <p className={`text-2xl font-black tabular-nums ${tone}`}>{value}</p>
                  <p className="text-[11px] font-semibold text-gray-500">{label}</p>
                </div>
              </Tip>
            ))}
          </section>
        )}

        {showNew && isPlatformAdmin && (
          <div className="space-y-4 rounded-2xl border border-gray-200 bg-white p-5 shadow-sm">
            <p className="text-sm font-bold text-gray-900">Create a new organisation</p>
            <div className="grid gap-3 sm:grid-cols-2">
              <label className="block">
                <span className="mb-1 block text-xs font-semibold text-gray-600">Organisation name *</span>
                <input value={newOrg.name} onChange={e => setNewOrg(p => ({ ...p, name: e.target.value }))} placeholder="Acme Corp"
                  className="w-full rounded-xl border border-gray-200 px-3.5 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-400" />
              </label>
              <label className="block">
                <span className="mb-1 block text-xs font-semibold text-gray-600">Slug *</span>
                <input value={newOrg.slug} onChange={e => setNewOrg(p => ({ ...p, slug: e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, "-") }))} placeholder="acme-corp"
                  className="w-full rounded-xl border border-gray-200 px-3.5 py-2.5 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-indigo-400" />
              </label>
              <label className="block">
                <span className="mb-1 block text-xs font-semibold text-gray-600">GitHub organisation handle</span>
                <input value={newOrg.github_org} onChange={e => setNewOrg(p => ({ ...p, github_org: e.target.value }))} placeholder="acme-corp"
                  className="w-full rounded-xl border border-gray-200 px-3.5 py-2.5 font-mono text-sm focus:outline-none focus:ring-2 focus:ring-indigo-400" />
              </label>
              <label className="block">
                <span className="mb-1 block text-xs font-semibold text-gray-600">Plan</span>
                <select value={newOrg.plan} onChange={e => setNewOrg(p => ({ ...p, plan: e.target.value }))}
                  className="w-full rounded-xl border border-gray-200 bg-white px-3.5 py-2.5 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-400">
                  {["trial", "starter", "growth", "enterprise"].map(p => <option key={p} value={p}>{p.charAt(0).toUpperCase() + p.slice(1)}</option>)}
                </select>
              </label>
            </div>
            {createError && <p role="alert" className="text-xs font-semibold text-rose-600">{createError}</p>}
            <div className="flex items-center gap-3">
              <button onClick={createOrg} disabled={creating || !newOrg.name || !newOrg.slug}
                className="rounded-xl bg-indigo-600 px-5 py-2 text-sm font-bold text-white transition-colors hover:bg-indigo-700 disabled:opacity-60">{creating ? "Creating…" : "Create organisation"}</button>
              <button onClick={() => setShowNew(false)} className="text-sm text-gray-400 hover:text-gray-600">Cancel</button>
            </div>
          </div>
        )}

        {multi && views.length > 1 && (
          <div className="flex flex-wrap items-center gap-3">
            <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Search by name, slug or GitHub handle…" aria-label="Search organisations"
              className="w-72 max-w-full rounded-xl border border-gray-200 px-3.5 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-300" />
            <div className="flex flex-wrap items-center gap-1 rounded-lg bg-gray-100 p-0.5" role="group" aria-label="Filter by health">
              {FILTERS.filter(([h]) => h === "all" || countOf(h) > 0).map(([h, label]) => (
                <button key={h} onClick={() => setHealth(h)} aria-pressed={health === h}
                  className={`rounded-md px-2.5 py-1 text-xs font-semibold transition-all ${health === h ? "bg-white text-gray-900 shadow-sm" : "text-gray-500 hover:text-gray-700"}`}>
                  {label} <span className="tabular-nums text-gray-400">{countOf(h)}</span>
                </button>
              ))}
            </div>
            <label className="ml-auto flex items-center gap-2 text-xs text-gray-500">
              Sort
              <select value={sort} onChange={e => setSort(e.target.value as OrgSortKey)} className="rounded-lg border border-gray-200 bg-white px-2 py-1.5 text-xs text-gray-700">
                {SORTS.map(([k, label]) => <option key={k} value={k}>{label}</option>)}
              </select>
            </label>
          </div>
        )}

        <CapNotice cap="orgsListed" shown={orgs.length} total={total} noun="organisations" />

        <div className="space-y-4">
          {shown.map(org => <OrgCard key={org.id} org={org} tz={tz} />)}

          {shown.length === 0 && !error && (
            <div className="py-16 text-center text-gray-400">
              <p className="text-sm font-semibold">{views.length === 0 ? "No organisation yet" : "No organisation matches"}</p>
              {views.length === 0 ? (
                <Link href="/create-org" className="mt-3 inline-block text-sm font-semibold text-indigo-600 hover:text-indigo-800">Create your organisation →</Link>
              ) : (
                <button onClick={() => { setSearch(""); setHealth("all"); }} className="mt-3 text-sm font-semibold text-indigo-600 hover:text-indigo-800">Clear the search and filters</button>
              )}
            </div>
          )}
        </div>
      </div>
    </AuthGuard>
  );
}
