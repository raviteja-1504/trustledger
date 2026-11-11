"use client";

import { useEffect, useState, Suspense } from "react";
import AuthGuard from "@/components/AuthGuard";
import { formatDateOnly, useTimezone, getSavedTimezone } from "@/lib/timezone";
import PageSkeleton from "@/components/PageSkeleton";
import { authedFetch, isSeedMode } from "@/lib/useRealData";
import { useAuth } from "@/lib/auth";
import { contactEmail } from "@/lib/contacts";
import { LimitMeter } from "@/components/Limits";
import { RATE_CAPS, rateText } from "@/lib/limits";

interface UsageData {
  org:    { name: string; plan: string; member_since: string };
  limits: { scans: number; attestations: number; repos: number; members: number; reports: number };
  usage:  { scans_this_month: number; attestations_this_month: number; repos_active: number; members: number; reports_this_month: number; scans_all_time: number; attestations_all_time: number };
  period: { start: string; end: string };
}

/** What the free trial includes, in words, from the limits the server enforces. */
const n = (v: number, one: string, many: string) => v < 0 ? `Unlimited ${many}` : `${v.toLocaleString("en-US")} ${v === 1 ? one : many}`;
const featuresOf = (l: UsageData["limits"]) => [
  `${n(l.scans, "scan", "scans")} a month`, n(l.repos, "repository", "repositories"), n(l.members, "team member", "team members"),
  "Viewing and attesting scans is never limited",
];

function BillingContent() {
  const { profile } = useAuth();
  const [data,    setData]    = useState<UsageData | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (isSeedMode() && !profile?.org_id) {
      // Demo data
      setData({
        org:    { name: profile?.org_name ?? "Org", plan: "free", member_since: "2026-01-15T00:00:00Z" },
        limits: { scans: 3, attestations: -1, repos: 1, members: 2, reports: 1 },
        usage:  { scans_this_month: 2, attestations_this_month: 14, repos_active: 1, members: 1, reports_this_month: 0, scans_all_time: 2, attestations_all_time: 14 },
        period: { start: new Date(new Date().getFullYear(), new Date().getMonth(), 1).toISOString(), end: new Date().toISOString() },
      });
      setLoading(false);
      return;
    }
    authedFetch<UsageData>("/api/billing")
      .then(d => setData(d))
      .catch(() => setLoading(false))
      .finally(() => setLoading(false));
  }, [profile]);

  if (loading) return <PageSkeleton loading label="billing" />;
  if (!data)   return <AuthGuard><p className="text-sm text-gray-400 p-8">Could not load billing data.</p></AuthGuard>;

  const features  = featuresOf(data.limits);
  const since     = formatDateOnly(new Date(data.org.member_since), getSavedTimezone());
  const period    = formatDateOnly(new Date(data.period.start), getSavedTimezone());

  return (
    <AuthGuard>
      <div className="max-w-4xl mx-auto space-y-6 pb-10">

        {/* Header */}
        <div className="flex items-start justify-between gap-4 flex-wrap pt-1">
          <div>
            <h1 className="text-xl font-black text-gray-900">Usage</h1>
            <p className="text-sm text-gray-400 mt-0.5">{data.org.name} · Member since {since}</p>
          </div>
        </div>

        {/* Current plan: the free trial is the only plan */}
        <div className="bg-white rounded-2xl border shadow-sm overflow-hidden border-amber-200">
          <div className="p-6 flex items-start justify-between gap-4 flex-wrap" style={{ background: "linear-gradient(135deg, #fef3c7, white)" }}>
            <div>
              <span className="text-[10px] font-black uppercase tracking-widest text-amber-800">Current plan</span>
              <h2 className="text-2xl font-black text-gray-900">Free trial</h2>
              <p className="text-sm text-gray-500 mt-1">No payment needed.</p>
            </div>
            <ul className="space-y-1">
              {features.map(f => (
                <li key={f} className="flex items-center gap-2 text-xs text-gray-600">
                  <span className="text-emerald-500 font-bold">✓</span> {f}
                </li>
              ))}
            </ul>
          </div>
        </div>

        {/* Usage this month */}
        <div className="bg-white rounded-2xl border border-gray-200 p-6 shadow-sm space-y-5">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-black text-gray-900">Usage — {period}</h3>
              <p className="text-xs text-gray-400 mt-0.5">Resets on the 1st of each month</p>
            </div>
            <div className="grid grid-cols-2 gap-3 text-center">
              <div>
                <p className="text-lg font-black text-indigo-600">{data.usage.scans_all_time}</p>
                <p className="text-[9px] text-gray-400 uppercase tracking-wider">Total scans</p>
              </div>
              <div>
                <p className="text-lg font-black text-emerald-600">{data.usage.attestations_all_time}</p>
                <p className="text-[9px] text-gray-400 uppercase tracking-wider">Total attestations</p>
              </div>
            </div>
          </div>

          <div className="space-y-4">
            <LimitMeter label="Scans this month" noun="scans" used={data.usage.scans_this_month} limit={data.limits.scans} />
            <LimitMeter label="Attestations this month" noun="attestations" used={data.usage.attestations_this_month} limit={data.limits.attestations} />
            <LimitMeter label="Active repositories" noun="repositories" used={data.usage.repos_active} limit={data.limits.repos} />
            <LimitMeter label="Team members" noun="members" used={data.usage.members} limit={data.limits.members} />
            <LimitMeter label="Reports generated" noun="reports" used={data.usage.reports_this_month} limit={data.limits.reports} />
          </div>
          <div className="mt-5 border-t border-gray-100 pt-4" aria-label="Rate limits">
            <p className="text-[10px] font-black uppercase tracking-widest text-gray-400">Rate limits (all plans)</p>
            <ul className="mt-1.5 space-y-0.5 text-xs text-gray-500">
              {(Object.keys(RATE_CAPS) as Array<keyof typeof RATE_CAPS>).map(k => <li key={k}>{rateText(k)}</li>)}
            </ul>
            <p className="mt-1.5 text-[11px] text-gray-400">Past a rate limit the request is refused for a moment and can be retried; nothing is lost.</p>
          </div>
        </div>

        <div className="bg-white rounded-2xl border border-gray-200 p-6 shadow-sm">
          <h3 className="text-sm font-black text-gray-900">Need more?</h3>
          <p className="text-sm text-gray-500 mt-1">
            The free trial is the only plan for now. To scan more, or add repositories or teammates, email{" "}
            <a className="font-semibold text-indigo-600 hover:text-indigo-800" href={`mailto:${contactEmail("sales")}?subject=More%20scans`}>{contactEmail("sales")}</a>.
          </p>
        </div>

      </div>
    </AuthGuard>
  );
}

export default function BillingPage() {
  const tz = useTimezone();
  return (
    <Suspense fallback={<PageSkeleton loading label="billing" />}>
      <BillingContent />
    </Suspense>
  );
}
