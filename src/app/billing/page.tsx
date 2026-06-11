"use client";

import { useEffect, useState, Suspense } from "react";
import { useSearchParams } from "next/navigation";
import AuthGuard from "@/components/AuthGuard";
import PageSkeleton from "@/components/PageSkeleton";
import { authedFetch, isSeedMode } from "@/lib/useRealData";
import { useAuth } from "@/lib/auth";
import { useToastHelpers } from "@/lib/toast";

interface UsageData {
  org:    { name: string; plan: string; member_since: string };
  limits: { scans: number; attestations: number; repos: number; members: number; reports: number; price: number };
  usage:  { scans_this_month: number; attestations_this_month: number; repos_active: number; members: number; reports_this_month: number; scans_all_time: number; attestations_all_time: number };
  period: { start: string; end: string };
}

const PLAN_FEATURES: Record<string, string[]> = {
  trial:      ["100 scans / month","3 repositories","3 team members","Community support"],
  starter:    ["1,000 scans / month","10 repositories","5 team members","Email support","PDF reports"],
  growth:     ["10,000 scans / month","50 repositories","20 team members","Priority support","Compliance reports","JIRA / Linear integration"],
  enterprise: ["Unlimited scans","Unlimited repos","Unlimited members","Dedicated support","Custom SLA","SSO / SAML","Self-hosted option","Custom contracts"],
};

const PLAN_PRICES: Record<string, { monthly: number; annual: number }> = {
  trial:      { monthly:    0, annual:    0 },
  starter:    { monthly:  299, annual:  249 },
  growth:     { monthly:  999, annual:  799 },
  enterprise: { monthly:    0, annual:    0 }, // custom
};

const PLAN_COLOR: Record<string, { bg: string; text: string; border: string }> = {
  trial:      { bg:"#fef3c7", text:"#92400e", border:"#fde68a" },
  starter:    { bg:"#eff6ff", text:"#1d4ed8", border:"#bfdbfe" },
  growth:     { bg:"#f0fdf4", text:"#15803d", border:"#bbf7d0" },
  enterprise: { bg:"#ede9fe", text:"#6d28d9", border:"#ddd6fe" },
};

function UsageBar({ used, limit, label }: { used: number; limit: number; label: string }) {
  const pct     = limit < 0 ? 0 : Math.min(100, (used / limit) * 100);
  const isLimit = limit < 0;
  const danger  = pct >= 90;
  const warning = pct >= 70 && !danger;

  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between text-xs">
        <span className="font-semibold text-gray-700">{label}</span>
        <span className={`font-mono font-bold ${danger ? "text-rose-600" : warning ? "text-amber-600" : "text-gray-600"}`}>
          {used.toLocaleString()} / {isLimit ? "∞" : limit.toLocaleString()}
        </span>
      </div>
      <div className="h-2 bg-gray-100 rounded-full overflow-hidden">
        <div
          className="h-full rounded-full transition-all"
          style={{
            width:      isLimit ? "0%" : `${pct}%`,
            background: danger ? "#ef4444" : warning ? "#f59e0b" : "#6366f1",
          }}
        />
      </div>
      {danger && !isLimit && (
        <p className="text-[10px] text-rose-600 font-semibold">Approaching limit — consider upgrading</p>
      )}
    </div>
  );
}

function BillingContent() {
  const { profile } = useAuth();
  const { warning, error: toastError } = useToastHelpers();
  const [data,    setData]    = useState<UsageData | null>(null);
  const [loading, setLoading] = useState(true);
  const [billing, setBilling] = useState<"monthly"|"annual">("monthly");

  useEffect(() => {
    if (isSeedMode()) {
      // Demo data
      setData({
        org:    { name: profile?.org_name ?? "Org", plan:"growth", member_since:"2026-01-15T00:00:00Z" },
        limits: { scans:10000, attestations:50000, repos:50, members:20, reports:60, price:999 },
        usage:  { scans_this_month:1247, attestations_this_month:4382, repos_active:7, members:6, reports_this_month:3, scans_all_time:8471, attestations_all_time:31204 },
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

  const searchParams = useSearchParams();
  const upgraded  = searchParams?.get("upgraded") === "1";
  const cancelled  = searchParams?.get("cancelled") === "1";

  if (loading) return <PageSkeleton><div /></PageSkeleton>;
  if (!data)   return <AuthGuard><p className="text-sm text-gray-400 p-8">Could not load billing data.</p></AuthGuard>;

  const plan      = data.org.plan;
  const planColor = PLAN_COLOR[plan] ?? PLAN_COLOR.trial;
  const features  = PLAN_FEATURES[plan] ?? [];
  const nextPlans = ["trial","starter","growth"].filter(p => p !== plan);
  const since     = new Date(data.org.member_since).toLocaleDateString("en-GB", { month:"long", year:"numeric" });
  const period    = new Date(data.period.start).toLocaleDateString("en-GB", { month:"long", year:"numeric" });

  async function startCheckout(planKey: string) {
    if (isSeedMode()) { warning("Demo mode", "Connect Stripe in production: set STRIPE_SECRET_KEY and STRIPE_PRICE_* env vars."); return; }
    try {
      const res = await authedFetch<{ url: string }>("/api/stripe", {
        method: "POST",
        body:   JSON.stringify({ plan: planKey, billing }),
      });
      if (res.url) window.location.href = res.url;
    } catch { toastError("Stripe not configured", "Set STRIPE_SECRET_KEY in .env.local."); }
  }

  async function openPortal() {
    if (isSeedMode()) { warning("Demo mode", "Connect Stripe in production."); return; }
    try {
      const res = await authedFetch<{ url: string }>("/api/stripe?portal=1", { method: "POST" });
      if (res.url) window.location.href = res.url;
    } catch { toastError("Stripe not configured", "Configure STRIPE_SECRET_KEY to enable billing portal."); }
  }

  return (
    <AuthGuard>
      <div className="max-w-4xl mx-auto space-y-6 pb-10">

        {/* Header */}
        <div className="flex items-start justify-between gap-4 flex-wrap pt-1">
          <div>
            <h1 className="text-xl font-black text-gray-900">Billing & Usage</h1>
            <p className="text-sm text-gray-400 mt-0.5">{data.org.name} · Member since {since}</p>
          </div>
          {plan !== "trial" && plan !== "enterprise" && (
            <button onClick={openPortal}
              className="px-4 py-2 text-sm font-semibold rounded-xl border border-gray-200 hover:border-gray-300 text-gray-600 transition-colors">
              Manage subscription →
            </button>
          )}
        </div>

        {/* Upgrade success */}
        {upgraded && (
          <div className="bg-emerald-50 border border-emerald-200 rounded-2xl px-5 py-4 flex items-center gap-3">
            <span className="text-2xl">🎉</span>
            <div>
              <p className="text-sm font-black text-emerald-800">Subscription activated!</p>
              <p className="text-xs text-emerald-600 mt-0.5">Your 14-day free trial has started. You'll be billed at the end of the trial period.</p>
            </div>
          </div>
        )}
        {cancelled && (
          <div className="bg-amber-50 border border-amber-200 rounded-2xl px-5 py-4 text-sm text-amber-800">
            Checkout was cancelled — your plan was not changed.
          </div>
        )}

        {/* Current plan */}
        <div className="bg-white rounded-2xl border shadow-sm overflow-hidden"
          style={{ borderColor: planColor.border }}>
          <div className="p-6 flex items-start justify-between gap-4 flex-wrap"
            style={{ background: `linear-gradient(135deg, ${planColor.bg}, white)` }}>
            <div>
              <div className="flex items-center gap-2 mb-1">
                <span className="text-[10px] font-black uppercase tracking-widest" style={{ color: planColor.text }}>Current plan</span>
              </div>
              <h2 className="text-2xl font-black text-gray-900 capitalize">{plan}</h2>
              {plan !== "enterprise" && plan !== "trial" && (
                <p className="text-sm text-gray-500 mt-1">
                  ${PLAN_PRICES[plan]?.monthly ?? 0}/month · ${PLAN_PRICES[plan]?.annual ?? 0}/month billed annually
                </p>
              )}
              {plan === "enterprise" && <p className="text-sm text-gray-500 mt-1">Custom pricing · contact sales</p>}
              {plan === "trial" && <p className="text-sm text-gray-500 mt-1">Free tier · limited to 100 scans/month</p>}
            </div>
            <div>
              <ul className="space-y-1">
                {features.map(f => (
                  <li key={f} className="flex items-center gap-2 text-xs text-gray-600">
                    <span className="text-emerald-500 font-bold">✓</span> {f}
                  </li>
                ))}
              </ul>
            </div>
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
                <p className="text-lg font-black text-indigo-600">{data.usage.scans_all_time.toLocaleString()}</p>
                <p className="text-[9px] text-gray-400 uppercase tracking-wider">Total scans</p>
              </div>
              <div>
                <p className="text-lg font-black text-emerald-600">{data.usage.attestations_all_time.toLocaleString()}</p>
                <p className="text-[9px] text-gray-400 uppercase tracking-wider">Total attestations</p>
              </div>
            </div>
          </div>

          <div className="space-y-4">
            <UsageBar used={data.usage.scans_this_month}        limit={data.limits.scans}        label="Scans this month" />
            <UsageBar used={data.usage.attestations_this_month} limit={data.limits.attestations}  label="Attestations this month" />
            <UsageBar used={data.usage.repos_active}            limit={data.limits.repos}         label="Active repositories" />
            <UsageBar used={data.usage.members}                 limit={data.limits.members}       label="Team members" />
            <UsageBar used={data.usage.reports_this_month}      limit={data.limits.reports}       label="Reports generated" />
          </div>
        </div>

        {/* Upgrade — show for non-enterprise plans */}
        {plan !== "enterprise" && (
          <div className="bg-white rounded-2xl border border-gray-200 p-6 shadow-sm space-y-5">
            <div className="flex items-center justify-between gap-4">
              <h3 className="text-sm font-black text-gray-900">Upgrade your plan</h3>
              <div className="flex items-center gap-1 bg-gray-100 p-0.5 rounded-xl">
                {(["monthly","annual"] as const).map(b => (
                  <button key={b} onClick={() => setBilling(b)}
                    className={`px-3 py-1 text-xs font-semibold rounded-lg transition-all ${billing===b?"bg-white text-gray-900 shadow-sm":"text-gray-500"}`}>
                    {b === "monthly" ? "Monthly" : "Annual (save ~20%)"}
                  </button>
                ))}
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              {nextPlans.map(p => {
                const pc      = PLAN_COLOR[p] ?? PLAN_COLOR.starter;
                const prices  = PLAN_PRICES[p] ?? { monthly:0, annual:0 };
                const isCurrent = p === plan;
                const isPremium = p === "enterprise";
                const price   = billing === "annual" ? prices.annual : prices.monthly;

                return (
                  <div key={p} className={`rounded-2xl border-2 p-5 transition-all ${
                    isCurrent ? "border-indigo-500 bg-indigo-50" : "border-gray-200 hover:border-indigo-300"
                  }`}>
                    <p className="text-sm font-black text-gray-900 capitalize mb-1">{p}</p>
                    {isPremium ? (
                      <p className="text-xl font-black text-gray-900">Custom</p>
                    ) : (
                      <p className="text-xl font-black text-gray-900">
                        ${price}<span className="text-sm font-normal text-gray-400">/mo</span>
                      </p>
                    )}
                    <ul className="mt-3 space-y-1">
                      {(PLAN_FEATURES[p] ?? []).slice(0, 4).map(f => (
                        <li key={f} className="text-[11px] text-gray-600 flex items-center gap-1.5">
                          <span style={{ color: pc.text }}>✓</span> {f}
                        </li>
                      ))}
                    </ul>
                    <button
                      onClick={() => {
                        if (isPremium) window.open("mailto:sales@trustledger.dev?subject=Enterprise%20enquiry","_blank");
                        else if (!isCurrent) startCheckout(p);
                      }}
                      className="mt-4 w-full py-2 rounded-xl text-xs font-bold transition-all"
                      style={{
                        background: isCurrent ? pc.bg : "#6366f1",
                        color:      isCurrent ? pc.text : "white",
                      }}>
                      {isCurrent ? "Current plan" : isPremium ? "Contact sales" : `Upgrade to ${p}`}
                    </button>
                  </div>
                );
              })}
            </div>
            <p className="text-xs text-gray-400 text-center">All plans include a 14-day free trial. No credit card required.</p>
          </div>
        )}

      </div>
    </AuthGuard>
  );
}

export default function BillingPage() {
  return (
    <Suspense fallback={<PageSkeleton><div /></PageSkeleton>}>
      <BillingContent />
    </Suspense>
  );
}
