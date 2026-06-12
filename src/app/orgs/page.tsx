"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import AuthGuard from "@/components/AuthGuard";
import PageSkeleton from "@/components/PageSkeleton";
import { authedFetch, isSeedMode } from "@/lib/useRealData";
import { useAuth } from "@/lib/auth";

interface OrgSummary {
  id:              string;
  slug:            string;
  name:            string;
  github_org:      string | null;
  plan:            string;
  created_at:      string;
  scans_30d:       number;
  open_violations: number;
  member_count:    number;
  latest_risk:     string;
  latest_ai_pct:   number;
  last_scan:       string | null;
}

const RISK_COLOR: Record<string, string> = {
  CRITICAL: "#ef4444", HIGH: "#f97316", MEDIUM: "#f59e0b", LOW: "#22c55e", UNKNOWN: "#94a3b8",
};

const PLAN_BADGE: Record<string, { bg: string; text: string }> = {
  trial:      { bg:"#fef3c7", text:"#92400e" },
  starter:    { bg:"#eff6ff", text:"#1d4ed8" },
  growth:     { bg:"#f0fdf4", text:"#15803d" },
  enterprise: { bg:"#ede9fe", text:"#6d28d9" },
};

export default function OrgsPage() {
  const { profile } = useAuth();
  const [orgs,    setOrgs]    = useState<OrgSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [search,  setSearch]  = useState("");
  const [showNew, setShowNew] = useState(false);
  const [newOrg,  setNewOrg]  = useState({ slug: "", name: "", github_org: "", plan: "starter" });
  const [creating, setCreating] = useState(false);
  const [error,   setError]   = useState<string | null>(null);

  useEffect(() => {
    if (isSeedMode() && !profile?.org_id) {
      // Demo mode — show current org only
      if (profile) {
        setOrgs([{
          id:              profile.org_id,
          slug:            profile.org_slug,
          name:            profile.org_name,
          github_org:      null,
          plan:            "growth",
          created_at:      new Date(Date.now() - 30*86400_000).toISOString(),
          scans_30d:       171,
          open_violations: 12,
          member_count:    6,
          latest_risk:     "CRITICAL",
          latest_ai_pct:   0.61,
          last_scan:       new Date(Date.now() - 3600_000).toISOString(),
        }]);
      }
      setLoading(false);
      return;
    }

    authedFetch<{ orgs: OrgSummary[] }>("/api/orgs")
      .then(res => setOrgs(res.orgs ?? []))
      .catch(e => setError(String(e)))
      .finally(() => setLoading(false));
  }, [profile]);

  async function createOrg() {
    if (!newOrg.slug || !newOrg.name) return;
    setCreating(true);
    try {
      const res = await authedFetch<{ org: OrgSummary }>("/api/orgs", {
        method: "POST",
        body:   JSON.stringify(newOrg),
      });
      setOrgs(prev => [{ ...res.org, scans_30d:0, open_violations:0, member_count:1, latest_risk:"UNKNOWN", latest_ai_pct:0, last_scan:null }, ...prev]);
      setShowNew(false);
      setNewOrg({ slug:"", name:"", github_org:"", plan:"starter" });
    } catch (e) {
      setError(String(e));
    } finally {
      setCreating(false);
    }
  }

  const filtered = orgs.filter(o =>
    o.name.toLowerCase().includes(search.toLowerCase()) ||
    o.slug.toLowerCase().includes(search.toLowerCase()) ||
    (o.github_org ?? "").toLowerCase().includes(search.toLowerCase())
  );

  if (loading) return <PageSkeleton><div /></PageSkeleton>;

  return (
    <AuthGuard>
      <div className="max-w-5xl mx-auto space-y-5 pb-10">

        {/* Header */}
        <div className="flex items-center justify-between gap-4 flex-wrap pt-1">
          <div>
            <h1 className="text-xl font-black text-gray-900 tracking-tight">Organisations</h1>
            <p className="text-sm text-gray-400 mt-0.5">{orgs.length} org{orgs.length !== 1 ? "s" : ""} under management</p>
          </div>
          <div className="flex items-center gap-2">
            <input
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="Search orgs…"
              className="text-sm border border-gray-200 rounded-xl px-3.5 py-2 w-52 focus:outline-none focus:ring-2 focus:ring-indigo-300"
            />
            <button
              onClick={() => setShowNew(v => !v)}
              className="px-4 py-2 text-sm font-bold rounded-xl bg-indigo-600 text-white hover:bg-indigo-700 transition-colors"
            >
              + New org
            </button>
          </div>
        </div>

        {error && (
          <div className="bg-rose-50 border border-rose-200 rounded-xl px-4 py-3 text-sm text-rose-700">{error}</div>
        )}

        {/* New org form */}
        {showNew && (
          <div className="bg-white rounded-2xl border border-gray-200 p-5 shadow-sm space-y-4">
            <p className="text-sm font-bold text-gray-900">Create new organisation</p>
            <div className="grid grid-cols-2 gap-3">
              <label className="block">
                <span className="text-xs font-semibold text-gray-600 block mb-1">Organisation name *</span>
                <input value={newOrg.name} onChange={e => setNewOrg(p => ({ ...p, name: e.target.value }))}
                  placeholder="Acme Corp"
                  className="w-full text-sm border border-gray-200 rounded-xl px-3.5 py-2.5 focus:outline-none focus:ring-2 focus:ring-indigo-400" />
              </label>
              <label className="block">
                <span className="text-xs font-semibold text-gray-600 block mb-1">Slug *</span>
                <input value={newOrg.slug} onChange={e => setNewOrg(p => ({ ...p, slug: e.target.value.toLowerCase().replace(/[^a-z0-9-]/g, "-") }))}
                  placeholder="acme-corp"
                  className="w-full text-sm border border-gray-200 rounded-xl px-3.5 py-2.5 focus:outline-none focus:ring-2 focus:ring-indigo-400 font-mono" />
              </label>
              <label className="block">
                <span className="text-xs font-semibold text-gray-600 block mb-1">GitHub org handle</span>
                <input value={newOrg.github_org} onChange={e => setNewOrg(p => ({ ...p, github_org: e.target.value }))}
                  placeholder="acme-corp"
                  className="w-full text-sm border border-gray-200 rounded-xl px-3.5 py-2.5 focus:outline-none focus:ring-2 focus:ring-indigo-400 font-mono" />
              </label>
              <label className="block">
                <span className="text-xs font-semibold text-gray-600 block mb-1">Plan</span>
                <select value={newOrg.plan} onChange={e => setNewOrg(p => ({ ...p, plan: e.target.value }))}
                  className="w-full text-sm border border-gray-200 rounded-xl px-3.5 py-2.5 focus:outline-none focus:ring-2 focus:ring-indigo-400 bg-white">
                  {["trial","starter","growth","enterprise"].map(p => (
                    <option key={p} value={p}>{p.charAt(0).toUpperCase() + p.slice(1)}</option>
                  ))}
                </select>
              </label>
            </div>
            <div className="flex items-center gap-3">
              <button onClick={createOrg} disabled={creating || !newOrg.name || !newOrg.slug}
                className="px-5 py-2 text-sm font-bold rounded-xl bg-indigo-600 text-white hover:bg-indigo-700 transition-colors disabled:opacity-60">
                {creating ? "Creating…" : "Create organisation"}
              </button>
              <button onClick={() => setShowNew(false)} className="text-sm text-gray-400 hover:text-gray-600">Cancel</button>
            </div>
          </div>
        )}

        {/* Org grid */}
        <div className="grid grid-cols-1 gap-4">
          {filtered.map(org => {
            const plan    = PLAN_BADGE[org.plan] ?? PLAN_BADGE.starter;
            const riskCol = RISK_COLOR[org.latest_risk] ?? "#94a3b8";
            const lastScan = org.last_scan
              ? new Date(org.last_scan).toLocaleDateString("en-GB", { day:"numeric", month:"short" })
              : "Never";

            return (
              <div key={org.id} className="bg-white rounded-2xl border border-gray-200 shadow-sm overflow-hidden hover:shadow-md transition-shadow">
                <div className="px-6 py-4 flex items-start gap-4">
                  {/* Org avatar */}
                  <div className="w-12 h-12 rounded-2xl flex items-center justify-center text-white text-lg font-black shrink-0"
                    style={{ background: `linear-gradient(135deg, ${riskCol}33, ${riskCol}66)`, color: riskCol, border: `2px solid ${riskCol}33` }}>
                    {org.name.slice(0, 1).toUpperCase()}
                  </div>

                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <h3 className="text-base font-black text-gray-900">{org.name}</h3>
                      <span className="text-[10px] font-bold px-2 py-0.5 rounded-full"
                        style={{ background: plan.bg, color: plan.text }}>
                        {org.plan}
                      </span>
                      <span className="text-[10px] font-bold px-2 py-0.5 rounded-full"
                        style={{ background: `${riskCol}15`, color: riskCol, border: `1px solid ${riskCol}30` }}>
                        {org.latest_risk}
                      </span>
                    </div>
                    <p className="text-xs text-gray-400 mt-0.5">
                      {org.github_org ? `github.com/${org.github_org}` : org.slug}
                    </p>
                  </div>

                  {/* Metrics */}
                  <div className="flex items-center gap-6 shrink-0">
                    <div className="text-center">
                      <p className="text-lg font-black text-gray-900">{org.scans_30d}</p>
                      <p className="text-[10px] text-gray-400">Scans (30d)</p>
                    </div>
                    <div className="text-center">
                      <p className="text-lg font-black" style={{ color: org.open_violations > 0 ? "#ef4444" : "#22c55e" }}>
                        {org.open_violations}
                      </p>
                      <p className="text-[10px] text-gray-400">Open violations</p>
                    </div>
                    <div className="text-center">
                      <p className="text-lg font-black text-gray-900">{org.member_count}</p>
                      <p className="text-[10px] text-gray-400">Members</p>
                    </div>
                    <div className="text-center">
                      <p className="text-sm font-bold text-gray-600">{(org.latest_ai_pct * 100).toFixed(0)}%</p>
                      <p className="text-[10px] text-gray-400">Avg AI</p>
                    </div>
                    <div className="text-center hidden sm:block">
                      <p className="text-sm font-bold text-gray-600">{lastScan}</p>
                      <p className="text-[10px] text-gray-400">Last scan</p>
                    </div>
                  </div>

                  <Link
                    href={`/dashboard?org=${org.slug}`}
                    className="shrink-0 px-4 py-2 text-sm font-bold text-indigo-600 bg-indigo-50 hover:bg-indigo-100 rounded-xl transition-colors border border-indigo-100"
                  >
                    View →
                  </Link>
                </div>

                {/* Progress bar — open violations severity */}
                <div className="h-1.5 w-full" style={{ background: "#f1f5f9" }}>
                  <div
                    className="h-full transition-all"
                    style={{
                      width:  `${Math.min(100, (org.open_violations / Math.max(1, org.scans_30d * 3)) * 100)}%`,
                      background: riskCol,
                    }}
                  />
                </div>
              </div>
            );
          })}

          {filtered.length === 0 && (
            <div className="text-center py-16 text-gray-400">
              <p className="text-sm font-semibold">{search ? "No orgs match your search" : "No organisations yet"}</p>
              {!search && (
                <button onClick={() => setShowNew(true)} className="mt-3 text-sm text-indigo-600 hover:text-indigo-800 font-semibold">
                  Create the first organisation →
                </button>
              )}
            </div>
          )}
        </div>

      </div>
    </AuthGuard>
  );
}
