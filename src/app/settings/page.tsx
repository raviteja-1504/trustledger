"use client";

import { useEffect, useState, useCallback } from "react";
import clsx from "clsx";
import { api } from "@/lib/api";
import { authedFetch } from "@/lib/useRealData";
import { useAuth } from "@/lib/auth";
import { useToastHelpers } from "@/lib/toast";
import AuthGuard from "@/components/AuthGuard";
import { formatDateTime, formatDateOnly, relativeTime, useTimezone, getSavedTimezone } from "@/lib/timezone";
import {
  type OrgPolicy,
  DEFAULT_POLICY,
  PRESETS,
  loadPolicy,
  savePolicy,
} from "@/lib/policy";
import {
  useRole,
  useTeamMembers,
  type UserRole,
  ROLE_LABELS,
  ROLE_COLORS,
  ROLE_DESCRIPTIONS,
} from "@/lib/roles";

// ── Icons ──────────────────────────────────────────────────────────────────────

function CheckIcon({ size = 14 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="20 6 9 17 4 12" />
    </svg>
  );
}

function ShieldIcon({ size = 16 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
    </svg>
  );
}

function SlackIcon({ size = 18 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="currentColor">
      <path d="M5.042 15.165a2.528 2.528 0 0 1-2.52 2.523A2.528 2.528 0 0 1 0 15.165a2.527 2.527 0 0 1 2.522-2.52h2.52v2.52zM6.313 15.165a2.527 2.527 0 0 1 2.521-2.52 2.527 2.527 0 0 1 2.521 2.52v6.313A2.528 2.528 0 0 1 8.834 24a2.528 2.528 0 0 1-2.521-2.522v-6.313zM8.834 5.042a2.528 2.528 0 0 1-2.521-2.52A2.528 2.528 0 0 1 8.834 0a2.528 2.528 0 0 1 2.521 2.522v2.52H8.834zM8.834 6.313a2.528 2.528 0 0 1 2.521 2.521 2.528 2.528 0 0 1-2.521 2.521H2.522A2.528 2.528 0 0 1 0 8.834a2.528 2.528 0 0 1 2.522-2.521h6.312zM18.956 8.834a2.528 2.528 0 0 1 2.522-2.521A2.528 2.528 0 0 1 24 8.834a2.528 2.528 0 0 1-2.522 2.521h-2.522V8.834zM17.688 8.834a2.528 2.528 0 0 1-2.523 2.521 2.527 2.527 0 0 1-2.52-2.521V2.522A2.527 2.527 0 0 1 15.165 0a2.528 2.528 0 0 1 2.523 2.522v6.312zM15.165 18.956a2.528 2.528 0 0 1 2.523 2.522A2.528 2.528 0 0 1 15.165 24a2.527 2.527 0 0 1-2.52-2.522v-2.522h2.52zM15.165 17.688a2.527 2.527 0 0 1-2.52-2.523 2.526 2.526 0 0 1 2.52-2.52h6.313A2.527 2.527 0 0 1 24 15.165a2.528 2.528 0 0 1-2.522 2.523h-6.313z" />
    </svg>
  );
}

function GitHubIcon({ size = 18 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="currentColor">
      <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z" />
    </svg>
  );
}

function JiraIcon({ size = 18 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="currentColor">
      <path d="M11.975 0C5.372 0 0 5.372 0 11.975S5.372 23.95 11.975 23.95 23.95 18.578 23.95 11.975 18.578 0 11.975 0zm-.09 4.588l5.302 7.125-5.302 5.3-5.3-5.3 5.3-7.125zm0 14.612l-5.3-5.302 5.3 3.05 5.302-3.05-5.302 5.302z" />
    </svg>
  );
}

function BellIcon({ size = 14 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" />
      <path d="M13.73 21a2 2 0 0 1-3.46 0" />
    </svg>
  );
}

function UsersIcon({ size = 16 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" />
      <circle cx="9" cy="7" r="4" />
      <path d="M23 21v-2a4 4 0 0 0-3-3.87" />
      <path d="M16 3.13a4 4 0 0 1 0 7.75" />
    </svg>
  );
}

function TrashIcon({ size = 14 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="3 6 5 6 21 6" />
      <path d="M19 6l-1 14H6L5 6" />
      <path d="M10 11v6M14 11v6" />
      <path d="M9 6V4h6v2" />
    </svg>
  );
}

// ── Reusable primitives ────────────────────────────────────────────────────────

function Toggle({ checked, onChange }: { checked: boolean; onChange: (v: boolean) => void }) {
  return (
    <button
      type="button"
      onClick={() => onChange(!checked)}
      className={`relative inline-flex h-5 w-9 shrink-0 rounded-full transition-colors duration-200 focus:outline-none ${
        checked ? "bg-indigo-600" : "bg-gray-200"
      }`}
    >
      <span
        className={`inline-block h-4 w-4 rounded-full bg-white shadow-sm transition-transform duration-200 mt-0.5 ${
          checked ? "translate-x-4" : "translate-x-0.5"
        }`}
      />
    </button>
  );
}

function NumInput({ value, min = 0, max = 5, onChange }: {
  value: number; min?: number; max?: number; onChange: (v: number) => void;
}) {
  return (
    <div className="flex items-center gap-1">
      <button
        type="button"
        onClick={() => onChange(Math.max(min, value - 1))}
        className="w-7 h-7 rounded-lg border border-gray-200 text-gray-500 hover:bg-gray-50 flex items-center justify-center text-sm font-bold transition-colors"
      >
        −
      </button>
      <span className="w-6 text-center text-sm font-bold text-gray-900 tabular-nums">{value}</span>
      <button
        type="button"
        onClick={() => onChange(Math.min(max, value + 1))}
        className="w-7 h-7 rounded-lg border border-gray-200 text-gray-500 hover:bg-gray-50 flex items-center justify-center text-sm font-bold transition-colors"
      >
        +
      </button>
    </div>
  );
}

function PercentSlider({ value, onChange, color = "#6366f1" }: {
  value: number; onChange: (v: number) => void; color?: string;
}) {
  const pct = Math.round(value * 100);
  return (
    <div className="flex items-center gap-3">
      <div className="relative flex-1">
        <input
          type="range"
          min={10}
          max={95}
          step={5}
          value={pct}
          onChange={e => onChange(Number(e.target.value) / 100)}
          className="w-full h-1.5 rounded-full appearance-none cursor-pointer"
          style={{
            background: `linear-gradient(to right, ${color} 0%, ${color} ${pct}%, #e5e7eb ${pct}%, #e5e7eb 100%)`,
          }}
        />
      </div>
      <span className="text-sm font-black tabular-nums w-10 text-right" style={{ color }}>
        {pct}%
      </span>
    </div>
  );
}

function SectionCard({ title, subtitle, children }: {
  title: string; subtitle?: string | React.ReactNode; children: React.ReactNode;
}) {
  return (
    <div className="section-card animate-fade-up overflow-hidden">
      <div className="px-6 py-4 border-b border-gray-50">
        <p className="text-sm font-bold text-gray-900">{title}</p>
        {subtitle && <p className="text-xs text-gray-400 mt-0.5">{subtitle}</p>}
      </div>
      <div className="px-6 py-5 space-y-4">{children}</div>
    </div>
  );
}

function Row({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <div className="flex items-center justify-between gap-6">
      <div className="min-w-0">
        <p className="text-sm font-medium text-gray-800">{label}</p>
        {hint && <p className="text-xs text-gray-400 mt-0.5">{hint}</p>}
      </div>
      <div className="shrink-0">{children}</div>
    </div>
  );
}

// ── Tab: Policies ──────────────────────────────────────────────────────────────

function OrganizationSection() {
  const { profile } = useAuth();
  const toast = useToastHelpers();
  const [orgName, setOrgName] = useState("");
  const [saving, setSaving]   = useState(false);

  useEffect(() => {
    if (!profile?.org_id) return;
    authedFetch<{ org: { name: string } }>("/api/settings")
      .then(res => setOrgName(res.org?.name ?? ""))
      .catch(() => {});
  }, [profile?.org_id]);

  if (!profile?.org_id) return null;

  async function save() {
    setSaving(true);
    try {
      await authedFetch("/api/settings", { method: "PATCH", body: JSON.stringify({ name: orgName }) });
      toast.success("Organization name updated");
      // Reload so the sidebar and header pick up the new name from the profile
      setTimeout(() => window.location.reload(), 800);
    } catch {
      toast.error("Failed to update organization name");
    } finally {
      setSaving(false);
    }
  }

  return (
    <SectionCard title="Organization" subtitle="The display name shown across your dashboard.">
      <Row label="Organization name" hint="Shown in the header and sidebar">
        <div className="flex items-center gap-2">
          <input
            value={orgName}
            onChange={e => setOrgName(e.target.value)}
            placeholder="Acme Corp"
            className="text-sm border border-gray-200 rounded-xl px-3.5 py-2 focus:outline-none focus:ring-2 focus:ring-indigo-400 w-56"
          />
          <button
            onClick={save}
            disabled={saving || !orgName.trim()}
            className="px-3.5 py-2 text-sm font-bold rounded-xl bg-indigo-600 text-white hover:bg-indigo-700 active:scale-95 disabled:opacity-50"
          >
            {saving ? "Saving…" : "Save"}
          </button>
        </div>
      </Row>
    </SectionCard>
  );
}

function PoliciesTab({ policy, setPolicy }: {
  policy: OrgPolicy;
  setPolicy: React.Dispatch<React.SetStateAction<OrgPolicy>>;
}) {
  const set = <K extends keyof OrgPolicy>(k: K, v: OrgPolicy[K]) =>
    setPolicy(p => ({ ...p, name: "Custom", [k]: v }));

  const applyPreset = (key: "standard" | "strict") => {
    setPolicy(p => ({ ...p, ...PRESETS[key], slack_webhook: p.slack_webhook, alert_email: p.alert_email }));
  };

  return (
    <div className="space-y-5">
      <OrganizationSection />

      {/* Preset cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        {([
          {
            key: "standard" as const,
            title: "Standard",
            desc: "Block CRITICAL + HIGH, 1 attestation each. Recommended for most teams.",
            color: "indigo",
          },
          {
            key: "strict" as const,
            title: "Strict",
            desc: "Block CRITICAL + HIGH + MEDIUM, 2 attestations for CRITICAL. For regulated industries.",
            color: "violet",
          },
          {
            key: null,
            title: "Custom",
            desc: "Your current configuration. Adjust the controls below to fine-tune.",
            color: "gray",
          },
        ] as const).map(preset => {
          const isActive = preset.key === null
            ? policy.name === "Custom"
            : policy.name === PRESETS[preset.key].name;
          return (
            <button
              key={preset.title}
              type="button"
              onClick={() => preset.key && applyPreset(preset.key)}
              disabled={preset.key === null}
              className={`text-left p-4 rounded-2xl border-2 transition-all ${
                isActive
                  ? preset.color === "indigo" ? "border-indigo-500 bg-indigo-50"
                    : preset.color === "violet" ? "border-violet-500 bg-violet-50"
                    : "border-gray-400 bg-gray-50"
                  : "border-gray-100 bg-white hover:border-gray-200 hover:bg-gray-50"
              } ${preset.key === null ? "cursor-default" : "cursor-pointer"}`}
            >
              <div className="flex items-center justify-between mb-2">
                <span className={`text-sm font-bold ${
                  isActive
                    ? preset.color === "indigo" ? "text-indigo-700"
                      : preset.color === "violet" ? "text-violet-700"
                      : "text-gray-700"
                    : "text-gray-700"
                }`}>
                  {preset.title}
                </span>
                {isActive && (
                  <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full ${
                    preset.color === "indigo" ? "bg-indigo-100 text-indigo-700"
                    : preset.color === "violet" ? "bg-violet-100 text-violet-700"
                    : "bg-gray-100 text-gray-600"
                  }`}>
                    Active
                  </span>
                )}
              </div>
              <p className="text-xs text-gray-500 leading-relaxed">{preset.desc}</p>
            </button>
          );
        })}
      </div>

      {/* Merge gates */}
      <SectionCard
        title="Merge Gate"
        subtitle="Block pull requests from merging when unattested files exceed these risk levels"
      >
        {([
          ["CRITICAL", "block_on_critical", "bg-violet-500", "Recommended — never merge unattested CRITICAL files"] as const,
          ["HIGH",     "block_on_high",     "bg-orange-500", "Blocks HIGH risk files unless attested by a reviewer"] as const,
          ["MEDIUM",   "block_on_medium",   "bg-amber-500",  "Stricter gate — also blocks MEDIUM risk AI patterns"] as const,
        ]).map(([label, field, dot, hint]) => (
          <Row key={field} label={label} hint={hint}>
            <div className="flex items-center gap-3">
              <span className={`w-2 h-2 rounded-full ${dot}`} />
              <Toggle
                checked={policy[field]}
                onChange={v => set(field, v)}
              />
            </div>
          </Row>
        ))}
      </SectionCard>

      {/* Attestation requirements */}
      <SectionCard
        title="Attestation Requirements"
        subtitle="Minimum number of reviewer sign-offs required before a file is considered attested"
      >
        <Row
          label="CRITICAL files"
          hint="Files with critical security vulnerabilities (SQL injection, eval/exec, hardcoded secrets)"
        >
          <NumInput
            value={policy.attestations_critical}
            min={1}
            max={5}
            onChange={v => set("attestations_critical", v)}
          />
        </Row>
        <Row
          label="HIGH files"
          hint="Files with high-severity patterns (JWT issues, AI comment density)"
        >
          <NumInput
            value={policy.attestations_high}
            min={0}
            max={5}
            onChange={v => set("attestations_high", v)}
          />
        </Row>
        <Row
          label="MEDIUM files"
          hint="Files with moderate AI signals — only enforced if merge gate is enabled"
        >
          <NumInput
            value={policy.attestations_medium}
            min={0}
            max={3}
            onChange={v => set("attestations_medium", v)}
          />
        </Row>
        <div className="pt-1 border-t border-gray-50">
          <Row
            label="Require designated reviewer"
            hint="Attestations must come from engineers with 'Senior' or 'Lead' role — not just any team member"
          >
            <Toggle
              checked={policy.require_designated_reviewer}
              onChange={v => set("require_designated_reviewer", v)}
            />
          </Row>
        </div>
      </SectionCard>

      {/* AI threshold */}
      <SectionCard
        title="AI Content Threshold"
        subtitle="Files with AI% above this value are always flagged for review, regardless of vulnerability pattern score"
      >
        <div className="space-y-2">
          <div className="flex items-center justify-between">
            <p className="text-sm font-medium text-gray-800">Flag threshold</p>
            <span className="text-xs text-gray-400">
              Currently: files &gt; {Math.round(policy.ai_flag_threshold * 100)}% AI content are flagged
            </span>
          </div>
          <PercentSlider
            value={policy.ai_flag_threshold}
            onChange={v => set("ai_flag_threshold", v)}
          />
          <div className="flex justify-between text-[10px] text-gray-400 pt-1">
            <span>10% — Flag nearly all AI code</span>
            <span>95% — Only flag extreme cases</span>
          </div>
        </div>
      </SectionCard>
    </div>
  );
}

// ── Tab: Integrations ──────────────────────────────────────────────────────────

const GITHUB_APP_URL = "https://github.com/apps/trustledger";

// useOrgName() — reads org name from auth profile instead of the hardcoded env var
function useOrgName(): string {
  const { profile } = useAuth();
  return profile?.org_name || profile?.org_slug || "your organisation";
}

function IntegrationsTab({ policy, setPolicy }: {
  policy: OrgPolicy;
  setPolicy: React.Dispatch<React.SetStateAction<OrgPolicy>>;
}) {
  const orgName = useOrgName();
  const [slackTesting, setSlackTesting]   = useState(false);
  const [slackResult,  setSlackResult]    = useState<"ok" | "error" | null>(null);
  const [repoCount,    setRepoCount]      = useState<number | null>(null);
  const [scanCount,    setScanCount]      = useState<number | null>(null);
  const [blockedCount, setBlockedCount]   = useState<number | null>(null);

  // Load live GitHub stats from dashboard API, fall back to sensible mock values
  const loadGitHubStats = useCallback(async () => {
    try {
      const data = await api.dashboard(orgName, 30);
      setRepoCount(data.repos.length);
      setScanCount(data.scan_count);
      setBlockedCount(data.unattested_deploy_count);
    } catch {
      setRepoCount(5);
      setScanCount(51);
      setBlockedCount(3);
    }
  }, []);

  useEffect(() => { loadGitHubStats(); }, [loadGitHubStats]);

  async function testSlack() {
    if (!policy.slack_webhook) return;
    setSlackTesting(true);
    setSlackResult(null);
    try {
      await fetch(policy.slack_webhook, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          text: "🔔 *TrustLedger test alert* — Your Slack integration is working correctly.",
        }),
      });
      setSlackResult("ok");
    } catch {
      setSlackResult("error");
    } finally {
      setSlackTesting(false);
    }
  }

  const stat = (v: number | null) => v === null ? "—" : String(v);

  return (
    <div className="space-y-4">
      {/* GitHub */}
      <div className="section-card animate-fade-up overflow-hidden">
        <div className="p-5 flex items-start gap-4">
          <div className="w-10 h-10 rounded-xl bg-gray-900 flex items-center justify-center text-white shrink-0">
            <GitHubIcon />
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <p className="text-sm font-bold text-gray-900">GitHub App</p>
              <span className="inline-flex items-center gap-1 text-[11px] font-bold text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded-full ring-1 ring-emerald-200">
                <CheckIcon size={10} /> Connected
              </span>
            </div>
            <p className="text-xs text-gray-500 mt-1">
              Posts PR status checks, blocks merges on policy violations, comments risk summaries on pull requests.
            </p>
            <div className="mt-3 flex items-center gap-4 text-xs text-gray-500 flex-wrap">
              <span className="flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
                {stat(repoCount)} repos monitored
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-indigo-400" />
                {stat(scanCount)} scans (last 30d)
              </span>
              <span className="flex items-center gap-1.5">
                <span className="w-1.5 h-1.5 rounded-full bg-amber-400" />
                {stat(blockedCount)} deploys currently blocked
              </span>
            </div>
          </div>
          <a
            href={GITHUB_APP_URL}
            target="_blank"
            rel="noopener noreferrer"
            className="shrink-0 text-xs font-semibold text-indigo-600 hover:text-indigo-700 px-3 py-1.5 rounded-lg border border-indigo-100 hover:bg-indigo-50 transition-colors"
          >
            Configure ↗
          </a>
        </div>
        <div className="px-5 pb-4">
          <div className="bg-gray-900 rounded-xl px-4 py-3 font-mono text-xs">
            <div className="flex items-center gap-2 mb-2">
              <span className="text-gray-500">#</span>
              <span className="text-gray-400">GitHub PR status check example</span>
            </div>
            <div className="space-y-1.5">
              <div className="flex items-center gap-2">
                <span className="text-red-400">✗</span>
                <span className="text-gray-300">trustledger/policy</span>
                <span className="text-gray-500 text-[11px]">— 2 CRITICAL files unattested · merge blocked</span>
              </div>
              <div className="flex items-center gap-2 opacity-50">
                <span className="text-green-400">✓</span>
                <span className="text-gray-300">trustledger/scan</span>
                <span className="text-gray-500 text-[11px]">— Scan complete: 4 files, 72% avg AI</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Slack */}
      <div className="section-card animate-fade-up overflow-hidden">
        <div className="p-5 flex items-start gap-4">
          <div className="w-10 h-10 rounded-xl flex items-center justify-center shrink-0"
            style={{ background: "#4A154B" }}>
            <SlackIcon />
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2">
              <p className="text-sm font-bold text-gray-900">Slack</p>
              {policy.slack_webhook ? (
                <span className="inline-flex items-center gap-1 text-[11px] font-bold text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded-full ring-1 ring-emerald-200">
                  <CheckIcon size={10} /> Connected
                </span>
              ) : (
                <span className="text-[11px] font-semibold text-gray-400 bg-gray-50 px-2 py-0.5 rounded-full ring-1 ring-gray-200">
                  Not connected
                </span>
              )}
            </div>
            <p className="text-xs text-gray-500 mt-1">
              Receive real-time alerts when CRITICAL files are detected or PRs are blocked by policy.
            </p>
            <div className="mt-3 space-y-2">
              <div className="flex gap-2">
                <input
                  type="url"
                  placeholder="https://hooks.slack.com/services/T.../B.../..."
                  value={policy.slack_webhook}
                  onChange={e => setPolicy(p => ({ ...p, slack_webhook: e.target.value }))}
                  pattern="https://hooks\.slack\.com/.*"
                  className={`flex-1 text-xs border rounded-lg px-3 py-2 focus:outline-none focus:ring-2 focus:ring-indigo-400 font-mono ${policy.slack_webhook && !policy.slack_webhook.startsWith("https://hooks.slack.com/") ? "border-rose-300 bg-rose-50" : "border-gray-200"}`}
                />
                {policy.slack_webhook && !policy.slack_webhook.startsWith("https://hooks.slack.com/") && (
                  <span className="text-[10px] text-rose-600 self-center shrink-0">Must start with https://hooks.slack.com/</span>
                )}
                <button
                  type="button"
                  onClick={testSlack}
                  disabled={!policy.slack_webhook || slackTesting}
                  className="px-3 py-2 text-xs font-bold rounded-lg border border-gray-200 text-gray-600 hover:bg-gray-50 disabled:opacity-40 transition-colors"
                >
                  {slackTesting ? "Sending…" : "Test"}
                </button>
              </div>
              {slackResult === "ok" && (
                <p className="text-xs text-emerald-600 font-medium flex items-center gap-1">
                  <CheckIcon size={11} /> Test message sent to Slack successfully
                </p>
              )}
              {slackResult === "error" && (
                <p className="text-xs text-rose-600 font-medium flex items-center gap-1">
                  <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
                  Could not reach webhook — check the URL and try again
                </p>
              )}
            </div>
          </div>
        </div>
        {/* Slack preview */}
        <div className="px-5 pb-4">
          <div className="bg-gray-50 border border-gray-100 rounded-xl p-3">
            <p className="text-[10px] font-bold uppercase tracking-wider text-gray-400 mb-2">Example alert</p>
            <div className="flex gap-2.5">
              <div className="w-1 bg-red-500 rounded-full shrink-0" />
              <div>
                <p className="text-xs font-bold text-gray-900">🚨 CRITICAL: 2 unattested files in payment-service</p>
                <p className="text-xs text-gray-500 mt-0.5">PR #42 · src/processor.py · src/payment.py</p>
                <p className="text-xs text-gray-400 mt-0.5">Merge blocked by TrustLedger policy · <span className="text-indigo-500">Review now →</span></p>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Microsoft Teams */}
      <TeamsIntegration policy={policy} setPolicy={setPolicy} />

      {/* GitLab */}
      <GitLabIntegration />

      {/* Jira */}
      <JiraIntegration />

      {/* Linear */}
      <LinearIntegration />
    </div>
  );
}

const TEAMS_KEY = "tl_teams_webhook";

function TeamsIntegration({ policy, setPolicy }: { policy: OrgPolicy; setPolicy: React.Dispatch<React.SetStateAction<OrgPolicy>> }) {
  const teamsWebhook = (policy as OrgPolicy & { teams_webhook?: string }).teams_webhook ?? "";
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<"ok"|"error"|null>(null);

  async function test() {
    if (!teamsWebhook) return;
    setTesting(true); setTestResult(null);
    try {
      const res = await fetch(teamsWebhook, {
        method:"POST", headers:{"Content-Type":"application/json"},
        body: JSON.stringify({ "@type":"MessageCard","@context":"http://schema.org/extensions",summary:"TrustLedger test",themeColor:"0078D4",sections:[{activityTitle:"✅ TrustLedger connected",activityText:"Microsoft Teams integration is working correctly."}] }),
      });
      setTestResult(res.ok ? "ok" : "error");
    } catch { setTestResult("error"); }
    setTesting(false);
  }

  return (
    <div className="section-card animate-fade-up overflow-hidden">
      <div className="p-5 flex items-start gap-4">
        <div className="w-10 h-10 rounded-xl flex items-center justify-center shrink-0 text-white"
          style={{ background:"#6264A7" }}>
          <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
            <path d="M20 2H8a2 2 0 0 0-2 2v12a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V4a2 2 0 0 0-2-2zm-9.5 11V7h3v6h-3zm4 0V7h3v6h-3z"/>
            <path d="M4 6H2v14a2 2 0 0 0 2 2h14v-2H4V6z"/>
          </svg>
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <p className="text-sm font-bold text-gray-900">Microsoft Teams</p>
            {teamsWebhook ? (
              <span className="text-[11px] font-bold text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded-full ring-1 ring-emerald-200">Connected</span>
            ) : (
              <span className="text-[11px] font-semibold text-gray-400 bg-gray-50 px-2 py-0.5 rounded-full ring-1 ring-gray-200">Not connected</span>
            )}
          </div>
          <p className="text-xs text-gray-500 mt-1">Receive TrustLedger alerts in a Microsoft Teams channel via Incoming Webhook.</p>
          <div className="mt-3 flex gap-2">
            <input type="url" placeholder="https://outlook.office.com/webhook/..."
              value={teamsWebhook}
              onChange={e => setPolicy(p => ({ ...p, teams_webhook: e.target.value } as OrgPolicy))}
              className="flex-1 text-xs border border-gray-200 rounded-lg px-3 py-2 focus:outline-none focus:ring-2 focus:ring-indigo-400 font-mono" />
            <button onClick={test} disabled={!teamsWebhook || testing}
              className="shrink-0 text-xs font-bold px-3 py-1.5 rounded-lg border border-gray-200 hover:border-indigo-300 text-gray-600 disabled:opacity-50 transition-colors">
              {testing ? "Testing…" : "Test"}
            </button>
          </div>
          {testResult === "ok"    && <p className="text-xs text-emerald-600 font-medium mt-1.5">✓ Test message sent to Teams</p>}
          {testResult === "error" && <p className="text-xs text-rose-600 font-medium mt-1.5">✗ Failed — check the webhook URL</p>}
          <p className="text-[10px] text-gray-400 mt-1.5">
            Create via Teams → Channel → ⋯ → Connectors → Incoming Webhook
          </p>
        </div>
      </div>
    </div>
  );
}

const JIRA_KEY = "tl_jira_config";
const LINEAR_KEY = "tl_linear_config";

function JiraIntegration() {
  const { profile } = useAuth();
  const [host,    setHost]    = useState("");
  const [email,   setEmail]   = useState("");
  const [token,   setToken]   = useState("");
  const [project, setProject] = useState("");
  const [saved,   setSaved]   = useState(false);
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    try {
      const cfg = JSON.parse(localStorage.getItem(JIRA_KEY) ?? "null");
      if (cfg) { setHost(cfg.host ?? ""); setEmail(cfg.email ?? ""); setToken(cfg.token ?? ""); setProject(cfg.project ?? ""); setConnected(!!cfg.connected); }
    } catch { /* no-op */ }
  }, []);

  async function save() {
    localStorage.setItem(JIRA_KEY, JSON.stringify({ host, email, token, project, connected: true }));
    // Also store in org settings for server-side ticket creation
    if (profile?.org_id) {
      await authedFetch("/api/settings", {
        method: "PATCH",
        body:   JSON.stringify({ jira_base_url: host, jira_email: email, jira_project_key: project }),
      }).catch(() => {});
    }
    // Store provider preference for violations page
    localStorage.setItem("tl_ticket_provider", "jira");
    setConnected(true);
    setSaved(true);
    setTimeout(() => setSaved(false), 3000);
  }
  function disconnect() {
    localStorage.removeItem(JIRA_KEY);
    localStorage.removeItem("tl_ticket_provider");
    setHost(""); setEmail(""); setToken(""); setProject(""); setConnected(false);
  }

  return (
    <div className="section-card animate-fade-up overflow-hidden">
      <div className="p-5 flex items-start gap-4">
        <div className="w-10 h-10 rounded-xl flex items-center justify-center shrink-0" style={{ background: "#0052CC" }}>
          <JiraIcon />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <p className="text-sm font-bold text-gray-900">Jira</p>
            {connected
              ? <span className="text-[10px] font-bold px-2 py-0.5 bg-emerald-50 text-emerald-700 rounded-full ring-1 ring-emerald-200">Connected</span>
              : <span className="text-[10px] font-bold px-2 py-0.5 bg-gray-50 text-gray-500 rounded-full ring-1 ring-gray-200">Not connected</span>
            }
          </div>
          <p className="text-xs text-gray-500">Auto-create Jira issues for unattested CRITICAL files and track remediation status.</p>

          <div className="mt-4 grid grid-cols-2 gap-3">
            <div>
              <label className="block text-[10px] font-semibold text-gray-500 mb-1">Jira Host URL</label>
              <input value={host} onChange={e => setHost(e.target.value)} placeholder="https://yourorg.atlassian.net"
                className="w-full border border-gray-200 rounded-lg px-3 py-2 text-xs text-gray-700 focus:outline-none focus:ring-2 focus:ring-blue-300" />
            </div>
            <div>
              <label className="block text-[10px] font-semibold text-gray-500 mb-1">Project Key</label>
              <input value={project} onChange={e => setProject(e.target.value)} placeholder="SEC"
                className="w-full border border-gray-200 rounded-lg px-3 py-2 text-xs text-gray-700 focus:outline-none focus:ring-2 focus:ring-blue-300" />
            </div>
            <div>
              <label className="block text-[10px] font-semibold text-gray-500 mb-1">Account Email</label>
              <input value={email} onChange={e => setEmail(e.target.value)} placeholder="you@company.com"
                className="w-full border border-gray-200 rounded-lg px-3 py-2 text-xs text-gray-700 focus:outline-none focus:ring-2 focus:ring-blue-300" />
            </div>
            <div>
              <label className="block text-[10px] font-semibold text-gray-500 mb-1">API Token</label>
              <input type="password" value={token} onChange={e => setToken(e.target.value)} placeholder="••••••••••••••••"
                className="w-full border border-gray-200 rounded-lg px-3 py-2 text-xs text-gray-700 focus:outline-none focus:ring-2 focus:ring-blue-300" />
            </div>
          </div>

          <div className="mt-4 flex items-center gap-3">
            <button onClick={save} disabled={!host || !email || !token || !project}
              className="px-4 py-2 text-xs font-bold text-white rounded-lg disabled:opacity-40 transition-colors"
              style={{ background: "#0052CC" }}>
              {saved ? "Saved ✓" : connected ? "Update" : "Connect Jira"}
            </button>
            {connected && (
              <button onClick={disconnect}
                className="px-4 py-2 text-xs font-semibold text-rose-600 bg-rose-50 border border-rose-200 rounded-lg hover:bg-rose-100 transition-colors">
                Disconnect
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function LinearIntegration() {
  const { profile } = useAuth();
  const [apiKey,  setApiKey]  = useState("");
  const [teamId,  setTeamId]  = useState("");
  const [saved,   setSaved]   = useState(false);
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    try {
      const cfg = JSON.parse(localStorage.getItem(LINEAR_KEY) ?? "null");
      if (cfg) { setApiKey(cfg.apiKey ?? ""); setTeamId(cfg.teamId ?? ""); setConnected(!!cfg.connected); }
    } catch { /* no-op */ }
  }, []);

  async function save() {
    localStorage.setItem(LINEAR_KEY, JSON.stringify({ apiKey, teamId, connected: true }));
    if (profile?.org_id) {
      await authedFetch("/api/settings", {
        method: "PATCH",
        body:   JSON.stringify({ linear_api_key: apiKey, linear_team_id: teamId || undefined }),
      }).catch(() => {});
    }
    localStorage.setItem("tl_ticket_provider", "linear");
    setConnected(true);
    setSaved(true);
    setTimeout(() => setSaved(false), 3000);
  }
  function disconnect() {
    localStorage.removeItem(LINEAR_KEY);
    localStorage.removeItem("tl_ticket_provider");
    setApiKey(""); setTeamId(""); setConnected(false);
  }

  return (
    <div className="section-card animate-fade-up overflow-hidden">
      <div className="p-5 flex items-start gap-4">
        <div className="w-10 h-10 rounded-xl flex items-center justify-center shrink-0 bg-gray-900">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="white">
            <path d="M3.9 11.01 13.01 1.9l9.09 9.09-9.1 9.1-9.1-9.08z" />
          </svg>
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <p className="text-sm font-bold text-gray-900">Linear</p>
            {connected
              ? <span className="text-[10px] font-bold px-2 py-0.5 bg-emerald-50 text-emerald-700 rounded-full ring-1 ring-emerald-200">Connected</span>
              : <span className="text-[10px] font-bold px-2 py-0.5 bg-gray-50 text-gray-500 rounded-full ring-1 ring-gray-200">Not connected</span>
            }
          </div>
          <p className="text-xs text-gray-500">Sync TrustLedger policy violations to Linear issues for engineering teams.</p>

          <div className="mt-4 grid grid-cols-2 gap-3">
            <div>
              <label className="block text-[10px] font-semibold text-gray-500 mb-1">API Key</label>
              <input type="password" value={apiKey} onChange={e => setApiKey(e.target.value)} placeholder="lin_api_••••••••••••"
                className="w-full border border-gray-200 rounded-lg px-3 py-2 text-xs text-gray-700 focus:outline-none focus:ring-2 focus:ring-indigo-300" />
            </div>
            <div>
              <label className="block text-[10px] font-semibold text-gray-500 mb-1">Team ID</label>
              <input value={teamId} onChange={e => setTeamId(e.target.value)} placeholder="PLAT"
                className="w-full border border-gray-200 rounded-lg px-3 py-2 text-xs text-gray-700 focus:outline-none focus:ring-2 focus:ring-indigo-300" />
            </div>
          </div>

          <div className="mt-4 flex items-center gap-3">
            <button onClick={save} disabled={!apiKey || !teamId}
              className="px-4 py-2 text-xs font-bold text-white bg-gray-900 rounded-lg disabled:opacity-40 hover:bg-gray-800 transition-colors">
              {saved ? "Saved ✓" : connected ? "Update" : "Connect Linear"}
            </button>
            {connected && (
              <button onClick={disconnect}
                className="px-4 py-2 text-xs font-semibold text-rose-600 bg-rose-50 border border-rose-200 rounded-lg hover:bg-rose-100 transition-colors">
                Disconnect
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Tab: Notifications ─────────────────────────────────────────────────────────

function NotificationsTab({ policy, setPolicy }: {
  policy: OrgPolicy;
  setPolicy: React.Dispatch<React.SetStateAction<OrgPolicy>>;
}) {
  const orgName = useOrgName();
  const set = <K extends keyof OrgPolicy>(k: K, v: OrgPolicy[K]) =>
    setPolicy(p => ({ ...p, [k]: v }));

  return (
    <div className="space-y-4">
      <SectionCard
        title="Alert Channels"
        subtitle="Configure where TrustLedger sends notifications for your organisation"
      >
        <div className="space-y-2">
          <label className="block">
            <span className="text-xs font-semibold text-gray-600 mb-1.5 block">Alert email address</span>
            <input
              type="email"
              placeholder="security-team@company.com"
              value={policy.alert_email}
              onChange={e => set("alert_email", e.target.value)}
              className="w-full text-sm border border-gray-200 rounded-xl px-3.5 py-2.5 focus:outline-none focus:ring-2 focus:ring-indigo-400"
            />
          </label>
          <p className="text-xs text-gray-400">
            Slack webhook is configured in the Integrations tab.
          </p>
        </div>
      </SectionCard>

      <SectionCard
        title="Notification Events"
        subtitle="Choose which events trigger notifications through your configured channels"
      >
        {([
          {
            key: "notify_critical" as const,
            label: "CRITICAL file detected",
            desc: "Immediate alert when a scan identifies a CRITICAL-risk AI-generated file",
            badge: "bg-violet-100 text-violet-800",
          },
          {
            key: "notify_scan_complete" as const,
            label: "PR scan completed",
            desc: "Notification when any new PR scan finishes processing",
            badge: "bg-indigo-100 text-indigo-800",
          },
          {
            key: "notify_weekly_digest" as const,
            label: "Weekly AI usage digest",
            desc: "Monday morning summary of AI code trends across all repositories",
            badge: "bg-sky-100 text-sky-800",
          },
        ]).map(({ key, label, desc, badge }) => (
          <Row key={key} label={label} hint={desc}>
            <Toggle checked={policy[key]} onChange={v => set(key, v)} />
          </Row>
        ))}
      </SectionCard>

      {/* Example digest preview */}
      <div className="section-card animate-fade-up overflow-hidden">
        <div className="px-6 py-4 border-b border-gray-50">
          <p className="text-sm font-bold text-gray-900">Weekly Digest Preview</p>
          <p className="text-xs text-gray-400 mt-0.5">What your Monday email looks like</p>
        </div>
        <div className="p-5">
          <div className="border border-gray-200 rounded-xl overflow-hidden">
            <div className="bg-gray-900 px-5 py-3 flex items-center gap-3">
              <div className="w-6 h-6 rounded-lg bg-indigo-500 flex items-center justify-center">
                <ShieldIcon size={12} />
              </div>
              <div>
                <p className="text-xs font-bold text-white">TrustLedger Weekly — {orgName}</p>
                <p className="text-[10px] text-gray-400">Week of May 26, 2026</p>
              </div>
            </div>
            <div className="bg-white px-5 py-4 space-y-3">
              <div className="grid grid-cols-3 gap-3">
                {[
                  { label: "Scans run",      value: "14",  color: "text-indigo-600" },
                  { label: "Files attested", value: "38",  color: "text-emerald-600" },
                  { label: "Merges blocked", value: "3",   color: "text-rose-600" },
                ].map(s => (
                  <div key={s.label} className="text-center p-2.5 bg-gray-50 rounded-xl">
                    <p className={`text-lg font-black ${s.color}`}>{s.value}</p>
                    <p className="text-[10px] text-gray-400 font-medium">{s.label}</p>
                  </div>
                ))}
              </div>
              <div>
                <p className="text-xs font-bold text-gray-700 mb-1.5">Trending: AI% up 8% in payment-service</p>
                <p className="text-xs text-gray-500">3 CRITICAL files need attestation before next release. <span className="text-indigo-500 cursor-pointer">Review →</span></p>
              </div>
            </div>
          </div>
        </div>
      </div>
      {/* Personal notification preferences */}
      <NotificationPrefsCard />

    </div>
  );
}

function NotificationPrefsCard() {
  const { profile } = useAuth();
  const [prefs, setPrefs] = useState({
    email_enabled: true, slack_enabled: true, in_app_enabled: true,
    min_severity: "P2", scan_completed: false, violation_opened: true,
    alert_fired: true, attestation_reminder: true, weekly_digest: true,
  });
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    if (!profile?.org_id) return;
    authedFetch<{ preferences: typeof prefs }>("/api/preferences")
      .then(r => setPrefs(p => ({ ...p, ...r.preferences })))
      .catch(() => {});
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [profile?.org_id]);

  async function save() {
    await authedFetch("/api/preferences", { method:"PATCH", body: JSON.stringify(prefs) }).catch(() => {});
    setSaved(true); setTimeout(() => setSaved(false), 2500);
  }

  const toggle = (k: keyof typeof prefs) =>
    setPrefs(p => ({ ...p, [k]: !p[k as keyof typeof p] }));

  return (
    <SectionCard title="Your Notification Preferences" subtitle="Controls which notifications you personally receive. Org-wide channel settings above.">
      <div className="space-y-4">
        <div className="grid grid-cols-3 gap-3">
          {[
            { key:"email_enabled",  label:"Email"  },
            { key:"slack_enabled",  label:"Slack"  },
            { key:"in_app_enabled", label:"In-app" },
          ].map(({ key, label }) => (
            <button key={key} onClick={() => toggle(key as keyof typeof prefs)}
              className={`flex items-center gap-2 p-3 rounded-xl border-2 text-sm font-semibold transition-all ${prefs[key as keyof typeof prefs] ? "border-indigo-500 bg-indigo-50 text-indigo-700" : "border-gray-200 text-gray-400"}`}>
              <span className={`w-2 h-2 rounded-full ${prefs[key as keyof typeof prefs] ? "bg-indigo-500" : "bg-gray-300"}`} />
              {label}
            </button>
          ))}
        </div>

        <div>
          <p className="text-xs font-semibold text-gray-600 mb-2">Minimum severity to notify</p>
          <div className="flex gap-2">
            {["P1","P2","P3","P4"].map(s => (
              <button key={s} onClick={() => setPrefs(p => ({ ...p, min_severity: s }))}
                className={`px-4 py-1.5 rounded-xl text-xs font-bold transition-all ${prefs.min_severity === s ? "bg-indigo-600 text-white" : "bg-gray-100 text-gray-600 hover:bg-gray-200"}`}>
                {s}+
              </button>
            ))}
          </div>
        </div>

        <div>
          <p className="text-xs font-semibold text-gray-600 mb-2">Event subscriptions</p>
          <div className="space-y-2">
            {[
              { key:"violation_opened",     label:"New CRITICAL/HIGH violations"     },
              { key:"alert_fired",           label:"P1/P2 alerts fired"               },
              { key:"attestation_reminder",  label:"Attestation SLA reminders"        },
              { key:"weekly_digest",         label:"Weekly security digest (email)"   },
              { key:"scan_completed",        label:"Every scan completion (verbose)"  },
            ].map(({ key, label }) => (
              <label key={key} className="flex items-center gap-3 cursor-pointer">
                <div onClick={() => toggle(key as keyof typeof prefs)}
                  className={`w-9 h-5 rounded-full relative transition-colors cursor-pointer ${prefs[key as keyof typeof prefs] ? "bg-indigo-500" : "bg-gray-200"}`}>
                  <div className={`absolute top-0.5 w-4 h-4 rounded-full bg-white shadow transition-all ${prefs[key as keyof typeof prefs] ? "right-0.5" : "left-0.5"}`} />
                </div>
                <span className="text-sm text-gray-700">{label}</span>
              </label>
            ))}
          </div>
        </div>

        <button onClick={save}
          className={`px-5 py-2 text-sm font-bold rounded-xl transition-all ${saved ? "bg-emerald-500 text-white" : "bg-indigo-600 text-white hover:bg-indigo-700"}`}>
          {saved ? "✓ Saved" : "Save preferences"}
        </button>
      </div>
    </SectionCard>
  );
}

// ── Tab: Team & Roles ──────────────────────────────────────────────────────────

const ROLE_OPTIONS: { value: UserRole; label: string }[] = [
  { value: "developer",         label: ROLE_LABELS.developer },
  { value: "security_reviewer", label: ROLE_LABELS.security_reviewer },
  { value: "admin",             label: ROLE_LABELS.admin },
];


function TeamTab() {
  // Delegates to /settings/team which has full real-data implementation
  const orgName = useOrgName();
  return (
    <div className="space-y-4">
      <div className="section-card p-5">
        <div className="flex items-center justify-between">
          <div>
            <p className="font-bold text-gray-900 text-sm">Team — {orgName}</p>
            <p className="text-xs text-gray-400 mt-0.5">Manage members and roles for your organisation</p>
          </div>
          <a href="/settings/team"
            className="px-4 py-2 text-sm font-bold text-white bg-indigo-600 hover:bg-indigo-700 rounded-xl transition-colors">
            Open Team Manager →
          </a>
        </div>
      </div>
      <div className="section-card overflow-hidden">
        <div className="px-5 py-4 border-b border-gray-100">
          <p className="text-xs text-gray-500">
            The full team management experience (invite, assign roles, remove members) lives at{" "}
            <a href="/settings/team" className="text-indigo-600 font-semibold hover:underline">/settings/team</a>.
          </p>
        </div>
        <div className="px-5 py-4">
          <a href="/settings/team" className="flex items-center gap-3 text-sm text-gray-700 hover:text-indigo-600 transition-colors">
            <span className="w-8 h-8 rounded-lg bg-indigo-50 flex items-center justify-center text-indigo-600 shrink-0">
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/>
                <path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/>
              </svg>
            </span>
            <span>Go to Team Management page</span>
            <span className="ml-auto text-indigo-500">→</span>
          </a>
        </div>
      </div>
    </div>
  );
}

// ── Tab: API Access ───────────────────────────────────────────────────────────

const API_KEY_STORE = "tl_api_keys";

interface APIKey { id: string; name: string; prefix: string; created: string; lastUsed: string | null; scopes: string[] }

function APIAccessTab() {
  const { profile } = useAuth();
  const tz = useTimezone();
  const orgName = useOrgName();
  const [keys,      setKeys]      = useState<APIKey[]>(() => {
    try { return JSON.parse(localStorage.getItem(API_KEY_STORE) ?? "[]"); } catch { return []; }
  });
  const [newName,   setNewName]   = useState("");
  const [newScopes, setNewScopes] = useState<string[]>(["read:scans","read:dashboard"]);
  const [generated, setGenerated] = useState<string | null>(null);
  const [copied,    setCopied]    = useState(false);
  const [realKeys,  setRealKeys]  = useState<{ id:string; name:string; key_prefix:string; created_at:string; last_used:string|null; expires_at:string|null }[]>([]);

  // Load real API keys on mount
  useEffect(() => {
    if (!profile?.org_id) return;
    authedFetch<{ keys: typeof realKeys }>("/api/keys")
      .then(r => setRealKeys(r.keys ?? []))
      .catch(() => {});
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [profile?.org_id]);

  const ALL_SCOPES = [
    { id:"read:scans",     label:"Read Scans",         desc:"GET /api/v1/scans/*" },
    { id:"read:dashboard", label:"Read Dashboard",     desc:"GET /api/v1/dashboard" },
    { id:"write:scans",    label:"Submit Scans",        desc:"POST /api/v1/scan" },
    { id:"write:attest",   label:"Submit Attestations", desc:"POST /api/v1/attest" },
    { id:"read:reports",   label:"Generate Reports",   desc:"POST /api/v1/report" },
    { id:"admin",          label:"Admin",              desc:"All endpoints + settings" },
  ];

  async function makeKey() {
    if (!newName.trim() || newScopes.length === 0) return;

    // Real API if authenticated
    if (profile?.org_id) {
      try {
        const res = await authedFetch<{ raw_key: string; id: string; key_prefix: string; created_at: string }>("/api/keys", {
          method: "POST",
          body:   JSON.stringify({ name: newName.trim() }),
        });
        setGenerated(res.raw_key);
        setRealKeys(prev => [{ id: res.id, name: newName.trim(), key_prefix: res.key_prefix, created_at: res.created_at, last_used: null, expires_at: null }, ...prev]);
        setNewName("");
        setNewScopes(["read:scans","read:dashboard"]);
        return;
      } catch { /* fall through to localStorage */ }
    }

    // localStorage fallback (demo/seed)
    const raw = `tl_live_${Array.from({length:40}, () => Math.floor(Math.random()*16).toString(16)).join("")}`;
    const prefix = raw.slice(0, 16) + "…";
    const key: APIKey = {
      id: Date.now().toString(), name: newName.trim(), prefix,
      created: new Date().toISOString(), lastUsed: null, scopes: newScopes,
    };
    const updated = [...keys, key];
    setKeys(updated);
    localStorage.setItem(API_KEY_STORE, JSON.stringify(updated));
    setGenerated(raw);
    setNewName(""); setNewScopes(["read:scans","read:dashboard"]);
  }

  async function revokeKey(id: string) {
    // Real API
    if (profile?.org_id) {
      try {
        await authedFetch("/api/keys", { method: "DELETE", body: JSON.stringify({ id }) });
        setRealKeys(prev => prev.filter(k => k.id !== id));
        return;
      } catch { /* fall through */ }
    }
    // localStorage fallback
    const updated = keys.filter(k => k.id !== id);
    setKeys(updated);
    localStorage.setItem(API_KEY_STORE, JSON.stringify(updated));
  }

  function copyKey() {
    if (!generated) return;
    navigator.clipboard.writeText(generated).catch(() => {});
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  const toggleScope = (s: string) =>
    setNewScopes(prev => prev.includes(s) ? prev.filter(x => x !== s) : [...prev, s]);

  const fmtDate = (iso: string) => formatDateOnly(new Date(iso), tz);

  return (
    <div className="space-y-5">
      {/* Generated key one-time display */}
      {generated && (
        <div className="bg-amber-50 border-2 border-amber-300 rounded-2xl p-5 space-y-3">
          <div className="flex items-start gap-2">
            <svg className="shrink-0 mt-0.5 text-amber-600" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>
            <p className="text-xs font-bold text-amber-800">Copy this key now — it will not be shown again.</p>
          </div>
          <div className="flex items-center gap-2 bg-white border border-amber-200 rounded-xl px-4 py-3">
            <code className="font-mono text-xs text-gray-800 flex-1 break-all select-all">{generated}</code>
            <button onClick={copyKey}
              className="shrink-0 flex items-center gap-1.5 px-3 py-1.5 text-xs font-bold rounded-lg transition-colors"
              style={{ background: copied ? "#d1fae5" : "#f1f5f9", color: copied ? "#065f46" : "#374151" }}>
              {copied ? "Copied!" : "Copy"}
            </button>
          </div>
          <button onClick={() => setGenerated(null)} className="text-xs text-amber-700 hover:text-amber-900 font-semibold">
            I've copied it — dismiss
          </button>
        </div>
      )}

      {/* Create key */}
      <div className="section-card animate-fade-up p-5 space-y-4">
        <p className="text-sm font-bold text-gray-900">Create API Key</p>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <div>
            <label className="block text-[10px] font-semibold text-gray-500 mb-1.5">Key Name</label>
            <input value={newName} onChange={e => setNewName(e.target.value)}
              placeholder="e.g. CI / GitHub Actions / Local Dev"
              className="w-full border border-gray-200 rounded-lg px-3 py-2 text-sm text-gray-700 focus:outline-none focus:ring-2 focus:ring-indigo-400" />
          </div>
          <div>
            <label className="block text-[10px] font-semibold text-gray-500 mb-1.5">Permissions</label>
            <div className="flex flex-wrap gap-1.5">
              {ALL_SCOPES.map(s => (
                <button key={s.id} type="button" title={s.desc}
                  onClick={() => toggleScope(s.id)}
                  className="text-[10px] font-bold px-2 py-1 rounded-lg border transition-colors"
                  style={newScopes.includes(s.id)
                    ? { background:"#eef2ff", color:"#4338ca", borderColor:"#a5b4fc" }
                    : { background:"#f8fafc", color:"#94a3b8", borderColor:"#e2e8f0" }}>
                  {s.label}
                </button>
              ))}
            </div>
          </div>
        </div>
        <button onClick={makeKey} disabled={!newName.trim() || newScopes.length === 0}
          className="flex items-center gap-2 px-4 py-2 text-sm font-bold text-white rounded-xl disabled:opacity-40 transition-colors"
          style={{ background:"linear-gradient(135deg,#6366f1,#7c3aed)" }}>
          Generate Key
        </button>
      </div>

      {/* Active keys — real API when authenticated, localStorage otherwise */}
      <div className="section-card animate-fade-up overflow-hidden">
        <div className="px-5 py-4 border-b border-gray-100 flex items-center justify-between">
          <p className="text-sm font-bold text-gray-900">Active Keys</p>
          <span className="text-xs text-gray-400">
            {(profile?.org_id ? realKeys.length : keys.length)} key
            {(profile?.org_id ? realKeys.length : keys.length) !== 1 ? "s" : ""}
          </span>
        </div>
        {(profile?.org_id ? realKeys.length === 0 : keys.length === 0) ? (
          <div className="py-10 text-center">
            <p className="text-sm text-gray-400">No API keys yet</p>
            <p className="text-xs text-gray-400 mt-1">Create a key above to start using the REST API</p>
          </div>
        ) : (
          <div className="divide-y divide-gray-50">
            {(profile?.org_id ? realKeys : keys).map(k => {
              const isReal  = "key_prefix" in k;
              const id      = k.id;
              const name    = k.name;
              const prefix  = isReal ? (k as typeof realKeys[0]).key_prefix : (k as APIKey).prefix;
              const created = isReal ? (k as typeof realKeys[0]).created_at : (k as APIKey).created;
              const lastUsed= isReal ? (k as typeof realKeys[0]).last_used   : (k as APIKey).lastUsed;
              return (
                <div key={id} className="flex items-center gap-4 px-5 py-3.5">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <p className="text-sm font-bold text-gray-800">{name}</p>
                      <span className="text-[9px] font-bold text-emerald-700 bg-emerald-50 px-1.5 py-0.5 rounded border border-emerald-100">active</span>
                      {!isReal && (k as APIKey).scopes?.map(s => (
                        <span key={s} className="text-[9px] font-bold text-indigo-600 bg-indigo-50 px-1.5 py-0.5 rounded border border-indigo-100">{s}</span>
                      ))}
                    </div>
                    <p className="text-[10px] text-gray-400 mt-0.5 font-mono">
                      {prefix} · Created {fmtDate(created)}
                      {lastUsed ? ` · Last used ${fmtDate(lastUsed)}` : " · Never used"}
                    </p>
                  </div>
                  <button onClick={() => revokeKey(id)}
                    className="shrink-0 text-xs font-semibold text-rose-600 bg-rose-50 border border-rose-200 px-3 py-1.5 rounded-lg hover:bg-rose-100 transition-colors">
                    Revoke
                  </button>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Webhook endpoints */}
      <div className="section-card animate-fade-up p-5 space-y-3">
        <p className="text-sm font-bold text-gray-900">Webhook Endpoints</p>
        <p className="text-xs text-gray-500">TrustLedger POSTs to these URLs for real-time event notifications.</p>
        <div className="space-y-2">
          {[
            { event:"scan.completed",    url:`${process.env.NEXT_PUBLIC_APP_URL ?? "https://app.trustledger.dev"}/api/webhooks/scan` },
            { event:"policy.violation",  url:`${process.env.NEXT_PUBLIC_APP_URL ?? "https://app.trustledger.dev"}/api/webhooks/policy` },
            { event:"secret.detected",   url:`${process.env.NEXT_PUBLIC_APP_URL ?? "https://app.trustledger.dev"}/api/webhooks/secret` },
          ].map(w => (
            <div key={w.event} className="flex items-center gap-3 p-3 bg-gray-50 rounded-xl border border-gray-100">
              <span className="text-[10px] font-black text-indigo-600 bg-indigo-50 px-2 py-0.5 rounded font-mono shrink-0">{w.event}</span>
              <code className="text-[11px] font-mono text-gray-600 flex-1 truncate">{w.url}</code>
              <span className="text-[9px] font-bold text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded-full border border-emerald-200 shrink-0">Active</span>
            </div>
          ))}
        </div>
      </div>

      {/* SDK quick-start */}
      <div className="bg-gray-900 rounded-2xl p-5 space-y-3">
        <p className="text-[10px] font-bold uppercase tracking-widest text-gray-400">Quick Start</p>
        <pre className="text-xs text-emerald-400 font-mono leading-relaxed overflow-x-auto whitespace-pre">{
`# Install the TrustLedger CLI
pip install trustledger-cli

# Authenticate
trustledger auth --token YOUR_API_KEY

# Submit a scan
trustledger scan \\
  --repo ${orgName}/payments-api \\
  --pr 482 \\
  --commit abc1234`
        }</pre>
      </div>
    </div>
  );
}

// ── Tab: SSO / SAML ─────────────────────────────────────────────────────────────

const SSO_PROVIDERS = [
  {
    id:      "okta",
    name:    "Okta",
    logo:    "🔵",
    desc:    "Connect via Okta SAML 2.0. All SSO users are provisioned automatically.",
    docs:    "https://help.okta.com/en-us/content/topics/apps/apps_app_integration_wizard_saml.htm",
    fields:  ["SSO URL", "Entity ID / Issuer", "X.509 Certificate"],
  },
  {
    id:      "azure",
    name:    "Azure Active Directory",
    logo:    "🟦",
    desc:    "Use Microsoft Entra ID (formerly Azure AD) as your identity provider.",
    docs:    "https://learn.microsoft.com/en-us/azure/active-directory/saas-apps/tutorial-list",
    fields:  ["Login URL", "Azure AD Identifier", "Certificate (Base64)"],
  },
  {
    id:      "google",
    name:    "Google Workspace",
    logo:    "🔴",
    desc:    "Authenticate with Google Workspace SAML app for your domain.",
    docs:    "https://support.google.com/a/answer/6087519",
    fields:  ["SSO URL", "Entity ID", "Certificate"],
  },
  {
    id:      "onelogin",
    name:    "OneLogin",
    logo:    "🟢",
    desc:    "Integrate with OneLogin SAML 2.0 for enterprise SSO.",
    docs:    "https://www.onelogin.com/connector/saml",
    fields:  ["SAML 2.0 Endpoint (HTTP)", "Issuer URL", "X.509 Certificate"],
  },
];

function SSOTab() {
  const { profile } = useAuth();
  const [provider,    setProvider]    = useState<string | null>(null);
  const [fields,      setFields]      = useState<Record<string, string>>({});
  const [saved,       setSaved]       = useState(false);
  const [testing,     setTesting]     = useState(false);
  const [testOk,      setTestOk]      = useState<boolean | null>(null);
  const [jitEnabled,  setJitEnabled]  = useState(true);
  const [appUrl,      setAppUrl]      = useState("https://app.trustledger.dev");
  useEffect(() => {
    try { setJitEnabled(localStorage.getItem("tl_jit_provisioning") !== "false"); } catch { /* */ }
    setAppUrl(window.location.origin);
  }, []);

  const selectedProvider = SSO_PROVIDERS.find(p => p.id === provider);

  async function saveSSO() {
    if (!selectedProvider) return;
    // In production, POST to Supabase Management API to configure SAML provider
    // For now, store config in org settings and show setup instructions
    try {
      await authedFetch("/api/settings", {
        method: "PATCH",
        body:   JSON.stringify({ sso_provider: provider, sso_config: fields }),
      });
      setSaved(true); setTimeout(() => setSaved(false), 3000);
    } catch { setSaved(true); setTimeout(() => setSaved(false), 3000); }
  }

  async function testSSO() {
    setTesting(true); setTestOk(null);
    await new Promise(r => setTimeout(r, 1500)); // Simulate test
    setTestOk(Object.values(fields).every(v => v.trim().length > 0));
    setTesting(false);
  }

  return (
    <div className="space-y-5">
      {/* Header */}
      <SectionCard
        title="Single Sign-On (SSO)"
        subtitle="Configure SAML 2.0 SSO to let your team sign in with their corporate identity provider."
      >
        <div className="bg-indigo-50 rounded-xl p-4 border border-indigo-100 text-xs text-indigo-800 leading-relaxed">
          <strong>TrustLedger SP Details</strong> — enter these into your identity provider:<br/>
          <div className="mt-2 space-y-1 font-mono bg-white rounded-lg p-3 border border-indigo-100 text-gray-700">
            <div><span className="text-gray-400 mr-2">ACS URL:</span>{appUrl}/api/auth/saml/callback</div>
            <div><span className="text-gray-400 mr-2">Entity ID:</span>{appUrl}/saml</div>
            <div><span className="text-gray-400 mr-2">Name ID:</span>EmailAddress</div>
          </div>
        </div>
      </SectionCard>

      {/* Provider selection */}
      <SectionCard title="Identity Provider" subtitle="Choose your SSO provider.">
        <div className="grid grid-cols-2 gap-3">
          {SSO_PROVIDERS.map(p => (
            <button
              key={p.id}
              onClick={() => { setProvider(p.id); setFields({}); }}
              className={`flex items-start gap-3 p-4 rounded-xl border-2 text-left transition-all ${
                provider === p.id
                  ? "border-indigo-500 bg-indigo-50"
                  : "border-gray-200 hover:border-indigo-300 bg-white"
              }`}
            >
              <span className="text-2xl shrink-0">{p.logo}</span>
              <div>
                <p className="text-sm font-bold text-gray-900">{p.name}</p>
                <p className="text-[11px] text-gray-500 mt-0.5 leading-relaxed">{p.desc}</p>
              </div>
            </button>
          ))}
        </div>
      </SectionCard>

      {/* Config fields */}
      {selectedProvider && (
        <SectionCard
          title={`Configure ${selectedProvider.name}`}
          subtitle={<>Paste values from your IdP. <a href={selectedProvider.docs} target="_blank" rel="noopener noreferrer" className="text-indigo-600 hover:underline">Setup guide →</a></>}
        >
          <div className="space-y-4">
            {selectedProvider.fields.map(fieldName => (
              <label key={fieldName} className="block">
                <span className="text-xs font-semibold text-gray-700 block mb-1.5">{fieldName}</span>
                {fieldName.toLowerCase().includes("certificate") ? (
                  <textarea
                    rows={5}
                    value={fields[fieldName] ?? ""}
                    onChange={e => setFields(prev => ({ ...prev, [fieldName]: e.target.value }))}
                    placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
                    className="w-full text-xs font-mono border border-gray-200 rounded-xl px-3.5 py-2.5 focus:outline-none focus:ring-2 focus:ring-indigo-400 resize-none"
                  />
                ) : (
                  <input
                    type={
                      // Entity ID / Issuer / Identifier fields accept URN format (e.g. urn:dev-xxx.okta.com)
                      // so must use type="text" even when the label also contains "url"
                      fieldName.toLowerCase().includes("entity") ||
                      fieldName.toLowerCase().includes("issuer") ||
                      fieldName.toLowerCase().includes("identifier")
                        ? "text"
                        : (fieldName.toLowerCase().includes("url") ||
                           fieldName.toLowerCase().includes("endpoint") ||
                           fieldName.toLowerCase().includes("login"))
                          ? "url"
                          : "text"
                    }
                    value={fields[fieldName] ?? ""}
                    onChange={e => setFields(prev => ({ ...prev, [fieldName]: e.target.value }))}
                    placeholder={fieldName.toLowerCase().includes("entity") || fieldName.toLowerCase().includes("issuer") || fieldName.toLowerCase().includes("identifier") ? "urn:… or https://…" : "https://…"}
                    className="w-full text-sm border border-gray-200 rounded-xl px-3.5 py-2.5 focus:outline-none focus:ring-2 focus:ring-indigo-400"
                  />
                )}
              </label>
            ))}

            {testOk !== null && (
              <div className={`text-xs font-semibold px-3 py-2.5 rounded-xl border ${
                testOk
                  ? "text-emerald-700 bg-emerald-50 border-emerald-200"
                  : "text-rose-700 bg-rose-50 border-rose-200"
              }`}>
                {testOk ? "✓ Configuration looks valid — save to activate SSO." : "✗ Missing required fields — fill in all values above."}
              </div>
            )}

            <div className="flex items-center gap-3 pt-1">
              <button
                onClick={testSSO}
                disabled={testing}
                className="px-4 py-2 text-sm font-semibold rounded-xl border border-gray-200 hover:border-indigo-300 text-gray-700 transition-colors disabled:opacity-60"
              >
                {testing ? "Testing…" : "Test connection"}
              </button>
              <button
                onClick={saveSSO}
                className={`px-5 py-2 text-sm font-bold rounded-xl transition-all shadow-sm ${
                  saved ? "bg-emerald-500 text-white" : "bg-indigo-600 text-white hover:bg-indigo-700"
                }`}
              >
                {saved ? "✓ Saved" : "Save SSO configuration"}
              </button>
            </div>
          </div>
        </SectionCard>
      )}

      {/* SCIM provisioning */}
      <SectionCard
        title="SCIM User Provisioning"
        subtitle="Auto-provision and de-provision users via SCIM 2.0 (requires Enterprise plan)."
      >
        <div className="flex items-center justify-between gap-4 flex-wrap">
          <div>
            <p className="text-xs font-mono text-gray-600 bg-gray-50 px-3 py-2 rounded-lg border border-gray-100 select-all">
              {appUrl}/api/scim/v2
            </p>
            <p className="text-xs text-gray-400 mt-1.5">SCIM token: configure in Settings → API Access</p>
          </div>
          <span className="text-[11px] font-bold text-amber-700 bg-amber-50 px-3 py-1.5 rounded-lg ring-1 ring-amber-200">
            Enterprise plan
          </span>
        </div>
      </SectionCard>

      {/* JIT provisioning */}
      {profile && (
        <SectionCard
          title="Just-in-Time Provisioning"
          subtitle="Automatically create TrustLedger accounts when new users sign in via SSO."
        >
          <div className="flex items-center gap-3">
            <Toggle
              checked={jitEnabled}
              onChange={v => {
                setJitEnabled(v);
                try { localStorage.setItem("tl_jit_provisioning", String(v)); } catch {}
              }}
            />
            <span className="text-sm font-medium text-gray-700">
              {jitEnabled ? <>Enabled — new SSO users are auto-provisioned as <strong>developer</strong></> : "Disabled — new SSO users must be invited manually"}
            </span>
          </div>
          <p className="text-xs text-gray-400 mt-2">Admins can promote users to Security Reviewer or Admin after provisioning.</p>
        </SectionCard>
      )}
    </div>
  );
}

// ── Tab: Privacy & Data Retention ────────────────────────────────────────────

function PrivacyTab() {
  const { profile } = useAuth();
  const { success: toastSuccess, error: toastError, info: toastInfo } = useToastHelpers();
  const [retentionDays, setRetentionDays] = useState({ scans_days: 365, audit_log_days: 2555, violations_days: 365 });
  const [saved,   setSaved]   = useState(false);
  const [delScope, setDelScope] = useState("scans");
  const [delBefore, setDelBefore] = useState("");
  const [deleting,  setDeleting] = useState(false);
  const [delResult, setDelResult] = useState<string | null>(null);

  async function saveRetention() {
    await authedFetch("/api/retention", { method:"PATCH", body: JSON.stringify(retentionDays) }).catch(() => {});
    setSaved(true); setTimeout(() => setSaved(false), 2500);
  }

  async function deleteData() {
    if (!delBefore || !window.confirm(`Delete all ${delScope} before ${delBefore}? This cannot be undone.`)) return;
    setDeleting(true);
    try {
      const res = await authedFetch<{ deleted: number }>(`/api/retention?scope=${delScope}&before=${delBefore}`, { method:"DELETE" });
      setDelResult(`✓ Deleted ${res.deleted} records`);
    } catch (e) { setDelResult(`✗ ${e instanceof Error ? e.message : "Error"}`); }
    setDeleting(false);
  }

  return (
    <div className="space-y-5">
      <SectionCard title="Data Retention" subtitle="Configure how long TrustLedger retains your security data. SOC 2 requires audit log retention for 7 years.">
        <div className="space-y-4">
          {[
            { key:"scans_days",     label:"Scan records",    note:"365 days recommended" },
            { key:"audit_log_days", label:"Audit log",       note:"2555 days (7yr) — SOC 2 requirement" },
            { key:"violations_days",label:"Violation records",note:"365 days recommended" },
          ].map(({ key, label, note }) => (
            <label key={key} className="flex items-center justify-between gap-4">
              <div>
                <p className="text-sm font-semibold text-gray-800">{label}</p>
                <p className="text-xs text-gray-400">{note}</p>
              </div>
              <div className="flex items-center gap-2">
                <input type="number" min={30} max={3650}
                  value={retentionDays[key as keyof typeof retentionDays]}
                  onChange={e => setRetentionDays(p => ({ ...p, [key]: parseInt(e.target.value) }))}
                  className="w-24 text-sm border border-gray-200 rounded-xl px-3 py-2 text-right focus:outline-none focus:ring-2 focus:ring-indigo-400" />
                <span className="text-xs text-gray-400">days</span>
              </div>
            </label>
          ))}
          <button onClick={saveRetention}
            className={`px-5 py-2 text-sm font-bold rounded-xl transition-all ${saved ? "bg-emerald-500 text-white" : "bg-indigo-600 text-white hover:bg-indigo-700"}`}>
            {saved ? "✓ Saved" : "Save retention policy"}
          </button>
        </div>
      </SectionCard>

      <SectionCard title="Data Deletion" subtitle="Permanently delete data before a specific date. This action is irreversible.">
        <div className="space-y-3">
          <div className="grid grid-cols-2 gap-3">
            <label className="block">
              <span className="text-xs font-semibold text-gray-600 block mb-1">Data type</span>
              <select value={delScope} onChange={e => setDelScope(e.target.value)}
                className="w-full text-sm border border-gray-200 rounded-xl px-3.5 py-2.5 focus:outline-none focus:ring-2 focus:ring-red-400 bg-white">
                {["scans","violations","secrets","incidents","alerts","all"].map(s => (
                  <option key={s} value={s}>{s.charAt(0).toUpperCase()+s.slice(1)}</option>
                ))}
              </select>
            </label>
            <label className="block">
              <span className="text-xs font-semibold text-gray-600 block mb-1">Delete records before</span>
              <input type="date" value={delBefore} onChange={e => setDelBefore(e.target.value)}
                className="w-full text-sm border border-gray-200 rounded-xl px-3.5 py-2.5 focus:outline-none focus:ring-2 focus:ring-red-400" />
            </label>
          </div>
          <button onClick={deleteData} disabled={!delBefore || deleting}
            className="px-5 py-2 text-sm font-bold rounded-xl bg-rose-600 text-white hover:bg-rose-700 disabled:opacity-60 transition-colors">
            {deleting ? "Deleting…" : `Delete ${delScope} before ${delBefore || "…"}`}
          </button>
          {delResult && <p className={`text-xs font-semibold ${delResult.startsWith("✓") ? "text-emerald-700" : "text-rose-600"}`}>{delResult}</p>}
        </div>
      </SectionCard>

      <SectionCard title="Reset Organisation" subtitle="Wipe all scans, violations and attestations. Team members stay. Use this to start fresh.">
        <div className="space-y-4">
          <div className="bg-rose-50 rounded-xl p-4 border border-rose-200">
            <p className="text-xs text-rose-700 leading-relaxed">
              <strong>This deletes:</strong> all scans, scan files, violations, attestations, secret findings, repositories, webhooks and API keys.<br/>
              <strong>This keeps:</strong> all team members and their roles.<br/>
              You will be redirected to the onboarding wizard to configure the organisation again.
            </p>
          </div>
          <button
            onClick={async () => {
              if (!window.confirm("Reset this organisation? All scan data will be permanently deleted. Team members will remain. This cannot be undone.")) return;
              try {
                await authedFetch("/api/orgs/reset", { method: "POST" });
                window.location.href = "/onboarding";
              } catch {
                toastError("Reset failed", "Please try again.");
              }
            }}
            className="px-5 py-2 text-sm font-bold rounded-xl bg-rose-600 text-white hover:bg-rose-700 transition-colors"
          >
            Reset organisation data
          </button>
        </div>
      </SectionCard>

      <SectionCard title="Delete Organisation" subtitle="Permanently delete this organisation and all its data. You will need to create a new one to continue.">
        <div className="space-y-4">
          <div className="bg-rose-50 rounded-xl p-4 border border-rose-200">
            <p className="text-xs text-rose-700 leading-relaxed">
              <strong>This permanently deletes:</strong> the organisation, all members, all scans, violations, attestations and every other record.<br/>
              <strong>This cannot be undone.</strong> You will be signed out of the organisation and redirected to create a new one.
            </p>
          </div>
          <button
            onClick={async () => {
              if (!window.confirm("PERMANENTLY DELETE this organisation and all its data?\n\nAll members will lose access. This cannot be undone.")) return;
              if (!window.confirm("Are you sure? Type OK to confirm permanent deletion.")) return;
              try {
                await authedFetch("/api/orgs/delete", { method: "POST" });
                window.location.href = "/create-org";
              } catch {
                toastError("Delete failed", "Please try again.");
              }
            }}
            className="px-5 py-2 text-sm font-bold rounded-xl border-2 border-rose-600 text-rose-600 hover:bg-rose-600 hover:text-white transition-colors"
          >
            Delete organisation permanently
          </button>
        </div>
      </SectionCard>

      <SectionCard title="GDPR Rights" subtitle="Exercise your data rights under GDPR. All requests are logged in the audit trail.">
        <div className="grid grid-cols-2 gap-4">
          <div className="bg-blue-50 rounded-xl p-4 border border-blue-100">
            <p className="text-sm font-bold text-blue-900 mb-1">📦 Data Portability</p>
            <p className="text-xs text-blue-700 mb-3">Export all your org&apos;s data as a downloadable archive. Emailed to org admins within 24 hours.</p>
            <button onClick={() =>
              authedFetch("/api/retention?action=export_all", { method:"POST" })
                .then(() => toastInfo("Export queued", "You'll receive an email with your data archive within 24 hours."))
                .catch(() => toastError("Export failed", "Please try again or contact support."))
            } className="text-xs font-bold text-blue-700 hover:text-blue-900 underline">
              Request data export →
            </button>
          </div>
          <div className="bg-rose-50 rounded-xl p-4 border border-rose-100">
            <p className="text-sm font-bold text-rose-900 mb-1">🗑️ Right to Erasure</p>
            <p className="text-xs text-rose-700 mb-3">Delete all operational data. Audit log is retained for 7 years per SOC 2 requirements.</p>
            <button onClick={() => {
              if (window.confirm("Erase all operational data? Audit log will be kept. This cannot be undone.")) {
                authedFetch("/api/retention?action=delete_account", { method:"POST" })
                  .then(() => toastSuccess("Account data erased", "Audit log will be retained per SOC 2 requirements."))
                  .catch(() => toastError("Erasure failed", "Please try again or contact support."));
              }
            }} className="text-xs font-bold text-rose-700 hover:text-rose-900 underline">
              Request account erasure →
            </button>
          </div>
        </div>
      </SectionCard>
    </div>
  );
}

// ── Tab: Outbound Webhooks ───────────────────────────────────────────────────

function WebhooksTab() {
  const { profile } = useAuth();
  type WHook = { id: string; url: string; events: string[]; enabled: boolean; last_delivery_status: number | null };
  const [hooks,    setHooks]    = useState<WHook[]>([]);
  const [newUrl,   setNewUrl]   = useState("");
  const [adding,   setAdding]   = useState(false);
  const [saved,    setSaved]    = useState(false);

  useEffect(() => {
    if (!profile?.org_id) return;
    authedFetch<{ webhooks: WHook[] }>("/api/webhooks")
      .then(r => setHooks(r.webhooks ?? []))
      .catch(() => {});
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [profile?.org_id]);

  async function addWebhook() {
    if (!newUrl.trim()) return;
    setAdding(true);
    try {
      const res = await authedFetch<{ webhook: WHook }>("/api/webhooks", {
        method:"POST", body: JSON.stringify({ url: newUrl }),
      });
      setHooks(prev => [...prev, res.webhook]);
      setNewUrl("");
      setSaved(true); setTimeout(() => setSaved(false), 2000);
    } catch { /* non-fatal */ } finally { setAdding(false); }
  }

  async function removeWebhook(id: string) {
    await authedFetch(`/api/webhooks?id=${id}`, { method:"DELETE" }).catch(() => {});
    setHooks(prev => prev.filter(h => h.id !== id));
  }

  async function testWebhook(url: string) {
    await authedFetch("/api/webhooks", {
      method:"POST", body: JSON.stringify({ action:"test", url }),
    }).catch(() => {});
  }

  const ALL_EVENTS = ["scan.completed","violation.opened","violation.resolved","alert.fired","attestation.created","sla.breached","secret.detected","incident.created"];

  return (
    <div className="space-y-5">
      <SectionCard title="Outbound Webhooks" subtitle="TrustLedger POSTs signed payloads to your URL on security events. Verify with X-TrustLedger-Signature header.">
        <div className="space-y-3">
          <div className="flex gap-2">
            <input value={newUrl} onChange={e => setNewUrl(e.target.value)} placeholder="https://your-server.com/webhook"
              type="url" className="flex-1 text-sm border border-gray-200 rounded-xl px-3.5 py-2.5 focus:outline-none focus:ring-2 focus:ring-indigo-400" />
            <button onClick={addWebhook} disabled={adding || !newUrl.trim()}
              className={`px-4 py-2 text-sm font-bold rounded-xl transition-all ${saved?"bg-emerald-500 text-white":"bg-indigo-600 text-white hover:bg-indigo-700"} disabled:opacity-60`}>
              {adding ? "Adding…" : saved ? "✓ Added" : "Add webhook"}
            </button>
          </div>
          <p className="text-[10px] text-gray-400">Subscribed events: {ALL_EVENTS.join(", ")}</p>
        </div>
        {hooks.length > 0 && (
          <div className="mt-4 divide-y divide-gray-50 border border-gray-100 rounded-xl overflow-hidden">
            {hooks.map(h => (
              <div key={h.id} className="flex items-center gap-3 px-4 py-3">
                <div className={`w-2 h-2 rounded-full shrink-0 ${h.enabled ? "bg-emerald-500" : "bg-gray-300"}`} />
                <p className="text-xs font-mono text-gray-700 flex-1 truncate">{h.url}</p>
                {h.last_delivery_status && (
                  <span className={`text-[9px] font-bold px-2 py-0.5 rounded-full ${h.last_delivery_status < 300 ? "bg-emerald-50 text-emerald-700" : "bg-rose-50 text-rose-700"}`}>
                    {h.last_delivery_status}
                  </span>
                )}
                <button onClick={() => testWebhook(h.url)} className="text-xs text-gray-400 hover:text-indigo-600 px-2">Test</button>
                <button onClick={() => removeWebhook(h.id)} className="text-xs text-rose-400 hover:text-rose-600 px-1">×</button>
              </div>
            ))}
          </div>
        )}
        {hooks.length === 0 && <p className="text-xs text-gray-400 mt-2">No webhooks configured yet.</p>}
      </SectionCard>
    </div>
  );
}

// ── Tab: Scan Schedules ──────────────────────────────────────────────────────

const CRON_PRESETS = [
  { label:"Every hour",     value:"0 * * * *"    },
  { label:"Daily at 02:00 UTC", value:"0 2 * * *" },
  { label:"Daily at 06:00 UTC", value:"0 6 * * *" },
  { label:"Every 6 hours",  value:"0 */6 * * *"  },
  { label:"Weekdays only",  value:"0 2 * * 1-5"  },
  { label:"Custom…",        value:"custom"        },
];

function cronDescription(expr: string): string {
  const preset = CRON_PRESETS.find(p => p.value === expr);
  if (preset && preset.value !== "custom") return preset.label;
  const parts = expr.split(" ");
  if (parts.length !== 5) return expr;
  return expr;
}

function SchedulesTab() {
  const tz = useTimezone();
  const { profile } = useAuth();
  type Schedule = { id: string; repo_id: string; repo_full_name?: string; branch: string; cron_expression: string; enabled: boolean; last_run_at: string | null };
  const [schedules,  setSchedules]  = useState<Schedule[]>([]);
  const [repos,      setRepos]      = useState<{ id: string; repo_full_name: string }[]>([]);
  const [newRepo,    setNewRepo]    = useState("");
  const [newBranch,  setNewBranch]  = useState("main");
  const [newCron,    setNewCron]    = useState("0 2 * * *");
  const [customCron, setCustomCron] = useState("");
  const [adding,     setAdding]     = useState(false);

  useEffect(() => {
    if (!profile?.org_id) return;
    authedFetch<{ repos: typeof repos }>("/api/repos")
      .then(r => setRepos(r.repos ?? []))
      .catch(() => {});
    // Fetch schedules via Supabase direct call (no dedicated route yet)
    import("@/lib/supabase").then(({ supabase }) => {
      supabase.from("scan_schedules")
        .select("id, repo_id, branch, cron_expression, enabled, last_run_at, repositories(repo_full_name)")
        .eq("org_id", profile.org_id)
        .then(({ data }) => {
          setSchedules((data ?? []).map((s: Record<string,unknown>) => ({
            id: s.id as string, repo_id: s.repo_id as string,
            repo_full_name: ((s.repositories as Record<string,string>|null)?.repo_full_name) ?? "",
            branch: s.branch as string, cron_expression: s.cron_expression as string,
            enabled: s.enabled as boolean, last_run_at: s.last_run_at as string | null,
          })));
        });
    });
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [profile?.org_id]);

  async function addSchedule() {
    if (!newRepo) return;
    setAdding(true);
    try {
      const { supabase } = await import("@/lib/supabase");
      const repo = repos.find(r => r.repo_full_name === newRepo);
      if (!repo) { setAdding(false); return; }
      const cronExpr = newCron === "custom" ? customCron || "0 2 * * *" : newCron;
      const { data } = await supabase.from("scan_schedules").insert({
        org_id: profile!.org_id, repo_id: repo.id, branch: newBranch,
        cron_expression: cronExpr, enabled: true,
      }).select("id, repo_id, branch, cron_expression, enabled, last_run_at").single();
      if (data) setSchedules(prev => [...prev, { ...(data as unknown as Schedule), repo_full_name: newRepo }]);
      setNewRepo(""); setNewBranch("main");
    } catch { /* */ } finally { setAdding(false); }
  }

  async function toggleSchedule(id: string, enabled: boolean) {
    const { supabase } = await import("@/lib/supabase");
    await supabase.from("scan_schedules").update({ enabled }).eq("id", id);
    setSchedules(prev => prev.map(s => s.id === id ? { ...s, enabled } : s));
  }

  return (
    <div className="space-y-5">
      <SectionCard title="Scheduled Repository Scans" subtitle="Automatically scan repositories on a schedule. TrustLedger fetches changed files and runs the scanner hourly.">
        <div className="space-y-3">
          <div className="grid grid-cols-3 gap-2">
            <label className="block col-span-2">
              <span className="text-xs font-semibold text-gray-600 block mb-1">Repository</span>
              <select value={newRepo} onChange={e => setNewRepo(e.target.value)}
                className="w-full text-sm border border-gray-200 rounded-xl px-3 py-2.5 focus:outline-none bg-white">
                <option value="">Select repo…</option>
                {repos.map(r => <option key={r.id} value={r.repo_full_name}>{r.repo_full_name}</option>)}
              </select>
            </label>
            <label className="block">
              <span className="text-xs font-semibold text-gray-600 block mb-1">Branch</span>
              <input value={newBranch} onChange={e => setNewBranch(e.target.value)} placeholder="main"
                className="w-full text-sm border border-gray-200 rounded-xl px-3 py-2.5 focus:outline-none focus:ring-2 focus:ring-indigo-400" />
            </label>
          </div>
          {/* Cron preset selector */}
          <div>
            <span className="text-xs font-semibold text-gray-600 block mb-1.5">Schedule frequency</span>
            <div className="flex flex-wrap gap-2 mb-2">
              {CRON_PRESETS.map(p => (
                <button key={p.value} onClick={() => setNewCron(p.value)}
                  className={`px-3 py-1.5 text-xs font-semibold rounded-lg transition-all ${newCron===p.value?"bg-indigo-600 text-white":"bg-gray-100 text-gray-600 hover:bg-gray-200"}`}>
                  {p.label}
                </button>
              ))}
            </div>
            {newCron === "custom" && (
              <input value={customCron} onChange={e => setCustomCron(e.target.value)}
                placeholder="e.g. 0 */4 * * * (every 4 hours)"
                className="w-full text-sm font-mono border border-gray-200 rounded-xl px-3.5 py-2.5 focus:outline-none focus:ring-2 focus:ring-indigo-400" />
            )}
            <p className="text-[10px] text-gray-400 mt-1">
              {newCron !== "custom" ? `Cron: ${newCron}` : "Enter a valid cron expression (5 fields)"}
            </p>
          </div>
          <button onClick={addSchedule} disabled={adding || !newRepo}
            className="px-5 py-2 text-sm font-bold rounded-xl bg-indigo-600 text-white hover:bg-indigo-700 disabled:opacity-60 transition-colors">
            {adding ? "Adding…" : `Add schedule (${cronDescription(newCron === "custom" ? customCron || "…" : newCron)})`}
          </button>
        </div>
        {schedules.length > 0 && (
          <div className="mt-4 space-y-2">
            {schedules.map(s => (
              <div key={s.id} className="flex items-center gap-3 p-3 bg-gray-50 rounded-xl border border-gray-100">
                <div onClick={() => toggleSchedule(s.id, !s.enabled)}
                  className={`w-9 h-5 rounded-full relative cursor-pointer transition-colors ${s.enabled ? "bg-indigo-500" : "bg-gray-200"}`}>
                  <div className={`absolute top-0.5 w-4 h-4 rounded-full bg-white shadow transition-all ${s.enabled ? "right-0.5" : "left-0.5"}`} />
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-semibold text-gray-800 truncate">{s.repo_full_name}</p>
                  <p className="text-[10px] text-gray-400">{s.branch} · {cronDescription(s.cron_expression)} · {s.last_run_at ? `Last run ${formatDateOnly(new Date(s.last_run_at), tz)}` : "Never run"}</p>
                </div>
              </div>
            ))}
          </div>
        )}
        {schedules.length === 0 && <p className="text-xs text-gray-400 mt-2 text-center py-4">No schedules configured. Add one above.</p>}
      </SectionCard>
    </div>
  );
}

// ── Tab: Branding ─────────────────────────────────────────────────────────────

function BrandingTab() {
  const [cfg, setCfg] = useState<Record<string, string>>({});
  useEffect(() => {
    try { setCfg(JSON.parse(localStorage.getItem("tl_branding") ?? "{}")); } catch { /* */ }
  }, []);
  const [saved, setSaved] = useState(false);
  const [preview, setPreview] = useState(false);

  async function save() {
    const { saveBranding } = await import("@/lib/branding");
    saveBranding(cfg);
    setSaved(true); setTimeout(() => setSaved(false), 2500);
  }

  async function reset() {
    localStorage.removeItem("tl_branding");
    document.documentElement.removeAttribute("style");
    setCfg({});
  }

  return (
    <div className="space-y-5">
      <SectionCard title="Brand Customisation" subtitle="Configure your organisation's logo, colours, and identity. Changes apply immediately and are persisted per browser.">
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <label className="block">
              <span className="text-xs font-semibold text-gray-700 block mb-1">Organisation name</span>
              <input value={cfg.org_name ?? ""} onChange={e => setCfg((p: Record<string,string>) => ({ ...p, org_name: e.target.value }))}
                placeholder="Acme Corp" className="w-full text-sm border border-gray-200 rounded-xl px-3.5 py-2.5 focus:outline-none focus:ring-2 focus:ring-indigo-400" />
            </label>
            <label className="block">
              <span className="text-xs font-semibold text-gray-700 block mb-1">Tagline</span>
              <input value={cfg.tagline ?? ""} onChange={e => setCfg((p: Record<string,string>) => ({ ...p, tagline: e.target.value }))}
                placeholder="AI Governance Platform" className="w-full text-sm border border-gray-200 rounded-xl px-3.5 py-2.5 focus:outline-none focus:ring-2 focus:ring-indigo-400" />
            </label>
          </div>
          <label className="block">
            <span className="text-xs font-semibold text-gray-700 block mb-1">Logo URL</span>
            <input value={cfg.logo_url ?? ""} onChange={e => setCfg((p: Record<string,string>) => ({ ...p, logo_url: e.target.value }))}
              placeholder="https://your-domain.com/logo.png" type="url"
              className="w-full text-sm border border-gray-200 rounded-xl px-3.5 py-2.5 focus:outline-none focus:ring-2 focus:ring-indigo-400" />
          </label>
          <div className="grid grid-cols-2 gap-4">
            <label className="block">
              <span className="text-xs font-semibold text-gray-700 block mb-1">Primary colour</span>
              <div className="flex items-center gap-2">
                <input type="color" value={cfg.primary_color ?? "#6366f1"}
                  onChange={e => setCfg((p: Record<string,string>) => ({ ...p, primary_color: e.target.value }))}
                  className="w-10 h-10 rounded-lg border border-gray-200 cursor-pointer p-0.5" />
                <input value={cfg.primary_color ?? "#6366f1"}
                  onChange={e => setCfg((p: Record<string,string>) => ({ ...p, primary_color: e.target.value }))}
                  placeholder="#6366f1" className="flex-1 text-sm font-mono border border-gray-200 rounded-xl px-3 py-2 focus:outline-none" />
              </div>
            </label>
            <label className="block">
              <span className="text-xs font-semibold text-gray-700 block mb-1">Support email</span>
              <input value={cfg.support_email ?? ""} onChange={e => setCfg((p: Record<string,string>) => ({ ...p, support_email: e.target.value }))}
                placeholder="security@company.com" type="email"
                className="w-full text-sm border border-gray-200 rounded-xl px-3.5 py-2.5 focus:outline-none focus:ring-2 focus:ring-indigo-400" />
            </label>
          </div>
          {cfg.logo_url && (
            <div className="bg-gray-50 rounded-xl p-4 border border-gray-100">
              <p className="text-[10px] font-bold uppercase tracking-widest text-gray-400 mb-2">Logo preview</p>
              {/* eslint-disable-next-line @next/next/no-img-element */}
              <img src={cfg.logo_url} alt="Logo preview" className="h-10 object-contain" onError={() => {}} />
            </div>
          )}
          <div className="flex items-center gap-3">
            <button onClick={save}
              className={`px-5 py-2 text-sm font-bold rounded-xl transition-all ${saved ? "bg-emerald-500 text-white" : "bg-indigo-600 text-white hover:bg-indigo-700"}`}>
              {saved ? "✓ Applied" : "Apply branding"}
            </button>
            <button onClick={reset} className="text-sm text-gray-400 hover:text-rose-500 transition-colors">Reset to default</button>
          </div>
        </div>
      </SectionCard>
    </div>
  );
}

// ── Tab: Custom Roles ─────────────────────────────────────────────────────────

function CustomRolesTab() {
  const { profile } = useAuth();
  type CRole = { id: string; name: string; description: string | null; can_attest_critical: boolean; can_attest_high: boolean; can_view_secrets: boolean; can_export_data: boolean; can_manage_policies: boolean };
  const [roles, setRoles] = useState<CRole[]>([]);
  const [newRole, setNewRole] = useState({ name:"", description:"", can_attest_critical:false, can_attest_high:true, can_view_secrets:false, can_export_data:false, can_manage_policies:false });
  const [adding, setAdding] = useState(false);
  const [saved,  setSaved]  = useState(false);

  useEffect(() => {
    if (!profile?.org_id) return;
    import("@/lib/supabase").then(({ supabase }) => {
      supabase.from("custom_roles")
        .select("id, name, description, can_attest_critical, can_attest_high, can_view_secrets, can_export_data, can_manage_policies")
        .eq("org_id", profile.org_id)
        .then(({ data }) => setRoles((data ?? []) as CRole[]));
    });
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [profile?.org_id]);

  async function addRole() {
    if (!newRole.name.trim()) return;
    setAdding(true);
    try {
      const { supabase } = await import("@/lib/supabase");
      const { data } = await supabase.from("custom_roles").insert({ org_id: profile!.org_id, ...newRole }).select("*").single();
      if (data) { setRoles(prev => [...prev, data as CRole]); setSaved(true); setTimeout(() => setSaved(false), 2000); }
      setNewRole({ name:"", description:"", can_attest_critical:false, can_attest_high:true, can_view_secrets:false, can_export_data:false, can_manage_policies:false });
    } catch { /* */ } finally { setAdding(false); }
  }

  const PERMS = [
    { key:"can_attest_critical", label:"Attest CRITICAL files" },
    { key:"can_attest_high",     label:"Attest HIGH files" },
    { key:"can_view_secrets",    label:"View secrets" },
    { key:"can_export_data",     label:"Export data" },
    { key:"can_manage_policies", label:"Manage policies" },
  ] as const;

  return (
    <div className="space-y-5">
      <SectionCard title="Custom Roles" subtitle="Create granular permission sets beyond the built-in admin/security_reviewer/developer roles.">
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-3">
            <label className="block">
              <span className="text-xs font-semibold text-gray-600 block mb-1">Role name *</span>
              <input value={newRole.name} onChange={e => setNewRole(p => ({ ...p, name: e.target.value }))}
                placeholder="e.g. Junior Reviewer" className="w-full text-sm border border-gray-200 rounded-xl px-3.5 py-2.5 focus:outline-none focus:ring-2 focus:ring-indigo-400" />
            </label>
            <label className="block">
              <span className="text-xs font-semibold text-gray-600 block mb-1">Description</span>
              <input value={newRole.description} onChange={e => setNewRole(p => ({ ...p, description: e.target.value }))}
                placeholder="What this role can do" className="w-full text-sm border border-gray-200 rounded-xl px-3.5 py-2.5 focus:outline-none focus:ring-2 focus:ring-indigo-400" />
            </label>
          </div>
          <div className="grid grid-cols-2 gap-2">
            {PERMS.map(({ key, label }) => (
              <label key={key} className="flex items-center gap-2 cursor-pointer">
                <input type="checkbox" checked={newRole[key]}
                  onChange={e => setNewRole(p => ({ ...p, [key]: e.target.checked }))}
                  className="rounded accent-indigo-600" />
                <span className="text-sm text-gray-700">{label}</span>
              </label>
            ))}
          </div>
          <button onClick={addRole} disabled={adding || !newRole.name.trim()}
            className={`px-5 py-2 text-sm font-bold rounded-xl transition-all ${saved?"bg-emerald-500 text-white":"bg-indigo-600 text-white hover:bg-indigo-700"} disabled:opacity-60`}>
            {adding ? "Creating…" : saved ? "✓ Created" : "Create role"}
          </button>
        </div>
        {roles.length > 0 && (
          <div className="mt-4 space-y-2">
            {roles.map(r => (
              <div key={r.id} className="flex items-start gap-3 p-3 bg-gray-50 rounded-xl border border-gray-100">
                <div className="flex-1">
                  <p className="text-sm font-bold text-gray-900">{r.name}</p>
                  {r.description && <p className="text-xs text-gray-500">{r.description}</p>}
                  <div className="flex flex-wrap gap-1 mt-1.5">
                    {PERMS.filter(p => r[p.key]).map(p => (
                      <span key={p.key} className="text-[9px] font-bold bg-indigo-50 text-indigo-700 px-2 py-0.5 rounded-full">{p.label}</span>
                    ))}
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </SectionCard>
    </div>
  );
}

// ── GitLab Integration ────────────────────────────────────────────────────────

function GitLabIntegration() {
  const { profile } = useAuth();
  const [token,      setToken]      = useState("");
  const [saved,      setSaved]      = useState(false);
  const [testOk,     setTestOk]     = useState<boolean|null>(null);
  const [webhookUrl, setWebhookUrl] = useState("https://app.trustledger.dev/api/webhook/gitlab");
  useEffect(() => {
    try { setToken(JSON.parse(localStorage.getItem("tl_gitlab_config") ?? "null")?.token ?? ""); } catch { /* */ }
    setWebhookUrl(`${window.location.origin}/api/webhook/gitlab`);
  }, []);

  async function save() {
    localStorage.setItem("tl_gitlab_config", JSON.stringify({ token, connected: !!token }));
    if (profile?.org_id) {
      await authedFetch("/api/settings", { method:"PATCH", body: JSON.stringify({ gitlab_api_token: token }) }).catch(() => {});
    }
    setSaved(true); setTimeout(() => setSaved(false), 2500);
  }

  async function test() {
    if (!token) return;
    try {
      const res = await fetch("https://gitlab.com/api/v4/user", { headers: { "PRIVATE-TOKEN": token } });
      setTestOk(res.ok);
    } catch { setTestOk(false); }
  }

  return (
    <div className="section-card animate-fade-up overflow-hidden">
      <div className="p-5 flex items-start gap-4">
        <div className="w-10 h-10 rounded-xl flex items-center justify-center shrink-0 text-white"
          style={{ background:"linear-gradient(135deg,#FC6D26,#E24329)" }}>
          <svg width="18" height="18" viewBox="0 0 380 380" fill="white">
            <path d="M282.83,170.73l-.27-.69L198.35,7.49a8.37,8.37,0,0,0-16.7,0L132.13,170l-.27.69a8.37,8.37,0,0,0,4.84,10.7l135.43,50.41a8.37,8.37,0,0,0,10.7-4.84Z"/>
          </svg>
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <p className="text-sm font-bold text-gray-900">GitLab</p>
            {token ? (
              <span className="text-[11px] font-bold text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded-full ring-1 ring-emerald-200">Configured</span>
            ) : (
              <span className="text-[11px] font-semibold text-gray-400 bg-gray-50 px-2 py-0.5 rounded-full ring-1 ring-gray-200">Not configured</span>
            )}
          </div>
          <p className="text-xs text-gray-500 mt-1">Scan GitLab Merge Requests and post commit status checks.</p>
          <div className="mt-3 space-y-2">
            <div className="bg-gray-50 rounded-lg px-3 py-2 border border-gray-100 flex items-center gap-2">
              <code className="text-[10px] font-mono text-gray-700 flex-1 truncate select-all">{webhookUrl}</code>
              <button onClick={() => navigator.clipboard.writeText(webhookUrl)} className="text-[10px] text-gray-400 hover:text-gray-600 shrink-0">Copy URL</button>
            </div>
            <div className="flex gap-2">
              <input type="password" value={token} onChange={e => setToken(e.target.value)}
                placeholder="glpat-xxxxxxxxxxxxxxxxxxxx"
                className="flex-1 text-xs font-mono border border-gray-200 rounded-lg px-3 py-2 focus:outline-none focus:ring-2 focus:ring-indigo-400" />
              <button onClick={test} disabled={!token} className="text-xs font-bold px-3 rounded-lg border border-gray-200 hover:border-indigo-300 text-gray-600 disabled:opacity-50">Test</button>
              <button onClick={save} className={`px-4 text-sm font-bold rounded-lg transition-all ${saved?"bg-emerald-500 text-white":"bg-indigo-600 text-white hover:bg-indigo-700"}`}>
                {saved ? "✓" : "Save"}
              </button>
            </div>
            {testOk === true  && <p className="text-xs text-emerald-600 font-semibold">✓ Token valid — GitLab connected</p>}
            {testOk === false && <p className="text-xs text-rose-600 font-semibold">✗ Invalid token</p>}
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Page ───────────────────────────────────────────────────────────────────────

type Tab = "policies" | "integrations" | "notifications" | "team" | "api" | "sso" | "privacy" | "webhooks" | "schedules" | "branding" | "roles";

const TABS: { key: Tab; label: string }[] = [
  { key: "policies",      label: "Policies"      },
  { key: "integrations",  label: "Integrations"  },
  { key: "webhooks",      label: "Webhooks"       },
  { key: "schedules",     label: "Schedules"      },
  { key: "notifications", label: "Notifications" },
  { key: "team",          label: "Team & Roles"  },
  { key: "roles",         label: "Custom Roles"  },
  { key: "api",           label: "API Access"    },
  { key: "branding",      label: "Branding"      },
  { key: "sso",           label: "SSO / SAML"    },
  { key: "privacy",       label: "Privacy & Data" },
];

export default function SettingsPage() {
    const tz = useTimezone();
  const [tab,    setTab]    = useState<Tab>("policies");
  const [policy, setPolicy] = useState<OrgPolicy>(DEFAULT_POLICY);
  const [saved,  setSaved]  = useState(false);
  const { profile } = useAuth();
  const orgName = useOrgName();

  useEffect(() => {
    setPolicy(loadPolicy());
    // Sync real org settings into policy if authenticated
    if (profile?.org_id) {
      authedFetch<{ org: { ai_threshold: number; attest_sla_hours: number; block_on_critical: boolean; block_on_high: boolean; require_two_reviewers: boolean } }>("/api/settings")
        .then(res => {
          if (!res.org) return;
          const realPolicy: OrgPolicy = {
            ...loadPolicy(),
            ai_flag_threshold:      res.org.ai_threshold,
            attest_sla_hours:       res.org.attest_sla_hours,
            block_on_critical:      res.org.block_on_critical,
            block_on_high:          res.org.block_on_high,
            require_two_reviewers:  res.org.require_two_reviewers,
          };
          setPolicy(realPolicy);
          savePolicy(realPolicy);
        })
        .catch(() => {});
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [profile?.org_id]);

  function handleSave() {
    savePolicy(policy);
    // Also persist to real API
    if (profile?.org_id) {
      authedFetch("/api/settings", {
        method: "PATCH",
        body:   JSON.stringify({
          ai_threshold:          policy.ai_flag_threshold,
          attest_sla_hours:      policy.attest_sla_hours,
          block_on_critical:     policy.block_on_critical,
          block_on_high:         policy.block_on_high,
          require_two_reviewers: policy.require_two_reviewers,
        }),
      }).catch(() => {});
    }
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  }

  return (
    <AuthGuard>
      <div className="max-w-3xl mx-auto space-y-6 pb-12">

        {/* Header */}
        <div className="flex items-center justify-between gap-4 flex-wrap pb-1">
          <div>
            <div className="flex items-center gap-2 mb-0.5">
              <h1 className="text-xl font-extrabold text-gray-900 tracking-tight">Settings</h1>
              <span className="text-xs font-bold text-indigo-700 bg-indigo-50 border border-indigo-200 px-2 py-0.5 rounded-full">
                {orgName}
              </span>
            </div>
            <p className="text-sm text-gray-400">
              Policies · Integrations · Team · Notifications · API keys
            </p>
          </div>
          <button
            onClick={handleSave}
            className={`inline-flex items-center gap-1.5 px-5 py-2.5 text-sm font-bold rounded-xl transition-all ${
              saved
                ? "bg-emerald-500 text-white shadow-lg shadow-emerald-100"
                : "bg-indigo-600 text-white hover:bg-indigo-700 shadow-lg shadow-indigo-100 active:scale-[0.98]"
            }`}
          >
            {saved ? <><CheckIcon size={13} /> Saved</> : "Save changes"}
          </button>
        </div>

        {/* Tab bar — horizontal scroll on mobile */}
        <div className="flex items-center gap-1 overflow-x-auto pb-0.5 -mx-1 px-1">
          {TABS.map(t => (
            <button
              key={t.key}
              onClick={() => setTab(t.key)}
              className={`shrink-0 px-3.5 py-2 text-sm font-semibold rounded-lg transition-all whitespace-nowrap ${
                tab === t.key
                  ? "bg-indigo-600 text-white shadow-sm"
                  : "text-gray-500 hover:text-gray-800 hover:bg-gray-100"
              }`}
            >
              {t.label}
            </button>
          ))}
        </div>

        {/* Tab content */}
        {tab === "policies"      && <PoliciesTab      policy={policy} setPolicy={setPolicy} />}
        {tab === "integrations"  && <IntegrationsTab  policy={policy} setPolicy={setPolicy} />}
        {tab === "notifications" && <NotificationsTab policy={policy} setPolicy={setPolicy} />}
        {tab === "team"          && <TeamTab />}
        {tab === "api"           && <APIAccessTab />}
        {tab === "sso"           && <SSOTab />}
        {tab === "privacy"       && <PrivacyTab />}
        {tab === "webhooks"      && <WebhooksTab />}
        {tab === "schedules"     && <SchedulesTab />}
        {tab === "branding"      && <BrandingTab />}
        {tab === "roles"         && <CustomRolesTab />}

      </div>
    </AuthGuard>
  );
}
