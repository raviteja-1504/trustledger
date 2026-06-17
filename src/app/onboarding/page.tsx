"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { authedFetch } from "@/lib/useRealData";

// ── Step definitions ──────────────────────────────────────────────────────────

type Step = "welcome" | "github" | "team" | "policy" | "done";

const STEPS: { key: Step; label: string }[] = [
  { key: "welcome", label: "Welcome"        },
  { key: "github",  label: "Connect GitHub" },
  { key: "team",    label: "Invite Team"    },
  { key: "policy",  label: "Set Policy"     },
  { key: "done",    label: "Ready"          },
];

const PROGRESS_KEY = "tl_onboarding_step";

// ── Icons ─────────────────────────────────────────────────────────────────────

function ShieldIcon() {
  return (
    <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      <polyline points="9 12 11 14 15 10"/>
    </svg>
  );
}

function GithubIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
      <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z"/>
    </svg>
  );
}

// ── Shared button styles ──────────────────────────────────────────────────────

function PrimaryBtn({ children, onClick, disabled = false }: {
  children: React.ReactNode; onClick?: () => void; disabled?: boolean;
}) {
  return (
    <button onClick={onClick} disabled={disabled}
      className="w-full py-3 rounded-2xl font-bold text-white text-sm transition-all disabled:opacity-50 hover:opacity-90"
      style={{ background: "linear-gradient(135deg,#6366f1,#7c3aed)" }}>
      {children}
    </button>
  );
}

function SkipBtn({ onClick }: { onClick: () => void }) {
  return (
    <button onClick={onClick}
      className="w-full py-2 rounded-2xl font-semibold text-gray-400 text-sm hover:text-gray-600 transition-colors">
      Skip for now
    </button>
  );
}

// ── Step: Welcome ─────────────────────────────────────────────────────────────

function WelcomeStep({ onNext }: { onNext: () => void }) {
  const { profile } = useAuth();
  return (
    <div className="text-center space-y-6">
      <div className="w-20 h-20 rounded-3xl flex items-center justify-center mx-auto text-white"
        style={{ background: "linear-gradient(135deg,#6366f1,#7c3aed)", boxShadow: "0 8px 32px rgba(99,102,241,0.4)" }}>
        <ShieldIcon />
      </div>
      <div>
        <h2 className="text-2xl font-black text-gray-900">
          Welcome{profile?.name ? `, ${profile.name.split(" ")[0]}` : ""}!
        </h2>
        <p className="text-gray-500 mt-2 max-w-sm mx-auto text-sm leading-relaxed">
          TrustLedger governs AI-generated code across your engineering org — scanning every PR,
          enforcing reviewer attestation, and generating signed compliance reports.
        </p>
      </div>
      <div className="grid grid-cols-3 gap-3 max-w-md mx-auto">
        {[
          { icon: "🔍", title: "Scan",    desc: "Every PR analysed automatically" },
          { icon: "✅", title: "Attest",  desc: "Reviewers sign off on AI code"    },
          { icon: "📋", title: "Report",  desc: "SOC 2, PCI-DSS, EU AI Act"        },
        ].map(f => (
          <div key={f.title} className="bg-gray-50 rounded-2xl p-4 border border-gray-100 text-center">
            <div className="text-2xl mb-1.5">{f.icon}</div>
            <p className="text-xs font-black text-gray-900">{f.title}</p>
            <p className="text-[10px] text-gray-500 mt-0.5 leading-snug">{f.desc}</p>
          </div>
        ))}
      </div>
      <div className="space-y-2">
        <PrimaryBtn onClick={onNext}>Get started →</PrimaryBtn>
        <p className="text-xs text-gray-400">Takes about 5 minutes</p>
      </div>
    </div>
  );
}

// ── Step: GitHub ──────────────────────────────────────────────────────────────

function GithubStep({ onNext }: { onNext: () => void }) {
  const { profile } = useAuth();
  const [orgHandle,   setOrgHandle]   = useState(profile?.org_slug ?? "");
  const [githubLogin, setGithubLogin] = useState(profile?.github_login ?? "");
  const [webhookSecret, setWebhookSecret] = useState("");
  const [copied,  setCopied]  = useState<string | null>(null);
  const [saving,  setSaving]  = useState(false);
  const [appUrl,  setAppUrl]  = useState("https://app.trustledger.dev");

  useEffect(() => {
    setWebhookSecret(Array.from({ length: 32 }, () => Math.floor(Math.random() * 16).toString(16)).join(""));
    setAppUrl(window.location.origin);
  }, []);

  function copy(text: string, key: string) {
    navigator.clipboard.writeText(text).catch(() => {});
    setCopied(key);
    setTimeout(() => setCopied(null), 2000);
  }

  async function save() {
    setSaving(true);
    try {
      await Promise.all([
        orgHandle.trim() && authedFetch("/api/onboarding", {
          method: "POST",
          body: JSON.stringify({ action: "save_github_org", github_org: orgHandle.trim() }),
        }).catch(() => {}),
        githubLogin.trim() && authedFetch("/api/onboarding", {
          method: "POST",
          body: JSON.stringify({ action: "save_github_login", github_login: githubLogin.trim() }),
        }).catch(() => {}),
      ]);
    } finally {
      setSaving(false);
      onNext();
    }
  }

  return (
    <div className="space-y-5">
      <div className="text-center">
        <div className="w-12 h-12 rounded-2xl bg-gray-900 flex items-center justify-center mx-auto mb-3 text-white">
          <GithubIcon />
        </div>
        <h2 className="text-xl font-black text-gray-900">Connect GitHub</h2>
        <p className="text-sm text-gray-500 mt-1">Install the GitHub App and configure the webhook.</p>
      </div>

      {/* 1 — Install app */}
      <div className="bg-indigo-50 rounded-2xl p-4 border border-indigo-100 space-y-3">
        <div className="flex items-center gap-2">
          <span className="w-6 h-6 rounded-full bg-indigo-600 text-white text-xs font-black flex items-center justify-center shrink-0">1</span>
          <p className="text-sm font-bold text-indigo-900">Install TrustLedger GitHub App</p>
        </div>
        <a href="https://github.com/apps/trustledger/installations/new" target="_blank" rel="noopener noreferrer"
          className="inline-flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-bold text-white"
          style={{ background: "#24292f" }}>
          <GithubIcon /> Install on GitHub →
        </a>
      </div>

      {/* 2 — Webhook config */}
      <div className="bg-gray-50 rounded-2xl p-4 border border-gray-100 space-y-3">
        <div className="flex items-center gap-2">
          <span className="w-6 h-6 rounded-full bg-gray-600 text-white text-xs font-black flex items-center justify-center shrink-0">2</span>
          <p className="text-sm font-bold text-gray-900">Configure webhook in GitHub App settings</p>
        </div>
        {[
          { label: "Webhook URL",    value: `${appUrl}/api/webhook/github`, key: "url"    },
          { label: "Webhook Secret", value: webhookSecret,                  key: "secret" },
        ].map(row => (
          <div key={row.key}>
            <p className="text-xs font-semibold text-gray-500 mb-1">{row.label}</p>
            <div className="flex items-center gap-2 bg-white rounded-xl border border-gray-200 px-3 py-2">
              <code className="text-xs font-mono text-gray-700 flex-1 truncate select-all">{row.value}</code>
              <button onClick={() => copy(row.value, row.key)}
                className="shrink-0 text-xs font-bold px-2 py-1 rounded-lg transition-colors"
                style={{ background: copied === row.key ? "#d1fae5" : "#f1f5f9", color: copied === row.key ? "#065f46" : "#374151" }}>
                {copied === row.key ? "Copied!" : "Copy"}
              </button>
            </div>
          </div>
        ))}
        <p className="text-[10px] text-gray-400">Select events: Pull requests · Pushes · Check runs</p>
      </div>

      {/* 3 — Org details */}
      <div className="space-y-3">
        <div>
          <label className="text-xs font-semibold text-gray-700 block mb-1.5">
            Your GitHub organisation handle
          </label>
          <input value={orgHandle} onChange={e => setOrgHandle(e.target.value)} placeholder="acme-corp"
            className="w-full text-sm border border-gray-200 rounded-xl px-4 py-2.5 focus:outline-none focus:ring-2 focus:ring-indigo-400 font-mono" />
        </div>
        <div>
          <label className="text-xs font-semibold text-gray-700 block mb-1.5">
            Your GitHub username <span className="text-gray-400 font-normal">(for developer-scoped view)</span>
          </label>
          <input value={githubLogin} onChange={e => setGithubLogin(e.target.value)} placeholder="your-github-handle"
            className="w-full text-sm border border-gray-200 rounded-xl px-4 py-2.5 focus:outline-none focus:ring-2 focus:ring-indigo-400 font-mono" />
        </div>
      </div>

      <PrimaryBtn onClick={save} disabled={saving || !orgHandle.trim()}>
        {saving ? "Saving…" : "I've installed the app →"}
      </PrimaryBtn>
      <SkipBtn onClick={onNext} />
    </div>
  );
}

// ── Step: Team ────────────────────────────────────────────────────────────────

type InviteRow = { email: string; role: "admin" | "security_reviewer" | "developer"; name: string };

function TeamStep({ onNext }: { onNext: () => void }) {
  const [rows, setRows] = useState<InviteRow[]>([
    { email: "", role: "security_reviewer", name: "" },
  ]);
  const [inviting, setInviting] = useState(false);
  const [results,  setResults]  = useState<{ email: string; ok: boolean }[]>([]);
  const [done,     setDone]     = useState(false);

  function updateRow(i: number, field: keyof InviteRow, value: string) {
    setRows(prev => prev.map((r, idx) => idx === i ? { ...r, [field]: value } : r));
  }

  function addRow() {
    setRows(prev => [...prev, { email: "", role: "security_reviewer", name: "" }]);
  }

  function removeRow(i: number) {
    setRows(prev => prev.filter((_, idx) => idx !== i));
  }

  async function invite() {
    const valid = rows.filter(r => r.email.trim().includes("@"));
    if (valid.length === 0) { onNext(); return; }
    setInviting(true);
    const res = await Promise.all(
      valid.map(async r => {
        try {
          await authedFetch("/api/team", {
            method: "POST",
            body: JSON.stringify({ email: r.email.trim(), role: r.role, name: r.name.trim() || undefined }),
          });
          return { email: r.email, ok: true };
        } catch {
          return { email: r.email, ok: false };
        }
      })
    );
    setResults(res);
    setInviting(false);
    setDone(true);
  }

  const ROLE_LABELS: Record<InviteRow["role"], string> = {
    admin:              "Admin",
    security_reviewer:  "Security Reviewer",
    developer:          "Developer",
  };

  if (done) {
    return (
      <div className="space-y-5">
        <div className="text-center">
          <div className="text-4xl mb-3">🎉</div>
          <h2 className="text-xl font-black text-gray-900">Team invited!</h2>
        </div>
        <div className="space-y-2">
          {results.map(r => (
            <div key={r.email} className={`flex items-center gap-2 px-3 py-2 rounded-xl text-xs font-medium ${r.ok ? "bg-emerald-50 text-emerald-700" : "bg-rose-50 text-rose-700"}`}>
              <span>{r.ok ? "✓" : "✕"}</span>
              <span>{r.email}</span>
              {!r.ok && <span className="ml-auto text-rose-500">Already a member or failed</span>}
            </div>
          ))}
        </div>
        <PrimaryBtn onClick={onNext}>Continue →</PrimaryBtn>
      </div>
    );
  }

  return (
    <div className="space-y-5">
      <div className="text-center">
        <div className="text-3xl mb-3">👥</div>
        <h2 className="text-xl font-black text-gray-900">Invite your team</h2>
        <p className="text-sm text-gray-500 mt-1">Add security reviewers and developers to your organisation.</p>
      </div>

      <div className="space-y-2">
        {rows.map((row, i) => (
          <div key={i} className="grid grid-cols-[1fr_140px_100px_28px] gap-2 items-center">
            <input
              type="email"
              placeholder="email@company.com"
              value={row.email}
              onChange={e => updateRow(i, "email", e.target.value)}
              className="text-sm border border-gray-200 rounded-xl px-3 py-2 focus:outline-none focus:ring-2 focus:ring-indigo-300"
            />
            <input
              type="text"
              placeholder="Name"
              value={row.name}
              onChange={e => updateRow(i, "name", e.target.value)}
              className="text-sm border border-gray-200 rounded-xl px-3 py-2 focus:outline-none focus:ring-2 focus:ring-indigo-300"
            />
            <select
              value={row.role}
              onChange={e => updateRow(i, "role", e.target.value as InviteRow["role"])}
              className="text-xs border border-gray-200 rounded-xl px-2 py-2 focus:outline-none focus:ring-2 focus:ring-indigo-300"
            >
              {(Object.keys(ROLE_LABELS) as InviteRow["role"][]).map(r => (
                <option key={r} value={r}>{ROLE_LABELS[r]}</option>
              ))}
            </select>
            <button onClick={() => removeRow(i)} disabled={rows.length === 1}
              className="w-7 h-7 flex items-center justify-center rounded-lg text-gray-400 hover:text-rose-500 hover:bg-rose-50 disabled:opacity-30 transition-colors text-lg leading-none">
              ×
            </button>
          </div>
        ))}
        <button onClick={addRow}
          className="text-xs font-semibold text-indigo-600 hover:text-indigo-800 flex items-center gap-1 transition-colors mt-1">
          + Add another
        </button>
      </div>

      <div className="space-y-2">
        <PrimaryBtn onClick={invite} disabled={inviting}>
          {inviting ? "Sending invites…" : "Send invites"}
        </PrimaryBtn>
        <SkipBtn onClick={onNext} />
      </div>
    </div>
  );
}

// ── Step: Policy ──────────────────────────────────────────────────────────────

type Preset = "standard" | "strict" | "custom";

const PRESETS: Record<Preset, { label: string; desc: string; ai: number; sla: number; blockCrit: boolean; blockHigh: boolean }> = {
  standard: { label: "Standard", desc: "Block CRITICAL only. Warn on HIGH. 24h attestation SLA.",              ai: 0.80, sla: 24, blockCrit: true,  blockHigh: false },
  strict:   { label: "Strict",   desc: "Block CRITICAL + HIGH. 12h SLA. Designed for financial/healthcare.",   ai: 0.70, sla: 12, blockCrit: true,  blockHigh: true  },
  custom:   { label: "Custom",   desc: "Apply now then fine-tune anytime in Settings → Org Policy.",            ai: 0.80, sla: 24, blockCrit: true,  blockHigh: false },
};

function PolicyStep({ onNext }: { onNext: () => void }) {
  const [preset, setPreset] = useState<Preset>("standard");
  const [saving, setSaving] = useState(false);

  async function save() {
    setSaving(true);
    const cfg = PRESETS[preset];
    await authedFetch("/api/settings", {
      method: "PATCH",
      body: JSON.stringify({
        ai_threshold:      cfg.ai,
        attest_sla_hours:  cfg.sla,
        block_on_critical: cfg.blockCrit,
        block_on_high:     cfg.blockHigh,
      }),
    }).catch(() => {});
    setSaving(false);
    onNext();
  }

  return (
    <div className="space-y-5">
      <div className="text-center">
        <div className="text-3xl mb-3">⚙️</div>
        <h2 className="text-xl font-black text-gray-900">Set your policy</h2>
        <p className="text-sm text-gray-500 mt-1">Choose how strictly TrustLedger gates AI-generated code.</p>
      </div>

      <div className="space-y-2">
        {(Object.entries(PRESETS) as [Preset, typeof PRESETS[Preset]][]).map(([key, cfg]) => (
          <button key={key} onClick={() => setPreset(key)}
            className={`w-full text-left p-4 rounded-2xl border-2 transition-all ${
              preset === key ? "border-indigo-500 bg-indigo-50" : "border-gray-200 bg-white hover:border-indigo-200"
            }`}>
            <div className="flex items-center gap-2 mb-1 flex-wrap">
              <p className="text-sm font-black text-gray-900">{cfg.label}</p>
              <span className="text-[9px] font-bold px-2 py-0.5 rounded-full bg-gray-100 text-gray-600">AI&gt;{(cfg.ai * 100).toFixed(0)}%</span>
              <span className="text-[9px] font-bold px-2 py-0.5 rounded-full bg-gray-100 text-gray-600">SLA {cfg.sla}h</span>
              {cfg.blockHigh && <span className="text-[9px] font-bold px-2 py-0.5 rounded-full bg-orange-100 text-orange-700">Blocks HIGH</span>}
            </div>
            <p className="text-xs text-gray-500">{cfg.desc}</p>
          </button>
        ))}
      </div>

      <PrimaryBtn onClick={save} disabled={saving}>
        {saving ? "Saving…" : "Apply policy →"}
      </PrimaryBtn>
    </div>
  );
}

// ── Step: Done ────────────────────────────────────────────────────────────────

function DoneStep() {
  const router = useRouter();
  return (
    <div className="text-center space-y-6">
      <div className="text-6xl">🎉</div>
      <div>
        <h2 className="text-2xl font-black text-gray-900">You&apos;re all set!</h2>
        <p className="text-sm text-gray-500 mt-2 max-w-sm mx-auto leading-relaxed">
          TrustLedger is connected and ready. Your next pull request will be automatically analysed
          and your team will be notified of any HIGH or CRITICAL AI-generated code.
        </p>
      </div>
      <div className="grid grid-cols-2 gap-3 max-w-sm mx-auto">
        {[
          { icon: "📊", title: "Dashboard",    href: "/dashboard"   },
          { icon: "👥", title: "Team",         href: "/settings/team" },
          { icon: "📋", title: "Compliance",   href: "/compliance"  },
          { icon: "⚙️", title: "Settings",     href: "/settings"    },
        ].map(l => (
          <button key={l.title} onClick={() => router.push(l.href)}
            className="flex items-center gap-2 p-4 rounded-2xl border border-gray-200 hover:border-indigo-300 hover:bg-indigo-50 transition-all text-left group">
            <span className="text-xl">{l.icon}</span>
            <span className="text-sm font-semibold text-gray-700 group-hover:text-indigo-700">{l.title}</span>
          </button>
        ))}
      </div>
      <button onClick={() => router.push("/dashboard")}
        className="px-10 py-3 rounded-2xl font-bold text-white text-sm"
        style={{ background: "linear-gradient(135deg,#6366f1,#7c3aed)", boxShadow: "0 4px 20px rgba(99,102,241,0.35)" }}>
        Go to dashboard →
      </button>
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function OnboardingPage() {
  const [stepIdx, setStepIdx] = useState<number>(() => {
    if (typeof window === "undefined") return 0;
    const saved = parseInt(localStorage.getItem(PROGRESS_KEY) ?? "0");
    return isNaN(saved) ? 0 : Math.min(saved, STEPS.length - 1);
  });

  const step = STEPS[stepIdx].key;

  function next() {
    const next = Math.min(stepIdx + 1, STEPS.length - 1);
    setStepIdx(next);
    if (typeof window !== "undefined") localStorage.setItem(PROGRESS_KEY, String(next));

    // Mark org as onboarding_complete when reaching the done step
    if (next === STEPS.length - 1) {
      authedFetch("/api/onboarding", {
        method: "POST",
        body: JSON.stringify({ action: "complete" }),
      }).catch(() => {});
      // Clear saved progress
      if (typeof window !== "undefined") localStorage.removeItem(PROGRESS_KEY);
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center px-4 py-12"
      style={{ background: "linear-gradient(135deg,#f8fafc 0%,#eff6ff 50%,#f8fafc 100%)" }}>
      <div className="w-full max-w-lg">

        {/* Progress bar */}
        <div className="mb-8">
          <div className="flex items-center justify-center gap-1 mb-3">
            {STEPS.map((s, i) => (
              <div key={s.key} className="flex items-center gap-1">
                <div className="flex items-center justify-center transition-all overflow-hidden"
                  style={{
                    width:        i <= stepIdx ? 28 : 8,
                    height:       8,
                    borderRadius: 4,
                    background:   i < stepIdx ? "#10b981" : i === stepIdx ? "#6366f1" : "#e2e8f0",
                    transition:   "all 0.3s ease",
                  }}>
                  {i < stepIdx && (
                    <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">
                      <polyline points="20 6 9 17 4 12"/>
                    </svg>
                  )}
                </div>
                {i < STEPS.length - 1 && (
                  <div className="w-4 h-0.5 rounded-full" style={{ background: i < stepIdx ? "#10b981" : "#e2e8f0" }} />
                )}
              </div>
            ))}
          </div>
          <p className="text-center text-xs text-gray-400">
            Step {stepIdx + 1} of {STEPS.length} —{" "}
            <span className="font-semibold text-gray-600">{STEPS[stepIdx].label}</span>
          </p>
        </div>

        {/* Card */}
        <div className="bg-white rounded-3xl shadow-xl border border-gray-100 p-8">
          {step === "welcome" && <WelcomeStep onNext={next} />}
          {step === "github"  && <GithubStep  onNext={next} />}
          {step === "team"    && <TeamStep    onNext={next} />}
          {step === "policy"  && <PolicyStep  onNext={next} />}
          {step === "done"    && <DoneStep />}
        </div>

        {/* Back link (except welcome and done) */}
        {stepIdx > 0 && stepIdx < STEPS.length - 1 && (
          <button onClick={() => { const prev = stepIdx - 1; setStepIdx(prev); localStorage.setItem(PROGRESS_KEY, String(prev)); }}
            className="mt-4 w-full text-center text-xs text-gray-400 hover:text-gray-600 transition-colors">
            ← Back
          </button>
        )}

      </div>
    </div>
  );
}
