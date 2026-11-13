"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { authedFetch } from "@/lib/useRealData";
import { BrandMark } from "@/components/BrandLogo";
import { normalizeGithubHandle } from "@/lib/githubHandle";
import { clearDoneSteps, firstUnfinishedIndex, loadDoneSteps, markStepDone, type WizardStep } from "@/lib/onboardingProgress";

// ── Step definitions ──────────────────────────────────────────────────────────

type Step = "welcome" | "github" | "team" | "policy" | "done";

const STEPS: { key: Step; label: string }[] = [
  { key: "welcome", label: "Welcome"        },
  { key: "github",  label: "Connect GitHub" },
  { key: "team",    label: "Invite Team"    },
  { key: "policy",  label: "Set Policy"     },
  { key: "done",    label: "Ready"          },
];


// ── Icons ─────────────────────────────────────────────────────────────────────

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
      <div className="w-20 h-20 rounded-3xl flex items-center justify-center mx-auto"
        style={{ background: "#050810", boxShadow: "0 8px 32px rgba(15,23,42,0.25)" }}>
        <BrandMark size={58} />
      </div>
      <div>
        <h2 className="text-2xl font-black text-gray-900">
          Welcome{profile?.name ? `, ${profile.name.split(" ")[0]}` : ""}!
        </h2>
        <p className="text-gray-500 mt-2 max-w-sm mx-auto text-sm leading-relaxed">
          TrustLedger governs AI-generated code across your engineering org — scanning every PR,
          enforcing reviewer attestation, and generating signed evidence assessments.
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
  const { user } = useAuth();
  // Never pre-filled from the organisation's slug (that is TrustLedger's own name for it, not a GitHub name): only from the
  // handle already saved, or from the GitHub installation, below.
  const [orgHandle,   setOrgHandle]   = useState("");
  const [touched,     setTouched]     = useState(false);
  const meta = (user?.user_metadata ?? {}) as Record<string, unknown>;
  const [githubLogin, setGithubLogin] = useState(profile?.github_login ?? (typeof meta.user_name === "string" ? meta.user_name : ""));
  // what this organisation has linked today, and its name, from the server
  const [savedHandle, setSavedHandle] = useState<string | null>(null);
  const [orgName, setOrgName] = useState(profile?.org_name ?? "");
  useEffect(() => {
    authedFetch<{ github_org?: string | null; org_name?: string }>("/api/onboarding")
      .then(r => {
        setSavedHandle(r?.github_org ?? null);
        if (r?.org_name) setOrgName(r.org_name);
        if (r?.github_org) setOrgHandle(h => h || r.github_org!);
      })
      .catch(() => {});
  }, []);
  const [saving,  setSaving]  = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  // GitHub sends the person back here after installing, with ?installation_id=...: ask GitHub which account that is
  const [installedOn, setInstalledOn] = useState<string | null>(null);
  // setup_action=request: installed on an organisation whose owner must approve it first, so it is not installed yet
  const [requested, setRequested] = useState(false);
  useEffect(() => {
    const q = new URLSearchParams(window.location.search);
    if (q.get("setup_action") === "request") setRequested(true);
    if (q.get("error") === "installation_save_failed") setSaveError("GitHub installed the app, but we couldn't save the connection. Please try the install again.");
    if (q.get("error") === "installation_not_verified") setSaveError(q.get("why") === "not_configured"
      ? "We couldn't confirm the GitHub installation because TrustLedger's GitHub sign-in isn't configured yet. Please contact support."
      : "We couldn't confirm that this GitHub installation is yours, so it wasn't connected. Click Install on GitHub again and approve the install with your own GitHub account.");
    if (q.get("error") === "missing_installation_id") setSaveError("GitHub didn't send back the installation details. Please try the install again.");
    const id = q.get("installation_id");
    if (!id || !/^\d+$/.test(id)) return;
    authedFetch<{ login: string }>(`/api/github-app/installation?id=${id}`)
      .then(r => { setInstalledOn(r.login); setOrgHandle(r.login); })
      .catch(() => {});
  }, []);
  // Is TrustLedger's GitHub App already set up on this deployment, and where does a customer install it?
  const [info, setInfo] = useState<{ configured: boolean; install_url: string | null } | null>(null);
  const [infoFailed, setInfoFailed] = useState(false);
  const loadInfo = () => {
    setInfoFailed(false);
    authedFetch<{ configured: boolean; install_url: string | null }>("/api/github-app/info").then(setInfo).catch(() => setInfoFailed(true));
  };
  useEffect(() => { loadInfo(); }, []);   // eslint-disable-line react-hooks/exhaustive-deps

  const parsed = normalizeGithubHandle(orgHandle);
  // The app was installed on one account and the handle names another: pull requests are matched on the handle, so say so
  const installedDiffers = !!installedOn && parsed.ok && parsed.handle !== installedOn.toLowerCase();

  async function save() {
    setTouched(true);
    if (!parsed.ok) return;
    setSaving(true);
    setSaveError(null);
    try {
      // Linking the organisation is what makes pull requests from it scanned: if it fails, do not move on as if it worked
      await authedFetch("/api/onboarding", {
        method: "POST",
        body: JSON.stringify({ action: "save_github_org", github_org: parsed.ok ? parsed.handle : orgHandle.trim() }),
      });
    } catch (e) {
      const code = e instanceof Error ? e.message : "";
      setSaveError(code === "github_org_taken"
        ? "That GitHub account is already linked to another TrustLedger organisation. If you have created more than one TrustLedger organisation, check which one you are signed in to (shown at the top of this page). Otherwise, ask whoever linked it to remove it first."
        : code === "github_org_invalid" || code === "github_org_required"
          ? "That isn't a GitHub account name. Enter the part after github.com/, for example acme-corp."
          : "We couldn't save that. Please try again.");
      setSaving(false);
      return;
    }
    // the username is optional and only for the developer view: a failure here does not stop setup
    if (githubLogin.trim()) {
      await authedFetch("/api/onboarding", { method: "POST", body: JSON.stringify({ action: "save_github_login", github_login: githubLogin.trim() }) }).catch(() => {});
    }
    setSaving(false);
    onNext();
  }

  return (
    <div className="space-y-5">
      <div className="text-center">
        <div className="w-12 h-12 rounded-2xl bg-gray-900 flex items-center justify-center mx-auto mb-3 text-white">
          <GithubIcon />
        </div>
        <h2 className="text-xl font-black text-gray-900">Connect GitHub</h2>
        <p className="text-sm text-gray-500 mt-1">Install the TrustLedger GitHub App on the repositories you want scanned.</p>
      </div>

      {requested && !installedOn && (
        <div role="note" className="bg-amber-50 border border-amber-200 rounded-2xl p-4 space-y-1">
          <p className="text-sm font-bold text-amber-900">Your install request is waiting for approval</p>
          <p className="text-xs text-amber-800 leading-relaxed">
            You asked to install the app on a GitHub organisation you don&apos;t own, so GitHub sent the request to that organisation&apos;s owner. The app is not installed there until an owner approves it (GitHub &rarr; the organisation&apos;s Settings &rarr; GitHub Apps &rarr; Pending requests). Once approved, come back here, or install it on your own account instead.
          </p>
        </div>
      )}
      {installedOn ? (
        <div className="bg-emerald-50 border border-emerald-200 rounded-2xl p-4 space-y-1">
          <p className="text-sm font-bold text-emerald-900">✓ GitHub App installed on {installedOn}</p>
          <p className="text-xs text-emerald-800 leading-relaxed">Check the details below and continue. Open or update a pull request on one of the repositories you selected and it will be scanned.</p>
          {info?.install_url && <a href={info.install_url} className="inline-block text-xs font-semibold text-emerald-900 underline underline-offset-2">Install on another account</a>}
        </div>
      ) : infoFailed ? (
        <div className="bg-amber-50 border border-amber-200 rounded-2xl p-4 space-y-2">
          <p className="text-sm text-amber-900">We couldn&apos;t check the GitHub connection just now.</p>
          <button type="button" onClick={loadInfo} className="text-xs font-bold text-amber-900 underline underline-offset-2">Try again</button>
        </div>
      ) : !info ? (
        <div className="h-24 rounded-2xl bg-gray-50 border border-gray-100 animate-pulse" aria-label="Checking the GitHub connection" />
      ) : !info.configured ? (
        <div className="bg-amber-50 border border-amber-200 rounded-2xl p-4 space-y-2">
          <p className="text-sm font-bold text-amber-900">TrustLedger isn&apos;t connected to GitHub yet</p>
          <p className="text-xs text-amber-800 leading-relaxed">
            The GitHub App is created once, by whoever runs this TrustLedger deployment. Ask them to finish that, then come back and click Install.
          </p>
          <a href="/setup/github-app" className="inline-block text-xs font-bold text-amber-900 underline underline-offset-2">
            I run this deployment: set up the GitHub App →
          </a>
        </div>
      ) : info.install_url ? (
        <div className="bg-indigo-50 rounded-2xl p-4 border border-indigo-100 space-y-3">
          <p className="text-sm font-bold text-indigo-900">Install the TrustLedger GitHub App</p>
          <p className="text-xs text-indigo-800 leading-relaxed">
            Click the button, choose your GitHub organisation, and select the repositories you want scanned. One repository is enough to start.
          </p>
          {/* same tab: GitHub sends the person back here when the install is done */}
          <a href={info.install_url}
            className="block text-center text-sm font-bold text-white rounded-xl py-2.5" style={{ background: "#24292f" }}>
            Install on GitHub →
          </a>
          <p className="text-[11px] text-indigo-700 leading-snug">
            GitHub installs on the account you are <strong>signed into in this browser</strong>: check the avatar at the top right of the GitHub page before you confirm.
            To use a different account, <a href="https://github.com/logout" target="_blank" rel="noopener noreferrer" className="font-bold underline underline-offset-2">sign out of GitHub first</a>, then click Install again.
          </p>
        </div>
      ) : (
        <div className="bg-amber-50 border border-amber-200 rounded-2xl p-4 space-y-2">
          <p className="text-sm text-amber-900">We couldn&apos;t get the GitHub install link just now.</p>
          <button type="button" onClick={loadInfo} className="text-xs font-bold text-amber-900 underline underline-offset-2">Try again</button>
        </div>
      )}

      {/* The handle: what it is, why it matters, what will be saved */}
      <div className="space-y-3">
        <div role="note" className="rounded-2xl border border-indigo-100 bg-indigo-50/60 p-4 space-y-2.5">
          <p className="text-sm font-bold text-indigo-950">What is the GitHub account name?</p>
          <p className="text-xs text-indigo-900 leading-relaxed">
            It is the name that comes right after <span className="font-mono">github.com/</span> in your repository addresses:
          </p>
          <p className="rounded-lg bg-white border border-indigo-100 px-3 py-2 font-mono text-[12px] text-gray-500 break-all">
            github.com/<strong className="text-indigo-700 bg-indigo-50 px-1 rounded">acme-corp</strong>/payments-api
          </p>
          <ul className="text-xs text-indigo-900 leading-relaxed space-y-1 list-disc pl-4">
            <li>TrustLedger matches every pull request to your TrustLedger organisation{orgName ? <> (<strong>{orgName}</strong>)</> : null} by this name. <strong>If it does not match, pull requests are not scanned.</strong></li>
            <li>It can be a company account or your own personal account: whichever owns the repositories you want scanned.</li>
            <li>It is <strong>not</strong> your email address, your TrustLedger organisation&apos;s name or a full repository link.</li>
            <li>One GitHub account can be linked to one TrustLedger organisation.</li>
          </ul>
        </div>

        {savedHandle && !installedOn && (
          <p className="text-xs text-gray-600">
            Currently linked: <span className="font-mono font-semibold text-gray-900">github.com/{savedHandle}</span>. Change it below if that is wrong.
          </p>
        )}

        <div>
          <label htmlFor="gh-handle" className="text-xs font-semibold text-gray-700 block mb-1.5">
            GitHub account that owns the repositories
          </label>
          <div className={`flex items-stretch rounded-xl border bg-white focus-within:ring-2 focus-within:ring-indigo-400 ${touched && !parsed.ok ? "border-rose-300" : "border-gray-200"}`}>
            <span className="flex items-center pl-3 pr-1 text-sm font-mono text-gray-400 select-none">github.com/</span>
            <input id="gh-handle" value={orgHandle} onChange={e => { setOrgHandle(e.target.value); setSaveError(null); }} onBlur={() => setTouched(true)}
              placeholder="acme-corp" autoComplete="off" autoCapitalize="none" spellCheck={false}
              aria-invalid={touched && !parsed.ok} aria-describedby="gh-handle-help"
              className="min-w-0 flex-1 text-sm rounded-r-xl pl-0 pr-4 py-2.5 focus:outline-none font-mono bg-transparent" />
          </div>
          <div id="gh-handle-help" className="mt-1.5 space-y-1.5">
            {installedOn && parsed.ok && parsed.handle === installedOn.toLowerCase() && (
              <p className="text-[11px] text-emerald-700">✓ Filled in from your GitHub installation on <span className="font-mono">{installedOn}</span>.</p>
            )}
            {touched && !parsed.ok && <p role="alert" className="text-[11px] text-rose-700">{parsed.message}</p>}
            {parsed.ok && (
              <p className="text-[11px] text-gray-600 leading-snug">
                Pull requests in <span className="font-mono font-semibold text-gray-900">github.com/{parsed.handle}/…</span> will be scanned in {orgName ? <strong>{orgName}</strong> : "your TrustLedger organisation"}.
                {parsed.changed && <span className="text-gray-500"> (We tidied what you typed; this is what will be saved.)</span>}
              </p>
            )}
            {installedDiffers && (
              <div role="alert" className="rounded-xl border border-amber-200 bg-amber-50 p-2.5 space-y-1">
                <p className="text-[11px] text-amber-900 leading-snug">
                  You installed the app on <strong className="font-mono">{installedOn}</strong>, but this says <strong className="font-mono">{parsed.ok ? parsed.handle : ""}</strong>.
                  Pull requests are matched on this name, so repositories owned by <span className="font-mono">{installedOn}</span> would not be scanned.
                </p>
                <button type="button" onClick={() => setOrgHandle(installedOn!)} className="text-[11px] font-bold text-amber-900 underline underline-offset-2">
                  Use {installedOn}
                </button>
              </div>
            )}
          </div>
        </div>

        <div>
          <label htmlFor="gh-login" className="text-xs font-semibold text-gray-700 block mb-1.5">
            Your own GitHub username <span className="text-gray-400 font-normal">(optional)</span>
          </label>
          <input id="gh-login" value={githubLogin} onChange={e => setGithubLogin(e.target.value)} placeholder="your-github-handle" autoComplete="off" autoCapitalize="none" spellCheck={false}
            className="w-full text-sm border border-gray-200 rounded-xl px-4 py-2.5 focus:outline-none focus:ring-2 focus:ring-indigo-400 font-mono" />
          <p className="mt-1.5 text-[11px] text-gray-500 leading-snug">
            You, personally. It only lets TrustLedger show you the pull requests you wrote. It can be the same as the account above if you use a personal account.
          </p>
        </div>
      </div>

      {saveError && <p role="alert" className="text-xs text-rose-700 bg-rose-50 border border-rose-200 rounded-xl px-3 py-2">{saveError}</p>}
      <PrimaryBtn onClick={save} disabled={saving || !orgHandle.trim()}>
        {saving ? "Saving…" : "Save and continue →"}
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

// ── Who is signed in ────────────────────────────────────────────────────────

/** Shown on every step: which person, how they signed in and which TrustLedger organisation this setup is for. Setting up under the
 * wrong account (a different GitHub login in the same browser) is the most common way a customer ends up with a handle on the wrong
 * organisation, so it is stated plainly, with a way out. */
function SignedInAs() {
  const { user, profile, signOut } = useAuth();
  const router = useRouter();
  if (!user && !profile) return null;
  const meta = (user?.user_metadata ?? {}) as Record<string, unknown>;
  const provider = (user?.app_metadata as { provider?: string } | undefined)?.provider;
  const email = profile?.email || user?.email || "";
  const name = profile?.name || (typeof meta.full_name === "string" ? meta.full_name : "") || "";
  const ghLogin = profile?.github_login || (typeof meta.user_name === "string" ? meta.user_name : "") || (typeof meta.preferred_username === "string" ? meta.preferred_username : "");
  const viaGithub = provider === "github";
  const initial = (name || email || "?").trim().charAt(0).toUpperCase();
  const role = (profile?.role ?? "").replace(/_/g, " ");
  return (
    <div data-testid="signed-in-as" className="mb-4 flex items-center gap-3 rounded-2xl border border-gray-200 bg-white/80 px-4 py-3">
      <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-indigo-600 text-sm font-bold text-white" aria-hidden>{initial}</span>
      <div className="min-w-0 flex-1 text-xs leading-snug">
        <p className="text-gray-500">Signed in as</p>
        <p className="truncate font-semibold text-gray-900">{name || email || "your account"}{name && email ? <span className="font-normal text-gray-500"> · {email}</span> : null}</p>
        <p className="break-words text-gray-500">
          {viaGithub ? <>with GitHub{ghLogin ? <> (<span className="font-mono">@{ghLogin}</span>)</> : null}</> : provider === "email" ? "with email and password" : null}
          {profile?.org_name ? <>{viaGithub || provider === "email" ? " · " : ""}organisation <strong className="text-gray-700">{profile.org_name}</strong>{role ? ` (${role})` : ""}</> : null}
        </p>
      </div>
      {signOut && (
        <button type="button" onClick={async () => { await signOut(); router.push("/login"); }}
          className="shrink-0 text-xs font-semibold text-gray-500 underline underline-offset-2 hover:text-gray-800">
          Not you? Sign out
        </button>
      )}
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function OnboardingPage() {
  // The same five steps until setup is finished. Finished steps are remembered (lib/onboardingProgress.ts) and show as
  // done; the wizard reopens at the first one still to do. Leaving part-way does not complete setup.
  const [stepIdx, setStepIdx] = useState<number>(0);
  const [done, setDone] = useState<WizardStep[]>([]);
  const [ready, setReady] = useState(false);
  useEffect(() => {
    const saved = loadDoneSteps();
    setDone(saved);
    setStepIdx(firstUnfinishedIndex(saved));
    setReady(true);
  }, []);

  const step = STEPS[stepIdx].key;
  const router = useRouter();

  // Leave the wizard without finishing: setup is NOT marked complete, so the overview keeps offering it
  function skip() {
    router.push("/dashboard");
  }

  function next() {
    const next = Math.min(stepIdx + 1, STEPS.length - 1);
    setDone(markStepDone(STEPS[stepIdx].key));      // this step is finished: remembered, shown as done
    setStepIdx(next);

    // Mark org as onboarding_complete when reaching the done step
    if (next === STEPS.length - 1) {
      authedFetch("/api/onboarding", {
        method: "POST",
        body: JSON.stringify({ action: "complete" }),
      }).catch(() => {});
      clearDoneSteps();     // finished: nothing left to remember
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
                    width:        i === stepIdx || done.includes(s.key) ? 28 : 8,
                    height:       8,
                    borderRadius: 4,
                    background:   done.includes(s.key) ? "#10b981" : i === stepIdx ? "#6366f1" : "#e2e8f0",
                    transition:   "all 0.3s ease",
                  }}>
                  {done.includes(s.key) && (
                    <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">
                      <polyline points="20 6 9 17 4 12"/>
                    </svg>
                  )}
                </div>
                {i < STEPS.length - 1 && (
                  <div className="w-4 h-0.5 rounded-full" style={{ background: done.includes(s.key) ? "#10b981" : "#e2e8f0" }} />
                )}
              </div>
            ))}
          </div>
          <p className="text-center text-xs text-gray-400">
            Step {stepIdx + 1} of {STEPS.length} —{" "}
            <span className="font-semibold text-gray-600">{STEPS[stepIdx].label}</span>
            {done.length > 0 && step !== "done" && <span className="text-gray-400"> · {done.length} of {STEPS.length - 1} done</span>}
          </p>
        </div>

        <SignedInAs />

        {/* Card */}
        <div className="bg-white rounded-3xl shadow-xl border border-gray-100 p-8 min-h-[12rem]">
          {ready && step === "welcome" && <WelcomeStep onNext={next} />}
          {ready && step === "github"  && <GithubStep  onNext={next} />}
          {ready && step === "team"    && <TeamStep    onNext={next} />}
          {ready && step === "policy"  && <PolicyStep  onNext={next} />}
          {ready && step === "done"    && <DoneStep />}
        </div>

        {/* Back link (except welcome and done) */}
        {stepIdx > 0 && stepIdx < STEPS.length - 1 && (
          <button onClick={() => setStepIdx(stepIdx - 1)}
            className="mt-4 w-full text-center text-xs text-gray-400 hover:text-gray-600 transition-colors">
            ← Back
          </button>
        )}

        {stepIdx < STEPS.length - 1 && (
          <button onClick={skip} className="mt-2 w-full text-center text-xs text-gray-400 hover:text-gray-600 underline underline-offset-2 transition-colors">
            Skip for now — your overview will keep offering setup until it is finished
          </button>
        )}

      </div>
    </div>
  );
}
