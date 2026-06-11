"use client";

import { useState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { authedFetch } from "@/lib/useRealData";

// ── Step definitions ──────────────────────────────────────────────────────────

type Step = "welcome" | "github" | "scan" | "team" | "policy" | "done";

const STEPS: { key: Step; label: string; desc: string }[] = [
  { key:"welcome", label:"Welcome",        desc:"Introduction"               },
  { key:"github",  label:"Connect GitHub", desc:"Link your GitHub org"       },
  { key:"scan",    label:"First Scan",     desc:"Scan a pull request"        },
  { key:"team",    label:"Invite Team",    desc:"Add security reviewers"     },
  { key:"policy",  label:"Set Policy",     desc:"Configure your gate"        },
  { key:"done",    label:"Ready",          desc:"You're all set!"            },
];

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
    <svg width="22" height="22" viewBox="0 0 24 24" fill="currentColor">
      <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z"/>
    </svg>
  );
}

// ── Step components ───────────────────────────────────────────────────────────

function WelcomeStep({ onNext }: { onNext: () => void }) {
  const { profile } = useAuth();
  return (
    <div className="text-center space-y-6">
      <div className="w-20 h-20 rounded-3xl flex items-center justify-center mx-auto text-white"
        style={{ background:"linear-gradient(135deg,#6366f1,#7c3aed)", boxShadow:"0 8px 32px rgba(99,102,241,0.4)" }}>
        <ShieldIcon />
      </div>
      <div>
        <h2 className="text-2xl font-black text-gray-900">
          Welcome{profile?.name ? `, ${profile.name.split(" ")[0]}` : ""}!
        </h2>
        <p className="text-gray-500 mt-2 max-w-sm mx-auto text-sm leading-relaxed">
          TrustLedger scans every pull request for AI-generated code, enforces reviewer attestation,
          and generates signed compliance reports — in under 5 minutes.
        </p>
      </div>
      <div className="grid grid-cols-3 gap-4 max-w-md mx-auto text-center">
        {[
          { icon:"🔍", title:"Scan", desc:"Every PR analysed for AI content" },
          { icon:"✅", title:"Attest", desc:"Reviewers sign off on AI code" },
          { icon:"📋", title:"Report", desc:"SOC 2, PCI-DSS, EU AI Act" },
        ].map(f => (
          <div key={f.title} className="bg-gray-50 rounded-2xl p-4 border border-gray-100">
            <div className="text-2xl mb-2">{f.icon}</div>
            <p className="text-xs font-black text-gray-900">{f.title}</p>
            <p className="text-[10px] text-gray-500 mt-0.5 leading-snug">{f.desc}</p>
          </div>
        ))}
      </div>
      <button onClick={onNext}
        className="px-8 py-3 rounded-2xl font-bold text-white text-sm transition-all hover:scale-105"
        style={{ background:"linear-gradient(135deg,#6366f1,#7c3aed)", boxShadow:"0 4px 20px rgba(99,102,241,0.35)" }}>
        Get started →
      </button>
      <p className="text-xs text-gray-400">Takes about 5 minutes</p>
    </div>
  );
}

function GithubStep({ onNext }: { onNext: (data: Record<string, string>) => void }) {
  const { profile } = useAuth();
  const [orgHandle,   setOrgHandle]   = useState(profile?.org_slug ?? "");
  const [webhookSecret, setWebhookSecret] = useState("");
  const [copied,  setCopied]  = useState<string | null>(null);
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

  return (
    <div className="space-y-6">
      <div className="text-center">
        <div className="w-14 h-14 rounded-2xl bg-gray-900 flex items-center justify-center mx-auto mb-4 text-white">
          <GithubIcon />
        </div>
        <h2 className="text-xl font-black text-gray-900">Connect GitHub</h2>
        <p className="text-sm text-gray-500 mt-1">Install the TrustLedger GitHub App and configure the webhook.</p>
      </div>

      <div className="space-y-4">
        {/* Step 1 — Install app */}
        <div className="bg-indigo-50 rounded-2xl p-5 border border-indigo-100">
          <div className="flex items-center gap-2 mb-3">
            <span className="w-6 h-6 rounded-full bg-indigo-600 text-white text-xs font-black flex items-center justify-center shrink-0">1</span>
            <p className="text-sm font-bold text-indigo-900">Install TrustLedger GitHub App</p>
          </div>
          <p className="text-xs text-indigo-700 mb-3">Install on your GitHub organisation to allow scanning pull requests and posting check results.</p>
          <a
            href={`https://github.com/apps/trustledger/installations/new${orgHandle ? `?target_id=${orgHandle}` : ""}`}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-2 px-4 py-2 rounded-xl text-sm font-bold text-white transition-all"
            style={{ background:"#24292f" }}
          >
            <GithubIcon />
            Install on GitHub →
          </a>
        </div>

        {/* Step 2 — Webhook config */}
        <div className="bg-gray-50 rounded-2xl p-5 border border-gray-100 space-y-3">
          <div className="flex items-center gap-2 mb-1">
            <span className="w-6 h-6 rounded-full bg-gray-600 text-white text-xs font-black flex items-center justify-center shrink-0">2</span>
            <p className="text-sm font-bold text-gray-900">Configure webhook (in GitHub App settings)</p>
          </div>

          {[
            { label:"Webhook URL",    value:`${appUrl}/api/webhook/github`,  key:"url"    },
            { label:"Webhook Secret", value:webhookSecret,                   key:"secret" },
          ].map(row => (
            <div key={row.key}>
              <p className="text-xs font-semibold text-gray-500 mb-1">{row.label}</p>
              <div className="flex items-center gap-2 bg-white rounded-xl border border-gray-200 px-3 py-2.5">
                <code className="text-xs font-mono text-gray-700 flex-1 truncate select-all">{row.value}</code>
                <button onClick={() => copy(row.value, row.key)}
                  className="shrink-0 text-xs font-bold px-2.5 py-1 rounded-lg transition-colors"
                  style={{ background: copied===row.key ? "#d1fae5" : "#f1f5f9", color: copied===row.key ? "#065f46" : "#374151" }}>
                  {copied === row.key ? "Copied!" : "Copy"}
                </button>
              </div>
            </div>
          ))}
          <p className="text-[10px] text-gray-400">Select events: Pull requests, Pushes, Check runs</p>
        </div>

        {/* Step 3 — GitHub org */}
        <div className="space-y-2">
          <label className="block">
            <span className="text-xs font-semibold text-gray-700 block mb-1.5">Your GitHub organisation handle</span>
            <input value={orgHandle} onChange={e => setOrgHandle(e.target.value)}
              placeholder="acme-corp"
              className="w-full text-sm border border-gray-200 rounded-xl px-4 py-3 focus:outline-none focus:ring-2 focus:ring-indigo-400 font-mono" />
          </label>
        </div>
      </div>

      <button
        onClick={() => onNext({ github_org: orgHandle, webhook_secret: webhookSecret })}
        disabled={!orgHandle.trim()}
        className="w-full py-3 rounded-2xl font-bold text-white text-sm transition-all disabled:opacity-50"
        style={{ background:"linear-gradient(135deg,#6366f1,#7c3aed)" }}>
        I&apos;ve installed the app →
      </button>
    </div>
  );
}

function ScanStep({ onNext }: { onNext: (data: Record<string, string>) => void }) {
  const [repo,    setRepo]    = useState("");
  const [pr,      setPr]      = useState("");
  const [sha,     setSha]     = useState("");
  const [scanning, setScanning] = useState(false);
  const [result,  setResult]  = useState<{ overall_risk: string; file_count: number; scan_id: string } | null>(null);
  const [error,   setError]   = useState<string | null>(null);
  const { profile } = useAuth();
  const ORG = profile?.org_slug ?? "your-org";

  async function runScan() {
    setScanning(true); setError(null); setResult(null);
    try {
      const res = await authedFetch<{ overall_risk: string; file_count: number; scan_id: string }>("/api/scans", {
        method: "POST",
        body:   JSON.stringify({
          repo:       repo || `${ORG}/payments-api`,
          pr_number:  parseInt(pr || "1"),
          commit_sha: sha || "demo",
          files:      [
            { path:"src/processors/card_validator.py", content:`import psycopg2\nSECRET = "sk_live_demo"\ndef process(user_id):\n    q = f"SELECT * FROM cards WHERE id = '{user_id}'"\n    # AI-generated: direct interpolation` },
            { path:"src/utils/helper.ts", content:`// Helper utilities\nexport function formatCurrency(amount: number, currency: string): string {\n  return new Intl.NumberFormat('en-US', { style: 'currency', currency }).format(amount);\n}` },
          ],
        }),
      });
      setResult(res);
    } catch (e) {
      setError(String(e));
    } finally {
      setScanning(false);
    }
  }

  return (
    <div className="space-y-6">
      <div className="text-center">
        <div className="text-4xl mb-3">🔍</div>
        <h2 className="text-xl font-black text-gray-900">Run your first scan</h2>
        <p className="text-sm text-gray-500 mt-1">Try scanning a PR from your codebase, or use our demo scan.</p>
      </div>

      {!result ? (
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-3">
            <label className="block">
              <span className="text-xs font-semibold text-gray-600 block mb-1">Repository (optional)</span>
              <input value={repo} onChange={e => setRepo(e.target.value)} placeholder={`${ORG}/my-repo`}
                className="w-full text-sm border border-gray-200 rounded-xl px-3.5 py-2.5 focus:outline-none focus:ring-2 focus:ring-indigo-400" />
            </label>
            <label className="block">
              <span className="text-xs font-semibold text-gray-600 block mb-1">PR number (optional)</span>
              <input value={pr} onChange={e => setPr(e.target.value)} placeholder="42" type="number"
                className="w-full text-sm border border-gray-200 rounded-xl px-3.5 py-2.5 focus:outline-none focus:ring-2 focus:ring-indigo-400" />
            </label>
          </div>

          {error && <p className="text-xs text-rose-600 bg-rose-50 px-3 py-2 rounded-xl border border-rose-200">{error}</p>}

          <div className="flex gap-3">
            <button onClick={runScan} disabled={scanning}
              className="flex-1 py-3 rounded-2xl font-bold text-white text-sm transition-all disabled:opacity-60"
              style={{ background:"linear-gradient(135deg,#6366f1,#7c3aed)" }}>
              {scanning ? "Scanning…" : "Run demo scan"}
            </button>
            <button onClick={() => onNext({})} className="px-5 py-3 rounded-2xl font-semibold text-gray-500 border border-gray-200 hover:border-gray-300 text-sm">
              Skip
            </button>
          </div>
        </div>
      ) : (
        <div className="space-y-4">
          <div className="bg-emerald-50 rounded-2xl p-5 border border-emerald-200">
            <div className="flex items-center gap-3 mb-3">
              <span className="text-2xl">✅</span>
              <div>
                <p className="font-black text-emerald-800">Scan complete!</p>
                <p className="text-xs text-emerald-600">Scan ID: {result.scan_id}</p>
              </div>
            </div>
            <div className="grid grid-cols-3 gap-3">
              {[
                { label:"Overall Risk",   value:result.overall_risk },
                { label:"Files Scanned",  value:String(result.file_count) },
                { label:"Scan ID",        value:result.scan_id.slice(0, 8) + "…" },
              ].map(s => (
                <div key={s.label} className="bg-white rounded-xl p-3 text-center border border-emerald-100">
                  <p className="text-sm font-black text-gray-900">{s.value}</p>
                  <p className="text-[10px] text-gray-400 mt-0.5">{s.label}</p>
                </div>
              ))}
            </div>
          </div>
          <button onClick={() => onNext({ scan_id: result.scan_id })}
            className="w-full py-3 rounded-2xl font-bold text-white text-sm"
            style={{ background:"linear-gradient(135deg,#6366f1,#7c3aed)" }}>
            Continue →
          </button>
        </div>
      )}
    </div>
  );
}

function TeamStep({ onNext }: { onNext: (data: Record<string, string>) => void }) {
  const [emails,   setEmails]   = useState("");
  const [inviting, setInviting] = useState(false);
  const [invited,  setInvited]  = useState(false);

  async function invite() {
    if (!emails.trim()) { onNext({}); return; }
    setInviting(true);
    const list = emails.split(/[\n,;]+/).map(e => e.trim()).filter(e => e.includes("@"));
    await Promise.all(
      list.map(email =>
        authedFetch("/api/settings", {
          method: "POST",
          body:   JSON.stringify({ action: "invite_member", email, role: "security_reviewer" }),
        }).catch(() => {})
      )
    );
    setInvited(true);
    setInviting(false);
  }

  return (
    <div className="space-y-6">
      <div className="text-center">
        <div className="text-4xl mb-3">👥</div>
        <h2 className="text-xl font-black text-gray-900">Invite your team</h2>
        <p className="text-sm text-gray-500 mt-1">Add security reviewers who will attest AI-generated code before it merges.</p>
      </div>

      {!invited ? (
        <div className="space-y-4">
          <label className="block">
            <span className="text-xs font-semibold text-gray-600 block mb-1.5">Reviewer email addresses</span>
            <textarea value={emails} onChange={e => setEmails(e.target.value)} rows={4}
              placeholder={"alice@company.com\nbob@company.com\ncarol@company.com"}
              className="w-full text-sm border border-gray-200 rounded-xl px-4 py-3 focus:outline-none focus:ring-2 focus:ring-indigo-400 resize-none" />
            <p className="text-[10px] text-gray-400 mt-1">One per line, or comma-separated. They'll receive a magic link to join.</p>
          </label>
          <div className="flex gap-3">
            <button onClick={invite} disabled={inviting}
              className="flex-1 py-3 rounded-2xl font-bold text-white text-sm disabled:opacity-60"
              style={{ background:"linear-gradient(135deg,#6366f1,#7c3aed)" }}>
              {inviting ? "Sending invites…" : "Send invites"}
            </button>
            <button onClick={() => onNext({})} className="px-5 py-3 rounded-2xl font-semibold text-gray-500 border border-gray-200 text-sm">
              Skip
            </button>
          </div>
        </div>
      ) : (
        <div className="space-y-4">
          <div className="bg-emerald-50 rounded-2xl p-5 border border-emerald-200 text-center">
            <p className="text-2xl mb-2">🎉</p>
            <p className="font-black text-emerald-800">Invites sent!</p>
            <p className="text-xs text-emerald-600 mt-1">
              {emails.split(/[\n,;]+/).filter(e => e.trim().includes("@")).length} invite(s) sent via email.
            </p>
          </div>
          <button onClick={() => onNext({ invited: "true" })}
            className="w-full py-3 rounded-2xl font-bold text-white text-sm"
            style={{ background:"linear-gradient(135deg,#6366f1,#7c3aed)" }}>
            Continue →
          </button>
        </div>
      )}
    </div>
  );
}

function PolicyStep({ onNext }: { onNext: (data: Record<string, string>) => void }) {
  const [preset, setPreset] = useState<"standard" | "strict" | "custom">("standard");
  const [saving, setSaving] = useState(false);

  const PRESETS = {
    standard: { label:"Standard",     desc:"Block CRITICAL, warn on HIGH. 24h attestation SLA.", ai:0.80, sla:24, blockCrit:true,  blockHigh:false },
    strict:   { label:"Strict",       desc:"Block CRITICAL + HIGH. 12h SLA. Dual reviewer required.", ai:0.70, sla:12, blockCrit:true,  blockHigh:true  },
    custom:   { label:"Custom",       desc:"Configure your own thresholds in Settings → Policies.", ai:0.80, sla:24, blockCrit:true,  blockHigh:false },
  };

  async function save() {
    setSaving(true);
    const cfg = PRESETS[preset];
    await authedFetch("/api/settings", {
      method: "PATCH",
      body:   JSON.stringify({
        ai_threshold:      cfg.ai,
        attest_sla_hours:  cfg.sla,
        block_on_critical: cfg.blockCrit,
        block_on_high:     cfg.blockHigh,
      }),
    }).catch(() => {});
    setSaving(false);
    onNext({ policy: preset });
  }

  return (
    <div className="space-y-6">
      <div className="text-center">
        <div className="text-4xl mb-3">⚙️</div>
        <h2 className="text-xl font-black text-gray-900">Set your policy</h2>
        <p className="text-sm text-gray-500 mt-1">Choose how strictly TrustLedger gates your AI-generated code.</p>
      </div>

      <div className="space-y-3">
        {(Object.entries(PRESETS) as [typeof preset, typeof PRESETS[typeof preset]][]).map(([key, cfg]) => (
          <button
            key={key}
            onClick={() => setPreset(key)}
            className={`w-full text-left p-4 rounded-2xl border-2 transition-all ${
              preset === key ? "border-indigo-500 bg-indigo-50" : "border-gray-200 bg-white hover:border-indigo-200"
            }`}
          >
            <div className="flex items-center justify-between gap-3 mb-1">
              <p className="text-sm font-black text-gray-900">{cfg.label}</p>
              <div className="flex gap-2">
                <span className="text-[9px] font-bold px-2 py-0.5 rounded-full bg-gray-100 text-gray-600">
                  AI&gt;{(cfg.ai*100).toFixed(0)}%
                </span>
                <span className="text-[9px] font-bold px-2 py-0.5 rounded-full bg-gray-100 text-gray-600">
                  SLA {cfg.sla}h
                </span>
                {cfg.blockHigh && (
                  <span className="text-[9px] font-bold px-2 py-0.5 rounded-full bg-orange-100 text-orange-700">
                    Blocks HIGH
                  </span>
                )}
              </div>
            </div>
            <p className="text-xs text-gray-500">{cfg.desc}</p>
          </button>
        ))}
      </div>

      <button onClick={save} disabled={saving}
        className="w-full py-3 rounded-2xl font-bold text-white text-sm disabled:opacity-60"
        style={{ background:"linear-gradient(135deg,#6366f1,#7c3aed)" }}>
        {saving ? "Saving…" : "Apply policy →"}
      </button>
    </div>
  );
}

function DoneStep() {
  const router = useRouter();
  return (
    <div className="text-center space-y-6">
      <div className="text-6xl">🎉</div>
      <div>
        <h2 className="text-2xl font-black text-gray-900">You&apos;re all set!</h2>
        <p className="text-sm text-gray-500 mt-2 max-w-sm mx-auto leading-relaxed">
          TrustLedger is connected and ready to scan. Your next pull request will be automatically analysed.
        </p>
      </div>
      <div className="grid grid-cols-2 gap-3 max-w-sm mx-auto">
        {[
          { icon:"📊", title:"View dashboard",  href:"/dashboard"  },
          { icon:"🔐", title:"Review policies", href:"/settings"   },
          { icon:"📋", title:"See compliance",  href:"/compliance" },
          { icon:"📖", title:"Read the docs",   href:"https://docs.trustledger.dev" },
        ].map(l => (
          <button key={l.title}
            onClick={() => { if (l.href.startsWith("http")) window.open(l.href,"_blank"); else router.push(l.href); }}
            className="flex items-center gap-2 p-4 rounded-2xl border border-gray-200 hover:border-indigo-300 hover:bg-indigo-50 transition-all text-left group">
            <span className="text-xl">{l.icon}</span>
            <span className="text-sm font-semibold text-gray-700 group-hover:text-indigo-700">{l.title}</span>
          </button>
        ))}
      </div>
      <button onClick={() => router.push("/dashboard")}
        className="px-10 py-3 rounded-2xl font-bold text-white text-sm"
        style={{ background:"linear-gradient(135deg,#6366f1,#7c3aed)", boxShadow:"0 4px 20px rgba(99,102,241,0.35)" }}>
        Go to dashboard →
      </button>
    </div>
  );
}

// ── Main page ─────────────────────────────────────────────────────────────────

export default function OnboardingPage() {
  const [stepIdx, setStepIdx] = useState(0);
  const step = STEPS[stepIdx].key;

  function next() { setStepIdx(i => Math.min(i + 1, STEPS.length - 1)); }

  return (
    <div className="min-h-screen flex items-center justify-center px-4 py-12"
      style={{ background:"linear-gradient(135deg,#f8fafc 0%,#eff6ff 50%,#f8fafc 100%)" }}>
      <div className="w-full max-w-lg">

        {/* Progress */}
        <div className="mb-8">
          <div className="flex items-center justify-center gap-1 mb-4">
            {STEPS.map((s, i) => (
              <div key={s.key} className="flex items-center gap-1">
                <div
                  className="flex items-center justify-center transition-all"
                  style={{
                    width:  i <= stepIdx ? 28 : 8,
                    height: 8,
                    borderRadius: 4,
                    background: i < stepIdx ? "#10b981" : i === stepIdx ? "#6366f1" : "#e2e8f0",
                    transition: "all 0.3s",
                  }}
                >
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
            Step {stepIdx + 1} of {STEPS.length} — <span className="font-semibold text-gray-600">{STEPS[stepIdx].label}</span>
          </p>
        </div>

        {/* Card */}
        <div className="bg-white rounded-3xl shadow-xl border border-gray-100 p-8">
          {step === "welcome" && <WelcomeStep onNext={next} />}
          {step === "github"  && <GithubStep  onNext={() => next()} />}
          {step === "scan"    && <ScanStep    onNext={() => next()} />}
          {step === "team"    && <TeamStep    onNext={() => next()} />}
          {step === "policy"  && <PolicyStep  onNext={() => next()} />}
          {step === "done"    && <DoneStep />}
        </div>

      </div>
    </div>
  );
}
