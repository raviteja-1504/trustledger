"use client";

import { useState, useEffect } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { supabase } from "@/lib/supabase";

const SKIP_AUTH = process.env.NEXT_PUBLIC_SKIP_AUTH === "true";

function ShieldIcon() {
  return (
    <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      <polyline points="9 12 11 14 15 10"/>
    </svg>
  );
}

const DEMO_ROLES = [
  {
    role:    "admin",
    label:   "Admin",
    name:    "Alex Admin",
    email:   "admin@trustledger.dev",
    icon:    "👑",
    color:   "#7c3aed",
    bg:      "rgba(124,58,237,0.12)",
    border:  "rgba(124,58,237,0.3)",
    desc:    "Full access — settings, team management, all features",
    badges:  ["Settings", "Team", "Reports", "Attestation"],
  },
  {
    role:    "security_reviewer",
    label:   "Security Reviewer",
    name:    "Sam Security",
    email:   "security@trustledger.dev",
    icon:    "🛡️",
    color:   "#d97706",
    bg:      "rgba(217,119,6,0.12)",
    border:  "rgba(217,119,6,0.3)",
    desc:    "Attest files, view violations, export compliance reports",
    badges:  ["Attest", "Violations", "Compliance"],
  },
  {
    role:    "developer",
    label:   "Developer",
    name:    "Dev User",
    email:   "dev@trustledger.dev",
    icon:    "💻",
    color:   "#0ea5e9",
    bg:      "rgba(14,165,233,0.12)",
    border:  "rgba(14,165,233,0.3)",
    desc:    "View scans, dashboard, and reports — read-only access",
    badges:  ["View Scans", "Dashboard", "Reports"],
  },
  {
    role:    "auditor",
    label:   "Auditor",
    name:    "Alice Auditor",
    email:   "auditor@trustledger.dev",
    icon:    "📋",
    color:   "#16a34a",
    bg:      "rgba(22,163,74,0.12)",
    border:  "rgba(22,163,74,0.3)",
    desc:    "Read-only access to compliance reports and audit trail",
    badges:  ["Audit Trail", "Compliance", "Export"],
  },
];

// ── Demo login page (SKIP_AUTH=true) ─────────────────────────────────────────

function DemoLoginPage() {
  const router = useRouter();
  const [selected, setSelected] = useState("admin");

  function loginAs(role: string) {
    localStorage.setItem("tl_demo_role", role);
    localStorage.setItem("tl_role_dev", role);
    // Reload so auth context picks up the new role
    window.location.href = "/dashboard";
  }

  return (
    <div className="min-h-screen flex items-center justify-center"
      style={{ background: "linear-gradient(135deg,#0f172a 0%,#1e1040 50%,#0f172a 100%)" }}>
      <div className="w-full max-w-2xl px-4">

        {/* Logo */}
        <div className="flex flex-col items-center mb-10">
          <div className="w-16 h-16 rounded-2xl flex items-center justify-center text-white mb-4"
            style={{ background: "linear-gradient(135deg,#6366f1,#7c3aed)", boxShadow: "0 8px 32px rgba(99,102,241,0.4)" }}>
            <ShieldIcon />
          </div>
          <h1 className="text-2xl font-black text-white tracking-tight">TrustLedger</h1>
          <p className="text-sm mt-1" style={{ color: "rgba(165,180,252,0.7)" }}>AI Code Governance Platform</p>
        </div>

        {/* Demo mode notice */}
        <div className="rounded-xl px-4 py-3 mb-6 text-center"
          style={{ background: "rgba(99,102,241,0.1)", border: "1px solid rgba(99,102,241,0.25)" }}>
          <p className="text-sm font-semibold" style={{ color: "#a5b4fc" }}>
            🎯 Demo Mode — Choose a role to explore TrustLedger
          </p>
          <p className="text-xs mt-1" style={{ color: "rgba(165,180,252,0.5)" }}>
            Each role has different permissions. Switch roles at any time from the sidebar.
          </p>
        </div>

        {/* Role cards */}
        <div className="grid grid-cols-2 gap-4 mb-6">
          {DEMO_ROLES.map(r => (
            <button key={r.role}
              onClick={() => setSelected(r.role)}
              className="text-left rounded-2xl p-5 transition-all"
              style={{
                background:   selected === r.role ? r.bg : "rgba(255,255,255,0.04)",
                border:       selected === r.role ? `1.5px solid ${r.border}` : "1.5px solid rgba(255,255,255,0.08)",
                transform:    selected === r.role ? "scale(1.02)" : "scale(1)",
              }}>
              <div className="flex items-center gap-3 mb-3">
                <span className="text-2xl">{r.icon}</span>
                <div>
                  <div className="font-bold text-white text-sm">{r.label}</div>
                  <div className="text-xs" style={{ color: "rgba(255,255,255,0.4)" }}>{r.email}</div>
                </div>
                {selected === r.role && (
                  <div className="ml-auto w-5 h-5 rounded-full flex items-center justify-center"
                    style={{ background: r.color }}>
                    <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="white" strokeWidth="3">
                      <polyline points="20 6 9 17 4 12"/>
                    </svg>
                  </div>
                )}
              </div>
              <p className="text-xs mb-3" style={{ color: "rgba(255,255,255,0.5)", lineHeight: 1.5 }}>
                {r.desc}
              </p>
              <div className="flex flex-wrap gap-1">
                {r.badges.map(b => (
                  <span key={b} className="text-[10px] font-semibold px-2 py-0.5 rounded-full"
                    style={{ background: `${r.color}22`, color: r.color, border: `1px solid ${r.color}44` }}>
                    {b}
                  </span>
                ))}
              </div>
            </button>
          ))}
        </div>

        {/* Login button */}
        <button
          onClick={() => loginAs(selected)}
          className="w-full py-4 rounded-2xl font-bold text-base text-white transition-all"
          style={{
            background: "linear-gradient(135deg,#6366f1,#7c3aed)",
            boxShadow:  "0 8px 24px rgba(99,102,241,0.4)",
          }}
          onMouseEnter={e => { (e.currentTarget as HTMLElement).style.transform = "translateY(-1px)"; }}
          onMouseLeave={e => { (e.currentTarget as HTMLElement).style.transform = "translateY(0)"; }}
        >
          {DEMO_ROLES.find(r => r.role === selected)?.icon} &nbsp;
          Enter as {DEMO_ROLES.find(r => r.role === selected)?.label}
        </button>

        <p className="mt-4 text-center text-xs" style={{ color: "rgba(255,255,255,0.2)" }}>
          Demo mode — no credentials required · Data stored in browser localStorage
        </p>
      </div>
    </div>
  );
}

// ── Production login page ─────────────────────────────────────────────────────

function GitHubIcon() {
  return (
    <svg width="20" height="20" viewBox="0 0 24 24" fill="currentColor">
      <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z"/>
    </svg>
  );
}

function ProductionLoginPage() {
  const { user, signInWithGitHub, signInWithEmail, signUpWithEmail, resetPassword, loading } = useAuth();
  const router       = useRouter();
  const searchParams = useSearchParams();
  const errorParam   = searchParams?.get("error");
  const [githubBusy, setGithubBusy] = useState(false);

  const [mode,      setMode]      = useState<"signin" | "signup" | "forgot" | "set-password">("signin");
  const [newPass,   setNewPass]   = useState("");
  const [newPassOk, setNewPassOk] = useState<string | null>(null);
  const [showEmail, setShowEmail] = useState(false);
  const [email,     setEmail]     = useState("");
  const [password,  setPassword]  = useState("");
  const [confirm,   setConfirm]   = useState("");
  const [name,      setName]      = useState("");
  const [formErr,   setFormErr]   = useState<string | null>(null);
  const [formOk,    setFormOk]    = useState<string | null>(null);
  const [busy,      setBusy]      = useState(false);

  // Detect PASSWORD_RECOVERY event from Supabase when user clicks the reset link.
  // The link embeds tokens in the URL hash; Supabase JS picks them up and fires
  // PASSWORD_RECOVERY instead of SIGNED_IN, giving us a chance to show the
  // "set new password" form before navigating away.
  useEffect(() => {
    const { data: { subscription } } = supabase.auth.onAuthStateChange((event) => {
      if (event === "PASSWORD_RECOVERY") setMode("set-password");
    });
    return () => subscription.unsubscribe();
  }, []);

  useEffect(() => {
    if (user && mode !== "set-password") router.replace("/dashboard");
  }, [user, router, mode]);

  function switchMode(m: "signin" | "signup" | "forgot") {
    setMode(m); setFormErr(null); setFormOk(null);
    setEmail(""); setPassword(""); setConfirm(""); setName("");
    setShowEmail(m === "signup" || m === "forgot");
  }

  async function handleEmail(e: React.FormEvent) {
    e.preventDefault();
    setFormErr(null); setFormOk(null);
    if (mode === "signup" && password !== confirm) {
      setFormErr("Passwords do not match."); return;
    }
    setBusy(true);
    if (mode === "signin") {
      const { error } = await signInWithEmail(email, password);
      setBusy(false);
      if (error) setFormErr(error);
      else router.replace("/dashboard");
    } else if (mode === "signup") {
      const { error } = await signUpWithEmail(email, password, name);
      setBusy(false);
      if (error) setFormErr(error);
      else setFormOk("Account created! Check your email to confirm your address, then sign in.");
    } else {
      const { error } = await resetPassword(email);
      setBusy(false);
      if (error) setFormErr(error);
      else setFormOk("Password reset email sent — check your inbox and follow the link to set a new password.");
    }
  }

  async function handleSetPassword(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true); setFormErr(null);
    const { error } = await supabase.auth.updateUser({ password: newPass });
    setBusy(false);
    if (error) { setFormErr(error.message); return; }
    setNewPassOk("Password set! Taking you to the dashboard…");
    setTimeout(() => router.replace("/dashboard"), 1500);
  }

  if (loading) return null;

  // Password recovery mode — show set-password form fullscreen, no tabs
  if (mode === "set-password") {
    return (
      <div className="min-h-screen flex flex-col items-center justify-center px-4"
        style={{ background: "linear-gradient(135deg,#0f172a 0%,#1e1040 50%,#0f172a 100%)" }}>
        <div className="w-full max-w-sm">
          <div className="flex flex-col items-center mb-8">
            <div className="w-14 h-14 rounded-2xl flex items-center justify-center text-white mb-4"
              style={{ background: "linear-gradient(135deg,#6366f1,#7c3aed)", boxShadow: "0 8px 32px rgba(99,102,241,0.4)" }}>
              <ShieldIcon />
            </div>
            <h1 className="text-2xl font-black text-white tracking-tight">Set your password</h1>
            <p className="text-sm mt-1" style={{ color: "rgba(165,180,252,0.6)" }}>Choose a password to secure your account</p>
          </div>
          <div className="rounded-2xl p-7 space-y-4" style={{ background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.08)" }}>
            {formErr && <div className="px-3 py-2.5 rounded-xl text-sm text-rose-300 bg-rose-900/30 border border-rose-700/40">{formErr}</div>}
            {newPassOk && <div className="px-3 py-2.5 rounded-xl text-sm text-emerald-300 bg-emerald-900/30 border border-emerald-700/40">{newPassOk}</div>}
            {!newPassOk && (
              <form onSubmit={handleSetPassword} className="space-y-3">
                <input type="password" placeholder="New password (min 8 chars)" value={newPass}
                  onChange={e => setNewPass(e.target.value)} required minLength={8} autoFocus
                  className="w-full px-4 py-2.5 rounded-xl text-sm bg-white/5 border border-white/10 text-white placeholder-white/30 focus:outline-none focus:border-indigo-500" />
                <button type="submit" disabled={busy}
                  className="w-full py-2.5 rounded-xl font-semibold text-sm text-white"
                  style={{ background: "linear-gradient(135deg,#6366f1,#7c3aed)", opacity: busy ? 0.7 : 1 }}>
                  {busy ? "Saving…" : "Set password & sign in"}
                </button>
              </form>
            )}
          </div>
        </div>
      </div>
    );
  }

  const inputCls = "w-full px-4 py-2.5 rounded-xl text-sm bg-white/5 border border-white/10 text-white placeholder-white/30 focus:outline-none focus:border-indigo-500";

  return (
    <div className="min-h-screen flex flex-col items-center justify-center px-4"
      style={{ background: "linear-gradient(135deg,#0f172a 0%,#1e1040 50%,#0f172a 100%)" }}>
      <div className="w-full max-w-sm">

        {/* Branding */}
        <div className="flex flex-col items-center mb-8">
          <div className="w-14 h-14 rounded-2xl flex items-center justify-center text-white mb-4"
            style={{ background: "linear-gradient(135deg,#6366f1,#7c3aed)", boxShadow: "0 8px 32px rgba(99,102,241,0.4)" }}>
            <ShieldIcon />
          </div>
          <h1 className="text-2xl font-black text-white tracking-tight">TrustLedger</h1>
          <p className="text-sm mt-1" style={{ color: "rgba(165,180,252,0.6)" }}>AI Code Governance</p>
        </div>

        {/* Sign in / Sign up toggle */}
        <div className="flex rounded-xl p-1 mb-5" style={{ background: "rgba(255,255,255,0.05)" }}>
          {(["signin","signup","forgot"] as const).map(m => (
            <button key={m} onClick={() => switchMode(m)}
              className="flex-1 py-2 rounded-lg text-xs font-semibold transition-all"
              style={{
                background: mode === m ? "rgba(99,102,241,0.8)" : "transparent",
                color:      mode === m ? "white" : "rgba(255,255,255,0.4)",
              }}>
              {m === "signin" ? "Sign In" : m === "signup" ? "Sign Up" : "Forgot Password"}
            </button>
          ))}
        </div>

        {/* Card */}
        <div className="rounded-2xl p-7 space-y-4" style={{
          background: "rgba(255,255,255,0.04)",
          border: "1px solid rgba(255,255,255,0.08)",
        }}>
          <p className="text-base font-bold text-white text-center">
            {mode === "signin" ? "Sign in to your organisation" : mode === "signup" ? "Create your account" : "Reset your password"}
          </p>

          {/* Errors / success */}
          {errorParam && mode === "signin" && (() => {
            const msg =
              errorParam === "session_timeout" ? "You were signed out due to inactivity."
            : errorParam === "pkce_lost"       ? "Sign-in session expired — please try again."
            : errorParam === "missing_code"    ? "GitHub did not return an authorisation code. Please try again."
            : errorParam === "access_denied"   ? "GitHub access was denied. Please authorise TrustLedger to continue."
            : errorParam === "auth_failed"     ? "Sign-in failed. Please try again or contact support."
            : `Sign-in error: ${decodeURIComponent(errorParam)}`;
            return (
              <div className="px-3 py-2.5 rounded-xl text-xs text-rose-300 bg-rose-900/30 border border-rose-700/40">
                <p>{msg}</p>
              </div>
            );
          })()}
          {formErr && (
            <div className="px-3 py-2.5 rounded-xl text-sm text-rose-300 bg-rose-900/30 border border-rose-700/40">
              {formErr}
            </div>
          )}
          {formOk && (
            <div className="px-3 py-2.5 rounded-xl text-sm text-emerald-300 bg-emerald-900/30 border border-emerald-700/40">
              {formOk}
            </div>
          )}

          {/* GitHub — only for sign in */}
          {mode === "signin" && (
            <button
              onClick={async () => { setGithubBusy(true); await signInWithGitHub(); }}
              disabled={githubBusy}
              className="w-full flex items-center justify-center gap-3 py-3 rounded-xl font-semibold text-sm text-white transition-all disabled:opacity-70"
              style={{ background: "#24292f", border: "1px solid rgba(255,255,255,0.12)" }}
              onMouseEnter={e => { if (!githubBusy) (e.currentTarget as HTMLElement).style.background = "#1a1f24"; }}
              onMouseLeave={e => { (e.currentTarget as HTMLElement).style.background = "#24292f"; }}
            >
              {githubBusy ? (
                <svg className="animate-spin w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                  <path d="M21 12a9 9 0 1 1-6.219-8.56"/>
                </svg>
              ) : <GitHubIcon />}
              {githubBusy ? "Redirecting to GitHub…" : "Continue with GitHub"}
            </button>
          )}

          {/* Email form */}
          {mode === "signup" || mode === "forgot" || showEmail ? (
            <form onSubmit={handleEmail} className="space-y-2.5">
              {mode === "signup" && (
                <input type="text" placeholder="Full name" value={name}
                  onChange={e => setName(e.target.value)} required autoFocus
                  className={inputCls} />
              )}
              <input type="email" placeholder="Work email" value={email}
                onChange={e => setEmail(e.target.value)} required
                autoFocus={mode === "signin" || mode === "forgot"}
                className={inputCls} />
              {mode !== "forgot" && (
                <input type="password" placeholder="Password" value={password}
                  onChange={e => setPassword(e.target.value)} required minLength={8}
                  className={inputCls} />
              )}
              {mode === "signup" && (
                <input type="password" placeholder="Confirm password" value={confirm}
                  onChange={e => setConfirm(e.target.value)} required minLength={8}
                  className={inputCls} />
              )}
              <button type="submit" disabled={busy}
                className="w-full py-2.5 rounded-xl font-semibold text-sm text-white transition-all"
                style={{ background: "linear-gradient(135deg,#6366f1,#7c3aed)", opacity: busy ? 0.7 : 1 }}>
                {busy
                  ? (mode === "signin" ? "Signing in…" : mode === "signup" ? "Creating account…" : "Sending…")
                  : (mode === "signin" ? "Sign in" : mode === "signup" ? "Create account" : "Send reset link")}
              </button>
            </form>
          ) : (
            <button
              onClick={() => setShowEmail(true)}
              className="w-full py-2.5 rounded-xl text-sm font-medium transition-colors"
              style={{ color: "rgba(255,255,255,0.4)", border: "1px solid rgba(255,255,255,0.08)" }}
              onMouseEnter={e => { (e.currentTarget as HTMLElement).style.color = "rgba(255,255,255,0.65)"; }}
              onMouseLeave={e => { (e.currentTarget as HTMLElement).style.color = "rgba(255,255,255,0.4)"; }}
            >
              Sign in with email instead
            </button>
          )}
        </div>

        <p className="mt-5 text-center text-xs" style={{ color: "rgba(255,255,255,0.18)" }}>
          By signing in you agree to our Terms of Service and Privacy Policy
        </p>
      </div>
    </div>
  );
}

// ── Entry point — show correct page based on mode ─────────────────────────────

export default function LoginPage() {
  return SKIP_AUTH ? <DemoLoginPage /> : <ProductionLoginPage />;
}
