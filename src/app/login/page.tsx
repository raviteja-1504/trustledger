"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { useAuth } from "@/lib/auth";
import { authedFetch } from "@/lib/useRealData";
import { LINK_ERROR_CODES, fullPageNavigate, loginErrorMessage, safeNextPath } from "@/lib/authFlow";
import { BrandLogo, BrandMark, BrandWordmark } from "@/components/BrandLogo";

const SKIP_AUTH = process.env.NEXT_PUBLIC_SKIP_AUTH === "true";

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
    desc:    "Attest files, view violations, export evidence assessments",
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
    desc:    "Read-only access to evidence assessments and audit trail",
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
          <h1><BrandLogo height={84} /></h1>
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
// Same visual language as the landing page (src/app/page.tsx): ink background with a cyan glow and a faint
// grid, glass cards, cyan primary buttons with dark text, mono uppercase eyebrows.

const INK = "#050810";
const CYAN = "#22d3ee";
const VIOLET = "#a78bfa";

function GitHubIcon({ size = 18 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
      <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z"/>
    </svg>
  );
}

function Eyebrow({ children }: { children: React.ReactNode }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-[11px] font-bold uppercase tracking-[0.14em] px-3 py-1.5 rounded-full border font-mono"
      style={{ color: CYAN, background: `${CYAN}1c`, borderColor: `${CYAN}4d` }}>
      <span className="w-1.5 h-1.5 rounded-full" style={{ background: CYAN, boxShadow: `0 0 8px ${CYAN}` }} />
      {children}
    </span>
  );
}

const VALUE_POINTS = [
  { title: "Every PR, scored", body: "How much is AI-written, and the real vulnerabilities traced across files in six languages." },
  { title: "Secrets, dependencies, cloud & API", body: "Leaked keys, reachable vulnerable packages, IaC and endpoint checks — in the same review." },
  { title: "Proof, not promises", body: "A named reviewer signs off every file, and each scan exports a signed Trust Record." },
];

/** Page frame shared by every sign-in screen: landing-page background, top bar, optional value panel. */
function AuthShell({ children, aside = false }: { children: React.ReactNode; aside?: boolean }) {
  return (
    <div className="relative min-h-screen overflow-hidden text-white" style={{ background: `radial-gradient(ellipse 90% 55% at 50% 0%, ${CYAN}16, transparent 58%), ${INK}` }}>
      <div className="absolute inset-0 pointer-events-none" aria-hidden="true">
        <div className="absolute -top-40 -left-24 w-[30rem] h-[30rem] rounded-full blur-[140px]" style={{ background: CYAN, opacity: 0.08 }} />
        <div className="absolute -top-24 -right-24 w-[26rem] h-[26rem] rounded-full blur-[140px]" style={{ background: VIOLET, opacity: 0.06 }} />
        <div className="absolute inset-0" style={{ backgroundImage: "linear-gradient(rgba(255,255,255,0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.03) 1px, transparent 1px)", backgroundSize: "56px 56px" }} />
        <div className="absolute bottom-0 inset-x-0 h-52" style={{ background: `linear-gradient(to top, ${INK}, transparent)` }} />
      </div>

      <header className="relative z-10 max-w-6xl mx-auto px-5 h-16 flex items-center justify-between">
        <Link href="/" aria-label="TrustLedger home" className="flex items-center"><BrandWordmark height={30} /></Link>
        <Link href="/" className="flex items-center gap-1.5 text-xs font-medium text-white/50 hover:text-white/85 transition-colors">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <path d="M19 12H5"/><path d="M12 19l-7-7 7-7"/>
          </svg>
          Back to home
        </Link>
      </header>

      {/* One fixed top offset at every size: a 38rem block (the tallest form, Sign Up) centred in the space
          under the header. Fixed rather than centring the live content, so switching tabs never moves anything.
          Below xl (phones, tablets either way up) a single centred column; from xl two top-aligned columns. */}
      <main style={{ paddingTop: "max(1.5rem, calc((100svh - 4rem - 38rem) / 2))" }} className={`relative z-10 max-w-6xl mx-auto px-5 pb-16 grid gap-12 items-start justify-items-center ${aside ? "xl:grid-cols-[1.05fr_minmax(0,440px)] xl:gap-20 xl:justify-items-stretch" : ""}`}>
        {aside && (
          <section className="hidden xl:block space-y-7" aria-label="Why TrustLedger">
            <Eyebrow>Code security with proof</Eyebrow>
            <h2 className="text-5xl font-black tracking-tight leading-[1.05]" style={{ textShadow: "0 4px 40px rgba(0,0,0,0.7)" }}>
              Know what ships.<br />
              <span style={{ background: `linear-gradient(90deg, ${CYAN}, #67e8f9, #a5f3fc)`, WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent", backgroundClip: "text" }}>Prove it was reviewed.</span>
            </h2>
            <ul className="space-y-5 max-w-md">
              {VALUE_POINTS.map(p => (
                <li key={p.title} className="flex gap-3.5">
                  <span className="mt-1 w-5 h-5 shrink-0 rounded-md flex items-center justify-center" style={{ background: `${CYAN}1f`, border: `1px solid ${CYAN}55`, color: CYAN }}>
                    <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3.5" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true"><polyline points="20 6 9 17 4 12" /></svg>
                  </span>
                  <span>
                    <span className="block text-sm font-bold text-white/90">{p.title}</span>
                    <span className="block text-sm text-white/55 leading-relaxed mt-0.5">{p.body}</span>
                  </span>
                </li>
              ))}
            </ul>
          </section>
        )}
        <div className="w-full max-w-[440px]">{children}</div>
      </main>
    </div>
  );
}

/** The glass card the forms sit in — the landing page's card treatment. */
function AuthCard({ children }: { children: React.ReactNode }) {
  return (
    <div className="relative rounded-2xl p-7 sm:p-8 space-y-5 border backdrop-blur-xl"
      style={{ background: "rgba(10,15,28,0.72)", borderColor: "rgba(255,255,255,0.09)", boxShadow: `0 24px 80px rgba(0,0,0,0.55), 0 0 0 1px ${CYAN}0d inset` }}>
      <div className="absolute -top-px left-10 right-10 h-px" style={{ background: `linear-gradient(90deg, transparent, ${CYAN}88, transparent)` }} aria-hidden="true" />
      {children}
    </div>
  );
}

type Mode = "signin" | "signup" | "forgot" | "set-password" | "mfa";

const RESET_EXPIRED = "Your password reset link has expired or was already used. Enter your email to get a new one.";

function ProductionLoginPage() {
  const {
    user, loading, passwordRecovery,
    signInWithGitHub, signInWithEmail, signUpWithEmail, resendConfirmation, resetPassword,
    clearPasswordRecovery, cancelPasswordRecovery, completePasswordReset, signOut,
  } = useAuth();
  const router       = useRouter();
  const searchParams = useSearchParams();
  const errorParam   = searchParams?.get("error") ?? null;
  const next         = safeNextPath(searchParams?.get("next"));
  const [githubBusy, setGithubBusy] = useState(false);

  const [mode, setMode] = useState<Mode>(() =>
    errorParam && LINK_ERROR_CODES.has(errorParam) ? "forgot"
    : searchParams?.get("mode") === "signup" ? "signup"
    : "signin");
  const [newPass,    setNewPass]    = useState("");
  const [newConfirm, setNewConfirm] = useState("");
  const [newPassOk,  setNewPassOk]  = useState<string | null>(null);
  const [showEmail,  setShowEmail]  = useState(false);
  const [email,      setEmail]      = useState("");
  const [password,   setPassword]   = useState("");
  const [confirm,    setConfirm]    = useState("");
  const [name,       setName]       = useState("");
  const [mfaCode,    setMfaCode]    = useState("");
  const [formErr,    setFormErr]    = useState<string | null>(null);
  const [formOk,     setFormOk]     = useState<string | null>(null);
  const [needsConfirmation, setNeedsConfirmation] = useState(false);
  const [busy,       setBusy]       = useState(false);

  // A reset link was opened (the auth context persists the flag across the redirect to /login).
  useEffect(() => {
    if (passwordRecovery && user) setMode("set-password");
  }, [passwordRecovery, user]);

  // The reset flag outlived its session (link abandoned, then signed out / timed out): without this the
  // page would show "Set your password" forever with nothing able to save it.
  useEffect(() => {
    if (loading || !passwordRecovery || user) return;
    clearPasswordRecovery();
    setMode("forgot"); setShowEmail(true);
    setFormErr(RESET_EXPIRED);
  }, [loading, passwordRecovery, user, clearPasswordRecovery]);

  // Signed in (any route here: email, GitHub, a finished reset): ask for the 2FA code if this session
  // still needs it, otherwise continue to where the user was going.
  useEffect(() => {
    if (!user || passwordRecovery || mode === "set-password" || mode === "mfa") return;
    let cancelled = false;
    authedFetch<{ required: boolean; verified: boolean }>("/api/auth/2fa/login")
      .then(s => { if (!cancelled) { if (s.required && !s.verified) setMode("mfa"); else router.replace(next); } })
      .catch(() => { if (!cancelled) router.replace(next); });
    return () => { cancelled = true; };
  }, [user, passwordRecovery, mode, next, router]);

  function switchMode(m: "signin" | "signup" | "forgot") {
    setMode(m); setFormErr(null); setFormOk(null); setNeedsConfirmation(false);
    setEmail(""); setPassword(""); setConfirm(""); setName("");
    setShowEmail(m === "signup" || m === "forgot");
  }

  async function handleEmail(e: React.FormEvent) {
    e.preventDefault();
    setFormErr(null); setFormOk(null); setNeedsConfirmation(false);
    if (mode === "signup" && password !== confirm) {
      setFormErr("Passwords do not match."); return;
    }
    setBusy(true);
    if (mode === "signin") {
      const { error } = await signInWithEmail(email, password);
      setBusy(false);
      if (error) {
        setFormErr(error);
        setNeedsConfirmation(/not confirmed/i.test(error));
      }
      // Success: the signed-in effect above takes over (2FA step or redirect).
    } else if (mode === "signup") {
      const { error } = await signUpWithEmail(email, password, name);
      setBusy(false);
      if (error) setFormErr(error);
      else setFormOk("Account created! Check your email to confirm your address, then sign in.");
    } else {
      const { error } = await resetPassword(email);
      setBusy(false);
      if (error) setFormErr(error);
      else setFormOk("Password reset email sent — check your inbox and open the link in this browser to set a new password.");
    }
  }

  async function handleResend() {
    setBusy(true); setFormErr(null);
    const { error } = await resendConfirmation(email);
    setBusy(false);
    if (error) setFormErr(error);
    else { setNeedsConfirmation(false); setFormOk("Confirmation email sent — check your inbox, then sign in."); }
  }

  async function handleSetPassword(e: React.FormEvent) {
    e.preventDefault();
    setFormErr(null);
    if (newPass !== newConfirm) { setFormErr("Passwords do not match."); return; }
    setBusy(true);
    const { error, mfaRequired } = await completePasswordReset(newPass);
    setBusy(false);
    if (error) { setFormErr(error); return; }
    if (mfaRequired) { setMode("mfa"); setFormOk("Password set. Now enter your two-factor code."); return; }
    setNewPassOk("Password set! Taking you to the dashboard…");
    setTimeout(() => router.replace(next), 1500);
  }

  async function handleMfa(e: React.FormEvent) {
    e.preventDefault();
    setFormErr(null); setBusy(true);
    try {
      await authedFetch("/api/auth/2fa/login", { method: "POST", body: JSON.stringify({ code: mfaCode }) });
      fullPageNavigate(next);
    } catch (err) {
      setBusy(false);
      setFormErr(err instanceof Error ? err.message : "That code didn't match. Try again.");
    }
  }

  async function handleGitHub() {
    setGithubBusy(true); setFormErr(null);
    const { error } = await signInWithGitHub();
    // On success the browser is already leaving for GitHub; on failure, give the button back.
    if (error) { setGithubBusy(false); setFormErr("Couldn't start GitHub sign-in. Please try again."); }
  }

  if (loading) return null;

  const inputCls = "w-full px-4 py-3 rounded-xl text-sm text-white placeholder-white/30 border outline-none transition-colors bg-white/[0.04] border-white/10 hover:border-white/20 focus:border-cyan-400/70 focus:bg-white/[0.06] focus:ring-2 focus:ring-cyan-400/20";
  const errBox = formErr && <div role="alert" className="px-3.5 py-2.5 rounded-xl text-sm text-rose-200 bg-rose-500/10 border border-rose-400/30">{formErr}</div>;
  const okBox  = formOk && <div role="status" className="px-3.5 py-2.5 rounded-xl text-sm text-emerald-200 bg-emerald-500/10 border border-emerald-400/30">{formOk}</div>;
  const primaryBtn = (label: string, busyLabel: string) => (
    <button type="submit" disabled={busy}
      className="w-full py-3 rounded-xl font-bold text-sm transition-all active:scale-[0.98] disabled:opacity-70 hover:-translate-y-px"
      style={{ color: INK, background: `linear-gradient(135deg, #67e8f9, ${CYAN})`, boxShadow: `0 6px 28px ${CYAN}55` }}>
      {busy ? busyLabel : label}
    </button>
  );
  const quietLink = (label: string, onClick: () => void) => (
    <button type="button" onClick={onClick} className="w-full text-center text-xs text-white/45 hover:text-white/80 underline underline-offset-4 transition-colors">{label}</button>
  );

  // Password recovery and the 2FA step — focused, single card, no tabs
  if (mode === "set-password" || mode === "mfa") {
    const isMfa = mode === "mfa";
    return (
      <AuthShell>
        <AuthCard>
          <div className="flex flex-col items-center text-center gap-3">
            <BrandMark size={56} />
            <Eyebrow>{isMfa ? "Step 2 of 2" : "Account recovery"}</Eyebrow>
            <h1 className="text-2xl font-black tracking-tight">{isMfa ? "Two-factor authentication" : "Set your password"}</h1>
            <p className="text-sm text-white/55 leading-relaxed">
              {isMfa ? "Enter the 6-digit code from your authenticator app, or one of your backup codes." : "Choose a new password for your TrustLedger account."}
            </p>
          </div>
          {errBox}
          {okBox}
          {newPassOk && <div role="status" className="px-3.5 py-2.5 rounded-xl text-sm text-emerald-200 bg-emerald-500/10 border border-emerald-400/30">{newPassOk}</div>}
          {isMfa ? (
            <form onSubmit={handleMfa} className="space-y-3">
              <input type="text" inputMode="numeric" autoComplete="one-time-code" placeholder="123 456" aria-label="Two-factor code"
                value={mfaCode} onChange={e => setMfaCode(e.target.value)} required autoFocus maxLength={12}
                className={`${inputCls} text-center text-lg font-mono tracking-[0.35em]`} />
              {primaryBtn("Verify", "Verifying…")}
              {quietLink("Use a different account", async () => { await signOut(); setMode("signin"); setMfaCode(""); setFormErr(null); setFormOk(null); })}
            </form>
          ) : !newPassOk && (
            <form onSubmit={handleSetPassword} className="space-y-3">
              <input type="password" placeholder="New password (min 8 chars)" aria-label="New password" value={newPass}
                onChange={e => setNewPass(e.target.value)} required minLength={8} autoFocus autoComplete="new-password"
                className={inputCls} />
              <input type="password" placeholder="Confirm new password" aria-label="Confirm new password" value={newConfirm}
                onChange={e => setNewConfirm(e.target.value)} required minLength={8} autoComplete="new-password"
                className={inputCls} />
              {primaryBtn("Set password & sign in", "Saving…")}
              {quietLink("Cancel and go back to sign in", async () => { await cancelPasswordRecovery(); switchMode("signin"); })}
            </form>
          )}
        </AuthCard>
      </AuthShell>
    );
  }

  const paramMessage = mode !== "signup" ? loginErrorMessage(errorParam) : null;
  const heading = mode === "signin" ? "Welcome back" : mode === "signup" ? "Create your account" : "Reset your password";
  const sub = mode === "signin" ? "Sign in to your organisation." : mode === "signup" ? "Start scanning your pull requests in minutes." : "We'll email you a link to set a new password.";

  return (
    <AuthShell aside>
      <AuthCard>
        <div className="space-y-1.5 text-center">
          <h1 className="text-2xl font-black tracking-tight">{heading}</h1>
          <p className="text-sm text-white/55">{sub}</p>
        </div>

        {/* Sign in / Sign up / Forgot toggle */}
        <div className="grid grid-cols-3 gap-1 rounded-xl p-1 border" role="tablist" aria-label="Account"
          style={{ background: "rgba(255,255,255,0.03)", borderColor: "rgba(255,255,255,0.08)" }}>
          {(["signin","signup","forgot"] as const).map(m => (
            <button key={m} role="tab" aria-selected={mode === m} onClick={() => switchMode(m)}
              className="py-2 px-1 rounded-lg text-[11px] sm:text-xs font-bold whitespace-nowrap transition-all"
              style={mode === m
                ? { color: INK, background: `linear-gradient(135deg, #67e8f9, ${CYAN})`, boxShadow: `0 2px 14px ${CYAN}44` }
                : { color: "rgba(255,255,255,0.5)" }}>
              {m === "signin" ? "Sign In" : m === "signup" ? "Sign Up" : "Forgot Password"}
            </button>
          ))}
        </div>

        {/* Errors / success — the ?error= code is mapped to our own text, never shown as-is */}
        {paramMessage && !formErr && !formOk && (
          <div role="alert" className="px-3.5 py-2.5 rounded-xl text-sm text-rose-200 bg-rose-500/10 border border-rose-400/30">
            <p>{paramMessage}</p>
          </div>
        )}
        {errBox}
        {needsConfirmation && mode === "signin" && (
          <button type="button" onClick={handleResend} disabled={busy || !email}
            className="w-full py-2.5 rounded-xl text-xs font-bold transition-colors border hover:bg-cyan-400/10"
            style={{ color: "#a5f3fc", borderColor: `${CYAN}55` }}>
            Resend confirmation email
          </button>
        )}
        {okBox}

        {/* GitHub — only for sign in */}
        {mode === "signin" && (
          <button
            onClick={handleGitHub}
            disabled={githubBusy}
            className="w-full flex items-center justify-center gap-2.5 py-3 rounded-xl font-semibold text-sm text-white/90 transition-all border disabled:opacity-70 hover:border-white/30 hover:bg-white/[0.09]"
            style={{ background: "rgba(255,255,255,0.06)", borderColor: "rgba(255,255,255,0.16)" }}
          >
            {githubBusy ? (
              <svg className="animate-spin w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" aria-hidden="true">
                <path d="M21 12a9 9 0 1 1-6.219-8.56"/>
              </svg>
            ) : <GitHubIcon />}
            {githubBusy ? "Redirecting to GitHub…" : "Continue with GitHub"}
          </button>
        )}

        {mode === "signin" && (showEmail ? (
          <div className="flex items-center gap-3 text-[11px] font-mono uppercase tracking-[0.14em] text-white/35" aria-hidden="true">
            <span className="h-px flex-1 bg-white/10" />or with email<span className="h-px flex-1 bg-white/10" />
          </div>
        ) : null)}

        {/* Email form */}
        {mode === "signup" || mode === "forgot" || showEmail ? (
          <form onSubmit={handleEmail} className="space-y-3">
            {mode === "signup" && (
              <input type="text" placeholder="Full name" aria-label="Full name" value={name}
                onChange={e => setName(e.target.value)} required autoFocus autoComplete="name"
                className={inputCls} />
            )}
            <input type="email" placeholder="Work email" aria-label="Work email" value={email}
              onChange={e => setEmail(e.target.value)} required autoComplete="email"
              autoFocus={mode === "signin" || mode === "forgot"}
              className={inputCls} />
            {mode !== "forgot" && (
              <input type="password" placeholder={mode === "signup" ? "Password (min 8 chars)" : "Password"} aria-label="Password" value={password}
                onChange={e => setPassword(e.target.value)} required minLength={8}
                autoComplete={mode === "signup" ? "new-password" : "current-password"}
                className={inputCls} />
            )}
            {mode === "signup" && (
              <input type="password" placeholder="Confirm password" aria-label="Confirm password" value={confirm}
                onChange={e => setConfirm(e.target.value)} required minLength={8} autoComplete="new-password"
                className={inputCls} />
            )}
            {primaryBtn(
              mode === "signin" ? "Sign in" : mode === "signup" ? "Create account" : "Send reset link",
              mode === "signin" ? "Signing in…" : mode === "signup" ? "Creating account…" : "Sending…",
            )}
          </form>
        ) : (
          <button
            onClick={() => setShowEmail(true)}
            className="w-full py-3 rounded-xl text-sm font-medium transition-colors border text-white/55 hover:text-white/85 hover:border-white/20"
            style={{ borderColor: "rgba(255,255,255,0.09)" }}
          >
            Sign in with email instead
          </button>
        )}

        {mode === "signup" && (
          <p className="text-xs text-white/40 text-center leading-relaxed" style={{ textWrap: "balance" }}>
            Joining your team? Ask an admin to invite you — invites put you straight into their organisation.
          </p>
        )}
      </AuthCard>

      <p className="mt-6 text-center text-xs text-white/35 leading-relaxed" style={{ textWrap: "balance" }}>
        By continuing you agree to our{" "}
        <Link href="/terms" className="underline underline-offset-2 hover:text-white/70">Terms of Service</Link>
        {" "}and{" "}
        <Link href="/privacy" className="underline underline-offset-2 hover:text-white/70">Privacy Policy</Link>.
      </p>
    </AuthShell>
  );
}

// ── Entry point — show correct page based on mode ─────────────────────────────

export default function LoginPage() {
  return SKIP_AUTH ? <DemoLoginPage /> : <ProductionLoginPage />;
}
