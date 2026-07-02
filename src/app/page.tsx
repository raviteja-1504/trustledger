"use client";

import Link from "next/link";

const ORG = process.env.NEXT_PUBLIC_ORG ?? "novapay";

// ── Icons ──────────────────────────────────────────────────────────────────────

function ShieldIcon({ size = 20, className = "" }: { size?: number; className?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      <polyline points="9 12 11 14 15 10" />
    </svg>
  );
}

function ArrowRightIcon({ size = 16 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <line x1="5" y1="12" x2="19" y2="12" /><polyline points="12 5 19 12 12 19" />
    </svg>
  );
}

function CheckIcon({ size = 14 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="20 6 9 17 4 12" />
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

// ── Data ───────────────────────────────────────────────────────────────────────

const FEATURES = [
  {
    icon: (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M9.5 2A2.5 2.5 0 0 1 12 4.5v15a2.5 2.5 0 0 1-4.96-.46 2.5 2.5 0 0 1-2.96-3.08 3 3 0 0 1-.34-5.58 2.5 2.5 0 0 1 1.32-4.24 2.5 2.5 0 0 1 1.98-3Z" />
        <path d="M14.5 2A2.5 2.5 0 0 0 12 4.5v15a2.5 2.5 0 0 0 4.96-.46 2.5 2.5 0 0 0 2.96-3.08 3 3 0 0 0 .34-5.58 2.5 2.5 0 0 0-1.32-4.24 2.5 2.5 0 0 0-1.98-3Z" />
      </svg>
    ),
    title: "AI Detection Engine",
    desc: "Combines ML structural analysis with pattern-based vulnerability scanning. Detects SQL injection, hardcoded secrets, eval/exec, and JWT issues introduced by AI assistants.",
    accent: "from-violet-500 to-indigo-600",
    tag: "ML + Pattern",
    glow: "rgba(124,58,237,0.2)",
  },
  {
    icon: (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
        <polyline points="9 12 11 14 15 10" />
      </svg>
    ),
    title: "Configurable Policy Engine",
    desc: "Define merge gates per risk level. Require 1 or 2 reviewers for CRITICAL files. Block MEDIUM-risk code in regulated repos. Preset Standard and Strict policies included.",
    accent: "from-indigo-500 to-blue-600",
    tag: "Governance",
    glow: "rgba(99,102,241,0.2)",
  },
  {
    icon: (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <rect x="3" y="3" width="18" height="18" rx="2" />
        <path d="M3 9h18" /><path d="M9 21V9" />
      </svg>
    ),
    title: "GitHub Status Checks",
    desc: "Posts pass/fail status checks directly on pull requests. Blocks merging when policy violations exist. Comments a risk summary so reviewers see exactly what needs attention.",
    accent: "from-slate-600 to-slate-800",
    tag: "Integration",
    glow: "rgba(100,116,139,0.2)",
  },
  {
    icon: (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
        <polyline points="14 2 14 8 20 8" />
        <line x1="16" y1="13" x2="8" y2="13" /><line x1="16" y1="17" x2="8" y2="17" />
      </svg>
    ),
    title: "Compliance Reports",
    desc: "Generate cryptographically-signed audit packages for SOC 2, EU AI Act Article 9, and PCI-DSS Req. 6.4. Evidence-ready PDFs with attestation trails and risk summaries.",
    accent: "from-emerald-500 to-teal-600",
    tag: "Compliance",
    glow: "rgba(16,185,129,0.2)",
  },
  {
    icon: (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
      </svg>
    ),
    title: "Real-Time Dashboard",
    desc: "Org-wide health score, AI% trends, per-repo risk breakdown, and an activity feed. See which PRs are blocked, which files are unattested, and where AI adoption is accelerating.",
    accent: "from-amber-500 to-orange-600",
    tag: "Visibility",
    glow: "rgba(245,158,11,0.2)",
  },
  {
    icon: (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" /><circle cx="9" cy="7" r="4" />
        <path d="M23 21v-2a4 4 0 0 0-3-3.87" /><path d="M16 3.13a4 4 0 0 1 0 7.75" />
      </svg>
    ),
    title: "Reviewer Attestation",
    desc: "Named reviewer sign-off recorded per file with PGP signature, timestamp, and AI% at time of review. Immutable audit log that answers 'who reviewed this AI code and when.'",
    accent: "from-rose-500 to-pink-600",
    tag: "Audit Trail",
    glow: "rgba(244,63,94,0.2)",
  },
];

const STEPS = [
  {
    n: "01",
    title: "Connect your repos",
    desc: "Install the GitHub App in under 2 minutes. TrustLedger automatically scans every pull request — no config files, no CI changes.",
    color: "from-indigo-500 to-violet-600",
    num: 1,
  },
  {
    n: "02",
    title: "See exactly what AI wrote",
    desc: "Each PR shows AI% per file, detected vulnerability patterns, and a risk score. Expand any file to read the source code with risky lines highlighted.",
    color: "from-violet-500 to-purple-600",
    num: 2,
  },
  {
    n: "03",
    title: "Attest. Gate. Deploy.",
    desc: "Reviewers sign off on flagged files directly in the dashboard. Policy gates automatically block merges until all required attestations are recorded.",
    color: "from-emerald-500 to-teal-600",
    num: 3,
  },
];

const PRICING = [
  {
    name:    "Starter",
    price:   "$299",
    period:  "/ month",
    desc:    "For growing teams adopting AI-assisted development with compliance obligations.",
    cta:     "Start 14-day free trial",
    ctaHref: "/login",
    popular: false,
    features: [
      "10 repositories",
      "1,000 scans / month",
      "5 team members",
      "GitHub PR status checks",
      "AI% detection + risk scoring",
      "Standard + Strict policy engine",
      "Slack + email alerts",
      "PDF reports (SOC 2, PCI-DSS)",
      "90-day data retention",
    ],
  },
  {
    name:    "Growth",
    price:   "$999",
    period:  "/ month",
    desc:    "For regulated engineering organisations shipping AI code at scale.",
    cta:     "Start 14-day free trial",
    ctaHref: "/login",
    popular: true,
    features: [
      "50 repositories",
      "10,000 scans / month",
      "20 team members",
      "Everything in Starter, plus:",
      "JIRA / Linear ticket creation",
      "EU AI Act + PCI-DSS compliance reports",
      "AIBOM (AI Bill of Materials) export",
      "AI model attribution (Copilot, ChatGPT…)",
      "PagerDuty / webhook integrations",
      "Compliance calendar + email reminders",
      "1-year data retention",
    ],
  },
  {
    name:    "Enterprise",
    price:   "Custom",
    period:  "",
    desc:    "Unlimited scale, custom SLA, and dedicated support for large organisations.",
    cta:     "Talk to sales",
    ctaHref: "mailto:sales@trustledger.dev",
    popular: false,
    features: [
      "Unlimited repositories + scans",
      "Unlimited team members",
      "SSO / SAML 2.0 (Okta, Azure AD)",
      "SCIM user provisioning",
      "Self-hosted Docker deployment",
      "Multi-org MSP dashboard",
      "Custom policy engine",
      "Dedicated Slack support",
      "MSA + DPA + custom data residency",
      "Custom SLA and uptime guarantee",
    ],
  },
];


// ── NavBar ─────────────────────────────────────────────────────────────────────

function NavBar() {
  return (
    <header className="fixed top-0 inset-x-0 z-50 border-b border-white/[0.07]"
      style={{ background: "rgba(2,6,23,0.85)", backdropFilter: "blur(16px) saturate(180%)" }}>
      <div className="max-w-6xl mx-auto px-5 h-14 flex items-center justify-between gap-4">
        <div className="flex items-center gap-2.5">
          <div className="w-7 h-7 rounded-lg flex items-center justify-center text-white"
            style={{ background: "linear-gradient(135deg,#6366f1,#7c3aed)", boxShadow: "0 4px 14px rgba(99,102,241,0.45)" }}>
            <ShieldIcon size={14} />
          </div>
          <span className="font-bold text-white text-sm tracking-tight">TrustLedger</span>
        </div>

        <nav className="hidden md:flex items-center gap-6">
          {["Features", "How it works", "Pricing"].map(l => (
            <a key={l} href={`#${l.toLowerCase().replace(/ /g, "-")}`}
              className="text-sm text-white/45 hover:text-white/80 transition-colors font-medium">
              {l}
            </a>
          ))}
        </nav>

        <div className="flex items-center gap-2">
          <Link href="/login"
            className="text-sm font-semibold text-white/50 hover:text-white transition-colors px-3 py-1.5">
            Sign in
          </Link>
          <Link href="/login"
            className="flex items-center gap-1.5 text-sm font-bold text-white px-3.5 py-1.5 rounded-lg transition-all"
            style={{ background: "linear-gradient(135deg,#6366f1,#7c3aed)", boxShadow: "0 2px 12px rgba(99,102,241,0.4)" }}>
            Get started <ArrowRightIcon size={13} />
          </Link>
        </div>
      </div>
    </header>
  );
}

// ── HeroSection ────────────────────────────────────────────────────────────────

function HeroSection() {
  return (
    <section className="relative min-h-screen flex flex-col items-center justify-center text-center px-5 pt-14 overflow-hidden"
      style={{ background: "linear-gradient(180deg, #020617 0%, #0b0f23 55%, #130d2e 100%)" }}>

      {/* Layered background glows */}
      <div className="absolute inset-0 pointer-events-none overflow-hidden">
        {/* Primary center glow */}
        <div className="absolute top-[38%] left-1/2 -translate-x-1/2 -translate-y-1/2 w-[700px] h-[700px] rounded-full"
          style={{ background: "radial-gradient(circle, rgba(99,102,241,0.18) 0%, transparent 65%)" }} />
        {/* Secondary glows */}
        <div className="absolute bottom-[5%] left-[15%] w-[500px] h-[350px] rounded-full"
          style={{ background: "radial-gradient(circle, rgba(168,85,247,0.1) 0%, transparent 70%)" }} />
        <div className="absolute top-[20%] right-[10%] w-[350px] h-[350px] rounded-full"
          style={{ background: "radial-gradient(circle, rgba(59,130,246,0.1) 0%, transparent 70%)" }} />
        {/* Grid */}
        <div className="absolute inset-0"
          style={{ backgroundImage: "linear-gradient(rgba(255,255,255,0.025) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.025) 1px, transparent 1px)", backgroundSize: "64px 64px", opacity: 1 }} />
        {/* Horizontal fade gradient over grid bottom */}
        <div className="absolute bottom-0 left-0 right-0 h-40"
          style={{ background: "linear-gradient(to top, #020617, transparent)" }} />
      </div>

      <div className="relative max-w-4xl mx-auto space-y-6">
        {/* Badge */}
        <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full text-xs font-semibold text-indigo-300 border"
          style={{ background: "rgba(99,102,241,0.1)", borderColor: "rgba(99,102,241,0.25)" }}>
          <span className="w-1.5 h-1.5 rounded-full bg-indigo-400 animate-pulse" />
          Now with EU AI Act compliance reports
        </div>

        {/* Headline */}
        <h1 className="text-5xl sm:text-6xl lg:text-7xl font-black text-white tracking-tight leading-[1.05]">
          Know exactly<br />
          <span style={{ background: "linear-gradient(90deg, #818cf8, #a78bfa, #c084fc)", WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent", backgroundClip: "text" }}>
            how much AI
          </span><br />
          wrote your code.
        </h1>

        {/* Subheadline */}
        <p className="text-lg sm:text-xl text-white/45 max-w-2xl mx-auto leading-relaxed">
          TrustLedger scans every pull request for AI-generated code, flags security risks before they reach production, and records human reviewer sign-off — so you can always prove what shipped.
        </p>

        {/* CTAs */}
        <div className="flex flex-col sm:flex-row items-center justify-center gap-3 pt-2">
          <Link href="/login"
            className="flex items-center gap-2 px-6 py-3.5 rounded-xl text-white font-bold text-sm transition-all active:scale-[0.98]"
            style={{ background: "linear-gradient(135deg,#6366f1,#7c3aed)", boxShadow: "0 4px 24px rgba(99,102,241,0.45)" }}>
            Start free 14-day trial
            <ArrowRightIcon size={15} />
          </Link>
          <Link href="/dashboard"
            className="flex items-center gap-2 px-6 py-3.5 rounded-xl text-white/70 font-semibold text-sm transition-all border border-white/10 hover:border-white/20 hover:text-white/90"
            style={{ background: "rgba(255,255,255,0.04)" }}>
            <GitHubIcon size={15} />
            View live demo
          </Link>
        </div>

        {/* Social proof */}
        <p className="text-xs text-white/25 font-medium pt-2">
          Trusted by 50+ engineering teams · No credit card required to start
        </p>
      </div>

      {/* Dashboard preview */}
      <div className="relative mt-16 w-full max-w-5xl mx-auto">
        <div className="rounded-2xl overflow-hidden border border-white/[0.09] shadow-2xl"
          style={{ background: "linear-gradient(135deg, #0f172a, #1e1b4b)", boxShadow: "0 40px 80px rgba(0,0,0,0.6), 0 0 0 1px rgba(255,255,255,0.05)" }}>
          {/* Browser chrome */}
          <div className="px-4 py-2.5 flex items-center gap-2 border-b border-white/[0.07]"
            style={{ background: "rgba(255,255,255,0.02)" }}>
            <div className="flex items-center gap-1.5">
              <span className="w-2.5 h-2.5 rounded-full bg-rose-500/50" />
              <span className="w-2.5 h-2.5 rounded-full bg-amber-500/50" />
              <span className="w-2.5 h-2.5 rounded-full bg-emerald-500/50" />
            </div>
            <div className="flex-1 mx-4 rounded-md px-3 py-1 text-[11px] text-white/25 font-mono text-center"
              style={{ background: "rgba(255,255,255,0.04)", border: "1px solid rgba(255,255,255,0.06)" }}>
              app.trustledger.dev/dashboard
            </div>
          </div>
          {/* Mock content */}
          <div className="p-5 space-y-4">
            <div className="grid grid-cols-4 gap-3">
              {[
                { label: "Health Score", value: "74", color: "#f59e0b" },
                { label: "AI Content",   value: "48%", color: "#a78bfa" },
                { label: "Attested",     value: "81%", color: "#34d399" },
                { label: "Blocked PRs",  value: "3",   color: "#f87171" },
              ].map(s => (
                <div key={s.label} className="rounded-xl p-3 border border-white/[0.06]"
                  style={{ background: "rgba(255,255,255,0.04)" }}>
                  <p className="text-2xl font-black tabular-nums" style={{ color: s.color }}>{s.value}</p>
                  <p className="text-[10px] text-white/30 font-medium mt-0.5">{s.label}</p>
                </div>
              ))}
            </div>
            <div className="rounded-xl border border-white/[0.06] overflow-hidden"
              style={{ background: "rgba(255,255,255,0.02)" }}>
              <div className="px-4 py-2 border-b border-white/[0.05] flex items-center justify-between">
                <span className="text-xs font-bold text-white/35 uppercase tracking-wider">Recent Scans</span>
                <span className="text-[10px] text-white/20 font-mono">{ORG} · last 7 days</span>
              </div>
              {[
                { repo: "payments-core",   pr: "#104", risk: "CRITICAL", ai: "94%", bg: "rgba(124,58,237,0.12)", color: "#a78bfa" },
                { repo: "auth-gateway",    pr: "#204", risk: "HIGH",     ai: "71%", bg: "rgba(249,115,22,0.10)", color: "#fb923c" },
                { repo: "fraud-detection", pr: "#303", risk: "CRITICAL", ai: "88%", bg: "rgba(124,58,237,0.12)", color: "#a78bfa" },
              ].map(row => (
                <div key={row.pr} className="px-4 py-2.5 flex items-center gap-4 border-b border-white/[0.04] last:border-0">
                  <span className="font-mono text-xs text-white/45 shrink-0">{row.repo}</span>
                  <span className="text-[10px] text-white/25 font-mono">{row.pr}</span>
                  <span className="ml-auto text-[10px] font-bold px-2 py-0.5 rounded-md" style={{ background: row.bg, color: row.color }}>{row.risk}</span>
                  <span className="text-xs font-bold tabular-nums w-8 text-right" style={{ color: row.color }}>{row.ai}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
        {/* Glow under preview */}
        <div className="absolute -bottom-10 left-1/2 -translate-x-1/2 w-2/3 h-20 blur-3xl rounded-full"
          style={{ background: "linear-gradient(90deg, #6366f1, #a855f7)", opacity: 0.25 }} />
      </div>
    </section>
  );
}


// ── FeaturesSection ────────────────────────────────────────────────────────────

function FeaturesSection() {
  return (
    <section id="features" className="py-24 px-5"
      style={{ background: "linear-gradient(180deg, #020617 0%, #0a0d1f 50%, #020617 100%)" }}>
      {/* Subtle grid overlay */}
      <div className="absolute inset-0 pointer-events-none"
        style={{ backgroundImage: "linear-gradient(rgba(255,255,255,0.015) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.015) 1px, transparent 1px)", backgroundSize: "64px 64px" }} />

      <div className="max-w-6xl mx-auto relative">
        <div className="text-center mb-14">
          <span className="text-xs font-bold uppercase tracking-widest text-indigo-400 px-3 py-1 rounded-full border"
            style={{ background: "rgba(99,102,241,0.1)", borderColor: "rgba(99,102,241,0.25)" }}>
            Features
          </span>
          <h2 className="text-4xl font-black text-white mt-4 tracking-tight">
            Everything you need to govern AI code
          </h2>
          <p className="text-white/40 mt-3 max-w-xl mx-auto text-lg">
            From first scan to audit report — TrustLedger covers the entire AI code lifecycle in your engineering workflow.
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-5">
          {FEATURES.map(f => (
            <div key={f.title}
              className="group relative p-6 rounded-2xl transition-all duration-200 cursor-default"
              style={{ background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.07)" }}
              onMouseEnter={e => {
                const el = e.currentTarget as HTMLElement;
                el.style.background = `rgba(255,255,255,0.055)`;
                el.style.border = `1px solid rgba(255,255,255,0.13)`;
                el.style.transform = "translateY(-2px)";
                el.style.boxShadow = `0 12px 40px ${f.glow}`;
              }}
              onMouseLeave={e => {
                const el = e.currentTarget as HTMLElement;
                el.style.background = "rgba(255,255,255,0.03)";
                el.style.border = "1px solid rgba(255,255,255,0.07)";
                el.style.transform = "translateY(0)";
                el.style.boxShadow = "none";
              }}>
              <div className={`w-10 h-10 rounded-xl flex items-center justify-center text-white bg-gradient-to-br ${f.accent} mb-4`}
                style={{ boxShadow: `0 4px 16px ${f.glow}` }}>
                {f.icon}
              </div>
              <div className="flex items-center gap-2 mb-2">
                <h3 className="text-sm font-bold text-white">{f.title}</h3>
                <span className="text-[10px] font-bold text-white/30 px-1.5 py-0.5 rounded-md"
                  style={{ background: "rgba(255,255,255,0.06)", border: "1px solid rgba(255,255,255,0.08)" }}>
                  {f.tag}
                </span>
              </div>
              <p className="text-sm text-white/45 leading-relaxed">{f.desc}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

// ── HowItWorksSection ──────────────────────────────────────────────────────────

function HowItWorksSection() {
  return (
    <section id="how-it-works" className="py-24 px-5"
      style={{ background: "linear-gradient(180deg, #020617 0%, #0a0f1e 100%)" }}>
      <div className="max-w-4xl mx-auto">
        <div className="text-center mb-14">
          <span className="text-xs font-bold uppercase tracking-widest text-indigo-400 px-3 py-1 rounded-full border"
            style={{ background: "rgba(99,102,241,0.1)", borderColor: "rgba(99,102,241,0.25)" }}>
            How it works
          </span>
          <h2 className="text-4xl font-black text-white mt-4 tracking-tight">
            Up and running in 5 minutes
          </h2>
          <p className="text-white/40 mt-3 text-lg">
            No CI/CD changes. No config files. Just install the GitHub App and every PR is scanned automatically.
          </p>
        </div>

        <div className="space-y-4">
          {STEPS.map((s) => (
            <div key={s.n} className="flex gap-6 p-6 rounded-2xl border border-white/[0.07] transition-colors hover:border-white/[0.12]"
              style={{ background: "rgba(255,255,255,0.03)" }}>
              <div className={`w-10 h-10 rounded-xl bg-gradient-to-br ${s.color} flex items-center justify-center text-white font-black text-sm shrink-0`}
                style={{ boxShadow: "0 4px 16px rgba(99,102,241,0.3)" }}>
                {s.num}
              </div>
              <div>
                <h3 className="font-bold text-white mb-1">{s.title}</h3>
                <p className="text-sm text-white/45 leading-relaxed">{s.desc}</p>
              </div>
            </div>
          ))}
        </div>

        <div className="mt-10 p-5 rounded-2xl overflow-x-auto border border-white/[0.08]"
          style={{ background: "#0d1117" }}>
          <p className="text-xs text-white/30 font-mono mb-3"># Or submit scans via the REST API</p>
          <pre className="text-xs text-emerald-400 font-mono leading-relaxed whitespace-pre">{`curl -X POST https://api.trustledger.dev/api/v1/scan \\
  -H 'Authorization: Bearer YOUR_TOKEN' \\
  -H 'Content-Type: application/json' \\
  -d '{"repo": "myorg/myrepo", "pr_number": 42,
       "commit_sha": "abc1234",
       "files": [{"path": "src/auth.py", "content": "..."}]}'`}</pre>
        </div>
      </div>
    </section>
  );
}


// ── PricingSection ─────────────────────────────────────────────────────────────

function PricingSection() {
  return (
    <section id="pricing" className="py-24 px-5"
      style={{ background: "linear-gradient(180deg, #0d1320 0%, #0a0f1e 100%)" }}>
      <div className="max-w-5xl mx-auto">
        <div className="text-center mb-14">
          <span className="text-xs font-bold uppercase tracking-widest text-indigo-400 px-3 py-1 rounded-full border"
            style={{ background: "rgba(99,102,241,0.1)", borderColor: "rgba(99,102,241,0.25)" }}>
            Pricing
          </span>
          <h2 className="text-4xl font-black text-white mt-4 tracking-tight">
            Simple, transparent pricing
          </h2>
          <p className="text-white/40 mt-3 text-lg">
            Start free. Scale as your team grows. No surprises.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {PRICING.map(plan => (
            <div key={plan.name} className={`relative flex flex-col rounded-2xl p-6 transition-all duration-200`}
              style={plan.popular ? {
                background: "linear-gradient(160deg, rgba(99,102,241,0.15) 0%, rgba(124,58,237,0.08) 100%)",
                border: "1px solid rgba(99,102,241,0.35)",
                boxShadow: "0 8px 40px rgba(99,102,241,0.2)",
              } : {
                background: "rgba(255,255,255,0.03)",
                border: "1px solid rgba(255,255,255,0.08)",
              }}>

              {plan.popular && (
                <div className="absolute -top-3.5 left-1/2 -translate-x-1/2">
                  <span className="text-white text-[10px] font-black uppercase tracking-widest px-3 py-1 rounded-full"
                    style={{ background: "linear-gradient(135deg,#6366f1,#7c3aed)", boxShadow: "0 2px 10px rgba(99,102,241,0.4)" }}>
                    Most popular
                  </span>
                </div>
              )}

              <div className="mb-5">
                <p className="text-sm font-bold text-white">{plan.name}</p>
                <div className="flex items-end gap-1 mt-2">
                  <span className={`text-4xl font-black ${plan.popular ? "text-indigo-300" : "text-white"}`}>
                    {plan.price}
                  </span>
                  {plan.period && <span className="text-white/35 text-sm mb-1">{plan.period}</span>}
                </div>
                <p className="text-xs text-white/35 mt-1.5 leading-relaxed">{plan.desc}</p>
              </div>

              <ul className="space-y-2.5 flex-1 mb-6">
                {plan.features.map(f => (
                  <li key={f} className="flex items-start gap-2.5 text-sm text-white/55">
                    <span className={`w-4 h-4 rounded-full flex items-center justify-center shrink-0 mt-0.5 ${
                      plan.popular ? "bg-indigo-500/20 text-indigo-400" : "bg-white/8 text-white/35"
                    }`}>
                      <CheckIcon size={10} />
                    </span>
                    {f}
                  </li>
                ))}
              </ul>

              <Link href={(plan as typeof plan & { ctaHref?: string }).ctaHref ?? "/login"}
                className="w-full flex items-center justify-center py-3 rounded-xl font-bold text-sm transition-all"
                style={plan.popular ? {
                  background: "linear-gradient(135deg,#6366f1,#7c3aed)",
                  color: "white",
                  boxShadow: "0 4px 16px rgba(99,102,241,0.4)",
                } : {
                  background: "rgba(255,255,255,0.07)",
                  color: "rgba(255,255,255,0.7)",
                  border: "1px solid rgba(255,255,255,0.1)",
                }}>
                {plan.cta}
              </Link>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

// ── CTASection ─────────────────────────────────────────────────────────────────

function CTASection() {
  return (
    <section className="py-24 px-5 relative overflow-hidden"
      style={{ background: "linear-gradient(135deg, #0a0f1e 0%, #1a1040 50%, #0a0f1e 100%)" }}>
      {/* Glow */}
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[400px] rounded-full pointer-events-none"
        style={{ background: "radial-gradient(ellipse, rgba(99,102,241,0.15) 0%, transparent 65%)" }} />

      <div className="relative max-w-3xl mx-auto text-center space-y-6">
        <div className="w-14 h-14 rounded-2xl mx-auto flex items-center justify-center text-indigo-400"
          style={{ background: "rgba(99,102,241,0.15)", border: "1px solid rgba(99,102,241,0.3)" }}>
          <ShieldIcon size={26} />
        </div>
        <h2 className="text-4xl font-black text-white tracking-tight">
          Stop shipping AI code blind.
        </h2>
        <p className="text-white/45 text-lg max-w-xl mx-auto leading-relaxed">
          Every AI assistant can introduce vulnerabilities. TrustLedger makes sure a human reviewed and signed off before any of it reaches production.
        </p>
        <div className="flex flex-col sm:flex-row items-center justify-center gap-3 pt-2">
          <Link href="/dashboard"
            className="flex items-center gap-2 px-8 py-4 rounded-xl text-white font-bold transition-all active:scale-[0.98]"
            style={{ background: "linear-gradient(135deg,#6366f1,#7c3aed)", boxShadow: "0 4px 24px rgba(99,102,241,0.45)" }}>
            See the live demo
            <ArrowRightIcon />
          </Link>
          <a href="mailto:hello@trustledger.dev"
            className="flex items-center gap-2 px-8 py-4 rounded-xl text-white/60 font-semibold transition-all border border-white/[0.1] hover:border-white/[0.2] hover:text-white/80"
            style={{ background: "rgba(255,255,255,0.04)" }}>
            Talk to sales
          </a>
        </div>
      </div>
    </section>
  );
}

// ── Footer ─────────────────────────────────────────────────────────────────────

function Footer() {
  return (
    <footer className="py-12 px-5 border-t border-white/[0.06]"
      style={{ background: "#020617" }}>
      <div className="max-w-6xl mx-auto flex flex-col sm:flex-row items-start justify-between gap-8">
        <div>
          <div className="flex items-center gap-2.5 mb-3">
            <div className="w-7 h-7 rounded-lg flex items-center justify-center text-white"
              style={{ background: "linear-gradient(135deg,#6366f1,#7c3aed)" }}>
              <ShieldIcon size={14} />
            </div>
            <span className="font-bold text-white text-sm">TrustLedger</span>
          </div>
          <p className="text-xs text-white/25 max-w-xs leading-relaxed">
            AI code provenance tracking and attestation for teams that care about what ships.
          </p>
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-3 gap-8 text-sm">
          <div>
            <p className="font-bold text-white/40 text-xs uppercase tracking-wider mb-3">Product</p>
            <ul className="space-y-2">
              {[
                { label: "Features",  href: "#features"     },
                { label: "Pricing",   href: "#pricing"      },
                { label: "How it works", href: "#how-it-works" },
                { label: "Live demo", href: "/dashboard"    },
              ].map(l => (
                <li key={l.label}>
                  <a href={l.href} className="text-white/25 hover:text-white/55 transition-colors">{l.label}</a>
                </li>
              ))}
            </ul>
          </div>
          <div>
            <p className="font-bold text-white/40 text-xs uppercase tracking-wider mb-3">Compliance</p>
            <ul className="space-y-2">
              {[
                { label: "SOC 2",      href: "/reports" },
                { label: "EU AI Act",  href: "/reports" },
                { label: "PCI-DSS",    href: "/reports" },
                { label: "Reports",    href: "/reports" },
              ].map(l => (
                <li key={l.label}>
                  <Link href={l.href} className="text-white/25 hover:text-white/55 transition-colors">{l.label}</Link>
                </li>
              ))}
            </ul>
          </div>
          <div>
            <p className="font-bold text-white/40 text-xs uppercase tracking-wider mb-3">Company</p>
            <ul className="space-y-2">
              {[
                { label: "Dashboard",  href: "/dashboard" },
                { label: "Settings",   href: "/settings"  },
                { label: "Contact",    href: "mailto:hello@trustledger.dev" },
                { label: "Privacy",    href: "#"          },
              ].map(l => (
                <li key={l.label}>
                  <a href={l.href} className="text-white/25 hover:text-white/55 transition-colors">{l.label}</a>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </div>
      <div className="max-w-6xl mx-auto mt-10 pt-6 border-t border-white/[0.05] flex flex-col sm:flex-row items-center justify-between gap-3">
        <p className="text-xs text-white/18">© 2026 TrustLedger. All rights reserved.</p>
        <div className="flex items-center gap-1.5 text-xs text-white/18">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />
          All systems operational
        </div>
      </div>
    </footer>
  );
}

// ── Page ───────────────────────────────────────────────────────────────────────

export default function LandingPage() {
  return (
    <div style={{ background: "#020617" }}>
      <NavBar />
      <HeroSection />
      <FeaturesSection />
      <HowItWorksSection />
      <PricingSection />
      <CTASection />
      <Footer />
    </div>
  );
}
