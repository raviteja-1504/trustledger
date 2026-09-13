"use client";

import Link from "next/link";

const ORG = process.env.NEXT_PUBLIC_ORG ?? "acme";

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

function GitHubIcon({ size = 18 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="currentColor">
      <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z" />
    </svg>
  );
}

// ── Data ───────────────────────────────────────────────────────────────────────
// Mirrors the sidebar's real nav groups (Threats / Code Risk / Compliance /
// Audit) rather than describing only the AI-detection piece — the product
// has grown into a full PR-time risk platform, and the homepage was still
// pitching just the AI% slice of it.

const FEATURES = [
  {
    icon: (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M9.5 2A2.5 2.5 0 0 1 12 4.5v15a2.5 2.5 0 0 1-4.96-.46 2.5 2.5 0 0 1-2.96-3.08 3 3 0 0 1-.34-5.58 2.5 2.5 0 0 1 1.32-4.24 2.5 2.5 0 0 1 1.98-3Z" />
        <path d="M14.5 2A2.5 2.5 0 0 0 12 4.5v15a2.5 2.5 0 0 0 4.96-.46 2.5 2.5 0 0 0 2.96-3.08 3 3 0 0 0 .34-5.58 2.5 2.5 0 0 0-1.32-4.24 2.5 2.5 0 0 0-1.98-3Z" />
      </svg>
    ),
    title: "AI Detection Engine",
    desc: "47 signals across AST structure, semantic call-graphs, and git provenance — detects AI-generated code and attributes it to the tool that wrote it.",
    accent: "from-violet-500 to-indigo-600",
    tag: "ML + Static Analysis",
    glow: "rgba(124,58,237,0.2)",
  },
  {
    icon: (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <rect x="3" y="11" width="18" height="11" rx="2" /><path d="M7 11V7a5 5 0 0 1 10 0v4" />
      </svg>
    ),
    title: "Secrets Detection",
    desc: "Flags hardcoded API keys, tokens, and credentials the moment they land in a PR — before they reach a commit history you can't rewrite.",
    accent: "from-rose-500 to-pink-600",
    tag: "Secrets",
    glow: "rgba(244,63,94,0.2)",
  },
  {
    icon: (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z" />
        <polyline points="3.27 6.96 12 12.01 20.73 6.96" /><line x1="12" y1="22.08" x2="12" y2="12" />
      </svg>
    ),
    title: "Dependency & Supply Chain Risk",
    desc: "Tracks vulnerable and phantom dependencies across every repo, with an exportable AI Bill of Materials (AIBOM) for procurement and audit requests.",
    accent: "from-sky-500 to-blue-600",
    tag: "SBOM",
    glow: "rgba(56,189,248,0.2)",
  },
  {
    icon: (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
        <polyline points="9 12 11 14 15 10" />
      </svg>
    ),
    title: "Policy Engine & PR Gating",
    desc: "Define merge gates per risk level. Require reviewer sign-off on CRITICAL files, block MEDIUM-risk code in regulated repos. Presets included, fully configurable.",
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
    title: "Status Checks Everywhere",
    desc: "Posts pass/fail checks directly on pull requests across GitHub, GitLab, and Bitbucket. Comments a risk summary so reviewers see exactly what needs attention.",
    accent: "from-slate-600 to-slate-800",
    tag: "Integration",
    glow: "rgba(100,116,139,0.2)",
  },
  {
    icon: (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" />
        <path d="M13.73 21a2 2 0 0 1-3.46 0" />
      </svg>
    ),
    title: "Incident Response & Alerting",
    desc: "Auto-escalates unattested CRITICAL findings into tracked incidents with SLA deadlines, and fires real-time alerts to Slack, email, or PagerDuty on policy breaches.",
    accent: "from-amber-500 to-orange-600",
    tag: "Response",
    glow: "rgba(245,158,11,0.2)",
  },
  {
    icon: (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
        <polyline points="14 2 14 8 20 8" />
        <line x1="16" y1="13" x2="8" y2="13" /><line x1="16" y1="17" x2="8" y2="17" />
      </svg>
    ),
    title: "Compliance Evidence",
    desc: "Cryptographically-signed audit packages mapped to SOC 2, EU AI Act Article 9, and PCI-DSS Req. 6.4 — plus a compliance calendar for recurring obligations.",
    accent: "from-emerald-500 to-teal-600",
    tag: "Compliance",
    glow: "rgba(16,185,129,0.2)",
  },
  {
    icon: (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" /><circle cx="9" cy="7" r="4" />
        <path d="M23 21v-2a4 4 0 0 0-3-3.87" /><path d="M16 3.13a4 4 0 0 1 0 7.75" />
      </svg>
    ),
    title: "Reviewer Attestation & Audit Trail",
    desc: "Named reviewer sign-off recorded per file with signature, timestamp, and risk context at review time. An immutable log that answers 'who reviewed this, and when' — forever.",
    accent: "from-fuchsia-500 to-purple-600",
    tag: "Audit Trail",
    glow: "rgba(217,70,239,0.2)",
  },
  {
    icon: (
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
      </svg>
    ),
    title: "Real-Time Security Posture",
    desc: "One score per org, trended over time — health, AI adoption, attestation coverage, SLA compliance, and open risk, all in a dashboard your board can read.",
    accent: "from-cyan-500 to-teal-600",
    tag: "Visibility",
    glow: "rgba(45,212,191,0.2)",
  },
];

const STEPS = [
  {
    n: "01",
    title: "Connect your repos",
    desc: "Install the GitHub App in under 2 minutes (GitLab and Bitbucket also supported). TrustLedger scans every pull request automatically — no config files, no CI changes.",
    color: "from-indigo-500 to-violet-600",
    num: 1,
  },
  {
    n: "02",
    title: "See every risk in one place",
    desc: "Each PR shows AI% per file, flagged secrets, vulnerable dependencies, and a risk score. Expand any file to read the source with risky lines highlighted.",
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

const WHY_ROWS = [
  {
    vs: "GitHub Advanced Security / Snyk",
    them: "Finds known CVEs in dependencies and secrets in committed history — after the fact.",
    us: "Catches AI-written code risk, hardcoded secrets, and vulnerable dependencies together, at PR time — before any of it merges. Complements GHAS/Snyk; doesn't replace them.",
    accent: "#6366f1",
  },
  {
    vs: "SonarQube / Semgrep",
    them: "Static analysis rules run on the final diff. No concept of who — or what — wrote the code, and no path from a finding to a resolution.",
    us: "Attributes code to the AI tool that wrote it, tracks every finding through to a named reviewer's sign-off, and rolls it into an SLA-tracked queue instead of a report nobody closes out.",
    accent: "#10b981",
  },
  {
    vs: "Manual review + spreadsheets",
    them: "Reviewers eyeball the diff, chase compliance evidence by hand, and track incidents in a doc that's out of date by Friday.",
    us: "Every PR gets a risk score, a named attestation, and an audit-ready trail. Violations, incidents, and compliance evidence live in one system that's always current — because it's generated, not maintained.",
    accent: "#f59e0b",
  },
];

const ARCH_SIGNALS = [
  { label: "AST structural analysis",        desc: "Parses source into an abstract syntax tree and scores structural patterns that correlate with LLM output — long function bodies, uniform naming, missing edge-case handling." },
  { label: "SSA-form taint tracking",         desc: "Converts code to static single-assignment form and follows tainted data across function boundaries. Catches injection paths and credential leaks that single-file scanners miss." },
  { label: "Cross-file semantic graph",       desc: "Builds a call graph across the entire PR. Detects AI-generated glue code that wires together real modules in unsafe ways — a class of bug invisible to per-file tools." },
  { label: "Git provenance scoring",          desc: "Scores commit velocity, message entropy, signing rate, and LOC/commit ratio against norms. A 1,300 LOC/commit average from a single author is a signal, not a fact — weighted accordingly." },
  { label: "Developer baseline deviation",    desc: "Tracks each GitHub login's historical AI%, file count, and commit cadence. A sudden 3× spike in AI content on a PR flags as anomalous even if the absolute score is moderate." },
  { label: "AI tool attribution",             desc: "Detects .cursor/, .claude/, .copilot-instructions, Windsurf config, and inline marker comments to attribute code to specific AI assistants — not just 'AI wrote this' but 'Cursor wrote this'." },
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
          {["Features", "Why TrustLedger", "How it works"].map(l => (
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
        <div className="absolute top-[38%] left-1/2 -translate-x-1/2 -translate-y-1/2 w-[700px] h-[700px] rounded-full"
          style={{ background: "radial-gradient(circle, rgba(99,102,241,0.18) 0%, transparent 65%)" }} />
        <div className="absolute bottom-[5%] left-[15%] w-[500px] h-[350px] rounded-full"
          style={{ background: "radial-gradient(circle, rgba(168,85,247,0.1) 0%, transparent 70%)" }} />
        <div className="absolute top-[20%] right-[10%] w-[350px] h-[350px] rounded-full"
          style={{ background: "radial-gradient(circle, rgba(59,130,246,0.1) 0%, transparent 70%)" }} />
        <div className="absolute inset-0"
          style={{ backgroundImage: "linear-gradient(rgba(255,255,255,0.025) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.025) 1px, transparent 1px)", backgroundSize: "64px 64px", opacity: 1 }} />
        <div className="absolute bottom-0 left-0 right-0 h-40"
          style={{ background: "linear-gradient(to top, #020617, transparent)" }} />
      </div>

      <div className="relative max-w-4xl mx-auto space-y-6">
        {/* Badge */}
        <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full text-xs font-semibold text-indigo-300 border"
          style={{ background: "rgba(99,102,241,0.1)", borderColor: "rgba(99,102,241,0.25)" }}>
          <span className="w-1.5 h-1.5 rounded-full bg-indigo-400 animate-pulse" />
          One gate for AI code, secrets & dependency risk
        </div>

        {/* Headline */}
        <h1 className="text-5xl sm:text-6xl lg:text-7xl font-black text-white tracking-tight leading-[1.05]">
          Know exactly<br />
          <span style={{ background: "linear-gradient(90deg, #818cf8, #a78bfa, #c084fc)", WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent", backgroundClip: "text" }}>
            what shipped
          </span><br />
          in every PR.
        </h1>

        {/* Subheadline */}
        <p className="text-lg sm:text-xl text-white/45 max-w-2xl mx-auto leading-relaxed">
          TrustLedger scans every pull request for AI-generated code, hardcoded secrets, and vulnerable dependencies — then gates merges on policy and records human sign-off, so you can always prove what shipped.
        </p>

        {/* CTAs */}
        <div className="flex flex-col sm:flex-row items-center justify-center gap-3 pt-2">
          <Link href="/login"
            className="flex items-center gap-2 px-6 py-3.5 rounded-xl text-white font-bold text-sm transition-all active:scale-[0.98]"
            style={{ background: "linear-gradient(135deg,#6366f1,#7c3aed)", boxShadow: "0 4px 24px rgba(99,102,241,0.45)" }}>
            Get started free
            <ArrowRightIcon size={15} />
          </Link>
          <Link href="/dashboard"
            className="flex items-center gap-2 px-6 py-3.5 rounded-xl text-white/70 font-semibold text-sm transition-all border border-white/10 hover:border-white/20 hover:text-white/90"
            style={{ background: "rgba(255,255,255,0.04)" }}>
            <GitHubIcon size={15} />
            Explore the dashboard
          </Link>
        </div>

        <p className="text-xs text-white/25 font-medium pt-2">
          No credit card required to start
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
                { label: "Health Score",   value: "74", color: "#f59e0b" },
                { label: "Open Violations", value: "12", color: "#f87171" },
                { label: "Secrets Found",  value: "3",  color: "#a78bfa" },
                { label: "SLA Breaches",   value: "0",  color: "#38bdf8" },
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
                { repo: "payments-core",   pr: "#104", risk: "CRITICAL", finding: "AI code · 94%",   bg: "rgba(124,58,237,0.12)", color: "#a78bfa" },
                { repo: "auth-gateway",    pr: "#204", risk: "HIGH",     finding: "Vulnerable dep",  bg: "rgba(249,115,22,0.10)", color: "#fb923c" },
                { repo: "fraud-detection", pr: "#303", risk: "CRITICAL", finding: "Hardcoded secret",bg: "rgba(244,63,94,0.12)",  color: "#fb7185" },
              ].map(row => (
                <div key={row.pr} className="px-4 py-2.5 flex items-center gap-4 border-b border-white/[0.04] last:border-0">
                  <span className="font-mono text-xs text-white/45 shrink-0">{row.repo}</span>
                  <span className="text-[10px] text-white/25 font-mono">{row.pr}</span>
                  <span className="ml-auto text-[10px] font-bold px-2 py-0.5 rounded-md" style={{ background: row.bg, color: row.color }}>{row.risk}</span>
                  <span className="text-xs font-semibold w-28 text-right" style={{ color: row.color }}>{row.finding}</span>
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
            Everything you need to govern what ships
          </h2>
          <p className="text-white/40 mt-3 max-w-xl mx-auto text-lg">
            From first scan to audit report — TrustLedger covers AI code, secrets, and dependency risk in one PR-time workflow.
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

// ── WhySection ────────────────────────────────────────────────────────────────

function WhySection() {
  return (
    <section id="why-trustledger" className="py-24 px-5"
      style={{ background: "linear-gradient(180deg, #020617 0%, #080c1a 100%)" }}>
      <div className="max-w-5xl mx-auto">
        <div className="text-center mb-14">
          <span className="text-xs font-bold uppercase tracking-widest text-indigo-400 px-3 py-1 rounded-full border"
            style={{ background: "rgba(99,102,241,0.1)", borderColor: "rgba(99,102,241,0.25)" }}>
            Why TrustLedger
          </span>
          <h2 className="text-4xl font-black text-white mt-4 tracking-tight">
            One platform, not five point tools.
          </h2>
          <p className="text-white/40 mt-3 text-lg max-w-2xl mx-auto">
            Existing scanners were built for human-written code and one risk type at a time. TrustLedger covers AI code, secrets, and dependency risk together, with a single audit trail behind all of it.
          </p>
        </div>

        <div className="space-y-4">
          {WHY_ROWS.map(row => (
            <div key={row.vs} className="rounded-2xl border border-white/[0.07] overflow-hidden"
              style={{ background: "rgba(255,255,255,0.025)" }}>
              <div className="px-6 py-3 border-b border-white/[0.06]"
                style={{ background: "rgba(255,255,255,0.02)" }}>
                <span className="text-[11px] font-bold uppercase tracking-widest"
                  style={{ color: "rgba(255,255,255,0.25)" }}>vs  </span>
                <span className="text-xs font-bold text-white/40">{row.vs}</span>
              </div>
              <div className="grid md:grid-cols-2 divide-y md:divide-y-0 md:divide-x divide-white/[0.06]">
                <div className="px-6 py-5">
                  <p className="text-[10px] font-bold uppercase tracking-widest text-white/20 mb-2">They do</p>
                  <p className="text-sm text-white/40 leading-relaxed">{row.them}</p>
                </div>
                <div className="px-6 py-5">
                  <p className="text-[10px] font-bold uppercase tracking-widest mb-2" style={{ color: `${row.accent}99` }}>TrustLedger does</p>
                  <p className="text-sm text-white/70 leading-relaxed">{row.us}</p>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

// ── ArchSection ────────────────────────────────────────────────────────────────

function ArchSection() {
  return (
    <section className="py-24 px-5"
      style={{ background: "linear-gradient(180deg, #080c1a 0%, #020617 100%)" }}>
      <div className="max-w-5xl mx-auto">
        <div className="text-center mb-14">
          <span className="text-xs font-bold uppercase tracking-widest text-violet-400 px-3 py-1 rounded-full border"
            style={{ background: "rgba(139,92,246,0.1)", borderColor: "rgba(139,92,246,0.25)" }}>
            Under the hood
          </span>
          <h2 className="text-4xl font-black text-white mt-4 tracking-tight">
            A real detection engine, not regex.
          </h2>
          <p className="text-white/40 mt-3 text-lg max-w-2xl mx-auto">
            47 signals across six analysis layers power the AI-detection half of the platform. Every scan combines static, semantic, behavioral, and provenance evidence — then weights it against your team's own baseline.
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {ARCH_SIGNALS.map((s, i) => (
            <div key={s.label} className="p-5 rounded-2xl border border-white/[0.07] transition-all duration-200 hover:border-white/[0.14]"
              style={{ background: "rgba(255,255,255,0.025)" }}>
              <div className="flex items-center gap-2 mb-3">
                <span className="text-[10px] font-black tabular-nums w-5 h-5 rounded-md flex items-center justify-center shrink-0"
                  style={{ background: "rgba(139,92,246,0.15)", color: "#a78bfa", border: "1px solid rgba(139,92,246,0.25)" }}>
                  {String(i + 1).padStart(2, "0")}
                </span>
                <p className="text-xs font-bold text-white/80">{s.label}</p>
              </div>
              <p className="text-xs text-white/40 leading-relaxed">{s.desc}</p>
            </div>
          ))}
        </div>

        {/* Architecture flow diagram */}
        <div className="mt-12 rounded-2xl border border-white/[0.08] overflow-hidden"
          style={{ background: "rgba(255,255,255,0.02)" }}>
          <div className="px-6 py-4 border-b border-white/[0.06]">
            <p className="text-[10px] font-black uppercase tracking-widest text-white/25">Scan pipeline — per PR</p>
          </div>
          <div className="px-6 py-6 flex flex-wrap items-center gap-2">
            {[
              { label: "GitHub webhook", color: "#374151" },
              { label: "QStash queue", color: "#1e3a5f" },
              { label: "File fetch", color: "#1e3a5f" },
              { label: "AST + SSA", color: "#2d1f5e" },
              { label: "Semantic graph", color: "#2d1f5e" },
              { label: "Secrets + deps", color: "#3b1f1f" },
              { label: "Git provenance", color: "#1a3a2a" },
              { label: "ML classifier", color: "#1a3a2a" },
              { label: "Risk score", color: "#3b1f1f" },
              { label: "Attestation gate", color: "#3b1f1f" },
              { label: "Check run ✓", color: "#1a3a2a" },
            ].map((step, i, arr) => (
              <div key={step.label} className="flex items-center gap-2">
                <div className="px-3 py-1.5 rounded-lg text-[11px] font-bold text-white/60"
                  style={{ background: step.color, border: "1px solid rgba(255,255,255,0.08)" }}>
                  {step.label}
                </div>
                {i < arr.length - 1 && (
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="rgba(255,255,255,0.2)" strokeWidth="2.5">
                    <line x1="5" y1="12" x2="19" y2="12"/><polyline points="12 5 19 12 12 19"/>
                  </svg>
                )}
              </div>
            ))}
          </div>
          <div className="px-6 pb-5 grid grid-cols-1 sm:grid-cols-3 gap-4 border-t border-white/[0.05] pt-5">
            {[
              { stat: "<500ms", label: "Webhook response", sub: "Scan runs async via QStash" },
              { stat: "47",     label: "Detection signals", sub: "AST · SSA · semantic · git · ML" },
              { stat: "∞",      label: "Cross-PR memory",   sub: "Identical file → auto-attested" },
            ].map(s => (
              <div key={s.label} className="text-center">
                <p className="text-2xl font-black text-violet-400 tabular-nums">{s.stat}</p>
                <p className="text-xs font-bold text-white/50 mt-1">{s.label}</p>
                <p className="text-[10px] text-white/25 mt-0.5">{s.sub}</p>
              </div>
            ))}
          </div>
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
            No CI/CD changes. No config files. Install once and every PR is scanned for AI code, secrets, and dependency risk automatically.
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
          <pre className="text-xs text-emerald-400 font-mono leading-relaxed whitespace-pre">{`curl -X POST https://app.trustledger.dev/api/scans \\
  -H 'X-TrustLedger-Key: YOUR_API_KEY' \\
  -H 'Content-Type: application/json' \\
  -d '{"repo": "myorg/myrepo", "pr_number": 42,
       "commit_sha": "abc1234",
       "files": [{"path": "src/auth.py", "content": "..."}]}'`}</pre>
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
          Stop shipping risk blind.
        </h2>
        <p className="text-white/45 text-lg max-w-xl mx-auto leading-relaxed">
          AI assistants, leaked secrets, and vulnerable dependencies can all slip into a PR unnoticed. TrustLedger makes sure a human reviewed and signed off before any of it reaches production.
        </p>
        <div className="flex flex-col sm:flex-row items-center justify-center gap-3 pt-2">
          <Link href="/dashboard"
            className="flex items-center gap-2 px-8 py-4 rounded-xl text-white font-bold transition-all active:scale-[0.98]"
            style={{ background: "linear-gradient(135deg,#6366f1,#7c3aed)", boxShadow: "0 4px 24px rgba(99,102,241,0.45)" }}>
            See the platform in action
            <ArrowRightIcon />
          </Link>
          <a href="mailto:hello@trustledger.dev"
            className="flex items-center gap-2 px-8 py-4 rounded-xl text-white/60 font-semibold transition-all border border-white/[0.1] hover:border-white/[0.2] hover:text-white/80"
            style={{ background: "rgba(255,255,255,0.04)" }}>
            Contact us
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
            AI code, secrets, and dependency risk — scanned, gated, and attested — for teams that care about what ships.
          </p>
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-3 gap-8 text-sm">
          <div>
            <p className="font-bold text-white/40 text-xs uppercase tracking-wider mb-3">Product</p>
            <ul className="space-y-2">
              {[
                { label: "Features",     href: "#features"        },
                { label: "Why TrustLedger", href: "#why-trustledger" },
                { label: "How it works", href: "#how-it-works"    },
                { label: "Explore dashboard", href: "/dashboard"  },
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
                { label: "Privacy",    href: "/privacy"   },
                { label: "Terms",      href: "/terms"     },
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
      <WhySection />
      <ArchSection />
      <HowItWorksSection />
      <CTASection />
      <Footer />
    </div>
  );
}
