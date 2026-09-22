"use client";

import Link from "next/link";
import { useEffect, useRef, useState } from "react";

const ORG = process.env.NEXT_PUBLIC_ORG ?? "acme";

// ── Design tokens ────────────────────────────────────────────────────────────
// A deliberate break from the generic indigo/violet "AI startup" gradient the
// rest of the app inherited: this page is the front door for a real static
// analysis engine (six language-specific AST taint engines, not a marketing
// gimmick), so the palette reads as a scanner/telemetry surface -- near-black
// with a precise cyan signal color -- rather than another purple blob hero.
// Severity colors (critical/high/medium) are semantic and kept separate from
// the cyan brand accent, same discipline the product's own UI already uses.

const INK = "#050810";
const SURFACE = "#0a0f1c";
const CYAN = "#22d3ee";
const ROSE = "#fb7185";
const AMBER = "#fbbf24";
const ORANGE = "#fb923c";

// ── Motion ───────────────────────────────────────────────────────────────────

/** Fades + lifts an element in once it scrolls into view. Respects
 * prefers-reduced-motion (the element is simply shown, not animated). */
function useReveal<T extends HTMLElement>() {
  const ref = useRef<T | null>(null);
  const [shown, setShown] = useState(false);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) { setShown(true); return; }
    const io = new IntersectionObserver(
      ([entry]) => { if (entry.isIntersecting) { setShown(true); io.disconnect(); } },
      { threshold: 0.15, rootMargin: "0px 0px -8% 0px" },
    );
    io.observe(el);
    return () => io.disconnect();
  }, []);
  return { ref, shown };
}

function Reveal({ children, delay = 0, className = "", style }: { children: React.ReactNode; delay?: number; className?: string; style?: React.CSSProperties }) {
  const { ref, shown } = useReveal<HTMLDivElement>();
  return (
    <div ref={ref} className={className}
      style={{
        ...style,
        opacity: shown ? 1 : 0,
        transform: shown ? "translateY(0)" : "translateY(18px)",
        transition: `opacity 0.7s cubic-bezier(0.16,1,0.3,1) ${delay}ms, transform 0.7s cubic-bezier(0.16,1,0.3,1) ${delay}ms`,
      }}>
      {children}
    </div>
  );
}

/** Counts a number up from 0 once scrolled into view. */
function CountUp({ to, suffix = "", duration = 1100 }: { to: number; suffix?: string; duration?: number }) {
  const { ref, shown } = useReveal<HTMLSpanElement>();
  const [val, setVal] = useState(0);
  useEffect(() => {
    if (!shown) return;
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) { setVal(to); return; }
    const start = performance.now();
    let raf = 0;
    const tick = (now: number) => {
      const t = Math.min(1, (now - start) / duration);
      const eased = 1 - Math.pow(1 - t, 3);
      setVal(Math.round(eased * to));
      if (t < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [shown, to, duration]);
  return <span ref={ref} className="tabular-nums">{val}{suffix}</span>;
}

// ── Icons ────────────────────────────────────────────────────────────────────

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
function ScanIcon({ size = 22 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M3 7V5a2 2 0 0 1 2-2h2M17 3h2a2 2 0 0 1 2 2v2M21 17v2a2 2 0 0 1-2 2h-2M7 21H5a2 2 0 0 1-2-2v-2" />
      <line x1="3" y1="12" x2="21" y2="12" />
    </svg>
  );
}
function GitBranchIcon({ size = 22 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <line x1="6" y1="3" x2="6" y2="15" /><circle cx="18" cy="6" r="3" /><circle cx="6" cy="18" r="3" />
      <path d="M18 9a9 9 0 0 1-9 9" />
    </svg>
  );
}
function RouteIcon({ size = 22 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="6" cy="19" r="2" /><circle cx="18" cy="5" r="2" />
      <path d="M18 7v3a5 5 0 0 1-5 5H8" />
    </svg>
  );
}
function LockIcon({ size = 22 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="11" width="18" height="11" rx="2" /><path d="M7 11V7a5 5 0 0 1 10 0v4" />
    </svg>
  );
}
function PackageIcon({ size = 22 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z" />
      <polyline points="3.27 6.96 12 12.01 20.73 6.96" /><line x1="12" y1="22.08" x2="12" y2="12" />
    </svg>
  );
}
function LayersIcon({ size = 22 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polygon points="12 2 2 7 12 12 22 7 12 2" /><polyline points="2 17 12 22 22 17" /><polyline points="2 12 12 17 22 12" />
    </svg>
  );
}
function FingerprintIcon({ size = 22 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 10a2 2 0 0 0-2 2c0 1.5-.5 2.5-1 3" /><path d="M6 8a6 6 0 0 1 12 0c0 1 0 3-1 5" />
      <path d="M15 19c1-1 2-3 2-5" /><path d="M4 14c0 2 1 4 2 5" /><path d="M9 14c0 1 0 2-1 3.5" />
      <path d="M12 4a8 8 0 0 1 8 8c0 2 0 3-.5 4.5" />
    </svg>
  );
}
function KeyIcon({ size = 22 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" />
    </svg>
  );
}

// ── Data ─────────────────────────────────────────────────────────────────────

interface VulnClass { name: string; cwe: string; group: string }
const VULN_CLASSES: VulnClass[] = [
  { name: "SQL Injection", cwe: "CWE-89", group: "Injection" },
  { name: "Command Injection", cwe: "CWE-78", group: "Injection" },
  { name: "NoSQL Injection", cwe: "CWE-943", group: "Injection" },
  { name: "LDAP Injection", cwe: "CWE-90", group: "Injection" },
  { name: "XPath Injection", cwe: "CWE-643", group: "Injection" },
  { name: "SSTI", cwe: "CWE-1336", group: "Injection" },
  { name: "Reflected XSS", cwe: "CWE-79", group: "Injection" },
  { name: "SSRF", cwe: "CWE-918", group: "Request forgery" },
  { name: "Open Redirect", cwe: "CWE-601", group: "Request forgery" },
  { name: "Path Traversal", cwe: "CWE-22", group: "Filesystem" },
  { name: "File Inclusion", cwe: "CWE-98", group: "Filesystem" },
  { name: "Insecure Deserialization", cwe: "CWE-502", group: "Data handling" },
  { name: "Mass Assignment", cwe: "CWE-915", group: "Data handling" },
  { name: "Prototype Pollution", cwe: "CWE-1321", group: "Data handling" },
  { name: "HTTP Header Injection", cwe: "CWE-113", group: "Data handling" },
  { name: "BOLA / IDOR", cwe: "CWE-639", group: "Authorization" },
  { name: "JWT Signature Bypass", cwe: "CWE-347", group: "Authorization" },
  { name: "Timing Attack", cwe: "CWE-208", group: "Authorization" },
  { name: "ReDoS", cwe: "CWE-1333", group: "Availability" },
  { name: "Arbitrary Code Execution", cwe: "CWE-95", group: "Availability" },
];

interface LangEngine { lang: string; ext: string; note: string; extra: string }
const LANGUAGES: LangEngine[] = [
  { lang: "TypeScript / JavaScript", ext: ".ts .tsx .js", note: "Cross-file resolution + source-sink trace", extra: "Named, default, namespace & CommonJS imports" },
  { lang: "Python", ext: ".py", note: "Cross-file resolution + source-sink trace", extra: "Relative & absolute imports, package modules" },
  { lang: "Go", ext: ".go", note: "Path-sensitive, BOLA ownership dominance", extra: "Request/writer var tracking, out-parameters" },
  { lang: "C#", ext: ".cs", note: "Path-sensitive, BOLA ownership dominance", extra: "ASP.NET Core attribute-driven sources" },
  { lang: "PHP", ext: ".php", note: "Path-sensitive, BOLA ownership dominance", extra: "Global-scope sticky memory across functions" },
  { lang: "Java", ext: ".java", note: "Spring annotation & entry-point aware", extra: "Two-tier confidence for un-annotated params" },
];

const FEATURES = [
  {
    icon: <ScanIcon />,
    title: "Real AST Taint Engines",
    desc: "A dedicated parser and data-flow engine per language — not one regex ruleset stretched across six syntaxes. Sources, sanitizers, and sinks are tracked as real program state, with path-sensitive branch merging so a sanitized branch doesn't false-positive and an unsanitized one doesn't get missed.",
    accent: CYAN,
  },
  {
    icon: <RouteIcon />,
    title: "Source → Sink Traces",
    desc: "Every finding ships with the actual data-flow path — a bounded backward slice from the sink back to its origin, hop by hop, with real file and line numbers at each step, including across a file boundary.",
    accent: CYAN,
  },
  {
    icon: <GitBranchIcon />,
    title: "Cross-File Resolution",
    desc: "Named, default, namespace, and CommonJS imports; re-export chains; a bounded multi-hop fixed point so a wrapper around an imported call is still recognized as propagating — not just one file at a time.",
    accent: CYAN,
  },
  {
    icon: <LockIcon />,
    title: "Broken Object-Level Authorization",
    desc: "Structural ownership-dominance analysis, not a keyword-proximity guess: a resource lookup is only cleared when a real comparison against the authenticated principal dominates it on every path that reaches the sink.",
    accent: ROSE,
  },
  {
    icon: <PackageIcon />,
    title: "Dependency & Supply Chain (SCA)",
    desc: "Live CVE lookups against OSV.dev across npm, PyPI, Go, Maven, NuGet, Packagist, crates.io, and RubyGems — plus hallucinated-package and typosquat detection for every manifest, from package.json to composer.json.",
    accent: AMBER,
  },
  {
    icon: <FingerprintIcon />,
    title: "Stable Finding Fingerprints",
    desc: "Every finding gets a hash of its own flow, not its line number — the same vulnerability survives unrelated edits elsewhere in the file across scans, so you can track a finding from first detection to fix.",
    accent: CYAN,
  },
  {
    icon: <LayersIcon />,
    title: "Benchmark-Backed Recall",
    desc: "A 60+7-case hard benchmark per language, committed to the repo and re-run on every change, gating on a per-case regression diff — not just an aggregate score that can silently mask a real loss.",
    accent: CYAN,
  },
  {
    icon: <KeyIcon />,
    title: "Context-Aware Sanitizers",
    desc: "Escaping is checked against where a value actually lands — an HTML-escaped value dropped into a <script> block or an unquoted attribute is still flagged, because encoding for one context doesn't make a value safe in another.",
    accent: ROSE,
  },
];

const STEPS = [
  { n: 1, title: "Connect your repos", desc: "Install the GitHub App in under 2 minutes (GitLab and Bitbucket also supported). Every pull request is scanned automatically — no config files, no CI changes." },
  { n: 2, title: "Get a real data-flow trace, not a guess", desc: "Each finding shows the exact path from source to sink, the sink-class it violates, and the file/line at every hop — including across a file boundary." },
  { n: 3, title: "Attest. Gate. Deploy.", desc: "Reviewers sign off on flagged files directly in the dashboard. Policy gates block merges until required attestations and fixes are recorded." },
];

const WHY_ROWS = [
  {
    vs: "Regex-based scanners",
    them: "Match a pattern on one line. No concept of whether the value is actually attacker-controlled, whether it was sanitized first, or whether it even reaches a sink.",
    us: "Real data-flow: a bitmask of sink classes carried from source to sink, cleared only by a sanitizer that actually neutralizes that class — an HTML escaper clears XSS, not SQL injection.",
    accent: CYAN,
  },
  {
    vs: "Single-file scanners",
    them: "Stop at the file boundary. A wrapper function that calls an imported helper looks untainted, because the helper's own body is in a different file.",
    us: "A bounded multi-hop cross-file resolver: named/default/namespace imports, re-export chains, and a wrapper around a cross-file call is itself recognized as propagating.",
    accent: CYAN,
  },
  {
    vs: "Manual review + spreadsheets",
    them: "Reviewers eyeball the diff, chase compliance evidence by hand, and re-derive the same data-flow analysis a computer already proved, every single time.",
    us: "Every finding carries its own proof — a real trace, a stable fingerprint, and a severity backed by CWE — so review time goes to judgment calls, not re-deriving whether a flow exists.",
    accent: AMBER,
  },
];

const ARCH_FACTS = [
  { label: "Sink-class bitmask model", desc: "A taint value is a bitmask of 15 sink classes (SQL, command, XSS, SSRF, path, header, LDAP, XPath, NoSQL, SSTI, eval, deserialization, redirect, include, control), not a boolean. A sanitizer clears only the classes it actually neutralizes." },
  { label: "Path-sensitive propagation", desc: "Branches are walked on cloned state and merged with a may-taint join; an arm that returns or throws is dropped from the join. A value sanitized on one branch and raw on another is tracked correctly on both." },
  { label: "Narrow validation guards", desc: "Only unambiguous proofs clear a variable — literal-collection membership, strict numeric checks, equality with a literal. A regex match or a custom validator function is deliberately NOT trusted." },
  { label: "BOLA ownership dominance", desc: "An authorization check only suppresses a finding when it actually dominates the sink in control-flow order, for the same resource id the sink uses — not merely present somewhere in the function." },
  { label: "Bounded interprocedural analysis", desc: "Same-file call chains resolve through a fixed-point worklist, capped at 3 rounds, so A calling B calling C converges without becoming an unbounded whole-program solve." },
  { label: "Cross-file fixed point", desc: "Export summaries are recomputed across up to 3 rounds so a file that only wraps an imported call still gets credited with propagating it — closing the one-hop cap a naive cross-file pass would have." },
];

// ── Shared UI ────────────────────────────────────────────────────────────────

function Eyebrow({ children, color = CYAN }: { children: React.ReactNode; color?: string }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-[11px] font-bold uppercase tracking-[0.14em] px-3 py-1.5 rounded-full border font-mono"
      style={{ color, background: `${color}14`, borderColor: `${color}33` }}>
      {children}
    </span>
  );
}

// ── NavBar ───────────────────────────────────────────────────────────────────

function NavBar() {
  return (
    <header className="fixed top-0 inset-x-0 z-50 border-b" style={{ borderColor: "rgba(255,255,255,0.06)", background: "rgba(5,8,16,0.82)", backdropFilter: "blur(16px) saturate(160%)" }}>
      <div className="max-w-6xl mx-auto px-5 h-14 flex items-center justify-between gap-4">
        <div className="flex items-center gap-2.5">
          <div className="w-7 h-7 rounded-lg flex items-center justify-center text-[#050810]" style={{ background: CYAN, boxShadow: `0 0 20px ${CYAN}55` }}>
            <ShieldIcon size={14} />
          </div>
          <span className="font-bold text-white text-sm tracking-tight">TrustLedger</span>
        </div>

        <nav className="hidden md:flex items-center gap-6">
          {["Vulnerabilities", "Engines", "Features", "How it works"].map(l => (
            <a key={l} href={`#${l.toLowerCase().replace(/ /g, "-")}`} className="text-sm text-white/45 hover:text-white/80 transition-colors font-medium">
              {l}
            </a>
          ))}
        </nav>

        <div className="flex items-center gap-2">
          <Link href="/login" className="text-sm font-semibold text-white/50 hover:text-white transition-colors px-3 py-1.5">Sign in</Link>
          <Link href="/login" className="flex items-center gap-1.5 text-sm font-bold px-3.5 py-1.5 rounded-lg transition-all text-[#050810]" style={{ background: CYAN, boxShadow: `0 2px 16px ${CYAN}4d` }}>
            Get started <ArrowRightIcon size={13} />
          </Link>
        </div>
      </div>
    </header>
  );
}

// ── Hero: trace visualization ───────────────────────────────────────────────

const TRACE_STEPS = [
  { kind: "source", file: "route.ts", line: 3, label: "req.query.id", tone: CYAN },
  { kind: "assignment", file: "route.ts", line: 4, label: "const q = buildQuery(id)", tone: "#94a3b8" },
  { kind: "cross-file", file: "→ db.ts", line: 2, label: "crosses into ./db via \"buildQuery\"", tone: AMBER },
  { kind: "sink", file: "route.ts", line: 5, label: "db.execute(q)", tone: ROSE },
];

function TraceVisual() {
  const { ref, shown } = useReveal<HTMLDivElement>();
  return (
    <div ref={ref} className="relative rounded-2xl overflow-hidden border" style={{ borderColor: "rgba(255,255,255,0.08)", background: "linear-gradient(180deg, rgba(10,15,28,0.9), rgba(6,10,18,0.95))", boxShadow: "0 40px 90px rgba(0,0,0,0.55), 0 0 0 1px rgba(255,255,255,0.03)" }}>
      <div className="px-4 py-2.5 flex items-center gap-2 border-b" style={{ borderColor: "rgba(255,255,255,0.06)", background: "rgba(255,255,255,0.02)" }}>
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full" style={{ background: `${ROSE}80` }} />
          <span className="w-2.5 h-2.5 rounded-full" style={{ background: `${AMBER}80` }} />
          <span className="w-2.5 h-2.5 rounded-full" style={{ background: "#34d39980" }} />
        </div>
        <span className="text-[11px] font-mono font-semibold ml-2 text-white/50">how a trace reads</span>
        <span className="ml-auto text-[10px] font-mono text-white/20">illustrative example</span>
      </div>

      <div className="p-5 sm:p-6 font-mono text-[12.5px]">
        {TRACE_STEPS.map((s, i) => (
          <div key={i} className="relative flex gap-4 pb-6 last:pb-0">
            {i < TRACE_STEPS.length - 1 && (
              <span className="absolute left-[9px] top-6 bottom-0 w-px overflow-hidden" style={{ background: "rgba(255,255,255,0.08)" }}>
                <span className="block w-full" style={{
                  height: "40%", background: `linear-gradient(180deg, transparent, ${CYAN}, transparent)`,
                  animation: shown ? `traceFlow 2.2s ${0.15 + i * 0.15}s ease-in-out infinite` : "none",
                }} />
              </span>
            )}
            <span className="relative z-10 w-[19px] h-[19px] rounded-full border-2 flex items-center justify-center shrink-0 mt-0.5"
              style={{ borderColor: s.tone, background: INK, opacity: shown ? 1 : 0, transform: shown ? "scale(1)" : "scale(0.4)", transition: `opacity 0.4s ${i * 0.13}s, transform 0.4s ${i * 0.13}s cubic-bezier(0.34,1.56,0.64,1)` }}>
              <span className="w-[7px] h-[7px] rounded-full" style={{ background: s.tone }} />
            </span>
            <div style={{ opacity: shown ? 1 : 0, transform: shown ? "translateX(0)" : "translateX(-8px)", transition: `opacity 0.4s ${i * 0.13 + 0.05}s, transform 0.4s ${i * 0.13 + 0.05}s` }}>
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-[9px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded" style={{ color: s.tone, background: `${s.tone}1a` }}>{s.kind}</span>
                <span className="text-white/25 text-[11px]">{s.file}:{s.line}</span>
              </div>
              <p className="mt-1 text-white/75">{s.label}</p>
            </div>
          </div>
        ))}
      </div>

      <style>{`@keyframes traceFlow { 0% { transform: translateY(-140%); } 100% { transform: translateY(340%); } }`}</style>
    </div>
  );
}

// ── HeroSection ──────────────────────────────────────────────────────────────

function HeroSection() {
  return (
    <section className="relative flex flex-col items-center justify-center text-center px-5 pt-32 pb-20 overflow-hidden" style={{ background: `radial-gradient(ellipse 90% 60% at 50% 0%, ${CYAN}14, transparent 60%), ${INK}` }}>
      <div className="absolute inset-0 pointer-events-none overflow-hidden">
        <div className="absolute inset-0" style={{ backgroundImage: "linear-gradient(rgba(255,255,255,0.022) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.022) 1px, transparent 1px)", backgroundSize: "56px 56px" }} />
        <div className="absolute bottom-0 left-0 right-0 h-52" style={{ background: `linear-gradient(to top, ${INK}, transparent)` }} />
      </div>

      <Reveal className="relative max-w-4xl mx-auto space-y-6">
        <Eyebrow>
          <span className="w-1.5 h-1.5 rounded-full" style={{ background: CYAN, boxShadow: `0 0 8px ${CYAN}` }} />
          Real data-flow analysis, six languages
        </Eyebrow>

        <h1 className="text-5xl sm:text-6xl lg:text-7xl font-black text-white tracking-tight leading-[1.05]">
          Find the flow.<br />
          <span style={{ background: `linear-gradient(90deg, ${CYAN}, #67e8f9, #a5f3fc)`, WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent", backgroundClip: "text" }}>
            Not the line.
          </span>
        </h1>

        <p className="text-lg sm:text-xl text-white/45 max-w-2xl mx-auto leading-relaxed">
          TrustLedger scans every pull request with real AST-based taint engines — six languages, twenty vulnerability classes, cross-file resolution, and a source-to-sink trace on every finding. Then it gates merges on policy and records who signed off.
        </p>

        <div className="flex flex-col sm:flex-row items-center justify-center gap-3 pt-2">
          <Link href="/login" className="flex items-center gap-2 px-6 py-3.5 rounded-xl font-bold text-sm transition-all active:scale-[0.98] text-[#050810]" style={{ background: CYAN, boxShadow: `0 4px 28px ${CYAN}4d` }}>
            Get started free <ArrowRightIcon size={15} />
          </Link>
          <Link href="/dashboard" className="flex items-center gap-2 px-6 py-3.5 rounded-xl text-white/70 font-semibold text-sm transition-all border hover:text-white/90" style={{ borderColor: "rgba(255,255,255,0.1)", background: "rgba(255,255,255,0.03)" }}>
            <GitHubIcon size={15} /> Explore the dashboard
          </Link>
        </div>
        <p className="text-xs text-white/25 font-medium pt-1">No credit card required to start</p>
      </Reveal>

      <Reveal delay={150} className="relative mt-16 w-full max-w-xl mx-auto">
        <TraceVisual />
        <div className="absolute -bottom-8 left-1/2 -translate-x-1/2 w-2/3 h-16 blur-3xl rounded-full pointer-events-none" style={{ background: CYAN, opacity: 0.14 }} />
      </Reveal>

      <Reveal delay={280} className="relative mt-16 w-full max-w-4xl mx-auto grid grid-cols-2 sm:grid-cols-4 gap-4">
        {[
          { to: 6, label: "language engines" },
          { to: 20, label: "vulnerability classes" },
          { to: 3, label: "cross-file hop rounds" },
          { to: 8, label: "SCA ecosystems (OSV.dev)" },
        ].map(s => (
          <div key={s.label} className="text-center">
            <p className="text-3xl font-black font-mono" style={{ color: CYAN }}><CountUp to={s.to} /></p>
            <p className="text-[11px] text-white/35 font-medium mt-1">{s.label}</p>
          </div>
        ))}
      </Reveal>
    </section>
  );
}

// ── Vulnerability coverage grid ─────────────────────────────────────────────

const GROUP_COLORS: Record<string, string> = {
  "Injection": CYAN, "Request forgery": ORANGE, "Filesystem": AMBER,
  "Data handling": "#a78bfa", "Authorization": ROSE, "Availability": "#34d399",
};

function VulnCoverageSection() {
  const groups = Array.from(new Set(VULN_CLASSES.map(v => v.group)));
  return (
    <section id="vulnerabilities" className="py-24 px-5" style={{ background: SURFACE }}>
      <div className="max-w-6xl mx-auto">
        <Reveal className="text-center mb-14">
          <Eyebrow>Coverage</Eyebrow>
          <h2 className="text-4xl font-black text-white mt-4 tracking-tight">Twenty vulnerability classes, real data-flow evidence</h2>
          <p className="text-white/40 mt-3 max-w-2xl mx-auto text-lg">Every finding below is matched by tracking an actual tainted value from its source to a real sink — not a keyword or a line pattern.</p>
        </Reveal>

        <div className="space-y-8">
          {groups.map((g, gi) => (
            <Reveal key={g} delay={gi * 60}>
              <div className="flex items-center gap-2 mb-3">
                <span className="w-1.5 h-1.5 rounded-full" style={{ background: GROUP_COLORS[g] }} />
                <span className="text-[11px] font-bold uppercase tracking-widest text-white/35 font-mono">{g}</span>
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-2.5">
                {VULN_CLASSES.filter(v => v.group === g).map(v => (
                  <div key={v.name} className="group flex items-center justify-between gap-2 px-3.5 py-3 rounded-xl border transition-all"
                    style={{ borderColor: "rgba(255,255,255,0.07)", background: "rgba(255,255,255,0.025)" }}>
                    <span className="text-sm font-semibold text-white/80">{v.name}</span>
                    <span className="text-[10px] font-mono text-white/25 shrink-0">{v.cwe}</span>
                  </div>
                ))}
              </div>
            </Reveal>
          ))}
        </div>
      </div>
    </section>
  );
}

// ── Language engines section ────────────────────────────────────────────────

function LanguageEngineSection() {
  return (
    <section id="engines" className="py-24 px-5" style={{ background: INK }}>
      <div className="max-w-5xl mx-auto">
        <Reveal className="text-center mb-14">
          <Eyebrow>Engines</Eyebrow>
          <h2 className="text-4xl font-black text-white mt-4 tracking-tight">Six languages. Six real parsers.</h2>
          <p className="text-white/40 mt-3 max-w-2xl mx-auto text-lg">
            Each language gets its own dedicated AST parser and taint-propagation engine, tuned to that ecosystem's own frameworks and idioms — not a single ruleset stretched across six syntaxes.
          </p>
        </Reveal>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          {LANGUAGES.map((l, i) => (
            <Reveal key={l.lang} delay={i * 70}>
              <div className="group p-5 rounded-2xl border transition-all" style={{ borderColor: "rgba(255,255,255,0.08)", background: "rgba(255,255,255,0.025)" }}
                onMouseEnter={e => { (e.currentTarget as HTMLElement).style.borderColor = `${CYAN}44`; }}
                onMouseLeave={e => { (e.currentTarget as HTMLElement).style.borderColor = "rgba(255,255,255,0.08)"; }}>
                <div className="flex items-center justify-between mb-2">
                  <span className="font-bold text-white text-sm">{l.lang}</span>
                  <span className="text-[10px] font-mono text-white/25">{l.ext}</span>
                </div>
                <p className="text-sm text-white/60 leading-relaxed">{l.note}</p>
                <p className="text-xs text-white/30 mt-1.5">{l.extra}</p>
              </div>
            </Reveal>
          ))}
        </div>
      </div>
    </section>
  );
}

// ── FeaturesSection ──────────────────────────────────────────────────────────

function FeaturesSection() {
  return (
    <section id="features" className="py-24 px-5" style={{ background: SURFACE }}>
      <div className="max-w-6xl mx-auto">
        <Reveal className="text-center mb-14">
          <Eyebrow>Features</Eyebrow>
          <h2 className="text-4xl font-black text-white mt-4 tracking-tight">Built like a scanner, not a linter</h2>
          <p className="text-white/40 mt-3 max-w-xl mx-auto text-lg">Every capability below maps to a real, tested engine component — not a roadmap slide.</p>
        </Reveal>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {FEATURES.map((f, i) => (
            <Reveal key={f.title} delay={(i % 4) * 60}>
              <div className="group relative p-5 rounded-2xl transition-all duration-200 h-full" style={{ background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.07)" }}
                onMouseEnter={e => { const el = e.currentTarget as HTMLElement; el.style.borderColor = `${f.accent}55`; el.style.transform = "translateY(-2px)"; el.style.boxShadow = `0 12px 32px ${f.accent}22`; }}
                onMouseLeave={e => { const el = e.currentTarget as HTMLElement; el.style.borderColor = "rgba(255,255,255,0.07)"; el.style.transform = "translateY(0)"; el.style.boxShadow = "none"; }}>
                <div className="w-9 h-9 rounded-lg flex items-center justify-center mb-3.5" style={{ color: f.accent, background: `${f.accent}14`, border: `1px solid ${f.accent}2a` }}>
                  {f.icon}
                </div>
                <h3 className="text-sm font-bold text-white mb-1.5">{f.title}</h3>
                <p className="text-[13px] text-white/45 leading-relaxed">{f.desc}</p>
              </div>
            </Reveal>
          ))}
        </div>
      </div>
    </section>
  );
}

// ── ArchSection ──────────────────────────────────────────────────────────────

function ArchSection() {
  return (
    <section className="py-24 px-5" style={{ background: INK }}>
      <div className="max-w-5xl mx-auto">
        <Reveal className="text-center mb-14">
          <Eyebrow color="#a78bfa">Under the hood</Eyebrow>
          <h2 className="text-4xl font-black text-white mt-4 tracking-tight">A real taint model, documented in the open</h2>
          <p className="text-white/40 mt-3 text-lg max-w-2xl mx-auto">
            The propagation engine, its sanitizer model, and every design tradeoff are documented in the codebase itself — here's the shape of it.
          </p>
        </Reveal>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {ARCH_FACTS.map((s, i) => (
            <Reveal key={s.label} delay={i * 50}>
              <div className="p-5 rounded-2xl border h-full" style={{ borderColor: "rgba(255,255,255,0.07)", background: "rgba(255,255,255,0.02)" }}>
                <div className="flex items-center gap-2 mb-3">
                  <span className="text-[10px] font-black tabular-nums w-5 h-5 rounded-md flex items-center justify-center shrink-0 font-mono" style={{ background: "rgba(167,139,250,0.15)", color: "#a78bfa", border: "1px solid rgba(167,139,250,0.25)" }}>
                    {String(i + 1).padStart(2, "0")}
                  </span>
                  <p className="text-xs font-bold text-white/80">{s.label}</p>
                </div>
                <p className="text-xs text-white/40 leading-relaxed">{s.desc}</p>
              </div>
            </Reveal>
          ))}
        </div>

        <Reveal delay={200} className="mt-10 rounded-2xl border overflow-hidden" style={{ borderColor: "rgba(255,255,255,0.08)", background: "rgba(255,255,255,0.02)" }}>
          <div className="px-6 py-4 border-b" style={{ borderColor: "rgba(255,255,255,0.06)" }}>
            <p className="text-[10px] font-black uppercase tracking-widest text-white/25 font-mono">Scan pipeline — per file</p>
          </div>
          <div className="px-6 py-6 flex flex-wrap items-center gap-2 font-mono">
            {["Parse (AST)", "Source recognition", "Sink-class mask", "Path-sensitive walk", "Sanitizer clears", "Cross-file resolve", "BOLA dominance", "Trace + fingerprint"].map((step, i, arr) => (
              <div key={step} className="flex items-center gap-2">
                <div className="px-3 py-1.5 rounded-lg text-[11px] font-bold text-white/60 border" style={{ background: "rgba(255,255,255,0.03)", borderColor: "rgba(255,255,255,0.08)" }}>{step}</div>
                {i < arr.length - 1 && (
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="rgba(255,255,255,0.2)" strokeWidth="2.5"><line x1="5" y1="12" x2="19" y2="12" /><polyline points="12 5 19 12 12 19" /></svg>
                )}
              </div>
            ))}
          </div>
        </Reveal>
      </div>
    </section>
  );
}

// ── WhySection ───────────────────────────────────────────────────────────────

function WhySection() {
  return (
    <section className="py-24 px-5" style={{ background: SURFACE }}>
      <div className="max-w-5xl mx-auto">
        <Reveal className="text-center mb-14">
          <Eyebrow>Why TrustLedger</Eyebrow>
          <h2 className="text-4xl font-black text-white mt-4 tracking-tight">Proof, not a pattern match</h2>
          <p className="text-white/40 mt-3 text-lg max-w-2xl mx-auto">Every finding traces back to a real flow through your code — reviewers spend time on judgment calls, not re-deriving whether the bug is real.</p>
        </Reveal>

        <div className="space-y-4">
          {WHY_ROWS.map((row, i) => (
            <Reveal key={row.vs} delay={i * 70}>
              <div className="rounded-2xl border overflow-hidden" style={{ borderColor: "rgba(255,255,255,0.07)", background: "rgba(255,255,255,0.02)" }}>
                <div className="px-6 py-3 border-b" style={{ borderColor: "rgba(255,255,255,0.06)", background: "rgba(255,255,255,0.015)" }}>
                  <span className="text-[11px] font-bold uppercase tracking-widest text-white/25 font-mono">vs </span>
                  <span className="text-xs font-bold text-white/40">{row.vs}</span>
                </div>
                <div className="grid md:grid-cols-2 divide-y md:divide-y-0 md:divide-x divide-white/[0.06]">
                  <div className="px-6 py-5">
                    <p className="text-[10px] font-bold uppercase tracking-widest text-white/20 mb-2">They do</p>
                    <p className="text-sm text-white/40 leading-relaxed">{row.them}</p>
                  </div>
                  <div className="px-6 py-5">
                    <p className="text-[10px] font-bold uppercase tracking-widest mb-2" style={{ color: `${row.accent}cc` }}>TrustLedger does</p>
                    <p className="text-sm text-white/70 leading-relaxed">{row.us}</p>
                  </div>
                </div>
              </div>
            </Reveal>
          ))}
        </div>
      </div>
    </section>
  );
}

// ── HowItWorksSection ────────────────────────────────────────────────────────

function HowItWorksSection() {
  return (
    <section id="how-it-works" className="py-24 px-5" style={{ background: INK }}>
      <div className="max-w-4xl mx-auto">
        <Reveal className="text-center mb-14">
          <Eyebrow>How it works</Eyebrow>
          <h2 className="text-4xl font-black text-white mt-4 tracking-tight">Up and running in 5 minutes</h2>
          <p className="text-white/40 mt-3 text-lg">No CI/CD changes. No config files. Install once and every PR is scanned automatically.</p>
        </Reveal>

        <div className="space-y-4">
          {STEPS.map((s, i) => (
            <Reveal key={s.n} delay={i * 80}>
              <div className="flex gap-6 p-6 rounded-2xl border transition-colors" style={{ borderColor: "rgba(255,255,255,0.07)", background: "rgba(255,255,255,0.025)" }}>
                <div className="w-10 h-10 rounded-xl flex items-center justify-center font-black text-sm shrink-0 text-[#050810]" style={{ background: CYAN, boxShadow: `0 4px 16px ${CYAN}4d` }}>{s.n}</div>
                <div>
                  <h3 className="font-bold text-white mb-1">{s.title}</h3>
                  <p className="text-sm text-white/45 leading-relaxed">{s.desc}</p>
                </div>
              </div>
            </Reveal>
          ))}
        </div>

        <Reveal delay={260} className="mt-10 p-5 rounded-2xl overflow-x-auto border" style={{ borderColor: "rgba(255,255,255,0.08)", background: "#080b12" }}>
          <p className="text-xs text-white/30 font-mono mb-3"># Or submit scans via the REST API</p>
          <pre className="text-xs font-mono leading-relaxed whitespace-pre" style={{ color: "#5eead4" }}>{`curl -X POST https://app.trustledger.dev/api/scans \\
  -H 'X-TrustLedger-Key: YOUR_API_KEY' \\
  -H 'Content-Type: application/json' \\
  -d '{"repo": "myorg/myrepo", "pr_number": 42,
       "commit_sha": "abc1234",
       "files": [{"path": "src/auth.py", "content": "..."}]}'`}</pre>
        </Reveal>
      </div>
    </section>
  );
}

// ── CTASection ───────────────────────────────────────────────────────────────

function CTASection() {
  return (
    <section className="py-24 px-5 relative overflow-hidden" style={{ background: `radial-gradient(ellipse 70% 60% at 50% 40%, ${CYAN}14, transparent 65%), ${SURFACE}` }}>
      <Reveal className="relative max-w-3xl mx-auto text-center space-y-6">
        <div className="w-14 h-14 rounded-2xl mx-auto flex items-center justify-center" style={{ color: CYAN, background: `${CYAN}14`, border: `1px solid ${CYAN}33` }}>
          <ShieldIcon size={26} />
        </div>
        <h2 className="text-4xl font-black text-white tracking-tight">Stop shipping vulnerabilities blind.</h2>
        <p className="text-white/45 text-lg max-w-xl mx-auto leading-relaxed">
          SQL injection, SSRF, broken authorization, and vulnerable dependencies can all slip into a PR unnoticed. TrustLedger proves the flow, traces it to the sink, and makes sure a human signed off before any of it reaches production.
        </p>
        <div className="flex flex-col sm:flex-row items-center justify-center gap-3 pt-2">
          <Link href="/dashboard" className="flex items-center gap-2 px-8 py-4 rounded-xl font-bold transition-all active:scale-[0.98] text-[#050810]" style={{ background: CYAN, boxShadow: `0 4px 28px ${CYAN}4d` }}>
            See the platform in action <ArrowRightIcon />
          </Link>
          <a href="mailto:hello@trustledger.dev" className="flex items-center gap-2 px-8 py-4 rounded-xl text-white/60 font-semibold transition-all border hover:text-white/80" style={{ borderColor: "rgba(255,255,255,0.1)", background: "rgba(255,255,255,0.03)" }}>
            Contact us
          </a>
        </div>
      </Reveal>
    </section>
  );
}

// ── Footer ───────────────────────────────────────────────────────────────────

function Footer() {
  return (
    <footer className="py-12 px-5 border-t" style={{ borderColor: "rgba(255,255,255,0.06)", background: INK }}>
      <div className="max-w-6xl mx-auto flex flex-col sm:flex-row items-start justify-between gap-8">
        <div>
          <div className="flex items-center gap-2.5 mb-3">
            <div className="w-7 h-7 rounded-lg flex items-center justify-center text-[#050810]" style={{ background: CYAN }}>
              <ShieldIcon size={14} />
            </div>
            <span className="font-bold text-white text-sm">TrustLedger</span>
          </div>
          <p className="text-xs text-white/25 max-w-xs leading-relaxed">
            Real data-flow vulnerability scanning, AI code governance, and dependency risk — scanned, traced, gated, and attested — for teams that care about what ships.
          </p>
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-3 gap-8 text-sm">
          <div>
            <p className="font-bold text-white/40 text-xs uppercase tracking-wider mb-3">Product</p>
            <ul className="space-y-2">
              {[{ label: "Vulnerabilities", href: "#vulnerabilities" }, { label: "Engines", href: "#engines" }, { label: "Features", href: "#features" }, { label: "Explore dashboard", href: "/dashboard" }].map(l => (
                <li key={l.label}><a href={l.href} className="text-white/25 hover:text-white/55 transition-colors">{l.label}</a></li>
              ))}
            </ul>
          </div>
          <div>
            <p className="font-bold text-white/40 text-xs uppercase tracking-wider mb-3">Compliance</p>
            <ul className="space-y-2">
              {[{ label: "SOC 2", href: "/reports" }, { label: "EU AI Act", href: "/reports" }, { label: "PCI-DSS", href: "/reports" }, { label: "Reports", href: "/reports" }].map(l => (
                <li key={l.label}><Link href={l.href} className="text-white/25 hover:text-white/55 transition-colors">{l.label}</Link></li>
              ))}
            </ul>
          </div>
          <div>
            <p className="font-bold text-white/40 text-xs uppercase tracking-wider mb-3">Company</p>
            <ul className="space-y-2">
              {[{ label: "Dashboard", href: "/dashboard" }, { label: "Settings", href: "/settings" }, { label: "Contact", href: "mailto:hello@trustledger.dev" }, { label: "Privacy", href: "/privacy" }, { label: "Terms", href: "/terms" }].map(l => (
                <li key={l.label}><a href={l.href} className="text-white/25 hover:text-white/55 transition-colors">{l.label}</a></li>
              ))}
            </ul>
          </div>
        </div>
      </div>
      <div className="max-w-6xl mx-auto mt-10 pt-6 border-t flex flex-col sm:flex-row items-center justify-between gap-3" style={{ borderColor: "rgba(255,255,255,0.05)" }}>
        <p className="text-xs text-white/18">© 2026 TrustLedger. All rights reserved.</p>
        <div className="flex items-center gap-1.5 text-xs text-white/18">
          <span className="w-1.5 h-1.5 rounded-full" style={{ background: "#34d399" }} />
          All systems operational
        </div>
      </div>
    </footer>
  );
}

// ── Page ─────────────────────────────────────────────────────────────────────

export default function LandingPage() {
  void ORG;
  return (
    <div style={{ background: INK }}>
      <NavBar />
      <HeroSection />
      <VulnCoverageSection />
      <LanguageEngineSection />
      <FeaturesSection />
      <ArchSection />
      <WhySection />
      <HowItWorksSection />
      <CTASection />
      <Footer />
    </div>
  );
}
