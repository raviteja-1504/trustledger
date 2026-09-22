"use client";

import Link from "next/link";
import { useEffect, useRef, useState } from "react";

// ── Design tokens ────────────────────────────────────────────────────────────
// Scoped to this page only (not a global rebrand): a near-black, cyan-accented
// "scanner telemetry" palette instead of the generic indigo/violet AI-startup
// gradient. Severity/signal colors below are semantic per pillar, kept
// distinct from the cyan brand accent.

const INK = "#050810";
const SURFACE = "#0a0f1c";
const CYAN = "#22d3ee";
const ROSE = "#fb7185";
const AMBER = "#fbbf24";
const ORANGE = "#fb923c";
const VIOLET = "#a78bfa";
const EMERALD = "#34d399";
const SKY = "#38bdf8";

// ── Motion ───────────────────────────────────────────────────────────────────

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
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /><polyline points="9 12 11 14 15 10" />
    </svg>
  );
}
function ArrowRightIcon({ size = 16 }: { size?: number }) {
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><line x1="5" y1="12" x2="19" y2="12" /><polyline points="12 5 19 12 12 19" /></svg>;
}
function GitHubIcon({ size = 18 }: { size?: number }) {
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="currentColor"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z" /></svg>;
}
function iconEl(d: React.ReactNode, size = 20) {
  return <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">{d}</svg>;
}
const OverviewIcon = (s = 20) => iconEl(<><rect x="3" y="3" width="7" height="7" rx="1.5" /><rect x="14" y="3" width="7" height="7" rx="1.5" /><rect x="3" y="14" width="7" height="7" rx="1.5" /><rect x="14" y="14" width="7" height="7" rx="1.5" /></>, s);
const ThreatIcon = (s = 20) => iconEl(<path d="M13 2L3 14h9l-1 8 10-12h-9l1-8z" />, s);
const CodeRiskIcon = (s = 20) => iconEl(<><polyline points="16 18 22 12 16 6" /><polyline points="8 6 2 12 8 18" /></>, s);
const ComplianceIcon = (s = 20) => iconEl(<><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /><polyline points="9 12 11 14 15 10" /></>, s);
const AuditIcon = (s = 20) => iconEl(<><path d="M9 11l3 3L22 4" /><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11" /></>, s);
const AiIntelIcon = (s = 20) => iconEl(<><path d="M12 2a4 4 0 0 0-4 4v1a3 3 0 0 0-2 2.83V13a3 3 0 0 0 2 2.83V17a4 4 0 0 0 8 0v-1.17A3 3 0 0 0 18 13v-3.17A3 3 0 0 0 16 7V6a4 4 0 0 0-4-4z" /><line x1="12" y1="17" x2="12" y2="22" /><line x1="9" y1="22" x2="15" y2="22" /></>, s);
const ScanIcon = (s = 22) => iconEl(<><path d="M3 7V5a2 2 0 0 1 2-2h2M17 3h2a2 2 0 0 1 2 2v2M21 17v2a2 2 0 0 1-2 2h-2M7 21H5a2 2 0 0 1-2-2v-2" /><line x1="3" y1="12" x2="21" y2="12" /></>, s);
const GitBranchIcon = (s = 22) => iconEl(<><line x1="6" y1="3" x2="6" y2="15" /><circle cx="18" cy="6" r="3" /><circle cx="6" cy="18" r="3" /><path d="M18 9a9 9 0 0 1-9 9" /></>, s);
const RouteIcon = (s = 22) => iconEl(<><circle cx="6" cy="19" r="2" /><circle cx="18" cy="5" r="2" /><path d="M18 7v3a5 5 0 0 1-5 5H8" /></>, s);
const LockIcon = (s = 22) => iconEl(<><rect x="3" y="11" width="18" height="11" rx="2" /><path d="M7 11V7a5 5 0 0 1 10 0v4" /></>, s);
const PackageIcon = (s = 22) => iconEl(<><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z" /><polyline points="3.27 6.96 12 12.01 20.73 6.96" /><line x1="12" y1="22.08" x2="12" y2="12" /></>, s);
const FingerprintIcon = (s = 22) => iconEl(<><path d="M12 10a2 2 0 0 0-2 2c0 1.5-.5 2.5-1 3" /><path d="M6 8a6 6 0 0 1 12 0c0 1 0 3-1 5" /><path d="M15 19c1-1 2-3 2-5" /><path d="M4 14c0 2 1 4 2 5" /><path d="M9 14c0 1 0 2-1 3.5" /><path d="M12 4a8 8 0 0 1 8 8c0 2 0 3-.5 4.5" /></>, s);
const BellIcon = (s = 20) => iconEl(<><path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9" /><path d="M13.73 21a2 2 0 0 1-3.46 0" /></>, s);
const IncidentIcon = (s = 20) => iconEl(<><circle cx="12" cy="12" r="10" /><path d="M8 12l2.5 2.5L16 8.5" /></>, s);
const RadarIcon = (s = 20) => iconEl(<><path d="M12 2a10 10 0 1 0 10 10" /><path d="M12 6v6l4 2" /><circle cx="18" cy="6" r="3" fill="currentColor" stroke="none" /></>, s);
const GaugeIcon = (s = 20) => iconEl(<><path d="M12 2a10 10 0 1 0 10 10" strokeOpacity="0" /><polyline points="22 12 18 12 15 21 9 3 6 12 2 12" /></>, s);
const KeyIcon = (s = 20) => iconEl(<path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" />, s);
const UsersIcon = (s = 20) => iconEl(<><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" /><circle cx="9" cy="7" r="4" /><path d="M23 21v-2a4 4 0 0 0-3-3.87" /><path d="M16 3.13a4 4 0 0 1 0 7.75" /></>, s);
const ClipboardIcon = (s = 20) => iconEl(<><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><polyline points="14 2 14 8 20 8" /><line x1="16" y1="13" x2="8" y2="13" /><line x1="16" y1="17" x2="8" y2="17" /></>, s);
const FileScanIcon = (s = 20) => iconEl(<><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><polyline points="14 2 14 8 20 8" /><circle cx="11.5" cy="14.5" r="2.5" /><line x1="13.3" y1="16.3" x2="16" y2="19" /></>, s);

// ── Data ─────────────────────────────────────────────────────────────────────

interface Pillar {
  id: string; icon: (s?: number) => React.ReactNode; color: string; name: string; tagline: string;
  desc: string; bullets: string[]; pages: string[];
}
const PILLARS: Pillar[] = [
  {
    id: "overview", icon: OverviewIcon, color: CYAN, name: "Overview", tagline: "One health score for everything that touches a PR",
    desc: "A single organization-wide score blends attestation coverage, policy compliance, and critical-risk resolution into one number that trends over time — the same view your team and your board can both read.",
    bullets: [
      "Org-wide health score, trended over time, with per-repo breakdown",
      "Analytics: scan volume, finding trends, time-to-attest",
      "AI adoption, attestation coverage, and SLA compliance in one place",
      "Per-file risk drill-down from any repo view",
    ],
    pages: ["Dashboard", "Analytics", "Security Posture"],
  },
  {
    id: "threats", icon: ThreatIcon, color: ORANGE, name: "Threats", tagline: "Real-time detection, routed to the right response",
    desc: "Every policy breach becomes a tracked alert. Every unattested CRITICAL finding becomes an incident with an SLA deadline. Threat Intelligence cross-references what's actually in your codebase against active, in-the-wild exploitation — not a generic CVE mailing list.",
    bullets: [
      "Real-time alerts to Slack, email, or PagerDuty on policy breaches",
      "Incidents auto-escalate from unattested CRITICAL findings, with SLA deadlines",
      "Threat Intel flags vulnerability patterns actually detected in your repos",
      "AI-specific threat tracking for exploits that target AI-generated code patterns",
    ],
    pages: ["Violations", "Alerts", "Incidents", "Threat Intel"],
  },
  {
    id: "code-risk", icon: CodeRiskIcon, color: ROSE, name: "Code Risk", tagline: "What's actually in the code — vulnerabilities, secrets, dependencies",
    desc: "Six real AST-based taint engines trace SQL injection, XSS, SSRF, and seventeen other vulnerability classes from source to sink. The same scan flags hardcoded secrets the moment they land, and checks every dependency manifest against a live CVE feed.",
    bullets: [
      "Real data-flow taint engines: JS/TS, Python, Java, Go, C#, PHP",
      "20 vulnerability classes, each with a full source-to-sink trace",
      "Secrets detection — API keys, tokens, credentials — before they reach history",
      "Live CVE lookups (OSV.dev) across 8 ecosystems, plus typosquat detection",
    ],
    pages: ["Scan History", "Secrets", "Dependencies"],
  },
  {
    id: "compliance", icon: ComplianceIcon, color: EMERALD, name: "Compliance", tagline: "Evidence that's generated, not maintained",
    desc: "Cryptographically-signed audit packages map straight to SOC 2, EU AI Act Article 9, and PCI-DSS Req. 6.4. A CWE-mapped risk register tracks every finding with an assigned reviewer and a deadline; an SLA dashboard shows exactly what's overdue.",
    bullets: [
      "Compliance evidence mapped to SOC 2, EU AI Act, and PCI-DSS",
      "Exception management with named approval and expiry",
      "CWE-mapped Risk Register with assigned reviewers and deadlines",
      "SLA dashboard: on-track, at-risk, and severely-overdue findings",
    ],
    pages: ["Compliance", "SLA Dashboard", "Risk Register"],
  },
  {
    id: "audit", icon: AuditIcon, color: VIOLET, name: "Audit", tagline: "An immutable answer to \"who reviewed this, and when\"",
    desc: "Every attestation is recorded with a named reviewer, a signature, a timestamp, and the risk context at the moment of review. Reports export as signed evidence packages, ready for an auditor or a procurement request.",
    bullets: [
      "Named reviewer attestation with signature + timestamp, per file",
      "Immutable audit trail across every PR, every scan, every override",
      "Exportable reports: SOC 2 evidence, Trust Services Criteria, provenance packages",
      "SBOM export (SPDX, CycloneDX) for procurement and vendor requests",
    ],
    pages: ["Audit Trail", "Reports"],
  },
  {
    id: "ai-intel", icon: AiIntelIcon, color: SKY, name: "AI Intel", tagline: "Know what wrote your code — and whether it was allowed to",
    desc: "47 signals across AST structure, git provenance, and behavioral analysis score how much of a file is AI-generated and attribute it to the tool that wrote it. Shadow AI Detector flags tools that aren't on your org's approved list before an unreviewed model becomes part of your supply chain.",
    bullets: [
      "AI% per file, attributed to Copilot, Cursor, Claude, Windsurf, and more",
      "TrustScore™ — a blended org score across attestation, policy, and risk resolution",
      "Shadow AI Detector: unauthorized tool usage, confidence-scored",
      "Developer baseline deviation — a sudden spike flags as anomalous, not just a raw score",
    ],
    pages: ["TrustScore™", "Shadow AI"],
  },
];

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
const GROUP_COLORS: Record<string, string> = { "Injection": CYAN, "Request forgery": ORANGE, "Filesystem": AMBER, "Data handling": VIOLET, "Authorization": ROSE, "Availability": EMERALD };

interface LangEngine { lang: string; ext: string; note: string; extra: string }
const LANGUAGES: LangEngine[] = [
  { lang: "TypeScript / JavaScript", ext: ".ts .tsx .js", note: "Cross-file resolution + source-sink trace", extra: "Named, default, namespace & CommonJS imports" },
  { lang: "Python", ext: ".py", note: "Cross-file resolution + source-sink trace", extra: "Relative & absolute imports, package modules" },
  { lang: "Go", ext: ".go", note: "Path-sensitive, BOLA ownership dominance", extra: "Request/writer var tracking, out-parameters" },
  { lang: "C#", ext: ".cs", note: "Path-sensitive, BOLA ownership dominance", extra: "ASP.NET Core attribute-driven sources" },
  { lang: "PHP", ext: ".php", note: "Path-sensitive, BOLA ownership dominance", extra: "Global-scope sticky memory across functions" },
  { lang: "Java", ext: ".java", note: "Spring annotation & entry-point aware", extra: "Two-tier confidence for un-annotated params" },
];

const PIPELINE_STAGES = [
  { label: "GitHub webhook", detail: "PR opened or updated", color: "#374151" },
  { label: "File fetch", detail: "Every changed file, async via queue", color: "#1e3a5f" },
  { label: "AI signal scan", detail: "AST · git provenance · behavioral", color: SKY },
  { label: "Taint engine", detail: "Per-language AST + data-flow", color: ROSE },
  { label: "Secrets + deps", detail: "Credential scan + live CVE lookup", color: AMBER },
  { label: "Policy engine", detail: "Risk score against merge gates", color: VIOLET },
  { label: "Attestation gate", detail: "Blocks until reviewer sign-off", color: EMERALD },
  { label: "Check run ✓", detail: "Posted to the PR", color: EMERALD },
];

const WHY_ROWS = [
  { vs: "Point tools (one per risk type)", them: "A SAST tool for vulnerabilities, a separate secrets scanner, a separate SCA tool, and no visibility into what's actually AI-generated — four dashboards, four audit trails, nothing reconciled.", us: "One platform: vulnerabilities, secrets, dependencies, and AI provenance scored together on every PR, with one policy engine and one audit trail behind all of it.", accent: CYAN },
  { vs: "Regex-based scanners", them: "Match a pattern on one line. No concept of whether the value is actually attacker-controlled, whether it was sanitized first, or whether it even reaches a sink.", us: "Real data-flow: a bitmask of sink classes carried from source to sink, cleared only by a sanitizer that actually neutralizes that class.", accent: ROSE },
  { vs: "Manual review + spreadsheets", them: "Reviewers eyeball the diff, chase compliance evidence by hand, and track AI tool usage — if at all — in a doc that's out of date by Friday.", us: "Every PR gets a risk score, a named attestation, and an audit-ready trail. Shadow AI usage, policy exceptions, and SLA breaches live in one system that's always current.", accent: AMBER },
];

const AI_FACTS = [
  { label: "AST structural analysis", desc: "Parses source into an abstract syntax tree and scores structural patterns that correlate with LLM output — long function bodies, uniform naming, missing edge-case handling." },
  { label: "Git provenance scoring", desc: "Scores commit velocity, message entropy, signing rate, and LOC/commit ratio against norms. A 1,300 LOC/commit average from a single author is a signal, not a fact — weighted accordingly." },
  { label: "Developer baseline deviation", desc: "Tracks each contributor's historical AI%, file count, and commit cadence. A sudden 3× spike in AI content on a PR flags as anomalous even if the absolute score is moderate." },
  { label: "AI tool attribution", desc: "Detects .cursor/, .claude/, .copilot-instructions, Windsurf config, and inline marker comments to attribute code to specific assistants — not just \"AI wrote this\" but \"Cursor wrote this\"." },
  { label: "Shadow AI detection", desc: "Flags AI-tool usage signatures that aren't on your org's approved-tools policy list, confidence-scored, with the affected developers surfaced directly." },
  { label: "Cross-file semantic graph", desc: "Builds a call graph across the entire PR to catch AI-generated glue code that wires together real modules in unsafe ways — invisible to a per-file tool." },
];
const ENGINE_FACTS = [
  { label: "Sink-class bitmask model", desc: "A taint value is a bitmask of 15 sink classes, not a boolean. A sanitizer clears only the classes it actually neutralizes — an HTML escaper clears XSS, not SQL injection." },
  { label: "Path-sensitive propagation", desc: "Branches are walked on cloned state and merged with a may-taint join; a value sanitized on one branch and raw on another is tracked correctly on both." },
  { label: "Narrow validation guards", desc: "Only unambiguous proofs clear a variable — literal-collection membership, strict numeric checks, equality with a literal. A regex match is deliberately NOT trusted." },
  { label: "BOLA ownership dominance", desc: "An authorization check only suppresses a finding when it actually dominates the sink in control-flow order — not merely present somewhere in the function." },
  { label: "Bounded interprocedural analysis", desc: "Same-file call chains resolve through a fixed-point worklist, capped at 3 rounds, so A calling B calling C converges without an unbounded whole-program solve." },
  { label: "Cross-file fixed point", desc: "Export summaries recompute across up to 3 rounds so a file that only wraps an imported call still gets credited with propagating it." },
];

const STEPS = [
  { n: 1, title: "Connect your repos", desc: "Install the GitHub App in under 2 minutes (GitLab and Bitbucket also supported). Every pull request is scanned automatically — no config files, no CI changes." },
  { n: 2, title: "See every signal in one place", desc: "AI% per file, secrets, vulnerable dependencies, and traced vulnerabilities — each with a real data-flow path, not a guess. One risk score ties it together." },
  { n: 3, title: "Attest. Gate. Deploy.", desc: "Reviewers sign off on flagged files directly in the dashboard. Policy gates block merges until required attestations and fixes are recorded." },
];

// ── Shared UI ────────────────────────────────────────────────────────────────

function Eyebrow({ children, color = CYAN }: { children: React.ReactNode; color?: string }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-[11px] font-bold uppercase tracking-[0.14em] px-3 py-1.5 rounded-full border font-mono" style={{ color, background: `${color}1c`, borderColor: `${color}4d` }}>
      {children}
    </span>
  );
}

// ── NavBar ───────────────────────────────────────────────────────────────────

function NavBar() {
  return (
    <header className="fixed top-0 inset-x-0 z-50 border-b" style={{ borderColor: "rgba(255,255,255,0.09)", background: "rgba(5,8,16,0.82)", backdropFilter: "blur(16px) saturate(160%)" }}>
      <div className="max-w-6xl mx-auto px-5 h-14 flex items-center justify-between gap-4">
        <div className="flex items-center gap-2.5">
          <div className="w-7 h-7 rounded-lg flex items-center justify-center text-[#050810]" style={{ background: CYAN, boxShadow: `0 0 20px ${CYAN}55` }}>
            <ShieldIcon size={14} />
          </div>
          <span className="font-bold text-white text-sm tracking-tight">TrustLedger</span>
        </div>
        <nav className="hidden md:flex items-center gap-6">
          {["Platform", "Vulnerabilities", "How it works"].map(l => (
            <a key={l} href={`#${l.toLowerCase().replace(/ /g, "-")}`} className="text-sm text-white/64 hover:text-white/90 transition-colors font-medium">{l}</a>
          ))}
        </nav>
        <div className="flex items-center gap-2">
          <Link href="/login" className="text-sm font-semibold text-white/68 hover:text-white transition-colors px-3 py-1.5">Sign in</Link>
          <Link href="/login" className="flex items-center gap-1.5 text-sm font-bold px-3.5 py-1.5 rounded-lg transition-all text-[#050810]" style={{ background: `linear-gradient(135deg, #67e8f9, ${CYAN})`, boxShadow: `0 2px 18px ${CYAN}66` }}>
            Get started <ArrowRightIcon size={13} />
          </Link>
        </div>
      </div>
    </header>
  );
}

// ── Hero: multi-signal strip + trace visual ─────────────────────────────────

const SIGNAL_CHIPS = [
  { label: "AI-generated", value: "92%", color: SKY },
  { label: "Secret found", value: "1", color: VIOLET },
  { label: "Vulnerable dep", value: "CVE-2024", color: AMBER },
  { label: "SQL injection", value: "traced", color: ROSE },
];

function SignalStrip() {
  return (
    <div className="flex flex-wrap items-center justify-center gap-2.5">
      {SIGNAL_CHIPS.map((c, i) => (
        <Reveal key={c.label} delay={i * 90} className="flex items-center gap-2 px-3 py-1.5 rounded-full border font-mono text-[11px]" style={{ borderColor: `${c.color}4d`, background: `${c.color}12` }}>
          <span className="w-1.5 h-1.5 rounded-full" style={{ background: c.color }} />
          <span className="text-white/68">{c.label}</span>
          <span className="font-bold" style={{ color: c.color }}>{c.value}</span>
        </Reveal>
      ))}
    </div>
  );
}

const TRACE_STEPS = [
  { kind: "source", file: "route.ts", line: 3, label: "req.query.id", tone: CYAN },
  { kind: "assignment", file: "route.ts", line: 4, label: "const q = buildQuery(id)", tone: "#94a3b8" },
  { kind: "cross-file", file: "→ db.ts", line: 2, label: "crosses into ./db via \"buildQuery\"", tone: AMBER },
  { kind: "sink", file: "route.ts", line: 5, label: "db.execute(q)", tone: ROSE },
];

function TraceVisual() {
  const { ref, shown } = useReveal<HTMLDivElement>();
  return (
    <div ref={ref} className="relative rounded-2xl overflow-hidden border" style={{ borderColor: "rgba(255,255,255,0.11)", background: "linear-gradient(180deg, rgba(10,15,28,0.9), rgba(6,10,18,0.95))", boxShadow: "0 40px 90px rgba(0,0,0,0.55), 0 0 0 1px rgba(255,255,255,0.045)" }}>
      <div className="px-4 py-2.5 flex items-center gap-2 border-b" style={{ borderColor: "rgba(255,255,255,0.09)", background: "rgba(255,255,255,0.035)" }}>
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full" style={{ background: `${ROSE}80` }} />
          <span className="w-2.5 h-2.5 rounded-full" style={{ background: `${AMBER}80` }} />
          <span className="w-2.5 h-2.5 rounded-full" style={{ background: `${EMERALD}80` }} />
        </div>
        <span className="text-[11px] font-mono font-semibold ml-2 text-white/68">how a trace reads</span>
        <span className="ml-auto text-[10px] font-mono text-white/34">illustrative example</span>
      </div>
      <div className="p-5 sm:p-6 font-mono text-[12.5px]">
        {TRACE_STEPS.map((s, i) => (
          <div key={i} className="relative flex gap-4 pb-6 last:pb-0">
            {i < TRACE_STEPS.length - 1 && (
              <span className="absolute left-[9px] top-6 bottom-0 w-px overflow-hidden" style={{ background: "rgba(255,255,255,0.11)" }}>
                <span className="block w-full" style={{ height: "40%", background: `linear-gradient(180deg, transparent, ${CYAN}, transparent)`, animation: shown ? `traceFlow 2.2s ${0.15 + i * 0.15}s ease-in-out infinite` : "none" }} />
              </span>
            )}
            <span className="relative z-10 w-[19px] h-[19px] rounded-full border-2 flex items-center justify-center shrink-0 mt-0.5"
              style={{ borderColor: s.tone, background: INK, opacity: shown ? 1 : 0, transform: shown ? "scale(1)" : "scale(0.4)", transition: `opacity 0.4s ${i * 0.13}s, transform 0.4s ${i * 0.13}s cubic-bezier(0.34,1.56,0.64,1)` }}>
              <span className="w-[7px] h-[7px] rounded-full" style={{ background: s.tone }} />
            </span>
            <div style={{ opacity: shown ? 1 : 0, transform: shown ? "translateX(0)" : "translateX(-8px)", transition: `opacity 0.4s ${i * 0.13 + 0.05}s, transform 0.4s ${i * 0.13 + 0.05}s` }}>
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-[9px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded" style={{ color: s.tone, background: `${s.tone}1a` }}>{s.kind}</span>
                <span className="text-white/40 text-[11px]">{s.file}:{s.line}</span>
              </div>
              <p className="mt-1 text-white/85">{s.label}</p>
            </div>
          </div>
        ))}
      </div>
      <style>{`@keyframes traceFlow { 0% { transform: translateY(-140%); } 100% { transform: translateY(340%); } }`}</style>
    </div>
  );
}

function HeroSection() {
  return (
    <section className="relative flex flex-col items-center justify-center text-center px-5 pt-32 pb-16 overflow-hidden" style={{ background: `radial-gradient(ellipse 90% 60% at 50% 0%, ${CYAN}22, transparent 60%), ${INK}` }}>
      <div className="absolute inset-0 pointer-events-none overflow-hidden">
        <div className="absolute -top-32 -left-24 w-[32rem] h-[32rem] rounded-full blur-[120px]" style={{ background: CYAN, opacity: 0.16 }} />
        <div className="absolute -top-16 -right-24 w-[28rem] h-[28rem] rounded-full blur-[120px]" style={{ background: VIOLET, opacity: 0.13 }} />
        <div className="absolute top-40 left-1/2 -translate-x-1/2 w-[26rem] h-[26rem] rounded-full blur-[130px]" style={{ background: SKY, opacity: 0.1 }} />
        <div className="absolute inset-0" style={{ backgroundImage: "linear-gradient(rgba(255,255,255,0.05) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.05) 1px, transparent 1px)", backgroundSize: "56px 56px", maskImage: "radial-gradient(ellipse 70% 60% at 50% 20%, black, transparent)" }} />
        <div className="absolute bottom-0 left-0 right-0 h-52" style={{ background: `linear-gradient(to top, ${INK}, transparent)` }} />
      </div>

      <Reveal className="relative max-w-4xl mx-auto space-y-6">
        <Eyebrow><span className="w-1.5 h-1.5 rounded-full" style={{ background: CYAN, boxShadow: `0 0 8px ${CYAN}` }} />One platform for everything that touches a PR</Eyebrow>
        <h1 className="text-5xl sm:text-6xl lg:text-7xl font-black text-white tracking-tight leading-[1.05]">
          AI provenance.<br />
          <span style={{ background: `linear-gradient(90deg, ${CYAN}, #67e8f9, #a5f3fc)`, WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent", backgroundClip: "text" }}>Real vulnerabilities.</span><br />
          One risk score.
        </h1>
        <p className="text-lg sm:text-xl text-white/64 max-w-2xl mx-auto leading-relaxed">
          TrustLedger scores how much of a PR is AI-generated, traces real vulnerabilities across six languages, catches secrets and vulnerable dependencies, and gates the merge on policy — with a named reviewer's sign-off recorded on every file.
        </p>
        <div className="flex flex-col sm:flex-row items-center justify-center gap-3 pt-2">
          <Link href="/login" className="flex items-center gap-2 px-6 py-3.5 rounded-xl font-bold text-sm transition-all active:scale-[0.98] text-[#050810]"
            style={{ background: `linear-gradient(135deg, #67e8f9, ${CYAN})`, boxShadow: `0 6px 32px ${CYAN}66` }}
            onMouseEnter={e => { const el = e.currentTarget as HTMLElement; el.style.transform = "translateY(-2px)"; el.style.boxShadow = `0 10px 40px ${CYAN}88`; }}
            onMouseLeave={e => { const el = e.currentTarget as HTMLElement; el.style.transform = "translateY(0)"; el.style.boxShadow = `0 6px 32px ${CYAN}66`; }}>
            Get started free <ArrowRightIcon size={15} />
          </Link>
          <Link href="/dashboard" className="flex items-center gap-2 px-6 py-3.5 rounded-xl text-white/82 font-semibold text-sm transition-all border hover:text-white/95"
            style={{ borderColor: "rgba(255,255,255,0.18)", background: "rgba(255,255,255,0.06)" }}
            onMouseEnter={e => { (e.currentTarget as HTMLElement).style.borderColor = "rgba(255,255,255,0.32)"; (e.currentTarget as HTMLElement).style.background = "rgba(255,255,255,0.09)"; }}
            onMouseLeave={e => { (e.currentTarget as HTMLElement).style.borderColor = "rgba(255,255,255,0.18)"; (e.currentTarget as HTMLElement).style.background = "rgba(255,255,255,0.06)"; }}>
            <GitHubIcon size={15} /> Explore the dashboard
          </Link>
        </div>
        <p className="text-xs text-white/40 font-medium pt-1">No credit card required to start</p>
      </Reveal>

      <Reveal delay={120} className="relative mt-10">
        <SignalStrip />
      </Reveal>

      <Reveal delay={200} className="relative mt-10 w-full max-w-xl mx-auto">
        <TraceVisual />
        <div className="absolute -bottom-8 left-1/2 -translate-x-1/2 w-2/3 h-16 blur-3xl rounded-full pointer-events-none" style={{ background: CYAN, opacity: 0.14 }} />
      </Reveal>

      <Reveal delay={320} className="relative mt-16 w-full max-w-4xl mx-auto grid grid-cols-2 sm:grid-cols-4 gap-4">
        {[{ to: 6, label: "language engines" }, { to: 20, label: "vulnerability classes" }, { to: 47, label: "AI-detection signals" }, { to: 8, label: "SCA ecosystems" }].map(s => (
          <div key={s.label} className="text-center">
            <p className="text-3xl font-black font-mono" style={{ color: "#67e8f9", textShadow: `0 0 24px ${CYAN}88` }}><CountUp to={s.to} /></p>
            <p className="text-[11px] text-white/50 font-medium mt-1">{s.label}</p>
          </div>
        ))}
      </Reveal>
    </section>
  );
}

// ── Pillars: tabbed, equal-weight platform overview ─────────────────────────

function PillarsSection() {
  const [active, setActive] = useState(0);
  const tabRefs = useRef<(HTMLButtonElement | null)[]>([]);
  const [indicator, setIndicator] = useState({ left: 0, width: 0 });

  useEffect(() => {
    const el = tabRefs.current[active];
    if (el) setIndicator({ left: el.offsetLeft, width: el.offsetWidth });
  }, [active]);

  const p = PILLARS[active];

  return (
    <section id="platform" className="py-24 px-5" style={{ background: `radial-gradient(ellipse 70% 50% at 50% 0%, ${p.color}12, transparent 65%), ${SURFACE}`, transition: "background 0.5s ease" }}>
      <div className="max-w-5xl mx-auto">
        <Reveal className="text-center mb-12">
          <Eyebrow>The platform</Eyebrow>
          <h2 className="text-4xl font-black text-white mt-4 tracking-tight">Six pillars. One scan.</h2>
          <p className="text-white/58 mt-3 max-w-2xl mx-auto text-lg">Every pull request runs through all six — the same structure as the dashboard itself, not a marketing simplification of it.</p>
        </Reveal>

        {/* Tab bar */}
        <Reveal delay={100} className="relative flex flex-wrap justify-center gap-1 mb-2 border-b" style={{ borderColor: "rgba(255,255,255,0.14)" }}>
          {PILLARS.map((pl, i) => (
            <button key={pl.id} ref={el => { tabRefs.current[i] = el; }} onClick={() => setActive(i)}
              className="relative flex items-center gap-2 px-4 py-3 text-sm font-semibold transition-colors whitespace-nowrap"
              style={{ color: active === i ? "#fff" : "rgba(255,255,255,0.55)" }}>
              <span style={{ color: active === i ? pl.color : "rgba(255,255,255,0.45)" }}>{pl.icon(16)}</span>
              {pl.name}
            </button>
          ))}
          <span className="absolute bottom-0 h-[2px] rounded-full transition-all duration-300 ease-out" style={{ left: indicator.left, width: indicator.width, background: p.color, boxShadow: `0 0 8px ${p.color}` }} />
        </Reveal>

        {/* Panel */}
        <div key={p.id} className="grid md:grid-cols-5 gap-8 pt-10" style={{ animation: "fadeSlideIn 0.4s cubic-bezier(0.16,1,0.3,1)" }}>
          <div className="md:col-span-3">
            <div className="w-11 h-11 rounded-xl flex items-center justify-center mb-4" style={{ color: p.color, background: `${p.color}1c`, border: `1px solid ${p.color}4d` }}>
              {p.icon(22)}
            </div>
            <h3 className="text-2xl font-black text-white tracking-tight mb-2">{p.tagline}</h3>
            <p className="text-white/68 leading-relaxed mb-5">{p.desc}</p>
            <div className="flex flex-wrap gap-2">
              {p.pages.map(page => (
                <span key={page} className="text-[11px] font-mono px-2.5 py-1 rounded-full border text-white/58" style={{ borderColor: "rgba(255,255,255,0.14)", background: "rgba(255,255,255,0.045)" }}>{page}</span>
              ))}
            </div>
          </div>
          <div className="md:col-span-2 space-y-2.5">
            {p.bullets.map((b, i) => (
              <div key={i} className="flex items-start gap-2.5 p-3 rounded-xl border" style={{ borderColor: "rgba(255,255,255,0.09)", background: "rgba(255,255,255,0.035)", boxShadow: "inset 0 1px 0 rgba(255,255,255,0.06)" }}>
                <span className="w-1.5 h-1.5 rounded-full mt-1.5 shrink-0" style={{ background: p.color }} />
                <span className="text-[13px] text-white/74 leading-snug">{b}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
      <style>{`@keyframes fadeSlideIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }`}</style>
    </section>
  );
}

// ── Vulnerability coverage grid ─────────────────────────────────────────────

function VulnCoverageSection() {
  const groups = Array.from(new Set(VULN_CLASSES.map(v => v.group)));
  return (
    <section id="vulnerabilities" className="py-24 px-5" style={{ background: `radial-gradient(ellipse 70% 50% at 50% 0%, ${ROSE}12, transparent 65%), ${INK}` }}>
      <div className="max-w-6xl mx-auto">
        <Reveal className="text-center mb-14">
          <Eyebrow color={ROSE}>Zoom in — Code Risk</Eyebrow>
          <h2 className="text-4xl font-black text-white mt-4 tracking-tight">Twenty vulnerability classes, real data-flow evidence</h2>
          <p className="text-white/58 mt-3 max-w-2xl mx-auto text-lg">Every finding below is matched by tracking an actual tainted value from its source to a real sink — not a keyword or a line pattern.</p>
        </Reveal>
        <div className="space-y-8">
          {groups.map((g, gi) => (
            <Reveal key={g} delay={gi * 60}>
              <div className="flex items-center gap-2 mb-3">
                <span className="w-1.5 h-1.5 rounded-full" style={{ background: GROUP_COLORS[g] }} />
                <span className="text-[11px] font-bold uppercase tracking-widest text-white/50 font-mono">{g}</span>
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-2.5">
                {VULN_CLASSES.filter(v => v.group === g).map(v => (
                  <div key={v.name} className="flex items-center justify-between gap-2 px-3.5 py-3 rounded-xl border transition-colors" style={{ borderColor: "rgba(255,255,255,0.14)", background: "rgba(255,255,255,0.04)", boxShadow: "inset 0 1px 0 rgba(255,255,255,0.05)" }}>
                    <span className="text-sm font-semibold text-white/90">{v.name}</span>
                    <span className="text-[10px] font-mono text-white/40 shrink-0">{v.cwe}</span>
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

// ── Language engines ─────────────────────────────────────────────────────────

function LanguageEngineSection() {
  return (
    <section className="py-24 px-5" style={{ background: `radial-gradient(ellipse 70% 50% at 50% 0%, ${AMBER}0f, transparent 65%), ${SURFACE}` }}>
      <div className="max-w-5xl mx-auto">
        <Reveal className="text-center mb-14">
          <Eyebrow color={ROSE}>Zoom in — Code Risk</Eyebrow>
          <h2 className="text-4xl font-black text-white mt-4 tracking-tight">Six languages. Six real parsers.</h2>
          <p className="text-white/58 mt-3 max-w-2xl mx-auto text-lg">Each language gets its own dedicated AST parser and taint-propagation engine, tuned to that ecosystem's own frameworks — not one ruleset stretched across six syntaxes.</p>
        </Reveal>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          {LANGUAGES.map((l, i) => (
            <Reveal key={l.lang} delay={i * 70}>
              <div className="group p-5 rounded-2xl border transition-all" style={{ borderColor: "rgba(255,255,255,0.11)", background: "rgba(255,255,255,0.04)", boxShadow: "inset 0 1px 0 rgba(255,255,255,0.05)" }}
                onMouseEnter={e => { const el = e.currentTarget as HTMLElement; el.style.borderColor = `${ROSE}55`; el.style.background = "rgba(255,255,255,0.06)"; }}
                onMouseLeave={e => { const el = e.currentTarget as HTMLElement; el.style.borderColor = "rgba(255,255,255,0.11)"; el.style.background = "rgba(255,255,255,0.04)"; }}>
                <div className="flex items-center justify-between mb-2">
                  <span className="font-bold text-white text-sm">{l.lang}</span>
                  <span className="text-[10px] font-mono text-white/40">{l.ext}</span>
                </div>
                <p className="text-sm text-white/74 leading-relaxed">{l.note}</p>
                <p className="text-xs text-white/46 mt-1.5">{l.extra}</p>
              </div>
            </Reveal>
          ))}
        </div>
      </div>
    </section>
  );
}

// ── Pipeline: what a PR scan actually does ──────────────────────────────────

function PipelineSection() {
  return (
    <section id="how-it-analyzes" className="py-24 px-5" style={{ background: `radial-gradient(ellipse 70% 50% at 50% 0%, ${VIOLET}12, transparent 65%), ${INK}` }}>
      <div className="max-w-5xl mx-auto">
        <Reveal className="text-center mb-14">
          <Eyebrow>Every PR, every push</Eyebrow>
          <h2 className="text-4xl font-black text-white mt-4 tracking-tight">What one scan actually does</h2>
          <p className="text-white/58 mt-3 max-w-2xl mx-auto text-lg">All six pillars run on the same scan, in this order, in under a few seconds per file.</p>
        </Reveal>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {PIPELINE_STAGES.map((s, i) => (
            <Reveal key={s.label} delay={i * 60}>
              <div className="relative h-full p-4 rounded-2xl border" style={{ borderColor: "rgba(255,255,255,0.11)", background: "rgba(255,255,255,0.04)", boxShadow: "inset 0 1px 0 rgba(255,255,255,0.05)" }}>
                <span className="text-[10px] font-mono font-black" style={{ color: s.color }}>{String(i + 1).padStart(2, "0")}</span>
                <p className="text-sm font-bold text-white mt-1.5 leading-tight">{s.label}</p>
                <p className="text-[11px] text-white/50 mt-1 leading-snug">{s.detail}</p>
              </div>
            </Reveal>
          ))}
        </div>
      </div>
    </section>
  );
}

// ── FeaturesSection ──────────────────────────────────────────────────────────

const FEATURES = [
  { icon: RouteIcon, title: "Source → Sink Traces", desc: "Every finding ships with the actual data-flow path, hop by hop, with real file and line numbers — including across a file boundary.", accent: CYAN },
  { icon: GitBranchIcon, title: "Cross-File Resolution", desc: "Named, default, namespace, and CommonJS imports; re-export chains; a wrapper around an imported call is still recognized as propagating.", accent: CYAN },
  { icon: LockIcon, title: "Broken Object-Level Authorization", desc: "Structural ownership-dominance analysis: a resource lookup only clears when a real comparison against the principal dominates every path to the sink.", accent: ROSE },
  { icon: PackageIcon, title: "Dependency & Supply Chain", desc: "Live CVE lookups across npm, PyPI, Go, Maven, NuGet, Packagist, crates.io, and RubyGems, plus hallucinated-package and typosquat detection.", accent: AMBER },
  { icon: FingerprintIcon, title: "Stable Finding Fingerprints", desc: "A hash of the flow itself, not the line number — the same finding survives unrelated edits elsewhere in the file across scans.", accent: CYAN },
  { icon: BellIcon, title: "Policy-Driven Alerting", desc: "Real-time alerts to Slack, email, or PagerDuty on policy breaches, with severity-aware routing.", accent: ORANGE },
  { icon: UsersIcon, title: "Reviewer Attestation", desc: "Named sign-off recorded per file with signature, timestamp, and risk context at review time — an audit trail that answers itself.", accent: VIOLET },
  { icon: KeyIcon, title: "Context-Aware Sanitizers", desc: "An HTML-escaped value dropped into a <script> block or an unquoted attribute is still flagged — encoding for one context doesn't cover another.", accent: ROSE },
];

function FeaturesSection() {
  return (
    <section id="features" className="py-24 px-5" style={{ background: `radial-gradient(ellipse 70% 50% at 50% 0%, ${CYAN}12, transparent 65%), ${SURFACE}` }}>
      <div className="max-w-6xl mx-auto">
        <Reveal className="text-center mb-14">
          <Eyebrow>Features</Eyebrow>
          <h2 className="text-4xl font-black text-white mt-4 tracking-tight">Built like a scanner, not a linter</h2>
          <p className="text-white/58 mt-3 max-w-xl mx-auto text-lg">Every capability below maps to a real, tested component — not a roadmap slide.</p>
        </Reveal>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {FEATURES.map((f, i) => (
            <Reveal key={f.title} delay={(i % 4) * 60}>
              <div className="group relative p-5 rounded-2xl transition-all duration-200 h-full" style={{ background: "rgba(255,255,255,0.045)", border: "1px solid rgba(255,255,255,0.14)", boxShadow: "inset 0 1px 0 rgba(255,255,255,0.06)" }}
                onMouseEnter={e => { const el = e.currentTarget as HTMLElement; el.style.borderColor = `${f.accent}66`; el.style.background = "rgba(255,255,255,0.07)"; el.style.transform = "translateY(-3px)"; el.style.boxShadow = `0 16px 36px ${f.accent}2e, inset 0 1px 0 rgba(255,255,255,0.08)`; }}
                onMouseLeave={e => { const el = e.currentTarget as HTMLElement; el.style.borderColor = "rgba(255,255,255,0.14)"; el.style.background = "rgba(255,255,255,0.045)"; el.style.transform = "translateY(0)"; el.style.boxShadow = "inset 0 1px 0 rgba(255,255,255,0.06)"; }}>
                <div className="w-9 h-9 rounded-lg flex items-center justify-center mb-3.5" style={{ color: f.accent, background: `${f.accent}1c`, border: `1px solid ${f.accent}38` }}>{f.icon(18)}</div>
                <h3 className="text-sm font-bold text-white mb-1.5">{f.title}</h3>
                <p className="text-[13px] text-white/64 leading-relaxed">{f.desc}</p>
              </div>
            </Reveal>
          ))}
        </div>
      </div>
    </section>
  );
}

// ── ArchSection: two engines, side by side ──────────────────────────────────

function FactGrid({ facts, color }: { facts: { label: string; desc: string }[]; color: string }) {
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
      {facts.map((s, i) => (
        <Reveal key={s.label} delay={i * 40}>
          <div className="p-4 rounded-xl border h-full" style={{ borderColor: "rgba(255,255,255,0.14)", background: "rgba(255,255,255,0.035)" }}>
            <div className="flex items-center gap-2 mb-2">
              <span className="text-[9px] font-black tabular-nums w-4.5 h-4.5 rounded-md flex items-center justify-center shrink-0 font-mono" style={{ background: `${color}2c`, color, border: `1px solid ${color}4d`, width: 18, height: 18 }}>{i + 1}</span>
              <p className="text-xs font-bold text-white/90">{s.label}</p>
            </div>
            <p className="text-xs text-white/58 leading-relaxed">{s.desc}</p>
          </div>
        </Reveal>
      ))}
    </div>
  );
}

function ArchSection() {
  return (
    <section className="py-24 px-5" style={{ background: `radial-gradient(ellipse 70% 50% at 50% 0%, ${SKY}12, transparent 65%), ${INK}` }}>
      <div className="max-w-5xl mx-auto">
        <Reveal className="text-center mb-14">
          <Eyebrow color={SKY}>Under the hood</Eyebrow>
          <h2 className="text-4xl font-black text-white mt-4 tracking-tight">Two real engines, documented in the open</h2>
          <p className="text-white/58 mt-3 text-lg max-w-2xl mx-auto">The AI-provenance model and the vulnerability taint model are two separate, independently-tested systems — here's the shape of each.</p>
        </Reveal>
        <div className="grid lg:grid-cols-2 gap-10">
          <Reveal>
            <div className="flex items-center gap-2 mb-4"><span style={{ color: SKY }}>{AiIntelIcon(18)}</span><h3 className="font-bold text-white text-sm">AI provenance engine</h3></div>
            <FactGrid facts={AI_FACTS} color={SKY} />
          </Reveal>
          <Reveal delay={100}>
            <div className="flex items-center gap-2 mb-4"><span style={{ color: ROSE }}>{CodeRiskIcon(18)}</span><h3 className="font-bold text-white text-sm">Vulnerability taint engine</h3></div>
            <FactGrid facts={ENGINE_FACTS} color={ROSE} />
          </Reveal>
        </div>
      </div>
    </section>
  );
}

// ── WhySection ───────────────────────────────────────────────────────────────

function WhySection() {
  return (
    <section className="py-24 px-5" style={{ background: `radial-gradient(ellipse 70% 50% at 50% 0%, ${AMBER}0f, transparent 65%), ${SURFACE}` }}>
      <div className="max-w-5xl mx-auto">
        <Reveal className="text-center mb-14">
          <Eyebrow>Why TrustLedger</Eyebrow>
          <h2 className="text-4xl font-black text-white mt-4 tracking-tight">Proof, not a pattern match</h2>
          <p className="text-white/58 mt-3 text-lg max-w-2xl mx-auto">Every finding traces back to a real signal in your code — reviewers spend time on judgment calls, not re-deriving whether it's real.</p>
        </Reveal>
        <div className="space-y-4">
          {WHY_ROWS.map((row, i) => (
            <Reveal key={row.vs} delay={i * 70}>
              <div className="rounded-2xl border overflow-hidden" style={{ borderColor: "rgba(255,255,255,0.14)", background: "rgba(255,255,255,0.035)" }}>
                <div className="px-6 py-3 border-b" style={{ borderColor: "rgba(255,255,255,0.09)", background: "rgba(255,255,255,0.045)" }}>
                  <span className="text-[11px] font-bold uppercase tracking-widest text-white/40 font-mono">vs </span>
                  <span className="text-xs font-bold text-white/58">{row.vs}</span>
                </div>
                <div className="grid md:grid-cols-2 divide-y md:divide-y-0 md:divide-x divide-white/[0.09]">
                  <div className="px-6 py-5"><p className="text-[10px] font-bold uppercase tracking-widest text-white/34 mb-2">They do</p><p className="text-sm text-white/58 leading-relaxed">{row.them}</p></div>
                  <div className="px-6 py-5"><p className="text-[10px] font-bold uppercase tracking-widest mb-2" style={{ color: `${row.accent}cc` }}>TrustLedger does</p><p className="text-sm text-white/82 leading-relaxed">{row.us}</p></div>
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
    <section id="how-it-works" className="py-24 px-5" style={{ background: `radial-gradient(ellipse 70% 50% at 50% 0%, ${EMERALD}12, transparent 65%), ${INK}` }}>
      <div className="max-w-4xl mx-auto">
        <Reveal className="text-center mb-14">
          <Eyebrow>How it works</Eyebrow>
          <h2 className="text-4xl font-black text-white mt-4 tracking-tight">Up and running in 5 minutes</h2>
          <p className="text-white/58 mt-3 text-lg">No CI/CD changes. No config files. Install once and every PR is scanned automatically.</p>
        </Reveal>
        <div className="space-y-4">
          {STEPS.map((s, i) => (
            <Reveal key={s.n} delay={i * 80}>
              <div className="flex gap-6 p-6 rounded-2xl border transition-colors" style={{ borderColor: "rgba(255,255,255,0.14)", background: "rgba(255,255,255,0.04)" }}>
                <div className="w-10 h-10 rounded-xl flex items-center justify-center font-black text-sm shrink-0 text-[#050810]" style={{ background: CYAN, boxShadow: `0 4px 16px ${CYAN}4d` }}>{s.n}</div>
                <div><h3 className="font-bold text-white mb-1">{s.title}</h3><p className="text-sm text-white/64 leading-relaxed">{s.desc}</p></div>
              </div>
            </Reveal>
          ))}
        </div>
        <Reveal delay={260} className="mt-10 p-5 rounded-2xl overflow-x-auto border" style={{ borderColor: "rgba(255,255,255,0.11)", background: "#080b12" }}>
          <p className="text-xs text-white/46 font-mono mb-3"># Or submit scans via the REST API</p>
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
    <section className="py-24 px-5 relative overflow-hidden" style={{ background: `radial-gradient(ellipse 70% 60% at 50% 40%, ${CYAN}22, transparent 65%), ${SURFACE}` }}>
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[36rem] h-[36rem] rounded-full blur-[140px] pointer-events-none" style={{ background: CYAN, opacity: 0.1 }} />
      <Reveal className="relative max-w-3xl mx-auto text-center space-y-6">
        <div className="w-14 h-14 rounded-2xl mx-auto flex items-center justify-center" style={{ color: CYAN, background: `${CYAN}1f`, border: `1px solid ${CYAN}44`, boxShadow: `0 0 32px ${CYAN}4d` }}><ShieldIcon size={26} /></div>
        <h2 className="text-4xl font-black text-white tracking-tight">Stop shipping blind.</h2>
        <p className="text-white/64 text-lg max-w-xl mx-auto leading-relaxed">
          AI-generated code, leaked secrets, vulnerable dependencies, and broken authorization can all slip into a PR unnoticed. TrustLedger scores it, traces it, and makes sure a human signed off before any of it reaches production.
        </p>
        <div className="flex flex-col sm:flex-row items-center justify-center gap-3 pt-2">
          <Link href="/dashboard" className="flex items-center gap-2 px-8 py-4 rounded-xl font-bold transition-all active:scale-[0.98] text-[#050810]"
            style={{ background: `linear-gradient(135deg, #67e8f9, ${CYAN})`, boxShadow: `0 6px 32px ${CYAN}66` }}
            onMouseEnter={e => { const el = e.currentTarget as HTMLElement; el.style.transform = "translateY(-2px)"; el.style.boxShadow = `0 10px 40px ${CYAN}88`; }}
            onMouseLeave={e => { const el = e.currentTarget as HTMLElement; el.style.transform = "translateY(0)"; el.style.boxShadow = `0 6px 32px ${CYAN}66`; }}>
            See the platform in action <ArrowRightIcon />
          </Link>
          <a href="mailto:hello@trustledger.dev" className="flex items-center gap-2 px-8 py-4 rounded-xl text-white/74 font-semibold transition-all border hover:text-white/90" style={{ borderColor: "rgba(255,255,255,0.18)", background: "rgba(255,255,255,0.06)" }}>Contact us</a>
        </div>
      </Reveal>
    </section>
  );
}

// ── Footer ───────────────────────────────────────────────────────────────────

function Footer() {
  return (
    <footer className="py-12 px-5 border-t" style={{ borderColor: "rgba(255,255,255,0.09)", background: INK }}>
      <div className="max-w-6xl mx-auto flex flex-col sm:flex-row items-start justify-between gap-8">
        <div>
          <div className="flex items-center gap-2.5 mb-3">
            <div className="w-7 h-7 rounded-lg flex items-center justify-center text-[#050810]" style={{ background: CYAN }}><ShieldIcon size={14} /></div>
            <span className="font-bold text-white text-sm">TrustLedger</span>
          </div>
          <p className="text-xs text-white/40 max-w-xs leading-relaxed">AI provenance, real vulnerability scanning, secrets, dependencies, and compliance — scored, traced, gated, and attested — for teams that care about what ships.</p>
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-8 text-sm">
          <div>
            <p className="font-bold text-white/58 text-xs uppercase tracking-wider mb-3">Platform</p>
            <ul className="space-y-2">{[{ label: "Overview", href: "/dashboard" }, { label: "Vulnerabilities", href: "#vulnerabilities" }, { label: "AI Intel", href: "/trust-score" }, { label: "Threats", href: "/violations" }].map(l => <li key={l.label}><a href={l.href} className="text-white/40 hover:text-white/70 transition-colors">{l.label}</a></li>)}</ul>
          </div>
          <div>
            <p className="font-bold text-white/58 text-xs uppercase tracking-wider mb-3">Code Risk</p>
            <ul className="space-y-2">{[{ label: "Scan History", href: "/scans" }, { label: "Secrets", href: "/secrets" }, { label: "Dependencies", href: "/dependencies" }].map(l => <li key={l.label}><a href={l.href} className="text-white/40 hover:text-white/70 transition-colors">{l.label}</a></li>)}</ul>
          </div>
          <div>
            <p className="font-bold text-white/58 text-xs uppercase tracking-wider mb-3">Compliance</p>
            <ul className="space-y-2">{[{ label: "SOC 2 / EU AI Act", href: "/reports" }, { label: "Risk Register", href: "/risk-register" }, { label: "SLA Dashboard", href: "/sla" }, { label: "Audit Trail", href: "/audit" }].map(l => <li key={l.label}><Link href={l.href} className="text-white/40 hover:text-white/70 transition-colors">{l.label}</Link></li>)}</ul>
          </div>
          <div>
            <p className="font-bold text-white/58 text-xs uppercase tracking-wider mb-3">Company</p>
            <ul className="space-y-2">{[{ label: "Dashboard", href: "/dashboard" }, { label: "Settings", href: "/settings" }, { label: "Contact", href: "mailto:hello@trustledger.dev" }, { label: "Privacy", href: "/privacy" }, { label: "Terms", href: "/terms" }].map(l => <li key={l.label}><a href={l.href} className="text-white/40 hover:text-white/70 transition-colors">{l.label}</a></li>)}</ul>
          </div>
        </div>
      </div>
      <div className="max-w-6xl mx-auto mt-10 pt-6 border-t flex flex-col sm:flex-row items-center justify-between gap-3" style={{ borderColor: "rgba(255,255,255,0.14)" }}>
        <p className="text-xs text-white/32">© 2026 TrustLedger. All rights reserved.</p>
        <div className="flex items-center gap-1.5 text-xs text-white/32"><span className="w-1.5 h-1.5 rounded-full" style={{ background: EMERALD }} />All systems operational</div>
      </div>
    </footer>
  );
}

// ── Page ─────────────────────────────────────────────────────────────────────

export default function LandingPage() {
  return (
    <div style={{ background: INK }}>
      <NavBar />
      <HeroSection />
      <PillarsSection />
      <VulnCoverageSection />
      <LanguageEngineSection />
      <PipelineSection />
      <FeaturesSection />
      <ArchSection />
      <WhySection />
      <HowItWorksSection />
      <CTASection />
      <Footer />
    </div>
  );
}
