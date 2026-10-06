"use client";

import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import { FINDING_CATALOG } from "@/lib/findingCatalog";
import { BrandLogo, BrandMark, BrandWordmark } from "@/components/BrandLogo";

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
const IncidentIcon = (s = 20) => iconEl(<><circle cx="12" cy="12" r="10" /><path d="M8 12l2.5 2.5L16 8.5" /></>, s);
const RadarIcon = (s = 20) => iconEl(<><path d="M12 2a10 10 0 1 0 10 10" /><path d="M12 6v6l4 2" /><circle cx="18" cy="6" r="3" fill="currentColor" stroke="none" /></>, s);
const GaugeIcon = (s = 20) => iconEl(<><path d="M12 2a10 10 0 1 0 10 10" strokeOpacity="0" /><polyline points="22 12 18 12 15 21 9 3 6 12 2 12" /></>, s);
const KeyIcon = (s = 20) => iconEl(<path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" />, s);
const UsersIcon = (s = 20) => iconEl(<><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" /><circle cx="9" cy="7" r="4" /><path d="M23 21v-2a4 4 0 0 0-3-3.87" /><path d="M16 3.13a4 4 0 0 1 0 7.75" /></>, s);
const ClipboardIcon = (s = 20) => iconEl(<><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><polyline points="14 2 14 8 20 8" /><line x1="16" y1="13" x2="8" y2="13" /><line x1="16" y1="17" x2="8" y2="17" /></>, s);
const FileScanIcon = (s = 20) => iconEl(<><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" /><polyline points="14 2 14 8 20 8" /><circle cx="11.5" cy="14.5" r="2.5" /><line x1="13.3" y1="16.3" x2="16" y2="19" /></>, s);
const AlertIcon = (s = 20) => iconEl(<><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" /><line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" /></>, s);
const WebhookIcon = (s = 20) => iconEl(<><path d="M18 16.98h-5.99c-1.1 0-1.95.94-2.48 1.9A4 4 0 0 1 2 17c0-.9.3-1.72.83-2.38" /><path d="M18.4 15.03a4 4 0 0 0-3.2-6.03h-.46" /><path d="M8.5 8.5a4 4 0 0 1 6.72-1.5" /><circle cx="18" cy="16.98" r="1.5" /><circle cx="2" cy="17" r="1" /></>, s);
const DownloadIcon = (s = 20) => iconEl(<><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" /><polyline points="7 10 12 15 17 10" /><line x1="12" y1="15" x2="12" y2="3" /></>, s);
const CheckCircleIcon = (s = 20) => iconEl(<><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" /><polyline points="22 4 12 14.01 9 11.01" /></>, s);
const CloudIcon = (s = 20) => iconEl(<path d="M18 10h-1.26A8 8 0 1 0 9 20h9a5 5 0 0 0 0-10z" />, s);
const ApiIcon = (s = 20) => iconEl(<><path d="M4 7h16M4 12h10M4 17h7" /><circle cx="18" cy="16" r="3" /><path d="M20.2 18.2 22 20" /></>, s);
const ContainerIcon = (s = 20) => iconEl(<><rect x="2" y="7" width="20" height="14" rx="2" /><path d="M6 7V4h12v3M7 11v6M12 11v6M17 11v6" /></>, s);
const HelmIcon = (s = 20) => iconEl(<><circle cx="12" cy="12" r="3" /><circle cx="12" cy="12" r="8" /><path d="M12 2v2M12 20v2M2 12h2M20 12h2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" /></>, s);
const MergeIcon = (s = 20) => iconEl(<><circle cx="6" cy="6" r="2.5" /><circle cx="6" cy="18" r="2.5" /><circle cx="18" cy="12" r="2.5" /><path d="M6 8.5v7M8.3 7.2 15.7 11M8.3 16.8l7.4-3.8" /></>, s);

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
    desc: "Nine real AST-based taint engines trace SQL injection, XSS, SSRF, and seventeen other vulnerability classes from source to sink — across files, services and includes, not just within one file. The same scan flags hardcoded secrets the moment they land, and ranks every vulnerable dependency by whether your code actually reaches it.",
    bullets: [
      "Real data-flow taint engines: JS/TS, Python, Java, Kotlin, Go, C#, PHP, Ruby, Rust — across files in all nine",
      "20 vulnerability classes, each with a source-to-sink trace and the exact sink argument",
      "Secrets detection — API keys, tokens, credentials — before they reach history",
      "Live CVEs across 8 ecosystems, ranked by reachability: is the vulnerable function called?",
    ],
    pages: ["Scan History", "Secrets", "Dependencies"],
  },
  {
    id: "cloud-api", icon: CloudIcon, color: AMBER, name: "Cloud & API", tagline: "What you deploy and expose, checked before it exists",
    desc: "The same PR scan reads your infrastructure and your API surface: Kubernetes manifests and Helm charts per container, Terraform for AWS, GCP and Azure, CloudFormation, ARM, Bicep and Serverless templates, Dockerfiles and Compose files — plus every endpoint your code and OpenAPI specs declare. No cloud credentials required.",
    bullets: [
      "Kubernetes & Helm: privilege escalation, root users, host paths, RBAC wildcards, committed Secrets",
      "Cloud posture from code: public buckets, open admin ports, public databases, wildcard IAM",
      "Containers: end-of-life base images, disabled sandboxing, TLS checks turned off in builds",
      "API inventory across 6 languages + OpenAPI, flagging the endpoint missing its siblings' auth",
    ],
    pages: ["API Security", "Scan History", "PR review"],
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

/** `mono` / `color`: the monogram badge each language gets on the page (its community color, not a logo). */
interface LangEngine { lang: string; short: string; mono: string; color: string; ext: string; note: string; extra: string }
const LANGUAGES: LangEngine[] = [
  { lang: "TypeScript / JavaScript", short: "TypeScript", mono: "TS", color: "#3b82f6", ext: ".ts .tsx .js", note: "Cross-file flows through functions, classes & services", extra: "Named, default, namespace & CommonJS imports; NestJS injection" },
  { lang: "Python", short: "Python", mono: "Py", color: "#facc15", ext: ".py", note: "Cross-module flows through functions & service classes", extra: "Relative & absolute imports, injected services" },
  { lang: "Java", short: "Java", mono: "Jv", color: "#f97316", ext: ".java", note: "Spring services across files, entry-point aware", extra: "@Autowired & constructor injection, interface → implementation" },
  { lang: "Kotlin", short: "Kotlin", mono: "Kt", color: "#a78bfa", ext: ".kt .kts", note: "Spring, Ktor & Servlet; shares cross-file evidence with Java", extra: "Kotlin controllers resolve Java services, and Java resolves Kotlin" },
  { lang: "Go", short: "Go", mono: "Go", color: "#22d3ee", ext: ".go", note: "Cross-package calls, path-sensitive, BOLA dominance", extra: "Struct-field and typed-parameter method resolution" },
  { lang: "C#", short: "C#", mono: "C#", color: "#c084fc", ext: ".cs", note: "Services across files, path-sensitive, BOLA dominance", extra: "Constructor & primary-constructor dependency injection" },
  { lang: "PHP", short: "PHP", mono: "PHP", color: "#818cf8", ext: ".php", note: "Functions & classes across includes, path-sensitive", extra: "__DIR__, relative & transitive includes; static calls" },
  { lang: "Ruby", short: "Ruby", mono: "Rb", color: "#f43f5e", ext: ".rb", note: "Rails & Sinatra controllers to services and models", extra: "Strong params, before_action state, service objects, scopes" },
  { lang: "Rust", short: "Rust", mono: "Rs", color: "#fb923c", ext: ".rs", note: "Axum, Actix & Rocket handlers, format! traced per argument", extra: "State<Arc<T>> services, trait objects, module functions via use" },
];
/** Frameworks the engines model by name (sources, sinks, injection) -- each one appears in an engine. */
const FRAMEWORKS = ["Express", "NestJS", "Next.js", "Flask", "FastAPI", "Spring", "JAX-RS", "Ktor", "ASP.NET", "Laravel", "Rails", "Sinatra", "Axum", "Actix", "Rocket"];

/** The hero's example PR check -- illustrative, labelled as such on the page. */
const MOCK_FINDINGS = [
  { sev: "Critical", color: ROSE, icon: AlertIcon, title: "SQL injection", detail: "req.body.email → db/users.ts:18", tag: "2 files" },
  { sev: "High", color: VIOLET, icon: KeyIcon, title: "AWS access key committed", detail: "config/deploy.ts:7", tag: "secret" },
  { sev: "High", color: AMBER, icon: PackageIcon, title: "lodash 4.17.20 · CVE-2021-23337", detail: "template() called from routes/email.ts", tag: "reachable" },
  { sev: "Medium", color: EMERALD, icon: ApiIcon, title: "POST /reset has no auth check", detail: "its 6 sibling routes do", tag: "API" },
];

const FAQS = [
  { q: "Do I need to change my CI pipeline?", a: "No. TrustLedger installs as a GitHub App — GitLab and Bitbucket are supported too — and scans every pull request automatically, with no config files and no CI changes. If you'd rather drive it yourself, scans can also be submitted through the REST API." },
  { q: "Which languages and frameworks are covered?", a: "Nine languages have their own AST parser and taint engine: TypeScript/JavaScript, Python, Java, Kotlin, Go, C#, PHP, Ruby and Rust, tuned to frameworks such as Express, NestJS, Flask, FastAPI, Spring, Ktor, ASP.NET, Laravel, Rails, Axum, Actix and Rocket. Infrastructure checks cover Terraform, CloudFormation, ARM, Bicep, Serverless, Kubernetes, Helm, Docker and OpenAPI." },
  { q: "How is this different from a regex-based scanner?", a: "A vulnerability is reported only when an attacker-controlled value is traced to a real sink — through assignments, branches, helper functions and other files — and a sanitizer clears only the vulnerability classes it actually neutralizes. Every finding ships with its source-to-sink trace, so reviewers can check it in seconds." },
  { q: "What does AI provenance measure?", a: "47 signals across code structure, git history and behavior estimate how much of each file is AI-generated and attribute it to the tool that wrote it — Copilot, Cursor, Claude, Windsurf and more — and flag tools that aren't on your approved list." },
  { q: "Can it block a merge?", a: "Yes. Policy gates hold a pull request until the required fixes or a named reviewer's attestation are recorded, and the result is posted back to the PR as a check run." },
  { q: "Does it help with compliance?", a: "Attestations, exceptions and findings land in an immutable audit trail and export as signed evidence packages mapped to SOC 2, the EU AI Act and PCI-DSS, along with SBOMs in SPDX and CycloneDX." },
];

const PIPELINE_STAGES = [
  { label: "GitHub webhook", detail: "PR opened or updated", color: "#94a3b8", icon: WebhookIcon },
  { label: "File fetch", detail: "Every changed file, async via queue", color: "#7dd3fc", icon: DownloadIcon },
  { label: "AI signal scan", detail: "AST · git provenance · behavioral", color: SKY, icon: AiIntelIcon },
  { label: "Taint engine", detail: "Per-language AST + cross-file data-flow", color: ROSE, icon: CodeRiskIcon },
  { label: "Secrets, deps, IaC", detail: "Credentials · CVEs by reachability · cloud, container & API config", color: AMBER, icon: KeyIcon },
  { label: "Policy engine", detail: "Risk score against merge gates", color: VIOLET, icon: ComplianceIcon },
  { label: "Attestation gate", detail: "Blocks until reviewer sign-off", color: EMERALD, icon: UsersIcon },
  { label: "Check run", detail: "Posted to the PR", color: EMERALD, icon: CheckCircleIcon },
];

const WHY_ROWS = [
  { vs: "Point tools (one per risk type)", them: "A SAST tool for vulnerabilities, a separate secrets scanner, an SCA tool, an IaC scanner, an API inventory, and no visibility into what's actually AI-generated — a dashboard and an audit trail for each, nothing reconciled.", us: "One platform: vulnerabilities, secrets, dependencies, cloud and container config, API auth coverage, and AI provenance scored together on every PR, with one policy engine and one audit trail behind all of it.", accent: CYAN },
  { vs: "SCA that lists every CVE", them: "Every CVE in every declared package, sorted by CVSS — including packages nothing imports and functions nothing calls. Teams learn to ignore the list.", us: "Each vulnerable package is ranked by reachability: the vulnerable function called from a route, imported from reachable code, imported only by tests, or never imported — with the file and line as evidence.", accent: AMBER },
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
  { label: "Sink-class bitmask model", desc: "A taint value is a bitmask of 15 sink classes, not a boolean. A sanitizer clears only the classes it neutralizes — and the trace shows it: htmlspecialchars() before a SQL query is called out, not trusted." },
  { label: "Path-sensitive propagation", desc: "Branches are walked on cloned state and merged with a may-taint join; a value sanitized on one branch and raw on another is tracked correctly on both." },
  { label: "Narrow validation guards", desc: "Only unambiguous proofs clear a variable — literal-collection membership, strict numeric checks, equality with a literal, a fully anchored digits-only or character-class pattern. A loose regex match is deliberately NOT trusted." },
  { label: "BOLA ownership dominance", desc: "An authorization check only suppresses a finding when it actually dominates the sink in control-flow order — not merely present somewhere in the function." },
  { label: "Fixed-point call resolution", desc: "Call summaries iterate until nothing changes — same-file and across files — so an eight-deep helper chain or a five-file flow converges, with a safety cap instead of an arbitrary round limit." },
  { label: "Cross-file flows, one finding", desc: "Imports, injected services, Go packages and PHP includes are followed in all nine languages, including Rails autoloading, Kotlin↔Java calls and Rust modules. A flow is reported once, at the caller, listing every file on its path — the callee's duplicate is folded in." },
];

const STEPS = [
  { n: 1, title: "Connect your repos", desc: "Install the GitHub App in under 2 minutes (GitLab and Bitbucket also supported). Every pull request is scanned automatically — no config files, no CI changes." },
  { n: 2, title: "See every signal in one place", desc: "AI% per file, secrets, reachable vulnerable dependencies, traced vulnerabilities, and cloud, container and API misconfigurations — each with real evidence, not a guess. One risk score ties it together." },
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
        <Link href="/" aria-label="TrustLedger home" className="flex items-center">
          <BrandWordmark height={32} />
        </Link>
        <nav className="hidden lg:flex items-center gap-6">
          {["Platform", "Languages", "Vulnerabilities", "Cloud & API", "How it works", "FAQ"].map(l => (
            <a key={l} href={`#${l.toLowerCase().replace(/ & /g, "-").replace(/ /g, "-")}`} className="text-sm text-white/65 hover:text-white/90 transition-colors font-medium">{l}</a>
          ))}
        </nav>
        <div className="flex items-center gap-2">
          <Link href="/login" className="text-sm font-semibold text-white/70 hover:text-white transition-colors px-3 py-1.5">Sign in</Link>
          <Link href="/login?mode=signup" className="flex items-center gap-1.5 text-sm font-bold px-3.5 py-1.5 rounded-lg transition-all text-[#050810]" style={{ background: `linear-gradient(135deg, #67e8f9, ${CYAN})`, boxShadow: `0 2px 18px ${CYAN}66` }}>
            Get started <ArrowRightIcon size={13} />
          </Link>
        </div>
      </div>
    </header>
  );
}

// ── Hero: what a PR check looks like + trace visual ─────────────────────────

/** A risk gauge that fills to `value` once visible. */
function RiskGauge({ value, color }: { value: number; color: string }) {
  const { ref, shown } = useReveal<HTMLDivElement>();
  const r = 26, c = 2 * Math.PI * r;
  return (
    <div ref={ref} className="relative w-[72px] h-[72px] shrink-0">
      <svg width="72" height="72" viewBox="0 0 72 72" className="-rotate-90">
        <circle cx="36" cy="36" r={r} fill="none" stroke="rgba(255,255,255,0.09)" strokeWidth="7" />
        <circle cx="36" cy="36" r={r} fill="none" stroke={color} strokeWidth="7" strokeLinecap="round"
          strokeDasharray={c} strokeDashoffset={shown ? c * (1 - value / 100) : c}
          style={{ transition: "stroke-dashoffset 1.2s cubic-bezier(0.16,1,0.3,1) 0.3s", filter: `drop-shadow(0 0 6px ${color}88)` }} />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-xl font-black text-white leading-none"><CountUp to={value} /></span>
        <span className="text-[8px] font-bold uppercase tracking-wider mt-0.5" style={{ color }}>risk</span>
      </div>
    </div>
  );
}

function PrCheckMock() {
  return (
    <div className="relative">
      <div className="absolute -inset-6 rounded-[2rem] blur-3xl pointer-events-none" style={{ background: `linear-gradient(135deg, ${CYAN}26, ${VIOLET}1f, ${ROSE}1a)` }} />
      <div className="relative rounded-2xl overflow-hidden border text-left" style={{ borderColor: "rgba(255,255,255,0.13)", background: "linear-gradient(180deg, rgba(13,19,34,0.96), rgba(7,11,20,0.98))", boxShadow: "0 40px 100px rgba(0,0,0,0.6), 0 0 0 1px rgba(255,255,255,0.04)" }}>
        {/* pull request header */}
        <div className="px-4 sm:px-5 py-3 flex items-center gap-2.5 border-b" style={{ borderColor: "rgba(255,255,255,0.09)", background: "rgba(255,255,255,0.03)" }}>
          <span className="text-white/60"><GitHubIcon size={15} /></span>
          <div className="min-w-0 flex-1">
            <p className="text-[13px] font-semibold text-white truncate">Add password reset flow <span className="text-white/35 font-normal">#482</span></p>
            <p className="text-[10.5px] font-mono text-white/40 truncate">acme/api · feature/reset → main · 14 files</p>
          </div>
          <span className="text-[10px] font-bold px-2 py-1 rounded-md shrink-0" style={{ color: ROSE, background: `${ROSE}1a`, border: `1px solid ${ROSE}40` }}>Merge blocked</span>
        </div>
        {/* score */}
        <div className="px-4 sm:px-5 py-4 flex items-center gap-4 border-b" style={{ borderColor: "rgba(255,255,255,0.07)" }}>
          <RiskGauge value={82} color={ROSE} />
          <div className="min-w-0 flex-1 space-y-2.5">
            <div>
              <div className="flex items-center justify-between text-[11px] mb-1"><span className="text-white/55">AI-generated</span><span className="font-mono font-bold" style={{ color: SKY }}>68% · Cursor</span></div>
              <div className="h-1.5 rounded-full overflow-hidden" style={{ background: "rgba(255,255,255,0.08)" }}><div className="h-full rounded-full" style={{ width: "68%", background: `linear-gradient(90deg, ${SKY}, ${CYAN})` }} /></div>
            </div>
            <div className="flex items-center gap-1.5 flex-wrap">
              {[["1 critical", ROSE], ["2 high", AMBER], ["1 medium", EMERALD]].map(([t, c]) => (
                <span key={t} className="text-[10px] font-bold font-mono px-1.5 py-0.5 rounded" style={{ color: c, background: `${c}1a` }}>{t}</span>
              ))}
            </div>
          </div>
        </div>
        {/* findings */}
        <div className="divide-y" style={{ borderColor: "rgba(255,255,255,0.06)" }}>
          {MOCK_FINDINGS.map((f, i) => (
            <Reveal key={f.title} delay={300 + i * 110} className="px-4 sm:px-5 py-2.5 flex items-center gap-3" style={{ borderColor: "rgba(255,255,255,0.06)" }}>
              <span className="w-7 h-7 rounded-lg flex items-center justify-center shrink-0" style={{ color: f.color, background: `${f.color}1a`, border: `1px solid ${f.color}38` }}>{f.icon(13)}</span>
              <div className="min-w-0 flex-1">
                <p className="text-[12.5px] font-semibold text-white/90 truncate">{f.title}</p>
                <p className="text-[10.5px] font-mono text-white/40 truncate">{f.detail}</p>
              </div>
              <span className="text-[9.5px] font-bold uppercase tracking-wide px-1.5 py-0.5 rounded shrink-0 hidden sm:inline" style={{ color: "rgba(255,255,255,0.6)", background: "rgba(255,255,255,0.07)" }}>{f.tag}</span>
              <span className="text-[10px] font-bold w-14 text-right shrink-0" style={{ color: f.color }}>{f.sev}</span>
            </Reveal>
          ))}
        </div>
        {/* gate */}
        <div className="px-4 sm:px-5 py-3 flex items-center gap-3 border-t" style={{ borderColor: "rgba(255,255,255,0.09)", background: "rgba(255,255,255,0.03)" }}>
          <span className="relative flex w-2 h-2 shrink-0"><span className="absolute inset-0 rounded-full animate-ping" style={{ background: AMBER, opacity: 0.6 }} /><span className="relative w-2 h-2 rounded-full" style={{ background: AMBER }} /></span>
          <p className="text-[11.5px] text-white/60 flex-1 min-w-0 truncate">Waiting for a named reviewer to attest <span className="font-mono text-white/80">auth/reset.ts</span></p>
          <span className="text-[11px] font-bold px-2.5 py-1 rounded-md shrink-0 text-[#050810]" style={{ background: `linear-gradient(135deg, #67e8f9, ${CYAN})` }}>Review &amp; attest</span>
        </div>
      </div>
      <p className="relative text-center text-[10.5px] font-mono text-white/35 mt-3">Example PR check · illustrative</p>
    </div>
  );
}

const TRACE_STEPS = [
  { kind: "source", file: "diagnostics.ts", line: 4, label: "req.query.host", tone: CYAN },
  { kind: "assignment", file: "diagnostics.ts", line: 5, label: "const cmd = `ping -c 1 ${host}`", tone: "#94a3b8" },
  { kind: "branch", file: "diagnostics.ts", line: 7, label: "if (debugMode) {…} else {…} — taint survives both arms", tone: VIOLET },
  { kind: "cross-file", file: "→ shell.ts", line: 3, label: "crosses into ./shell via \"runPing\"", tone: AMBER },
  { kind: "sink", file: "shell.ts", line: 8, label: "exec(cmd)", tone: ROSE },
  { kind: "fingerprint", file: "shell.ts", line: 8, label: "stable ID assigned — survives unrelated edits to this file", tone: EMERALD },
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
        <span className="text-[11px] font-mono font-semibold ml-2 text-white/70">how a trace reads</span>
        <span className="ml-auto text-[10px] font-mono text-white/40">illustrative example</span>
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
    <section className="relative flex flex-col items-center justify-center text-center px-5 pt-28 lg:pt-36 pb-16 overflow-hidden" style={{ background: `radial-gradient(ellipse 90% 55% at 50% 0%, ${CYAN}16, transparent 58%), ${INK}` }}>
      <div className="absolute inset-0 pointer-events-none overflow-hidden">
        <div className="absolute -top-40 -left-24 w-[30rem] h-[30rem] rounded-full blur-[140px]" style={{ background: CYAN, opacity: 0.08 }} />
        <div className="absolute -top-24 -right-24 w-[26rem] h-[26rem] rounded-full blur-[140px]" style={{ background: VIOLET, opacity: 0.06 }} />
        <div className="absolute inset-0" style={{ backgroundImage: "linear-gradient(rgba(255,255,255,0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.03) 1px, transparent 1px)", backgroundSize: "56px 56px" }} />
        <div className="absolute bottom-0 left-0 right-0 h-52" style={{ background: `linear-gradient(to top, ${INK}, transparent)` }} />
      </div>

      <div className="relative w-full max-w-7xl mx-auto grid grid-cols-1 lg:grid-cols-[1.12fr_1fr] gap-12 lg:gap-12 xl:gap-16 items-center">
        <Reveal className="min-w-0 space-y-6 lg:text-left">
          <Eyebrow><span className="w-1.5 h-1.5 rounded-full" style={{ background: CYAN, boxShadow: `0 0 8px ${CYAN}` }} />One platform for everything that touches a PR</Eyebrow>
          <h1 className="text-[2.6rem] min-[400px]:text-5xl sm:text-6xl lg:text-[3.25rem] xl:text-[3.85rem] font-black text-white tracking-tight leading-[1.05]" style={{ textShadow: "0 4px 40px rgba(0,0,0,0.7)" }}>
            AI provenance.<br />
            <span style={{ background: `linear-gradient(90deg, ${CYAN}, #67e8f9, #a5f3fc)`, WebkitBackgroundClip: "text", WebkitTextFillColor: "transparent", backgroundClip: "text" }}>Real vulnerabilities.</span><br />
            One risk score.
          </h1>
          <p className="text-lg sm:text-xl text-white/65 max-w-xl mx-auto lg:mx-0 leading-relaxed">
            Every pull request scored for AI-generated code, real vulnerabilities traced across files in nine languages, leaked secrets, reachable vulnerable dependencies and cloud misconfigurations — and held until a named reviewer signs off.
          </p>
          <div className="flex flex-col sm:flex-row items-center justify-center lg:justify-start gap-3 pt-1">
            <Link href="/login?mode=signup" className="flex items-center gap-2 px-6 py-3.5 rounded-xl font-bold text-sm transition-all active:scale-[0.98] text-[#050810]"
              style={{ background: `linear-gradient(135deg, #67e8f9, ${CYAN})`, boxShadow: `0 6px 32px ${CYAN}66` }}
              onMouseEnter={e => { const el = e.currentTarget as HTMLElement; el.style.transform = "translateY(-2px)"; el.style.boxShadow = `0 10px 40px ${CYAN}88`; }}
              onMouseLeave={e => { const el = e.currentTarget as HTMLElement; el.style.transform = "translateY(0)"; el.style.boxShadow = `0 6px 32px ${CYAN}66`; }}>
              Get started free <ArrowRightIcon size={15} />
            </Link>
            <Link href="/dashboard" className="flex items-center gap-2 px-6 py-3.5 rounded-xl text-white/80 font-semibold text-sm transition-all border hover:text-white/95"
              style={{ borderColor: "rgba(255,255,255,0.18)", background: "rgba(255,255,255,0.06)" }}
              onMouseEnter={e => { (e.currentTarget as HTMLElement).style.borderColor = "rgba(255,255,255,0.32)"; (e.currentTarget as HTMLElement).style.background = "rgba(255,255,255,0.09)"; }}
              onMouseLeave={e => { (e.currentTarget as HTMLElement).style.borderColor = "rgba(255,255,255,0.18)"; (e.currentTarget as HTMLElement).style.background = "rgba(255,255,255,0.06)"; }}>
              <GitHubIcon size={15} /> Explore the dashboard
            </Link>
          </div>
          <ul className="flex flex-wrap justify-center lg:justify-start gap-x-5 gap-y-2 pt-1">
            {["Free to start — no credit card", "Installs as a GitHub App in ~2 minutes", "No CI changes or config files"].map(t => (
              <li key={t} className="flex items-center gap-1.5 text-[12.5px] text-white/55">
                <span style={{ color: EMERALD }}><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12" /></svg></span>{t}
              </li>
            ))}
          </ul>
        </Reveal>
        <Reveal delay={150} className="min-w-0 w-full max-w-xl mx-auto lg:max-w-none">
          <PrCheckMock />
        </Reveal>
      </div>

      <Reveal delay={320} className="relative mt-20 w-full max-w-5xl mx-auto grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4 pt-10 border-t" style={{ borderColor: "rgba(255,255,255,0.08)" }}>
        {[{ to: 9, label: "language engines" }, { to: 20, label: "vulnerability classes" }, { to: 47, label: "AI-detection signals" }, { to: 8, label: "SCA ecosystems" }, { to: IAC_FORMATS.length, label: "IaC & cloud formats" }, { to: 6, label: "API languages inventoried" }].map(s => (
          <div key={s.label} className="text-center">
            <p className="text-3xl font-black font-mono" style={{ color: "#67e8f9", textShadow: `0 0 24px ${CYAN}88` }}><CountUp to={s.to} /></p>
            <p className="text-[11px] text-white/50 font-medium mt-1">{s.label}</p>
          </div>
        ))}
      </Reveal>
    </section>
  );
}

// ── Stack band: "does it support us?", answered right under the hero ────────

function Monogram({ l, size = 34 }: { l: LangEngine; size?: number }) {
  return (
    <span className="rounded-lg flex items-center justify-center shrink-0 font-black font-mono" style={{ width: size, height: size, fontSize: l.mono.length > 2 ? size * 0.3 : size * 0.36, color: l.color, background: `${l.color}1f`, border: `1px solid ${l.color}55`, boxShadow: `inset 0 1px 0 rgba(255,255,255,0.06)` }}>{l.mono}</span>
  );
}

function StackBand() {
  return (
    <section className="relative py-14 px-5 border-y overflow-hidden" style={{ borderColor: "rgba(255,255,255,0.07)", background: SURFACE }}>
      <Reveal className="max-w-6xl mx-auto text-center">
        <p className="text-[11px] font-bold uppercase tracking-[0.18em] text-white/45 font-mono">Works with the stack you already ship</p>
        <div className="mt-6 flex flex-wrap justify-center gap-2.5">
          {LANGUAGES.map(l => (
            <a key={l.lang} href="#languages" className="flex items-center gap-2 pl-1.5 pr-3.5 py-1.5 rounded-xl border transition-all hover:-translate-y-0.5"
              style={{ borderColor: "rgba(255,255,255,0.1)", background: "rgba(255,255,255,0.035)" }}
              onMouseEnter={e => { (e.currentTarget as HTMLElement).style.borderColor = `${l.color}66`; }}
              onMouseLeave={e => { (e.currentTarget as HTMLElement).style.borderColor = "rgba(255,255,255,0.1)"; }}>
              <Monogram l={l} size={28} />
              <span className="text-sm font-semibold text-white/85">{l.short}</span>
            </a>
          ))}
        </div>
      </Reveal>
      {/* a scrolling row (two copies for a seamless loop); with reduced motion, one static wrapped list */}
      <div className="tl-marquee-mask relative mt-7 max-w-5xl mx-auto overflow-hidden">
        <div className="tl-marquee flex w-max gap-8">
          {[0, 1].flatMap(copy => [...FRAMEWORKS, "GitHub", "GitLab", "Bitbucket"].map(f => (
            <span key={`${f}-${copy}`} aria-hidden={copy === 1 || undefined} className={`text-[13px] font-semibold text-white/40 whitespace-nowrap font-mono${copy === 1 ? " tl-dup" : ""}`}>{f}</span>
          )))}
        </div>
      </div>
      <style>{`
        .tl-marquee-mask { mask-image: linear-gradient(90deg, transparent, #000 12%, #000 88%, transparent); -webkit-mask-image: linear-gradient(90deg, transparent, #000 12%, #000 88%, transparent); }
        .tl-marquee { animation: tlMarquee 38s linear infinite; }
        @keyframes tlMarquee { from { transform: translateX(0); } to { transform: translateX(-50%); } }
        @media (prefers-reduced-motion: reduce) {
          .tl-marquee-mask { mask-image: none; -webkit-mask-image: none; }
          .tl-marquee { animation: none; flex-wrap: wrap; justify-content: center; width: auto; row-gap: 0.6rem; }
          .tl-dup { display: none; }
        }
      `}</style>
    </section>
  );
}

// ── Proof: the trace next to "them vs us" ───────────────────────────────────

function ProofSection() {
  return (
    <section id="why" className="py-24 px-5" style={{ background: `radial-gradient(ellipse 70% 50% at 50% 0%, ${ROSE}0a, transparent 65%), ${INK}` }}>
      <div className="max-w-6xl mx-auto">
        <Reveal className="text-center mb-14">
          <Eyebrow color={ROSE}>Why TrustLedger</Eyebrow>
          <h2 className="text-4xl sm:text-5xl font-black text-white mt-4 tracking-tight">Proof, <span style={{ color: ROSE }}>not a pattern match</span></h2>
          <p className="text-white/60 mt-3 text-lg max-w-2xl mx-auto">Every finding comes with the path an attacker's value takes to the dangerous call — so reviewers spend their time on judgment calls, not on re-deriving whether it's real.</p>
        </Reveal>
        <div className="grid grid-cols-1 lg:grid-cols-[1fr_1.05fr] gap-8 items-start">
          <Reveal className="min-w-0 lg:sticky lg:top-24">
            <TraceVisual />
          </Reveal>
          <div className="min-w-0 space-y-3.5">
            {WHY_ROWS.map((row, i) => (
              <Reveal key={row.vs} delay={i * 70}>
                <div className="rounded-2xl border p-5" style={{ borderColor: "rgba(255,255,255,0.11)", background: "rgba(255,255,255,0.035)" }}>
                  <p className="text-[11px] font-bold uppercase tracking-widest text-white/40 font-mono mb-3">vs {row.vs}</p>
                  <div className="flex gap-2.5 mb-2.5">
                    <span className="mt-0.5 shrink-0 w-4 h-4 rounded-full flex items-center justify-center text-[10px] font-black" style={{ color: "rgba(255,255,255,0.45)", background: "rgba(255,255,255,0.07)" }}>✕</span>
                    <p className="text-[13px] text-white/50 leading-relaxed">{row.them}</p>
                  </div>
                  <div className="flex gap-2.5">
                    <span className="mt-0.5 shrink-0 w-4 h-4 rounded-full flex items-center justify-center text-[10px] font-black" style={{ color: row.accent, background: `${row.accent}22` }}>✓</span>
                    <p className="text-[13.5px] text-white/85 leading-relaxed">{row.us}</p>
                  </div>
                </div>
              </Reveal>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}

// ── FAQ ──────────────────────────────────────────────────────────────────────

function FaqSection() {
  return (
    <section id="faq" className="py-24 px-5" style={{ background: SURFACE }}>
      <div className="max-w-3xl mx-auto">
        <Reveal className="text-center mb-12">
          <Eyebrow>FAQ</Eyebrow>
          <h2 className="text-4xl font-black text-white mt-4 tracking-tight">Questions teams ask first</h2>
        </Reveal>
        <div className="space-y-3">
          {FAQS.map((f, i) => (
            <Reveal key={f.q} delay={i * 50}>
              <details className="group rounded-2xl border transition-colors open:bg-white/[0.045]" style={{ borderColor: "rgba(255,255,255,0.11)", background: "rgba(255,255,255,0.03)" }}>
                <summary className="flex items-center justify-between gap-4 px-5 py-4 cursor-pointer list-none [&::-webkit-details-marker]:hidden">
                  <span className="font-semibold text-white/90 text-[15px]">{f.q}</span>
                  <span className="w-7 h-7 rounded-lg flex items-center justify-center shrink-0 transition-transform duration-200 group-open:rotate-45" style={{ color: CYAN, background: `${CYAN}14`, border: `1px solid ${CYAN}33` }}>
                    <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round"><line x1="12" y1="5" x2="12" y2="19" /><line x1="5" y1="12" x2="19" y2="12" /></svg>
                  </span>
                </summary>
                <p className="px-5 pb-5 -mt-1 text-sm text-white/65 leading-relaxed">{f.a}</p>
              </details>
            </Reveal>
          ))}
        </div>
      </div>
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
    <section id="platform" className="py-24 px-5" style={{ background: `radial-gradient(ellipse 70% 50% at 50% 0%, ${p.color}0c, transparent 65%), ${SURFACE}`, transition: "background 0.5s ease" }}>
      <div className="max-w-5xl mx-auto">
        <Reveal className="text-center mb-12">
          <Eyebrow>The platform</Eyebrow>
          <h2 className="text-4xl font-black text-white mt-4 tracking-tight">Seven pillars. One scan.</h2>
          <p className="text-white/60 mt-3 max-w-2xl mx-auto text-lg">Every pull request runs through all seven — the same structure as the dashboard itself, not a marketing simplification of it.</p>
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
            <p className="text-white/70 leading-relaxed mb-5">{p.desc}</p>
            <div className="flex flex-wrap gap-2">
              {p.pages.map(page => (
                <span key={page} className="text-[11px] font-mono px-2.5 py-1 rounded-full border text-white/60" style={{ borderColor: "rgba(255,255,255,0.14)", background: "rgba(255,255,255,0.045)" }}>{page}</span>
              ))}
            </div>
          </div>
          <div className="md:col-span-2 space-y-2.5">
            {p.bullets.map((b, i) => (
              <div key={i} className="flex items-start gap-2.5 p-3 rounded-xl border" style={{ borderColor: "rgba(255,255,255,0.09)", background: "rgba(255,255,255,0.035)", boxShadow: "inset 0 1px 0 rgba(255,255,255,0.06)" }}>
                <span className="w-1.5 h-1.5 rounded-full mt-1.5 shrink-0" style={{ background: p.color }} />
                <span className="text-[13px] text-white/75 leading-snug">{b}</span>
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
    <section id="vulnerabilities" className="py-24 px-5" style={{ background: `radial-gradient(ellipse 70% 50% at 50% 0%, ${ROSE}0c, transparent 65%), ${SURFACE}` }}>
      <div className="max-w-6xl mx-auto">
        <Reveal className="text-center mb-14">
          <Eyebrow color={ROSE}>Zoom in — Code Risk</Eyebrow>
          <h2 className="text-4xl font-black text-white mt-4 tracking-tight">Twenty vulnerability classes, real data-flow evidence</h2>
          <p className="text-white/60 mt-3 max-w-2xl mx-auto text-lg">Every finding below is matched by tracking an actual tainted value from its source to a real sink — not a keyword or a line pattern.</p>
        </Reveal>
        <div className="space-y-8">
          {groups.map((g, gi) => (
            <Reveal key={g} delay={gi * 60}>
              <div className="flex items-center gap-2 mb-3">
                <span className="w-1.5 h-1.5 rounded-full" style={{ background: GROUP_COLORS[g] }} />
                <span className="text-[11px] font-bold uppercase tracking-widest text-white/50 font-mono">{g}</span>
              </div>
              <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 gap-3">
                {VULN_CLASSES.filter(v => v.group === g).map(v => (
                  <div key={v.name} className="group relative flex items-center gap-3 pl-4 pr-3 py-3 rounded-xl border overflow-hidden transition-all" style={{ borderColor: "rgba(255,255,255,0.14)", background: "rgba(255,255,255,0.04)", boxShadow: "inset 0 1px 0 rgba(255,255,255,0.05)" }}
                    onMouseEnter={e => { const el = e.currentTarget as HTMLElement; el.style.borderColor = `${GROUP_COLORS[g]}55`; el.style.background = "rgba(255,255,255,0.07)"; el.style.transform = "translateY(-2px)"; el.style.boxShadow = `0 10px 24px ${GROUP_COLORS[g]}22, inset 0 1px 0 rgba(255,255,255,0.06)`; }}
                    onMouseLeave={e => { const el = e.currentTarget as HTMLElement; el.style.borderColor = "rgba(255,255,255,0.14)"; el.style.background = "rgba(255,255,255,0.04)"; el.style.transform = "translateY(0)"; el.style.boxShadow = "inset 0 1px 0 rgba(255,255,255,0.05)"; }}>
                    <span className="absolute left-0 top-0 bottom-0 w-[3px]" style={{ background: GROUP_COLORS[g] }} />
                    <span className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0" style={{ color: GROUP_COLORS[g], background: `${GROUP_COLORS[g]}1c` }}>{AlertIcon(15)}</span>
                    <div className="min-w-0 flex-1">
                      <p className="text-sm font-semibold text-white/90 truncate">{v.name}</p>
                      <p className="text-[10px] font-mono text-white/45 mt-0.5">{v.cwe}</p>
                    </div>
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
    <section id="languages" className="py-24 px-5" style={{ background: `radial-gradient(ellipse 70% 50% at 50% 0%, ${AMBER}0a, transparent 65%), ${INK}` }}>
      <div className="max-w-5xl mx-auto">
        <Reveal className="text-center mb-14">
          <Eyebrow color={ROSE}>Zoom in — Code Risk</Eyebrow>
          <h2 className="text-4xl sm:text-5xl font-black text-white mt-4 tracking-tight">Nine languages. <span style={{ color: "#67e8f9" }}>Nine real parsers.</span></h2>
          <p className="text-white/60 mt-3 max-w-2xl mx-auto text-lg">Each language gets its own dedicated AST parser and taint-propagation engine, tuned to that ecosystem's own frameworks — not one ruleset stretched across nine syntaxes.</p>
        </Reveal>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {LANGUAGES.map((l, i) => (
            <Reveal key={l.lang} delay={i * 70}>
              <div className="group relative h-full p-5 rounded-2xl border transition-all overflow-hidden" style={{ borderColor: "rgba(255,255,255,0.11)", background: "rgba(255,255,255,0.04)", boxShadow: "inset 0 1px 0 rgba(255,255,255,0.05)" }}
                onMouseEnter={e => { const el = e.currentTarget as HTMLElement; el.style.borderColor = `${l.color}66`; el.style.background = "rgba(255,255,255,0.06)"; el.style.transform = "translateY(-3px)"; }}
                onMouseLeave={e => { const el = e.currentTarget as HTMLElement; el.style.borderColor = "rgba(255,255,255,0.11)"; el.style.background = "rgba(255,255,255,0.04)"; el.style.transform = "translateY(0)"; }}>
                <span className="absolute -top-10 -right-10 w-28 h-28 rounded-full blur-2xl pointer-events-none" style={{ background: l.color, opacity: 0.08 }} />
                <div className="relative flex items-center gap-3 mb-3">
                  <Monogram l={l} />
                  <div className="min-w-0 flex-1">
                    <p className="font-bold text-white text-sm truncate">{l.lang}</p>
                    <p className="text-[10px] font-mono text-white/40">{l.ext}</p>
                  </div>
                </div>
                <p className="text-sm text-white/75 leading-relaxed">{l.note}</p>
                <p className="text-xs text-white/45 mt-1.5">{l.extra}</p>
              </div>
            </Reveal>
          ))}
        </div>
      </div>
    </section>
  );
}

// ── Cloud & API coverage, generated from the live rule catalog ──────────────

const IAC_FORMATS = ["Terraform", "CloudFormation / SAM", "ARM templates", "Bicep", "Serverless", "Kubernetes & Helm", "Docker & Compose"];

const LEGACY_K8S = ["iac-privileged-container", "iac-container-run-as-root", "iac-host-namespace-access", "iac-dangerous-capability", "iac-unpinned-image-tag"];
// Older Terraform-only rules; iac-s3-public-acl and iac-public-db are the same checks as cloud-storage-public
// and cloud-db-public (for more formats), so they aren't listed twice.
const LEGACY_CLOUD = ["iac-open-ingress", "iac-unencrypted-storage", "iac-iam-wildcard"];
const CLOUD_API_GROUPS: Array<{ name: string; color: string; icon: (s?: number) => React.ReactNode; blurb: string; match: (id: string) => boolean }> = [
  { name: "Kubernetes & Helm", color: SKY, icon: HelmIcon, blurb: "Checked per container, with pod-level settings inherited and Helm values respected.", match: id => id.startsWith("iac-k8s-") || LEGACY_K8S.includes(id) },
  { name: "Cloud posture", color: AMBER, icon: CloudIcon, blurb: "AWS, GCP and Azure resources as your templates define them — before they're created.", match: id => id.startsWith("cloud-") || LEGACY_CLOUD.includes(id) },
  { name: "Containers", color: ORANGE, icon: ContainerIcon, blurb: "Dockerfiles and Compose files: what the image is built from and how it runs.", match: id => id.startsWith("container-") },
  { name: "API security", color: EMERALD, icon: ApiIcon, blurb: "Your code's routes and your OpenAPI specs, with the authentication visible for each.", match: id => id.startsWith("api-") },
];

function CloudApiSection() {
  const groups = CLOUD_API_GROUPS.map(g => {
    const titles = Array.from(new Set(Object.entries(FINDING_CATALOG).filter(([id]) => g.match(id)).map(([, e]) => e.title)));
    return { ...g, titles };
  });
  const total = groups.reduce((n, g) => n + g.titles.length, 0);
  return (
    <section id="cloud-api" className="py-24 px-5" style={{ background: `radial-gradient(ellipse 70% 50% at 50% 0%, ${AMBER}0c, transparent 65%), ${INK}` }}>
      <div className="max-w-6xl mx-auto">
        <Reveal className="text-center mb-10">
          <Eyebrow color={AMBER}>Zoom in — Cloud & API</Eyebrow>
          <h2 className="text-4xl font-black text-white mt-4 tracking-tight">{total} checks for what you deploy and expose</h2>
          <p className="text-white/60 mt-3 max-w-2xl mx-auto text-lg">Infrastructure, containers and APIs are read from the same pull request as your code — each finding on its exact line, with a fix. No cloud credentials, no agents.</p>
        </Reveal>
        <Reveal delay={60} className="flex flex-wrap justify-center gap-2 mb-12">
          {IAC_FORMATS.map(f => (
            <span key={f} className="text-[11px] font-mono px-3 py-1.5 rounded-full border text-white/70" style={{ borderColor: `${AMBER}40`, background: `${AMBER}10` }}>{f}</span>
          ))}
          <span className="text-[11px] font-mono px-3 py-1.5 rounded-full border text-white/70" style={{ borderColor: `${EMERALD}40`, background: `${EMERALD}10` }}>OpenAPI / Swagger</span>
        </Reveal>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
          {groups.map((g, gi) => (
            <Reveal key={g.name} delay={gi * 70}>
              <div className="h-full p-6 rounded-2xl border" style={{ borderColor: "rgba(255,255,255,0.12)", background: "rgba(255,255,255,0.04)", boxShadow: "inset 0 1px 0 rgba(255,255,255,0.05)" }}>
                <div className="flex items-center gap-3 mb-2">
                  <span className="w-10 h-10 rounded-xl flex items-center justify-center shrink-0" style={{ color: g.color, background: `${g.color}1c`, border: `1px solid ${g.color}40` }}>{g.icon(19)}</span>
                  <div className="min-w-0">
                    <p className="font-bold text-white">{g.name}</p>
                    <p className="text-[11px] font-mono" style={{ color: g.color }}>{g.titles.length} checks</p>
                  </div>
                </div>
                <p className="text-[13px] text-white/60 leading-relaxed mb-4">{g.blurb}</p>
                <div className="flex flex-wrap gap-1.5">
                  {g.titles.map(t => (
                    <span key={t} className="text-[11px] px-2 py-1 rounded-md text-white/75" style={{ background: "rgba(255,255,255,0.06)", border: "1px solid rgba(255,255,255,0.09)" }}>{t}</span>
                  ))}
                </div>
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
    <section id="how-it-analyzes" className="py-24 px-5" style={{ background: `radial-gradient(ellipse 70% 50% at 50% 0%, ${VIOLET}0c, transparent 65%), ${INK}` }}>
      <div className="max-w-5xl mx-auto">
        <Reveal className="text-center mb-14">
          <Eyebrow>Every PR, every push</Eyebrow>
          <h2 className="text-4xl font-black text-white mt-4 tracking-tight">What one scan actually does</h2>
          <p className="text-white/60 mt-3 max-w-2xl mx-auto text-lg">All seven pillars run on the same scan, in this order, in under a few seconds per file.</p>
        </Reveal>
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          {PIPELINE_STAGES.map((s, i) => (
            <Reveal key={s.label} delay={i * 60}>
              <div className="group relative h-full min-h-[168px] p-5 rounded-2xl border transition-all" style={{ borderColor: "rgba(255,255,255,0.11)", background: "rgba(255,255,255,0.04)", boxShadow: "inset 0 1px 0 rgba(255,255,255,0.05)" }}
                onMouseEnter={e => { const el = e.currentTarget as HTMLElement; el.style.borderColor = `${s.color}55`; el.style.background = "rgba(255,255,255,0.065)"; el.style.transform = "translateY(-3px)"; }}
                onMouseLeave={e => { const el = e.currentTarget as HTMLElement; el.style.borderColor = "rgba(255,255,255,0.11)"; el.style.background = "rgba(255,255,255,0.04)"; el.style.transform = "translateY(0)"; }}>
                <div className="flex items-center justify-between mb-4">
                  <span className="w-11 h-11 rounded-xl flex items-center justify-center" style={{ color: s.color, background: `${s.color}1c`, border: `1px solid ${s.color}38` }}>{s.icon(20)}</span>
                  <span className="text-[11px] font-mono font-black text-white/30">{String(i + 1).padStart(2, "0")}</span>
                </div>
                <p className="text-base font-bold text-white leading-tight">{s.label}</p>
                <p className="text-[12.5px] text-white/55 mt-1.5 leading-snug">{s.detail}</p>
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
  { icon: GitBranchIcon, title: "Cross-File Data Flow", desc: "In all nine languages: imports and re-exports, injected services (Spring, ASP.NET, NestJS, Axum state), Go packages, PHP includes, Rails autoloading, Rust modules — measured by a 72-case cross-file benchmark on every change.", accent: CYAN },
  { icon: MergeIcon, title: "One Issue, One Finding", desc: "When the pattern layer, the taint engine and cross-file analysis see the same bug, it becomes one finding listing every location and every detector that agreed.", accent: CYAN },
  { icon: LockIcon, title: "Broken Object-Level Authorization", desc: "Structural ownership-dominance analysis: a resource lookup only clears when a real comparison against the principal dominates every path to the sink.", accent: ROSE },
  { icon: PackageIcon, title: "Reachable Dependencies", desc: "Live CVEs across 8 ecosystems, ranked by whether the vulnerable function is called, the package is reachable from an entry point, used only in tests, or never imported.", accent: AMBER },
  { icon: CloudIcon, title: "Cloud & IaC Posture", desc: "Terraform (AWS, GCP, Azure), CloudFormation, ARM, Bicep and Serverless: public storage, open admin ports, public databases, wildcard IAM, hard-coded credentials — no cloud credentials needed.", accent: AMBER },
  { icon: HelmIcon, title: "Kubernetes & Containers", desc: "Per-container hardening in manifests and Helm charts, RBAC wildcards, committed Secrets; end-of-life base images and disabled sandboxing in Dockerfiles and Compose.", accent: AMBER },
  { icon: ApiIcon, title: "API Endpoint Inventory", desc: "Every route across Express, Next.js, Flask, FastAPI, Spring, ASP.NET, Go and Laravel plus OpenAPI specs — and the endpoint missing the auth its siblings have.", accent: EMERALD },
  { icon: FingerprintIcon, title: "Stable Finding Fingerprints", desc: "A hash of the flow itself, not the line number — the same finding survives unrelated edits elsewhere in the file across scans.", accent: CYAN },
  { icon: UsersIcon, title: "Reviewer Attestation", desc: "Named sign-off recorded per file with signature, timestamp, and risk context at review time — an audit trail that answers itself.", accent: VIOLET },
  { icon: KeyIcon, title: "Context-Aware Sanitizers", desc: "An HTML-escaped value dropped into a <script> block or an unquoted attribute is still flagged — encoding for one context doesn't cover another.", accent: ROSE },
  { icon: AlertIcon, title: "Exact Sink Arguments", desc: "Only the exploitable argument counts: the SQL text, not bound parameters; the LDAP filter, not the base DN; the program, not its arguments.", accent: ROSE },
];

function FeaturesSection() {
  return (
    <section id="features" className="py-24 px-5" style={{ background: `radial-gradient(ellipse 70% 50% at 50% 0%, ${CYAN}0c, transparent 65%), ${SURFACE}` }}>
      <div className="max-w-6xl mx-auto">
        <Reveal className="text-center mb-14">
          <Eyebrow>Features</Eyebrow>
          <h2 className="text-4xl font-black text-white mt-4 tracking-tight">Built like a scanner, not a linter</h2>
          <p className="text-white/60 mt-3 max-w-xl mx-auto text-lg">Every capability below maps to a real, tested component — not a roadmap slide.</p>
        </Reveal>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {FEATURES.map((f, i) => (
            <Reveal key={f.title} delay={(i % 4) * 60}>
              <div className="group relative p-5 rounded-2xl transition-all duration-200 h-full" style={{ background: "rgba(255,255,255,0.045)", border: "1px solid rgba(255,255,255,0.14)", boxShadow: "inset 0 1px 0 rgba(255,255,255,0.06)" }}
                onMouseEnter={e => { const el = e.currentTarget as HTMLElement; el.style.borderColor = `${f.accent}66`; el.style.background = "rgba(255,255,255,0.07)"; el.style.transform = "translateY(-3px)"; el.style.boxShadow = `0 16px 36px ${f.accent}2e, inset 0 1px 0 rgba(255,255,255,0.08)`; }}
                onMouseLeave={e => { const el = e.currentTarget as HTMLElement; el.style.borderColor = "rgba(255,255,255,0.14)"; el.style.background = "rgba(255,255,255,0.045)"; el.style.transform = "translateY(0)"; el.style.boxShadow = "inset 0 1px 0 rgba(255,255,255,0.06)"; }}>
                <div className="w-9 h-9 rounded-lg flex items-center justify-center mb-3.5" style={{ color: f.accent, background: `${f.accent}1c`, border: `1px solid ${f.accent}38` }}>{f.icon(18)}</div>
                <h3 className="text-sm font-bold text-white mb-1.5">{f.title}</h3>
                <p className="text-[13px] text-white/65 leading-relaxed">{f.desc}</p>
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
          <div className="p-4 rounded-xl border h-full" style={{ borderColor: "rgba(255,255,255,0.14)", background: "rgba(255,255,255,0.035)", minHeight: 128 }}>
            <div className="flex items-center gap-2 mb-2">
              <span className="text-[9px] font-black tabular-nums w-4.5 h-4.5 rounded-md flex items-center justify-center shrink-0 font-mono" style={{ background: `${color}2c`, color, border: `1px solid ${color}4d`, width: 18, height: 18 }}>{i + 1}</span>
              <p className="text-xs font-bold text-white/90">{s.label}</p>
            </div>
            <p className="text-xs text-white/60 leading-relaxed">{s.desc}</p>
          </div>
        </Reveal>
      ))}
    </div>
  );
}

function ArchSection() {
  return (
    <section className="py-24 px-5" style={{ background: `radial-gradient(ellipse 70% 50% at 50% 0%, ${SKY}0c, transparent 65%), ${INK}` }}>
      <div className="max-w-5xl mx-auto">
        <Reveal className="text-center mb-14">
          <Eyebrow color={SKY}>Under the hood</Eyebrow>
          <h2 className="text-4xl font-black text-white mt-4 tracking-tight">Two real engines, documented in the open</h2>
          <p className="text-white/60 mt-3 text-lg max-w-2xl mx-auto">The AI-provenance model and the vulnerability taint model are two separate, independently-tested systems — here's the shape of each.</p>
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

// ── HowItWorksSection ────────────────────────────────────────────────────────

function HowItWorksSection() {
  return (
    <section id="how-it-works" className="py-24 px-5" style={{ background: `radial-gradient(ellipse 70% 50% at 50% 0%, ${EMERALD}0c, transparent 65%), ${SURFACE}` }}>
      <div className="max-w-4xl mx-auto">
        <Reveal className="text-center mb-14">
          <Eyebrow>How it works</Eyebrow>
          <h2 className="text-4xl font-black text-white mt-4 tracking-tight">Up and running in 5 minutes</h2>
          <p className="text-white/60 mt-3 text-lg">No CI/CD changes. No config files. Install once and every PR is scanned automatically.</p>
        </Reveal>
        <div className="space-y-4">
          {STEPS.map((s, i) => (
            <Reveal key={s.n} delay={i * 80}>
              <div className="flex gap-6 p-6 rounded-2xl border transition-colors" style={{ borderColor: "rgba(255,255,255,0.14)", background: "rgba(255,255,255,0.04)" }}>
                <div className="w-10 h-10 rounded-xl flex items-center justify-center font-black text-sm shrink-0 text-[#050810]" style={{ background: CYAN, boxShadow: `0 4px 16px ${CYAN}4d` }}>{s.n}</div>
                <div><h3 className="font-bold text-white mb-1">{s.title}</h3><p className="text-sm text-white/65 leading-relaxed">{s.desc}</p></div>
              </div>
            </Reveal>
          ))}
        </div>
        <Reveal delay={260} className="mt-10 p-5 rounded-2xl overflow-x-auto border" style={{ borderColor: "rgba(255,255,255,0.11)", background: "#080b12" }}>
          <p className="text-xs text-white/45 font-mono mb-3"># Or submit scans via the REST API</p>
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
    <section className="py-24 px-5 relative overflow-hidden" style={{ background: `radial-gradient(ellipse 70% 60% at 50% 40%, ${CYAN}16, transparent 65%), ${INK}` }}>
      <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[36rem] h-[36rem] rounded-full blur-[140px] pointer-events-none" style={{ background: CYAN, opacity: 0.06 }} />
      <Reveal className="relative max-w-3xl mx-auto text-center space-y-6 rounded-3xl border px-6 py-14 sm:px-12" style={{ borderColor: `${CYAN}2e`, background: "linear-gradient(180deg, rgba(34,211,238,0.06), rgba(255,255,255,0.02))", boxShadow: `0 30px 80px rgba(0,0,0,0.45), inset 0 1px 0 rgba(255,255,255,0.06)` }}>
        <BrandMark size={72} className="mx-auto" />
        <h2 className="text-4xl sm:text-5xl font-black text-white tracking-tight">Stop shipping blind.</h2>
        <p className="text-white/65 text-lg max-w-xl mx-auto leading-relaxed">
          AI-generated code, leaked secrets, reachable vulnerable dependencies, a public bucket, an endpoint that forgot its auth check — any of it can slip into a PR unnoticed. TrustLedger scores it, traces it, and makes sure a human signed off before any of it reaches production.
        </p>
        <div className="flex flex-col sm:flex-row items-center justify-center gap-3 pt-2">
          <Link href="/login?mode=signup" className="flex items-center gap-2 px-8 py-4 rounded-xl font-bold transition-all active:scale-[0.98] text-[#050810]"
            style={{ background: `linear-gradient(135deg, #67e8f9, ${CYAN})`, boxShadow: `0 6px 32px ${CYAN}66` }}
            onMouseEnter={e => { const el = e.currentTarget as HTMLElement; el.style.transform = "translateY(-2px)"; el.style.boxShadow = `0 10px 40px ${CYAN}88`; }}
            onMouseLeave={e => { const el = e.currentTarget as HTMLElement; el.style.transform = "translateY(0)"; el.style.boxShadow = `0 6px 32px ${CYAN}66`; }}>
            Get started free <ArrowRightIcon />
          </Link>
          <Link href="/dashboard" className="flex items-center gap-2 px-8 py-4 rounded-xl text-white/75 font-semibold transition-all border hover:text-white/90" style={{ borderColor: "rgba(255,255,255,0.18)", background: "rgba(255,255,255,0.06)" }}>
            Explore the dashboard
          </Link>
        </div>
        <p className="text-sm text-white/45">Questions first? <a href="mailto:hello@trustledger.dev" className="font-semibold text-white/70 hover:text-white underline underline-offset-4 decoration-white/25">Talk to us</a> — hello@trustledger.dev</p>
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
          <BrandLogo height={52} className="mb-3" />
          <p className="text-xs text-white/40 max-w-xs leading-relaxed">AI provenance, real vulnerability scanning, secrets, dependencies, cloud, container and API security, and compliance — scored, traced, gated, and attested — for teams that care about what ships.</p>
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-8 text-sm">
          <div>
            <p className="font-bold text-white/60 text-xs uppercase tracking-wider mb-3">Platform</p>
            <ul className="space-y-2">{[{ label: "Overview", href: "/dashboard" }, { label: "Vulnerabilities", href: "#vulnerabilities" }, { label: "AI Intel", href: "/trust-score" }, { label: "Threats", href: "/violations" }].map(l => <li key={l.label}><a href={l.href} className="text-white/40 hover:text-white/70 transition-colors">{l.label}</a></li>)}</ul>
          </div>
          <div>
            <p className="font-bold text-white/60 text-xs uppercase tracking-wider mb-3">Code Risk</p>
            <ul className="space-y-2">{[{ label: "Scan History", href: "/scans" }, { label: "Secrets", href: "/secrets" }, { label: "Dependencies", href: "/dependencies" }, { label: "API Security", href: "/api-security" }, { label: "Cloud & API checks", href: "#cloud-api" }].map(l => <li key={l.label}><a href={l.href} className="text-white/40 hover:text-white/70 transition-colors">{l.label}</a></li>)}</ul>
          </div>
          <div>
            <p className="font-bold text-white/60 text-xs uppercase tracking-wider mb-3">Compliance</p>
            <ul className="space-y-2">{[{ label: "SOC 2 / EU AI Act", href: "/reports" }, { label: "Risk Register", href: "/risk-register" }, { label: "SLA Dashboard", href: "/sla" }, { label: "Audit Trail", href: "/audit" }].map(l => <li key={l.label}><Link href={l.href} className="text-white/40 hover:text-white/70 transition-colors">{l.label}</Link></li>)}</ul>
          </div>
          <div>
            <p className="font-bold text-white/60 text-xs uppercase tracking-wider mb-3">Company</p>
            <ul className="space-y-2">{[{ label: "Dashboard", href: "/dashboard" }, { label: "Settings", href: "/settings" }, { label: "Contact", href: "mailto:hello@trustledger.dev" }, { label: "Privacy", href: "/privacy" }, { label: "Terms", href: "/terms" }].map(l => <li key={l.label}><a href={l.href} className="text-white/40 hover:text-white/70 transition-colors">{l.label}</a></li>)}</ul>
          </div>
        </div>
      </div>
      <div className="max-w-6xl mx-auto mt-10 pt-6 border-t flex flex-col sm:flex-row items-center justify-between gap-3" style={{ borderColor: "rgba(255,255,255,0.14)" }}>
        <p className="text-xs text-white/40">© 2026 TrustLedger. All rights reserved.</p>
        <Link href="/status" className="flex items-center gap-1.5 text-xs text-white/40 hover:text-white/70 transition-colors"><span className="w-1.5 h-1.5 rounded-full" style={{ background: EMERALD }} />System status</Link>
      </div>
    </footer>
  );
}

// ── Page ─────────────────────────────────────────────────────────────────────

export default function LandingPage() {
  return (
    <div className="tl-landing" style={{ background: INK }}>
      <style>{`.tl-landing h1, .tl-landing h2, .tl-landing h3 { text-shadow: 0 2px 20px rgba(0,0,0,0.55); }`}</style>
      <NavBar />
      <HeroSection />
      <StackBand />
      <ProofSection />
      <PillarsSection />
      <LanguageEngineSection />
      <VulnCoverageSection />
      <CloudApiSection />
      <HowItWorksSection />
      <PipelineSection />
      <FeaturesSection />
      <ArchSection />
      <FaqSection />
      <CTASection />
      <Footer />
    </div>
  );
}
