"use client";

import Link from "next/link";
import { useEffect, useRef, useState } from "react";
import { BrandMark } from "@/components/BrandLogo";
import { contactEmail } from "@/lib/contacts";
import { LANGUAGE_ENGINES, type LanguageEngine } from "@/lib/publicCoverage";
import { SiteNav, SiteFooter } from "@/components/marketing/Site";
import { IAC_FORMATS } from "@/lib/siteContent";

/** Figures computed server-side (app/page.tsx) from the published benchmark report and the engine registries. */
export interface LandingEvidence {
  engineCommit: string;
  measuredAt: string;
  pooledTpr: number;
  pooledFpr: number;
  labelledCases: number;
  corpora: { name: string; languages: string[]; score: number }[];
  juiceDetected: number;
  juiceTotal: number;
  ruleCount: number;
  cweCount: number;
}

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
const CloudIcon = (s = 20) => iconEl(<path d="M18 10h-1.26A8 8 0 1 0 9 20h9a5 5 0 0 0 0-10z" />, s);

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
    pages: ["Dashboard", "Analytics", "Trust Score"],
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
    desc: "Ten real AST-based taint engines trace SQL injection, XSS, SSRF, buffer overflows and twenty-four other vulnerability classes from source to sink — across files, services and includes, not just within one file. The same scan flags hardcoded secrets the moment they land, and ranks every vulnerable dependency by whether your code actually reaches it.",
    bullets: [
      "Real data-flow taint engines: JS/TS, Python, Java, Kotlin, Go, C#, PHP, Ruby, Rust, C/C++ — across files in all ten",
      "28 vulnerability classes, each with a source-to-sink trace and the exact sink argument",
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


/** The ten engines, as described in lib/publicCoverage.ts (shared with the docs). */
type LangEngine = LanguageEngine;
const LANGUAGES: LangEngine[] = LANGUAGE_ENGINES;

const FAQS = [
  { q: "Do I need to change my CI pipeline?", a: "No. TrustLedger installs as a GitHub App — GitLab and Bitbucket are supported too — and scans every pull request automatically, with no config files and no CI changes. If you'd rather drive it yourself, scans can also be submitted through the REST API." },
  { q: "Which languages and frameworks are covered?", a: "Ten languages have their own AST parser and taint engine: TypeScript/JavaScript, Python, Java, Kotlin, Go, C#, PHP, Ruby, Rust and C/C++ (which also checks memory safety: use-after-free, double free, unchecked allocations, buffer overflows), tuned to frameworks such as Express, NestJS, Flask, FastAPI, Spring, Ktor, ASP.NET, Laravel, Rails, Axum, Actix and Rocket. Infrastructure checks cover Terraform, CloudFormation, ARM, Bicep, Serverless, Kubernetes, Helm, Docker and OpenAPI." },
  { q: "How is this different from a regex-based scanner?", a: "A vulnerability is reported only when an attacker-controlled value is traced to a real sink — through assignments, branches, helper functions and other files — and a sanitizer clears only the vulnerability classes it actually neutralizes. Every finding ships with its source-to-sink trace, so reviewers can check it in seconds." },
  { q: "What does AI provenance measure?", a: "47 signals across code structure, git history and behavior estimate how much of each file is AI-generated and attribute it to the tool that wrote it — Copilot, Cursor, Claude, Windsurf and more — and flag tools that aren't on your approved list." },
  { q: "Can it block a merge?", a: "Yes. Policy gates hold a pull request until the required fixes or a named reviewer's attestation are recorded, and the result is posted back to the PR as a check run." },
  { q: "Does it help with compliance?", a: "Attestations, exceptions and findings land in an immutable audit trail and export as signed evidence packages mapped to SOC 2, the EU AI Act and PCI-DSS, along with SBOMs in SPDX and CycloneDX." },
];


const WHY_ROWS = [
  { vs: "Point tools (one per risk type)", them: "A SAST tool for vulnerabilities, a separate secrets scanner, an SCA tool, an IaC scanner, an API inventory, and no visibility into what's actually AI-generated — a dashboard and an audit trail for each, nothing reconciled.", us: "One platform: vulnerabilities, secrets, dependencies, cloud and container config, API auth coverage, and AI provenance scored together on every PR, with one policy engine and one audit trail behind all of it.", accent: CYAN },
  { vs: "SCA that lists every CVE", them: "Every CVE in every declared package, sorted by CVSS — including packages nothing imports and functions nothing calls. Teams learn to ignore the list.", us: "Each vulnerable package is ranked by reachability: the vulnerable function called from a route, imported from reachable code, imported only by tests, or never imported — with the file and line as evidence.", accent: AMBER },
  { vs: "Regex-based scanners", them: "Match a pattern on one line. No concept of whether the value is actually attacker-controlled, whether it was sanitized first, or whether it even reaches a sink.", us: "Real data-flow: a bitmask of sink classes carried from source to sink, cleared only by a sanitizer that actually neutralizes that class.", accent: ROSE },
  { vs: "Manual review + spreadsheets", them: "Reviewers eyeball the diff, chase compliance evidence by hand, and track AI tool usage — if at all — in a doc that's out of date by Friday.", us: "Every PR gets a risk score, a named attestation, and an audit-ready trail. Shadow AI usage, policy exceptions, and SLA breaches live in one system that's always current.", accent: AMBER },
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

// ── Hero visual: what a pull request gets ───────────────────────────────────

/** An illustrative pull-request check (labelled as an example on the card): the signals, the files and the gate. */
const PR_SIGNALS = [
  { label: "AI-generated", value: "62%", tone: VIOLET },
  { label: "Vulnerabilities traced", value: "2", tone: ROSE },
  { label: "Secrets", value: "1", tone: AMBER },
  { label: "Reachable deps", value: "3", tone: CYAN },
];
const PR_FILES = [
  { file: "src/billing/export.ts", risk: "CRITICAL", tone: ROSE, note: "SQL injection traced across 2 files", state: "needs sign-off" },
  { file: "src/auth/session.ts", risk: "HIGH", tone: AMBER, note: "78% AI-generated · Cursor", state: "needs sign-off" },
  { file: "src/ui/Table.tsx", risk: "LOW", tone: EMERALD, note: "No findings", state: "clear" },
];

function PrCheckVisual() {
  return (
    <div className="relative">
      <div className="absolute -inset-6 rounded-[2rem] blur-3xl pointer-events-none" style={{ background: `linear-gradient(135deg, ${CYAN}26, ${VIOLET}1f, ${ROSE}1a)` }} />
      <div className="relative rounded-2xl overflow-hidden border text-left" style={{ borderColor: "rgba(255,255,255,0.13)", background: "linear-gradient(180deg, rgba(10,15,28,0.94), rgba(6,10,18,0.97))", boxShadow: "0 40px 100px rgba(0,0,0,0.6)" }}>
        <div className="px-4 py-2.5 flex items-center gap-2 border-b" style={{ borderColor: "rgba(255,255,255,0.09)", background: "rgba(255,255,255,0.035)" }}>
          <div className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-full" style={{ background: `${ROSE}80` }} />
            <span className="w-2.5 h-2.5 rounded-full" style={{ background: `${AMBER}80` }} />
            <span className="w-2.5 h-2.5 rounded-full" style={{ background: `${EMERALD}80` }} />
          </div>
          <span className="text-[11px] font-mono font-semibold ml-2 text-white/70">TrustLedger check · pull request</span>
          <span className="ml-auto text-[10px] font-mono text-white/40">illustrative example</span>
        </div>
        <div className="p-5 sm:p-6 space-y-5">
          <div className="flex items-start justify-between gap-4">
            <div className="min-w-0">
              <p className="text-white/90 font-bold truncate">Add CSV export to billing</p>
              <p className="text-[11.5px] font-mono text-white/45 mt-0.5 truncate">#482 · feature/billing-export · 14 files</p>
            </div>
            <div className="shrink-0 text-right">
              <p className="text-[10px] font-bold uppercase tracking-wider font-mono" style={{ color: ROSE }}>Risk · High</p>
              <p className="text-3xl font-black font-mono leading-none mt-0.5" style={{ color: ROSE }}>74</p>
            </div>
          </div>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
            {PR_SIGNALS.map(sg => (
              <div key={sg.label} className="rounded-xl border px-3 py-2.5" style={{ borderColor: `${sg.tone}33`, background: `${sg.tone}0f` }}>
                <p className="text-xl font-black font-mono leading-none" style={{ color: sg.tone }}>{sg.value}</p>
                <p className="text-[10.5px] text-white/55 mt-1.5 leading-tight">{sg.label}</p>
              </div>
            ))}
          </div>
          <ul className="space-y-2">
            {PR_FILES.map(f => (
              <li key={f.file} className="flex items-center gap-3 rounded-xl border px-3 py-2.5" style={{ borderColor: "rgba(255,255,255,0.08)", background: "rgba(255,255,255,0.025)" }}>
                <span className="text-[9px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded font-mono shrink-0" style={{ color: f.tone, background: `${f.tone}1a` }}>{f.risk}</span>
                <div className="min-w-0 flex-1">
                  <p className="text-[12.5px] font-mono text-white/85 truncate">{f.file}</p>
                  <p className="text-[11px] text-white/45 truncate">{f.note}</p>
                </div>
                <span className="text-[10.5px] font-mono shrink-0" style={{ color: f.state === "clear" ? EMERALD : "rgba(255,255,255,0.5)" }}>{f.state}</span>
              </li>
            ))}
          </ul>
          <div className="rounded-xl border px-4 py-3 flex items-center gap-3" style={{ borderColor: `${ROSE}44`, background: `${ROSE}12` }}>
            <span className="w-2 h-2 rounded-full shrink-0" style={{ background: ROSE, boxShadow: `0 0 10px ${ROSE}` }} />
            <p className="text-[12.5px] text-white/80"><strong className="text-white">Merge held</strong> until the 2 flagged files are signed off by a named reviewer.</p>
          </div>
        </div>
      </div>
      <p className="relative text-center text-[10.5px] font-mono text-white/45 mt-3">An example of one pull request check · <Link href="/demo" className="underline underline-offset-2 text-white/70">scan a sample app yourself</Link></p>
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

function HeroSection({ evidence }: { evidence: LandingEvidence }) {
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
            Every pull request scored for AI-generated code, real vulnerabilities traced across files in ten languages, leaked secrets, reachable vulnerable dependencies and cloud misconfigurations — and held until a named reviewer signs off.
          </p>
          <div className="flex flex-col sm:flex-row items-center justify-center lg:justify-start gap-3 pt-1">
            <Link href="/demo" className="flex items-center gap-2 px-6 py-3.5 rounded-xl font-bold text-sm transition-all active:scale-[0.98] text-[#050810]"
              style={{ background: `linear-gradient(135deg, #67e8f9, ${CYAN})`, boxShadow: `0 6px 32px ${CYAN}66` }}
              onMouseEnter={e => { const el = e.currentTarget as HTMLElement; el.style.transform = "translateY(-2px)"; el.style.boxShadow = `0 10px 40px ${CYAN}88`; }}
              onMouseLeave={e => { const el = e.currentTarget as HTMLElement; el.style.transform = "translateY(0)"; el.style.boxShadow = `0 6px 32px ${CYAN}66`; }}>
              Try the live demo <ArrowRightIcon size={15} />
            </Link>
            <Link href="/login?mode=signup" className="flex items-center gap-2 px-6 py-3.5 rounded-xl text-white/80 font-semibold text-sm transition-all border hover:text-white/95"
              style={{ borderColor: "rgba(255,255,255,0.18)", background: "rgba(255,255,255,0.06)" }}
              onMouseEnter={e => { (e.currentTarget as HTMLElement).style.borderColor = "rgba(255,255,255,0.32)"; (e.currentTarget as HTMLElement).style.background = "rgba(255,255,255,0.09)"; }}
              onMouseLeave={e => { (e.currentTarget as HTMLElement).style.borderColor = "rgba(255,255,255,0.18)"; (e.currentTarget as HTMLElement).style.background = "rgba(255,255,255,0.06)"; }}>
              <GitHubIcon size={15} /> Connect a repository
            </Link>
          </div>
          <p className="text-[12.5px] text-white/50">
            Measured on {evidence.labelledCases.toLocaleString()} labelled benchmark samples: {(evidence.pooledTpr * 100).toFixed(0)}% of vulnerabilities found, {(evidence.pooledFpr * 100).toFixed(1)}% of safe samples flagged. <Link href="/benchmarks" className="underline underline-offset-2 text-white/75 hover:text-white">See the full report</Link>
          </p>
          <ul className="flex flex-wrap justify-center lg:justify-start gap-x-5 gap-y-2 pt-1">
            {["Free to start — no credit card", "Installs as a GitHub App in ~2 minutes", "No CI changes or config files"].map(t => (
              <li key={t} className="flex items-center gap-1.5 text-[12.5px] text-white/55">
                <span style={{ color: EMERALD }}><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12" /></svg></span>{t}
              </li>
            ))}
          </ul>
        </Reveal>
        <Reveal delay={150} className="min-w-0 w-full max-w-xl mx-auto lg:max-w-none">
          <PrCheckVisual />
        </Reveal>
      </div>

      <Reveal delay={320} className="relative mt-20 w-full max-w-5xl mx-auto grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4 pt-10 border-t" style={{ borderColor: "rgba(255,255,255,0.08)" }}>
        {[{ to: LANGUAGES.length, label: "language engines" }, { to: evidence.ruleCount, label: "data-flow rules" }, { to: evidence.cweCount, label: "CWEs mapped" }, { to: 47, label: "AI-detection signals" }, { to: IAC_FORMATS.length, label: "IaC & cloud formats" }, { to: 6, label: "API languages inventoried" }].map(s => (
          <div key={s.label} className="text-center">
            <p className="text-3xl font-black font-mono" style={{ color: "#67e8f9", textShadow: `0 0 24px ${CYAN}88` }}><CountUp to={s.to} /></p>
            <p className="text-[11px] text-white/50 font-medium mt-1">{s.label}</p>
          </div>
        ))}
      </Reveal>
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
          <h2 className="text-4xl font-black text-white mt-4 tracking-tight">Everything on a pull request, in one place</h2>
          <p className="text-white/60 mt-3 max-w-2xl mx-auto text-lg">Six areas, one scan: pick a tab to see what each one covers.</p>
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
        <div key={p.id} className="grid md:grid-cols-5 gap-8 p-6 sm:p-9 mt-8 rounded-3xl border" style={{ animation: "fadeSlideIn 0.4s cubic-bezier(0.16,1,0.3,1)", borderColor: `${p.color}38`, background: `radial-gradient(ellipse 80% 70% at 0% 0%, ${p.color}14, transparent 70%), rgba(255,255,255,0.025)`, boxShadow: `inset 0 1px 0 ${p.color}40, 0 24px 60px rgba(0,0,0,0.3)` }}>
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



// ── Cloud & API coverage, generated from the live rule catalog ──────────────





// ── FeaturesSection ──────────────────────────────────────────────────────────





// ── HowItWorksSection ────────────────────────────────────────────────────────

function HowItWorksSection() {
  return (
    <section id="how-it-works" className="py-24 px-5" style={{ background: `radial-gradient(ellipse 70% 50% at 50% 0%, ${EMERALD}0c, transparent 65%), ${INK}` }}>
      <div className="max-w-6xl mx-auto">
        <Reveal className="text-center mb-14">
          <Eyebrow>How it works</Eyebrow>
          <h2 className="text-4xl font-black text-white mt-4 tracking-tight">Up and running in 5 minutes</h2>
          <p className="text-white/60 mt-3 text-lg">No CI/CD changes. No config files. Install once and every PR is scanned automatically.</p>
        </Reveal>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
          {STEPS.map((s, i) => (
            <Reveal key={s.n} delay={i * 90}>
              <div className="relative h-full p-6 pt-7 rounded-2xl border text-center" style={{ borderColor: "rgba(255,255,255,0.12)", background: "rgba(255,255,255,0.04)", boxShadow: "inset 0 1px 0 rgba(255,255,255,0.06)" }}>
                <div className="mx-auto w-12 h-12 rounded-2xl flex items-center justify-center font-black text-lg text-[#050810]" style={{ background: `linear-gradient(135deg, #67e8f9, ${CYAN})`, boxShadow: `0 6px 24px ${CYAN}55` }}>{s.n}</div>
                <h3 className="font-bold text-white text-lg mt-4 mb-2">{s.title}</h3>
                <p className="text-sm text-white/65 leading-relaxed">{s.desc}</p>
              </div>
            </Reveal>
          ))}
        </div>
        <Reveal delay={260} className="mt-8 text-center">
          <p className="text-[13px] text-white/55">Prefer to drive it yourself? Scans can also be submitted through the <Link href="/docs/api" className="underline underline-offset-4 text-white/75">REST API</Link>.</p>
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
          <Link href="/demo" className="flex items-center gap-2 px-8 py-4 rounded-xl font-bold transition-all active:scale-[0.98] text-[#050810]"
            style={{ background: `linear-gradient(135deg, #67e8f9, ${CYAN})`, boxShadow: `0 6px 32px ${CYAN}66` }}
            onMouseEnter={e => { const el = e.currentTarget as HTMLElement; el.style.transform = "translateY(-2px)"; el.style.boxShadow = `0 10px 40px ${CYAN}88`; }}
            onMouseLeave={e => { const el = e.currentTarget as HTMLElement; el.style.transform = "translateY(0)"; el.style.boxShadow = `0 6px 32px ${CYAN}66`; }}>
            Try the live demo <ArrowRightIcon />
          </Link>
          <Link href="/login?mode=signup" className="flex items-center gap-2 px-8 py-4 rounded-xl text-white/75 font-semibold transition-all border hover:text-white/90" style={{ borderColor: "rgba(255,255,255,0.18)", background: "rgba(255,255,255,0.06)" }}>
            Connect a repository
          </Link>
        </div>
        <p className="text-[13px] text-white/50 max-w-xl mx-auto">Connecting asks for read access to pull requests and code, and write access to checks — <Link href="/trust#permissions" className="underline underline-offset-4 text-white/70">why each permission</Link>. Free to start, no credit card.</p>
        <p className="text-sm text-white/45">Questions or pricing? <a href={`mailto:${contactEmail("sales")}`} className="font-semibold text-white/70 hover:text-white underline underline-offset-4 decoration-white/25">Talk to us</a> — {contactEmail("sales")}</p>
      </Reveal>
    </section>
  );
}




// ── Page ─────────────────────────────────────────────────────────────────────

// ── Inside the dashboard: one line per sidebar page ──────────────────────────

const DASH_GROUPS: { name: string; color: string; pages: { name: string; desc: string }[] }[] = [
  { name: "Overview", color: CYAN, pages: [
    { name: "Overview", desc: "Org health score, per-repo breakdown and what needs attention now." },
    { name: "Analytics", desc: "Scan volume, finding trends and time-to-attest." },
    { name: "TrustScore™", desc: "One blended score across attestation, policy and risk resolution." },
  ] },
  { name: "Threats", color: ORANGE, pages: [
    { name: "Threats", desc: "Policy breaches, alerts and incidents with SLA deadlines, plus threat intelligence on patterns found in your repos." },
  ] },
  { name: "Code Risk", color: ROSE, pages: [
    { name: "Scan History", desc: "Every scan, with per-file risk and source-to-sink traces." },
    { name: "Secrets", desc: "Hardcoded keys and tokens, caught as they land." },
    { name: "Dependencies", desc: "Live CVEs ranked by whether your code actually reaches them." },
    { name: "API Security", desc: "Every endpoint inventoried, and the route missing the auth its siblings have." },
  ] },
  { name: "Compliance", color: EMERALD, pages: [
    { name: "Compliance", desc: "Evidence mapped to SOC 2, the EU AI Act and PCI-DSS." },
    { name: "SLA Dashboard", desc: "What is on track, at risk or overdue." },
    { name: "Risk Register", desc: "CWE-mapped risks with assigned reviewers and deadlines." },
  ] },
  { name: "Audit", color: VIOLET, pages: [
    { name: "Audit Trail", desc: "An immutable record of every attestation, scan and override." },
    { name: "Reports", desc: "Signed evidence packages and SBOM exports (SPDX, CycloneDX)." },
    { name: "Trace", desc: "Follow any scan step by step to see why a result looks the way it does." },
    { name: "Rule Catalog", desc: "Every rule with its CWE, what it flags and how to fix it." },
  ] },
  { name: "AI Intel", color: SKY, pages: [
    { name: "Shadow AI", desc: "AI tools that are not on your approved list, confidence-scored." },
  ] },
];

/** Three columns of group cards, balanced by page count, so the section reads as a grid and not a ragged list. */
const DASH_COLUMNS = [["Overview", "Compliance"], ["Code Risk", "AI Intel"], ["Audit", "Threats"]];

function DashboardSection() {
  const byName = new Map(DASH_GROUPS.map(g => [g.name, g]));
  return (
    <section id="dashboard" className="py-24 px-5" style={{ background: `radial-gradient(ellipse 70% 45% at 50% 0%, ${CYAN}0d, transparent 65%), ${SURFACE}` }}>
      <div className="max-w-6xl mx-auto">
        <Reveal className="text-center mb-12">
          <Eyebrow>Inside the dashboard</Eyebrow>
          <h2 className="text-4xl font-black text-white mt-4 tracking-tight">Every page, in one line</h2>
          <p className="text-white/60 mt-3 max-w-xl mx-auto text-lg">What you will find in the sidebar once you connect a repository.</p>
        </Reveal>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-5 items-start">
          {DASH_COLUMNS.map((col, ci) => (
            <div key={ci} className="flex flex-col gap-5">
              {col.map(name => {
                const g = byName.get(name)!;
                return (
                  <Reveal key={g.name} delay={ci * 70}>
                    <div className="rounded-2xl border overflow-hidden" style={{ borderColor: `${g.color}33`, background: "rgba(255,255,255,0.035)", boxShadow: `inset 0 1px 0 ${g.color}40, 0 18px 40px rgba(0,0,0,0.25)` }}>
                      <div className="flex items-center gap-2.5 px-5 py-3.5 border-b" style={{ borderColor: "rgba(255,255,255,0.07)", background: `linear-gradient(90deg, ${g.color}1a, transparent)` }}>
                        <span className="w-2 h-2 rounded-full" style={{ background: g.color, boxShadow: `0 0 10px ${g.color}` }} />
                        <p className="text-[11px] font-bold uppercase tracking-widest font-mono" style={{ color: g.color }}>{g.name}</p>
                        <span className="ml-auto text-[11px] font-mono text-white/35">{g.pages.length} {g.pages.length === 1 ? "page" : "pages"}</span>
                      </div>
                      <ul className="divide-y" style={{ borderColor: "rgba(255,255,255,0.06)" }}>
                        {g.pages.map(pg => (
                          <li key={pg.name} className="px-5 py-3.5" style={{ borderColor: "rgba(255,255,255,0.06)" }}>
                            <p className="text-sm font-bold text-white">{pg.name}</p>
                            <p className="text-[13px] text-white/65 leading-snug mt-0.5">{pg.desc}</p>
                          </li>
                        ))}
                      </ul>
                    </div>
                  </Reveal>
                );
              })}
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

// ── Explore: the rest of the story lives in the site's tabs ─────────────────

const EXPLORE = [
  { href: "/demo", color: CYAN, title: "Live demo", desc: "Run the real scanner on a sample app, edit the code, and watch the walkthrough videos." },
  { href: "/benchmarks", color: EMERALD, title: "Benchmarks", desc: "Precision and recall on public labelled benchmarks, published with the failures." },
  { href: "/docs", color: VIOLET, title: "Docs", desc: "How a scan works, the ten language engines, every rule and the cloud & API checks." },
  { href: "/trust", color: AMBER, title: "Trust Center", desc: "What happens to your code, permissions, retention, subprocessors and compliance." },
];

/** A hairline between sections, so the page reads as separate chapters. */
function Divider() {
  return <div aria-hidden className="h-px w-full" style={{ background: "linear-gradient(90deg, transparent, rgba(255,255,255,0.16), transparent)" }} />;
}

function ExploreSection() {
  return (
    <section id="explore" className="py-20 px-5" style={{ background: INK }}>
      <div className="max-w-6xl mx-auto">
        <Reveal className="text-center mb-10">
          <Eyebrow>Go deeper</Eyebrow>
          <h2 className="text-3xl font-black text-white mt-4 tracking-tight">Want the details? They are one click away</h2>
        </Reveal>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {EXPLORE.map((x, i) => (
            <Reveal key={x.href} delay={i * 60}>
              <Link href={x.href} className="group block h-full p-5 rounded-2xl border transition-all duration-200 hover:-translate-y-1 hover:bg-white/[0.07]" style={{ borderColor: `${x.color}40`, background: `linear-gradient(180deg, ${x.color}14, rgba(255,255,255,0.03) 55%)`, boxShadow: `inset 0 2px 0 ${x.color}88` }}>
                <p className="font-bold text-white flex items-center gap-2" style={{ color: x.color }}>{x.title} <ArrowRightIcon size={14} /></p>
                <p className="text-[13px] text-white/65 mt-2 leading-relaxed">{x.desc}</p>
              </Link>
            </Reveal>
          ))}
        </div>
      </div>
    </section>
  );
}

// ── Page ─────────────────────────────────────────────────────────────────────

/**
 * Kept short on purpose: what it is (hero), everything it covers (the pillar tabs and a one-line list of every dashboard page), how to start, why it differs,
 * where to go deeper (the site's tabs), common questions, and the call to action. The engine internals, pipeline,
 * benchmark results, language and framework lists, and the trust details live in Docs, Benchmarks, Live demo and
 * the Trust Center.
 */
export default function LandingClient({ evidence }: { evidence: LandingEvidence }) {
  return (
    <div className="tl-landing" style={{ background: INK }}>
      <style>{`.tl-landing h1, .tl-landing h2, .tl-landing h3 { text-shadow: 0 2px 20px rgba(0,0,0,0.55); }`}</style>
      <SiteNav active="/" />
      <HeroSection evidence={evidence} />
      <Divider />
      <PillarsSection />
      <Divider />
      <DashboardSection />
      <Divider />
      <HowItWorksSection />
      <Divider />
      <ProofSection />
      <Divider />
      <ExploreSection />
      <Divider />
      <FaqSection />
      <CTASection />
      <SiteFooter />
    </div>
  );
}
