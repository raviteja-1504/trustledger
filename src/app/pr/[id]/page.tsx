"use client"; // v2

import { useEffect, useState, useMemo, Suspense } from "react";
import { createPortal } from "react-dom";
import { useParams, useSearchParams } from "next/navigation";
import Link from "next/link";
import AuthGuard from "@/components/AuthGuard";
import RiskBadge from "@/components/RiskBadge";
import ProgressBar from "@/components/ProgressBar";
import CodeViewer from "@/components/CodeViewer";
import { api } from "@/lib/api";
import { loadPolicy, evaluatePolicy, type OrgPolicy, type PolicyResult } from "@/lib/policy";
import type { FileResult, ScanResult, RiskLevel } from "@/types";
import { useAttestationsRealtime } from "@/lib/realtime";
import { authedFetch } from "@/lib/useRealData";
import { formatDateTime, useTimezone } from "@/lib/timezone";
import { useAuth } from "@/lib/auth";
import { usePresence, initials } from "@/lib/presence";
import AIAttributionBadge from "@/components/AIAttributionBadge";

// ── Signal library ────────────────────────────────────────────────────────────

type SignalSev = "critical" | "high" | "medium" | "low";

const SIGNAL_META: Record<string, { label: string; desc: string; sev: SignalSev; security?: boolean }> = {
  // ── Security vulnerabilities (shown with line numbers) ─────────────────────
  "sql-injection":           { label: "SQL Injection",             desc: "Query built with string interpolation — use parameterised queries",                          sev: "critical", security: true },
  "nosql-injection":         { label: "NoSQL Injection",           desc: "User input in MongoDB operator/query without schema validation",                             sev: "critical", security: true },
  "hardcoded-secret":        { label: "Hardcoded Secret",          desc: "API key, password, or token embedded directly in source code",                               sev: "critical", security: true },
  "eval-exec":               { label: "Eval / Exec",               desc: "Dynamic code execution via eval() or exec() — arbitrary code execution risk",                sev: "critical", security: true },
  "command-injection":       { label: "Command Injection",         desc: "User input flows into shell command — allows arbitrary OS command execution",                 sev: "critical", security: true },
  "path-traversal":          { label: "Path Traversal",            desc: "User-controlled path could escape sandbox and read/write arbitrary files",                    sev: "critical", security: true },
  "ssrf":                    { label: "SSRF",                      desc: "Server-side request forgery — user controls the URL of an outgoing request",                  sev: "critical", security: true },
  "jwt-none-alg":            { label: "JWT None Algorithm",        desc: "JWT verification may accept 'none' algorithm, bypassing signature checks",                    sev: "critical", security: true },
  "prototype-pollution":     { label: "Prototype Pollution",       desc: "Object property assignment from user input can pollute global prototype",                    sev: "high",     security: true },
  "xss":                     { label: "XSS",                       desc: "User-controlled value inserted into DOM without sanitisation",                                sev: "high",     security: true },
  "mass-assignment":         { label: "Mass Assignment",           desc: "Request body fields assigned to model without allowlist — may expose sensitive fields",        sev: "high",     security: true },
  "insecure-deserialisation":{ label: "Insecure Deserialisation",  desc: "Untrusted data deserialised without type validation",                                         sev: "high",     security: true },
  "weak-crypto":             { label: "Weak Cryptography",         desc: "Deprecated or weak algorithm (MD5, SHA1, DES) used for security-critical operation",          sev: "high",     security: true },
  "open-redirect":           { label: "Open Redirect",             desc: "User-controlled redirect target can send users to malicious sites",                           sev: "high",     security: true },
  "pii-in-logs":             { label: "PII in Logs",               desc: "Personally identifiable information may be written to logs",                                  sev: "high",     security: true },
  "idor":                    { label: "IDOR",                      desc: "Object referenced by user-supplied ID without ownership check",                               sev: "high",     security: true },
  "insecure-randomness":     { label: "Insecure Randomness",       desc: "Math.random() or weak RNG used for security tokens",                                         sev: "high",     security: true },
  "cookie-insecurity":       { label: "Insecure Cookie",          desc: "Cookie missing Secure, HttpOnly, or SameSite attribute",                                      sev: "medium",   security: true },
  "verbose-errors":          { label: "Verbose Error Exposure",    desc: "Stack traces or internal details exposed to clients",                                         sev: "medium",   security: true },
  "sensitive-data-in-url":   { label: "Sensitive Data in URL",     desc: "Credentials or tokens passed in URL query parameters (logged by proxies)",                   sev: "medium",   security: true },
  "timing-attack":           { label: "Timing Attack",             desc: "Non-constant-time comparison of secrets enables timing oracle attacks",                       sev: "medium",   security: true },
  "watermark-detection":     { label: "AI Watermark",              desc: "Invisible Unicode characters detected — AI tool may have embedded a watermark",               sev: "high",     security: true },
  "backdoor-detection":      { label: "Backdoor / Logic Bomb",     desc: "Date-gated condition, hardcoded bypass, or exfiltration pattern detected",                    sev: "critical", security: true },
  "prompt-leakage":          { label: "Prompt Leakage",            desc: "AI system prompt or instruction text may be embedded in this file",                          sev: "high",     security: true },
  "behavioral-risk":         { label: "Behavioral Risk",           desc: "Suspicious behavioral pattern (logic bomb, exfiltration, hidden channel)",                    sev: "high",     security: true },
  "supply-chain-risk":       { label: "Supply Chain Risk",         desc: "Risky or typosquatted package imports detected",                                              sev: "medium",   security: true },
  "cross-file-taint-exposure":{ label: "Cross-file Taint",        desc: "Tainted data from an imported module may reach a sensitive sink in this file",                sev: "high",     security: true },
  // ── AI detection signals (file-level, no line numbers) ───────────────────────
  "comment-phrasing":        { label: "AI Comment Phrasing",       desc: "Formulaic, instructional comment style matches AI generation signatures",                    sev: "low"  },
  "language-specific":       { label: "Language-specific Pattern", desc: "Stereotyped per-language patterns frequently produced by AI code generators",                sev: "low"  },
  "ngram-fingerprint":       { label: "Token N-gram Fingerprint",  desc: "Characteristic token sequences (e.g. 'return {success:' 'const result=await') match AI output", sev: "low" },
  "test-structure":          { label: "Uniform Test Structure",    desc: "Robotically uniform test suite layout — AI models generate repetitive test boilerplate",      sev: "low"  },
  "structural-clones":       { label: "Structural Clones",         desc: "3+ near-identical function bodies — indicates AI-generated CRUD scaffold",                   sev: "low"  },
  "lexical-diversity":       { label: "Low Lexical Diversity",     desc: "Low type-token ratio — AI reuses a small vocabulary of ~200 identifiers consistently",        sev: "low"  },
  "variable-vocabulary":     { label: "Generic Variable Names",    desc: "Generic names (result, handler, payload, data) are an AI hallmark",                          sev: "low"  },
  "sentence-identifiers":    { label: "Long Identifier Names",     desc: "4-word function names (processUserAuthentication) are a characteristic AI pattern",           sev: "low"  },
  "error-uniformity":        { label: "Uniform Error Handling",    desc: "Robotically consistent error handling across all functions",                                  sev: "low"  },
  "cyclomatic-uniformity":   { label: "Uniform Complexity",        desc: "All functions have near-identical cyclomatic complexity — AI generates identically structured code", sev: "low" },
  "doc-coverage":            { label: "Full Doc Coverage",         desc: "Every function documented — AI documents all; humans skip obvious ones",                      sev: "low"  },
  "structural-repetition":   { label: "Structural Repetition",     desc: "Try/catch boilerplate repeated in every function",                                           sev: "low"  },
  "function-size":           { label: "Uniform Function Size",     desc: "Suspiciously same-sized functions — AI generates to a target line count",                    sev: "low"  },
  "comment-density":         { label: "High Comment Density",      desc: "AI comments every block; senior developers comment sparingly",                               sev: "low"  },
  "method-chain-density":    { label: "Method Chain Density",      desc: "AI prefers fluent method chains; humans use intermediate variables",                         sev: "low"  },
  "structured-logging":      { label: "Structured Logging",        desc: "AI uses structured context objects in every log call",                                       sev: "low"  },
  "guard-clause-density":    { label: "Guard Clause Density",      desc: "AI applies early-return guards mechanically to every function",                              sev: "low"  },
  "exhaustive-switches":     { label: "Exhaustive Switches",       desc: "AI adds default cases to all switch statements",                                            sev: "low"  },
  "exception-specificity":   { label: "Specific Exceptions",       desc: "Specific exception types in every catch block — AI pattern",                                sev: "low"  },
  "magic-number-absence":    { label: "No Magic Numbers",          desc: "AI names all constants; human developers sometimes inline them",                            sev: "low"  },
  "boilerplate":             { label: "Boilerplate Density",       desc: "Repetitive template patterns characteristic of AI scaffolding",                             sev: "low"  },
  "error-message-phrasing":  { label: "AI Error Messages",         desc: "'Invalid X', 'X is required', 'Failed to X' — formulaic AI error templates",               sev: "low"  },
  "identifier-length":       { label: "Uniform Identifier Length", desc: "No short loop variables (i, j) — AI avoids brevity",                                       sev: "low"  },
  "token-frequency":         { label: "Token Frequency Profile",   desc: "await/const/interface surplus vs var/this/prototype matches AI output distribution",        sev: "low"  },
  "hallucinated-api":        { label: "Hallucinated API",          desc: "Non-existent method calls (validateAndSave, Array.isEmpty) — AI hallucination",             sev: "medium" },
  "copy-paste-pattern":      { label: "Copy-paste Pattern",        desc: "Verbatim StackOverflow or tutorial implementation",                                         sev: "low"  },
  "style-drift":             { label: "Style Drift",               desc: "AI-signal density jumps sharply mid-file — partial AI insertion",                          sev: "low"  },
  "async-consistency":       { label: "Async Consistency",         desc: "Modern async/await used throughout — consistent with AI output",                            sev: "low"  },
  "functional-preference":   { label: "Functional Style",          desc: "Consistent use of map/filter/reduce over loops — AI preference",                           sev: "low"  },
  "template-literals":       { label: "Template Literals",         desc: "Exclusive template literal usage — modern style AI consistently applies",                   sev: "low"  },
  "naming-consistency":      { label: "Naming Consistency",        desc: "Perfectly consistent camelCase/snake_case — AI enforces style rules uniformly",             sev: "low"  },
  "import-organization":     { label: "Organised Imports",         desc: "Imports grouped and ordered — AI applies this consistently, humans vary",                   sev: "low"  },
  "dead-code-absence":       { label: "No Dead Code",              desc: "No unused variables or imports — AI avoids them; humans accumulate them",                   sev: "low"  },
  "async-try-catch":         { label: "Async Try-catch",           desc: "Every async function wrapped in try/catch — AI best-practice adherence",                   sev: "low"  },
  "immutable-preference":    { label: "Immutable Preference",      desc: "Consistent const usage — AI prefers immutability",                                         sev: "low"  },
  "type-guards":             { label: "Type Guards",               desc: "TypeScript type guards applied systematically — AI follows strict-mode patterns",           sev: "low"  },
  "return-types":            { label: "Return Type Annotations",   desc: "Every function has explicit return type — AI strict-mode output",                          sev: "low"  },
  "verb-prefix":             { label: "Verb Prefix Naming",        desc: "All functions prefixed with verb (get, set, handle) — AI naming convention",               sev: "low"  },
  "destructuring-density":   { label: "Object Destructuring",      desc: "Consistent destructuring — modern JS pattern AI applies everywhere",                       sev: "low"  },
  "line-length":             { label: "Line Length Uniformity",    desc: "Very uniform line lengths — Prettier-formatted AI output",                                 sev: "low"  },
  "default-params":          { label: "Default Parameters",        desc: "Default parameter values used consistently — AI best practice",                            sev: "low"  },
  "arrow-consistency":       { label: "Arrow Functions",           desc: "Consistent arrow function style throughout — AI modern JS preference",                     sev: "low"  },
  "blank-line-regularity":   { label: "Blank Line Regularity",     desc: "Max 1 blank line between blocks, perfect regularity — AI formatting signature",            sev: "low"  },
  "nesting-depth":           { label: "Shallow Nesting",           desc: "Shallow nesting depth throughout — AI applies early-exit patterns",                        sev: "low"  },
  "ai-model-attribution":    { label: "AI Model Attribution",      desc: "Specific AI tool detected from style fingerprints",                                        sev: "low"  },
  "ai-comment-pattern":      { label: "AI Comment Pattern",        desc: "Comment verbosity and style strongly match AI generation signatures",                      sev: "low"  },
  "structural-uniformity":   { label: "Structural Uniformity",     desc: "Code blocks show unusually uniform structure — AI copy-paste without human variation",     sev: "low"  },
  "identifier-entropy":      { label: "Low Identifier Entropy",    desc: "Generic, predictable naming — AI tends toward low-entropy identifiers",                    sev: "low"  },
};

const SEV_COLORS: Record<SignalSev, { badge: string; dot: string }> = {
  critical: { badge: "bg-violet-100 text-violet-800 ring-violet-300", dot: "bg-violet-500" },
  high:     { badge: "bg-orange-100 text-orange-800 ring-orange-300", dot: "bg-orange-500" },
  medium:   { badge: "bg-amber-100 text-amber-800 ring-amber-300",    dot: "bg-amber-400"  },
  low:      { badge: "bg-sky-100 text-sky-700 ring-sky-200",          dot: "bg-sky-400"    },
};

// ── Helpers ───────────────────────────────────────────────────────────────────

const LANG_COLORS: Record<string, string> = {
  python:     "bg-blue-50 text-blue-700 ring-blue-100",
  javascript: "bg-yellow-50 text-yellow-700 ring-yellow-100",
  typescript: "bg-blue-50 text-blue-600 ring-blue-100",
  go:         "bg-cyan-50 text-cyan-700 ring-cyan-100",
  java:       "bg-orange-50 text-orange-700 ring-orange-100",
  rust:       "bg-red-50 text-red-700 ring-red-100",
  cpp:        "bg-violet-50 text-violet-700 ring-violet-100",
};

function riskOrder(r: RiskLevel): number {
  return ({ CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0 } as const)[r] ?? 0;
}

// ── Icons ─────────────────────────────────────────────────────────────────────

function ShieldIcon({ size = 14 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      <polyline points="9 12 11 14 15 10" />
    </svg>
  );
}

function SpinnerIcon() {
  return (
    <svg className="animate-spin w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
      <path d="M21 12a9 9 0 1 1-6.219-8.56" />
    </svg>
  );
}

function AlertTriIcon({ size = 15 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
      <line x1="12" y1="9" x2="12" y2="13" /><line x1="12" y1="17" x2="12.01" y2="17" />
    </svg>
  );
}

function CheckCircleIcon({ size = 15 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10" /><polyline points="9 12 11 14 15 10" />
    </svg>
  );
}

function UserIcon() {
  return (
    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" /><circle cx="12" cy="7" r="4" />
    </svg>
  );
}

function PencilIcon() {
  return (
    <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7" />
      <path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z" />
    </svg>
  );
}

// ── Reviewer Bar ──────────────────────────────────────────────────────────────

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
function isValidEmail(email: string): boolean {
  return EMAIL_RE.test(email);
}

function ReviewerBar({ email, github, onSave }: {
  email: string; github: string; onSave: (e: string, g: string) => void;
}) {
  const [editing, setEditing]   = useState(!email);
  const [draftEmail,  setDE]    = useState(email);
  const [draftGithub, setDG]    = useState(github);

  useEffect(() => { setDE(email); setDG(github); }, [email, github]);

  if (!editing) {
    return (
      <div className="flex items-center gap-3 px-4 py-2.5 bg-indigo-50/70 border border-indigo-100 rounded-xl">
        <div className="w-7 h-7 rounded-full bg-indigo-100 flex items-center justify-center text-indigo-600 shrink-0">
          <UserIcon />
        </div>
        <div className="flex-1 min-w-0">
          <span className="text-xs font-semibold text-indigo-800">{email}</span>
          <span className="text-xs text-indigo-400 ml-2">· @{github}</span>
        </div>
        <span className="text-[10px] text-indigo-400 hidden sm:block">Reviewer identity for attestations</span>
        <button
          onClick={() => setEditing(true)}
          className="flex items-center gap-1.5 text-[11px] font-semibold text-indigo-500 hover:text-indigo-700 px-2.5 py-1.5 rounded-lg hover:bg-indigo-100 transition-colors shrink-0"
        >
          <PencilIcon /> Edit
        </button>
      </div>
    );
  }

  return (
    <div className="flex flex-col sm:flex-row items-start sm:items-center gap-2.5 px-4 py-3 bg-amber-50 border border-amber-200 rounded-xl">
      <div className="flex items-center gap-1.5 text-xs font-semibold text-amber-800 shrink-0">
        <UserIcon />
        Set reviewer to attest:
      </div>
      <div className="flex flex-1 items-center gap-2 flex-wrap">
        <input
          type="email"
          placeholder="reviewer@company.com"
          value={draftEmail}
          onChange={e => setDE(e.target.value)}
          className="flex-1 min-w-[160px] text-xs border border-amber-200 bg-white rounded-lg px-2.5 py-1.5 focus:outline-none focus:ring-2 focus:ring-amber-400"
        />
        <input
          type="text"
          placeholder="github-username"
          value={draftGithub}
          onChange={e => setDG(e.target.value)}
          className="w-36 text-xs border border-amber-200 bg-white rounded-lg px-2.5 py-1.5 focus:outline-none focus:ring-2 focus:ring-amber-400"
        />
        <button
          disabled={!isValidEmail(draftEmail) || !draftGithub}
          onClick={() => { onSave(draftEmail, draftGithub); setEditing(false); }}
          className="px-3.5 py-1.5 text-xs font-bold bg-amber-500 text-white rounded-lg disabled:opacity-40 hover:bg-amber-600 transition-colors"
        >
          Save
        </button>
        {draftEmail && !isValidEmail(draftEmail) && (
          <span className="text-[11px] text-rose-600 w-full">Enter a valid email address (e.g. you@company.com)</span>
        )}
      </div>
    </div>
  );
}

// ── Attest Review Modal ───────────────────────────────────────────────────────

function AttestReviewModal({ file, reviewerEmail, onConfirm, onClose }: {
  file: FileResult;
  reviewerEmail: string;
  onConfirm: () => Promise<void>;
  onClose: () => void;
}) {
  const [attesting, setAttesting] = useState(false);
  const [mounted, setMounted] = useState(false);

  useEffect(() => { setMounted(true); }, []);

  async function handleConfirm() {
    setAttesting(true);
    try { await onConfirm(); } finally { setAttesting(false); }
  }

  if (!mounted) return null;

  return createPortal(
    <>
      <div className="fixed inset-0 z-40 bg-black/50 backdrop-blur-sm" onClick={onClose} />
      <div className="fixed right-0 top-0 z-50 h-screen w-full max-w-2xl bg-white shadow-2xl flex flex-col overflow-hidden">

        {/* Header */}
        <div className="shrink-0 px-6 pt-5 pb-4 border-b border-gray-100 flex items-center justify-between gap-3">
          <div className="flex items-center gap-3 min-w-0">
            <div className="w-9 h-9 shrink-0 rounded-xl bg-gradient-to-br from-indigo-500 to-violet-600 flex items-center justify-center text-white shadow-md shadow-indigo-200">
              <ShieldIcon size={16} />
            </div>
            <div className="min-w-0">
              <h2 className="text-sm font-black text-gray-900">Review & Attest</h2>
              <p className="text-[11px] text-gray-400 mt-0.5 font-mono truncate">{file.file_path}</p>
            </div>
          </div>
          <button onClick={onClose} className="w-8 h-8 shrink-0 rounded-lg flex items-center justify-center text-gray-400 hover:text-gray-600 hover:bg-gray-100 transition-colors">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
              <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
            </svg>
          </button>
        </div>

        {/* Body */}
        <div className="flex-1 min-h-0 overflow-y-auto px-6 py-5 space-y-5">

          {/* Source code — first so it's immediately visible */}
          <div>
            <p className="text-[10px] font-bold uppercase tracking-wider text-gray-400 mb-2">
              Source Code
              {file.risk_indicators.length > 0 && (
                <span className="ml-2 normal-case font-normal text-gray-500">(risky lines highlighted)</span>
              )}
            </p>
            {file.content ? (
              <CodeViewer
                code={file.content}
                language={file.language}
                filename={file.file_path}
                riskIndicators={file.risk_indicators}
              />
            ) : (
              <div className="flex items-center gap-3 bg-gray-50 border border-dashed border-gray-200 rounded-xl px-4 py-4">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#9ca3af" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/>
                  <polyline points="14 2 14 8 20 8"/>
                </svg>
                <div>
                  <p className="text-xs font-semibold text-gray-600">Source not available</p>
                  <p className="text-[11px] text-gray-400 mt-0.5">Re-submit this scan with file content to enable inline code review.</p>
                </div>
              </div>
            )}
          </div>

          {/* Meta */}
          <div className="flex flex-wrap items-start gap-5 pt-1">
            <div>
              <p className="text-[10px] font-bold uppercase tracking-wider text-gray-400 mb-1.5">Language</p>
              <span className={`text-[10px] font-bold px-2 py-0.5 rounded-md ring-1 ${LANG_COLORS[file.language?.toLowerCase() ?? ""] ?? "bg-gray-50 text-gray-600 ring-gray-100"}`}>
                {file.language ?? "unknown"}
              </span>
            </div>
            <div>
              <p className="text-[10px] font-bold uppercase tracking-wider text-gray-400 mb-1.5">AI Content</p>
              <div className="flex items-center gap-2">
                <div className="w-28"><ProgressBar value={file.ai_percentage} mode="ai" height="h-2" /></div>
                <span className="text-sm font-black text-gray-800 tabular-nums">{(file.ai_percentage * 100).toFixed(1)}%</span>
              </div>
            </div>
            <div>
              <p className="text-[10px] font-bold uppercase tracking-wider text-gray-400 mb-1.5">Risk</p>
              <RiskBadge level={file.risk_score} />
            </div>
            {reviewerEmail && (
              <div>
                <p className="text-[10px] font-bold uppercase tracking-wider text-gray-400 mb-1.5">Reviewer</p>
                <span className="text-xs font-semibold text-indigo-700">{reviewerEmail}</span>
              </div>
            )}
          </div>

          {/* Signals — split into security vulnerabilities and AI detection */}
          {file.risk_indicators.length > 0 && (() => {
            const securitySigs = file.risk_indicators.filter(s => SIGNAL_META[s]?.security);
            const aiSigs       = file.risk_indicators.filter(s => !SIGNAL_META[s]?.security);

            const renderSignal = (sig: string) => {
              const meta = SIGNAL_META[sig] ?? { label: sig, desc: "Detection signal", sev: "low" as SignalSev };
              const { badge, dot } = SEV_COLORS[meta.sev];
              const instances = (file.indicators ?? []).filter(i => i.id === sig);
              const lines = instances.map(i => i.line).filter((l): l is number => typeof l === "number");
              const detail = instances[0]?.detail;
              const isSec = !!meta.security;
              return (
                <div key={sig} className={`flex items-start gap-3 rounded-xl border p-3 ${
                  isSec && meta.sev === "critical" ? "bg-rose-50 border-rose-200"
                  : isSec && meta.sev === "high"   ? "bg-orange-50 border-orange-200"
                  : isSec && meta.sev === "medium"  ? "bg-amber-50 border-amber-200"
                  : "bg-gray-50 border-gray-100"}`}>
                  <div className={`w-1.5 h-1.5 rounded-full shrink-0 mt-1.5 ${dot}`} />
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2 mb-0.5 flex-wrap">
                      <p className="text-xs font-bold text-gray-900">{meta.label}</p>
                      <span className={`text-[10px] font-bold px-1.5 py-px rounded-md ring-1 uppercase ${badge}`}>{meta.sev}</span>
                      {lines.length > 0 && (
                        <span className="ml-auto text-[10px] font-bold text-gray-600 bg-white border border-gray-200 px-2 py-px rounded-md font-mono">
                          {lines.length === 1 ? `Line ${lines[0]}` : `Lines ${lines.slice(0, 3).join(", ")}${lines.length > 3 ? ` +${lines.length - 3}` : ""}`}
                        </span>
                      )}
                    </div>
                    <p className="text-[11px] text-gray-500 leading-relaxed">{meta.desc}</p>
                    {detail && (
                      <p className="text-[10px] font-mono text-rose-700 bg-rose-50 border border-rose-100 rounded-md px-2 py-1 mt-1.5 truncate" title={detail}>
                        {detail}
                      </p>
                    )}
                  </div>
                </div>
              );
            };

            return (
              <div className="space-y-4">
                {/* Security vulnerabilities */}
                {securitySigs.length > 0 && (
                  <div>
                    <p className="text-[10px] font-bold uppercase tracking-wider text-rose-500 mb-2">
                      Security Vulnerabilities ({securitySigs.length})
                    </p>
                    <div className="space-y-2">{securitySigs.map(renderSignal)}</div>
                  </div>
                )}
                {/* AI detection signals */}
                {aiSigs.length > 0 && (
                  <div>
                    <p className="text-[10px] font-bold uppercase tracking-wider text-gray-400 mb-2">
                      AI Detection Signals ({aiSigs.length})
                    </p>
                    <div className="space-y-1.5">{aiSigs.map(renderSignal)}</div>
                  </div>
                )}
              </div>
            );
          })()}
        </div>

        {/* Footer */}
        <div className="shrink-0 px-6 py-4 border-t border-gray-100 bg-gray-50/60">
          <div className="flex items-center justify-between gap-3">
            <p className="text-xs text-gray-400">
              Review the code above, then confirm. This action is logged in the audit trail.
            </p>
            <div className="flex items-center gap-2 shrink-0">
              <button onClick={onClose} disabled={attesting} className="px-4 py-2 text-sm font-semibold text-gray-500 rounded-xl hover:bg-gray-100 transition-colors disabled:opacity-40">
                Cancel
              </button>
              <button
                onClick={handleConfirm}
                disabled={attesting}
                className="inline-flex items-center gap-2 px-5 py-2 text-sm font-bold bg-gradient-to-r from-indigo-600 to-violet-600 text-white rounded-xl hover:from-indigo-700 hover:to-violet-700 disabled:opacity-40 shadow-md shadow-indigo-200 transition-all active:scale-[0.98]"
              >
                {attesting ? <><SpinnerIcon /> Attesting…</> : <><ShieldIcon size={13} /> Confirm Attestation</>}
              </button>
            </div>
          </div>
        </div>
      </div>
    </>,
    document.body
  );
}

// ── File Row ──────────────────────────────────────────────────────────────────

function FileRow({ file, reviewerEmail, reviewerGithub, onRequestAttest }: {
  file: FileResult;
  reviewerEmail: string;
  reviewerGithub: string;
  onRequestAttest: (f: FileResult) => void;
}) {
  const [attested,  setAttested]  = useState(file.attested);
  const [expanded,  setExpanded]  = useState(false);

  // Keep attested in sync when parent marks the file via attestedSet
  useEffect(() => { setAttested(file.attested); }, [file.attested]);

  const isHigh      = file.risk_score === "HIGH" || file.risk_score === "CRITICAL";
  const needsAttest = !attested && isHigh;

  const fileShort = file.file_path.split("/").slice(-1)[0];
  const fileDir   = file.file_path.includes("/")
    ? file.file_path.split("/").slice(0, -1).join("/") + "/"
    : "";

  const rowBg = attested
    ? "bg-emerald-50/20"
    : isHigh
      ? "bg-rose-50/25"
      : "";

  return (
    <>
      {/* ── Main row ── */}
      <tr
        className={`transition-colors cursor-pointer hover:bg-indigo-50/30 ${rowBg} ${expanded ? "!bg-indigo-50/40" : ""}`}
        onClick={() => setExpanded(v => !v)}
      >
        {/* File path */}
        <td className="px-4 py-3.5 pl-5">
          <div className="flex items-start gap-2 min-w-0">
            <span className={`text-gray-400 mt-0.5 shrink-0 transition-transform duration-150 inline-block ${expanded ? "rotate-90" : ""}`}>›</span>
            <div className="min-w-0">
              {fileDir && <span className="text-[10px] text-gray-400 font-mono block truncate leading-tight">{fileDir}</span>}
              <span className="font-mono text-xs font-semibold text-gray-900 break-all">{fileShort}</span>
            </div>
          </div>
        </td>

        {/* Language */}
        <td className="px-3 py-3.5 hidden sm:table-cell">
          {file.language && (
            <span className={`text-[10px] font-bold px-2 py-0.5 rounded-md ring-1 ${LANG_COLORS[file.language?.toLowerCase()] ?? "bg-gray-50 text-gray-600 ring-gray-100"}`}>
              {file.language}
            </span>
          )}
        </td>

        {/* AI % */}
        <td className="px-4 py-3.5 min-w-[120px]">
          <ProgressBar value={file.ai_percentage} mode="ai" />
        </td>

        {/* Risk */}
        <td className="px-3 py-3.5">
          <RiskBadge level={file.risk_score} />
        </td>

        {/* Signals */}
        <td className="px-3 py-3.5 hidden md:table-cell">
          {file.risk_indicators.length > 0 ? (
            <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-indigo-600 bg-indigo-50 px-2 py-0.5 rounded-full ring-1 ring-indigo-100">
              {file.risk_indicators.length} signal{file.risk_indicators.length !== 1 ? "s" : ""}
            </span>
          ) : (
            <span className="text-gray-300 text-xs">—</span>
          )}
        </td>

        {/* Status */}
        <td className="px-3 py-3.5">
          {attested ? (
            <span className="inline-flex items-center gap-1 text-[11px] font-bold text-emerald-700 bg-emerald-50 px-2.5 py-1 rounded-full ring-1 ring-emerald-200">
              <svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12" /></svg>
              Verified
            </span>
          ) : isHigh ? (
            <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-rose-600 bg-rose-50 px-2.5 py-1 rounded-full ring-1 ring-rose-200">
              Pending
            </span>
          ) : (
            <span className="text-gray-300 text-xs font-medium">OK</span>
          )}
        </td>

        {/* Attest action */}
        <td className="px-3 py-3.5 pr-5 text-right" onClick={e => e.stopPropagation()}>
          {needsAttest && (
            <button
              onClick={e => { e.stopPropagation(); onRequestAttest(file); }}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-bold rounded-lg transition-all active:scale-95 shadow-sm bg-indigo-600 text-white hover:bg-indigo-700 hover:shadow-md"
            >
              <ShieldIcon size={12} /> Attest
            </button>
          )}
        </td>
      </tr>

      {/* ── Expanded detail panel ── */}
      {expanded && (
        <tr className="bg-slate-50/80">
          <td colSpan={7} className="px-5 py-4 pl-11 border-b border-gray-100">
            <div className="space-y-4 max-w-3xl">

              {/* Full path */}
              <div>
                <p className="text-[10px] font-bold uppercase tracking-wider text-gray-400 mb-1">Full Path</p>
                <code className="text-xs font-mono text-gray-700 bg-white border border-gray-200 px-3 py-1.5 rounded-lg block w-fit">{file.file_path}</code>
              </div>

              {/* AI breakdown */}
              <div className="flex items-start gap-6 flex-wrap">
                <div>
                  <p className="text-[10px] font-bold uppercase tracking-wider text-gray-400 mb-2">AI Content</p>
                  <div className="flex items-center gap-3">
                    <div className="w-36"><ProgressBar value={file.ai_percentage} mode="ai" height="h-2" /></div>
                    <span className="text-sm font-black text-gray-800 tabular-nums">{(file.ai_percentage * 100).toFixed(1)}%</span>
                    <span className={`text-[11px] font-semibold px-2 py-0.5 rounded-full ${
                      file.ai_percentage > 0.7 ? "bg-rose-100 text-rose-700" :
                      file.ai_percentage > 0.4 ? "bg-amber-100 text-amber-700" :
                      "bg-emerald-100 text-emerald-700"
                    }`}>
                      {file.ai_percentage > 0.7 ? "High AI" : file.ai_percentage > 0.4 ? "Moderate AI" : "Low AI"}
                    </span>
                  </div>
                </div>
                {/* AI model attribution */}
                {file.content && (
                  <div>
                    <p className="text-[10px] font-bold uppercase tracking-wider text-gray-400 mb-2">Likely Source</p>
                    <AIAttributionBadge content={file.content} language={file.language} showBreakdown={false} />
                  </div>
                )}
                <div>
                  <p className="text-[10px] font-bold uppercase tracking-wider text-gray-400 mb-2">Risk Level</p>
                  <RiskBadge level={file.risk_score} />
                </div>
                <div>
                  <p className="text-[10px] font-bold uppercase tracking-wider text-gray-400 mb-2">Attestation</p>
                  {attested ? (
                    <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-emerald-700">
                      <CheckCircleIcon size={13} /> Reviewer confirmed
                    </span>
                  ) : isHigh ? (
                    <span className="inline-flex items-center gap-1.5 text-xs font-semibold text-rose-600">
                      <AlertTriIcon size={13} /> Required before deploy
                    </span>
                  ) : (
                    <span className="text-xs text-gray-400">Not required ({file.risk_score})</span>
                  )}
                </div>
              </div>

              {/* Signals — security vulnerabilities + AI detection */}
              {file.risk_indicators.length > 0 && (() => {
                const secSigs = file.risk_indicators.filter(s => SIGNAL_META[s]?.security);
                const aiSigs  = file.risk_indicators.filter(s => !SIGNAL_META[s]?.security);
                const renderRowSignal = (sig: string) => {
                  const meta = SIGNAL_META[sig] ?? { label: sig, desc: "Detection signal", sev: "low" as SignalSev };
                  const { badge, dot } = SEV_COLORS[meta.sev];
                  const instances = (file.indicators ?? []).filter(i => i.id === sig);
                  const lines = instances.map(i => i.line).filter((l): l is number => typeof l === "number");
                  const detail = instances[0]?.detail;
                  return (
                    <div key={sig} className={`flex items-start gap-3 rounded-xl border p-3 shadow-sm ${
                      meta.security && meta.sev === "critical" ? "bg-rose-50 border-rose-200"
                      : meta.security && meta.sev === "high"   ? "bg-orange-50 border-orange-200"
                      : "bg-white border-gray-100"}`}>
                      <div className={`w-1.5 h-1.5 rounded-full shrink-0 mt-1.5 ${dot}`} />
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center gap-2 mb-0.5 flex-wrap">
                          <p className="text-xs font-bold text-gray-900">{meta.label}</p>
                          <span className={`text-[10px] font-bold px-1.5 py-px rounded-md ring-1 uppercase ${badge}`}>{meta.sev}</span>
                          {lines.length > 0 && (
                            <span className="ml-auto text-[10px] font-bold text-gray-600 bg-white border border-gray-200 px-2 py-px rounded-md font-mono">
                              {lines.length === 1 ? `Line ${lines[0]}` : `Lines ${lines.slice(0,3).join(", ")}${lines.length > 3 ? ` +${lines.length-3}` : ""}`}
                            </span>
                          )}
                        </div>
                        <p className="text-[11px] text-gray-500 leading-relaxed">{meta.desc}</p>
                        {detail && (
                          <p className="text-[10px] font-mono text-rose-700 bg-rose-50 border border-rose-100 rounded-md px-2 py-1 mt-1 truncate" title={detail}>{detail}</p>
                        )}
                      </div>
                    </div>
                  );
                };
                return (
                  <div className="space-y-3">
                    {secSigs.length > 0 && (
                      <div>
                        <p className="text-[10px] font-bold uppercase tracking-wider text-rose-500 mb-2">
                          Security Vulnerabilities ({secSigs.length})
                        </p>
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">{secSigs.map(renderRowSignal)}</div>
                      </div>
                    )}
                    {aiSigs.length > 0 && (
                      <div>
                        <p className="text-[10px] font-bold uppercase tracking-wider text-gray-400 mb-2">
                          AI Detection Signals ({aiSigs.length})
                        </p>
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">{aiSigs.map(renderRowSignal)}</div>
                      </div>
                    )}
                  </div>
                );
              })()}

              {file.risk_indicators.length === 0 && !isHigh && (
                <p className="text-xs text-gray-400 italic">No risk signals detected — file meets AI provenance requirements</p>
              )}

              {/* Attest CTA inside expanded row */}
              {needsAttest && (
                <div className="flex items-center justify-between bg-amber-50 border border-amber-200 rounded-xl px-4 py-3">
                  <div>
                    <p className="text-xs font-bold text-amber-800">Ready to attest?</p>
                    <p className="text-[11px] text-amber-600 mt-0.5">Open the code review panel to inspect source and confirm.</p>
                  </div>
                  <button
                    onClick={e => { e.stopPropagation(); onRequestAttest(file); }}
                    className="inline-flex items-center gap-2 px-4 py-2 text-xs font-bold bg-indigo-600 text-white rounded-xl hover:bg-indigo-700 transition-colors shadow-sm shrink-0"
                  >
                    <ShieldIcon size={12} /> Review & Attest
                  </button>
                </div>
              )}

              {/* Source code */}
              {file.content ? (
                <div>
                  <p className="text-[10px] font-bold uppercase tracking-wider text-gray-400 mb-2">
                    Source Code
                    <span className="ml-2 normal-case font-normal text-gray-500">
                      (risky lines highlighted in red)
                    </span>
                  </p>
                  <CodeViewer
                    code={file.content}
                    language={file.language}
                    filename={file.file_path}
                    riskIndicators={file.risk_indicators}
                  />
                </div>
              ) : (
                <div className="flex items-center gap-3 bg-gray-50 border border-dashed border-gray-200 rounded-xl px-4 py-3.5">
                  <div className="w-8 h-8 rounded-lg bg-gray-100 flex items-center justify-center shrink-0">
                    <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round" className="text-gray-400">
                      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
                      <polyline points="14 2 14 8 20 8" />
                      <line x1="16" y1="13" x2="8" y2="13" />
                      <line x1="16" y1="17" x2="8" y2="17" />
                      <polyline points="10 9 9 9 8 9" />
                    </svg>
                  </div>
                  <div>
                    <p className="text-xs font-semibold text-gray-600">Source not captured in this scan</p>
                    <p className="text-[11px] text-gray-400 mt-0.5">
                      File content was not submitted when this scan was created. Re-submit this PR with file content to enable code review.
                    </p>
                  </div>
                </div>
              )}
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

// ── Policy Gate ───────────────────────────────────────────────────────────────

function PolicyGate({ result, policy }: { result: PolicyResult; policy: OrgPolicy }) {
  const sevColors: Record<string, string> = {
    critical: "text-violet-700 bg-violet-50 ring-violet-200",
    high:     "text-orange-700 bg-orange-50 ring-orange-200",
    medium:   "text-amber-700  bg-amber-50  ring-amber-200",
  };
  const sevDot: Record<string, string> = {
    critical: "bg-violet-500",
    high:     "bg-orange-500",
    medium:   "bg-amber-400",
  };

  return (
    <div className={`rounded-2xl border overflow-hidden ${
      result.pass
        ? "border-emerald-200 bg-emerald-50/50"
        : result.gated
          ? "border-rose-200 bg-rose-50/40"
          : "border-amber-200 bg-amber-50/40"
    }`}>
      <div className="px-5 py-3.5 flex items-center gap-3 flex-wrap">
        {/* Status badge */}
        <div className={`flex items-center gap-2 px-3 py-1.5 rounded-xl font-bold text-xs ${
          result.pass
            ? "bg-emerald-100 text-emerald-800"
            : result.gated
              ? "bg-rose-100 text-rose-800"
              : "bg-amber-100 text-amber-800"
        }`}>
          {result.pass ? (
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">
              <polyline points="20 6 9 17 4 12" />
            </svg>
          ) : (
            <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
              <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
            </svg>
          )}
          {result.pass ? "Policy PASS" : result.gated ? "Policy FAIL — Merge Blocked" : "Policy WARN"}
        </div>

        <div className="flex-1 min-w-0">
          <p className="text-xs font-semibold text-gray-700">
            Policy: <span className="font-bold text-gray-900">{policy.name}</span>
            <span className="mx-2 text-gray-300">·</span>
            {result.pass
              ? "All requirements met — this PR is clear to merge"
              : `${result.violations.length} violation${result.violations.length !== 1 ? "s" : ""} — resolve before merging`}
          </p>
        </div>

        <Link
          href="/settings"
          className="text-xs font-semibold text-indigo-500 hover:text-indigo-700 shrink-0"
        >
          Edit policy →
        </Link>
      </div>

      {/* Violations */}
      {result.violations.length > 0 && (
        <div className="border-t border-current/10 px-5 py-3 space-y-1.5"
          style={{ borderColor: result.gated ? "#fecaca" : "#fde68a" }}>
          {result.violations.map((v, i) => (
            <div key={i} className="flex items-start gap-2.5">
              <span className={`w-1.5 h-1.5 rounded-full shrink-0 mt-1.5 ${sevDot[v.severity] ?? "bg-gray-400"}`} />
              <p className="text-xs text-gray-700 leading-relaxed">
                <span className={`text-[10px] font-bold px-1.5 py-px rounded ring-1 mr-1.5 ${sevColors[v.severity] ?? ""}`}>
                  {v.severity.toUpperCase()}
                </span>
                <code className="font-mono text-gray-600 mr-1">{v.file.split("/").pop()}</code>
                {v.reason}
              </p>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Page ──────────────────────────────────────────────────────────────────────

function PRDetailContent() {
  const id = (useParams<{ id: string }>() ?? { id: "" }).id;
  const searchParams = useSearchParams();
  const { profile } = useAuth();
  const tz = useTimezone();

  const [scan,    setScan]    = useState<ScanResult | null>(null);
  const [error,   setError]   = useState<string | null>(null);

  // Realtime presence — show who else is reviewing this scan
  const { reviewers } = usePresence(scan?.scan_id ?? null);
  // Initialise attestedSet from persisted tl_violation_statuses so navigation doesn't reset state
  const [attestedSet, setAttestedSet] = useState<Set<string>>(() => {
    if (typeof window === "undefined") return new Set<string>();
    try {
      const statuses = JSON.parse(localStorage.getItem("tl_violation_statuses") ?? "{}") as Record<string,string>;
      const paths = Object.entries(statuses)
        .filter(([key, val]) => val === "resolved" && key.split("::")[1] === id)
        .map(([key]) => key.split("::").slice(2).join("::"));
      return new Set(paths);
    } catch { return new Set<string>(); }
  });
  const [riskFilter, setRiskFilter]   = useState<"all" | "unattested" | "high">("all");
  const [reviewerEmail,  setReviewerEmail]  = useState("");
  const [reviewerGithub, setReviewerGithub] = useState("");
  const [attestingAll, setAttestingAll]     = useState(false);
  const [attestTarget, setAttestTarget]     = useState<FileResult | null>(null);
  const [policy,   setPolicy]   = useState<OrgPolicy | null>(null);
  const [syncingCheck, setSyncingCheck] = useState(false);
  const [syncResult, setSyncResult] = useState<{ ok: boolean; msg: string; canForce?: boolean } | null>(null);

  // Restore reviewer + policy from localStorage
  useEffect(() => {
    const storedEmail = localStorage.getItem("tl_reviewer_email") ?? "";
    if (storedEmail && !isValidEmail(storedEmail)) {
      // Previously-saved value isn't a valid email (e.g. a GitHub username was
      // entered by mistake) — clear it so attest calls don't fail validation
      // and the reviewer bar prompts for a correct value.
      localStorage.removeItem("tl_reviewer_email");
    } else {
      setReviewerEmail(storedEmail);
    }
    setReviewerGithub(localStorage.getItem("tl_reviewer_github") ?? "");
    setPolicy(loadPolicy());
    // Re-sync attestedSet in case localStorage was updated while away
    try {
      const statuses = JSON.parse(localStorage.getItem("tl_violation_statuses") ?? "{}") as Record<string,string>;
      const paths = Object.entries(statuses)
        .filter(([key, val]) => val === "resolved" && key.split("::")[1] === id)
        .map(([key]) => key.split("::").slice(2).join("::"));
      if (paths.length > 0) setAttestedSet(prev => new Set([...Array.from(prev), ...paths]));
    } catch {}
  }, [id]);

  // Deep link from Reports/Dashboard: ?attest=<file_path> opens the
  // Review & Attest modal for that file once the scan has loaded, so
  // reviewers always see the source code before attesting.
  useEffect(() => {
    const target = searchParams?.get("attest");
    if (!target || !scan) return;
    const file = scan.files.find(f => f.file_path === target);
    if (file && !(file.attested || attestedSet.has(file.file_path))) {
      setAttestTarget(file);
    }
  }, [searchParams, scan, attestedSet]);

  useEffect(() => {
    api.getScan(id).then(setScan).catch(() => setError("404 Not Found"));
  }, [id]);

  async function syncCheckRun(force = false) {
    if (!scan) return;
    setSyncingCheck(true);
    if (!force) setSyncResult(null);
    try {
      const data = await authedFetch<{
        synced?: boolean; reason?: string; message?: string; error?: string;
      }>("/api/sync-check-run", {
        method: "POST",
        body: JSON.stringify({ scan_id: scan.scan_id, force }),
      });
      if (data.synced) {
        setSyncResult({ ok: true, msg: "GitHub check run updated to ✓ success." });
      } else if (data.reason === "no_check_run") {
        setSyncResult({ ok: false, msg: "No GitHub check run is linked to this scan." });
      } else if (data.reason === "files_pending") {
        setSyncResult({ ok: false, msg: data.message ?? "Some files are still pending.", canForce: true });
      } else {
        setSyncResult({ ok: false, msg: data.error ?? "Sync failed." });
      }
    } catch {
      setSyncResult({ ok: false, msg: "Network error — could not reach the server." });
    } finally {
      setSyncingCheck(false);
    }
  }

  function saveReviewer(email: string, github: string) {
    setReviewerEmail(email);
    setReviewerGithub(github);
    localStorage.setItem("tl_reviewer_email",  email);
    localStorage.setItem("tl_reviewer_github", github);
  }

  function recordActivityEvent(path: string, email: string) {
    if (!scan) return;
    const file = scan.files.find(f => f.file_path === path);
    const event = {
      type: "attestation",
      timestamp: new Date().toISOString(),
      repo: scan.repo,
      pr_number: scan.pr_number,
      scan_id: scan.scan_id,
      overall_risk: file?.risk_score ?? "HIGH",
      file_count: 0,
      total_ai_pct: file?.ai_percentage ?? 0,
      file_path: path,
      reviewer_email: email,
    };
    try {
      const existing = JSON.parse(localStorage.getItem("tl_local_activity") ?? "[]");
      localStorage.setItem("tl_local_activity", JSON.stringify([event, ...existing].slice(0, 200)));
    } catch {}
  }

  function resolveOneFile(path: string) {
    if (!scan) return;
    try {
      const stored = JSON.parse(localStorage.getItem("tl_violation_statuses") ?? "{}") as Record<string,string>;
      const snap   = JSON.parse(localStorage.getItem("tl_notif_snapshot") ?? "null");
      const updates: Record<string,string> = {};

      const riskPfx = (r: string) =>
        r === "CRITICAL" ? "crit" : r === "HIGH" ? "high" : r === "MEDIUM" ? "med" : "low";

      // Resolve this specific file — any risk level
      if (snap?.top_risk_files) {
        (snap.top_risk_files as { scan_id:string; file_path:string; risk_score:string }[])
          .filter(f => f.scan_id === scan.scan_id && f.file_path === path)
          .forEach(f => { updates[`${riskPfx(f.risk_score)}::${scan.scan_id}::${path}`] = "resolved"; });
      }
      // Fallback: use scan file risk_score
      if (Object.keys(updates).length === 0) {
        const mockFile = scan.files.find(f => f.file_path === path);
        if (mockFile) updates[`${riskPfx(mockFile.risk_score)}::${scan.scan_id}::${path}`] = "resolved";
      }
      if (Object.keys(updates).length > 0) {
        localStorage.setItem("tl_violation_statuses", JSON.stringify({ ...stored, ...updates }));
        window.dispatchEvent(new Event("tl:badge"));
      }
    } catch {}
  }

  // Persist an attestation to the real API so it's recorded in Supabase and,
  // for GitHub-sourced scans, can flip the PR's Check Run to "success".
  function persistAttestation(path: string, email: string, github: string) {
    if (scan && profile?.org_id) {
      return authedFetch("/api/attest", {
        method: "POST",
        body:   JSON.stringify({
          scan_id:         scan.scan_id,
          file_path:       path,
          reviewer_email:  email,
          reviewer_github: github || undefined,
        }),
      }).catch(() => {});
    }
    return Promise.resolve();
  }

  function markAttested(path: string) {
    setAttestedSet(s => { const n = new Set(s); n.add(path); return n; });
    if (scan) {
      resolveOneFile(path);
      const email = reviewerEmail || "reviewer@trustledger.dev";
      recordActivityEvent(path, email);
      persistAttestation(path, email, reviewerGithub).then(() => {
        const remaining = scan.files.filter(
          f => (f.risk_score === "HIGH" || f.risk_score === "CRITICAL") &&
               f.file_path !== path && !f.attested && !attestedSet.has(f.file_path)
        );
        if (remaining.length === 0) syncCheckRun(true);
      });
    }
  }

  // Realtime — when another reviewer attests a file, update our attestedSet
  useAttestationsRealtime(
    scan?.scan_id,
    (att: Record<string, unknown>) => {
      const fp = att.file_path as string | undefined;
      if (fp) setAttestedSet(s => { const n = new Set(s); n.add(fp); return n; });
    },
  );

  // Reads tl_notif_snapshot to find EXACTLY which violation keys the dashboard tracks
  // for this scan, then marks them all resolved.
  function resolveViolationsForScan(scanId: string) {
    try {
      const stored  = JSON.parse(localStorage.getItem("tl_violation_statuses") ?? "{}") as Record<string,string>;
      const snap    = JSON.parse(localStorage.getItem("tl_notif_snapshot") ?? "null");
      const updates: Record<string,string> = {};

      const riskPfx = (r: string) =>
        r === "CRITICAL" ? "crit" : r === "HIGH" ? "high" : r === "MEDIUM" ? "med" : "low";

      // Mark ALL top_risk_files from this scan as resolved (any risk level)
      if (snap?.top_risk_files) {
        (snap.top_risk_files as { scan_id:string; file_path:string; risk_score:string }[])
          .filter(f => f.scan_id === scanId)
          .forEach(f => {
            updates[`${riskPfx(f.risk_score)}::${scanId}::${f.file_path}`] = "resolved";
          });
      }

      // Also write for all current scan files to ensure full coverage
      if (scan) {
        scan.files.forEach(f => {
          updates[`${riskPfx(f.risk_score)}::${scanId}::${f.file_path}`] = "resolved";
        });
      }

      localStorage.setItem("tl_violation_statuses", JSON.stringify({ ...stored, ...updates }));
      window.dispatchEvent(new Event("tl:badge"));
    } catch {}
  }

  async function performAttest(file: FileResult) {
    const email  = reviewerEmail  || "reviewer@trustledger.dev";
    const github = reviewerGithub || "reviewer";
    if (!reviewerEmail || !reviewerGithub) saveReviewer(email, github);
    markAttested(file.file_path);
    setAttestTarget(null);
  }

  async function attestAll() {
    if (!scan) return;
    setAttestingAll(true);
    const email  = reviewerEmail  || "reviewer@trustledger.dev";
    const github = reviewerGithub || "reviewer";
    if (!reviewerEmail || !reviewerGithub) saveReviewer(email, github);
    const toAttest = scan.files.filter(
      f => (f.risk_score === "HIGH" || f.risk_score === "CRITICAL") &&
           !f.attested && !attestedSet.has(f.file_path)
    );
    for (const f of toAttest) {
      await persistAttestation(f.file_path, email, github);
      setAttestedSet(s => { const n = new Set(s); n.add(f.file_path); return n; });
      recordActivityEvent(f.file_path, email);
    }
    // Mark ALL violations for this scan resolved using snapshot data — handles any path mismatch
    resolveViolationsForScan(scan.scan_id);
    setAttestingAll(false);
    await syncCheckRun(true);
  }

  // When this repo is fully attested, find the next repo with open HIGH/CRIT work.
  // Must be declared before any early returns to satisfy Rules of Hooks.
  const nextUnresolved = useMemo<{ scanId: string; repoName: string } | null>(() => {
    if (!scan) return null;
    const hf = scan.files.filter(f => f.risk_score === "HIGH" || f.risk_score === "CRITICAL");
    const clear = hf.length > 0 && hf.filter(f => !f.attested && !attestedSet.has(f.file_path)).length === 0;
    if (!clear) return null;
    try {
      const snap = JSON.parse(localStorage.getItem("tl_notif_snapshot") ?? "null") as
        { top_risk_files: { scan_id: string; file_path: string; risk_score: string; attested: boolean; repo: string }[] } | null;
      const statuses = JSON.parse(localStorage.getItem("tl_violation_statuses") ?? "{}") as Record<string, string>;
      const pfx = (r: string) => r === "CRITICAL" ? "crit" : r === "HIGH" ? "high" : "med";
      const next = (snap?.top_risk_files ?? []).find(f => {
        if (f.scan_id === scan.scan_id) return false;
        if (f.attested) return false;
        if (f.risk_score !== "CRITICAL" && f.risk_score !== "HIGH") return false;
        const st = statuses[`${pfx(f.risk_score)}::${f.scan_id}::${f.file_path}`];
        return st !== "resolved" && st !== "in_review";
      });
      if (!next) return null;
      return { scanId: next.scan_id, repoName: next.repo.split("/").pop() ?? next.repo };
    } catch { return null; }
  }, [scan, attestedSet]);

  // ── Loading skeleton ────────────────────────────────────────────────────────
  if (!scan && !error) {
    return (
      <AuthGuard>
        <div className="max-w-5xl mx-auto animate-pulse space-y-4">
          <div className="h-40 rounded-2xl bg-gray-100" />
          <div className="h-12 rounded-xl bg-gray-100" />
          <div className="h-72 rounded-2xl bg-gray-100" />
        </div>
      </AuthGuard>
    );
  }

  // ── Error / not found ────────────────────────────────────────────────────────
  if (error && !scan) {
    const is404 = error.includes("404") || error.toLowerCase().includes("not found");
    const isOffline = error.toLowerCase().includes("failed to fetch") || error.toLowerCase().includes("network");
    return (
      <AuthGuard>
        <div className="max-w-5xl mx-auto">
          <div className="rounded-2xl overflow-hidden border border-gray-200"
            style={{ boxShadow:"0 4px 24px rgba(0,0,0,0.06)" }}>
            {/* Dark top bar */}
            <div className="px-8 py-6 flex items-center gap-4"
              style={{ background:"linear-gradient(135deg,#0f172a,#1e1b4b)" }}>
              <div className="w-12 h-12 rounded-2xl flex items-center justify-center shrink-0"
                style={{ background:"rgba(239,68,68,0.15)", border:"1px solid rgba(239,68,68,0.3)" }}>
                <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#f87171" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  {is404
                    ? <><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/><line x1="11" y1="8" x2="11" y2="12"/><line x1="11" y1="16" x2="11.01" y2="16"/></>
                    : <><path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></>
                  }
                </svg>
              </div>
              <div>
                <p className="text-white font-black text-lg">
                  {is404 ? "Scan not found" : isOffline ? "API offline" : "Failed to load scan"}
                </p>
                <p className="text-slate-400 text-sm mt-0.5">
                  {is404
                    ? `No scan record exists for ID: ${id}`
                    : isOffline
                    ? "The TrustLedger backend is not reachable"
                    : error}
                </p>
              </div>
            </div>

            {/* Body */}
            <div className="px-8 py-8 bg-white space-y-4">
              <p className="text-sm text-gray-600">
                {is404
                  ? `Scan "${id}" is from the live backend and isn't available in local demo mode. Use the Violations page to review and attest files instead.`
                  : "Make sure the backend server is running and your network is available."}
              </p>

              <div className="flex flex-wrap gap-3 pt-2">
                {is404 && (
                  <Link href="/violations"
                    className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-bold text-white transition-all"
                    style={{ background:"linear-gradient(135deg,#6366f1,#7c3aed)", boxShadow:"0 2px 10px rgba(99,102,241,0.35)" }}>
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M9 11l3 3L22 4"/><path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"/>
                    </svg>
                    Review in Violations
                  </Link>
                )}
                <Link href="/dashboard"
                  className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-bold text-gray-700 bg-gray-100 hover:bg-gray-200 transition-colors">
                  Go to Dashboard
                </Link>
              </div>
            </div>
          </div>
        </div>
      </AuthGuard>
    );
  }

  // ── Derived stats ───────────────────────────────────────────────────────────
  const allFiles    = scan?.files ?? [];
  const totalFiles  = allFiles.length;
  const highFiles   = allFiles.filter(f => f.risk_score === "HIGH" || f.risk_score === "CRITICAL");
  const highCount   = highFiles.length;
  const highAttested = highFiles.filter(f => f.attested || attestedSet.has(f.file_path)).length;
  const unattested   = highFiles.filter(f => !f.attested && !attestedSet.has(f.file_path)).length;
  const allClear     = highCount > 0 && unattested === 0;

  const filteredFiles = allFiles
    .filter(f => {
      if (riskFilter === "unattested") return !f.attested && !attestedSet.has(f.file_path) && (f.risk_score === "HIGH" || f.risk_score === "CRITICAL");
      if (riskFilter === "high")       return f.risk_score === "HIGH" || f.risk_score === "CRITICAL";
      return true;
    })
    .sort((a, b) => riskOrder(b.risk_score) - riskOrder(a.risk_score));

  return (
    <AuthGuard>
      <div className="max-w-5xl mx-auto space-y-4 pb-10">

        {/* ── Hero header ────────────────────────────────────────────────── */}
        {scan && (
          <div className="animate-fade-up relative overflow-hidden rounded-2xl bg-gradient-to-br from-slate-900 via-indigo-950 to-slate-900 px-6 py-6">
            <div
              className="absolute inset-0 opacity-10 pointer-events-none"
              style={{ backgroundImage: "radial-gradient(circle at 70% 40%, #6366f1 0%, transparent 55%)" }}
            />
            <div className="relative">
              {/* Breadcrumb */}
              <div className="flex items-center gap-1.5 text-xs text-slate-500 mb-3 font-medium flex-wrap">
                <span>{scan.repo.split("/")[0]}</span>
                <span className="text-slate-700">/</span>
                <span className="text-slate-400">{scan.repo.split("/").slice(1).join("/")}</span>
                <span className="text-slate-700">/</span>
                <span className="text-indigo-300 font-bold">PR #{scan.pr_number}</span>
                {/* Live reviewer presence */}
                {reviewers.length > 0 && (
                  <div className="flex items-center gap-1.5 ml-3">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                    <span className="text-emerald-400 font-semibold">{reviewers.length} also reviewing</span>
                    <div className="flex -space-x-1.5">
                      {reviewers.slice(0, 3).map(r => (
                        <div key={r.user_id}
                          title={r.name ?? r.email}
                          className="w-5 h-5 rounded-full flex items-center justify-center text-[8px] font-black text-white border border-slate-900 shrink-0"
                          style={{ background:"linear-gradient(135deg,#6366f1,#7c3aed)" }}>
                          {initials(r.email, r.name)}
                        </div>
                      ))}
                      {reviewers.length > 3 && (
                        <div className="w-5 h-5 rounded-full flex items-center justify-center text-[8px] font-bold text-white bg-slate-600 border border-slate-900 shrink-0">
                          +{reviewers.length - 3}
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>

              <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
                <div>
                  <h1 className="text-xl font-extrabold text-white tracking-tight">
                    PR #{scan.pr_number} · Scan Detail
                  </h1>
                  <div className="flex items-center gap-2.5 mt-2 flex-wrap">
                    <span className="font-mono text-xs text-slate-400 bg-slate-800/70 px-2.5 py-1 rounded-lg">{scan.commit_sha.slice(0, 8)}</span>
                    <RiskBadge level={scan.overall_risk} />
                    <span className="text-xs text-slate-400">{formatDateTime(scan.timestamp, tz)}</span>
                  </div>
                </div>

                {/* Quick stat pills */}
                <div className="flex items-stretch gap-2 shrink-0">
                  {[
                    { label: "Files",      value: totalFiles,   accent: "text-slate-200" },
                    { label: "High Risk",  value: highCount,    accent: highCount > 0 ? "text-orange-300" : "text-slate-400" },
                    { label: "Attested",   value: `${highAttested}/${highCount}`, accent: allClear ? "text-emerald-300" : "text-amber-300" },
                  ].map(s => (
                    <div key={s.label} className="bg-white/5 rounded-xl px-3.5 py-2.5 text-center min-w-[58px] border border-white/5">
                      <p className={`text-xl font-black leading-none tabular-nums ${s.accent}`}>{s.value}</p>
                      <p className="text-[10px] text-slate-500 font-medium mt-1 whitespace-nowrap">{s.label}</p>
                    </div>
                  ))}
                </div>
              </div>

              {/* Attestation progress bar */}
              {highCount > 0 && (
                <div className="mt-5">
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="text-xs text-slate-400 font-medium">
                      {allClear ? "All high-risk files attested ✓" : `${unattested} file${unattested !== 1 ? "s" : ""} pending attestation`}
                    </span>
                    <span className={`text-xs font-black tabular-nums ${allClear ? "text-emerald-400" : "text-amber-400"}`}>
                      {highAttested} / {highCount}
                    </span>
                  </div>
                  <div className="h-1.5 w-full rounded-full bg-slate-700/60 overflow-hidden">
                    <div
                      className={`h-full rounded-full transition-all duration-700 ${allClear ? "bg-emerald-500" : "bg-amber-400"}`}
                      style={{ width: `${(highAttested / highCount) * 100}%` }}
                    />
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* ── Evidence breakdown panel ────────────────────────────────────── */}
        {scan?.evidence_breakdown && (
          <div className="animate-fade-up section-card p-5">
            <div className="flex items-center justify-between mb-4">
              <div>
                <p className="font-bold text-gray-900 text-sm">AI Likelihood</p>
                <p className="text-xs text-gray-400 mt-0.5">Multi-signal evidence across code, PR behavior, git history and tooling</p>
              </div>
              <div className="text-right">
                <p className="text-lg font-black" style={{
                  color: scan.evidence_breakdown.likelihood === "Strong AI Evidence" ? "#ef4444"
                       : scan.evidence_breakdown.likelihood === "Likely AI-Assisted"   ? "#f97316"
                       : scan.evidence_breakdown.likelihood === "Mixed Authorship"     ? "#f59e0b"
                       : scan.evidence_breakdown.likelihood === "Human with Tool Assistance" ? "#6366f1"
                       : "#10b981"
                }}>
                  {Math.round(scan.evidence_breakdown.combined * 100)}%
                </p>
                <p className="text-[10px] font-semibold text-gray-500">{scan.evidence_breakdown.likelihood}</p>
              </div>
            </div>

            {/* Evidence bars */}
            <div className="grid grid-cols-2 gap-3 mb-4">
              {([
                { key: "code_evidence",     label: "Code Signals",       weight: "25%", color: "#6366f1" },
                { key: "pr_evidence",       label: "PR Behavior",        weight: "25%", color: "#f97316" },
                { key: "git_evidence",      label: "Git Provenance",     weight: "25%", color: "#8b5cf6" },
                { key: "baseline_evidence", label: "Author Baseline",    weight: "15%", color: "#ec4899" },
                { key: "tool_evidence",     label: "Tool Artifacts",     weight: "10%", color: "#06b6d4" },
              ] as const).map(({ key, label, weight, color }) => {
                const val = (scan.evidence_breakdown as unknown as Record<string, number>)[key] ?? 0;
                return (
                  <div key={key}>
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-[10px] font-semibold text-gray-600">{label}</span>
                      <div className="flex items-center gap-1.5">
                        <span className="text-[10px] text-gray-400">{weight}</span>
                        <span className="text-[11px] font-bold tabular-nums" style={{ color }}>{Math.round(val * 100)}%</span>
                      </div>
                    </div>
                    <div className="h-1.5 rounded-full overflow-hidden bg-gray-100">
                      <div className="h-full rounded-full transition-all duration-700"
                        style={{ width: `${val * 100}%`, background: color }} />
                    </div>
                  </div>
                );
              })}
            </div>

            {/* Boosts */}
            {scan.evidence_breakdown.boosts.length > 0 && (
              <div className="border-t border-gray-100 pt-3">
                <p className="text-[10px] font-bold uppercase tracking-wider text-gray-400 mb-2">Signal Boosts</p>
                <div className="space-y-1">
                  {scan.evidence_breakdown.boosts.map((b, i) => (
                    <div key={i} className="flex items-start gap-2 text-[11px] text-amber-700 bg-amber-50 border border-amber-100 rounded-lg px-3 py-1.5">
                      <span className="shrink-0 mt-0.5">⚡</span>
                      <span>{b}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* ── Reviewer identity bar ───────────────────────────────────────── */}
        {scan && (
          <div className="animate-fade-up delay-50">
            <ReviewerBar email={reviewerEmail} github={reviewerGithub} onSave={saveReviewer} />
          </div>
        )}

        {/* ── Action needed banner ────────────────────────────────────────── */}
        {unattested > 0 && (
          <div className="animate-fade-up flex items-center gap-3 bg-rose-50 border border-rose-200 rounded-xl px-4 py-3">
            <div className="w-8 h-8 rounded-lg bg-rose-100 flex items-center justify-center text-rose-600 shrink-0">
              <AlertTriIcon />
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-sm font-bold text-rose-800">
                {unattested} file{unattested !== 1 ? "s" : ""} pending attestation
              </p>
              <p className="text-xs text-rose-600 mt-0.5">HIGH and CRITICAL files require reviewer sign-off before deployment</p>
            </div>
            <button
              onClick={attestAll}
              disabled={attestingAll}
              className="shrink-0 inline-flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-bold rounded-lg bg-rose-600 text-white hover:bg-rose-700 disabled:opacity-60 transition-colors shadow-sm"
            >
              {attestingAll ? <><SpinnerIcon /> Attesting…</> : <><ShieldIcon size={12} /> Attest All</>}
            </button>
          </div>
        )}

        {/* ── All-clear banner ───────────────────────────────────────────── */}
        {allClear && (
          <div className="animate-fade-up flex flex-col gap-2">
            <div className="flex items-center gap-3 bg-emerald-50 border border-emerald-200 rounded-xl px-4 py-3">
              <div className="w-8 h-8 rounded-lg bg-emerald-100 flex items-center justify-center text-emerald-600 shrink-0">
                <CheckCircleIcon />
              </div>
              <p className="text-sm font-semibold text-emerald-800 flex-1">
                All {highCount} HIGH/CRITICAL file{highCount !== 1 ? "s" : ""} have been attested — this PR is cleared for deployment.
              </p>
              <button
                onClick={(e) => { e.preventDefault(); syncCheckRun(); }}
                disabled={syncingCheck}
                className="shrink-0 inline-flex items-center gap-1 px-3 py-1.5 text-xs font-bold text-emerald-700 bg-emerald-100 hover:bg-emerald-200 disabled:opacity-50 rounded-lg border border-emerald-200 transition-colors whitespace-nowrap"
              >
                {syncingCheck ? "Syncing…" : "↑ Sync GitHub Check"}
              </button>
              {nextUnresolved ? (
                <Link
                  href={`/pr/${nextUnresolved.scanId}`}
                  className="shrink-0 inline-flex items-center gap-1 px-3 py-1.5 text-xs font-bold text-emerald-700 bg-emerald-100 hover:bg-emerald-200 rounded-lg border border-emerald-200 transition-colors whitespace-nowrap"
                >
                  Review next: {nextUnresolved.repoName} →
                </Link>
              ) : (
                <Link
                  href="/dashboard"
                  className="shrink-0 inline-flex items-center gap-1 px-3 py-1.5 text-xs font-bold text-emerald-700 bg-emerald-100 hover:bg-emerald-200 rounded-lg border border-emerald-200 transition-colors whitespace-nowrap"
                >
                  Back to dashboard →
                </Link>
              )}
            </div>
            {syncResult && (
              <div className={`flex items-center gap-2 rounded-lg px-4 py-2 text-xs font-medium ${syncResult.ok ? "bg-emerald-50 text-emerald-700 border border-emerald-200" : "bg-red-50 text-red-700 border border-red-200"}`}>
                <span>{syncResult.ok ? "✓" : "✕"} {syncResult.msg}</span>
                {!syncResult.ok && syncResult.canForce && (
                  <button
                    onClick={(e) => { e.preventDefault(); syncCheckRun(true); }}
                    disabled={syncingCheck}
                    className="ml-auto shrink-0 px-2 py-0.5 text-xs font-bold text-red-700 bg-red-100 hover:bg-red-200 disabled:opacity-50 rounded border border-red-200 transition-colors"
                  >
                    Force Sync
                  </button>
                )}
              </div>
            )}
          </div>
        )}

        {/* ── Policy gate ────────────────────────────────────────────────── */}
        {scan && policy && (() => {
          const result = evaluatePolicy(policy, scan.files, attestedSet);
          return (
            <div className="animate-fade-up">
              <PolicyGate result={result} policy={policy} />
            </div>
          );
        })()}

        {/* ── Files table ────────────────────────────────────────────────── */}
        {scan && (
          <div className="section-card animate-fade-up delay-100">

            {/* Table header + filter */}
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 px-5 py-4 border-b border-gray-100">
              <div>
                <p className="font-bold text-gray-900 text-sm">
                  Files
                  <span className="ml-1.5 text-gray-400 font-normal text-xs">({filteredFiles.length} shown of {totalFiles})</span>
                </p>
                <p className="text-xs text-gray-400 mt-0.5">
                  Click any row to expand · {(scan.total_ai_percentage * 100).toFixed(1)}% avg AI content
                </p>
              </div>
              <div className="flex items-center gap-0.5 bg-gray-100 p-0.5 rounded-lg self-start sm:self-auto">
                {([
                  ["all",        "All",           null],
                  ["high",       "HIGH / CRIT",   null],
                  ["unattested", "Needs Attest",  unattested],
                ] as const).map(([v, label, count]) => (
                  <button
                    key={v}
                    onClick={() => setRiskFilter(v)}
                    className={`flex items-center gap-1 px-2.5 py-1 text-xs font-semibold rounded-md transition-all ${
                      riskFilter === v ? "bg-white text-gray-900 shadow-sm" : "text-gray-500 hover:text-gray-700"
                    }`}
                  >
                    {label}
                    {count !== null && count > 0 && (
                      <span className="text-[10px] bg-rose-100 text-rose-700 rounded-full px-1.5 font-bold">{count}</span>
                    )}
                  </button>
                ))}
              </div>
            </div>

            {/* Table */}
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-gray-100 bg-gray-50/60">
                    {["File", "Lang", "AI Content", "Risk", "Signals", "Status", "Action"].map(h => (
                      <th key={h} className="px-4 py-2.5 text-left text-[10px] font-bold uppercase tracking-wider text-gray-400 first:pl-5 last:pr-5 last:text-right">
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-50">
                  {filteredFiles.map(f => (
                    <FileRow
                      key={f.file_path}
                      file={{ ...f, attested: f.attested || attestedSet.has(f.file_path) }}
                      reviewerEmail={reviewerEmail}
                      reviewerGithub={reviewerGithub}
                      onRequestAttest={setAttestTarget}
                    />
                  ))}
                </tbody>
              </table>
            </div>

            {/* Empty state */}
            {filteredFiles.length === 0 && (
              <div className="py-12 text-center">
                <div className="w-12 h-12 rounded-2xl bg-emerald-50 flex items-center justify-center mx-auto mb-3">
                  <svg className="text-emerald-500 w-6 h-6" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <polyline points="20 6 9 17 4 12" />
                  </svg>
                </div>
                <p className="text-sm font-bold text-gray-700">
                  {riskFilter === "unattested" ? "All high-risk files are attested!" : "No files match this filter"}
                </p>
                <p className="text-xs text-gray-400 mt-1">
                  {riskFilter !== "all" ? 'Switch to "All" to view every file' : "No files in this scan"}
                </p>
              </div>
            )}

            {/* Footer */}
            <div className="px-5 py-3 border-t border-gray-100 bg-gray-50/40 flex items-center justify-between flex-wrap gap-2">
              <div className="flex items-center gap-4 text-xs text-gray-400">
                <span>{totalFiles} files</span>
                <span>·</span>
                <span>{highCount} HIGH/CRITICAL</span>
                <span>·</span>
                <span className={highAttested === highCount && highCount > 0 ? "text-emerald-600 font-semibold" : ""}>{highAttested} attested</span>
              </div>
              {allClear && highCount > 0 && (
                <span className="inline-flex items-center gap-1.5 text-xs font-bold text-emerald-700 bg-emerald-50 px-2.5 py-1 rounded-full ring-1 ring-emerald-200">
                  <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3.5" strokeLinecap="round" strokeLinejoin="round">
                    <polyline points="20 6 9 17 4 12" />
                  </svg>
                  Ready to deploy
                </span>
              )}
            </div>
          </div>
        )}

      </div>

      {/* ── Attest review modal ───────────────────────────────────────────── */}
      {attestTarget && (
        <AttestReviewModal
          file={attestTarget}
          reviewerEmail={reviewerEmail || "reviewer@trustledger.dev"}
          onConfirm={() => performAttest(attestTarget)}
          onClose={() => setAttestTarget(null)}
        />
      )}
    </AuthGuard>
  );
}

export default function PRDetailPage() {
  return (
    <Suspense fallback={
      <div className="flex items-center justify-center h-64">
        <svg className="animate-spin w-8 h-8 text-indigo-500" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M21 12a9 9 0 1 1-6.219-8.56"/>
        </svg>
      </div>
    }>
      <PRDetailContent />
    </Suspense>
  );
}
