"use client";

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
import { SEED_FILE_SAMPLES } from "@/lib/seedFileSamples";
import { useAuth } from "@/lib/auth";
import { usePresence, initials } from "@/lib/presence";
import AIAttributionBadge from "@/components/AIAttributionBadge";

// ── Signal library ────────────────────────────────────────────────────────────

type SignalSev = "critical" | "high" | "medium" | "low";

const SIGNAL_META: Record<string, { label: string; desc: string; sev: SignalSev }> = {
  "sql-injection":         { label: "SQL Injection",          desc: "Dynamic SQL construction without parameterization — high injection risk when AI-generated code handles user input",          sev: "critical" },
  "hardcoded-secret":      { label: "Hardcoded Secret",       desc: "API keys, passwords, or tokens may be embedded directly in source — a common AI model hallucination pattern",              sev: "critical" },
  "eval-exec":             { label: "Eval / Exec Usage",      desc: "Dynamic code execution via eval() or exec() — AI models frequently produce this anti-pattern without security consideration", sev: "critical" },
  "jwt-none-alg":          { label: "JWT None Algorithm",     desc: "JWT token verification may accept the 'none' algorithm, bypassing signature checks — a well-known AI security mistake",    sev: "high"     },
  "ai-comment-pattern":    { label: "AI Comment Pattern",     desc: "Comment verbosity and style strongly match AI generation signatures (over-explained, instructional tone)",                  sev: "low"      },
  "structural-uniformity": { label: "Structural Uniformity",  desc: "Code blocks show unusually uniform structure and indentation — indicates AI copy-paste without human variation",            sev: "medium"   },
  "comment-density":       { label: "High Comment Density",   desc: "Comment-to-code ratio far exceeds human baseline — typical of AI output that over-documents obvious logic",                sev: "low"      },
  "identifier-entropy":    { label: "Low Identifier Entropy", desc: "Variable and function names show low lexical entropy — AI models tend to use generic, predictable naming patterns",         sev: "medium"   },
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

          {/* Signals */}
          {file.risk_indicators.length > 0 && (
            <div>
              <p className="text-[10px] font-bold uppercase tracking-wider text-gray-400 mb-2">
                Risk Signals ({file.risk_indicators.length})
              </p>
              <div className="space-y-2">
                {file.risk_indicators.map(sig => {
                  const meta = SIGNAL_META[sig] ?? { label: sig, desc: "Custom detection signal", sev: "medium" as SignalSev };
                  const { badge, dot } = SEV_COLORS[meta.sev];
                  return (
                    <div key={sig} className="flex items-start gap-3 bg-gray-50 rounded-xl border border-gray-100 p-3">
                      <div className={`w-1.5 h-1.5 rounded-full shrink-0 mt-1.5 ${dot}`} />
                      <div className="min-w-0">
                        <div className="flex items-center gap-2 mb-0.5 flex-wrap">
                          <p className="text-xs font-bold text-gray-900">{meta.label}</p>
                          <span className={`text-[10px] font-bold px-1.5 py-px rounded-md ring-1 uppercase ${badge}`}>{meta.sev}</span>
                        </div>
                        <p className="text-[11px] text-gray-500 leading-relaxed">{meta.desc}</p>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
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

              {/* Signals */}
              {file.risk_indicators.length > 0 && (
                <div>
                  <p className="text-[10px] font-bold uppercase tracking-wider text-gray-400 mb-2">
                    Detected Signals ({file.risk_indicators.length})
                  </p>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                    {file.risk_indicators.map(sig => {
                      const meta = SIGNAL_META[sig] ?? { label: sig, desc: "Custom detection signal", sev: "medium" as SignalSev };
                      const { badge, dot } = SEV_COLORS[meta.sev];
                      return (
                        <div key={sig} className="flex items-start gap-3 bg-white rounded-xl border border-gray-100 p-3 shadow-sm">
                          <div className={`w-1.5 h-1.5 rounded-full shrink-0 mt-1.5 ${dot}`} />
                          <div className="min-w-0">
                            <div className="flex items-center gap-2 mb-0.5 flex-wrap">
                              <p className="text-xs font-bold text-gray-900">{meta.label}</p>
                              <span className={`text-[10px] font-bold px-1.5 py-px rounded-md ring-1 uppercase ${badge}`}>{meta.sev}</span>
                            </div>
                            <p className="text-[11px] text-gray-500 leading-relaxed">{meta.desc}</p>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}

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

const ORG = process.env.NEXT_PUBLIC_ORG ?? "novapay";

// ── Sample source code for offline review ─────────────────────────────────────

const MOCK_FILE_CONTENT: Record<string, string> = {
  "src/processors/card_validator.py": `import psycopg2
import stripe

# Hardcoded Stripe API key — must be rotated immediately
STRIPE_KEY = "sk_live_51Hx2trustledger_demo"

def validate_card(card_number: str, user_id: str):
    conn = psycopg2.connect("postgresql://prod_db")
    cursor = conn.cursor()

    # SQL injection: user_id injected directly into query
    query = f"SELECT * FROM cards WHERE user_id = '{user_id}'"
    cursor.execute(query)

    # Arbitrary code execution via eval
    result = eval("stripe.CreditCard.validate('" + card_number + "')")

    stripe.api_key = STRIPE_KEY
    return stripe.Charge.create(amount=int(result*100), currency="usd")`,

  "src/gateway/stripe_client.py": `import stripe

# Hardcoded production API key — rotate immediately
STRIPE_SECRET  = "sk_live_51Hx2trustledger_production_key"
WEBHOOK_SECRET = "whsec_prod_webhook_2024"

def create_charge(amount: int, currency: str, source: str):
    stripe.api_key = STRIPE_SECRET
    return stripe.Charge.create(
        amount=amount, currency=currency, source=source
    )

def verify_webhook(payload: bytes, sig: str) -> dict:
    return stripe.Webhook.construct_event(payload, sig, WEBHOOK_SECRET)`,

  "src/api/refund_handler.py": `# Refund handler
# This module processes refund requests for completed transactions.
# It validates the refund amount and calls the payment gateway.

def process_refund(transaction_id: str, amount: float, reason: str) -> dict:
    # Validate the refund amount
    if amount <= 0:
        raise ValueError("Refund amount must be positive")

    # Look up the original transaction
    transaction = get_transaction(transaction_id)

    # Apply the refund via payment gateway
    result = payment_gateway.refund(
        transaction_id=transaction_id,
        amount=int(amount * 100),
        reason=reason
    )
    return {"status": "refunded", "transaction_id": transaction_id, "amount": amount}`,

  "src/models/transaction.py": `from dataclasses import dataclass
from datetime import datetime
from typing import Optional

@dataclass
class Transaction:
    id: str
    amount: float
    currency: str
    status: str
    created_at: datetime
    updated_at: datetime
    user_id: str
    description: Optional[str] = None
    metadata: Optional[dict] = None

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "amount": self.amount,
            "currency": self.currency,
            "status": self.status,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }`,

  "src/utils/currency_formatter.py": `# Currency formatting utilities
# Provides human-readable formatting for monetary values.

SUPPORTED_CURRENCIES = ["USD", "EUR", "GBP", "JPY"]

def format_currency(amount: float, currency: str) -> str:
    # Format the amount according to the currency
    if currency == "USD":
        return f"\${amount:,.2f}"
    elif currency == "EUR":
        return f"EUR {amount:,.2f}"
    elif currency == "GBP":
        return f"GBP {amount:,.2f}"
    elif currency == "JPY":
        return f"JPY {int(amount):,}"
    return f"{amount:,.2f} {currency}"`,

  "src/middleware/auth_check.ts": `import jwt from "jsonwebtoken";

// Hardcoded secret — should use process.env.JWT_SECRET
const JWT_SECRET = "jwt_signing_secret_2024";

export function checkAuth(req: Request): { userId: string; role: string } | null {
  const token = req.headers.get("Authorization")?.replace("Bearer ", "");
  if (!token) return null;

  // VULNERABLE: accepts "none" algorithm — any token passes verification
  const payload = jwt.verify(token, JWT_SECRET, {
    algorithms: ["HS256", "none"],
  }) as { sub: string; role: string };

  return { userId: payload.sub, role: payload.role };
}`,

  "src/services/payment_service.ts": `// Payment service — orchestrates charge creation and validation

export class PaymentService {
  // AI-generated: eval on user-supplied formula
  async calculateFee(formula: string, amount: number): Promise<number> {
    const result = eval(formula); // RCE risk
    return result * amount;
  }

  async processPayment(data: {
    amount: number;
    currency: string;
    userId: string;
    description: string;
  }): Promise<{ id: string; status: string }> {
    const fee = await this.calculateFee("0.029 + 0.30", data.amount);
    const charge = await this.createCharge({ ...data, fee });
    return { id: charge.id, status: charge.status };
  }

  private async createCharge(data: object): Promise<any> {
    return fetch("/api/charges", {
      method: "POST",
      body: JSON.stringify(data),
    }).then(r => r.json());
  }
}`,

  "src/oauth/token_exchange.ts": `import jwt from "jsonwebtoken";

// JWT secret hardcoded — use process.env.JWT_SECRET
const JWT_SECRET = "jwt_secret_prod_2024";

export function verifyToken(token: string): object {
  // Accepts 'none' algorithm — JWT bypass vulnerability
  const payload = jwt.decode(token, JWT_SECRET, {
    algorithms: ["HS256", "none"],
    ignoreExpiration: false,
  });
  return payload as object;
}

export function createToken(userId: string, role: string): string {
  return jwt.sign({ sub: userId, role }, JWT_SECRET, {
    expiresIn: "24h",
    algorithm: "HS256",
  });
}`,

  "src/auth/token_service.py": `import jwt

# Hardcoded JWT secret — must use secrets manager
JWT_SECRET = "jwt_secret_prod_2024"

def verify_token(token: str) -> dict:
    # Accepts 'none' algorithm — JWT bypass vulnerability
    payload = jwt.decode(
        token, JWT_SECRET,
        algorithms=["HS256", "none"],
        options={"verify_signature": False}
    )
    return payload

def issue_token(user_id: str, role: str) -> str:
    return jwt.encode(
        {"sub": user_id, "role": role},
        JWT_SECRET, algorithm="HS256"
    )`,

  "src/middleware/rate_limiter.ts": `// Rate limiter middleware
// Limits requests per IP to prevent abuse.

const RATE_LIMIT = 100;
const WINDOW_MS  = 60_000;

const counters = new Map<string, { count: number; reset: number }>();

export function rateLimit(req: Request): boolean {
  const ip  = req.headers.get("x-forwarded-for") ?? "unknown";
  const now = Date.now();
  const entry = counters.get(ip);

  if (!entry || now > entry.reset) {
    counters.set(ip, { count: 1, reset: now + WINDOW_MS });
    return true;
  }
  if (entry.count >= RATE_LIMIT) return false;
  entry.count++;
  return true;
}`,

  "models/risk_scorer.ts": `const MODEL_KEY = "sk-prod-ml-inference-2024";

export function scoreRisk(formula: string, context: Record<string, number>): number {
  // AI-generated: arbitrary code execution via eval
  const result = eval(formula);
  return result;
}

export function runFormula(code: string): any {
  // CRITICAL: exec on user-controlled input
  const fn = new Function("context", code);
  return fn(context);
}

export function getModelPrediction(data: object): number {
  const key = MODEL_KEY;
  return fetch(\`https://api.ml-service.io/predict?key=\${key}\`, {
    method: "POST", body: JSON.stringify(data)
  }).then(r => r.json()) as any;
}`,

  "src/rules/velocity_check.py": `import psycopg2

def check_velocity(user_id: str, transaction_amount: float) -> dict:
    conn = psycopg2.connect("postgresql://fraud_db")
    cursor = conn.cursor()

    # SQL injection: user_id injected into query
    query = f"SELECT COUNT(*) FROM transactions WHERE user_id = '{user_id}' AND amount > 100"
    cursor.execute(query)
    count = cursor.fetchone()[0]

    return {
        "user_id": user_id,
        "transaction_count": count,
        "flagged": count > 10,
    }`,

  "src/utils/feature_extractor.py": `# Feature extraction utility
# Extracts numerical features from transaction data for ML models.

import numpy as np

def extract_features(transaction: dict) -> list:
    # Extract numerical features
    amount    = transaction.get("amount", 0)
    hour      = transaction.get("hour", 0)
    day_of_week = transaction.get("day_of_week", 0)
    is_international = int(transaction.get("is_international", False))

    return [amount, hour, day_of_week, is_international]`,

  "src/database/connection.py": `import psycopg2

# Hardcoded production credentials — use environment variables
DB_HOST     = "prod-db.internal"
DB_PORT     = 5432
DB_NAME     = "fraud_db"
DB_USER     = "admin"
DB_PASSWORD = "prod_password_2024"

def get_connection():
    return psycopg2.connect(
        host=DB_HOST, port=DB_PORT, dbname=DB_NAME,
        user=DB_USER, password=DB_PASSWORD
    )`,

  "src/models/credit_score.ts": `// Credit score calculation module
// Uses weighted average of risk factors to produce a score 0-1000.

export interface RiskFactors {
  paymentHistory:    number;
  creditUtilization: number;
  accountAge:        number;
  recentInquiries:   number;
}

export function calculateCreditScore(factors: RiskFactors): number {
  const weights = {
    paymentHistory:    0.35,
    creditUtilization: 0.30,
    accountAge:        0.15,
    recentInquiries:   0.10,
  };
  const score = Object.entries(weights).reduce((acc, [key, weight]) => {
    return acc + (factors[key as keyof RiskFactors] ?? 0) * weight;
  }, 0);
  return Math.round(score * 1000);
}`,

  "src/connectors/bigquery_writer.ts": `import { BigQuery } from '@google-cloud/bigquery';

// Hardcoded GCP credentials — use workload identity
const GCP_KEY = "AIzaSyC_prod_bigquery_key_2024";
const PROJECT  = "prod-analytics";

export async function writeResults(userId: string, data: object[]): Promise<void> {
  const bq = new BigQuery({ projectId: PROJECT, apiKey: GCP_KEY });

  // SQL injection: userId injected directly into query string
  const query = "SELECT * FROM \`" + PROJECT + ".analytics.users\`" +
                " WHERE user_id = '" + userId + "'";

  const [rows] = await bq.query({ query });
  console.log(rows);
}`,

  "src/pipelines/etl_runner.py": `import boto3

# Hardcoded AWS credentials — use IAM role
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

def run_pipeline(formula: str, bucket: str):
    # Arbitrary code execution via eval
    result = eval(formula)

    s3 = boto3.client(
        "s3",
        aws_access_key_id=AWS_ACCESS_KEY,
        aws_secret_access_key=AWS_SECRET_KEY,
    )
    s3.put_object(Bucket=bucket, Key="output.json", Body=str(result))
    return result`,

  "src/storage/s3_client.py": `import boto3

# Hardcoded AWS credentials — use IAM role or instance profile
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
BUCKET_NAME    = "prod-data-bucket"

def upload_file(file_path: str, key: str) -> bool:
    s3 = boto3.client(
        "s3",
        aws_access_key_id=AWS_ACCESS_KEY,
        aws_secret_access_key=AWS_SECRET_KEY,
    )
    s3.upload_file(file_path, BUCKET_NAME, key)
    return True`,

  "src/models/inference_engine.py": `import numpy as np

# Hardcoded model API key — should use env var
MODEL_API_KEY = "sk-prod-ml-inference-2024"
DB_PASSWORD   = "ml_db_prod_password"

class InferenceEngine:
    def predict(self, user_input: str) -> dict:
        # AI-generated: arbitrary code execution via eval
        result = eval(user_input)

        # SQL injection: user_input injected directly
        query = f"SELECT * FROM predictions WHERE input = '{user_input}'"
        self.cursor.execute(query)
        return {"result": result}

    def load_model(self, formula: str):
        # exec on user-provided formula string — RCE risk
        exec(formula)`,

  "src/training/data_pipeline.py": `import boto3, os

# Hardcoded AWS credentials — should use IAM role
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

def process_training_data(transform_fn: str, bucket: str) -> dict:
    # eval() on user-supplied transform — arbitrary code execution
    transform = eval(transform_fn)

    s3 = boto3.client(
        "s3",
        aws_access_key_id=AWS_ACCESS_KEY,
        aws_secret_access_key=AWS_SECRET_KEY,
    )
    obj = s3.get_object(Bucket=bucket, Key="training_data.jsonl")
    return transform(obj["Body"].read())`,

  "src/serving/model_server.py": `from flask import Flask, request, jsonify

app = Flask(__name__)

# Hardcoded model endpoint key
API_KEY = "sk-serving-prod-2024"

@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json()
    user_formula = data.get("formula", "")

    # CRITICAL: eval on user-controlled formula — RCE
    result = eval(user_formula)
    return jsonify({"prediction": result})

@app.route("/health")
def health():
    return {"status": "ok"}`,

  "src/middleware/auth_interceptor.ts": `import jwt from "jsonwebtoken";

// Hardcoded signing secret — use environment variable
const SIGNING_KEY = "api_gateway_secret_2024";

export async function authInterceptor(req: Request): Promise<boolean> {
  const token = req.headers.get("X-Auth-Token");
  if (!token) return false;

  // VULNERABLE: "none" algorithm accepted — token forgery possible
  const decoded = jwt.verify(token, SIGNING_KEY, {
    algorithms: ["RS256", "none"],
  });

  return !!decoded;
}`,

  "src/routes/api_router.ts": `import { Router } from "express";

// API router — registers all endpoint handlers
const router = Router();

router.get("/health",      (req, res) => res.json({ status: "ok" }));
router.get("/version",     (req, res) => res.json({ version: "1.0.0" }));
router.post("/scan",       handleScan);
router.post("/attest",     handleAttest);
router.get("/reports/:id", handleReport);

function handleScan(req: any, res: any) {
  const { repo, pr, files } = req.body;
  res.json({ scan_id: \`sc_\${Date.now()}\`, repo, pr, status: "queued" });
}

function handleAttest(req: any, res: any) {
  const { scan_id, file_path, reviewer } = req.body;
  res.json({ attested: true, scan_id, file_path, reviewer });
}

function handleReport(req: any, res: any) {
  res.json({ report_id: req.params.id, status: "generated" });
}

export default router;`,

  "src/notifications/email_client.ts": `import sendgrid from "@sendgrid/mail";

// Hardcoded SendGrid API key — must use environment variable
const SENDGRID_KEY = "SG.Gm9kXtestABCDEFGHIJKLMNOP";

sendgrid.setApiKey(SENDGRID_KEY);

export async function sendEmail(to: string, subject: string, body: string): Promise<void> {
  await sendgrid.send({
    to, from: "alerts@internal.io",
    subject, text: body,
  });
}`,

  "src/config/thresholds.ts": `// Risk threshold configuration
// These values control when alerts are triggered.

export const THRESHOLDS = {
  ai_content_critical: 0.85,
  ai_content_high:     0.70,
  attestation_sla_h:   24,
  min_attestation_pct: 0.60,
};`,

  "src/engines/scoring_engine.py": `# Scoring engine — computes risk scores for transactions
# All parameters are read from configuration at startup.

def score_transaction(amount: float, velocity: int, country: str) -> float:
    score = 0.0
    if amount > 1000:
        score += 0.3
    if velocity > 10:
        score += 0.4
    if country not in ["US", "CA", "GB", "DE"]:
        score += 0.3
    return min(score, 1.0)`,

  "src/alerts/slack_notifier.py": `import requests

# Slack webhook URL
SLACK_WEBHOOK = "https://hooks.slack.com/services/T001/B001/xyz"

def notify(message: str, severity: str = "info") -> bool:
    emoji = {"critical": ":red_circle:", "high": ":orange_circle:", "info": ":white_circle:"}.get(severity, ":white_circle:")
    payload = {"text": f"{emoji} {message}"}
    resp = requests.post(SLACK_WEBHOOK, json=payload)
    return resp.status_code == 200`,

  "src/api/risk_api.ts": `import { Router } from "express";
import { calculateCreditScore } from "../models/credit_score";

// Risk API router
const router = Router();

router.get("/score/:userId", async (req, res) => {
  const { userId } = req.params;
  const factors = await getRiskFactors(userId);
  const score   = calculateCreditScore(factors);
  res.json({ userId, score, timestamp: new Date().toISOString() });
});

router.post("/flag", async (req, res) => {
  const { userId, reason } = req.body;
  await flagUser(userId, reason);
  res.json({ flagged: true });
});

export default router;`,

  "src/utils/data_cleaner.py": `# Data cleaning utilities
# Removes duplicates, normalises strings, and validates schema.

import re

def clean_record(record: dict) -> dict:
    cleaned = {}
    for key, value in record.items():
        if isinstance(value, str):
            cleaned[key] = value.strip().lower()
        else:
            cleaned[key] = value
    return cleaned

def remove_duplicates(records: list) -> list:
    seen = set()
    unique = []
    for r in records:
        key = str(sorted(r.items()))
        if key not in seen:
            seen.add(key)
            unique.append(r)
    return unique`,

  "src/api/data_api.ts": `import { Router } from "express";

const router = Router();

router.get("/pipelines", (req, res) => {
  res.json({ pipelines: ["etl_runner", "batch_loader", "stream_processor"] });
});

router.post("/pipelines/:id/run", (req, res) => {
  const { id } = req.params;
  res.json({ pipeline: id, status: "started", run_id: \`run_\${Date.now()}\` });
});

export default router;`,

  "src/utils/request_validator.ts": `// Request validation utilities
// Validates incoming API request payloads against expected schemas.

export function validateScanRequest(body: unknown): { valid: boolean; errors: string[] } {
  const errors: string[] = [];
  if (!body || typeof body !== "object") return { valid: false, errors: ["Body must be an object"] };
  const b = body as Record<string, unknown>;
  if (!b.repo || typeof b.repo !== "string")      errors.push("repo is required");
  if (!b.pr   || typeof b.pr   !== "number")      errors.push("pr must be a number");
  if (!b.files || !Array.isArray(b.files))        errors.push("files must be an array");
  return { valid: errors.length === 0, errors };
}`,

  "src/config/model_config.yaml": `# Model configuration
# Controls inference parameters for the ML platform.

model:
  name: risk_classifier_v3
  version: "3.1.2"
  framework: pytorch
  device: cuda

inference:
  batch_size: 32
  max_tokens: 512
  temperature: 0.1
  timeout_ms: 5000

thresholds:
  high_risk: 0.85
  medium_risk: 0.60
  low_risk: 0.30`,

  "src/handlers/profile_update.ts": `import jwt from "jsonwebtoken";

// Hardcoded signing secret — use process.env.JWT_SECRET
const JWT_SECRET    = "user_service_jwt_secret_2024";
const INTERNAL_KEY  = "user_svc_internal_api_key";

export async function handleProfileUpdate(req: Request): Promise<Response> {
  const token = req.headers.get("Authorization")?.replace("Bearer ", "");
  if (!token) return new Response("Unauthorized", { status: 401 });

  // VULNERABLE: accepts "none" algorithm — any token passes
  const payload = jwt.verify(token, JWT_SECRET, {
    algorithms: ["HS256", "none"],
  }) as { sub: string; role: string };

  const body = await req.json();

  // AI-generated: eval on user-supplied formula — RCE risk
  if (body.computedField) {
    const value = eval(body.computedField);
    body.score = value;
  }

  const res = await fetch("/internal/users/" + payload.sub, {
    method: "PATCH",
    headers: { "X-Internal-Key": INTERNAL_KEY },
    body: JSON.stringify(body),
  });
  return new Response(await res.text(), { status: res.status });
}`,

  "src/providers/email_sender.py": `import sendgrid
from sendgrid.helpers.mail import Mail

# Hardcoded SendGrid API key — use environment variable
SENDGRID_KEY   = "SG.notification_svc_prod_key_2024"
FROM_EMAIL     = "no-reply@internal.io"

def send_notification(to_email: str, subject: str, user_data: dict) -> bool:
    sg = sendgrid.SendGridAPIClient(api_key=SENDGRID_KEY)

    # XSS risk: user_data["name"] interpolated directly into HTML body
    html_body = f"""
    <html><body>
      <h1>Hello, {user_data['name']}!</h1>
      <p>{user_data.get('message', 'You have a new notification.')}</p>
    </body></html>
    """

    message = Mail(
        from_email=FROM_EMAIL,
        to_emails=to_email,
        subject=subject,
        html_content=html_body,
    )
    response = sg.send(message)
    return response.status_code == 202`,

  "src/templates/render_engine.ts": `// Template rendering engine for notification emails

// Hardcoded API key — should use process.env.TEMPLATE_API_KEY
const TEMPLATE_KEY = "tmpl_notification_svc_prod_2024";

export function renderTemplate(templateId: string, variables: Record<string, string>): string {
  let template = fetchTemplate(templateId);

  // XSS: variables injected directly without sanitization
  for (const [key, value] of Object.entries(variables)) {
    template = template.split(\`{{\${key}}}\`).join(value);
  }

  return template;
}

export function renderAndSend(to: string, templateId: string, vars: Record<string, string>): void {
  const html = renderTemplate(templateId, vars);

  // AI-generated: eval to handle dynamic expressions in templates
  const processed = html.replace(/\{\{eval:(.*?)\}\}/g, (_, expr) => String(eval(expr)));

  fetch("https://api.sendgrid.com/v3/mail/send", {
    method: "POST",
    headers: { "Authorization": "Bearer " + TEMPLATE_KEY },
    body: JSON.stringify({ to, html_content: processed }),
  });
}

function fetchTemplate(id: string): string {
  return \`<p>Template \${id}</p>\`;
}`,

  "pkg/orders/handler.go": `package orders

import (
\t"database/sql"
\t"encoding/json"
\t"fmt"
\t"net/http"
)

// Hardcoded DB credentials — use environment variables or secrets manager
const (
\tDBPassword = "orders_db_prod_2024"
\tDBDSN      = "postgres://admin:" + DBPassword + "@prod-db.internal/orders"
)

func HandleGetOrder(w http.ResponseWriter, r *http.Request) {
\torderID := r.URL.Query().Get("id")
\tuserID  := r.URL.Query().Get("user_id")

\tdb, err := sql.Open("postgres", DBDSN)
\tif err != nil {
\t\thttp.Error(w, "db error", http.StatusInternalServerError)
\t\treturn
\t}
\tdefer db.Close()

\t// SQL injection: orderID and userID injected directly into query
\tquery := fmt.Sprintf(
\t\t"SELECT * FROM orders WHERE id = '%s' AND user_id = '%s'",
\t\torderID, userID,
\t)
\trows, err := db.Query(query)
\tif err != nil {
\t\thttp.Error(w, "query error", http.StatusInternalServerError)
\t\treturn
\t}
\tdefer rows.Close()

\tvar results []map[string]interface{}
\tjson.NewEncoder(w).Encode(results)
}`,

  "internal/db/queries.go": `package db

import (
\t"database/sql"
\t"fmt"
)

// Hardcoded production credentials — use env vars or AWS Secrets Manager
const (
\tDBHost     = "prod-db.internal"
\tDBPort     = 5432
\tDBUser     = "app_admin"
\tDBPassword = "prod_db_password_2024"
\tDBName     = "orders"
)

func Connect() (*sql.DB, error) {
\tdsn := fmt.Sprintf(
\t\t"host=%s port=%d user=%s password=%s dbname=%s sslmode=require",
\t\tDBHost, DBPort, DBUser, DBPassword, DBName,
\t)
\treturn sql.Open("postgres", dsn)
}

// SQL injection: userID not parameterized — use db.QueryContext with $1 placeholder
func GetOrdersByUser(db *sql.DB, userID string) (*sql.Rows, error) {
\tquery := fmt.Sprintf("SELECT * FROM orders WHERE user_id = '%s'", userID)
\treturn db.Query(query)
}

func GetOrderByID(db *sql.DB, orderID string, status string) (*sql.Rows, error) {
\t// SQL injection: both params concatenated
\tquery := fmt.Sprintf(
\t\t"SELECT * FROM orders WHERE id = '%s' AND status = '%s'",
\t\torderID, status,
\t)
\treturn db.Query(query)
}`,

  "src/main/java/billing/PaymentProcessor.java": `package billing;

import java.net.URI;
import java.net.http.*;
import java.sql.Connection;

public class PaymentProcessor {
    // Hardcoded Stripe API key — use environment variable STRIPE_SECRET_KEY
    private static final String STRIPE_KEY      = "sk_live_51Hx2billing_prod_key";
    private static final String WEBHOOK_SECRET  = "whsec_billing_webhook_2024";

    public ChargeResult charge(String customerId, long amountCents, String currency) throws Exception {
        HttpClient client = HttpClient.newHttpClient();
        String body = String.format(
            "{\"customer\":\"%s\",\"amount\":%d,\"currency\":\"%s\"}",
            customerId, amountCents, currency
        );
        HttpRequest req = HttpRequest.newBuilder()
            .uri(URI.create("https://api.stripe.com/v1/charges"))
            .header("Authorization", "Bearer " + STRIPE_KEY)
            .POST(HttpRequest.BodyPublishers.ofString(body))
            .build();
        HttpResponse<String> res = client.send(req, HttpResponse.BodyHandlers.ofString());
        return parseChargeResult(res.body());
    }

    // SQL injection: customerId concatenated into query string
    public void logCharge(Connection conn, String customerId, long amount) throws Exception {
        String sql = "INSERT INTO charge_log (customer_id, amount) VALUES ('"
                   + customerId + "', " + amount + ")";
        conn.createStatement().execute(sql);
    }

    private ChargeResult parseChargeResult(String json) { return new ChargeResult(); }
    public static class ChargeResult {}
}`,

  "src/main/java/billing/InvoiceService.java": `package billing;

import java.sql.*;

public class InvoiceService {
    private final Connection conn;

    public InvoiceService(Connection conn) {
        this.conn = conn;
    }

    // SQL injection: invoiceId and customerId concatenated directly
    public Invoice getInvoice(String invoiceId, String customerId) throws SQLException {
        String sql = "SELECT * FROM invoices WHERE id = '" + invoiceId
                   + "' AND customer_id = '" + customerId + "'";
        ResultSet rs = conn.createStatement().executeQuery(sql);
        if (rs.next()) {
            return new Invoice(rs.getString("id"), rs.getLong("amount"), rs.getString("status"));
        }
        return null;
    }

    // SQL injection: status filter not parameterized
    public ResultSet listInvoices(String customerId, String status) throws SQLException {
        String query = "SELECT * FROM invoices WHERE customer_id = '" + customerId
                     + "' AND status = '" + status + "'";
        return conn.createStatement().executeQuery(query);
    }

    public static class Invoice {
        public final String id;
        public final long amount;
        public final String status;
        Invoice(String id, long amount, String status) {
            this.id = id; this.amount = amount; this.status = status;
        }
    }
}`,

  "src/crypto/hash.rs": `use md5;
use sha1::{Digest, Sha1};

// Hardcoded salt — each user should have a unique random salt stored in DB
const STATIC_SALT: &str = "trustledger_static_salt_2024";
// Hardcoded signing key — use env var or secrets manager
const SECRET_KEY: &str  = "cli_tools_signing_key_prod";

/// Hash a password using MD5 — weak algorithm, use Argon2id or bcrypt instead
pub fn hash_password(password: &str) -> String {
    let input = format!("{}{}", STATIC_SALT, password);
    let digest = md5::compute(input.as_bytes());
    format!("{:x}", digest)
}

/// Sign payload with SHA-1 HMAC — insufficient strength, use HMAC-SHA256 minimum
pub fn sign_token(payload: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(format!("{}{}", SECRET_KEY, payload).as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Timing side-channel: == comparison is not constant-time
/// Use subtle::ConstantTimeEq instead
pub fn verify_token(payload: &str, provided_sig: &str) -> bool {
    let expected = sign_token(payload);
    expected == provided_sig
}`,

  "src/net/http_client.rs": `use std::collections::HashMap;

// Hardcoded bearer token — use env var or secrets manager
const INTERNAL_API_TOKEN: &str = "Bearer cli_tools_internal_api_2024";
// Plaintext HTTP endpoint — all traffic observable on the wire, use HTTPS
const METRICS_ENDPOINT: &str   = "http://metrics.internal/report";
const TRACE_ENDPOINT: &str     = "http://tracing.internal/spans";

pub async fn send_metrics(data: &HashMap<String, f64>) -> Result<(), String> {
    let client = reqwest::Client::new();

    // Plaintext HTTP: credentials and payload transmitted unencrypted
    let response = client
        .post(METRICS_ENDPOINT)
        .header("Authorization", INTERNAL_API_TOKEN)
        .json(data)
        .send()
        .await
        .map_err(|e| e.to_string())?;

    if !response.status().is_success() {
        return Err(format!("metrics push failed: {}", response.status()));
    }
    Ok(())
}

pub fn build_auth_header() -> String {
    // Token embedded in source — rotate and move to environment variable
    INTERNAL_API_TOKEN.to_string()
}`,

  // Larger, mixed human/AI-authored files (see src/lib/seedFileSamples.ts)
  ...SEED_FILE_SAMPLES,
};

// ── Demo scan data (used when backend is offline / mock ID) ──────────────────

// Enrich a file object with content from MOCK_FILE_CONTENT if not already set
function withContent(f: Omit<FileResult, "risk_score"> & { risk_score: string }): FileResult {
  return { ...f, risk_score: f.risk_score as RiskLevel, content: f.content ?? MOCK_FILE_CONTENT[f.file_path] };
}

function makeMockScans(): Record<string, ScanResult> {
  const o = ORG;
  return {
  "sc_mock_001": {
    scan_id:"sc_mock_001", repo:`${o}/payments-api`, pr_number:482,
    commit_sha:"a3f9c21d", overall_risk:"CRITICAL", total_ai_percentage:0.71,
    timestamp:"2026-05-26T14:32:00Z",
    files:[
      { file_path:"src/processors/card_validator.py",  language:"python",     ai_percentage:0.91, risk_score:"CRITICAL", risk_indicators:["sql-injection","hardcoded-secret","eval-exec","identifier-entropy"], attested:false },
      { file_path:"src/gateway/stripe_client.py",       language:"python",     ai_percentage:0.76, risk_score:"HIGH",     risk_indicators:["hardcoded-secret","ai-comment-pattern"],      attested:false },
      { file_path:"src/api/refund_handler.py",          language:"python",     ai_percentage:0.55, risk_score:"MEDIUM",   risk_indicators:["ai-comment-pattern","comment-density"],       attested:true  },
      { file_path:"src/models/transaction.py",          language:"python",     ai_percentage:0.44, risk_score:"MEDIUM",   risk_indicators:["structural-uniformity","identifier-entropy"],  attested:true  },
      { file_path:"src/utils/currency_formatter.py",   language:"python",     ai_percentage:0.21, risk_score:"LOW",      risk_indicators:["comment-density"],                            attested:true  },
      { file_path:"src/middleware/auth_check.ts",       language:"typescript", ai_percentage:0.63, risk_score:"HIGH",     risk_indicators:["jwt-none-alg","hardcoded-secret"],             attested:false },
      { file_path:"src/services/payment_service.ts",   language:"typescript", ai_percentage:0.82, risk_score:"HIGH",     risk_indicators:["eval-exec","structural-uniformity","ai-comment-pattern"], attested:false },
    ].map(withContent),
  },
  "sc_mock_002": {
    scan_id:"sc_mock_002", repo:`${o}/auth-service`, pr_number:341,
    commit_sha:"b7e2d94a", overall_risk:"HIGH", total_ai_percentage:0.44,
    timestamp:"2026-05-25T11:00:00Z",
    files:[
      { file_path:"src/oauth/token_exchange.ts",        language:"typescript", ai_percentage:0.68, risk_score:"HIGH",     risk_indicators:["jwt-none-alg"],           attested:true  },
      { file_path:"src/auth/token_service.py",          language:"python",     ai_percentage:0.59, risk_score:"HIGH",     risk_indicators:["hardcoded-secret"],       attested:false },
      { file_path:"src/middleware/rate_limiter.ts",     language:"typescript", ai_percentage:0.49, risk_score:"MEDIUM",   risk_indicators:["structural-uniformity"],  attested:true  },
      { file_path:"src/notifications/email_client.ts",  language:"typescript", ai_percentage:0.31, risk_score:"LOW",      risk_indicators:["ai-comment-pattern"],     attested:true  },
    ].map(withContent),
  },
  "sc_mock_003": {
    scan_id:"sc_mock_003", repo:`${o}/fraud-detection`, pr_number:219,
    commit_sha:"c4a1f83b", overall_risk:"CRITICAL", total_ai_percentage:0.58,
    timestamp:"2026-05-26T10:05:00Z",
    files:[
      { file_path:"models/risk_scorer.ts",              language:"typescript", ai_percentage:0.83, risk_score:"CRITICAL", risk_indicators:["eval-exec","structural-uniformity"],           attested:false },
      { file_path:"src/rules/velocity_check.py",        language:"python",     ai_percentage:0.62, risk_score:"HIGH",     risk_indicators:["sql-injection"],                              attested:true  },
      { file_path:"src/utils/feature_extractor.py",    language:"python",     ai_percentage:0.38, risk_score:"LOW",      risk_indicators:["comment-density"],                            attested:true  },
      { file_path:"src/database/connection.py",         language:"python",     ai_percentage:0.71, risk_score:"HIGH",     risk_indicators:["hardcoded-secret"],                           attested:false },
      { file_path:"src/config/thresholds.ts",           language:"typescript", ai_percentage:0.14, risk_score:"LOW",      risk_indicators:["ai-comment-pattern"],                         attested:true  },
    ].map(withContent),
  },
  "sc_mock_004": {
    scan_id:"sc_mock_004", repo:`${o}/risk-engine`, pr_number:88,
    commit_sha:"d9b5e12f", overall_risk:"MEDIUM", total_ai_percentage:0.36,
    timestamp:"2026-05-24T16:00:00Z",
    files:[
      { file_path:"src/models/credit_score.ts",         language:"typescript", ai_percentage:0.41, risk_score:"MEDIUM",   risk_indicators:["identifier-entropy"],     attested:true  },
      { file_path:"src/engines/scoring_engine.py",      language:"python",     ai_percentage:0.28, risk_score:"LOW",      risk_indicators:["comment-density"],        attested:true  },
      { file_path:"src/alerts/slack_notifier.py",       language:"python",     ai_percentage:0.37, risk_score:"LOW",      risk_indicators:["ai-comment-pattern"],     attested:true  },
      { file_path:"src/api/risk_api.ts",               language:"typescript", ai_percentage:0.44, risk_score:"MEDIUM",   risk_indicators:["structural-uniformity"],  attested:false },
    ].map(withContent),
  },
  "sc_mock_005": {
    scan_id:"sc_mock_005", repo:`${o}/data-platform`, pr_number:118,
    commit_sha:"e2c8a47d", overall_risk:"HIGH", total_ai_percentage:0.67,
    timestamp:"2026-05-27T14:00:00Z",
    files:[
      { file_path:"src/connectors/bigquery_writer.ts",  language:"typescript", ai_percentage:0.83, risk_score:"HIGH",     risk_indicators:["hardcoded-secret","sql-injection"],           attested:false },
      { file_path:"src/pipelines/etl_runner.py",        language:"python",     ai_percentage:0.65, risk_score:"HIGH",     risk_indicators:["eval-exec"],                                  attested:false },
      { file_path:"src/storage/s3_client.py",           language:"python",     ai_percentage:0.58, risk_score:"MEDIUM",   risk_indicators:["hardcoded-secret"],                           attested:false },
      { file_path:"src/utils/data_cleaner.py",          language:"python",     ai_percentage:0.33, risk_score:"LOW",      risk_indicators:["comment-density"],                            attested:true  },
      { file_path:"src/api/data_api.ts",                language:"typescript", ai_percentage:0.48, risk_score:"LOW",      risk_indicators:["structural-uniformity"],                      attested:true  },
    ].map(withContent),
  },
  "sc_mock_006": {
    scan_id:"sc_mock_006", repo:`${o}/ml-platform`, pr_number:88,
    commit_sha:"3f9d2c1a", overall_risk:"CRITICAL", total_ai_percentage:0.82,
    timestamp:"2026-05-29T10:00:00Z",
    files:[
      { file_path:"src/models/inference_engine.py",     language:"python",     ai_percentage:0.91, risk_score:"CRITICAL", risk_indicators:["eval-exec","hardcoded-secret","sql-injection"],attested:false },
      { file_path:"src/training/data_pipeline.py",      language:"python",     ai_percentage:0.85, risk_score:"HIGH",     risk_indicators:["hardcoded-secret","sql-injection"],           attested:false },
      { file_path:"src/serving/model_server.py",        language:"python",     ai_percentage:0.78, risk_score:"HIGH",     risk_indicators:["eval-exec"],                                  attested:false },
      { file_path:"src/utils/feature_extractor.py",     language:"python",     ai_percentage:0.61, risk_score:"MEDIUM",   risk_indicators:["structural-uniformity"],                      attested:false },
      { file_path:"src/config/model_config.yaml",       language:"yaml",       ai_percentage:0.22, risk_score:"LOW",      risk_indicators:["ai-comment-pattern"],                         attested:true  },
    ].map(withContent),
  },
  "sc_mock_007": {
    scan_id:"sc_mock_007", repo:`${o}/api-gateway`, pr_number:203,
    commit_sha:"8b1e4f9c", overall_risk:"HIGH", total_ai_percentage:0.52,
    timestamp:"2026-05-30T09:00:00Z",
    files:[
      { file_path:"src/middleware/auth_interceptor.ts", language:"typescript", ai_percentage:0.79, risk_score:"HIGH",     risk_indicators:["jwt-none-alg","hardcoded-secret"],            attested:true  },
      { file_path:"src/routes/api_router.ts",           language:"typescript", ai_percentage:0.58, risk_score:"MEDIUM",   risk_indicators:["structural-uniformity"],                      attested:true  },
      { file_path:"src/utils/request_validator.ts",     language:"typescript", ai_percentage:0.44, risk_score:"LOW",      risk_indicators:["comment-density"],                            attested:true  },
    ].map(withContent),
  },
  };
}
// ── Extended mock params for sc_mock_008–023 (referenced from /scans page) ───
// Each entry matches exactly the ScanSummary in the scans page mock data.
// Files are synthesised from repo + risk pattern — enough to review & attest.

interface MockParam {
  repo: string; pr: number; sha: string; branch: string;
  risk: RiskLevel; aiPct: number;
  files: { path: string; lang: string; ai: number; risk: RiskLevel; risks: string[]; attested: boolean }[];
}

function extendedMockScans(): Record<string, ScanResult> {
  const o = ORG;
  const params: Record<string, MockParam> = {
    "sc_mock_008": { repo:`${o}/payments-api`,    pr:479, sha:"m1n2o3p", branch:"fix/stripe-client",        risk:"HIGH",     aiPct:0.67, files:[
      { path:"src/gateway/stripe_client.py",      lang:"python",     ai:0.76, risk:"HIGH",   risks:["hardcoded-secret","sql-injection"],           attested:false },
      { path:"src/gateway/webhook_handler.py",    lang:"python",     ai:0.62, risk:"MEDIUM", risks:["structural-uniformity"],                      attested:false },
      { path:"src/utils/signature_verify.ts",     lang:"typescript", ai:0.41, risk:"LOW",    risks:["ai-comment-pattern"],                         attested:false },
    ]},
    "sc_mock_009": { repo:`${o}/payments-api`,    pr:477, sha:"c4d5e6f", branch:"feat/refund-handler",      risk:"MEDIUM",   aiPct:0.55, files:[
      { path:"src/api/refund_handler.py",         lang:"python",     ai:0.55, risk:"MEDIUM", risks:["structural-uniformity"],                      attested:true  },
      { path:"src/api/refund_validator.py",       lang:"python",     ai:0.48, risk:"MEDIUM", risks:["identifier-entropy"],                         attested:true  },
      { path:"src/models/refund.ts",              lang:"typescript", ai:0.39, risk:"LOW",    risks:["ai-comment-pattern"],                         attested:true  },
      { path:"src/utils/currency.py",             lang:"python",     ai:0.31, risk:"LOW",    risks:["comment-density"],                            attested:true  },
      { path:"src/tests/test_refund.py",          lang:"python",     ai:0.22, risk:"LOW",    risks:["ai-comment-pattern"],                         attested:true  },
    ]},
    "sc_mock_010": { repo:`${o}/risk-engine`,     pr:85,  sha:"g7h8i9j", branch:"feat/scoring-engine",      risk:"LOW",      aiPct:0.28, files:[
      { path:"src/engine/scoring_engine.ts",      lang:"typescript", ai:0.28, risk:"LOW",    risks:["ai-comment-pattern"],                         attested:true  },
      { path:"src/engine/rule_parser.ts",         lang:"typescript", ai:0.31, risk:"LOW",    risks:["comment-density"],                            attested:true  },
      { path:"src/utils/math_helpers.ts",         lang:"typescript", ai:0.19, risk:"LOW",    risks:["structural-uniformity"],                      attested:true  },
    ]},
    "sc_mock_011": { repo:`${o}/auth-service`,    pr:336, sha:"k1l2m3n", branch:"fix/rate-limiter",         risk:"LOW",      aiPct:0.22, files:[
      { path:"src/middleware/rate_limiter.ts",    lang:"typescript", ai:0.22, risk:"LOW",    risks:["ai-comment-pattern"],                         attested:true  },
      { path:"src/middleware/ip_blocklist.ts",    lang:"typescript", ai:0.18, risk:"LOW",    risks:["comment-density"],                            attested:true  },
      { path:"src/utils/throttle.ts",             lang:"typescript", ai:0.14, risk:"LOW",    risks:["structural-uniformity"],                      attested:true  },
    ]},
    "sc_mock_012": { repo:`${o}/payments-api`,    pr:471, sha:"o4p5q6r", branch:"feat/currency-formatter",  risk:"MEDIUM",   aiPct:0.34, files:[
      { path:"src/utils/currency_formatter.py",   lang:"python",     ai:0.34, risk:"MEDIUM", risks:["identifier-entropy"],                         attested:true  },
      { path:"src/utils/locale_helper.py",        lang:"python",     ai:0.28, risk:"LOW",    risks:["ai-comment-pattern"],                         attested:true  },
      { path:"src/utils/number_format.ts",        lang:"typescript", ai:0.22, risk:"LOW",    risks:["comment-density"],                            attested:true  },
      { path:"src/tests/test_currency.py",        lang:"python",     ai:0.19, risk:"LOW",    risks:["structural-uniformity"],                      attested:true  },
      { path:"src/types/currency_types.ts",       lang:"typescript", ai:0.14, risk:"LOW",    risks:["ai-comment-pattern"],                         attested:true  },
    ]},
    "sc_mock_013": { repo:`${o}/data-platform`,   pr:101, sha:"s7t8u9v", branch:"fix/ai-threshold",         risk:"HIGH",     aiPct:0.81, files:[
      { path:"src/pipelines/ai_threshold.py",     lang:"python",     ai:0.81, risk:"HIGH",   risks:["hardcoded-secret","eval-exec"],               attested:false },
      { path:"src/pipelines/data_validator.py",   lang:"python",     ai:0.74, risk:"HIGH",   risks:["sql-injection"],                             attested:false },
      { path:"src/config/threshold_config.py",    lang:"python",     ai:0.52, risk:"MEDIUM", risks:["structural-uniformity"],                      attested:true  },
      { path:"src/utils/pipeline_utils.ts",       lang:"typescript", ai:0.38, risk:"LOW",    risks:["ai-comment-pattern"],                         attested:true  },
    ]},
    "sc_mock_014": { repo:`${o}/fraud-detection`, pr:218, sha:"w1x2y3z", branch:"feat/velocity-check",      risk:"HIGH",     aiPct:0.62, files:[
      { path:"src/rules/velocity_check.py",       lang:"python",     ai:0.62, risk:"HIGH",   risks:["sql-injection","hardcoded-secret"],           attested:true  },
      { path:"src/rules/transaction_limits.py",   lang:"python",     ai:0.55, risk:"MEDIUM", risks:["structural-uniformity"],                      attested:true  },
      { path:"src/models/velocity_model.ts",      lang:"typescript", ai:0.44, risk:"MEDIUM", risks:["identifier-entropy"],                         attested:true  },
      { path:"src/utils/time_window.ts",          lang:"typescript", ai:0.29, risk:"LOW",    risks:["ai-comment-pattern"],                         attested:true  },
    ]},
    "sc_mock_015": { repo:`${o}/auth-service`,    pr:0,   sha:"a4b5c6d", branch:"main",                    risk:"LOW",      aiPct:0.18, files:[
      { path:"src/auth/session_manager.ts",       lang:"typescript", ai:0.18, risk:"LOW",    risks:["ai-comment-pattern"],                         attested:true  },
      { path:"src/auth/token_store.ts",           lang:"typescript", ai:0.15, risk:"LOW",    risks:["structural-uniformity"],                      attested:true  },
      { path:"src/utils/crypto_helpers.ts",       lang:"typescript", ai:0.12, risk:"LOW",    risks:["comment-density"],                            attested:true  },
    ]},
    "sc_mock_016": { repo:`${o}/payments-api`,    pr:0,   sha:"e7f8g9h", branch:"main",                    risk:"MEDIUM",   aiPct:0.42, files:[
      { path:"src/api/payment_handler.py",        lang:"python",     ai:0.52, risk:"MEDIUM", risks:["structural-uniformity"],                      attested:true  },
      { path:"src/api/charge_api.py",             lang:"python",     ai:0.48, risk:"MEDIUM", risks:["identifier-entropy"],                         attested:true  },
      { path:"src/models/payment.ts",             lang:"typescript", ai:0.42, risk:"MEDIUM", risks:["ai-comment-pattern"],                         attested:true  },
      { path:"src/services/processor.py",         lang:"python",     ai:0.38, risk:"LOW",    risks:["comment-density"],                            attested:true  },
    ]},
    "sc_mock_017": { repo:`${o}/auth-service`,    pr:345, sha:"b2c3d4e", branch:"feat/mfa-flow",            risk:"HIGH",     aiPct:0.53, files:[
      { path:"src/auth/mfa_handler.ts",           lang:"typescript", ai:0.79, risk:"HIGH",   risks:["hardcoded-secret","jwt-none-alg"],            attested:false },
      { path:"src/auth/totp_validator.ts",        lang:"typescript", ai:0.68, risk:"HIGH",   risks:["eval-exec"],                                 attested:true  },
      { path:"src/auth/backup_codes.ts",          lang:"typescript", ai:0.55, risk:"MEDIUM", risks:["structural-uniformity"],                      attested:true  },
      { path:"src/auth/mfa_setup.ts",             lang:"typescript", ai:0.47, risk:"MEDIUM", risks:["identifier-entropy"],                         attested:true  },
      { path:"src/utils/qr_generator.ts",         lang:"typescript", ai:0.38, risk:"LOW",    risks:["ai-comment-pattern"],                         attested:true  },
      { path:"src/tests/test_mfa.ts",             lang:"typescript", ai:0.21, risk:"LOW",    risks:["comment-density"],                            attested:true  },
    ]},
    "sc_mock_018": { repo:`${o}/risk-engine`,     pr:91,  sha:"f5g6h7i", branch:"feat/ml-pipeline",         risk:"CRITICAL", aiPct:0.84, files:[
      { path:"src/ml/pipeline_runner.py",         lang:"python",     ai:0.94, risk:"CRITICAL",risks:["eval-exec","hardcoded-secret","sql-injection"],attested:false },
      { path:"src/ml/model_loader.py",            lang:"python",     ai:0.87, risk:"CRITICAL",risks:["hardcoded-secret","eval-exec"],               attested:false },
      { path:"src/ml/feature_pipeline.py",        lang:"python",     ai:0.79, risk:"HIGH",   risks:["sql-injection"],                             attested:false },
      { path:"src/ml/data_preprocessor.py",       lang:"python",     ai:0.71, risk:"HIGH",   risks:["structural-uniformity"],                      attested:false },
      { path:"src/ml/inference_client.ts",        lang:"typescript", ai:0.63, risk:"MEDIUM", risks:["identifier-entropy"],                         attested:false },
      { path:"src/ml/schema_validator.ts",        lang:"typescript", ai:0.55, risk:"MEDIUM", risks:["structural-uniformity"],                      attested:false },
      { path:"src/config/ml_config.py",           lang:"python",     ai:0.44, risk:"MEDIUM", risks:["hardcoded-secret"],                           attested:false },
      { path:"src/utils/tensor_utils.py",         lang:"python",     ai:0.31, risk:"LOW",    risks:["ai-comment-pattern"],                         attested:false },
      { path:"src/tests/test_pipeline.py",        lang:"python",     ai:0.19, risk:"LOW",    risks:["comment-density"],                            attested:false },
    ]},
    "sc_mock_019": { repo:`${o}/data-platform`,   pr:0,   sha:"j8k9l0m", branch:"main",                    risk:"LOW",      aiPct:0.19, files:[
      { path:"src/pipelines/etl_runner.py",       lang:"python",     ai:0.65, risk:"HIGH",   risks:["sql-injection"],                             attested:false },
      { path:"src/pipelines/batch_processor.py",  lang:"python",     ai:0.22, risk:"LOW",    risks:["ai-comment-pattern"],                         attested:true  },
      { path:"src/utils/data_types.ts",           lang:"typescript", ai:0.15, risk:"LOW",    risks:["comment-density"],                            attested:true  },
    ]},
    "sc_mock_020": { repo:`${o}/fraud-detection`, pr:215, sha:"n1o2p3q", branch:"fix/duplicate-tx",         risk:"HIGH",     aiPct:0.49, files:[
      { path:"src/checks/duplicate_detector.py",  lang:"python",     ai:0.49, risk:"HIGH",   risks:["sql-injection","hardcoded-secret"],           attested:true  },
      { path:"src/checks/hash_comparator.py",     lang:"python",     ai:0.41, risk:"MEDIUM", risks:["structural-uniformity"],                      attested:true  },
      { path:"src/utils/tx_fingerprint.ts",       lang:"typescript", ai:0.28, risk:"LOW",    risks:["ai-comment-pattern"],                         attested:true  },
    ]},
    "sc_mock_021": { repo:`${o}/payments-api`,    pr:474, sha:"r4s5t6u", branch:"feat/payout-scheduler",    risk:"MEDIUM",   aiPct:0.41, files:[
      { path:"src/scheduler/payout_scheduler.py", lang:"python",     ai:0.41, risk:"MEDIUM", risks:["identifier-entropy"],                         attested:true  },
      { path:"src/scheduler/cron_manager.py",     lang:"python",     ai:0.38, risk:"LOW",    risks:["ai-comment-pattern"],                         attested:true  },
      { path:"src/models/schedule_model.ts",      lang:"typescript", ai:0.32, risk:"LOW",    risks:["structural-uniformity"],                      attested:true  },
      { path:"src/utils/timezone_helper.py",      lang:"python",     ai:0.28, risk:"LOW",    risks:["comment-density"],                            attested:true  },
      { path:"src/tests/test_scheduler.py",       lang:"python",     ai:0.19, risk:"LOW",    risks:["ai-comment-pattern"],                         attested:true  },
    ]},
    "sc_mock_022": { repo:`${o}/risk-engine`,     pr:82,  sha:"v7w8x9y", branch:"chore/lint-fixes",         risk:"LOW",      aiPct:0.14, files:[
      { path:"src/utils/lint_fixes.ts",           lang:"typescript", ai:0.14, risk:"LOW",    risks:["ai-comment-pattern"],                         attested:true  },
      { path:"src/config/eslint_rules.ts",        lang:"typescript", ai:0.11, risk:"LOW",    risks:["comment-density"],                            attested:true  },
    ]},
    "sc_mock_023": { repo:`${o}/fraud-detection`, pr:212, sha:"z0a1b2c", branch:"feat/geo-block",           risk:"MEDIUM",   aiPct:0.37, files:[
      { path:"src/rules/geo_blocker.py",          lang:"python",     ai:0.37, risk:"MEDIUM", risks:["structural-uniformity"],                      attested:true  },
      { path:"src/rules/ip_reputation.py",        lang:"python",     ai:0.31, risk:"LOW",    risks:["ai-comment-pattern"],                         attested:true  },
      { path:"src/utils/geoip_lookup.ts",         lang:"typescript", ai:0.24, risk:"LOW",    risks:["comment-density"],                            attested:true  },
      { path:"src/config/geo_rules.ts",           lang:"typescript", ai:0.18, risk:"LOW",    risks:["structural-uniformity"],                      attested:true  },
    ]},
    "sc_mock_024": { repo:`${o}/auth-service`,    pr:338, sha:"y1z2a3b", branch:"chore/deps-update",        risk:"MEDIUM",   aiPct:0.31, files:[
      { path:"src/auth/jwt_verifier.ts",          lang:"typescript", ai:0.31, risk:"MEDIUM", risks:["structural-uniformity"],                      attested:true  },
      { path:"src/middleware/cors_config.ts",     lang:"typescript", ai:0.24, risk:"LOW",    risks:["ai-comment-pattern"],                         attested:true  },
      { path:"src/utils/version_check.ts",        lang:"typescript", ai:0.18, risk:"LOW",    risks:["comment-density"],                            attested:true  },
    ]},
    // Large, mixed human/AI-authored files — exercise AST/SSA/semantic-graph/ML engines on realistic input
    "sc_mock_025": { repo:`${o}/data-platform`,   pr:107, sha:"d3e4f5a", branch:"feat/customer-sync-v2",    risk:"HIGH",     aiPct:0.43, files:[
      { path:"src/pipelines/customer_data_sync.py",   lang:"python",     ai:0.45, risk:"HIGH",   risks:["sql-injection","hardcoded-secret"],          attested:false },
      { path:"src/connectors/order_export_client.ts", lang:"typescript", ai:0.40, risk:"MEDIUM", risks:["hardcoded-secret","ai-comment-pattern"],     attested:true  },
    ]},
  };

  const now = new Date();
  const ts = (daysBack: number) => {
    const d = new Date(now); d.setDate(d.getDate() - daysBack); return d.toISOString();
  };
  const DAY_MAP: Record<string, number> = {
    "sc_mock_008":1, "sc_mock_009":2, "sc_mock_010":5, "sc_mock_011":5,
    "sc_mock_012":6, "sc_mock_013":5, "sc_mock_014":1, "sc_mock_015":3,
    "sc_mock_016":7, "sc_mock_017":0, "sc_mock_018":1, "sc_mock_019":2,
    "sc_mock_020":3, "sc_mock_021":4, "sc_mock_022":6, "sc_mock_023":7,
    "sc_mock_024":2, "sc_mock_025":1,
  };

  const result: Record<string, ScanResult> = {};
  for (const [id, p] of Object.entries(params)) {
    result[id] = {
      scan_id: id,
      repo: p.repo,
      pr_number: p.pr,
      commit_sha: p.sha,
      overall_risk: p.risk,
      total_ai_percentage: p.aiPct,
      timestamp: ts(DAY_MAP[id] ?? 0),
      files: p.files.map(f => withContent({
        file_path: f.path,
        language: f.lang,
        ai_percentage: f.ai,
        risk_score: f.risk,
        risk_indicators: f.risks,
        attested: f.attested,
      })),
    };
  }
  return result;
}

const MOCK_SCANS: Record<string, ScanResult> = { ...makeMockScans(), ...extendedMockScans() };

// ── Page ──────────────────────────────────────────────────────────────────────

function PRDetailContent() {
  const id = (useParams<{ id: string }>() ?? { id: "" }).id;
  const searchParams = useSearchParams();
  const { profile } = useAuth();

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
    // Use demo data immediately for known mock IDs (no backend call needed)
    if (MOCK_SCANS[id]) {
      setScan(MOCK_SCANS[id]);
      return;
    }
    // Check localStorage for a freshly submitted demo scan before hitting the API
    try {
      const local = localStorage.getItem(`tl_demo_scan_${id}`);
      if (local) { setScan(JSON.parse(local) as ScanResult); return; }
    } catch {}

    // Always try the real API first — real scan IDs (UUIDs) resolve here with
    // their actual stored file content. Only fall back to snapshot/mock
    // reconstruction below for synthetic ids (e.g. seeded "sc_NNN") that
    // don't exist as DB rows.
    api.getScan(id)
      .then(setScan)
      .catch(() => {
        // Build a scan from tl_notif_snapshot top_risk_files (seeded/demo ids)
        try {
          const snap = JSON.parse(localStorage.getItem("tl_notif_snapshot") ?? "null");
          const snapFiles = (snap?.top_risk_files as Array<{ scan_id:string; repo:string; file_path:string; ai_pct:number; risk_score:string; attested:boolean; pr_number:number }> ?? [])
            .filter(f => f.scan_id === id);
          if (snapFiles.length > 0) {
            const first = snapFiles[0];
            // Find a mock scan for the same repo to get realistic file content
            const repoName = first.repo.split("/").pop() ?? "";
            const repoMock = Object.values(MOCK_SCANS).find(s => s.repo.includes(repoName)) ?? Object.values(MOCK_SCANS)[0];
            setScan({
              ...repoMock,
              scan_id: id,
              repo: first.repo,
              pr_number: first.pr_number,
              overall_risk: first.risk_score as ScanResult["overall_risk"],
              total_ai_percentage: first.ai_pct,
              // Override files with snapshot files so attesting the right ones
              files: snapFiles.map(f => ({
                file_path: f.file_path,
                language: f.file_path.endsWith(".py") ? "python"
                  : f.file_path.endsWith(".ts") || f.file_path.endsWith(".tsx") ? "typescript"
                  : f.file_path.endsWith(".go") ? "go"
                  : f.file_path.endsWith(".java") ? "java"
                  : f.file_path.endsWith(".rs") ? "rust"
                  : f.file_path.endsWith(".js") || f.file_path.endsWith(".jsx") ? "javascript"
                  : f.file_path.endsWith(".rb") ? "ruby"
                  : f.file_path.endsWith(".kt") || f.file_path.endsWith(".kts") ? "kotlin"
                  : "unknown",
                ai_percentage: f.ai_pct,
                risk_score: f.risk_score as ScanResult["files"][0]["risk_score"],
                risk_indicators: ["hardcoded-secret"],
                attested: f.attested,
                content: MOCK_FILE_CONTENT[f.file_path],
              })),
            });
            return;
          }
        } catch {}

        // Check if any mock scan has a matching scan_id
        const mockFallback = Object.values(MOCK_SCANS).find(s => s.scan_id === id);
        if (mockFallback) { setScan(mockFallback); return; }

        setError("404 Not Found");
      });
  }, [id]);

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
      // Fallback: use MOCK_SCANS file risk_score
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

  function markAttested(path: string) {
    setAttestedSet(s => { const n = new Set(s); n.add(path); return n; });
    if (scan) {
      resolveOneFile(path);
      const email = reviewerEmail || "reviewer@trustledger.dev";
      recordActivityEvent(path, email);

      // Persist to real API (fire-and-forget)
      if (profile?.org_id) {
        authedFetch("/api/attest", {
          method: "POST",
          body:   JSON.stringify({
            scan_id:         scan.scan_id,
            file_path:       path,
            reviewer_email:  email,
            reviewer_github: reviewerGithub || undefined,
          }),
        }).catch(() => {});
      }
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
  // for this scan, then marks them all resolved. This works regardless of MOCK_SCANS content.
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

      // Fallback: write for all MOCK_SCANS files in this scan
      if (scan) {
        scan.files.forEach(f => {
          updates[`${riskPfx(f.risk_score)}::${scanId}::${f.file_path}`] = "resolved";
        });
      }

      localStorage.setItem("tl_violation_statuses", JSON.stringify({ ...stored, ...updates }));
      window.dispatchEvent(new Event("tl:badge"));
    } catch {}
  }

  // pr_id format the backend uses: "repo/pulls/number"
  const prId = scan ? `${scan.repo}/pulls/${scan.pr_number}` : "";

  async function performAttest(file: FileResult) {
    const email  = reviewerEmail  || "reviewer@trustledger.dev";
    const github = reviewerGithub || "reviewer";
    if (!reviewerEmail || !reviewerGithub) saveReviewer(email, github);
    try {
      await api.attest({ pr_id: prId, file_path: file.file_path, reviewer_email: email, reviewer_github_login: github });
    } catch {}
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
      try {
        await api.attest({ pr_id: prId, file_path: f.file_path, reviewer_email: email, reviewer_github_login: github });
      } catch { /* backend unavailable — mark locally */ }
      setAttestedSet(s => { const n = new Set(s); n.add(f.file_path); return n; });
      recordActivityEvent(f.file_path, email);
    }
    // Mark ALL violations for this scan resolved using snapshot data — handles any path mismatch
    resolveViolationsForScan(scan.scan_id);
    setAttestingAll(false);
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
                    <span className="text-xs text-slate-400">{new Date(scan.timestamp).toLocaleString()}</span>
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
          <div className="animate-fade-up flex items-center gap-3 bg-emerald-50 border border-emerald-200 rounded-xl px-4 py-3">
            <div className="w-8 h-8 rounded-lg bg-emerald-100 flex items-center justify-center text-emerald-600 shrink-0">
              <CheckCircleIcon />
            </div>
            <p className="text-sm font-semibold text-emerald-800 flex-1">
              All {highCount} HIGH/CRITICAL file{highCount !== 1 ? "s" : ""} have been attested — this PR is cleared for deployment.
            </p>
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
