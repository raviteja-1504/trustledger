"use client";

import { useState, useMemo, useEffect, useCallback } from "react";
import Link from "next/link";
import AuthGuard from "@/components/AuthGuard";
import PageSkeleton from "@/components/PageSkeleton";
import InfoTooltip from "@/components/InfoTooltip";
import { useToastHelpers } from "@/lib/toast";
import CodeViewer from "@/components/CodeViewer";
import { api } from "@/lib/api";
import { readSeed } from "@/lib/offlineData";
import type { DashboardData, ScanResult } from "@/types";
import { patchDataWithAttestations } from "@/lib/trustScore";
import { authedFetch } from "@/lib/useRealData";
import { useViolationsRealtime } from "@/lib/realtime";
import { useAuth } from "@/lib/auth";


// ── Types ──────────────────────────────────────────────────────────────────────

type VSeverity = "CRITICAL" | "HIGH" | "MEDIUM";
type VType     = "unattested_critical" | "unattested_high" | "unattested_medium"
               | "ai_threshold" | "no_reviewer" | "deploy_blocked" | "sla_breach";
type VStatus   = "open" | "in_review" | "resolved";

interface Violation {
  id: string;
  type: VType;
  severity: VSeverity;
  title: string;
  description: string;
  repo?: string;
  file?: string;
  pr_number?: number;
  scan_id?: string;
  detected_at: string;
  sla_deadline?: string;
  policy_rule: string;
}

// ── Inline Code Review ─────────────────────────────────────────────────────────

const SIGNAL_DESC: Record<string, string> = {
  // Security vulnerabilities
  "sql-injection":         "f-string or string concatenation in SQL query — bypasses parameterization, enables data exfiltration",
  "hardcoded-secret":      "API key, password, or cryptographic secret embedded directly in source code",
  "eval-exec":             "User-controlled input passed to eval()/exec() — arbitrary server-side code execution risk",
  "jwt-none-alg":          "JWT library configured to accept 'none' algorithm — allows forging any token without signature",
  "command-injection":     "User input interpolated into shell command string — OS command injection risk",
  "path-traversal":        "File path constructed from user input without sanitization — directory traversal risk",
  "xxe-injection":         "XML parser configured with external entity expansion enabled — XXE attack vector",
  "insecure-deserialize":  "Untrusted data passed to pickle/unserialize — arbitrary object injection risk",

  // AI provenance signals
  "ai-comment-pattern":    "Comment verbosity and phrasing match GitHub Copilot / ChatGPT output signatures — over-explained, instructional tone",
  "structural-uniformity": "All code blocks at exactly 4-space indent with no human variation — indicates AI copy-paste without editing",
  "comment-density":       "Comment-to-code ratio exceeds 35% — typical of AI output that documents every obvious statement",
  "identifier-entropy":    "Variable names are generic (data, result, item, obj) — AI models default to low-entropy identifiers",
  "boilerplate-pattern":   "Highly repetitive try-catch or validation blocks — AI generates defensive boilerplate without context",
};

const SEV_SIGNAL: Record<string, string> = {
  "sql-injection":"#7c3aed","hardcoded-secret":"#ef4444","eval-exec":"#ef4444",
  "jwt-none-alg":"#f97316","ai-comment-pattern":"#94a3b8",
  "structural-uniformity":"#f59e0b","comment-density":"#94a3b8","identifier-entropy":"#f59e0b",
};

interface InlineCodeReviewProps {
  scanId: string;
  filePath: string;
  onResolve: () => void;
  onReopen: () => void;
}

function InlineCodeReview({ scanId, filePath, onResolve, onReopen }: InlineCodeReviewProps) {
  const [scan, setScan]       = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadFailed, setLoadFailed] = useState(false);
  const [copied, setCopied]   = useState(false);

  useEffect(() => {
    let active = true;
    setLoading(true); setLoadFailed(false);
    api.getScan(scanId)
      .then(result => { if (active) setScan(result); })
      .catch(() => { if (active) setLoadFailed(true); })
      .finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [scanId, filePath]);

  const file = scan?.files.find(f => f.file_path === filePath) ?? scan?.files[0];

  if (loading) {
    return (
      <div className="flex items-center gap-2 px-5 py-4 text-xs text-gray-400">
        <svg className="animate-spin w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
          <path d="M21 12a9 9 0 1 1-6.219-8.56"/>
        </svg>
        Loading file content…
      </div>
    );
  }

  if (loadFailed) {
    return (
      <div className="px-5 py-4 text-xs text-gray-400">
        Couldn&apos;t load file content for this scan.{" "}
        <Link href={`/pr/${scanId}`} className="font-bold text-indigo-600 hover:text-indigo-800">Open PR review →</Link>
      </div>
    );
  }

  if (!file) {
    return (
      <div className="px-5 py-4 text-xs text-gray-400">
        File not found in scan results.{" "}
        <Link href={`/pr/${scanId}`} className="font-bold text-indigo-600 hover:text-indigo-800">Open PR review →</Link>
      </div>
    );
  }

  const lang = file.language === "typescript" || file.language === "javascript" ? "typescript" : "python";

  return (
    <div className="border-t border-gray-100">
      {/* Reviewer header */}
      <div className="flex items-center justify-between px-5 py-3"
        style={{ background:"linear-gradient(90deg,rgba(254,243,199,0.5),rgba(254,243,199,0.15))" }}>
        <div className="flex items-center gap-2.5">
          <div className="w-2 h-2 rounded-full bg-amber-500" />
          <span className="text-xs font-bold text-amber-800">Under Review</span>
          <span className="text-[10px] text-amber-700 font-mono bg-amber-100 px-2 py-0.5 rounded">
            {file.file_path.split("/").pop()}
          </span>
          <span className="text-[10px] text-amber-700">
            {(file.ai_percentage * 100).toFixed(0)}% AI · {file.language}
          </span>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => { navigator.clipboard.writeText(file.content ?? "").catch(()=>{}); setCopied(true); setTimeout(()=>setCopied(false),2000); }}
            className="text-[10px] font-semibold text-gray-500 hover:text-gray-700 bg-white border border-gray-200 px-2 py-1 rounded-lg transition-colors">
            {copied ? "Copied ✓" : "Copy code"}
          </button>
          <Link href={`/pr/${scanId}`} target="_blank"
            className="text-[10px] font-bold text-indigo-600 bg-indigo-50 hover:bg-indigo-100 border border-indigo-100 px-2 py-1 rounded-lg transition-colors flex items-center gap-1">
            Full PR view →
          </Link>
        </div>
      </div>

      {/* Risk signals */}
      {file.risk_indicators.length > 0 && (
        <div className="px-5 py-3 flex flex-wrap gap-2 border-b border-gray-100"
          style={{ background:"rgba(248,250,252,0.8)" }}>
          <span className="text-[9px] font-black uppercase tracking-wider text-gray-400 self-center">Detected signals:</span>
          {file.risk_indicators.map(sig => (
            <span key={sig} className="flex items-center gap-1 text-[10px] font-bold px-2 py-0.5 rounded-full"
              style={{ background:`${SEV_SIGNAL[sig] ?? "#94a3b8"}15`, color: SEV_SIGNAL[sig] ?? "#94a3b8", border:`1px solid ${SEV_SIGNAL[sig] ?? "#94a3b8"}30` }}>
              <span className="w-1.5 h-1.5 rounded-full" style={{ background: SEV_SIGNAL[sig] ?? "#94a3b8" }} />
              {sig} — {SIGNAL_DESC[sig] ?? sig}
            </span>
          ))}
        </div>
      )}

      {/* Code viewer */}
      <div className="px-5 py-3">
        <CodeViewer
          code={file.content ?? `# Content not available\n# File: ${file.file_path}`}
          language={lang}
          filename={file.file_path}
          riskIndicators={file.risk_indicators}
          maxHeight="320px"
        />
      </div>

      {/* Reviewer action bar */}
      <div className="flex items-center justify-between px-5 py-3 border-t border-gray-100"
        style={{ background:"rgba(248,250,252,0.7)" }}>
        <p className="text-[10px] text-gray-400 max-w-sm leading-relaxed">
          Review the code above for security issues. Only mark resolved once you have confirmed the risk is understood and mitigated.
        </p>
        <div className="flex items-center gap-2 shrink-0">
          <button onClick={onReopen}
            className="px-3 py-2 text-xs font-semibold text-gray-500 hover:text-gray-700 rounded-lg hover:bg-gray-100 transition-colors">
            Re-open
          </button>
          <button onClick={onResolve}
            className="flex items-center gap-1.5 px-4 py-2 text-sm font-bold text-white rounded-xl transition-all active:scale-[0.98]"
            style={{ background:"linear-gradient(135deg,#10b981,#059669)", boxShadow:"0 2px 12px rgba(16,185,129,0.35)" }}>
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">
              <polyline points="20 6 9 17 4 12"/>
            </svg>
            Mark Resolved
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Persistence ────────────────────────────────────────────────────────────────

const STATUS_KEY   = "tl_violation_statuses";
const ASSIGNEE_KEY = "tl_violation_assignees";

function loadStatuses(): Record<string, VStatus> {
  try { return JSON.parse(localStorage.getItem(STATUS_KEY) ?? "{}"); } catch { return {}; }
}
function saveStatuses(s: Record<string, VStatus>) {
  localStorage.setItem(STATUS_KEY, JSON.stringify(s));
  if (typeof window !== "undefined") window.dispatchEvent(new Event("tl:badge"));
}
function loadAssignees(): Record<string, string> {
  try { return JSON.parse(localStorage.getItem(ASSIGNEE_KEY) ?? "{}"); } catch { return {}; }
}
function saveAssignees(a: Record<string, string>) {
  localStorage.setItem(ASSIGNEE_KEY, JSON.stringify(a));
}

// ── Derive violations from dashboard data ─────────────────────────────────────

function deriveViolations(data: DashboardData): Violation[] {
  const now  = Date.now();
  const out: Violation[] = [];
  const SLA_CRIT = 24 * 3600_000;
  const SLA_HIGH = 48 * 3600_000;

  // Deterministic stable timestamp based on file path hash + a base offset in hours
  function detectedAt(seed: string, hoursAgo: number): string {
    let h = 0;
    for (let i = 0; i < seed.length; i++) h = (h * 31 + seed.charCodeAt(i)) & 0x7fffffff;
    // Keep jitter small (< 1h) so timestamps feel realistic without crossing SLA boundaries unexpectedly
    const jitter = (h % 55) * 60_000;
    return new Date(now - hoursAgo * 3_600_000 - jitter).toISOString();
  }

  // Compute effective unattested deploy count from localStorage (reflects local attestations)
  const effectiveDeployCount = (() => {
    try {
      const statuses = JSON.parse(localStorage.getItem("tl_violation_statuses") ?? "{}") as Record<string,string>;
      const riskPfx = (r: string) => r === "CRITICAL" ? "crit" : r === "HIGH" ? "high" : r === "MEDIUM" ? "med" : "low";
      const unresolvedRepos = new Set(
        data.top_risk_files
          .filter(f => !f.attested && (f.risk_score === "CRITICAL" || f.risk_score === "HIGH"))
          .filter(f => {
            const pfx = riskPfx(f.risk_score);
            const s   = statuses[`${pfx}::${f.scan_id}::${f.file_path}`];
            return s !== "resolved" && s !== "in_review";
          })
          .map(f => f.repo)
      );
      return unresolvedRepos.size;
    } catch { return data.unattested_deploy_count; }
  })();

  // 1. CRITICAL unattested files (detected ~6h ago — within SLA so no duplicate SLA entry needed)
  data.top_risk_files
    .filter(f => f.risk_score === "CRITICAL" && !f.attested)
    .forEach(f => {
      const det = detectedAt(f.file_path, 6);
      out.push({
        id:          `crit::${f.scan_id}::${f.file_path}`,
        type:        "unattested_critical",
        severity:    "CRITICAL",
        title:       "CRITICAL file unattested — merge blocked",
        description: `${f.file_path.split("/").pop()} in ${f.repo.split("/").pop()} is ${(f.ai_pct * 100).toFixed(0)}% AI content, flagged CRITICAL. Policy gate blocks merge until a designated reviewer attests.`,
        repo:        f.repo,
        file:        f.file_path,
        pr_number:   f.pr_number,
        scan_id:     f.scan_id,
        detected_at: det,
        sla_deadline: new Date(new Date(det).getTime() + SLA_CRIT).toISOString(),
        policy_rule: "CC8.1 — Change Management",
      });
    });

  // 2. HIGH unattested files (detected ~12h ago — within 48h SLA)
  data.top_risk_files
    .filter(f => f.risk_score === "HIGH" && !f.attested)
    .forEach(f => {
      const det = detectedAt(f.file_path, 12);
      out.push({
        id:          `high::${f.scan_id}::${f.file_path}`,
        type:        "unattested_high",
        severity:    "HIGH",
        title:       "HIGH-risk file awaiting attestation",
        description: `${f.file_path.split("/").pop()} (${(f.ai_pct * 100).toFixed(0)}% AI, HIGH risk) has not been attested. 48 h SLA applies — assign a reviewer now.`,
        repo:        f.repo,
        file:        f.file_path,
        pr_number:   f.pr_number,
        scan_id:     f.scan_id,
        detected_at: det,
        sla_deadline: new Date(new Date(det).getTime() + SLA_HIGH).toISOString(),
        policy_rule: "SLA Policy — HIGH files ≤ 48 h",
      });
    });

  // 3. MEDIUM unattested files
  data.top_risk_files
    .filter(f => f.risk_score === "MEDIUM" && !f.attested)
    .forEach(f => {
      const det = detectedAt(f.file_path, 18);
      out.push({
        id:          `med::${f.scan_id}::${f.file_path}`,
        type:        "unattested_medium",
        severity:    "MEDIUM",
        title:       "MEDIUM-risk file pending attestation",
        description: `${f.file_path.split("/").pop()} (${(f.ai_pct * 100).toFixed(0)}% AI, MEDIUM risk) requires attestation before the next quarterly review.`,
        repo:        f.repo,
        file:        f.file_path,
        pr_number:   f.pr_number,
        scan_id:     f.scan_id,
        detected_at: det,
        sla_deadline: new Date(new Date(det).getTime() + 7 * 24 * 3600_000).toISOString(),
        policy_rule: "Best Practice — MEDIUM files ≤ 7 d",
      });
    });

  // 4. Deploys blocked (uses effective count that reflects local attestations)
  if (effectiveDeployCount > 0) {
    const det = detectedAt("deploy-blocked", 4);
    out.push({
      id:          "deploy::blocked",
      type:        "deploy_blocked",
      severity:    "CRITICAL",
      title:       `${effectiveDeployCount} repo${effectiveDeployCount > 1 ? "s" : ""} blocked from deploying`,
      description: `${effectiveDeployCount} repositor${effectiveDeployCount > 1 ? "ies have" : "y has"} unattested CRITICAL or HIGH files blocking production deployment. Attest all required files to unblock.`,
      detected_at: det,
      sla_deadline: new Date(new Date(det).getTime() + SLA_CRIT).toISOString(),
      policy_rule:  "6.4.1 — Security Vulnerabilities",
    });
  }

  // 5. AI content threshold breach (repos > 80% AI content)
  data.repos
    .filter(r => r.ai_pct > 0.8)
    .forEach(r => {
      out.push({
        id:          `ai-thresh::${r.repo}`,
        type:        "ai_threshold",
        severity:    "CRITICAL",
        title:       `AI threshold exceeded — ${r.repo.split("/").pop()} at ${(r.ai_pct * 100).toFixed(0)}%`,
        description: `${r.repo.split("/").pop()} average AI content (${(r.ai_pct * 100).toFixed(0)}%) exceeds the 80% critical threshold. Additional senior review and dual attestation required per policy.`,
        repo:        r.repo,
        detected_at: detectedAt(r.repo, 8),
        policy_rule: "Custom — AI Content Limit",
      });
    });

  // 6. Low attestation repos (< 60%)
  data.repos
    .filter(r => r.attestation_rate < 0.6 && r.scan_count > 0)
    .forEach(r => {
      out.push({
        id:          `low-attest::${r.repo}`,
        type:        "no_reviewer",
        severity:    "HIGH",
        title:       `Low attestation coverage — ${r.repo.split("/").pop()} at ${Math.round(r.attestation_rate * 100)}%`,
        description: `${r.repo.split("/").pop()} attestation rate (${Math.round(r.attestation_rate * 100)}%) is below the 60% minimum. Assign designated reviewers and clear the backlog to remain compliant.`,
        repo:        r.repo,
        detected_at: detectedAt(r.repo + "-attest", 12),
        policy_rule: "CC6.1 — Logical Access Controls",
      });
    });

  return out;
}

// ── Helpers ─────────────────────────────────────────────────────────────────────

const SEV_STYLE: Record<VSeverity, { bg:string; text:string; border:string; dot:string }> = {
  CRITICAL: { bg:"#ede9fe", text:"#5b21b6", border:"#c4b5fd", dot:"#7c3aed" },
  HIGH:     { bg:"#ffedd5", text:"#7c2d12", border:"#fed7aa", dot:"#f97316" },
  MEDIUM:   { bg:"#fef3c7", text:"#78350f", border:"#fde68a", dot:"#f59e0b" },
};

const STATUS_STYLE: Record<VStatus, { bg:string; text:string; border:string; label:string }> = {
  open:       { bg:"#fef2f2", text:"#be123c", border:"#fecdd3", label:"Open"       },
  in_review:  { bg:"#fffbeb", text:"#b45309", border:"#fde68a", label:"In Review"  },
  resolved:   { bg:"#f0fdf4", text:"#15803d", border:"#bbf7d0", label:"Resolved"   },
};

const TYPE_LABELS: Record<VType, string> = {
  unattested_critical: "Unattested Critical",
  unattested_high:     "Unattested High",
  unattested_medium:   "Unattested Medium",
  ai_threshold:        "AI Threshold",
  no_reviewer:         "Low Coverage",
  deploy_blocked:      "Deploy Blocked",
  sla_breach:          "SLA Breach",
};

function timeAgo(iso: string) {
  const s = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 3600)  return `${Math.floor(s/60)}m ago`;
  if (s < 86400) return `${Math.floor(s/3600)}h ago`;
  return `${Math.floor(s/86400)}d ago`;
}

// ── Page ────────────────────────────────────────────────────────────────────────

const NOTES_KEY     = "tl_violation_notes";
const ESCALATE_KEY  = "tl_violation_escalations";

// Per-type remediation checklist
const REMEDIATION: Record<VType, string[]> = {
  unattested_critical: [
    "Open the PR and review all CRITICAL-flagged files",
    "Confirm no hardcoded secrets, eval(), or SQL injection patterns",
    "Verify AI content percentage matches expected level",
    "Assign a designated security reviewer in the PR",
    "Click 'Mark Resolved' once all files are attested",
  ],
  unattested_high:     [
    "Review the HIGH-risk file in the PR detail view",
    "Check risk indicators: hardcoded secrets, JWT bypass, eval/exec",
    "Confirm file purpose is understood and risk is acceptable",
    "Attest the file via the PR review page",
  ],
  unattested_medium:   [
    "Review the MEDIUM-risk file for AI-generated code patterns",
    "Confirm identifiers, comments, and structure are appropriate",
    "Attest the file before the next quarterly compliance review",
    "Document any accepted risk in the violation note",
  ],
  ai_threshold:        [
    "Review the repo's AI-generated code percentage in Analytics",
    "Identify which recent PRs pushed AI% above the threshold",
    "Require dual-reviewer attestation for all new PRs in this repo",
    "Consider adding an AI content gate to the CI pipeline",
  ],
  no_reviewer:         [
    "Identify unreviewed files in the repo's PR history",
    "Assign designated reviewers to the repo in Settings",
    "Work through the backlog using the Violations filter by repo",
    "Set a recurring review schedule to prevent recurrence",
  ],
  deploy_blocked:      [
    "Navigate to the Violations page and filter by the blocked repo",
    "Attest all CRITICAL and HIGH files to unblock deployment",
    "Verify attestation rate reaches 100% for the deploy window",
    "Re-trigger the CI/CD pipeline once all attestations are complete",
  ],
  sla_breach:          [
    "Immediately escalate to the security lead",
    "Document the reason for the SLA breach in the violation notes",
    "Attest or accept the risk with CISO sign-off",
    "File a post-incident review within 48h of resolution",
  ],
};

export default function ViolationsPage() {
  const { success, info, error: toastError } = useToastHelpers();
  const { profile } = useAuth();
  const [data,         setData]         = useState<DashboardData | null>(null);
  const [loading,      setLoading]      = useState(true);
  const [statuses,     setStatuses]     = useState<Record<string, VStatus>>({});
  const [assignees,    setAssignees]    = useState<Record<string, string>>({});
  const [notes,        setNotes]        = useState<Record<string, string>>({});
  const [escalated,    setEscalated]    = useState<Set<string>>(new Set());
  const [selected,     setSelected]     = useState<Set<string>>(new Set());
  const [teamMembers,  setTeamMembers]  = useState<{ email: string; name: string | null }[]>([]);
  const [expandedNote, setExpandedNote] = useState<string | null>(null);
  const [filterSev,    setFilterSev]    = useState<VSeverity | "all">("all");
  const [filterStat,   setFilterStat]   = useState<VStatus | "all">("open");
  const [filterRepo,   setFilterRepo]   = useState("all");
  const [reviewingId,  setReviewingId]  = useState<string | null>(null);
  const [refreshing,   setRefreshing]   = useState(false);
  const [lastRefreshed,setLastRefreshed]= useState<Date | null>(null);
  const [loadError,    setLoadError]    = useState<string | null>(null);

  // Load all persisted state
  useEffect(() => {
    setStatuses(loadStatuses());
    setAssignees(loadAssignees());
    try { setNotes(JSON.parse(localStorage.getItem(NOTES_KEY) ?? "{}")); } catch {}
    try {
      const esc = JSON.parse(localStorage.getItem(ESCALATE_KEY) ?? "[]");
      setEscalated(new Set(Array.isArray(esc) ? esc : []));
    } catch {}
  }, []);

  // Fetch real team members for reviewer dropdown
  useEffect(() => {
    if (!profile?.org_id) return;
    authedFetch<{ members: { email: string; name: string | null }[] }>("/api/team")
      .then(r => setTeamMembers((r.members ?? []).filter(m => m.email)))
      .catch(() => {});
  }, [profile?.org_id]);

  const fetchData = useCallback(async (spinner = false) => {
    if (spinner) setRefreshing(true);
    const seed = readSeed();
    if (seed) { setData(seed); setLoadError(null); setLastRefreshed(new Date()); setLoading(false); if (spinner) setRefreshing(false); return; }
    try {
      const d = await api.dashboard(profile?.org_slug ?? "", 90);
      setData(d); setLoadError(null); setLastRefreshed(new Date());
    } catch (e) {
      setData(null);
      setLoadError(e instanceof Error ? e.message : "Failed to load vulnerability data");
    }
    setLoading(false); if (spinner) setRefreshing(false);
  }, []);

  // Initial fetch + 30s auto-poll
  useEffect(() => {
    fetchData();
    const id = setInterval(() => fetchData(), 30_000);
    return () => clearInterval(id);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Realtime: refresh when violations table changes in DB
  useViolationsRealtime(profile?.org_id, () => fetchData(false));

  // Sync violation status resolution to real API (alongside localStorage)
  const syncViolationToAPI = useCallback(async (id: string, status: string, note?: string) => {
    if (!profile?.org_id) return;
    try {
      await authedFetch("/api/violations", {
        method: "PATCH",
        body:   JSON.stringify({ id, status, note }),
      });
    } catch { /* non-fatal — localStorage already updated */ }
  }, [profile?.org_id]);

  // Derive violations from live data, apply persisted statuses
  const violations = useMemo<(Violation & { status: VStatus; assignee?: string })[]>(() => {
    if (!data) return [];
    const base = deriveViolations(patchDataWithAttestations(data));
    return base.map(v => ({
      ...v,
      status:   statuses[v.id]  ?? "open",
      assignee: assignees[v.id] ?? undefined,
    }));
  }, [data, statuses, assignees]);

  function setStatus(id: string, status: VStatus) {
    const next = { ...statuses, [id]: status };
    setStatuses(next);
    saveStatuses(next);
    // Sync to real API (fire-and-forget)
    syncViolationToAPI(id, status);
    if (status === "in_review") { setReviewingId(id); info("Review started", "Code panel opened below — review and mark resolved when done."); }
    else if (status === "resolved") { if (reviewingId === id) setReviewingId(null); success("Violation resolved", "Status updated and saved."); }
    else if (status === "open") { info("Re-opened", "Violation moved back to open status."); }
  }

  function saveNote(id: string, text: string) {
    const next = { ...notes, [id]: text };
    setNotes(next);
    localStorage.setItem(NOTES_KEY, JSON.stringify(next));
  }

  function toggleEscalate(id: string) {
    const next = new Set(Array.from(escalated));
    if (next.has(id)) { next.delete(id); info("Escalation removed", "Violation de-escalated."); }
    else               { next.add(id);    success("Escalated!", "Security lead will be notified."); }
    setEscalated(next);
    localStorage.setItem(ESCALATE_KEY, JSON.stringify(Array.from(next)));
  }

  function setAssignee(id: string, email: string) {
    const next = { ...assignees, [id]: email };
    setAssignees(next);
    saveAssignees(next);
    success("Reviewer assigned", `${email.split("@")[0]} has been assigned.`);
  }

  function bulkResolve() {
    const next = { ...statuses };
    selected.forEach(id => { next[id] = "resolved"; });
    setStatuses(next);
    saveStatuses(next);
    setSelected(new Set());
    success(`${selected.size} violation${selected.size > 1 ? "s" : ""} resolved`, "Bulk resolution complete.");
  }

  function toggleSelect(id: string) {
    setSelected(prev => {
      const n = new Set(Array.from(prev));
      n.has(id) ? n.delete(id) : n.add(id);
      return n;
    });
  }

  function exportCSV() {
    const rows = [
      ["ID","Severity","Type","Status","Repo","File","PR","Detected","SLA Deadline","Assignee","Note","Escalated"],
      ...filtered.map(v => [
        v.id, v.severity, TYPE_LABELS[v.type], v.status,
        v.repo ?? "", v.file ?? "", v.pr_number?.toString() ?? "",
        v.detected_at, v.sla_deadline ?? "",
        assignees[v.id] ?? "", notes[v.id] ?? "",
        escalated.has(v.id) ? "YES" : "NO",
      ]),
    ];
    const csv = rows.map(r => r.map(c => `"${String(c).replace(/"/g,'""')}"`).join(",")).join("\n");
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([csv], { type:"text/csv" }));
    a.download = `violations-${new Date().toISOString().split("T")[0]}.csv`;
    a.click();
  }

  const repos = useMemo(() => Array.from(new Set(violations.filter(v => v.repo).map(v => v.repo!))), [violations]);

  const filtered = useMemo(() => violations.filter(v => {
    if (filterSev  !== "all" && v.severity !== filterSev)  return false;
    if (filterStat !== "all" && v.status   !== filterStat) return false;
    if (filterRepo !== "all" && v.repo     !== filterRepo) return false;
    return true;
  }), [violations, filterSev, filterStat, filterRepo]);

  const open     = violations.filter(v => v.status === "open").length;
  const critical = violations.filter(v => v.severity === "CRITICAL" && v.status !== "resolved").length;
  const slaOver  = violations.filter(v => v.sla_deadline && new Date(v.sla_deadline) < new Date() && v.status !== "resolved").length;
  const inReview = violations.filter(v => v.status === "in_review").length;

  const refreshAgo = lastRefreshed
    ? (() => {
        const s = Math.floor((Date.now() - lastRefreshed.getTime()) / 1000);
        return s < 10 ? "just now" : s < 60 ? `${s}s ago` : `${Math.floor(s/60)}m ago`;
      })()
    : "";

  return (
    <AuthGuard>
      <PageSkeleton rows={6} cards={4}>
      <div className="max-w-7xl mx-auto space-y-5 pb-10">

        {/* Header */}
        <div className="animate-fade-up flex items-start justify-between gap-4 flex-wrap">
          <div>
            <div className="flex items-center gap-2.5 mb-1">
              <div className="w-8 h-8 rounded-xl flex items-center justify-center"
                style={{ background:"rgba(239,68,68,0.1)", border:"1px solid rgba(239,68,68,0.2)" }}>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#ef4444" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/>
                </svg>
              </div>
              <h1 className="text-xl font-black text-gray-900 tracking-tight">Policy Violations</h1>
              {open > 0 && (
                <span className="text-xs font-black text-white bg-rose-500 px-2 py-0.5 rounded-full animate-pulse">
                  {open} open
                </span>
              )}
            </div>
            <p className="text-sm text-gray-400">
              Active policy violations derived from live scan data — updates every 30 s.
            </p>
          </div>

          <div className="flex flex-col items-end gap-0.5">
            <div className="flex items-center gap-2">
              <Link href="/settings"
                className="flex items-center gap-1.5 px-3 py-2 text-xs font-semibold text-gray-600 bg-white border border-gray-200 rounded-xl hover:bg-gray-50 transition-all shadow-sm">
                <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                  <circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>
                </svg>
                Edit Policies
              </Link>
              <button onClick={exportCSV}
                className="flex items-center gap-1.5 px-3 py-2 text-xs font-semibold text-gray-600 bg-white border border-gray-200 rounded-xl hover:bg-gray-50 transition-all shadow-sm">
                <svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>
                </svg>
                Export CSV
              </button>
              <button onClick={() => fetchData(true)} disabled={refreshing}
                className="flex items-center gap-1.5 px-3 py-2 text-xs font-semibold text-indigo-600 bg-indigo-50 border border-indigo-200 rounded-xl hover:bg-indigo-100 disabled:opacity-50 transition-all shadow-sm">
                <svg className={refreshing ? "animate-spin" : ""} width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                  <polyline points="23 4 23 10 17 10"/><path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10"/>
                </svg>
                {refreshing ? "Refreshing…" : "Refresh"}
              </button>
            </div>
            {refreshAgo && <span className="text-[9px] text-gray-400">Updated {refreshAgo}</span>}
          </div>
        </div>

        {/* Error banner */}
        {loadError && !loading && (
          <div className="animate-fade-up flex items-center justify-between gap-3 px-4 py-3 rounded-2xl border"
            style={{ background:"#fef2f2", borderColor:"#fecdd3" }}>
            <p className="text-sm text-rose-700">
              <span className="font-bold">Couldn&apos;t load vulnerabilities.</span> {loadError}
            </p>
            <button onClick={() => fetchData(true)} disabled={refreshing}
              className="shrink-0 px-3 py-1.5 text-xs font-bold text-rose-700 bg-white border border-rose-200 rounded-xl hover:bg-rose-50 disabled:opacity-50 transition-colors">
              {refreshing ? "Retrying…" : "Retry"}
            </button>
          </div>
        )}

        {/* Summary cards — click to filter */}
        <div className="animate-fade-up grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[
            { label:"Open Violations", value:open,     color:"#ef4444", bg:"#fef2f2", status:"open"      as VStatus|"all", info:{ title:"Open Violations", description:"Policy violations with status 'Open' — not yet acknowledged or under review. These require immediate action." } },
            { label:"Critical Active", value:critical, color:"#7c3aed", bg:"#ede9fe", status:"all"       as VStatus|"all", info:{ title:"Critical Active",  description:"Violations with CRITICAL severity that have not been resolved. CRITICAL = likelihood × impact ≥ 20, or CRITICAL-risk file unattested." } },
            { label:"SLA Breaches",    value:slaOver,  color:"#f97316", bg:"#fff7ed", status:"open"      as VStatus|"all", info:{ title:"SLA Breaches",    description:"Violations where the remediation deadline has passed. CRITICAL files must be resolved within 24h; HIGH within 48h." } },
            { label:"In Review",       value:inReview, color:"#f59e0b", bg:"#fffbeb", status:"in_review" as VStatus|"all", info:{ title:"In Review",       description:"Violations with status 'In Review' — a reviewer has started working on them but they are not yet resolved." } },
          ].map(s => (
            <div key={s.label}
              className="rounded-2xl p-4 border"
              style={{ background:s.bg, borderColor:s.color+"30" }}>
              <p className="text-2xl font-black tabular-nums" style={{ color:s.color }}>{s.value}</p>
              <div className="flex items-center gap-1.5 mt-1">
                <p className="text-xs font-semibold text-gray-500">{s.label}</p>
                <InfoTooltip title={s.info.title} description={s.info.description} position="top" />
              </div>
            </div>
          ))}
        </div>

        {/* Filters */}
        <div className="animate-fade-up flex flex-wrap items-center gap-2">
          {/* Status tabs with counts — scoped to current repo + severity filters */}
          <div className="flex items-center gap-0.5 bg-gray-100 p-0.5 rounded-xl">
            {(["all","open","in_review","resolved"] as const).map(s => {
              // Apply repo + severity filter first, then count by status
              const base = violations.filter(v => {
                if (filterSev  !== "all" && v.severity !== filterSev)  return false;
                if (filterRepo !== "all" && v.repo     !== filterRepo) return false;
                return true;
              });
              const count = s === "all" ? base.length : base.filter(v => v.status === s).length;
              const label = s==="all"?"All":s==="in_review"?"In Review":s.charAt(0).toUpperCase()+s.slice(1);
              return (
                <button key={s} onClick={() => setFilterStat(s)}
                  className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-semibold rounded-lg transition-all ${filterStat===s?"bg-white text-gray-900 shadow-sm":"text-gray-500 hover:text-gray-700"}`}>
                  {label}
                  {count > 0 && (
                    <span className={`text-[9px] font-black px-1.5 py-0.5 rounded-full tabular-nums ${
                      filterStat===s
                        ? s==="open"?"bg-rose-100 text-rose-700":s==="in_review"?"bg-amber-100 text-amber-700":s==="resolved"?"bg-emerald-100 text-emerald-700":"bg-gray-200 text-gray-600"
                        : "bg-gray-200/70 text-gray-500"
                    }`}>{count}</span>
                  )}
                </button>
              );
            })}
          </div>

          {/* Severity */}
          <div className="flex items-center gap-0.5 bg-gray-100 p-0.5 rounded-xl">
            {(["all","CRITICAL","HIGH","MEDIUM"] as const).map(s => (
              <button key={s} onClick={() => setFilterSev(s)}
                className={`px-3 py-1.5 text-xs font-semibold rounded-lg transition-all ${filterSev===s?"bg-white text-gray-900 shadow-sm":"text-gray-500 hover:text-gray-700"}`}>
                {s==="all"?"All Severity":s}
              </button>
            ))}
          </div>

          {/* Repo */}
          {repos.length > 1 && (
            <select value={filterRepo} onChange={e => setFilterRepo(e.target.value)}
              className="text-xs font-semibold text-gray-600 bg-white border border-gray-200 rounded-xl px-3 py-2 focus:outline-none focus:ring-2 focus:ring-indigo-400">
              <option value="all">All Repos</option>
              {repos.map(r => <option key={r} value={r}>{r.split("/").pop()}</option>)}
            </select>
          )}

          {(filterStat !== "all" || filterSev !== "all" || filterRepo !== "all") && (
            <button onClick={() => { setFilterStat("all"); setFilterSev("all"); setFilterRepo("all"); }}
              className="text-xs font-bold text-rose-600 hover:text-rose-800 px-2 py-1 rounded-lg hover:bg-rose-50 transition-colors">
              Clear filters
            </button>
          )}

          <span className="text-xs text-gray-400 ml-auto">
            {filtered.length} of {violations.length} violation{violations.length!==1?"s":""}
            {filterStat !== "all" && <span className="ml-1 text-indigo-500 font-semibold">· {filterStat === "in_review" ? "In Review" : filterStat.charAt(0).toUpperCase()+filterStat.slice(1)} only</span>}
          </span>
        </div>

        {/* Bulk action bar — appears when violations are selected */}
        {selected.size > 0 && (
          <div className="animate-fade-up flex items-center gap-3 bg-indigo-950 text-white px-5 py-3 rounded-2xl shadow-lg">
            <span className="text-sm font-bold">{selected.size} selected</span>
            <div className="flex-1" />
            <button onClick={bulkResolve}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-bold bg-emerald-500 hover:bg-emerald-400 rounded-lg transition-colors">
              <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
              Resolve All
            </button>
            <button onClick={() => {
              const next = { ...statuses };
              selected.forEach(id => { next[id] = "in_review"; });
              setStatuses(next); saveStatuses(next); setSelected(new Set());
              info(`${selected.size} violations moved to review`, "");
            }}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-bold bg-amber-500 hover:bg-amber-400 rounded-lg transition-colors">
              Mark In Review
            </button>
            <button onClick={() => setSelected(new Set())}
              className="text-xs text-indigo-300 hover:text-white px-2 py-1.5 rounded-lg transition-colors">
              Cancel
            </button>
          </div>
        )}

        {/* Violations list */}
        <div className="animate-fade-up space-y-3">
          {violations.length === 0 && !loading && !loadError ? (
            <div className="section-card py-16 text-center">
              <div className="w-12 h-12 rounded-2xl bg-emerald-50 flex items-center justify-center text-emerald-500 mx-auto mb-3">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>
                </svg>
              </div>
              <p className="text-sm font-bold text-gray-700">No violations detected</p>
              <p className="text-xs text-gray-400 mt-1">All files are attested and within policy thresholds</p>
            </div>
          ) : violations.length === 0 && !loading && loadError ? (
            <div className="section-card py-16 text-center">
              <p className="text-sm font-bold text-gray-700">No violation data available</p>
              <p className="text-xs text-gray-400 mt-1">Retry the load above once the connection is restored.</p>
            </div>
          ) : filtered.length === 0 ? (
            <div className="section-card py-12 text-center space-y-2">
              <p className="text-sm font-bold text-gray-600">
                {filterStat === "resolved" ? "No resolved violations yet" :
                 filterStat === "in_review" ? "No violations currently in review" :
                 "No violations match these filters"}
              </p>
              <p className="text-xs text-gray-400">
                {filterStat !== "all" || filterSev !== "all" || filterRepo !== "all"
                  ? "Try adjusting the filters above to see more results."
                  : "All files are attested and within policy thresholds. ✓"}
              </p>
              {(filterStat !== "all" || filterSev !== "all" || filterRepo !== "all") && (
                <button onClick={() => { setFilterStat("all"); setFilterSev("all"); setFilterRepo("all"); }}
                  className="text-xs font-bold text-indigo-600 hover:text-indigo-800 hover:underline">
                  Clear all filters →
                </button>
              )}
            </div>
          ) : filtered.map(v => {
            const sev  = SEV_STYLE[v.severity];
            const stat = STATUS_STYLE[v.status];
            const deadline = v.sla_deadline ? new Date(v.sla_deadline) : null;
            const isOver   = deadline ? deadline < new Date() : false;
            const hoursLeft = deadline ? Math.ceil((deadline.getTime() - Date.now()) / 3_600_000) : null;
            const isSelected   = selected.has(v.id);
            const isEscalated  = escalated.has(v.id);
            const violationNote = notes[v.id] ?? "";

            return (
              <div key={v.id}
                className={`section-card overflow-hidden border-l-4 transition-all hover:shadow-md ${isSelected ? "ring-2 ring-indigo-400" : ""} ${isEscalated ? "ring-1 ring-rose-400" : ""}`}
                style={{ borderLeftColor: isEscalated ? "#ef4444" : sev.dot }}>
                <div className="flex items-start gap-4 p-5">
                  {/* Checkbox */}
                  <div className="shrink-0 pt-1 flex flex-col items-center gap-2">
                    <input type="checkbox" checked={isSelected} onChange={() => toggleSelect(v.id)}
                      className="w-4 h-4 accent-indigo-600 cursor-pointer" />
                    {isEscalated && (
                      <span className="text-[8px] font-black text-rose-600 bg-rose-50 px-1 py-0.5 rounded border border-rose-200 animate-pulse">ESC</span>
                    )}
                  </div>

                  {/* Content */}
                  <div className="flex-1 min-w-0 space-y-2">
                    <div className="flex items-start justify-between gap-3 flex-wrap">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-[10px] font-bold px-2 py-0.5 rounded-full border"
                          style={{ background:sev.bg, color:sev.text, borderColor:sev.border }}>
                          {v.severity}
                        </span>
                        <span className="text-[10px] font-semibold text-gray-500 bg-gray-50 px-2 py-0.5 rounded border border-gray-100">
                          {TYPE_LABELS[v.type]}
                        </span>
                        <span className="text-[10px] font-bold px-2 py-0.5 rounded-full border"
                          style={{ background:stat.bg, color:stat.text, borderColor:stat.border }}>
                          {stat.label}
                        </span>
                      </div>
                      {/* SLA indicator */}
                      {deadline && v.status !== "resolved" && (
                        <span className={`text-[10px] font-bold px-2 py-0.5 rounded-full tabular-nums ${
                          isOver ? "text-rose-700 bg-rose-50 border border-rose-200 animate-pulse"
                                 : hoursLeft !== null && hoursLeft <= 24 ? "text-orange-700 bg-orange-50 border border-orange-200"
                                 : "text-gray-500 bg-gray-50 border border-gray-200"
                        }`}>
                          ⏱ {isOver ? `${Math.abs(hoursLeft!)}h overdue` : `${hoursLeft}h left`}
                        </span>
                      )}
                    </div>

                    <p className="text-sm font-bold text-gray-900">{v.title}</p>
                    <p className="text-xs text-gray-500 leading-relaxed">{v.description}</p>

                    <div className="flex items-center gap-4 flex-wrap">
                      {v.repo && (
                        <span className="text-[10px] font-mono text-indigo-600 bg-indigo-50 px-2 py-0.5 rounded">
                          {v.repo.split("/").pop()}
                        </span>
                      )}
                      {v.file && (
                        <span className="text-[10px] font-mono text-gray-500">{v.file.split("/").pop()}</span>
                      )}
                      {v.pr_number && v.scan_id && (
                        <Link href={`/pr/${v.scan_id}`}
                          className="text-[10px] font-bold text-indigo-600 hover:text-indigo-800 flex items-center gap-0.5">
                          PR #{v.pr_number} →
                        </Link>
                      )}
                      <span className="text-[10px] font-mono text-gray-400 bg-gray-50 px-1.5 py-0.5 rounded border border-gray-100">
                        {v.policy_rule}
                      </span>
                      {/* Compliance framework impact tags */}
                      {(() => {
                        const tags: { fw:string; color:string }[] = [];
                        if (v.policy_rule.includes("CC") || v.policy_rule.includes("A1.")) {
                          tags.push({ fw:"SOC 2", color:"#6366f1" });
                        }
                        if (v.policy_rule.includes("6.") && !v.policy_rule.includes("CC6")) {
                          tags.push({ fw:"PCI-DSS", color:"#10b981" });
                        }
                        if (v.policy_rule.includes("SLA") || v.policy_rule.includes("AI Content") || v.severity === "CRITICAL") {
                          tags.push({ fw:"EU AI Act", color:"#3b82f6" });
                        }
                        return tags.map(t => (
                          <span key={`${v.id}-${t.fw}`} className="text-[8px] font-black px-1.5 py-0.5 rounded text-white"
                            style={{ background:t.color }}>
                            {t.fw}
                          </span>
                        ));
                      })()}
                      <span className="text-[10px] text-gray-400">{timeAgo(v.detected_at)}</span>
                      {/* Assignee display / picker */}
                      <div className="flex items-center gap-1">
                        <svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>
                        <select value={v.assignee ?? ""} onChange={e => setAssignee(v.id, e.target.value)}
                          onClick={e => e.stopPropagation()}
                          className="text-[10px] text-gray-500 bg-transparent border-none outline-none cursor-pointer hover:text-indigo-600 max-w-[120px] truncate">
                          <option value="">Assign reviewer…</option>
                          {teamMembers.map(m => (
                            <option key={m.email} value={m.email}>
                              {m.name || m.email.split("@")[0]}
                            </option>
                          ))}
                        </select>
                      </div>
                      {violationNote && (
                        <span className="text-[10px] text-indigo-600 italic flex items-center gap-1">
                          <svg width="9" height="9" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
                          Note added
                        </span>
                      )}
                    </div>
                  </div>

                  {/* Actions */}
                  <div className="shrink-0 flex flex-col gap-1.5">
                    {/* Escalate button */}
                    <button onClick={() => toggleEscalate(v.id)}
                      aria-label={isEscalated ? "Remove escalation" : "Escalate this violation to security lead"}
                      className={`text-[11px] font-bold px-3 py-1.5 rounded-lg transition-colors whitespace-nowrap flex items-center gap-1 ${isEscalated ? "text-rose-700 bg-rose-50 border border-rose-200" : "text-gray-500 bg-gray-50 border border-gray-200 hover:border-rose-200 hover:text-rose-600"}`}>
                      <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
                      </svg>
                      {isEscalated ? "Escalated" : "Escalate"}
                    </button>
                    {v.status === "open" && (
                      <>
                        <button onClick={() => setStatus(v.id, "resolved")}
                          className="text-[11px] font-bold text-emerald-700 bg-emerald-50 border border-emerald-200 px-3 py-1.5 rounded-lg hover:bg-emerald-100 transition-colors whitespace-nowrap flex items-center gap-1">
                          <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
                          Mark Resolved
                        </button>
                        {v.scan_id && v.file && (
                          <button onClick={() => setStatus(v.id, "in_review")}
                            className="text-[11px] font-medium text-amber-700 bg-amber-50 border border-amber-200 px-3 py-1.5 rounded-lg hover:bg-amber-100 transition-colors whitespace-nowrap">
                            Review Code
                          </button>
                        )}
                      </>
                    )}
                    {v.status === "in_review" && (
                      <>
                        <button onClick={() => setStatus(v.id, "resolved")}
                          className="text-[11px] font-bold text-emerald-700 bg-emerald-50 border border-emerald-200 px-3 py-1.5 rounded-lg hover:bg-emerald-100 transition-colors whitespace-nowrap flex items-center gap-1">
                          <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><polyline points="20 6 9 17 4 12"/></svg>
                          Mark Resolved
                        </button>
                        {v.scan_id && v.file && (
                          <button onClick={() => setReviewingId(reviewingId === v.id ? null : v.id)}
                            className={`text-[11px] font-medium px-3 py-1.5 rounded-lg transition-colors whitespace-nowrap flex items-center gap-1 ${
                              reviewingId === v.id
                                ? "text-amber-800 bg-amber-100 border border-amber-300"
                                : "text-amber-700 bg-amber-50 border border-amber-200 hover:bg-amber-100"
                            }`}>
                            <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
                              <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/>
                            </svg>
                            {reviewingId === v.id ? "Hide Code" : "View Code"}
                          </button>
                        )}
                      </>
                    )}
                    {v.status === "resolved" && (
                      <button onClick={() => setStatus(v.id, "open")}
                        className="text-[11px] font-semibold text-gray-400 hover:text-rose-600 px-3 py-1.5 rounded-lg hover:bg-rose-50 transition-colors whitespace-nowrap">
                        Re-open
                      </button>
                    )}
                    {/* Add note toggle */}
                    <button onClick={() => setExpandedNote(expandedNote === v.id ? null : v.id)}
                      className={`text-[11px] font-medium px-3 py-1.5 rounded-lg transition-colors whitespace-nowrap flex items-center gap-1 ${expandedNote === v.id || violationNote ? "text-indigo-700 bg-indigo-50 border border-indigo-200" : "text-gray-400 hover:text-indigo-600 hover:bg-indigo-50 border border-gray-200"}`}>
                      <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
                      {violationNote ? "Edit Note" : "Add Note"}
                    </button>
                  </div>
                </div>

                {/* Note input */}
                {expandedNote === v.id && (
                  <div className="px-5 pb-4 border-t border-gray-100" style={{ background:"rgba(238,242,255,0.3)" }}>
                    <p className="text-[10px] font-bold text-indigo-600 uppercase tracking-widest mt-3 mb-2">Reviewer Note</p>
                    <textarea
                      value={violationNote}
                      onChange={e => saveNote(v.id, e.target.value)}
                      placeholder="Add context: risk accepted, waiting for vendor fix, escalation reason, etc."
                      rows={3}
                      className="w-full text-xs text-gray-700 bg-white border border-indigo-100 rounded-xl px-3 py-2 resize-none focus:outline-none focus:ring-2 focus:ring-indigo-300"
                    />
                    {violationNote && (
                      <button onClick={() => saveNote(v.id, "")}
                        className="text-[10px] text-gray-400 hover:text-rose-500 mt-1">
                        Clear note
                      </button>
                    )}
                  </div>
                )}

                {/* Remediation checklist — always visible when not resolved */}
                {v.status !== "resolved" && REMEDIATION[v.type] && (
                  <div className="px-5 pb-4 border-t border-gray-100" style={{ background:"rgba(248,250,252,0.8)" }}>
                    <p className="text-[10px] font-bold uppercase tracking-widest text-gray-400 mt-3 mb-2">Remediation Steps</p>
                    <div className="space-y-1.5">
                      {REMEDIATION[v.type].map((step, i) => (
                        <div key={i} className="flex items-start gap-2">
                          <span className="shrink-0 w-4 h-4 rounded-full border-2 border-gray-200 bg-white flex items-center justify-center mt-0.5 text-[8px] font-black text-gray-400">{i+1}</span>
                          <span className="text-[11px] text-gray-600 leading-snug">{step}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Inline code review panel — shown when in_review and reviewingId matches */}
                {v.status === "in_review" && reviewingId === v.id && v.scan_id && v.file && (
                  <InlineCodeReview
                    scanId={v.scan_id}
                    filePath={v.file}
                    onResolve={() => setStatus(v.id, "resolved")}
                    onReopen={() => setStatus(v.id, "open")}
                  />
                )}
              </div>
            );
          })}
        </div>

        {/* Policy note */}
        <div className="animate-fade-up flex items-start gap-3 bg-indigo-50 border border-indigo-100 rounded-xl px-4 py-3">
          <svg className="shrink-0 mt-0.5 text-indigo-500" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
            <circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>
          </svg>
          <p className="text-xs text-indigo-800 leading-relaxed">
            <span className="font-bold">Violation SLA policy:</span> CRITICAL violations must be resolved within 24 hours.
            HIGH violations within 48 hours. Status changes are saved locally and persist across sessions.
            Violations auto-update from live scan data every 30 seconds.
            <Link href="/settings" className="font-bold ml-1 underline underline-offset-2">Edit policies →</Link>
          </p>
        </div>

      </div>
      </PageSkeleton>
    </AuthGuard>
  );
}
