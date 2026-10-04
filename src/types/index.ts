import type { AttributionResult } from "@/lib/aiAttribution";
import type { TraceStep } from "@/lib/taint/taintCore";
import type { DataFlowEvidence } from "@/lib/dataFlowEvidence";
import type { FixSuggestion } from "@/lib/scanner";
import type { ScanHealth, ScanTelemetry } from "@/lib/scanHealth";
import type { FindingStatus, TriageDecision, LifecycleSummary, FixedFinding } from "@/lib/findingLifecycle";

export type { TraceStep, FixSuggestion };

export type RiskLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | "UNKNOWN";

// ── Scan ─────────────────────────────────────────────────────────────────────

export interface FileIndicator {
  id:       string;
  label:    string;
  severity: string;
  line?:    number;
  detail?:  string;
  // "third_party" (vendored/minified code) or "test_code" (test files) --
  // preserved as evidence but excluded from the file's risk_score; see
  // calculateRisk() and attachEvidence() in src/lib/scanner.ts.
  codeCategory?: "application" | "third_party" | "test_code";
  // Presence of a CWE is what the PR page uses to tell a real, CWE-mapped
  // security finding apart from an AI-heuristic signal when SIGNAL_META has
  // no curated entry for this id -- see isSecuritySignal() in pr/[id]/page.tsx.
  cwe?: string;
  // Per-instance call-graph reachability from src/lib/reachability.ts's
  // scoreExploitability(), merged onto the indicator in analyzeFile() and
  // persisted through the existing scan_files.indicators jsonb column -- no
  // separate DB column. Undefined means "unknown" (either this scan predates
  // the feature, or the finding wasn't a scored security indicator), not
  // "unreachable" -- see realReachability() in signalClassification.ts,
  // which is how the UI should always read this (never a static per-id
  // table, since the same rule id can be reachable at one line and dead code
  // at another within the same file).
  reachability?: "unreachable" | "reachable" | "tainted-path" | "entry-point";
  exploitability_score?: number;
  remediation_urgency?: "immediate" | "sprint" | "backlog" | "monitor";
  // Stable cross-scan identity of this exact finding (see src/lib/findingIdentity.ts) -- what suppression /
  // "new since last scan" tracking should key on, never the line number.
  fingerprint?: string;
  // Lifecycle in this PR and any triage decision on it (lib/findingLifecycle.ts); set by api/scans/[id].
  lifecycle_status?: FindingStatus;
  triage?: TriageDecision;
  // On lines the PR adds/changes (true) or already in a touched file (false); absent when unknown
  // (non-GitHub scans, or GitHub omitted the file's diff). See lib/prDiff.ts.
  introduced?: boolean;
  // 0-100 evidence strength: 95 = AST data-flow match; lower = pattern/heuristic. NOT severity.
  confidence?: number;
  // The tainted expression and the sink it reaches, verbatim from the AST engine (absent for regex findings).
  sourceExpr?: string;
  sinkExpr?: string;
  // Source -> sink data-flow path from the AST engine, source first, sink last (absent for regex findings).
  trace?: TraceStep[];
  // Other detectors that independently flagged this same issue.
  supportingDetectors?: string[];
  // Other locations of this same issue merged into this finding (see src/lib/findingCorrelation.ts).
  relatedLocations?: Array<{ line: number; id: string; label: string; detector: "data-flow" | "pattern"; reason: "same-line" | "on-path" | "cross-file"; file?: string }>;
  // Findings in other files of the PR whose confirmed data flow runs through this line.
  reachedFrom?: Array<{ file: string; line: number; id: string; source?: string }>;
  // Canonical data-flow evidence (src/lib/dataFlowEvidence.ts): source, exact sink + argument role, files
  // crossed, sanitisers on the path, canonical sink identity. Absent for pattern-only findings.
  flow?: DataFlowEvidence;
  // Function the flagged line sits in, when it could be named.
  functionName?: string;
}

// An explicit AI-tooling artifact (a repo config file or a commit/content
// marker) detected by detectAIToolingArtifacts() -- a literal fact ("this
// file exists" / "this string is present"), not a stylistic inference.
export interface AIToolingArtifact {
  tool:  string;
  file:  string;
  label: string;
}

export interface FileResult {
  file_path: string;
  language: string;
  ai_percentage: number;
  risk_score: RiskLevel;
  risk_indicators: string[];
  indicators?: FileIndicator[];
  attested: boolean;
  content?: string;
  attribution?: AttributionResult;
  // Remediation guidance for the vulnerability ids present in `indicators`, one per id.
  fix_suggestions?: FixSuggestion[];
}

export interface EvidenceBreakdown {
  code_evidence:      number;
  pr_evidence:        number;
  git_evidence:       number;
  tool_evidence:      number;
  baseline_evidence:  number;
  combined:           number;
  likelihood:         "Likely Human" | "Human with Tool Assistance" | "Mixed Authorship" | "Likely AI-Assisted" | "Strong AI Evidence";
  boosts:             string[];
  baseline_deviation?: {
    score:            number;
    loc_deviation:    number;
    commit_deviation: number;
    reasons:          string[];
  };
}

export interface ScanResult {
  scan_id: string;
  repo: string;
  pr_number: number;
  commit_sha: string;
  branch?: string;
  files: FileResult[];
  overall_risk: RiskLevel;
  total_ai_percentage: number;
  file_count?: number;
  attested_count?: number;
  triggered_by?: string;
  timestamp: string;
  evidence_breakdown?: EvidenceBreakdown;
  ai_tooling?: AIToolingArtifact[];
  // Set when attestation's automatic GitHub check-run flip-to-success
  // failed after a retry (see src/lib/attestation.ts) -- the PR page shows
  // a "GitHub status update failed — Retry" banner when this is non-null.
  check_run_sync_error?: string | null;
  // Scan health and timing (lib/scanHealth.ts); null before migration 20260930 or for older scans.
  health?: ScanHealth | null;
  telemetry?: ScanTelemetry | null;
  // The engine the server runs now -- a scan whose health.engine_version differs can be rescanned.
  current_engine_version?: string;
  // Finding lifecycle for this PR (lib/findingLifecycle.ts).
  lifecycle?: { summary: LifecycleSummary; fixed: FixedFinding[]; has_previous_scan: boolean };
}

// ── Attestation ───────────────────────────────────────────────────────────────

export interface AttestRequest {
  pr_id: string;
  file_path: string;
  reviewer_email: string;
  reviewer_github_login: string;
}

export interface AttestResponse {
  attestation_id: string;
  payload_hash: string;
  pgp_signature: string;
  attested_at: string;
}

// ── Status ────────────────────────────────────────────────────────────────────

export interface StatusResponse {
  blocked: boolean;
  unattested_files: string[];
  scan_id: string;
  commit_sha: string;
}

// ── Dashboard ─────────────────────────────────────────────────────────────────

export interface RiskTrendPoint {
  date: string;
  high_count: number;
  critical_count: number;
  medium_count: number;
}

export interface RepoStat {
  repo: string;
  ai_pct: number;
  attestation_rate: number;
  last_scan: string;
  scan_count: number;
  file_count: number;
  latest_scan_id: string;
  // CRITICAL/HIGH file count in the latest scan. Optional so older
  // cached/seed payloads without it still type-check.
  high_crit_count?: number;
}

export interface TopRiskFile {
  repo: string;
  file_path: string;
  ai_pct: number;
  risk_score: RiskLevel;
  attested: boolean;
  scan_id: string;
  pr_number: number;
  attested_by?: string;
  attested_at?: string;
}

export interface DashboardData {
  repos: RepoStat[];
  overall_ai_pct: number;
  attestation_rate: number;
  unattested_deploy_count: number;
  risk_trend: RiskTrendPoint[];
  // Exact CRITICAL/HIGH/MEDIUM file totals for the period -- NOT derivable
  // by summing risk_trend, which is row-limited for per-week bucketing.
  // Optional so older cached/seed payloads without it still type-check.
  risk_totals?: { critical_count: number; high_count: number; medium_count: number };
  scan_count: number;
  file_count: number;
  top_risk_files: TopRiskFile[];
  // Counts of open CRITICAL/HIGH violations whose attestation SLA deadline
  // has already passed (subset of unattested_deploy_count). Optional so
  // older cached/seed payloads without these fields still type-check.
  sla_breach_critical_count?: number;
  sla_breach_high_count?: number;
  // Individual CRITICAL/HIGH violations whose SLA deadline has passed —
  // lets the UI point directly at the breached files instead of just a count.
  sla_breach_files?: Array<{
    file_path: string;
    risk_score: RiskLevel;
    repo: string;
    scan_id: string;
    sla_deadline: string;
  }>;
  // Connected (switched-on) repositories, scanned in the period or not — the
  // denominator for 7-day coverage. Optional for older cached/seed payloads.
  connected_repo_count?: number;
  // attestation_rate = attested_high_crit ÷ total_high_crit (distinct files in
  // each repo's latest scan). Optional for older cached/seed payloads.
  attested_high_crit?: number;
  total_high_crit?: number;
  // The period actually covered (custom range or the last N days).
  period?: { start: string; end: string };
}

// ── Activity ──────────────────────────────────────────────────────────────────

export interface ActivityEvent {
  type: "scan" | "attestation";
  timestamp: string;
  repo: string;
  pr_number: number;
  scan_id: string;
  overall_risk: string;
  file_count: number;
  total_ai_pct: number;
  file_path: string;
  reviewer_email: string;
}

export interface ActivityResponse {
  events: ActivityEvent[];
}

// ── Report ────────────────────────────────────────────────────────────────────

export interface ScanRequest {
  repo: string;
  pr_number: number;
  commit_sha: string;
  files: Array<{ path: string; content: string }>;
}

export interface ReportRequest {
  org: string;
  period_start: string;
  period_end: string;
  framework: string;
}
