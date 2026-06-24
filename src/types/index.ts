export type RiskLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" | "UNKNOWN";

// ── Scan ─────────────────────────────────────────────────────────────────────

export interface FileIndicator {
  id:       string;
  label:    string;
  severity: string;
  line?:    number;
  detail?:  string;
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
