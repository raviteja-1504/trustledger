"use client";

export interface OrgPolicy {
  name: string;

  // Merge gates
  block_on_critical: boolean;
  block_on_high: boolean;
  block_on_medium: boolean;

  // Required attestations per risk level
  attestations_critical: number;
  attestations_high: number;
  attestations_medium: number;

  // AI% at which a file is considered "at risk" (overrides detection defaults)
  ai_flag_threshold: number; // 0.0–1.0

  // Reviewer requirements
  require_designated_reviewer: boolean;
  require_two_reviewers?: boolean;

  // SLA
  attest_sla_hours?: number;

  // Notifications
  slack_webhook: string;
  alert_email: string;
  notify_critical: boolean;
  notify_scan_complete: boolean;
  notify_weekly_digest: boolean;
}

export const PRESETS: Record<"standard" | "strict", Omit<OrgPolicy, "slack_webhook" | "alert_email">> = {
  standard: {
    name: "Standard",
    block_on_critical: true,
    block_on_high: true,
    block_on_medium: false,
    attestations_critical: 1,
    attestations_high: 1,
    attestations_medium: 0,
    ai_flag_threshold: 0.65,
    require_designated_reviewer: false,
    notify_critical: true,
    notify_scan_complete: false,
    notify_weekly_digest: true,
  },
  strict: {
    name: "Strict",
    block_on_critical: true,
    block_on_high: true,
    block_on_medium: true,
    attestations_critical: 2,
    attestations_high: 1,
    attestations_medium: 1,
    ai_flag_threshold: 0.50,
    require_designated_reviewer: true,
    notify_critical: true,
    notify_scan_complete: true,
    notify_weekly_digest: true,
  },
};

export const DEFAULT_POLICY: OrgPolicy = {
  ...PRESETS.standard,
  slack_webhook: "",
  alert_email: "",
};

const KEY = "tl_org_policy";

export function loadPolicy(): OrgPolicy {
  if (typeof window === "undefined") return { ...DEFAULT_POLICY };
  try {
    const s = localStorage.getItem(KEY);
    if (s) return { ...DEFAULT_POLICY, ...JSON.parse(s) };
  } catch {}
  return { ...DEFAULT_POLICY };
}

export function savePolicy(p: OrgPolicy): void {
  if (typeof window !== "undefined") {
    localStorage.setItem(KEY, JSON.stringify(p));
  }
}

export interface PolicyViolation {
  file: string;
  reason: string;
  severity: "critical" | "high" | "medium";
  // Populated when a real indicator drove the reason (as opposed to the
  // generic risk-level fallback below) -- lets the UI show CWE/confidence/
  // detail instead of just a templated "CRITICAL risk — requires N
  // attestation(s)" string with no explanation of what was actually found.
  indicator_id?:  string;
  cwe?:           string;
  confidence?:    number;
}

export interface PolicyResult {
  pass: boolean;
  violations: PolicyViolation[];
  gated: boolean; // would actually block merge
}

interface FileIndicator {
  id: string; label: string; severity: string; detail?: string;
  cwe?: string; confidence?: number; codeCategory?: string;
}

const SEVERITY_RANK: Record<string, number> = { critical: 3, high: 2, medium: 1, low: 0, info: -1 };

// The most specific non-third-party indicator at or above the violation's
// own severity -- this is what actually drove risk_score to this level (see
// scanner.ts's calculateRisk), so it's the right evidence to explain with.
function bestIndicatorFor(indicators: FileIndicator[] | undefined, minSeverity: string): FileIndicator | undefined {
  if (!indicators) return undefined;
  const candidates = indicators.filter(i =>
    i.codeCategory !== "third_party" &&
    (SEVERITY_RANK[i.severity] ?? -1) >= (SEVERITY_RANK[minSeverity] ?? 0)
  );
  if (candidates.length === 0) return undefined;
  return candidates.sort((a, b) =>
    (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0) ||
    (b.confidence ?? 0) - (a.confidence ?? 0)
  )[0];
}

function explainedReason(fallback: string, ind: FileIndicator | undefined): Pick<PolicyViolation, "reason" | "indicator_id" | "cwe" | "confidence"> {
  if (!ind) return { reason: fallback };
  const parts = [ind.label];
  if (ind.detail) parts.push(ind.detail);
  const suffix = [
    ind.cwe ? ind.cwe : null,
    ind.confidence != null ? `${ind.confidence}% confidence` : null,
  ].filter(Boolean).join(" · ");
  return {
    reason: suffix ? `${parts.join(" — ")} (${suffix})` : parts.join(" — "),
    indicator_id: ind.id, cwe: ind.cwe, confidence: ind.confidence,
  };
}

export function evaluatePolicy(
  policy: OrgPolicy,
  files: Array<{
    file_path: string;
    risk_score: string;
    attested: boolean;
    ai_percentage: number;
    indicators?: FileIndicator[];
  }>,
  attestedSet: Set<string>
): PolicyResult {
  const violations: PolicyViolation[] = [];

  for (const f of files) {
    const attested = f.attested || attestedSet.has(f.file_path);
    const risk = f.risk_score as "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";

    if (risk === "CRITICAL" && policy.block_on_critical) {
      const required = policy.attestations_critical;
      if (!attested) {
        violations.push({
          file: f.file_path,
          severity: "critical",
          ...explainedReason(
            `CRITICAL risk — requires ${required} attestation${required !== 1 ? "s" : ""}`,
            bestIndicatorFor(f.indicators, "critical"),
          ),
        });
      }
    }

    if (risk === "HIGH" && policy.block_on_high) {
      if (!attested) {
        violations.push({
          file: f.file_path,
          severity: "high",
          ...explainedReason(
            `HIGH risk — requires ${policy.attestations_high} attestation`,
            bestIndicatorFor(f.indicators, "high"),
          ),
        });
      }
    }

    if (risk === "MEDIUM" && policy.block_on_medium) {
      if (!attested) {
        violations.push({
          file: f.file_path,
          severity: "medium",
          ...explainedReason(
            `MEDIUM risk — policy requires attestation`,
            bestIndicatorFor(f.indicators, "medium"),
          ),
        });
      }
    }

    if (f.ai_percentage > policy.ai_flag_threshold && !attested && risk !== "LOW" && risk !== "UNKNOWN") {
      const already = violations.find(v => v.file === f.file_path);
      if (!already) {
        violations.push({
          file: f.file_path,
          reason: `AI content ${(f.ai_percentage * 100).toFixed(0)}% exceeds org threshold of ${(policy.ai_flag_threshold * 100).toFixed(0)}%`,
          severity: "medium",
        });
      }
    }
  }

  const gated = violations.some(v =>
    (v.severity === "critical" && policy.block_on_critical) ||
    (v.severity === "high"     && policy.block_on_high)     ||
    (v.severity === "medium"   && policy.block_on_medium)
  );

  return { pass: violations.length === 0, violations, gated };
}
