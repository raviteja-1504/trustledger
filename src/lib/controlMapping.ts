/**
 * Versioned mappings between compliance framework controls and the evidence
 * types that support them.
 *
 * IMPORTANT: A technical scan alone does NOT establish compliance. Each
 * mapping entry explicitly names which evidence types are required AND carries
 * a disclaimer.  Human review, policy documentation, and testing by an
 * independent assessor are always required beyond what TrustLedger can collect
 * automatically.
 *
 * Supported frameworks:
 *   SOC 2 (AICPA Trust Services Criteria, 2017)
 *   PCI-DSS v4.0
 *   ISO/IEC 27001:2022
 *   AI code governance (aigov) — TrustLedger's own AI-usage controls; the EU AI
 *     Act governs AI system providers/deployers, not teams using coding
 *     assistants, so it is not assessed here.
 *
 * Client-safe: no I/O, no imports from server-only modules.
 */

import type { EvidenceType } from "./evidenceRecord";

// ── Version ───────────────────────────────────────────────────────────────────

/** Bump when the set of controls or required evidence types changes. */
export const CONTROL_MAPPING_VERSION = "1.0";

// ── Types ─────────────────────────────────────────────────────────────────────

/**
 * Whether a single evidence record of this type partially or fully satisfies
 * a check on its own.
 *   "primary"     — this type is a direct signal for the control
 *   "corroborating" — provides supporting context; a primary is also needed
 */
export type EvidenceRole = "primary" | "corroborating";

export interface ControlEvidenceRequirement {
  evidence_type: EvidenceType;
  role:          EvidenceRole;
  /** Human-readable explanation of what this evidence type contributes. */
  rationale:     string;
}

export interface ControlMapping {
  control_id:   string;
  control_name: string;
  /**
   * Always false.  A collection of technical evidence records supports, but
   * never by itself establishes, compliance with a control.
   */
  sufficient_alone: false;
  required_evidence: ControlEvidenceRequirement[];
}

export interface FrameworkMapping {
  framework_id:      string;
  framework_name:    string;
  framework_version: string;
  mapping_version:   typeof CONTROL_MAPPING_VERSION;
  /**
   * What TrustLedger evidence covers and — critically — what it does NOT.
   * Always surface this alongside the evidence.
   */
  scope_disclaimer:  string;
  controls:          ControlMapping[];
}

// ── SOC 2 (AICPA TSC 2017) ────────────────────────────────────────────────────

export const SOC2_MAPPING: FrameworkMapping = {
  framework_id:      "soc2",
  framework_name:    "SOC 2",
  framework_version: "AICPA Trust Services Criteria (2017)",
  mapping_version:   CONTROL_MAPPING_VERSION,
  scope_disclaimer:
    "This evidence covers code-change management and vulnerability management only. " +
    "SOC 2 also covers infrastructure, availability, confidentiality, privacy, vendor " +
    "management and organisational controls that TrustLedger does not see. " +
    "A SOC 2 report can only be issued by a licensed CPA firm.",
  controls: [
    {
      control_id:       "CC8.1",
      control_name:     "Changes are authorised, tested and approved",
      sufficient_alone: false,
      required_evidence: [
        { evidence_type: "pr_approval",          role: "primary",       rationale: "Approval by someone other than the author before merge" },
        { evidence_type: "reviewer_attestation", role: "primary",       rationale: "Named sign-off on HIGH/CRITICAL files" },
        { evidence_type: "security_scan",        role: "corroborating", rationale: "Scan ran on the PR before it was merged" },
        { evidence_type: "repository_change",    role: "corroborating", rationale: "Commit record tying the approval to the change" },
      ],
    },
    {
      control_id:       "CC7.1",
      control_name:     "Vulnerabilities are detected and managed",
      sufficient_alone: false,
      required_evidence: [
        { evidence_type: "security_scan",             role: "primary",       rationale: "Automated scan on every PR" },
        { evidence_type: "secret_detection",          role: "primary",       rationale: "Secret-detection run and resolution" },
        { evidence_type: "vulnerability_remediation", role: "primary",       rationale: "Findings fixed within SLA deadline" },
        { evidence_type: "dependency_analysis",       role: "corroborating", rationale: "Third-party dependency vulnerabilities" },
      ],
    },
    {
      control_id:       "CC6.1",
      control_name:     "Approval rights are restricted to authorised roles",
      sufficient_alone: false,
      required_evidence: [
        { evidence_type: "access_control_event", role: "primary",       rationale: "Role assignments granting/revoking attest permission" },
        { evidence_type: "pr_approval",          role: "corroborating", rationale: "Sign-offs whose reviewer held the attest permission at the time" },
      ],
    },
    {
      control_id:       "CC7.2",
      control_name:     "Activity is logged and monitored",
      sufficient_alone: false,
      required_evidence: [
        { evidence_type: "access_control_event", role: "primary", rationale: "Audit-log entries for settings and role changes" },
        { evidence_type: "repository_change",    role: "primary", rationale: "Merge/push events in the connected repository" },
      ],
    },
  ],
};

// ── PCI-DSS v4.0 ──────────────────────────────────────────────────────────────

export const PCI_DSS_MAPPING: FrameworkMapping = {
  framework_id:      "pcidss",
  framework_name:    "PCI DSS v4.0",
  framework_version: "PCI DSS v4.0 Requirements 6 and 10",
  mapping_version:   CONTROL_MAPPING_VERSION,
  scope_disclaimer:
    "This evidence covers secure-development requirements for bespoke and custom software. " +
    "It does not cover network security, cardholder data protection, access management, " +
    "physical security, ASV scans or penetration testing. " +
    "Only an assessment by a QSA (Report on Compliance) or a Self-Assessment Questionnaire " +
    "establishes PCI DSS compliance.",
  controls: [
    {
      control_id:       "6.2.3",
      control_name:     "Bespoke software is reviewed before release",
      sufficient_alone: false,
      required_evidence: [
        { evidence_type: "pr_approval",          role: "primary",       rationale: "Pre-merge approval recorded" },
        { evidence_type: "reviewer_attestation", role: "primary",       rationale: "Named sign-off on the code review" },
        { evidence_type: "security_scan",        role: "corroborating", rationale: "Automated scan evidence for the change" },
      ],
    },
    {
      control_id:       "6.2.3.1",
      control_name:     "Code review by someone other than the author",
      sufficient_alone: false,
      required_evidence: [
        { evidence_type: "pr_approval",          role: "primary",       rationale: "Approval by a reviewer whose identity differs from the PR author" },
        { evidence_type: "access_control_event", role: "corroborating", rationale: "Role record confirming the reviewer held attest permission" },
      ],
    },
    {
      control_id:       "6.2.4",
      control_name:     "Common software attacks are prevented",
      sufficient_alone: false,
      required_evidence: [
        { evidence_type: "security_scan",  role: "primary",       rationale: "Scan for injection, XSS, path traversal, and other OWASP classes" },
        { evidence_type: "dependency_analysis", role: "corroborating", rationale: "Third-party library vulnerability scan" },
      ],
    },
    {
      control_id:       "6.3.1",
      control_name:     "Security vulnerabilities are identified and managed",
      sufficient_alone: false,
      required_evidence: [
        { evidence_type: "security_scan",             role: "primary", rationale: "Finding detection" },
        { evidence_type: "vulnerability_remediation", role: "primary", rationale: "Finding closure within the fix deadline" },
        { evidence_type: "secret_detection",          role: "primary", rationale: "Secret-finding detection and resolution" },
      ],
    },
    {
      control_id:       "10.3.2",
      control_name:     "Audit logs are protected from modification",
      sufficient_alone: false,
      required_evidence: [
        { evidence_type: "access_control_event", role: "primary", rationale: "Audit-log integrity entries (hash chain)" },
        { evidence_type: "repository_change",    role: "corroborating", rationale: "Repository event log entries" },
      ],
    },
  ],
};

// ── ISO/IEC 27001:2022 ────────────────────────────────────────────────────────

export const ISO27001_MAPPING: FrameworkMapping = {
  framework_id:      "iso27001",
  framework_name:    "ISO/IEC 27001:2022",
  framework_version: "ISO/IEC 27001:2022 Annex A",
  mapping_version:   CONTROL_MAPPING_VERSION,
  scope_disclaimer:
    "Evidence for the Annex A controls below, as they apply to software development. " +
    "It does not cover the ISMS itself (scope, risk assessment, Statement of Applicability, " +
    "management review) or other Annex A controls. " +
    "Certification is issued only by an accredited certification body.",
  controls: [
    {
      control_id:       "A.8.25",
      control_name:     "Secure development life cycle",
      sufficient_alone: false,
      required_evidence: [
        { evidence_type: "security_scan",     role: "primary",       rationale: "Automated security testing on every pull request" },
        { evidence_type: "repository_change", role: "corroborating", rationale: "Change records confirming scans ran on the change" },
      ],
    },
    {
      control_id:       "A.8.28",
      control_name:     "Secure coding",
      sufficient_alone: false,
      required_evidence: [
        { evidence_type: "reviewer_attestation", role: "primary",       rationale: "Named sign-off on HIGH/CRITICAL files" },
        { evidence_type: "pr_approval",          role: "corroborating", rationale: "Approval before merge" },
      ],
    },
    {
      control_id:       "A.8.29",
      control_name:     "Security testing in development",
      sufficient_alone: false,
      required_evidence: [
        { evidence_type: "security_scan",             role: "primary", rationale: "Automated scan on every PR" },
        { evidence_type: "vulnerability_remediation", role: "primary", rationale: "Findings resolved within SLA" },
      ],
    },
    {
      control_id:       "A.8.32",
      control_name:     "Change management",
      sufficient_alone: false,
      required_evidence: [
        { evidence_type: "pr_approval",          role: "primary",       rationale: "Approval before merge" },
        { evidence_type: "reviewer_attestation", role: "primary",       rationale: "Independent reviewer sign-off" },
        { evidence_type: "repository_change",    role: "corroborating", rationale: "Commit/merge event record" },
      ],
    },
    {
      control_id:       "A.8.8",
      control_name:     "Management of technical vulnerabilities",
      sufficient_alone: false,
      required_evidence: [
        { evidence_type: "vulnerability_remediation", role: "primary",       rationale: "Findings fixed within deadline" },
        { evidence_type: "secret_detection",          role: "primary",       rationale: "Leaked secrets resolved" },
        { evidence_type: "dependency_analysis",       role: "corroborating", rationale: "Third-party dependency scan" },
      ],
    },
    {
      control_id:       "A.8.15",
      control_name:     "Logging",
      sufficient_alone: false,
      required_evidence: [
        { evidence_type: "access_control_event", role: "primary",       rationale: "Audit-log entries for all security-relevant events" },
        { evidence_type: "repository_change",    role: "corroborating", rationale: "Repository activity log" },
      ],
    },
    {
      control_id:       "A.5.9",
      control_name:     "Inventory of information and other associated assets",
      sufficient_alone: false,
      required_evidence: [
        { evidence_type: "dependency_analysis",  role: "primary",       rationale: "Software dependency manifest capturing third-party assets" },
        { evidence_type: "repository_change",    role: "corroborating", rationale: "Change events that modify the asset inventory" },
      ],
    },
    {
      control_id:       "A.5.15",
      control_name:     "Access control",
      sufficient_alone: false,
      required_evidence: [
        { evidence_type: "access_control_event", role: "primary", rationale: "Member add/remove and role-change events" },
      ],
    },
    {
      control_id:       "A.5.36",
      control_name:     "Compliance with policies",
      sufficient_alone: false,
      required_evidence: [
        { evidence_type: "risk_assessment",      role: "primary",       rationale: "Risk register entries documenting accepted/treated risks" },
        { evidence_type: "security_scan",        role: "corroborating", rationale: "Automated policy check results" },
      ],
    },
  ],
};

// ── AI code governance (aigov) ────────────────────────────────────────────────
// Note: The EU AI Act governs AI system providers and deployers — not teams
// that use AI coding assistants. TrustLedger's "aigov" framework covers the
// internal controls for responsible AI tool use. These are good practice and
// support internal AI policies; they are not an EU AI Act assessment.

export const AIGOV_MAPPING: FrameworkMapping = {
  framework_id:      "aigov",
  framework_name:    "AI code governance",
  framework_version: "TrustLedger AI usage controls v1.0",
  mapping_version:   CONTROL_MAPPING_VERSION,
  scope_disclaimer:
    "Controls for how your team uses AI coding tools: approved tools, human review of " +
    "AI-written risky code, and recorded provenance. These are good practice and support " +
    "internal AI policies; they are not an EU AI Act assessment. " +
    "The EU AI Act governs organisations that provide or deploy AI systems in specific " +
    "regulated uses, not teams that use AI coding assistants.",
  controls: [
    {
      control_id:       "AIG-1",
      control_name:     "Only approved AI tools are used",
      sufficient_alone: false,
      required_evidence: [
        { evidence_type: "security_scan",    role: "primary",       rationale: "AI tool detection in pull requests" },
        { evidence_type: "risk_assessment",  role: "corroborating", rationale: "Approved-tools policy documented in the risk register" },
      ],
    },
    {
      control_id:       "AIG-2",
      control_name:     "AI-written risky code is reviewed by a human",
      sufficient_alone: false,
      required_evidence: [
        { evidence_type: "reviewer_attestation", role: "primary",       rationale: "Named sign-off on HIGH/CRITICAL files with high AI content" },
        { evidence_type: "security_scan",        role: "corroborating", rationale: "AI-content percentage measurement per file" },
      ],
    },
    {
      control_id:       "AIG-3",
      control_name:     "AI code provenance is recorded",
      sufficient_alone: false,
      required_evidence: [
        { evidence_type: "repository_change", role: "primary", rationale: "Commit-level AI tool evidence recorded per changed file" },
        { evidence_type: "security_scan",     role: "primary", rationale: "AI-content estimate stored with the scan result" },
      ],
    },
  ],
};

// ── Registry and lookup ───────────────────────────────────────────────────────

export const ALL_FRAMEWORK_MAPPINGS: readonly FrameworkMapping[] = [
  SOC2_MAPPING,
  PCI_DSS_MAPPING,
  ISO27001_MAPPING,
  AIGOV_MAPPING,
];

/** Look up a framework mapping by id (case-insensitive). */
export function getFrameworkMapping(frameworkId: string): FrameworkMapping | undefined {
  const id = frameworkId.toLowerCase().replace(/[^a-z0-9]/g, "");
  return ALL_FRAMEWORK_MAPPINGS.find(f => {
    const fid = f.framework_id.toLowerCase().replace(/[^a-z0-9]/g, "");
    return fid === id;
  });
}

/** All evidence types required for a specific control in a framework. */
export function requiredEvidenceTypes(
  frameworkId: string,
  controlId:   string,
): EvidenceType[] {
  const fw = getFrameworkMapping(frameworkId);
  if (!fw) return [];
  const ctrl = fw.controls.find(c => c.control_id === controlId);
  return ctrl?.required_evidence.map(r => r.evidence_type) ?? [];
}

// ── Coverage gap analysis ─────────────────────────────────────────────────────

import type { EvidenceRecord } from "./evidenceRecord";
import { isExpired } from "./evidenceRecord";

export type ControlCoverageStatus = "satisfied" | "partial" | "missing" | "expired";

export interface ControlCoverageResult {
  control_id:   string;
  control_name: string;
  status:       ControlCoverageStatus;
  /**
   * Always false.  Listed explicitly to make clear that even a "satisfied"
   * status means TrustLedger has collected supporting evidence — it does NOT
   * mean the control is compliant.
   */
  sufficient_alone: false;
  satisfied_types:  EvidenceType[];
  missing_types:    EvidenceType[];
  expired_types:    EvidenceType[];
  freshness_days:   number | null;
}

/**
 * Given all evidence records collected for an org+framework, compute coverage
 * status for every control in that framework.
 */
export function coverageReport(
  frameworkId: string,
  records:     EvidenceRecord[],
  now = new Date(),
): ControlCoverageResult[] {
  const fw = getFrameworkMapping(frameworkId);
  if (!fw) return [];

  return fw.controls.map(ctrl => {
    const ctrlRecords = records.filter(
      r => r.framework === fw.framework_id && r.control_id === ctrl.control_id,
    );

    const satisfied_types: EvidenceType[] = [];
    const missing_types:   EvidenceType[] = [];
    const expired_types:   EvidenceType[] = [];

    for (const req of ctrl.required_evidence) {
      const matching = ctrlRecords.filter(r => r.evidence_type === req.evidence_type);
      if (matching.length === 0) {
        missing_types.push(req.evidence_type);
      } else {
        const hasActive = matching.some(r => !isExpired(r, now) && r.verification_status !== "revoked");
        const hasExpired = matching.some(r => isExpired(r, now));
        if (hasActive) {
          satisfied_types.push(req.evidence_type);
        } else if (hasExpired) {
          expired_types.push(req.evidence_type);
        } else {
          missing_types.push(req.evidence_type);
        }
      }
    }

    const status: ControlCoverageStatus =
      missing_types.length === 0 && expired_types.length === 0 && satisfied_types.length > 0
        ? "satisfied"
        : expired_types.length > 0 && missing_types.length === 0
          ? "expired"
          : satisfied_types.length > 0
            ? "partial"
            : "missing";

    // Freshness: days until the soonest-expiring active record for this control
    const activeRecords = ctrlRecords.filter(r => !isExpired(r, now) && r.verification_status !== "revoked");
    const freshness_days = activeRecords.length > 0
      ? Math.min(...activeRecords.map(r => Math.round((new Date(r.expiration_date).getTime() - now.getTime()) / 86_400_000)))
      : null;

    return {
      control_id:       ctrl.control_id,
      control_name:     ctrl.control_name,
      status,
      sufficient_alone: false,
      satisfied_types,
      missing_types,
      expired_types,
      freshness_days,
    };
  });
}

/** Summary counts across all controls for a framework. */
export interface FrameworkCoverageSummary {
  framework_id:   string;
  mapping_version: string;
  scope_disclaimer: string;
  total_controls:  number;
  satisfied:       number;
  partial:         number;
  missing:         number;
  expired:         number;
  controls:        ControlCoverageResult[];
}

export function frameworkCoverageSummary(
  frameworkId: string,
  records:     EvidenceRecord[],
  now = new Date(),
): FrameworkCoverageSummary | undefined {
  const fw = getFrameworkMapping(frameworkId);
  if (!fw) return undefined;
  const controls = coverageReport(frameworkId, records, now);
  return {
    framework_id:     fw.framework_id,
    mapping_version:  fw.mapping_version,
    scope_disclaimer: fw.scope_disclaimer,
    total_controls:   controls.length,
    satisfied:  controls.filter(c => c.status === "satisfied").length,
    partial:    controls.filter(c => c.status === "partial").length,
    missing:    controls.filter(c => c.status === "missing").length,
    expired:    controls.filter(c => c.status === "expired").length,
    controls,
  };
}
