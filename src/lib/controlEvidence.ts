/**
 * Control evidence: what TrustLedger can actually PROVE about a set of compliance controls, from its own data.
 *
 * This is evidence for an auditor, not a compliance verdict. TrustLedger sees code changes, reviews, findings and
 * its own audit trail -- a small, specific slice of each framework. So:
 *   - each control is tied to concrete checks (CHECKS below) measured from real records, with the numbers shown;
 *   - a control's status says what the evidence shows -- collected / gaps / failing / not tested -- never "% ready";
 *   - every framework carries a scope statement saying what it does NOT cover.
 *
 * Citations are to the public framework texts: AICPA 2017 Trust Services Criteria (SOC 2), ISO/IEC 27001:2022
 * Annex A, PCI DSS v4.0. The EU AI Act is deliberately not assessed (it governs AI systems and their uses, not
 * teams that use AI coding tools); "AI code governance" covers TrustLedger's own AI-usage controls instead.
 *
 * Client-safe: pure, no I/O. The facts are loaded by lib/evidenceEngine.ts.
 */

export interface ComplianceFacts {
  period_start: string;
  period_end: string;
  /** Active repositories, and how many of them had at least one scan in the period. */
  repos: { active: number; scanned: number };
  prs_scanned: number;
  /** HIGH/CRITICAL files in each PR's latest scan in the period, and how many have a reviewer sign-off. */
  risky: { total: number; reviewed: number; ai_heavy_total: number; ai_heavy_reviewed: number };
  /** Sign-offs in the period: reviewer is not the PR author / is the author / can't be compared (missing identity). */
  reviews: { total: number; independent: number; self: number; unknown: number };
  /** Open findings now (latest row per repo+file), and how many are past their fix deadline. */
  findings: { open: number; open_with_deadline: number; overdue: number };
  secrets: { open: number; open_critical: number; resolved_in_period: number };
  audit: { valid: boolean; total: number; broken_at: number | null };
  access: { members: number; can_attest: number };
  /** available=false when the Shadow AI state couldn't be loaded (the policy check is then untested, not failing). */
  ai: { available: boolean; policy_configured: boolean; compliance: number | null; open_violations: number; files_analyzed: number };
}

export type EvidenceStatus = "pass" | "partial" | "fail" | "not_tested";
/** How each status reads to a person. "pass" is NOT "compliant": it means the evidence supports the control. */
export const STATUS_LABEL: Record<EvidenceStatus, string> = {
  pass: "Evidence collected", partial: "Gaps found", fail: "Failing", not_tested: "No evidence yet",
};

/**
 * What a check's evidence describes: what happened during the audit period ("period"), or the state when the
 * evidence was collected ("current": open findings, who holds sign-off rights, the audit chain, the AI policy). An
 * auditor tests the two differently -- a point-in-time state says nothing about the rest of the period.
 */
export type EvidenceBasis = "period" | "current";
export const BASIS_LABEL: Record<EvidenceBasis, string> = { period: "Over the period", current: "At collection time" };

export interface CheckResult {
  key: CheckKey;
  label: string;
  basis: EvidenceBasis;
  status: EvidenceStatus;
  /** 0-100: the measured share where there is one, else 100/0. */
  score: number;
  /** What was measured, with the numbers. */
  summary: string;
  /** What is missing, if anything. */
  gaps: string[];
}

export type CheckKey = "review" | "independent_review" | "scanning" | "remediation" | "secrets" | "audit_trail" | "approval_access" | "ai_policy" | "ai_review" | "ai_provenance";

/**
 * A control as an auditor writes it up in their working papers: what the control is, who owns it, how often it
 * operates, and the test TrustLedger's evidence lets them perform. `partial` says what part of the criterion the
 * evidence does NOT reach (the control id names a broader criterion than code changes).
 */
export interface ControlWriteUp {
  statement: string;
  owner: string;
  frequency: string;
  test: string;
  partial?: string;
}

export interface ControlResult extends ControlWriteUp {
  control_id: string;
  control_name: string;
  status: EvidenceStatus;
  score: number;
  checks: CheckResult[];
}

export interface FrameworkDef {
  id: "soc2" | "iso27001" | "pcidss" | "aigov";
  name: string;
  short: string;
  standard: string;
  scope: string;
  /** The framework's main areas this evidence doesn't reach -- listed so nobody reads the report as the whole framework. */
  not_covered: readonly string[];
  controls: Array<{ id: string; name: string; checks: CheckKey[] } & ControlWriteUp>;
}

// The same change-management control appears under SOC 2, ISO 27001 and PCI DSS: one write-up for all of them.
const CHANGE_CONTROL: ControlWriteUp = {
  statement: "Every change to application code is scanned for security issues and approved by someone other than its author before it is merged; a change the scan rates HIGH or CRITICAL also needs a named reviewer's sign-off.",
  owner: "Engineering lead (assign in your control matrix)",
  frequency: "Every pull request",
  test: "From the change register (every pull request merged in the period), confirm each has an approval recorded before it merged by someone other than the author, a TrustLedger scan, and a named sign-off on every HIGH or CRITICAL file. Draw the auditor sample from the register and inspect each selected pull request's evidence.",
};
const VULN_CONTROL: ControlWriteUp = {
  statement: "Code changes are scanned automatically for vulnerabilities and leaked secrets, and findings are fixed within the deadline set for their severity.",
  owner: "Security lead (assign in your control matrix)",
  frequency: "Every pull request; fix deadlines per severity",
  test: "Confirm every active repository was scanned in the period, that open findings are still within their fix deadline (any past it are listed as exceptions), and that leaked secrets were resolved.",
};
const LOG_PARTIAL = "Covers the integrity of TrustLedger's own activity log (scans, sign-offs, settings changes) -- not logging or monitoring of your production systems.";
const LOG_CONTROL: ControlWriteUp = {
  statement: "TrustLedger records every scan, sign-off and settings change in an append-only log, each entry chained to the previous one by SHA-256.",
  owner: "Security lead (assign in your control matrix)",
  frequency: "Continuous",
  test: "Recompute the log's hash chain for the whole period; it must verify end to end, and the database must refuse updates and deletes.",
  partial: LOG_PARTIAL,
};

/** What each check measures, in one line (compliance page's control map). */
export const CHECK_INFO: Record<CheckKey, { label: string; measures: string; basis: EvidenceBasis }> = {
  review:             { label: "High-risk changes reviewed",            basis: "period",  measures: "Share of HIGH/CRITICAL files in each pull request's latest scan with a named reviewer sign-off." },
  independent_review: { label: "Reviewer is not the author",            basis: "period",  measures: "Sign-offs whose reviewer's GitHub login differs from the pull request author's." },
  scanning:           { label: "Changes scanned automatically",         basis: "period",  measures: "Active repositories with at least one scan in the period; every pull request is scanned on push." },
  remediation:        { label: "Findings fixed on time",                basis: "current", measures: "Open findings still within their fix deadline (SLA), as they stand when the evidence is collected." },
  secrets:            { label: "Leaked secrets resolved",               basis: "current", measures: "Secret findings still open when the evidence is collected, and how many were resolved in the period." },
  audit_trail:        { label: "Tamper-evident audit trail",            basis: "current", measures: "The audit log's SHA-256 hash chain is recomputed when the evidence is collected and must verify end to end." },
  approval_access:    { label: "Sign-off restricted to authorised roles", basis: "current", measures: "Who holds the attest permission when the evidence is collected; it is checked on every sign-off request." },
  ai_policy:          { label: "Approved AI tools policy",              basis: "current", measures: "An approved-tools policy is set, and AI tool evidence in pull requests is for approved tools." },
  ai_review:          { label: "AI-written risky code reviewed",        basis: "period",  measures: "High-risk files that are mostly AI-written and have a named reviewer sign-off." },
  ai_provenance:      { label: "AI provenance recorded",                basis: "period",  measures: "Changed files with a stored AI-content estimate and AI tool evidence per commit." },
};

export const FRAMEWORKS: readonly FrameworkDef[] = [
  {
    id: "soc2", name: "SOC 2", short: "SOC 2", standard: "AICPA Trust Services Criteria (2017)",
    scope: "Evidence for the change-management and vulnerability-management criteria below, as they apply to code changes. SOC 2 also covers infrastructure, availability, confidentiality, privacy, vendor management and organisational controls that TrustLedger does not see. A SOC 2 report can only be issued by a licensed CPA firm.",
    not_covered: [
      "CC1–CC5: control environment, communication, risk assessment and monitoring activities (governance, policies, HR, board oversight)",
      "CC6 beyond sign-off rights: logical and physical access to your systems, identity provider, encryption, infrastructure",
      "CC7 beyond code: monitoring production systems, incident detection and response",
      "CC8 beyond code changes: infrastructure and configuration changes, deployments outside pull requests",
      "CC9: risk mitigation, vendor and business-partner management",
      "Availability, Confidentiality, Processing Integrity and Privacy criteria",
    ],
    controls: [
      { id: "CC8.1", name: "Changes are authorised, tested and approved", checks: ["review", "independent_review", "scanning"], ...CHANGE_CONTROL },
      { id: "CC7.1", name: "Vulnerabilities are detected and managed", checks: ["scanning", "remediation", "secrets"], ...VULN_CONTROL },
      { id: "CC6.1", name: "Approval rights are restricted", checks: ["approval_access"],
        statement: "Only members with the attest permission can sign off a high-risk change in TrustLedger; the permission is checked on every sign-off request and role changes are logged.",
        owner: "Security lead (assign in your control matrix)", frequency: "Every sign-off",
        test: "Inspect who holds the attest permission at the end of the period and the audit-log entries for role changes during it.",
        partial: "Covers who can sign off changes in TrustLedger only -- not logical access to your systems, data or infrastructure in general." },
      { id: "CC7.2", name: "Activity is logged and monitored", checks: ["audit_trail"], ...LOG_CONTROL },
    ],
  },
  {
    id: "iso27001", name: "ISO/IEC 27001:2022", short: "ISO 27001", standard: "ISO/IEC 27001:2022 Annex A",
    scope: "Evidence for the Annex A controls below, as they apply to software development. It does not cover the ISMS itself (scope, risk assessment, Statement of Applicability, management review) or other Annex A controls. Certification is issued only by an accredited certification body.",
    not_covered: [
      "Clauses 4–10: the ISMS itself -- scope, risk assessment and treatment, Statement of Applicability, internal audit, management review",
      "Annex A 5: organisational controls (policies, roles, supplier relationships, incident management, business continuity)",
      "Annex A 6: people controls (screening, awareness, training)",
      "Annex A 7: physical controls",
      "Annex A 8 beyond development: endpoint, identity and access, network, backup, cryptography, production logging and monitoring",
    ],
    controls: [
      { id: "A.8.25", name: "Secure development life cycle", checks: ["scanning"],
        statement: "Security testing is built into the development workflow: every pull request is scanned automatically before it can be merged.",
        owner: "Engineering lead (assign in your control matrix)", frequency: "Every pull request",
        test: "Confirm every active repository was scanned in the period and that scans ran on the pull requests in the change register." },
      { id: "A.8.28", name: "Secure coding", checks: ["review"],
        statement: "Code changes the scan rates HIGH or CRITICAL are reviewed and signed off by a named person before release.",
        owner: "Engineering lead (assign in your control matrix)", frequency: "Every high-risk change",
        test: "Confirm each HIGH or CRITICAL file in the period's pull requests has a named reviewer sign-off; unsigned files are listed as exceptions." },
      { id: "A.8.29", name: "Security testing in development", checks: ["scanning", "remediation"],
        statement: "Security testing runs on every change during development, and its findings are fixed within their deadline.",
        owner: "Security lead (assign in your control matrix)", frequency: "Every pull request; fix deadlines per severity",
        test: "Confirm scans ran in the period and that open findings are within their fix deadline; overdue findings are listed as exceptions." },
      { id: "A.8.32", name: "Change management", checks: ["review", "independent_review"], ...CHANGE_CONTROL },
      { id: "A.8.8", name: "Management of technical vulnerabilities", checks: ["remediation", "secrets"], ...VULN_CONTROL },
      { id: "A.8.15", name: "Logging", checks: ["audit_trail"], ...LOG_CONTROL },
    ],
  },
  {
    id: "pcidss", name: "PCI DSS v4.0", short: "PCI DSS", standard: "PCI DSS v4.0, Requirements 6 and 10",
    scope: "Evidence for the secure-development requirements below for bespoke and custom software. It does not cover network security, cardholder data protection, access management, physical security, ASV scans or penetration testing. Only an assessment by a QSA (Report on Compliance) or a Self-Assessment Questionnaire establishes PCI DSS compliance.",
    not_covered: [
      "Requirements 1–2: network security controls and secure configurations",
      "Requirements 3–4: protecting stored cardholder data and data in transit",
      "Requirement 5 and the rest of 6: anti-malware, public-facing web application protection, patching of system components",
      "Requirements 7–9: access control, authentication and physical security",
      "Requirement 10 beyond TrustLedger's own log; Requirement 11 (ASV scans, penetration testing); Requirement 12 (policies)",
    ],
    controls: [
      { id: "6.2.3", name: "Bespoke software is reviewed before release", checks: ["review", "scanning"], ...CHANGE_CONTROL },
      { id: "6.2.3.1", name: "Code review by someone other than the author", checks: ["independent_review", "approval_access"],
        statement: "Code changes are approved by someone other than their author, and only authorised roles can sign off high-risk changes.",
        owner: "Engineering lead (assign in your control matrix)", frequency: "Every pull request",
        test: "From the change register, confirm every merged pull request has an approval by someone other than its author; self-approved or unapproved merges are listed as exceptions." },
      { id: "6.2.4", name: "Common software attacks are prevented", checks: ["scanning"],
        statement: "Every change is scanned for common software attacks (injection, cross-site scripting, path traversal, insecure deserialisation and the other classes in the rule catalog) before it is merged.",
        owner: "Security lead (assign in your control matrix)", frequency: "Every pull request",
        test: "Confirm scans ran on the period's pull requests; findings are tracked under 6.3.1." },
      { id: "6.3.1", name: "Security vulnerabilities are identified and managed", checks: ["remediation", "secrets"], ...VULN_CONTROL },
      { id: "10.3.2", name: "Audit logs are protected from modification", checks: ["audit_trail"], ...LOG_CONTROL },
    ],
  },
  {
    id: "aigov", name: "AI code governance", short: "AI governance", standard: "TrustLedger AI usage controls",
    scope: "Controls for how your team uses AI coding tools: approved tools, human review of AI-written risky code, and recorded provenance. These are good practice and support internal AI policies; they are not a regulatory framework. The EU AI Act is not assessed here: it governs organisations that provide or deploy AI systems in specific uses, not teams that use AI coding assistants.",
    not_covered: [
      "An AI management system (ISO/IEC 42001): AI policy, risk and impact assessment, AI system life cycle, supplier management",
      "AI systems you build or deploy (EU AI Act obligations for providers and deployers, model risk management)",
      "Data used with AI tools: what code or data is sent to AI providers, retention and confidentiality terms",
    ],
    controls: [
      { id: "AIG-1", name: "Only approved AI tools are used", checks: ["ai_policy"],
        statement: "The organisation keeps a list of approved AI coding tools, and use of any other AI tool detected in pull requests is flagged for follow-up.",
        owner: "Engineering lead (assign in your control matrix)", frequency: "Every pull request",
        test: "Confirm an approved-tools policy was in place for the period and inspect open detections of unapproved tools." },
      { id: "AIG-2", name: "AI-written risky code is reviewed by a person", checks: ["ai_review"],
        statement: "A high-risk file that is mostly AI-written is reviewed and signed off by a named person before release.",
        owner: "Engineering lead (assign in your control matrix)", frequency: "Every high-risk change",
        test: "Confirm each high-risk, mostly AI-written file in the period has a named reviewer sign-off; unsigned files are exceptions." },
      { id: "AIG-3", name: "Reviewers are independent of the author", checks: ["independent_review"],
        statement: "Sign-offs are given by someone other than the change's author.",
        owner: "Engineering lead (assign in your control matrix)", frequency: "Every sign-off",
        test: "Compare each sign-off's reviewer with the pull request's author; self-approvals are exceptions." },
      { id: "AIG-4", name: "AI provenance is recorded for every change", checks: ["ai_provenance"],
        statement: "For every changed file, the estimated share of AI-written code and any AI tool evidence are stored against the commit.",
        owner: "Engineering lead (assign in your control matrix)", frequency: "Every pull request",
        test: "Confirm provenance records exist for the files changed in the period's pull requests." },
    ],
  },
];

const pct = (n: number, d: number) => (d > 0 ? Math.round((n / d) * 100) : 0);
const s = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

export function evaluateChecks(f: ComplianceFacts): Record<CheckKey, CheckResult> {
  const r = (key: CheckKey, label: string, status: EvidenceStatus, score: number, summary: string, gaps: string[] = []): CheckResult =>
    ({ key, label, basis: CHECK_INFO[key].basis, status, score, summary, gaps });
  const ratioStatus = (share: number, passAt: number, partialAt: number): EvidenceStatus => share >= passAt ? "pass" : share >= partialAt ? "partial" : "fail";

  // High-risk changes reviewed before merge
  const review = f.risky.total === 0
    ? r("review", "High-risk changes reviewed", "not_tested", 0, "No high-risk changes in this period, so there is nothing to sample.")
    : r("review", "High-risk changes reviewed", ratioStatus(f.risky.reviewed / f.risky.total, 0.9, 0.5), pct(f.risky.reviewed, f.risky.total),
      `${f.risky.reviewed} of ${s(f.risky.total, "high-risk file")} in recent pull requests have a named reviewer sign-off (${pct(f.risky.reviewed, f.risky.total)}%).`,
      f.risky.reviewed < f.risky.total ? [`${s(f.risky.total - f.risky.reviewed, "high-risk file")} not yet reviewed`] : []);

  // Reviewer is not the author
  const comparable = f.reviews.independent + f.reviews.self;
  const independent = f.reviews.total === 0
    ? r("independent_review", "Reviewer is not the author", "not_tested", 0, "No sign-offs in this period.")
    : comparable === 0
      ? r("independent_review", "Reviewer is not the author", "partial", 0, `${s(f.reviews.total, "sign-off")} in this period, but none could be compared with the pull request author.`,
        [`${s(f.reviews.unknown, "sign-off")} by a reviewer with no linked GitHub account, or on a pull request with no recorded author`])
      : r("independent_review", "Reviewer is not the author", f.reviews.self > 0 ? (f.reviews.self / comparable > 0.05 ? "fail" : "partial") : f.reviews.unknown > 0 ? "partial" : "pass",
        pct(f.reviews.independent, comparable),
        `${f.reviews.independent} of ${s(comparable, "comparable sign-off")} were by someone other than the pull request author.`,
        [
          ...(f.reviews.self ? [`${s(f.reviews.self, "self-approval")}: the author signed off their own change`] : []),
          ...(f.reviews.unknown ? [`${s(f.reviews.unknown, "sign-off")} couldn't be checked (reviewer has no linked GitHub account, or the pull request has no recorded author)`] : []),
        ]);

  // Every change scanned automatically
  const scanning = f.repos.active === 0
    ? r("scanning", "Changes scanned automatically", "not_tested", 0, "No active repositories.")
    : r("scanning", "Changes scanned automatically", ratioStatus(f.repos.scanned / f.repos.active, 0.9, 0.5), pct(f.repos.scanned, f.repos.active),
      `${f.repos.scanned} of ${s(f.repos.active, "active repository", "active repositories")} scanned in this period; ${s(f.prs_scanned, "pull request")} scanned for vulnerabilities, secrets and risky code.`,
      f.repos.scanned < f.repos.active ? [`${s(f.repos.active - f.repos.scanned, "active repository", "active repositories")} with no scan in this period`] : []);

  // Findings fixed within their deadline
  const remediation = f.prs_scanned === 0
    ? r("remediation", "Findings fixed on time", "not_tested", 0, "No scans in this period.")
    : f.findings.open_with_deadline === 0
      ? r("remediation", "Findings fixed on time", "pass", 100, `${s(f.findings.open, "open finding")}; none past a fix deadline.`)
      : r("remediation", "Findings fixed on time", ratioStatus(1 - f.findings.overdue / f.findings.open_with_deadline, 1, 0.8),
        pct(f.findings.open_with_deadline - f.findings.overdue, f.findings.open_with_deadline),
        `${f.findings.open_with_deadline - f.findings.overdue} of ${s(f.findings.open_with_deadline, "open finding")} with a deadline are still within it.`,
        f.findings.overdue ? [`${s(f.findings.overdue, "finding")} past its fix deadline`] : []);

  // Leaked secrets resolved
  const secrets = f.prs_scanned === 0
    ? r("secrets", "Leaked secrets resolved", "not_tested", 0, "No scans in this period.")
    : r("secrets", "Leaked secrets resolved", f.secrets.open === 0 ? "pass" : f.secrets.open_critical > 0 ? "fail" : "partial", f.secrets.open === 0 ? 100 : 0,
      `${s(f.secrets.open, "open secret finding")} (${f.secrets.open_critical} critical); ${f.secrets.resolved_in_period} resolved in this period.`,
      f.secrets.open ? [`${s(f.secrets.open, "secret")} still open: rotate the credential, then resolve the finding`] : []);

  // Tamper-evident audit trail
  const audit_trail = f.audit.total === 0
    ? r("audit_trail", "Tamper-evident audit trail", "not_tested", 0, "The audit log has no entries yet.")
    : f.audit.valid
      ? r("audit_trail", "Tamper-evident audit trail", "pass", 100, `${s(f.audit.total, "audit entry", "audit entries")}, each chained to the previous by SHA-256; the chain verifies intact. Updates and deletes are blocked by the database.`)
      : r("audit_trail", "Tamper-evident audit trail", "fail", 0, `The hash chain is broken${f.audit.broken_at != null ? ` at entry ${f.audit.broken_at}` : ""}: an entry was changed or removed.`, ["Investigate the broken audit chain"]);

  // Sign-off restricted to authorised roles (enforced by the product; the evidence is who holds the right)
  const approval_access = f.access.members === 0
    ? r("approval_access", "Sign-off restricted to authorised roles", "not_tested", 0, "No members.")
    : r("approval_access", "Sign-off restricted to authorised roles", "pass", 100,
      `Signing off a change requires the attest permission, checked on every request. ${f.access.can_attest} of ${s(f.access.members, "member")} hold it; changes to roles are recorded in the audit log.`);

  // AI tools policy
  const ai_policy = !f.ai.available
    ? r("ai_policy", "Approved AI tools policy", "not_tested", 0, "AI tool usage couldn't be loaded for this period.")
    : !f.ai.policy_configured
    ? r("ai_policy", "Approved AI tools policy", "fail", 0, "No approved AI tools policy has been set.", ["Choose your approved AI tools in Shadow AI"])
    : f.ai.compliance == null
      ? r("ai_policy", "Approved AI tools policy", "pass", 100, "A policy is set; no AI tool evidence in recent pull requests.")
      : r("ai_policy", "Approved AI tools policy", f.ai.open_violations === 0 ? "pass" : "partial", Math.round(f.ai.compliance * 100),
        `A policy is set; ${Math.round(f.ai.compliance * 100)}% of AI tool evidence in recent pull requests is for approved tools.`,
        f.ai.open_violations ? [`${s(f.ai.open_violations, "open detection")} of an unapproved AI tool`] : []);

  // AI-written risky code reviewed
  const ai_review = f.risky.ai_heavy_total === 0
    ? r("ai_review", "AI-written risky code reviewed", "not_tested", 0, "No high-risk, mostly AI-written files in this period.")
    : r("ai_review", "AI-written risky code reviewed", ratioStatus(f.risky.ai_heavy_reviewed / f.risky.ai_heavy_total, 0.9, 0.5), pct(f.risky.ai_heavy_reviewed, f.risky.ai_heavy_total),
      `${f.risky.ai_heavy_reviewed} of ${s(f.risky.ai_heavy_total, "high-risk file")} that are mostly AI-written have a named reviewer sign-off.`,
      f.risky.ai_heavy_reviewed < f.risky.ai_heavy_total ? [`${s(f.risky.ai_heavy_total - f.risky.ai_heavy_reviewed, "AI-written high-risk file")} not yet reviewed`] : []);

  // AI provenance recorded
  const ai_provenance = f.ai.files_analyzed === 0
    ? r("ai_provenance", "AI provenance recorded", "not_tested", 0, "No files analysed in this period.")
    : r("ai_provenance", "AI provenance recorded", "pass", 100,
      `${s(f.ai.files_analyzed, "changed file")} analysed in this period, each with its AI-content estimate and detected AI tool evidence stored against the commit.`);

  return { review, independent_review: independent, scanning, remediation, secrets, audit_trail, approval_access, ai_policy, ai_review, ai_provenance };
}

const RANK: Record<EvidenceStatus, number> = { fail: 0, partial: 1, not_tested: 2, pass: 3 };

/** A control's status is its weakest check's ("not tested" only when every check is untested). */
export function evaluateFramework(fw: FrameworkDef, checks: Record<CheckKey, CheckResult>): ControlResult[] {
  return fw.controls.map(c => {
    const results = c.checks.map(k => checks[k]);
    const tested = results.filter(x => x.status !== "not_tested");
    const status: EvidenceStatus = tested.length === 0 ? "not_tested"
      : tested.reduce<EvidenceStatus>((worst, x) => RANK[x.status] < RANK[worst] ? x.status : worst, "pass");
    const score = tested.length ? Math.min(...tested.map(x => x.score)) : 0;
    return {
      control_id: c.id, control_name: c.name, status, score, checks: results,
      statement: c.statement, owner: c.owner, frequency: c.frequency, test: c.test, ...(c.partial ? { partial: c.partial } : {}),
    };
  });
}

export function frameworkById(id: string): FrameworkDef | undefined {
  return FRAMEWORKS.find(f => f.id === id);
}

/** Old ids and names keep working ("eu"/"EU AI Act" → AI code governance). */
export function normalizeFrameworkId(raw: string): FrameworkDef["id"] {
  const key = (raw ?? "").toLowerCase().replace(/[^a-z0-9]/g, "");
  if (key.startsWith("soc")) return "soc2";
  if (key.startsWith("iso")) return "iso27001";
  if (key.startsWith("pci")) return "pcidss";
  if (key.startsWith("eu") || key.includes("aiact") || key.startsWith("ai")) return "aigov";
  return "soc2";
}

/** Raw rows for the period, as lib/evidenceEngine.ts loads them. */
export interface FactRows {
  period_start: string;
  period_end: string;
  now: string;
  activeRepos: readonly string[];
  scans: ReadonlyArray<{ id: string; repo: string; pr_number: number | null; pr_author: string | null; created_at: string }>;
  riskyFiles: ReadonlyArray<{ scan_id: string; file_path: string; ai_percentage: number | null; risk_score?: string | null }>;
  attestations: ReadonlyArray<{ scan_id: string; file_path: string; reviewer_github: string | null }>;
  violations: ReadonlyArray<{ scan_id: string; file_path: string; status: string; sla_deadline: string | null }>;
  secrets: { open: number; open_critical: number; resolved_in_period: number };
  audit: { valid: boolean; total: number; broken_at?: number | null };
  members: ReadonlyArray<{ can_attest: boolean }>;
  ai: { policy_configured: boolean; compliance: number | null; open_violations: number } | null;
  files_analyzed: number;
}

/** A file at least this AI-written counts as "mostly AI-written" (same threshold as the Trust Score). */
export const AI_HEAVY_SHARE = 0.5;

/** Each pull request's latest scan in the period: earlier pushes are superseded by later ones. */
function latestScanByPr(scans: FactRows["scans"]): Map<string, FactRows["scans"][number]> {
  const latestByPr = new Map<string, FactRows["scans"][number]>();
  for (const sc of scans) {
    const k = `${sc.repo}::${sc.pr_number ?? 0}`;
    const cur = latestByPr.get(k);
    if (!cur || sc.created_at > cur.created_at) latestByPr.set(k, sc);
  }
  return latestByPr;
}

export interface UnreviewedFile { repo: string; pr_number: number; scan_id: string; file_path: string; risk_score: string; ai_percentage: number }

/**
 * The HIGH/CRITICAL files the "High-risk changes reviewed" check counts as not reviewed -- the same files, by the same
 * rule (each pull request's latest scan; no sign-off on that scan and file) -- so a report's gap list and its CC8.1
 * count always agree. CRITICAL first, then by repository, pull request and path.
 */
export function unreviewedRiskyFiles(rows: Pick<FactRows, "scans" | "riskyFiles" | "attestations">): UnreviewedFile[] {
  const latest = new Map([...latestScanByPr(rows.scans).values()].map(s => [s.id, s]));
  const attested = new Set(rows.attestations.map(a => `${a.scan_id}::${a.file_path}`));
  const rank = (r: string) => (r === "CRITICAL" ? 0 : 1);
  return rows.riskyFiles
    .filter(f => latest.has(f.scan_id) && !attested.has(`${f.scan_id}::${f.file_path}`))
    .map(f => {
      const sc = latest.get(f.scan_id)!;
      return { repo: sc.repo, pr_number: sc.pr_number ?? 0, scan_id: f.scan_id, file_path: f.file_path, risk_score: f.risk_score ?? "HIGH", ai_percentage: f.ai_percentage ?? 0 };
    })
    .sort((a, b) => rank(a.risk_score) - rank(b.risk_score) || a.repo.localeCompare(b.repo) || a.pr_number - b.pr_number || a.file_path.localeCompare(b.file_path));
}

export function deriveFacts(rows: FactRows): ComplianceFacts {
  const active = new Set(rows.activeRepos);
  const scanById = new Map(rows.scans.map(s => [s.id, s]));

  const latestByPr = latestScanByPr(rows.scans);
  const latestIds = new Set([...latestByPr.values()].map(x => x.id));

  const attested = new Set(rows.attestations.map(a => `${a.scan_id}::${a.file_path}`));
  const risky = { total: 0, reviewed: 0, ai_heavy_total: 0, ai_heavy_reviewed: 0 };
  for (const f of rows.riskyFiles) {
    if (!latestIds.has(f.scan_id)) continue;
    const ok = attested.has(`${f.scan_id}::${f.file_path}`);
    risky.total++; if (ok) risky.reviewed++;
    if ((f.ai_percentage ?? 0) >= AI_HEAVY_SHARE) { risky.ai_heavy_total++; if (ok) risky.ai_heavy_reviewed++; }
  }

  // GitHub logins are case-insensitive.
  const reviews = { total: 0, independent: 0, self: 0, unknown: 0 };
  for (const a of rows.attestations) {
    const sc = scanById.get(a.scan_id);
    if (!sc) continue;
    reviews.total++;
    const reviewer = a.reviewer_github?.trim().toLowerCase(), author = sc.pr_author?.trim().toLowerCase();
    if (!reviewer || !author) reviews.unknown++;
    else if (reviewer === author) reviews.self++;
    else reviews.independent++;
  }

  // Open findings: the latest row per (repo, file) -- superseded rows don't count.
  const latestViolation = new Map<string, { status: string; sla: string | null; at: string }>();
  for (const v of rows.violations) {
    const sc = scanById.get(v.scan_id);
    if (!sc) continue;
    const k = `${sc.repo}::${v.file_path}`;
    const cur = latestViolation.get(k);
    if (!cur || sc.created_at > cur.at) latestViolation.set(k, { status: v.status, sla: v.sla_deadline, at: sc.created_at });
  }
  const open = [...latestViolation.values()].filter(v => v.status === "open" || v.status === "in_review");
  const withDeadline = open.filter(v => v.sla);

  return {
    period_start: rows.period_start, period_end: rows.period_end,
    repos: { active: active.size, scanned: [...active].filter(r => rows.scans.some(sc => sc.repo === r)).length },
    prs_scanned: latestByPr.size,
    risky, reviews,
    findings: { open: open.length, open_with_deadline: withDeadline.length, overdue: withDeadline.filter(v => v.sla! < rows.now).length },
    secrets: rows.secrets,
    audit: { valid: rows.audit.valid, total: rows.audit.total, broken_at: rows.audit.broken_at ?? null },
    access: { members: rows.members.length, can_attest: rows.members.filter(m => m.can_attest).length },
    ai: {
      available: rows.ai != null,
      policy_configured: rows.ai?.policy_configured ?? false,
      compliance: rows.ai?.compliance ?? null,
      open_violations: rows.ai?.open_violations ?? 0,
      files_analyzed: rows.files_analyzed,
    },
  };
}

export function countStatuses(controls: readonly ControlResult[]): Record<EvidenceStatus, number> {
  const out: Record<EvidenceStatus, number> = { pass: 0, partial: 0, fail: 0, not_tested: 0 };
  for (const c of controls) out[c.status]++;
  return out;
}
