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

export interface CheckResult {
  key: CheckKey;
  label: string;
  status: EvidenceStatus;
  /** 0-100: the measured share where there is one, else 100/0. */
  score: number;
  /** What was measured, with the numbers. */
  summary: string;
  /** What is missing, if anything. */
  gaps: string[];
}

export type CheckKey = "review" | "independent_review" | "scanning" | "remediation" | "secrets" | "audit_trail" | "approval_access" | "ai_policy" | "ai_review" | "ai_provenance";

export interface ControlResult {
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
  controls: Array<{ id: string; name: string; checks: CheckKey[] }>;
}

/** What each check measures, in one line (compliance page's control map). */
export const CHECK_INFO: Record<CheckKey, { label: string; measures: string }> = {
  review:             { label: "High-risk changes reviewed",            measures: "Share of HIGH/CRITICAL files in each pull request's latest scan with a named reviewer sign-off." },
  independent_review: { label: "Reviewer is not the author",            measures: "Sign-offs whose reviewer's GitHub login differs from the pull request author's." },
  scanning:           { label: "Changes scanned automatically",         measures: "Active repositories with at least one scan in the period; every pull request is scanned on push." },
  remediation:        { label: "Findings fixed on time",                measures: "Open findings still within their fix deadline (SLA)." },
  secrets:            { label: "Leaked secrets resolved",               measures: "Open secret findings, and how many were resolved in the period." },
  audit_trail:        { label: "Tamper-evident audit trail",            measures: "The audit log's SHA-256 hash chain is recomputed and must verify end to end." },
  approval_access:    { label: "Sign-off restricted to authorised roles", measures: "Who holds the attest permission; it is checked on every sign-off request." },
  ai_policy:          { label: "Approved AI tools policy",              measures: "An approved-tools policy is set, and AI tool evidence in pull requests is for approved tools." },
  ai_review:          { label: "AI-written risky code reviewed",        measures: "High-risk files that are mostly AI-written and have a named reviewer sign-off." },
  ai_provenance:      { label: "AI provenance recorded",                measures: "Changed files with a stored AI-content estimate and AI tool evidence per commit." },
};

export const FRAMEWORKS: readonly FrameworkDef[] = [
  {
    id: "soc2", name: "SOC 2", short: "SOC 2", standard: "AICPA Trust Services Criteria (2017)",
    scope: "Evidence for the change-management and vulnerability-management criteria below, as they apply to code changes. SOC 2 also covers infrastructure, availability, confidentiality, privacy, vendor management and organisational controls that TrustLedger does not see. A SOC 2 report can only be issued by a licensed CPA firm.",
    controls: [
      { id: "CC8.1", name: "Changes are authorised, tested and approved", checks: ["review", "independent_review", "scanning"] },
      { id: "CC7.1", name: "Vulnerabilities are detected and managed", checks: ["scanning", "remediation", "secrets"] },
      { id: "CC6.1", name: "Approval rights are restricted", checks: ["approval_access"] },
      { id: "CC7.2", name: "Activity is logged and monitored", checks: ["audit_trail"] },
    ],
  },
  {
    id: "iso27001", name: "ISO/IEC 27001:2022", short: "ISO 27001", standard: "ISO/IEC 27001:2022 Annex A",
    scope: "Evidence for the Annex A controls below, as they apply to software development. It does not cover the ISMS itself (scope, risk assessment, Statement of Applicability, management review) or other Annex A controls. Certification is issued only by an accredited certification body.",
    controls: [
      { id: "A.8.25", name: "Secure development life cycle", checks: ["scanning"] },
      { id: "A.8.28", name: "Secure coding", checks: ["review"] },
      { id: "A.8.29", name: "Security testing in development", checks: ["scanning", "remediation"] },
      { id: "A.8.32", name: "Change management", checks: ["review", "independent_review"] },
      { id: "A.8.8", name: "Management of technical vulnerabilities", checks: ["remediation", "secrets"] },
      { id: "A.8.15", name: "Logging", checks: ["audit_trail"] },
    ],
  },
  {
    id: "pcidss", name: "PCI DSS v4.0", short: "PCI DSS", standard: "PCI DSS v4.0, Requirements 6 and 10",
    scope: "Evidence for the secure-development requirements below for bespoke and custom software. It does not cover network security, cardholder data protection, access management, physical security, ASV scans or penetration testing. Only an assessment by a QSA (Report on Compliance) or a Self-Assessment Questionnaire establishes PCI DSS compliance.",
    controls: [
      { id: "6.2.3", name: "Bespoke software is reviewed before release", checks: ["review", "scanning"] },
      { id: "6.2.3.1", name: "Code review by someone other than the author", checks: ["independent_review", "approval_access"] },
      { id: "6.2.4", name: "Common software attacks are prevented", checks: ["scanning"] },
      { id: "6.3.1", name: "Security vulnerabilities are identified and managed", checks: ["remediation", "secrets"] },
      { id: "10.3.2", name: "Audit logs are protected from modification", checks: ["audit_trail"] },
    ],
  },
  {
    id: "aigov", name: "AI code governance", short: "AI governance", standard: "TrustLedger AI usage controls",
    scope: "Controls for how your team uses AI coding tools: approved tools, human review of AI-written risky code, and recorded provenance. These are good practice and support internal AI policies; they are not a regulatory framework. The EU AI Act is not assessed here: it governs organisations that provide or deploy AI systems in specific uses, not teams that use AI coding assistants.",
    controls: [
      { id: "AIG-1", name: "Only approved AI tools are used", checks: ["ai_policy"] },
      { id: "AIG-2", name: "AI-written risky code is reviewed by a person", checks: ["ai_review"] },
      { id: "AIG-3", name: "Reviewers are independent of the author", checks: ["independent_review"] },
      { id: "AIG-4", name: "AI provenance is recorded for every change", checks: ["ai_provenance"] },
    ],
  },
];

const pct = (n: number, d: number) => (d > 0 ? Math.round((n / d) * 100) : 0);
const s = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

export function evaluateChecks(f: ComplianceFacts): Record<CheckKey, CheckResult> {
  const r = (key: CheckKey, label: string, status: EvidenceStatus, score: number, summary: string, gaps: string[] = []): CheckResult =>
    ({ key, label, status, score, summary, gaps });
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
    return { control_id: c.id, control_name: c.name, status, score, checks: results };
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
  riskyFiles: ReadonlyArray<{ scan_id: string; file_path: string; ai_percentage: number | null }>;
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

export function deriveFacts(rows: FactRows): ComplianceFacts {
  const active = new Set(rows.activeRepos);
  const scanById = new Map(rows.scans.map(s => [s.id, s]));

  // Each pull request's latest scan: earlier pushes are superseded by later ones.
  const latestByPr = new Map<string, FactRows["scans"][number]>();
  for (const sc of rows.scans) {
    const k = `${sc.repo}::${sc.pr_number ?? 0}`;
    const cur = latestByPr.get(k);
    if (!cur || sc.created_at > cur.created_at) latestByPr.set(k, sc);
  }
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
