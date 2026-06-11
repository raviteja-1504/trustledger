/**
 * TrustLedger Compliance Policy Engine
 *
 * Evaluates source code and configuration files against four enterprise
 * compliance frameworks. Each framework is modelled as a set of controls;
 * each control has a set of detection rules (regex + structural checks).
 *
 * Frameworks:
 *   SOC 2 Type II  — Security, Availability, Confidentiality
 *   GDPR           — PII handling, consent, retention, erasure
 *   PCI-DSS v4.0   — Cardholder data, cryptography, access control
 *   HIPAA          — PHI handling, encryption, audit, access
 */

// ── Types ─────────────────────────────────────────────────────────────────────

export type ComplianceFramework = "SOC2" | "GDPR" | "PCI-DSS" | "HIPAA";

export interface ComplianceFinding {
  framework:   ComplianceFramework;
  control_id:  string;        // e.g. "SOC2-CC6.1", "GDPR-Art17", "PCI-DSS-3.4", "HIPAA-§164.312"
  title:       string;
  severity:    "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  file_path?:  string;
  line?:       number;
  detail:      string;
  remediation: string;
}

export interface ControlResult {
  control_id:  string;
  title:       string;
  status:      "PASS" | "FAIL" | "WARN" | "N/A";
  findings:    ComplianceFinding[];
}

export interface FrameworkReport {
  framework:     ComplianceFramework;
  controls:      ControlResult[];
  pass_count:    number;
  fail_count:    number;
  warn_count:    number;
  score:         number;  // 0–1
  risk_level:    "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
}

export interface ComplianceReport {
  frameworks:     FrameworkReport[];
  overall_score:  number;  // 0–1
  top_findings:   ComplianceFinding[];  // highest severity across all frameworks
}

// ── Detection rule helpers ────────────────────────────────────────────────────

interface Rule {
  re:          RegExp;
  invert?:     boolean;  // FAIL when pattern is ABSENT (required pattern)
  finding:     Omit<ComplianceFinding, "file_path" | "line">;
  line_level:  boolean;  // true = check each line; false = check whole file
}

function runRules(
  rules: Rule[], content: string, lines: string[], fp: string,
): ComplianceFinding[] {
  const findings: ComplianceFinding[] = [];
  for (const rule of rules) {
    if (rule.line_level) {
      lines.forEach((line, idx) => {
        if (rule.re.test(line) && !rule.invert) {
          findings.push({ ...rule.finding, file_path: fp, line: idx + 1 });
        }
      });
    } else {
      const matched = rule.re.test(content);
      const triggered = rule.invert ? !matched : matched;
      if (triggered) findings.push({ ...rule.finding, file_path: fp });
    }
  }
  return findings;
}

// ── SOC 2 Type II controls ────────────────────────────────────────────────────
// Focus areas: logical access, encryption, audit logging, monitoring, change management.

const SOC2_RULES: Array<Rule & { control_id: string; control_title: string }> = [
  {
    control_id:    "SOC2-CC6.1",
    control_title: "Logical & Physical Access Controls",
    re:   /(?:password|token|secret|apiKey|api_key)\s*=\s*["'][^"']{6,}["']/i,
    line_level: true,
    finding: { framework:"SOC2", control_id:"SOC2-CC6.1", title:"Hardcoded credential",
      severity:"CRITICAL", detail:"Hardcoded credential in source bypasses access control",
      remediation:"Store in environment variables or a secrets manager (Vault, AWS SSM)" },
  },
  {
    control_id:    "SOC2-CC6.1",
    control_title: "Logical & Physical Access Controls",
    re:   /role\s*(?:===?|!==?)\s*["'](?:admin|superuser|root)["']/i,
    line_level: true,
    finding: { framework:"SOC2", control_id:"SOC2-CC6.1", title:"Hardcoded role check",
      severity:"HIGH", detail:"Hardcoded role comparison risks privilege escalation bypass",
      remediation:"Use RBAC middleware with centralised policy enforcement" },
  },
  {
    control_id:    "SOC2-CC7.2",
    control_title: "System Monitoring",
    re:   /(?:console\.log|print|fmt\.Println)\s*\([^)]*(?:password|token|secret|key|credential)/i,
    line_level: true,
    finding: { framework:"SOC2", control_id:"SOC2-CC7.2", title:"Credential logged to console",
      severity:"HIGH", detail:"Sensitive value may appear in log aggregators",
      remediation:"Remove from log statement or mask with '****'" },
  },
  {
    control_id:    "SOC2-CC8.1",
    control_title: "Change Management",
    re:   /\bTODO\b.{0,60}(?:auth|token|secret|permission|access)/i,
    line_level: true,
    finding: { framework:"SOC2", control_id:"SOC2-CC8.1", title:"Unresolved security TODO",
      severity:"MEDIUM", detail:"Outstanding TODO on security-sensitive code path",
      remediation:"Resolve before merging to production branch" },
  },
  {
    control_id:    "SOC2-CC6.7",
    control_title: "Encryption in Transit",
    re:   /http:\/\/(?!localhost|127\.0\.0\.1)/,
    line_level: true,
    finding: { framework:"SOC2", control_id:"SOC2-CC6.7", title:"Plaintext HTTP endpoint",
      severity:"HIGH", detail:"Non-TLS HTTP URL in production code",
      remediation:"Replace with https:// endpoint" },
  },
  {
    control_id:    "SOC2-CC6.8",
    control_title: "Malicious Software Prevention",
    re:   /eval\s*\(|new\s+Function\s*\(/,
    line_level: true,
    finding: { framework:"SOC2", control_id:"SOC2-CC6.8", title:"Dynamic code execution",
      severity:"HIGH", detail:"eval() or new Function() enables arbitrary code injection",
      remediation:"Eliminate dynamic code execution; use data-driven logic" },
  },
  {
    control_id:    "SOC2-A1.2",
    control_title: "Availability — Rate Limiting",
    re:   /rateLimit|throttle|rate_limit/i,
    invert: true,
    line_level: false,
    finding: { framework:"SOC2", control_id:"SOC2-A1.2", title:"No rate limiting detected",
      severity:"MEDIUM", detail:"No rate-limit middleware found in this file",
      remediation:"Add express-rate-limit, Fastify rate-limiter, or equivalent" },
  },
];

// ── GDPR controls ─────────────────────────────────────────────────────────────

const GDPR_RULES: Array<Rule & { control_id: string; control_title: string }> = [
  {
    control_id:    "GDPR-Art5",
    control_title: "Data Minimisation",
    re:   /SELECT\s+\*\s+FROM|find\(\s*\{?\s*\}?\s*\)/i,
    line_level: true,
    finding: { framework:"GDPR", control_id:"GDPR-Art5", title:"SELECT * / unbounded query",
      severity:"MEDIUM", detail:"Fetching all columns/documents violates data minimisation",
      remediation:"Select only required fields: SELECT id, email FROM … or .find({}, {id:1, email:1})" },
  },
  {
    control_id:    "GDPR-Art9",
    control_title: "Special Category Data",
    re:   /\b(?:ssn|social_security|passport_number|dob|date_of_birth|religion|ethnicity|biometric|health_record|medical_record|diagnosis)\b/i,
    line_level: true,
    finding: { framework:"GDPR", control_id:"GDPR-Art9", title:"Special category personal data",
      severity:"HIGH", detail:"Code handles sensitive GDPR Article 9 categories",
      remediation:"Ensure explicit consent, purpose limitation, and encryption at rest" },
  },
  {
    control_id:    "GDPR-Art17",
    control_title: "Right to Erasure",
    re:   /DELETE\s+FROM|\.deleteOne|\.deleteMany|\.destroy\s*\(/i,
    invert: true,
    line_level: false,
    finding: { framework:"GDPR", control_id:"GDPR-Art17", title:"No deletion endpoint detected",
      severity:"INFO", detail:"No data deletion operation found — verify right-to-erasure is implemented",
      remediation:"Implement user-initiated data deletion endpoint" },
  },
  {
    control_id:    "GDPR-Art25",
    control_title: "Privacy by Design",
    re:   /password\b(?!.*(?:hash|bcrypt|scrypt|argon|pbkdf))/i,
    line_level: true,
    finding: { framework:"GDPR", control_id:"GDPR-Art25", title:"Possible plaintext password storage",
      severity:"CRITICAL", detail:"'password' field without hashing function reference",
      remediation:"Hash with bcrypt, scrypt, or argon2 before persisting" },
  },
  {
    control_id:    "GDPR-Art32",
    control_title: "Encryption at Rest",
    re:   /(?:md5|sha1|sha_1)\s*\(/i,
    line_level: true,
    finding: { framework:"GDPR", control_id:"GDPR-Art32", title:"Weak hash algorithm",
      severity:"HIGH", detail:"MD5/SHA-1 are cryptographically broken for data protection",
      remediation:"Use SHA-256 or stronger; use bcrypt/argon2 for passwords" },
  },
  {
    control_id:    "GDPR-Art30",
    control_title: "Records of Processing",
    re:   /(?:audit|AuditLog|audit_log|writeAudit)/,
    invert: true,
    line_level: false,
    finding: { framework:"GDPR", control_id:"GDPR-Art30", title:"No audit logging detected",
      severity:"MEDIUM", detail:"GDPR Article 30 requires records of processing activities",
      remediation:"Add audit log calls on data access, modification, and deletion" },
  },
];

// ── PCI-DSS v4.0 controls ─────────────────────────────────────────────────────

const PCI_RULES: Array<Rule & { control_id: string; control_title: string }> = [
  {
    control_id:    "PCI-DSS-3.4",
    control_title: "Render PAN Unreadable",
    re:   /\b(?:card_?number|pan|primary_?account_?number|cc_?number|credit_?card)\b/i,
    line_level: true,
    finding: { framework:"PCI-DSS", control_id:"PCI-DSS-3.4", title:"Cardholder PAN field reference",
      severity:"CRITICAL", detail:"PAN data must be masked, truncated, or encrypted at rest",
      remediation:"Tokenise with a PCI-compliant vault; never log or store raw PAN" },
  },
  {
    control_id:    "PCI-DSS-4.2.1",
    control_title: "Strong Cryptography in Transit",
    re:   /TLSv1\.0|TLSv1\.1|ssl_version\s*=\s*["'](?:TLSv1|SSLv)/i,
    line_level: true,
    finding: { framework:"PCI-DSS", control_id:"PCI-DSS-4.2.1", title:"Deprecated TLS version",
      severity:"HIGH", detail:"TLS 1.0/1.1 are prohibited by PCI-DSS v4.0; use TLS 1.2+",
      remediation:"Configure minimum TLS 1.2; prefer TLS 1.3" },
  },
  {
    control_id:    "PCI-DSS-6.4.3",
    control_title: "Payment Page Script Integrity",
    re:   /<script\s[^>]*src=["'][^"']+["'][^>]*>/i,
    line_level: true,
    finding: { framework:"PCI-DSS", control_id:"PCI-DSS-6.4.3", title:"Script tag without integrity attribute",
      severity:"MEDIUM", detail:"PCI-DSS 6.4.3 requires SRI hashes on all payment page scripts",
      remediation:"Add integrity='sha256-…' and crossorigin='anonymous' to script tags" },
  },
  {
    control_id:    "PCI-DSS-7.2.1",
    control_title: "Access Control Systems",
    re:   /(?:authorization|access_?control|checkPermission|hasRole|isAuthorized)/i,
    invert: true,
    line_level: false,
    finding: { framework:"PCI-DSS", control_id:"PCI-DSS-7.2.1", title:"No authorisation check detected",
      severity:"HIGH", detail:"Routes handling payment data must enforce role-based access control",
      remediation:"Add authorisation middleware (checkPermission, hasRole, policy engine)" },
  },
  {
    control_id:    "PCI-DSS-10.2",
    control_title: "Audit Log All Access",
    re:   /(?:cvv|cvv2|cvc|csc|card_?verification)\b/i,
    line_level: true,
    finding: { framework:"PCI-DSS", control_id:"PCI-DSS-10.2", title:"CVV/CVC field reference",
      severity:"CRITICAL", detail:"CVV must never be stored after authorisation",
      remediation:"Remove any persistence of CVV; PCI-DSS Requirement 3.3 prohibits storage" },
  },
  {
    control_id:    "PCI-DSS-12.3.3",
    control_title: "Cryptographic Key Management",
    re:   /(?:private_key|privateKey|secret_key|secretKey)\s*=\s*["'][A-Za-z0-9+/=]{20,}/i,
    line_level: true,
    finding: { framework:"PCI-DSS", control_id:"PCI-DSS-12.3.3", title:"Hardcoded cryptographic key",
      severity:"CRITICAL", detail:"Cryptographic keys must be stored in a key management system",
      remediation:"Use AWS KMS, HashiCorp Vault, or Azure Key Vault" },
  },
];

// ── HIPAA controls ────────────────────────────────────────────────────────────

const HIPAA_RULES: Array<Rule & { control_id: string; control_title: string }> = [
  {
    control_id:    "HIPAA-§164.312(a)",
    control_title: "Access Control — Unique User Identification",
    re:   /\b(?:patient_?id|patient_?name|mrn|medical_record_number|diagnosis|prescription|medication|icd_?10|procedure_?code)\b/i,
    line_level: true,
    finding: { framework:"HIPAA", control_id:"HIPAA-§164.312(a)", title:"PHI field detected",
      severity:"HIGH", detail:"Protected Health Information requires HIPAA safeguards",
      remediation:"Encrypt at rest, enforce minimum-necessary access, audit all access" },
  },
  {
    control_id:    "HIPAA-§164.312(e)",
    control_title: "Transmission Security",
    re:   /http:\/\/(?!localhost)/,
    line_level: true,
    finding: { framework:"HIPAA", control_id:"HIPAA-§164.312(e)", title:"PHI transmitted over HTTP",
      severity:"CRITICAL", detail:"HIPAA requires encryption for all PHI in transit",
      remediation:"Use HTTPS/TLS for all PHI transmission" },
  },
  {
    control_id:    "HIPAA-§164.312(b)",
    control_title: "Audit Controls",
    re:   /(?:audit|auditLog|hipaa_?audit|access_?log)/i,
    invert: true,
    line_level: false,
    finding: { framework:"HIPAA", control_id:"HIPAA-§164.312(b)", title:"No HIPAA audit logging",
      severity:"HIGH", detail:"HIPAA requires audit controls for all PHI system activity",
      remediation:"Implement audit logging with user ID, timestamp, action, and PHI record ID" },
  },
  {
    control_id:    "HIPAA-§164.312(c)",
    control_title: "Integrity Controls",
    re:   /(?:sha256|hmac|signature|checksum)/i,
    invert: true,
    line_level: false,
    finding: { framework:"HIPAA", control_id:"HIPAA-§164.312(c)", title:"No integrity verification",
      severity:"MEDIUM", detail:"HIPAA requires PHI integrity controls to detect tampering",
      remediation:"Add HMAC or digital signature verification on PHI records" },
  },
  {
    control_id:    "HIPAA-§164.308(a)(4)",
    control_title: "Information Access Management",
    re:   /console\.(?:log|info|debug)\s*\([^)]*(?:patient|diagnosis|medication|health|phi)\b/i,
    line_level: true,
    finding: { framework:"HIPAA", control_id:"HIPAA-§164.308(a)(4)", title:"PHI in application log",
      severity:"CRITICAL", detail:"Logging PHI violates minimum-necessary and creates disclosure risk",
      remediation:"Remove PHI from logs; if needed, log a record ID only" },
  },
  {
    control_id:    "HIPAA-§164.312(a)(2)(iv)",
    control_title: "Encryption at Rest",
    re:   /AES|encrypt|cipher|crypto\.createCipher/i,
    invert: true,
    line_level: false,
    finding: { framework:"HIPAA", control_id:"HIPAA-§164.312(a)(2)(iv)", title:"No encryption-at-rest pattern",
      severity:"MEDIUM", detail:"HIPAA addressable safeguard: PHI should be encrypted at rest",
      remediation:"Use AES-256-GCM for PHI fields before database persistence" },
  },
];

// ── Framework evaluation ──────────────────────────────────────────────────────

type RawRule = Rule & { control_id: string; control_title: string };

function evaluateFramework(
  framework:  ComplianceFramework,
  rules:      RawRule[],
  content:    string,
  lines:      string[],
  filePath:   string,
): FrameworkReport {
  // Group rules by control
  const controlMap = new Map<string, { title: string; rules: RawRule[] }>();
  for (const r of rules) {
    if (!controlMap.has(r.control_id)) {
      controlMap.set(r.control_id, { title: r.control_title, rules: [] });
    }
    controlMap.get(r.control_id)!.rules.push(r);
  }

  const controls: ControlResult[] = [];
  for (const [ctrl_id, ctrl] of Array.from(controlMap.entries())) {
    const findings = ctrl.rules.flatMap((r: RawRule) => runRules([r], content, lines, filePath));
    const status: ControlResult["status"] =
      findings.some((f: ComplianceFinding) => f.severity === "CRITICAL" || f.severity === "HIGH") ? "FAIL" :
      findings.some((f: ComplianceFinding) => f.severity === "MEDIUM") ? "WARN" :
      findings.length > 0 ? "WARN" : "PASS";
    controls.push({ control_id: ctrl_id, title: ctrl.title, status, findings });
  }

  const passCount = controls.filter(c => c.status === "PASS").length;
  const failCount = controls.filter(c => c.status === "FAIL").length;
  const warnCount = controls.filter(c => c.status === "WARN").length;
  const total     = controls.length || 1;
  const score     = (passCount + warnCount * 0.5) / total;
  const frameworkRiskLevel: FrameworkReport["risk_level"] =
    failCount >= 2 ? "CRITICAL" : failCount >= 1 ? "HIGH" : warnCount >= 2 ? "MEDIUM" : "LOW";

  return { framework, controls, pass_count: passCount, fail_count: failCount, warn_count: warnCount, score, risk_level: frameworkRiskLevel };
}

// ── Main entry ────────────────────────────────────────────────────────────────

export function evaluateCompliance(
  content:   string,
  filePath:  string,
  frameworks: ComplianceFramework[] = ["SOC2", "GDPR", "PCI-DSS", "HIPAA"],
): ComplianceReport {
  const lines = content.split("\n");
  const reports: FrameworkReport[] = [];

  if (frameworks.includes("SOC2"))    reports.push(evaluateFramework("SOC2",    SOC2_RULES,  content, lines, filePath));
  if (frameworks.includes("GDPR"))    reports.push(evaluateFramework("GDPR",    GDPR_RULES,  content, lines, filePath));
  if (frameworks.includes("PCI-DSS")) reports.push(evaluateFramework("PCI-DSS", PCI_RULES,   content, lines, filePath));
  if (frameworks.includes("HIPAA"))   reports.push(evaluateFramework("HIPAA",   HIPAA_RULES, content, lines, filePath));

  const overallScore = reports.length === 0 ? 1
    : reports.reduce((s, r) => s + r.score, 0) / reports.length;

  const allFindings = reports.flatMap(r => r.controls.flatMap(c => c.findings));
  const severityOrder = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
  const topFindings = allFindings
    .sort((a, b) => (severityOrder[b.severity] ?? 0) - (severityOrder[a.severity] ?? 0))
    .slice(0, 10);

  return { frameworks: reports, overall_score: overallScore, top_findings: topFindings };
}

// ── Multi-file scan aggregate ─────────────────────────────────────────────────

export function aggregateComplianceReports(reports: ComplianceReport[]): ComplianceReport {
  if (reports.length === 0) {
    return { frameworks: [], overall_score: 1, top_findings: [] };
  }
  const overallScore = reports.reduce((s, r) => s + r.overall_score, 0) / reports.length;
  const allFindings  = reports.flatMap(r => r.top_findings);
  const severityOrder = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
  const topFindings  = allFindings
    .sort((a, b) => (severityOrder[b.severity] ?? 0) - (severityOrder[a.severity] ?? 0))
    .slice(0, 20);
  // Merge framework reports across files
  const fwMap = new Map<ComplianceFramework, FrameworkReport>();
  for (const report of reports) {
    for (const fw of report.frameworks) {
      const existing = fwMap.get(fw.framework);
      if (!existing) { fwMap.set(fw.framework, { ...fw }); continue; }
      existing.fail_count  += fw.fail_count;
      existing.warn_count  += fw.warn_count;
      existing.pass_count  += fw.pass_count;
      existing.score        = (existing.score + fw.score) / 2;
      existing.controls     = [...existing.controls, ...fw.controls];
      const sev = (s: FrameworkReport["risk_level"]) =>
        ({ LOW:0, MEDIUM:1, HIGH:2, CRITICAL:3 }[s]);
      if (sev(fw.risk_level) > sev(existing.risk_level)) existing.risk_level = fw.risk_level;
    }
  }
  return { frameworks: Array.from(fwMap.values()), overall_score: overallScore, top_findings: topFindings };
}
