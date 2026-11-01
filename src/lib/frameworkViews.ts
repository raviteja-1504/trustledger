/**
 * Framework-specific views of the control evidence -- the form each framework's assessor works in, rather than the
 * same control list relabelled:
 *
 *   - ISO/IEC 27001: input for the Statement of Applicability, for the Annex A 8 development controls. TrustLedger
 *     fills in implementation and evidence where it has some, and says plainly where it has none; applicability is
 *     the organisation's decision, made in its own SoA.
 *   - PCI DSS 6.2.4: the common software attack classes the requirement lists, with the TrustLedger rules that check
 *     for each and where static scanning stops.
 *   - AI code governance: each AIG control's related ISO/IEC 42001 Annex A controls and NIST AI RMF 1.0
 *     subcategories. Indicative only: these support an AI management system's evidence, they don't establish
 *     conformity, and a control with no direct counterpart says so.
 *
 * SOC 2's own view is the change register (lib/changeRegister.ts). Client-safe: pure, no I/O.
 */
import type { EvidenceStatus, FrameworkDef } from "@/lib/controlEvidence";

/** What these views read from an evaluated control (lib/controlEvidence.ts ControlResult, or an evidence package's). */
export interface ControlLike {
  control_id: string;
  status: EvidenceStatus;
  checks: ReadonlyArray<{ gaps: readonly string[] }>;
  statement?: string;
  partial?: string;
}

// ── ISO/IEC 27001:2022 Statement of Applicability input ──────────────────────

export interface SoaRow {
  control: string;
  title: string;
  /** Whether TrustLedger holds evidence for it. Applicability itself is the organisation's decision. */
  evidenced: boolean;
  implementation: string;
  evidence_reference: string;
  status: EvidenceStatus | null;
  gaps: string[];
}

/** The Annex A 8 controls about building and changing software, in Annex A order (ISO/IEC 27001:2022 titles). */
const ISO_DEV_CONTROLS: ReadonlyArray<[id: string, title: string]> = [
  ["A.8.4", "Access to source code"],
  ["A.8.8", "Management of technical vulnerabilities"],
  ["A.8.15", "Logging"],
  ["A.8.25", "Secure development life cycle"],
  ["A.8.26", "Application security requirements"],
  ["A.8.27", "Secure system architecture and engineering principles"],
  ["A.8.28", "Secure coding"],
  ["A.8.29", "Security testing in development and acceptance"],
  ["A.8.30", "Outsourced development"],
  ["A.8.31", "Separation of development, test and production environments"],
  ["A.8.32", "Change management"],
  ["A.8.33", "Test information"],
];

const NOT_EVIDENCED = "TrustLedger holds no evidence for this control. Decide its applicability in your SoA and evidence it elsewhere.";

export function isoSoaRows(controls: readonly ControlLike[]): SoaRow[] {
  const byId = new Map(controls.map(c => [c.control_id, c]));
  return ISO_DEV_CONTROLS.map(([id, title]) => {
    const c = byId.get(id);
    if (!c) return { control: id, title, evidenced: false, implementation: NOT_EVIDENCED, evidence_reference: "—", status: null, gaps: [] };
    const reference = [`Control Evidence, ${id}`, ...(id === "A.8.32" ? ["Change-Management Register and auditor sample"] : [])].join("; ");
    return {
      control: id, title, evidenced: true,
      implementation: c.partial ? `${c.statement ?? ""} (Partial: ${c.partial})` : c.statement ?? "",
      evidence_reference: reference, status: c.status, gaps: c.checks.flatMap(k => k.gaps),
    };
  });
}

// ── PCI DSS v4.0 Requirement 6.2.4 attack classes ─────────────────────────────

export interface AttackClass {
  key: string;
  /** The attack class as Requirement 6.2.4 lists it. */
  title: string;
  /** TrustLedger rules (lib/findingCatalog.ts ids) that check bespoke code for it. */
  rules: readonly string[];
  /** What static scanning can't establish for this class, so the rest is evidenced another way. */
  limits: string;
}

export const PCI_624_CLASSES: readonly AttackClass[] = [
  { key: "injection", title: "Injection attacks (SQL, LDAP, XPath, OS command and other injection)",
    rules: ["sql-injection", "nosql-injection", "ldap-injection", "xpath-injection", "command-injection", "argument-injection", "graphql-injection",
      "ssti", "header-injection", "log-injection", "format-string", "eval-exec", "xxe", "file-inclusion", "unsafe-reflection"],
    limits: "Found where untrusted input reaches a query or command in the code TrustLedger scans; injection through stored data or other services is not traced." },
  { key: "data", title: "Attacks on data and data structures (buffer overflows, manipulating buffers, pointers, input data or shared data)",
    rules: ["buffer-overflow", "integer-overflow", "arithmetic-overflow", "use-after-free", "double-free", "null-dereference", "mismatched-deallocation",
      "input-validation", "insecure-deserialization", "prototype-pollution", "mass-assignment", "variable-overwrite", "race-condition", "toctou", "path-traversal"],
    limits: "Memory-safety rules apply to C and C++; concurrency issues are found only where the race is visible within a file." },
  { key: "crypto", title: "Attacks on cryptography usage (weak or insecure cryptographic implementations, algorithms, cipher suites or modes)",
    rules: ["weak-crypto", "insecure-randomness", "jwt-none-alg", "tls-verification-disabled", "timing-attack", "weak-signing-secret", "hardcoded-secret",
      "plaintext-password-storage", "cleartext-sensitive-storage"],
    limits: "Checks how code uses cryptography; key management, certificates and TLS configuration of your servers are outside the code." },
  { key: "business-logic", title: "Attacks on business logic (abusing or bypassing application features through APIs, protocols, client-side functionality), including XSS and CSRF",
    rules: ["xss", "csrf", "csrf-protection-disabled", "open-redirect", "ssrf", "weak-cors", "rate-limit-bypass", "resource-exhaustion", "redos",
      "type-juggling", "session-fixation", "cookie-no-httponly", "cookie-no-secure"],
    limits: "Static rules find known patterns (XSS, CSRF, SSRF and similar); flaws in your own business rules need code review and testing." },
  { key: "access-control", title: "Attacks on access control mechanisms (bypassing or abusing identification, authentication or authorization)",
    rules: ["idor", "bola-identity-mismatch", "bola-missing-ownership-check", "missing-function-level-authz", "privilege-escalation",
      "php-missing-session-guard", "unauthenticated-diagnostics", "insecure-permissions"],
    limits: "Finds missing checks in route handlers; whether your access model is right is a design question for review." },
  { key: "high-risk", title: "Attacks via any high-risk vulnerabilities identified in the vulnerability identification process (Requirement 6.3.1)",
    rules: [],
    limits: "Every finding above is tracked to a fix deadline by severity; the evidence is under 6.3.1 in Control Evidence." },
];

// ── AI code governance → ISO/IEC 42001 and NIST AI RMF ───────────────────────

export interface AiMapping {
  control: string;
  name: string;
  status: EvidenceStatus | null;
  iso42001: ReadonlyArray<{ id: string; title: string }>;
  nist_ai_rmf: ReadonlyArray<{ id: string; summary: string }>;
  note: string;
}

const AI_MAP: Readonly<Record<string, Omit<AiMapping, "control" | "name" | "status">>> = {
  "AIG-1": {
    iso42001: [{ id: "A.9.2", title: "Processes for responsible use of AI systems" }, { id: "A.10.3", title: "Suppliers" }],
    nist_ai_rmf: [
      { id: "GOVERN 6.1", summary: "Policies and procedures address AI risks associated with third-party entities" },
      { id: "MANAGE 3.1", summary: "AI risks and benefits from third-party resources are regularly monitored" },
    ],
    note: "AI coding assistants are third-party AI systems your team uses: an approved list and detection of others evidences how their use is governed.",
  },
  "AIG-2": {
    iso42001: [{ id: "A.9.2", title: "Processes for responsible use of AI systems" }],
    nist_ai_rmf: [{ id: "GOVERN 3.2", summary: "Roles and responsibilities for human-AI configurations and oversight of AI systems are defined" }],
    note: "A named person's sign-off on AI-written high-risk code is the human-oversight step for that use.",
  },
  "AIG-3": {
    iso42001: [], nist_ai_rmf: [],
    note: "No direct counterpart: separation of duties strengthens the human review in AIG-2.",
  },
  "AIG-4": {
    iso42001: [], nist_ai_rmf: [],
    note: "No direct counterpart: per-commit records of AI use support the reviews above and any AI-use inventory you keep.",
  },
};

export function aiGovernanceMappings(fw: FrameworkDef, controls: readonly ControlLike[]): AiMapping[] {
  const status = new Map(controls.map(c => [c.control_id, c.status]));
  return fw.controls.map(c => ({ control: c.id, name: c.name, status: status.get(c.id) ?? null, ...(AI_MAP[c.id] ?? { iso42001: [], nist_ai_rmf: [], note: "No mapping recorded." }) }));
}

export const AI_MAPPING_CAVEAT =
  "Indicative mapping, to help place this evidence in an AI management system (ISO/IEC 42001:2023 Annex A) or a NIST AI RMF 1.0 profile. It covers your team's use of AI coding tools only and does not show conformity with either; check each reference against the standard's text.";

// ── One view per framework, as it goes into the report record ────────────────

export type FrameworkView =
  | { kind: "iso_soa"; rows: SoaRow[] }
  | { kind: "pci_624"; classes: readonly AttackClass[] }
  | { kind: "ai_mapping"; caveat: string; rows: AiMapping[] };

export function frameworkView(fw: FrameworkDef, controls: readonly ControlLike[]): FrameworkView | null {
  if (fw.id === "iso27001") return { kind: "iso_soa", rows: isoSoaRows(controls) };
  if (fw.id === "pcidss") return { kind: "pci_624", classes: PCI_624_CLASSES };
  if (fw.id === "aigov") return { kind: "ai_mapping", caveat: AI_MAPPING_CAVEAT, rows: aiGovernanceMappings(fw, controls) };
  return null;
}

export const FRAMEWORK_VIEW_TITLE: Record<FrameworkView["kind"], string> = {
  iso_soa: "Statement of Applicability input (Annex A 8, development)",
  pci_624: "Requirement 6.2.4: common software attacks checked",
  ai_mapping: "Mapping to ISO/IEC 42001 and NIST AI RMF",
};
