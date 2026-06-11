export interface ControlObjective {
  id:             string;
  label:          string;
  description:    string;
  weight:         number;
  owner:          string;
  last_tested?:   string;
  next_test?:     string;
  test_frequency: "monthly" | "quarterly" | "annually";
  evidence_items: { type: string; description: string; auto: boolean }[];
  cross_map:      { framework: string; control_id: string }[];
}

export interface FrameworkDef {
  id:           string;
  shortName:    string;
  fullName:     string;
  standard:     string;
  color:        string;
  gradient:     string;
  headerBg:     string;
  certBody:     string;
  nextAudit:    string;
  certExpiry?:  string;
  controls:     ControlObjective[];
}

export interface CrossFrameworkTheme {
  theme:       string;
  description: string;
  controls:    { soc2: string; euai: string; pcidss: string; iso27001: string };
}

export const CROSS_FRAMEWORK_THEMES: CrossFrameworkTheme[] = [
  { theme:"Human Oversight",       description:"Require a named human reviewer before merging AI-generated code",
    controls:{ soc2:"CC6.1", euai:"Art.14", pcidss:"6.4.2", iso27001:"A.8.28" } },
  { theme:"Change Management",     description:"Track and attest every AI code change before deployment",
    controls:{ soc2:"CC8.1", euai:"Art.9",  pcidss:"6.4.2", iso27001:"A.8.26" } },
  { theme:"Continuous Monitoring", description:"Run automated scans on every pull request",
    controls:{ soc2:"CC7.2", euai:"Art.17", pcidss:"6.2.4", iso27001:"A.8.25" } },
  { theme:"AI Transparency",       description:"Disclose AI content percentage per file and per PR",
    controls:{ soc2:"CC7.2", euai:"Art.13", pcidss:"6.3.2", iso27001:"A.8.30" } },
  { theme:"Risk Management",       description:"Identify, score and mitigate AI code risks systematically",
    controls:{ soc2:"CC8.1", euai:"Art.9",  pcidss:"6.2.4", iso27001:"A.8.26" } },
  { theme:"Access Control",        description:"Restrict attestation to authorised named reviewers only",
    controls:{ soc2:"CC6.2", euai:"Art.14", pcidss:"6.4.2", iso27001:"A.8.28" } },
];

export function makeFrameworks(
  org: string,
  policy: Record<string, string> = {},
): FrameworkDef[] {
  const o = org;
  const auditDate = (key: string, def: string) => policy[key] ?? def;
  return [
    {
      id:"soc2", shortName:"SOC 2", fullName:"SOC 2 Type II",
      standard:"AICPA Trust Services Criteria 2017",
      color:"#6366f1", gradient:"linear-gradient(135deg,#6366f1,#7c3aed)",
      headerBg:"linear-gradient(135deg,#0f172a 0%,#1e1b4b 60%,#0f172a 100%)",
      certBody:"AICPA-accredited CPA firm", nextAudit:auditDate("soc2","2026-08-20"),
      controls: [
        { id:"CC6.1", label:"Logical Access Controls", description:"AI-authored changes reviewed only by authorised personnel via role-based access and attestation workflow.", weight:25, owner:`alice@${o}.io`, last_tested:"2026-05-01", next_test:"2026-08-01", test_frequency:"quarterly",
          evidence_items:[{ type:"attestation", description:"Signed reviewer attestation records (PGP)", auto:true },{ type:"policy", description:"Access control policy v1.2", auto:false },{ type:"screenshot", description:"GitHub App merge gate configuration", auto:false }],
          cross_map:[{ framework:"pcidss", control_id:"6.4.2" },{ framework:"euai", control_id:"Art.14" }] },
        { id:"CC6.2", label:"Authentication", description:"Reviewer identity verified via GitHub OAuth — no anonymous attestations permitted.", weight:20, owner:`alice@${o}.io`, last_tested:"2026-04-15", next_test:"2026-07-15", test_frequency:"quarterly",
          evidence_items:[{ type:"scan-log", description:"OAuth token log per attestation call", auto:true },{ type:"config", description:"GitHub App OAuth scope configuration", auto:false }],
          cross_map:[{ framework:"pcidss", control_id:"6.4.2" }] },
        { id:"CC7.2", label:"System Monitoring", description:"Continuous AI content scanning on every pull request — zero manual triggers required.", weight:20, owner:`bob@${o}.io`, last_tested:"2026-05-20", next_test:"2026-08-20", test_frequency:"quarterly",
          evidence_items:[{ type:"scan-log", description:"Automated scan logs per PR", auto:true },{ type:"report", description:"SOC 2 compliance report PDF", auto:false }],
          cross_map:[{ framework:"euai", control_id:"Art.17" },{ framework:"pcidss", control_id:"6.2.4" }] },
        { id:"CC8.1", label:"Change Management", description:"All changes formally attested before deployment — policy gate enforces this automatically.", weight:25, owner:`alice@${o}.io`, last_tested:"2026-05-15", next_test:"2026-08-15", test_frequency:"quarterly",
          evidence_items:[{ type:"attestation", description:"Attestation coverage across audit period", auto:true },{ type:"audit-trail", description:"Tamper-evident change management log", auto:true },{ type:"screenshot", description:"Blocked deploy evidence", auto:false }],
          cross_map:[{ framework:"pcidss", control_id:"6.4.2" },{ framework:"euai", control_id:"Art.9" }] },
        { id:"A1.2", label:"Availability", description:"Audit trail retained and accessible for ≥ 12 months. All scan and attestation records preserved.", weight:10, owner:`carol@${o}.io`, last_tested:"2026-05-01", next_test:"2026-11-01", test_frequency:"annually",
          evidence_items:[{ type:"audit-trail", description:"12-month event record retention", auto:true }],
          cross_map:[] },
      ],
    },
    {
      id:"euai", shortName:"EU AI Act", fullName:"EU Artificial Intelligence Act",
      standard:"Regulation (EU) 2024/1689 — Annex I High-Risk",
      color:"#3b82f6", gradient:"linear-gradient(135deg,#3b82f6,#0891b2)",
      headerBg:"linear-gradient(135deg,#0f172a 0%,#0c2340 60%,#0f172a 100%)",
      certBody:"EU Notified Body / Self-assessment", nextAudit:auditDate("euai","2026-07-15"),
      controls: [
        { id:"Art.9",  label:"Risk Management System", description:"Continuous identification, analysis and mitigation of AI system risks — documented and reviewable.", weight:25, owner:`alice@${o}.io`, last_tested:"2026-05-10", next_test:"2026-08-10", test_frequency:"quarterly",
          evidence_items:[{ type:"report", description:"Risk register with likelihood × impact scoring", auto:false },{ type:"scan-log", description:"Risk classification per scanned file", auto:true }],
          cross_map:[{ framework:"soc2", control_id:"CC8.1" }] },
        { id:"Art.10", label:"Data Governance", description:"Training data provenance documented per file — AI% and source metadata captured at scan time.", weight:20, owner:`bob@${o}.io`, last_tested:"2026-05-01", next_test:"2026-08-01", test_frequency:"quarterly",
          evidence_items:[{ type:"audit-trail", description:"AI provenance records per file", auto:true }],
          cross_map:[] },
        { id:"Art.13", label:"Transparency", description:"AI-generated code percentage disclosed per PR — automatically added to status checks.", weight:20, owner:`bob@${o}.io`, last_tested:"2026-05-20", next_test:"2026-08-20", test_frequency:"quarterly",
          evidence_items:[{ type:"scan-log", description:"AI% disclosure per PR scan result", auto:true }],
          cross_map:[] },
        { id:"Art.14", label:"Human Oversight", description:"Named human reviewer required for CRITICAL AI files — policy gate enforces sign-off before merge.", weight:25, owner:`alice@${o}.io`, last_tested:"2026-05-15", next_test:"2026-08-15", test_frequency:"quarterly",
          evidence_items:[{ type:"attestation", description:"Named reviewer sign-offs per CRITICAL file", auto:true },{ type:"policy", description:"Human oversight policy v1.2", auto:false }],
          cross_map:[{ framework:"soc2", control_id:"CC6.1" },{ framework:"pcidss", control_id:"6.4.2" }] },
        { id:"Art.17", label:"Quality Management", description:"Post-deployment monitoring via continuous automated scanning — every PR on every monitored repo.", weight:10, owner:`carol@${o}.io`, last_tested:"2026-05-20", next_test:"2026-08-20", test_frequency:"quarterly",
          evidence_items:[{ type:"scan-log", description:"Automated quality assessments per PR", auto:true }],
          cross_map:[{ framework:"soc2", control_id:"CC7.2" }] },
      ],
    },
    {
      id:"pcidss", shortName:"PCI-DSS", fullName:"PCI DSS v4.0",
      standard:"PCI Security Standards Council — Req 6 (Software Security)",
      color:"#10b981", gradient:"linear-gradient(135deg,#10b981,#0d9488)",
      headerBg:"linear-gradient(135deg,#0f172a 0%,#042f2e 60%,#0f172a 100%)",
      certBody:"QSA — SecurityMetrics", nextAudit:auditDate("pcidss","2026-08-22"), certExpiry:auditDate("pcidss","2026-08-22"),
      controls: [
        { id:"6.2.4", label:"Prevention of Software Attacks", description:"AI code screened for injection, eval/exec, JWT bypass, and hardcoded credential patterns.", weight:30, owner:`alice@${o}.io`, last_tested:"2026-05-20", next_test:"2026-08-20", test_frequency:"quarterly",
          evidence_items:[{ type:"scan-log", description:"Vulnerability signal detection log per PR", auto:true },{ type:"report", description:"PCI-DSS compliance report — Req 6.4", auto:false }],
          cross_map:[{ framework:"soc2", control_id:"CC7.2" },{ framework:"euai", control_id:"Art.9" }] },
        { id:"6.3.2", label:"Software Inventory", description:"AI-authored code logged per file and pull request — full AIBOM maintained.", weight:25, owner:`bob@${o}.io`, last_tested:"2026-05-01", next_test:"2026-08-01", test_frequency:"quarterly",
          evidence_items:[{ type:"audit-trail", description:"AI Bill of Materials (AIBOM) — all files", auto:true }],
          cross_map:[] },
        { id:"6.4.1", label:"Security Vulnerabilities", description:"CRITICAL-risk AI files blocked automatically from merge — zero manual override.", weight:20, owner:`alice@${o}.io`, last_tested:"2026-05-15", next_test:"2026-08-15", test_frequency:"quarterly",
          evidence_items:[{ type:"scan-log", description:"Blocked merge evidence per blocked file", auto:true }],
          cross_map:[] },
        { id:"6.4.2", label:"Change Control Process", description:"Dual-reviewer attestation required for payment-system changes — SOD enforced via policy.", weight:25, owner:`alice@${o}.io`, last_tested:"2026-05-20", next_test:"2026-08-20", test_frequency:"quarterly",
          evidence_items:[{ type:"attestation", description:"Dual reviewer records for payment code", auto:true },{ type:"screenshot", description:"Blocked merge evidence for payment PRs", auto:false }],
          cross_map:[{ framework:"soc2", control_id:"CC6.1" },{ framework:"soc2", control_id:"CC8.1" },{ framework:"euai", control_id:"Art.14" }] },
        { id:"6.4.3", label:"Payment Page Security", description:"AI content in payment paths flagged for mandatory review — high-risk repos monitored continuously.", weight:0, owner:`carol@${o}.io`, last_tested:"2026-05-10", next_test:"2026-08-10", test_frequency:"quarterly",
          evidence_items:[{ type:"scan-log", description:"Payment-path AI content monitoring logs", auto:true }],
          cross_map:[] },
      ],
    },
    {
      id:"iso27001", shortName:"ISO 27001", fullName:"ISO/IEC 27001:2022",
      standard:"ISO/IEC 27001:2022 Annex A — Software Development & AI Security Controls",
      color:"#0ea5e9", gradient:"linear-gradient(135deg,#0ea5e9,#0284c7)",
      headerBg:"linear-gradient(135deg,#0f172a 0%,#082f49 60%,#0f172a 100%)",
      certBody:"BSI / TÜV SÜD", nextAudit:auditDate("iso27001","2027-01-15"),
      controls: [
        { id:"A.8.25", label:"Secure Development Lifecycle", description:"TrustLedger scans every pull request — continuous security testing embedded in the SDLC, not bolted on after delivery.", weight:25, owner:`alice@${o}.io`, last_tested:"2026-05-20", next_test:"2026-08-20", test_frequency:"quarterly",
          evidence_items:[{ type:"scan-log", description:"Automated security scan per PR (SDLC gate)", auto:true },{ type:"policy", description:"Secure development policy v2.0", auto:false }],
          cross_map:[{ framework:"soc2", control_id:"CC7.2" },{ framework:"euai", control_id:"Art.17" },{ framework:"pcidss", control_id:"6.2.4" }] },
        { id:"A.8.26", label:"Application Security Requirements", description:"Policy gates codify AI content thresholds and attestation mandates — security requirements enforced automatically at merge time.", weight:20, owner:`alice@${o}.io`, last_tested:"2026-05-15", next_test:"2026-08-15", test_frequency:"quarterly",
          evidence_items:[{ type:"policy", description:"AI code security requirements policy v1.3", auto:false },{ type:"scan-log", description:"Policy enforcement log per PR", auto:true }],
          cross_map:[{ framework:"soc2", control_id:"CC8.1" },{ framework:"euai", control_id:"Art.9" }] },
        { id:"A.8.28", label:"Secure Coding", description:"Every AI-generated file must be attested by a named reviewer before merge — mandatory secure coding verification for all AI output.", weight:25, owner:`alice@${o}.io`, last_tested:"2026-05-20", next_test:"2026-08-20", test_frequency:"quarterly",
          evidence_items:[{ type:"attestation", description:"Named reviewer attestation records per file", auto:true },{ type:"audit-trail", description:"Code review evidence chain (tamper-evident)", auto:true }],
          cross_map:[{ framework:"soc2", control_id:"CC6.1" },{ framework:"euai", control_id:"Art.14" },{ framework:"pcidss", control_id:"6.4.2" }] },
        { id:"A.8.30", label:"Outsourced Development", description:"AI coding tools governed as outsourced development suppliers — AI origin tracked per file via AIBOM with full tool provenance.", weight:20, owner:`bob@${o}.io`, last_tested:"2026-05-01", next_test:"2026-08-01", test_frequency:"quarterly",
          evidence_items:[{ type:"audit-trail", description:"AI Bill of Materials — tool origin per file", auto:true },{ type:"policy", description:"Third-party AI tool approval register", auto:false }],
          cross_map:[{ framework:"euai", control_id:"Art.10" },{ framework:"pcidss", control_id:"6.3.2" }] },
        { id:"A.5.33", label:"Protection of Records", description:"Immutable cryptographically-chained audit log satisfies records integrity requirements — tamper detection built in to every event.", weight:10, owner:`carol@${o}.io`, last_tested:"2026-05-01", next_test:"2026-11-01", test_frequency:"annually",
          evidence_items:[{ type:"audit-trail", description:"Cryptographic chain — 12-month retention", auto:true }],
          cross_map:[{ framework:"soc2", control_id:"A1.2" }] },
      ],
    },
  ];
}
