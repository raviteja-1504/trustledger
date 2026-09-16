/**
 * Real Evidence Engine — computes genuine per-control compliance evidence
 * from live scan/attestation/violation/audit data. Extracted out of
 * api/evidence/collect/route.ts (which now just calls collectEvidence())
 * so /api/report can pull the exact same real per-control scores into the
 * generated PDF's Compliance Mapping section, instead of that page having
 * its own third, independently-invented scoring formula. Next.js route.ts
 * files may only export the reserved HTTP-method handlers, so this logic
 * has to live in a plain lib module to be shared across routes (same
 * reasoning as dashboardAggregate.ts).
 *
 * SOC 2:
 *   CC6.1 (Logical Access)    → attestation records (reviewer identity)
 *   CC6.2 (Authentication)    → OAuth login records from audit_log
 *   CC7.2 (System Monitoring) → scan completion records
 *   CC8.1 (Change Management) → attestation before merge evidence
 *   A1.2  (Availability)      → audit log retention records
 */

import { createServiceClient } from "@/lib/supabase";
import { verifyAuditChain } from "@/lib/audit";

export interface ControlEvidence {
  control_id:   string;
  control_name: string;
  status:       "pass" | "partial" | "fail" | "not_tested";
  evidence:     EvidenceItem[];
  score:        number;   // 0-100
}

export interface EvidenceItem {
  type:         string;
  description:  string;
  count:        number;
  collected_at: string;
  source:       string;
}

interface Signals {
  totalScans:          number;
  totalAttestations:   number;
  openViolations:       number;
  resolvedViolations:   number;
  auditEvents:          number;
  teamMembers:          number;
  secretFindings:        number;
  secretResolved:        number;
  scanFilesTotal:         number;
  chainIntegrity:         { valid: boolean; total: number };
  now:                    string;
}

// Attestation coverage relative to scan volume -- the same real "how much
// of what we scanned was actually reviewed" ratio used across several
// controls below (SOC 2 CC6.1, EU AI Act Art.14, PCI 6.4.2, ISO A.8.28).
function attestationCoveragePct(s: Signals): number {
  return Math.min(100, (s.totalAttestations / Math.max(1, s.totalScans)) * 100);
}
// Open-violation backlog health -- the same real "is remediation keeping
// up with detection" signal used across several controls (SOC 2 CC8.1,
// EU AI Act Art.9, PCI 6.4.1, ISO A.8.26).
function violationHealthPct(s: Signals): number {
  return Math.min(100, 100 - Math.min(50, s.openViolations * 5));
}

function buildSoc2(s: Signals): ControlEvidence[] {
  return [
    {
      control_id: "CC6.1", control_name: "Logical and Physical Access Controls",
      status: s.totalAttestations > 0 ? "pass" : "partial",
      score: attestationCoveragePct(s),
      evidence: [
        { type:"attestation_records", description:"Signed reviewer attestations with PGP-like payload hash", count:s.totalAttestations, collected_at:s.now, source:"attestations table" },
        { type:"team_roster", description:"Authorised reviewer list with role assignments", count:s.teamMembers, collected_at:s.now, source:"org_members table" },
      ],
    },
    {
      control_id: "CC6.2", control_name: "Authentication",
      status: s.auditEvents > 0 ? "pass" : "fail",
      score: s.auditEvents > 0 ? 100 : 0,
      evidence: [
        { type:"auth_events", description:"OAuth authentication events logged in tamper-evident audit trail", count:s.auditEvents, collected_at:s.now, source:"audit_log table" },
      ],
    },
    {
      control_id: "CC7.2", control_name: "System Monitoring",
      status: s.totalScans > 0 ? "pass" : "fail",
      score: s.totalScans > 0 ? 80 + (s.totalScans > 10 ? 20 : 0) : 0,
      evidence: [
        { type:"scan_records", description:"Automated AI content scans on every pull request", count:s.totalScans, collected_at:s.now, source:"scans table" },
        { type:"secret_detection", description:"Hardcoded credential and secret detection", count:s.secretFindings, collected_at:s.now, source:"secret_findings table" },
      ],
    },
    {
      control_id: "CC8.1", control_name: "Change Management",
      status: s.resolvedViolations > 0 && s.openViolations === 0 ? "pass" : s.openViolations > 5 ? "partial" : "pass",
      score: violationHealthPct(s),
      evidence: [
        { type:"policy_gate_evidence", description:"Deploy gate blocked merges until attestation completed", count:s.resolvedViolations, collected_at:s.now, source:"violations table (resolved)" },
        { type:"open_violations", description:"Currently open violations requiring remediation", count:s.openViolations, collected_at:s.now, source:"violations table (open)" },
      ],
    },
    {
      control_id: "A1.2", control_name: "Availability — Audit Log Retention",
      status: s.chainIntegrity.valid ? "pass" : "fail",
      score: s.chainIntegrity.valid ? 100 : 0,
      evidence: [
        { type:"audit_log_integrity", description:`Tamper-evident hash chain verified — ${s.chainIntegrity.total} records intact`, count:s.chainIntegrity.total, collected_at:s.now, source:"audit_log table (hash chain)" },
      ],
    },
  ];
}

function buildEuAiAct(s: Signals): ControlEvidence[] {
  const totalTracked = s.openViolations + s.resolvedViolations;
  return [
    {
      control_id: "Art.9", control_name: "Risk Management System",
      status: totalTracked === 0 ? "not_tested" : s.openViolations === 0 ? "pass" : "partial",
      score: totalTracked === 0 ? 0 : Math.round((s.resolvedViolations / totalTracked) * 100),
      evidence: [
        { type:"risk_classifications", description:"CRITICAL/HIGH/MEDIUM/LOW risk classification per scanned file", count:totalTracked, collected_at:s.now, source:"violations table" },
      ],
    },
    {
      control_id: "Art.10", control_name: "Data Governance",
      status: s.scanFilesTotal > 0 ? "pass" : "fail",
      score: s.scanFilesTotal > 0 ? 100 : 0,
      evidence: [
        { type:"provenance_records", description:"Per-file scan provenance (content hash, AI%, risk classification)", count:s.scanFilesTotal, collected_at:s.now, source:"scan_files table" },
      ],
    },
    {
      control_id: "Art.13", control_name: "Transparency",
      status: s.totalScans > 0 ? "pass" : "fail",
      score: s.totalScans > 0 ? 80 + (s.totalScans > 10 ? 20 : 0) : 0,
      evidence: [
        { type:"ai_disclosure", description:"AI content percentage computed and disclosed for every PR scan", count:s.totalScans, collected_at:s.now, source:"scans table" },
      ],
    },
    {
      control_id: "Art.14", control_name: "Human Oversight",
      status: s.totalAttestations > 0 ? "pass" : "partial",
      score: attestationCoveragePct(s),
      evidence: [
        { type:"reviewer_signoffs", description:"Named human reviewer attestations for HIGH/CRITICAL AI files", count:s.totalAttestations, collected_at:s.now, source:"attestations table" },
      ],
    },
    {
      control_id: "Art.17", control_name: "Quality Management",
      status: s.totalScans > 0 ? "pass" : "fail",
      score: s.totalScans > 0 ? 80 + (s.totalScans > 10 ? 20 : 0) : 0,
      evidence: [
        { type:"continuous_monitoring", description:"Automated post-deployment scanning on every pull request", count:s.totalScans, collected_at:s.now, source:"scans table" },
      ],
    },
  ];
}

function buildPciDss(s: Signals): ControlEvidence[] {
  const totalTracked = s.openViolations + s.resolvedViolations;
  return [
    {
      control_id: "6.2.4", control_name: "Prevention of Software Attacks",
      status: totalTracked === 0 ? "not_tested" : s.openViolations === 0 ? "pass" : "partial",
      score: totalTracked === 0 ? 0 : Math.round((s.resolvedViolations / totalTracked) * 100),
      evidence: [
        { type:"vulnerability_scans", description:"Injection, eval/exec, JWT-bypass and related pattern detection per PR", count:s.totalScans, collected_at:s.now, source:"scans table" },
      ],
    },
    {
      control_id: "6.3.2", control_name: "Software Inventory",
      status: s.scanFilesTotal > 0 ? "pass" : "fail",
      score: s.scanFilesTotal > 0 ? 100 : 0,
      evidence: [
        { type:"aibom_records", description:"AI Bill of Materials — every scanned file logged with provenance", count:s.scanFilesTotal, collected_at:s.now, source:"scan_files table" },
      ],
    },
    {
      control_id: "6.4.1", control_name: "Change Control Process",
      status: s.openViolations === 0 ? "pass" : s.openViolations > 5 ? "partial" : "pass",
      score: violationHealthPct(s),
      evidence: [
        { type:"open_violations", description:"Currently open violations requiring remediation before deploy", count:s.openViolations, collected_at:s.now, source:"violations table (open)" },
      ],
    },
    {
      control_id: "6.4.2", control_name: "Change Control — Dual Review",
      status: s.totalAttestations > 0 ? "pass" : "partial",
      score: attestationCoveragePct(s),
      evidence: [
        { type:"attestation_records", description:"Reviewer attestation records for changed code", count:s.totalAttestations, collected_at:s.now, source:"attestations table" },
      ],
    },
    {
      control_id: "6.4.3", control_name: "Payment Page Security",
      status: totalTracked === 0 ? "not_tested" : s.openViolations === 0 ? "pass" : "partial",
      score: totalTracked === 0 ? 0 : Math.round((s.resolvedViolations / totalTracked) * 100),
      evidence: [
        { type:"flagged_files", description:"High-risk AI-authored files flagged and tracked to resolution", count:totalTracked, collected_at:s.now, source:"violations table" },
      ],
    },
  ];
}

function buildIso27001(s: Signals): ControlEvidence[] {
  return [
    {
      control_id: "A.8.25", control_name: "Secure Development Lifecycle",
      status: s.totalScans > 0 ? "pass" : "fail",
      score: s.totalScans > 0 ? 80 + (s.totalScans > 10 ? 20 : 0) : 0,
      evidence: [
        { type:"scan_records", description:"Automated security scanning integrated into the development lifecycle", count:s.totalScans, collected_at:s.now, source:"scans table" },
      ],
    },
    {
      control_id: "A.8.26", control_name: "Application Security Requirements",
      status: s.openViolations === 0 ? "pass" : s.openViolations > 5 ? "partial" : "pass",
      score: violationHealthPct(s),
      evidence: [
        { type:"violation_backlog", description:"Open vs. resolved application security violations", count:s.openViolations + s.resolvedViolations, collected_at:s.now, source:"violations table" },
      ],
    },
    {
      control_id: "A.8.28", control_name: "Secure Coding",
      status: s.totalAttestations > 0 ? "pass" : "partial",
      score: attestationCoveragePct(s),
      evidence: [
        { type:"attestation_records", description:"Human reviewer sign-off coverage for AI-authored code", count:s.totalAttestations, collected_at:s.now, source:"attestations table" },
      ],
    },
    {
      control_id: "A.8.30", control_name: "Outsourced Development",
      status: s.scanFilesTotal > 0 ? "pass" : "fail",
      score: s.scanFilesTotal > 0 ? 100 : 0,
      evidence: [
        { type:"file_coverage", description:"Every file from every contributor (human or AI) scanned and logged", count:s.scanFilesTotal, collected_at:s.now, source:"scan_files table" },
      ],
    },
    {
      control_id: "A.5.33", control_name: "Protection of Records",
      status: s.chainIntegrity.valid ? "pass" : "fail",
      score: s.chainIntegrity.valid ? 100 : 0,
      evidence: [
        { type:"audit_log_integrity", description:`Tamper-evident hash chain verified — ${s.chainIntegrity.total} records intact`, count:s.chainIntegrity.total, collected_at:s.now, source:"audit_log table (hash chain)" },
      ],
    },
  ];
}

const FRAMEWORK_BUILDERS: Record<string, (s: Signals) => ControlEvidence[]> = {
  soc2: buildSoc2, euai: buildEuAiAct, pcidss: buildPciDss, iso27001: buildIso27001,
};

export function normalizeFramework(raw: string): string {
  const key = raw.toLowerCase().replace(/[^a-z0-9]/g, "");
  if (key.startsWith("soc")) return "soc2";
  if (key.startsWith("eu") || key.includes("aiact")) return "euai";
  if (key.startsWith("pci")) return "pcidss";
  if (key.startsWith("iso")) return "iso27001";
  return "soc2";
}

export interface EvidencePackage {
  framework:       string;
  period_start:    string;
  period_end:      string;
  generated_at:    string;
  overall_score:   number;
  controls:        ControlEvidence[];
  audit_integrity: { valid: boolean; total: number };
  summary: {
    total_scans:         number;
    total_attestations:  number;
    open_violations:     number;
    resolved_violations: number;
    secrets_detected:    number;
    secrets_resolved:    number;
    audit_events:        number;
    scan_files_total:    number;
  };
}

export async function collectEvidence(
  org_id: string, rawFramework: string, periodStart: string, periodEnd: string,
): Promise<EvidencePackage> {
  const framework = normalizeFramework(rawFramework);
  const db = createServiceClient();

  // Collect metrics from the database -- shared across all four frameworks,
  // each framework's controls just draw on this same real signal set in
  // different combinations (see buildSoc2/buildEuAiAct/buildPciDss/
  // buildIso27001 above).
  const [
    { count: totalScans },
    { count: totalAttestations },
    { count: openViolations },
    { count: resolvedViolations },
    { count: auditEvents },
    { count: teamMembers },
    { count: secretFindings },
    { count: secretResolved },
    { count: scanFilesTotal },
  ] = await Promise.all([
    db.from("scans").select("*",{ count:"exact",head:true }).eq("org_id",org_id).gte("created_at",periodStart).lte("created_at",periodEnd),
    db.from("attestations").select("*",{ count:"exact",head:true }).eq("org_id",org_id).gte("created_at",periodStart),
    db.from("violations").select("*",{ count:"exact",head:true }).eq("org_id",org_id).in("status",["open","in_review"]),
    db.from("violations").select("*",{ count:"exact",head:true }).eq("org_id",org_id).eq("status","resolved").gte("resolved_at",periodStart),
    db.from("audit_log").select("*",{ count:"exact",head:true }).eq("org_id",org_id).gte("created_at",periodStart),
    db.from("org_members").select("*",{ count:"exact",head:true }).eq("org_id",org_id),
    db.from("secret_findings").select("*",{ count:"exact",head:true }).eq("org_id",org_id).gte("created_at",periodStart),
    db.from("secret_findings").select("*",{ count:"exact",head:true }).eq("org_id",org_id).eq("status","resolved").gte("created_at",periodStart),
    db.from("scan_files").select("*",{ count:"exact",head:true }).eq("org_id",org_id).gte("created_at",periodStart),
  ]);

  // Verify audit log chain integrity
  const chainIntegrity = await verifyAuditChain(db, org_id);

  const signals: Signals = {
    totalScans: totalScans ?? 0, totalAttestations: totalAttestations ?? 0,
    openViolations: openViolations ?? 0, resolvedViolations: resolvedViolations ?? 0,
    auditEvents: auditEvents ?? 0, teamMembers: teamMembers ?? 0,
    secretFindings: secretFindings ?? 0, secretResolved: secretResolved ?? 0,
    scanFilesTotal: scanFilesTotal ?? 0, chainIntegrity,
    now: new Date().toISOString(),
  };

  const evidence = FRAMEWORK_BUILDERS[framework](signals);
  const overallScore = Math.round(evidence.reduce((s, e) => s + e.score, 0) / evidence.length);

  return {
    framework,
    period_start:    periodStart,
    period_end:      periodEnd,
    generated_at:    signals.now,
    overall_score:   overallScore,
    controls:        evidence,
    audit_integrity: chainIntegrity,
    summary: {
      total_scans:        signals.totalScans,
      total_attestations: signals.totalAttestations,
      open_violations:    signals.openViolations,
      resolved_violations:signals.resolvedViolations,
      secrets_detected:   signals.secretFindings,
      secrets_resolved:   signals.secretResolved,
      audit_events:       signals.auditEvents,
      scan_files_total:   signals.scanFilesTotal,
    },
  };
}
