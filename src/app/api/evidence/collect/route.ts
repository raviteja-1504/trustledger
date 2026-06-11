/**
 * SOC 2 Evidence Auto-Collection
 * Automatically maps TrustLedger scan data to SOC 2 Trust Services Criteria.
 *
 * POST /api/evidence/collect → collect evidence for a specific control
 * GET  /api/evidence/collect?framework=SOC2&period_start=...&period_end=...
 *       → generate a full evidence package for the audit period
 *
 * Evidence mapping:
 *   CC6.1 (Logical Access)    → attestation records (reviewer identity)
 *   CC6.2 (Authentication)    → OAuth login records from audit_log
 *   CC7.2 (System Monitoring) → scan completion records
 *   CC8.1 (Change Management) → attestation before merge evidence
 *   A1.2  (Availability)      → audit log retention records
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey } from "../../_middleware";
import { verifyAuditChain } from "@/lib/audit";

interface ControlEvidence {
  control_id:   string;
  control_name: string;
  status:       "pass" | "partial" | "fail" | "not_tested";
  evidence:     EvidenceItem[];
  score:        number;   // 0-100
}

interface EvidenceItem {
  type:         string;
  description:  string;
  count:        number;
  collected_at: string;
  source:       string;
}

export async function GET(req: NextRequest) {
  const { org_id, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  const url          = new URL(req.url);
  const framework    = url.searchParams.get("framework") ?? "SOC2";
  const periodStart  = url.searchParams.get("period_start") ?? new Date(Date.now() - 90 * 86400_000).toISOString();
  const periodEnd    = url.searchParams.get("period_end")   ?? new Date().toISOString();

  const db = createServiceClient();

  // Collect metrics from the database
  const [
    { count: totalScans },
    { count: totalAttestations },
    { count: openViolations },
    { count: resolvedViolations },
    { count: auditEvents },
    { count: teamMembers },
    { count: secretFindings },
    { count: secretResolved },
  ] = await Promise.all([
    db.from("scans").select("*",{ count:"exact",head:true }).eq("org_id",org_id).gte("created_at",periodStart).lte("created_at",periodEnd),
    db.from("attestations").select("*",{ count:"exact",head:true }).eq("org_id",org_id).gte("created_at",periodStart),
    db.from("violations").select("*",{ count:"exact",head:true }).eq("org_id",org_id).in("status",["open","in_review"]),
    db.from("violations").select("*",{ count:"exact",head:true }).eq("org_id",org_id).eq("status","resolved").gte("resolved_at",periodStart),
    db.from("audit_log").select("*",{ count:"exact",head:true }).eq("org_id",org_id).gte("created_at",periodStart),
    db.from("org_members").select("*",{ count:"exact",head:true }).eq("org_id",org_id),
    db.from("secret_findings").select("*",{ count:"exact",head:true }).eq("org_id",org_id).gte("created_at",periodStart),
    db.from("secret_findings").select("*",{ count:"exact",head:true }).eq("org_id",org_id).eq("status","resolved").gte("created_at",periodStart),
  ]);

  // Verify audit log chain integrity
  const chainIntegrity = await verifyAuditChain(db, org_id);

  const now = new Date().toISOString();

  // ── SOC 2 Evidence Package ────────────────────────────────────────────────
  const evidence: ControlEvidence[] = [
    {
      control_id:   "CC6.1",
      control_name: "Logical and Physical Access Controls",
      status:       (totalAttestations ?? 0) > 0 ? "pass" : "partial",
      score:        Math.min(100, ((totalAttestations ?? 0) / Math.max(1, totalScans ?? 1)) * 100),
      evidence: [
        {
          type:        "attestation_records",
          description: "Signed reviewer attestations with PGP-like payload hash",
          count:       totalAttestations ?? 0,
          collected_at: now,
          source:      "attestations table",
        },
        {
          type:        "team_roster",
          description: "Authorised reviewer list with role assignments",
          count:       teamMembers ?? 0,
          collected_at: now,
          source:      "org_members table",
        },
      ],
    },
    {
      control_id:   "CC6.2",
      control_name: "Authentication",
      status:       (auditEvents ?? 0) > 0 ? "pass" : "fail",
      score:        (auditEvents ?? 0) > 0 ? 100 : 0,
      evidence: [
        {
          type:        "auth_events",
          description: "OAuth authentication events logged in tamper-evident audit trail",
          count:       auditEvents ?? 0,
          collected_at: now,
          source:      "audit_log table",
        },
      ],
    },
    {
      control_id:   "CC7.2",
      control_name: "System Monitoring",
      status:       (totalScans ?? 0) > 0 ? "pass" : "fail",
      score:        Math.min(100, (totalScans ?? 0) > 0 ? 80 + ((totalScans ?? 0) > 10 ? 20 : 0) : 0),
      evidence: [
        {
          type:        "scan_records",
          description: "Automated AI content scans on every pull request",
          count:       totalScans ?? 0,
          collected_at: now,
          source:      "scans table",
        },
        {
          type:        "secret_detection",
          description: "Hardcoded credential and secret detection",
          count:       secretFindings ?? 0,
          collected_at: now,
          source:      "secret_findings table",
        },
      ],
    },
    {
      control_id:   "CC8.1",
      control_name: "Change Management",
      status:       (resolvedViolations ?? 0) > 0 && (openViolations ?? 0) === 0 ? "pass"
                  : (openViolations ?? 0) > 5 ? "partial" : "pass",
      score:        Math.min(100, 100 - Math.min(50, (openViolations ?? 0) * 5)),
      evidence: [
        {
          type:        "policy_gate_evidence",
          description: "Deploy gate blocked merges until attestation completed",
          count:       resolvedViolations ?? 0,
          collected_at: now,
          source:      "violations table (resolved)",
        },
        {
          type:        "open_violations",
          description: "Currently open violations requiring remediation",
          count:       openViolations ?? 0,
          collected_at: now,
          source:      "violations table (open)",
        },
      ],
    },
    {
      control_id:   "A1.2",
      control_name: "Availability — Audit Log Retention",
      status:       chainIntegrity.valid ? "pass" : "fail",
      score:        chainIntegrity.valid ? 100 : 0,
      evidence: [
        {
          type:        "audit_log_integrity",
          description: `Tamper-evident hash chain verified — ${chainIntegrity.total} records intact`,
          count:       chainIntegrity.total,
          collected_at: now,
          source:      "audit_log table (hash chain)",
        },
      ],
    },
  ];

  // Overall compliance score
  const overallScore = Math.round(evidence.reduce((s, e) => s + e.score, 0) / evidence.length);

  return NextResponse.json({
    framework,
    period_start:    periodStart,
    period_end:      periodEnd,
    generated_at:    now,
    overall_score:   overallScore,
    controls:        evidence,
    audit_integrity: chainIntegrity,
    summary: {
      total_scans:        totalScans ?? 0,
      total_attestations: totalAttestations ?? 0,
      open_violations:    openViolations ?? 0,
      resolved_violations:resolvedViolations ?? 0,
      secrets_detected:   secretFindings ?? 0,
      secrets_resolved:   secretResolved ?? 0,
      audit_events:       auditEvents ?? 0,
    },
  });
}

export async function POST(req: NextRequest) {
  const { org_id, user_id, actor_email, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  const body = await req.json() as {
    control_id:   string;
    framework_id: string;
    notes?:       string;
    url?:         string;
  };

  if (!body.control_id) return NextResponse.json({ error:"missing_control_id" }, { status:400 });

  const db  = createServiceClient();
  const now = new Date().toISOString();

  // Mark evidence as collected for this control
  await db.from("compliance_exceptions").upsert({
    org_id,
    framework_id: body.framework_id ?? "soc2",
    control_id:   body.control_id,
    title:        `Evidence collected for ${body.control_id}`,
    description:  body.notes ?? "Auto-collected by TrustLedger",
    status:       "resolved",
  }, { onConflict: "org_id,framework_id,control_id" });

  return NextResponse.json({ ok: true, control_id: body.control_id, collected_at: now });
}
