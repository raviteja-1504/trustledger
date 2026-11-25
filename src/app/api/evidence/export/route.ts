/**
 * GET /api/evidence/export
 *
 * Downloadable auditor evidence package for a framework + audit period.
 *
 * Returns a JSON document containing:
 *   - Framework metadata and mapping version
 *   - Control mapping (what evidence each control requires)
 *   - Scope disclaimer (what this evidence does and does NOT cover)
 *   - Evidence records collected in the period (metadata + content hashes)
 *   - Control coverage analysis (satisfied / partial / missing / expired), counting only evidence that verifies
 *   - Control owners, missing-evidence gaps and the remediation items that answer them (gap_report)
 *   - Audit trail entries for evidence collection in the period
 *   - Ed25519 cryptographic signature over the WHOLE package, as canonical JSON with keys sorted at every level
 *     (when configured). scripts/verify-evidence-export.cjs checks it, and re-derives every record's content hash.
 *   - Framework version used for evaluation
 *
 * Query params:
 *   framework      – required: "soc2" | "iso27001" | "pcidss" | "aigov"
 *   period_start   – ISO 8601 (default: 90 days ago)
 *   period_end     – ISO 8601 (default: now)
 *
 * Requires can_export_data permission.
 *
 * IMPORTANT: This package is supporting evidence for an assessor.
 * It does NOT establish compliance. A technical scan alone does not satisfy
 * any control. Compliance determinations require human review, policy
 * documentation, and testing by an independent assessor.
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey, requirePermission } from "../../_middleware";
import { writeAuditLog, canonicalJson } from "@/lib/audit";
import { safeError } from "@/lib/errors";
import { rowToEvidenceRecord, checkIntegrity } from "@/lib/evidenceRecord";
import { isTrustedEvidence } from "@/lib/evidenceVerification";
import { loadAnchors, loadControlOwners, loadRemediations } from "@/lib/evidenceTracking";
import { buildGapReport } from "@/lib/controlTracking";
import {
  getFrameworkMapping,
  frameworkCoverageSummary,
} from "@/lib/controlMapping";
import { signEd25519 } from "@/lib/exportSigning";

export async function GET(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });
  const roleErr = await requirePermission(auth, "can_export_data");
  if (roleErr) return NextResponse.json({ error: roleErr }, { status: 403 });

  const p = req.nextUrl.searchParams;
  const framework = p.get("framework");
  if (!framework) return NextResponse.json({ error: "missing_framework", supported: ["soc2", "iso27001", "pcidss", "aigov"] }, { status: 400 });

  const fw = getFrameworkMapping(framework);
  if (!fw) return NextResponse.json({ error: "unknown_framework", supported: ["soc2", "iso27001", "pcidss", "aigov"] }, { status: 400 });

  const periodEnd   = p.get("period_end")   ?? new Date().toISOString();
  const periodStart = p.get("period_start") ?? new Date(new Date(periodEnd).getTime() - 90 * 86_400_000).toISOString();

  const db = createServiceClient();

  // Load all evidence records for this org + framework in the period.
  const { data: rows, error: rowErr } = await db
    .from("evidence_log")
    .select("id, org_id, framework_id, control_id, note, file_url, collected_by, collected_by_email, created_at")
    .eq("org_id", auth.org_id)
    .eq("framework_id", fw.framework_id)
    .gte("created_at", periodStart)
    .lte("created_at", periodEnd)
    .order("created_at", { ascending: true }) as { data: Array<Record<string, unknown>> | null; error: unknown };

  if (rowErr) return safeError(rowErr, { code: "export_fetch_failed", message: "Could not load evidence records." });

  const records = (rows ?? [])
    .map(row => rowToEvidenceRecord(row as unknown as Parameters<typeof rowToEvidenceRecord>[0]))
    .filter((r): r is NonNullable<typeof r> => r !== null);

  // Load audit trail for evidence collection in the period.
  const { data: auditRows } = await db
    .from("audit_log")
    .select("id, event_type, actor_email, resource_id, payload, created_at")
    .eq("org_id", auth.org_id)
    .in("event_type", ["evidence_collected", "evidence_deleted", "evidence_uploaded"])
    .gte("created_at", periodStart)
    .lte("created_at", periodEnd)
    .order("created_at", { ascending: true }) as { data: Array<Record<string, unknown>> | null };

  const now = new Date();
  // Each record's hash is recomputed here, and compared with the copy in the audit log, so the package reports
  // what is true now rather than a stored status. A record that fails neither counts toward a control.
  const anchors = await loadAnchors(db, auth.org_id, records);
  const coverage = frameworkCoverageSummary(fw.framework_id, records, now, { isTrusted: r => isTrustedEvidence(r, anchors.get(r.evidence_id)) });

  // Who owns each control and how each gap is being answered (the remediation register, compliance_exceptions).
  const [owners, remediations] = await Promise.all([loadControlOwners(db, auth.org_id, fw.framework_id), loadRemediations(db, auth.org_id, fw.framework_id)]);
  const gapReport = buildGapReport(coverage!.controls, owners, remediations, now.toISOString().slice(0, 10));

  // Build the canonical export document.
  const pkg = {
    export_version:    "1.1",
    // What the signature covers: this whole document except `cryptographic_verification`, serialised as canonical
    // JSON (object keys sorted at every level, no whitespace). Version 1.0 signed only top-level scalars.
    signature_scheme:  "canonical-json-sorted-keys",
    generated_at:      now.toISOString(),
    generated_by:      auth.actor_email ?? auth.user_id ?? "system",
    org_id:            auth.org_id,
    period_start:      periodStart,
    period_end:        periodEnd,

    framework: {
      id:              fw.framework_id,
      name:            fw.framework_name,
      version:         fw.framework_version,
      mapping_version: fw.mapping_version,
    },

    // The scope disclaimer must always accompany the evidence.
    scope_disclaimer:  fw.scope_disclaimer,

    // ── Control mapping ───────────────────────────────────────────────────
    control_mapping: fw.controls.map(c => ({
      control_id:        c.control_id,
      control_name:      c.control_name,
      sufficient_alone:  c.sufficient_alone,  // always false
      required_evidence: c.required_evidence,
    })),

    // ── Evidence records ──────────────────────────────────────────────────
    // Note: original evidence (file_url / evidence_source) is a pointer only;
    // the actual artifact must be fetched separately where applicable.
    evidence_records: records.map(r => ({
      evidence_id:         r.evidence_id,
      control_id:          r.control_id,
      evidence_type:       r.evidence_type,
      evidence_source:     r.evidence_source,
      repository_id:       r.repository_id ?? null,
      commit_sha:          r.commit_sha ?? null,
      scan_id:             r.scan_id ?? null,
      attestation_id:      r.attestation_id ?? null,
      collection_timestamp: r.collection_timestamp,
      collector_identity:  r.collector_identity,
      content_hash:        r.content_hash,
      // 2: content_hash recomputes from the fields shown here (scripts/verify-evidence-export.cjs does so).
      // 1: collected before that; its hash cannot be recomputed and counts only once it has been verified.
      hash_version:        r.hash_version ?? 1,
      integrity:           checkIntegrity(r),
      audit_anchor:        anchors.get(r.evidence_id),
      verification_status: r.verification_status,
      expiration_date:     r.expiration_date,
    })),

    // ── Ownership, missing evidence and remediation ───────────────────────
    // Per control: owner, the evidence still missing / expired / unverified, and the remediation items that answer it.
    // A resolved remediation item does not close a gap; only verified, current evidence does.
    gap_report: gapReport,

    // ── Coverage analysis ─────────────────────────────────────────────────
    coverage,

    // ── Audit trail ───────────────────────────────────────────────────────
    audit_trail: (auditRows ?? []).map(e => ({
      id:           e["id"],
      event_type:   e["event_type"],
      actor_email:  e["actor_email"],
      resource_id:  e["resource_id"],
      payload:      e["payload"],
      timestamp:    e["created_at"],
    })),
  };

  // ── Cryptographic signature ───────────────────────────────────────────────
  const canonical = canonicalJson(pkg);
  const signature  = signEd25519(canonical, "canonical JSON of this document without cryptographic_verification: object keys sorted at every level, no whitespace");

  const response = {
    ...pkg,
    cryptographic_verification: signature
      ? {
          algorithm:      signature.algorithm,
          key_id:         signature.key_id,
          public_key_pem: signature.public_key_pem,
          signature:      signature.value,
          signed_content: signature.signed_content,
          note:           "Verify offline with scripts/verify-evidence-export.cjs <file> [trusted-public-key.pem]. Trust the key only if it matches the one published at /.well-known/trustledger-export-signing-key.",
        }
      : { note: "No signing key configured; set EXPORT_SIGNING_PRIVATE_KEY to enable Ed25519 signatures." },
  };

  await writeAuditLog(db, {
    org_id:        auth.org_id,
    event_type:    "data_exported",
    actor_id:      auth.user_id ?? null,
    actor_email:   auth.actor_email ?? null,
    resource_type: "evidence_export",
    resource_id:   undefined,
    payload: {
      framework:        fw.framework_id,
      period_start:     periodStart,
      period_end:       periodEnd,
      record_count:     records.length,
      signed:           !!signature,
    },
  });

  return new NextResponse(JSON.stringify(response, null, 2), {
    status: 200,
    headers: {
      "Content-Type":        "application/json",
      "Content-Disposition": `attachment; filename="evidence-export-${fw.framework_id}-${now.toISOString().slice(0, 10)}.json"`,
    },
  });
}
