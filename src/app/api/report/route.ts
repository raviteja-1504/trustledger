/**
 * PDF Report Generator — server-side
 * Generates signed control-evidence reports for SOC 2, ISO 27001, PCI DSS and AI code governance
 * (lib/controlEvidence.ts). The old "EUAI" id is accepted and maps to AI code governance.
 * Uses @react-pdf/renderer on the server.
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey, requirePermission } from "../_middleware";
import { writeAuditLog } from "@/lib/audit";
import { checkRateLimit, RATE_LIMITS } from "@/lib/rateLimit";
import { collectEvidence } from "@/lib/evidenceEngine";
import crypto from "crypto";
import { logger } from "@/lib/logger";
import { reportServerError } from "@/lib/serverErrors";
import { signEd25519 } from "@/lib/exportSigning";
import { canonicalJson } from "@/lib/trustRecord";
import type { ReportSignature } from "@/lib/reportPDF";
import { loadChangeRegister } from "@/lib/changeRegisterLoader";
import { REGISTER_CONTROL, registerForReport, type ReportChangeRegister } from "@/lib/changeRegister";
import { frameworkById } from "@/lib/controlEvidence";
import { frameworkView } from "@/lib/frameworkViews";

export async function POST(req: NextRequest) {
  const auth = await verifyApiKey(req);
  const { org_id, user_id, actor_email, error } = auth;
  if (error) return NextResponse.json({ error }, { status: 401 });
  const permErr = await requirePermission(auth, "can_create_reports");
  if (permErr) return NextResponse.json({ error: permErr }, { status: 403 });

  const rl = await checkRateLimit(org_id, RATE_LIMITS.report);
  if (!rl.success) {
    return NextResponse.json({ error: "rate_limited" }, { status: 429, headers: rl.headers });
  }

  const body = await req.json() as {
    framework:    string;   // SOC2 | ISO27001 | PCIDSS | AIGOV (EUAI accepted → AIGOV)
    period_start: string;
    period_end:   string;
    /** "pdf" (default): the PDF itself; "bundle": JSON with the PDF (base64) and its signed evidence record. */
    format?:      "pdf" | "bundle";
  };

  const db = createServiceClient();

  // Pull scan + attestation data for the period
  const { data: scans } = await db
    .from("scans")
    .select("id, repo_full_name, overall_risk, total_ai_percentage, file_count, created_at")
    .eq("org_id", org_id)
    .gte("created_at", body.period_start)
    .lte("created_at", body.period_end)
    .order("created_at", { ascending: true });

  const { data: attestations } = await db
    .from("attestations")
    .select("id, scan_id, file_path, risk_score, reviewer_email, payload_hash, created_at")
    .eq("org_id", org_id)
    .gte("created_at", body.period_start)
    .lte("created_at", body.period_end);

  const { data: secrets } = await db
    .from("secret_findings")
    .select("id, file_path, secret_type, severity, label, status, created_at")
    .eq("org_id", org_id)
    .gte("created_at", body.period_start)
    .lte("created_at", body.period_end);

  const { data: org } = await db
    .from("organizations")
    .select("name, slug, github_org")
    .eq("id", org_id)
    .single();

  // Real per-control evidence -- the same engine the Compliance and
  // Evidence pages use (lib/evidenceEngine.ts), not a fourth independently
  // -invented scoring formula. Drives the PDF's Compliance Mapping section.
  const evidence = await collectEvidence(org_id, body.framework, body.period_start, body.period_end);

  // File-level risk data for the period -- scan_files carries the actual
  // per-file risk classification that `scans` (scan-level rows) doesn't,
  // needed for a real Risk Overview breakdown and Gap Analysis below.
  // Bounded like every other list in this report; the report's headline
  // *counts* still come from exact head:true COUNT queries, not row length.
  const { data: riskFileRows } = await db
    .from("scan_files")
    .select("scan_id, file_path, risk_score, ai_percentage, created_at, scans(repo_full_name, pr_number)")
    .eq("org_id", org_id)
    .gte("created_at", body.period_start)
    .lte("created_at", body.period_end)
    .order("created_at", { ascending: false })
    .limit(1000);

  const countByRisk = async (risk: string) => {
    const { count } = await db
      .from("scan_files")
      .select("id", { count: "exact", head: true })
      .eq("org_id", org_id)
      .eq("risk_score", risk)
      .gte("created_at", body.period_start)
      .lte("created_at", body.period_end);
    return count ?? 0;
  };
  const [criticalCount, highCount, mediumCount, lowCount] = await Promise.all(
    ["CRITICAL", "HIGH", "MEDIUM", "LOW"].map(countByRisk)
  );

  const attestedFileSet = new Set((attestations ?? []).map(a => `${a.scan_id}::${a.file_path}`));
  type RiskFileRow = { scan_id: string; file_path: string; risk_score: string; ai_percentage: number; created_at: string; scans: { repo_full_name: string; pr_number: number } | null };
  const gapFiles = ((riskFileRows ?? []) as unknown as RiskFileRow[])
    .filter(f => (f.risk_score === "CRITICAL" || f.risk_score === "HIGH") && !attestedFileSet.has(`${f.scan_id}::${f.file_path}`))
    .slice(0, 15)
    .map(f => ({
      repo:       f.scans?.repo_full_name ?? "",
      pr_number:  f.scans?.pr_number ?? 0,
      file_path:  f.file_path,
      risk_score: f.risk_score,
      ai_percentage: f.ai_percentage,
    }));

  // Report Reference -- one id used consistently in the PDF header, the
  // Report Reference section, the footer, and the report_generations row
  // below, so "the report an auditor was handed" is traceable to one record.
  const reportId = crypto.randomUUID().toUpperCase();

  // The change-management register for the frameworks with a change-control criterion: every pull request merged in
  // the period, and the auditor sample drawn with this report's id as its seed (anyone with the record re-draws it).
  // A register that can't be built is stated in the report, not left out silently.
  let changeRegister: ReportChangeRegister | undefined;
  if (REGISTER_CONTROL[evidence.framework.toLowerCase()]) {
    try {
      changeRegister = registerForReport(await loadChangeRegister(db, org_id, body.period_start, body.period_end), reportId);
    } catch (err) {
      logger.error("Report change register failed", { org_id, detail: err instanceof Error ? err.message : String(err) });
      changeRegister = { error: "The change register could not be built when this report was generated (GitHub or TrustLedger's records could not be read)." };
    }
  }

  const frameworkDef = frameworkById(evidence.framework.toLowerCase());
  const fwView = frameworkDef ? frameworkView(frameworkDef, evidence.controls) : null;

  // Build report payload
  const reportData = {
    report_id:     reportId,
    org:           org ?? { name: "Unknown", slug: "", github_org: null },
    framework:     body.framework,
    period_start:  body.period_start,
    period_end:    body.period_end,
    generated_at:  new Date().toISOString(),
    generated_by:  actor_email ?? "—",
    framework_id:  evidence.framework,
    evidence_scope: { name: evidence.framework_name, standard: evidence.standard, scope: evidence.scope, status_counts: evidence.status_counts },
    metrics: {
      total_scans:        scans?.length ?? 0,
      total_files:        (scans ?? []).reduce((s, sc) => s + sc.file_count, 0),
      total_attestations: attestations?.length ?? 0,
      critical_findings:  criticalCount,
      high_risk_files:    evidence.facts.risky.total,
      high_risk_reviewed: evidence.facts.risky.reviewed,
      independent_reviews: evidence.facts.reviews.independent,
      self_approvals:     evidence.facts.reviews.self,
      secrets_detected:   secrets?.length ?? 0,
      avg_ai_percentage:  scans && scans.length > 0
        ? scans.reduce((s, sc) => s + sc.total_ai_percentage, 0) / scans.length
        : 0,
    },
    risk_breakdown: { critical: criticalCount, high: highCount, medium: mediumCount, low: lowCount },
    gaps:           gapFiles,
    compliance:     evidence.controls.map(c => ({
      control_id: c.control_id, control_name: c.control_name, status: c.status, score: c.score,
      statement: c.statement, owner: c.owner, frequency: c.frequency, test: c.test, ...(c.partial ? { partial: c.partial } : {}),
      checks: c.checks.map(k => ({ label: k.label, basis: k.basis, status: k.status, summary: k.summary, gaps: k.gaps })),
    })),
    not_covered:    evidence.not_covered,
    // the framework's own working form: ISO SoA input, PCI 6.2.4 attack classes, AI governance mappings
    ...(fwView ? { framework_view: fwView } : {}),
    ...(changeRegister ? { change_register: changeRegister } : {}),
    scans:       scans ?? [],
    attestations: attestations ?? [],
    secrets:      secrets ?? [],
  };

  // The signature covers the report's evidence record -- the exact data the PDF is rendered from -- as canonical JSON
  // (keys sorted, no whitespace), the same format as a Trust Record. The record goes to the requester with the PDF,
  // so an auditor can verify it independently: with the Ed25519 public key published at
  // /.well-known/trustledger-export-signing-key (scripts/verify-trust-record.mjs), and match it to the PDF through
  // the record's SHA-256 printed there. HMAC (a shared secret, checkable only by us) is the fallback when no Ed25519
  // key is configured; a cron secret is never used as a signing key.
  const canonical = canonicalJson(reportData);
  const recordSha256 = crypto.createHash("sha256").update(canonical).digest("hex");
  const ed = signEd25519(canonical, "canonical JSON of `record` (the report's evidence): object keys sorted at every level, no whitespace");
  const hmacKey = process.env.EXPORT_SIGNING_KEY;
  if (!ed && !hmacKey) {
    return NextResponse.json({ error: "report_signing_not_configured", detail: "Set EXPORT_SIGNING_PRIVATE_KEY (Ed25519) or EXPORT_SIGNING_KEY" }, { status: 503 });
  }
  const sig: ReportSignature = ed
    ? { ...ed, record_sha256: recordSha256 }
    : { algorithm: "HMAC-SHA256", value: crypto.createHmac("sha256", hmacKey!).update(canonical).digest("hex"), record_sha256: recordSha256 };
  const signature = sig.value;

  // Generate PDF using @react-pdf/renderer
  try {
    const { renderToBuffer } = await import("@react-pdf/renderer");
    const { createElement }  = await import("react");
    const { buildReportDocument } = await import("@/lib/reportPDF");
    const { toRendererElements, loadRendererReact } = await import("@/lib/pdfElements");

    // Rebuilt with the renderer's own React: the bundled one's elements are rejected by it (see lib/pdfElements.ts).
    const doc    = toRendererElements(createElement(buildReportDocument, { data: reportData, signature: sig }), loadRendererReact());
    const buffer = await renderToBuffer(doc as Parameters<typeof renderToBuffer>[0]);

    await writeAuditLog(db, {
      org_id,
      event_type:    "report_generated",
      actor_id:      user_id ?? null,
      actor_email:   actor_email ?? null,
      resource_type: "report",
      payload: {
        framework: body.framework, period_start: body.period_start, period_end: body.period_end, signature,
        signature_algorithm: sig.algorithm, record_sha256: recordSha256, ...("key_id" in sig ? { key_id: sig.key_id } : {}),
      },
    });

    // Structured, queryable record (Reports page's "Recent Reports" list)
    // alongside the audit log entry above -- who generated what, for
    // which period, with which signature.
    await db.from("report_generations").insert({
      id: reportId.toLowerCase(),
      org_id, framework: body.framework,
      period_start: body.period_start, period_end: body.period_end,
      generated_by: user_id ?? null, generated_by_email: actor_email ?? null,
      signature,
    });

    const filename = `trustledger-${body.framework.toLowerCase()}-${body.period_start.slice(0,7)}.pdf`;
    const uint8    = new Uint8Array(buffer);

    // format "bundle": the PDF and its signed evidence record in one response (the Reports page saves both). The
    // record is { record, signature }, verifiable offline with scripts/verify-trust-record.mjs.
    if (body.format === "bundle") {
      return NextResponse.json({
        report_id: reportId, filename,
        pdf_base64: Buffer.from(uint8).toString("base64"),
        evidence: { record: reportData, signature: sig },
      }, { headers: { "Cache-Control": "private, no-store" } });
    }
    return new NextResponse(uint8, {
      headers: {
        "Content-Type":            "application/pdf",
        "Content-Disposition":     `attachment; filename="${filename}"`,
        "Content-Length":          String(uint8.length),
        "X-TrustLedger-Signature": signature,
        "X-TrustLedger-Signature-Algorithm": sig.algorithm,
        "X-TrustLedger-Record-SHA256": recordSha256,
      },
    });

  } catch (err) {
    // A failed render is an error response (it used to be a 200 carrying the whole report as JSON), logged so the
    // cause is visible -- the page shows "couldn't render" for it.
    logger.error("Report PDF render failed", { org_id, framework: body.framework, detail: err instanceof Error ? err.message : String(err) });
    reportServerError(err, { code: "report_render_failed", framework: body.framework });
    return NextResponse.json({ error: "report_render_failed", pdf_render_failed: true }, { status: 500 });
  }
}
