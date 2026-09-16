/**
 * PDF Report Generator — server-side
 * Generates signed compliance reports for SOC 2, EU AI Act, PCI-DSS.
 * Uses @react-pdf/renderer on the server.
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey } from "../_middleware";
import { writeAuditLog } from "@/lib/audit";
import { checkRateLimit, RATE_LIMITS } from "@/lib/rateLimit";
import { collectEvidence } from "@/lib/evidenceEngine";
import crypto from "crypto";

export async function POST(req: NextRequest) {
  const { org_id, user_id, actor_email, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  const rl = await checkRateLimit(org_id, RATE_LIMITS.report);
  if (!rl.success) {
    return NextResponse.json({ error: "rate_limited" }, { status: 429, headers: rl.headers });
  }

  const body = await req.json() as {
    framework:    string;   // SOC2 | EUAI | PCIDSS
    period_start: string;
    period_end:   string;
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

  // Build report payload
  const reportData = {
    report_id:     reportId,
    org:           org ?? { name: "Unknown", slug: "", github_org: null },
    framework:     body.framework,
    period_start:  body.period_start,
    period_end:    body.period_end,
    generated_at:  new Date().toISOString(),
    generated_by:  actor_email ?? "—",
    metrics: {
      total_scans:        scans?.length ?? 0,
      total_files:        (scans ?? []).reduce((s, sc) => s + sc.file_count, 0),
      total_attestations: attestations?.length ?? 0,
      critical_findings:  (scans ?? []).filter(s => s.overall_risk === "CRITICAL").length,
      secrets_detected:   secrets?.length ?? 0,
      avg_ai_percentage:  scans && scans.length > 0
        ? scans.reduce((s, sc) => s + sc.total_ai_percentage, 0) / scans.length
        : 0,
    },
    risk_breakdown: { critical: criticalCount, high: highCount, medium: mediumCount, low: lowCount },
    gaps:           gapFiles,
    compliance:     evidence.controls.map(c => ({
      control_id: c.control_id, control_name: c.control_name, status: c.status, score: c.score,
      evidence: c.evidence.map(e => ({ description: e.description, count: e.count, source: e.source })),
    })),
    scans:        scans ?? [],
    attestations: attestations ?? [],
    secrets:      secrets ?? [],
  };

  // Real signature over the exact report content -- same pattern as
  // /api/export/signed: HMAC-SHA256, same already-configured signing key,
  // honestly labeled. This is what replaced the Reports page's fabricated
  // "SHA-256 with RSA-4096" / fake PGP block in the on-screen preview --
  // this is the genuine artifact those claims should have described.
  const signingKey = process.env.EXPORT_SIGNING_KEY ?? process.env.CRON_SECRET;
  if (!signingKey) {
    return NextResponse.json({ error: "report_signing_not_configured", detail: "Set EXPORT_SIGNING_KEY or CRON_SECRET" }, { status: 503 });
  }
  const contentToSign = JSON.stringify(reportData);
  const signature = crypto.createHmac("sha256", signingKey).update(contentToSign).digest("hex");

  // Generate PDF using @react-pdf/renderer
  try {
    const { renderToBuffer } = await import("@react-pdf/renderer");
    const { createElement }  = await import("react");
    const { buildReportDocument } = await import("@/lib/reportPDF");

    const doc    = createElement(buildReportDocument, { data: reportData, signature });
    const buffer = await renderToBuffer(doc as Parameters<typeof renderToBuffer>[0]);

    await writeAuditLog(db, {
      org_id,
      event_type:    "report_generated",
      actor_id:      user_id ?? null,
      actor_email:   actor_email ?? null,
      resource_type: "report",
      payload: { framework: body.framework, period_start: body.period_start, period_end: body.period_end, signature },
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

    return new NextResponse(uint8, {
      headers: {
        "Content-Type":            "application/pdf",
        "Content-Disposition":     `attachment; filename="${filename}"`,
        "Content-Length":          String(uint8.length),
        "X-TrustLedger-Signature": signature,
      },
    });

  } catch (err) {
    // Fallback: return JSON if PDF rendering failed. Logged (previously
    // silent) because a silent catch here means the client still gets a
    // 200 and force-downloads the JSON body as "*.pdf" -- a file that
    // can't be opened, with no trace of why in the response.
    console.error("report PDF render failed", { org_id, framework: body.framework, err });
    return NextResponse.json({ ...reportData, signature, pdf_render_failed: true });
  }
}
