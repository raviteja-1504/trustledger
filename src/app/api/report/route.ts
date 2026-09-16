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

  // Build report payload
  const reportData = {
    org:           org ?? { name: "Unknown", slug: "", github_org: null },
    framework:     body.framework,
    period_start:  body.period_start,
    period_end:    body.period_end,
    generated_at:  new Date().toISOString(),
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
