/**
 * PDF Report Generator — server-side
 * Generates signed compliance reports for SOC 2, EU AI Act, PCI-DSS.
 * Uses @react-pdf/renderer on the server.
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey } from "../_middleware";
import { writeAuditLog } from "@/lib/audit";

export async function POST(req: NextRequest) {
  const { org_id, user_id, actor_email, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

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

  // Generate PDF using @react-pdf/renderer
  try {
    const { renderToBuffer } = await import("@react-pdf/renderer");
    const { createElement }  = await import("react");
    const { buildReportDocument } = await import("@/lib/reportPDF");

    const doc    = createElement(buildReportDocument, { data: reportData });
    const buffer = await renderToBuffer(doc as Parameters<typeof renderToBuffer>[0]);

    await writeAuditLog(db, {
      org_id,
      event_type:    "report_generated",
      actor_id:      user_id ?? null,
      actor_email:   actor_email ?? null,
      resource_type: "report",
      payload: { framework: body.framework, period_start: body.period_start, period_end: body.period_end },
    });

    const filename = `trustledger-${body.framework.toLowerCase()}-${body.period_start.slice(0,7)}.pdf`;
    const uint8    = new Uint8Array(buffer);

    return new NextResponse(uint8, {
      headers: {
        "Content-Type":        "application/pdf",
        "Content-Disposition": `attachment; filename="${filename}"`,
        "Content-Length":      String(uint8.length),
      },
    });

  } catch {
    // Fallback: return JSON if PDF renderer unavailable
    return NextResponse.json(reportData);
  }
}
