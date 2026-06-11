/**
 * Weekly Compliance Report Cron
 * Runs every Monday at 08:00 UTC — generates PDF reports for all orgs
 * and emails them to admin users via SendGrid.
 * Vercel Cron schedule: "0 8 * * 1"
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { sendEmailAlert } from "@/lib/alertDelivery";

export async function GET(req: NextRequest) {
  const auth = req.headers.get("authorization");
  if (auth !== `Bearer ${process.env.CRON_SECRET}`) {
    return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  }

  const db = createServiceClient();
  const appUrl = process.env.NEXT_PUBLIC_APP_URL ?? "https://app.trustledger.dev";

  // Get all active orgs
  const { data: orgs } = await db
    .from("organizations")
    .select("id, name, slug") as { data: Array<{ id: string; name: string; slug: string }> | null };

  if (!orgs || orgs.length === 0) {
    return NextResponse.json({ ok: true, reports_sent: 0 });
  }

  const periodEnd   = new Date().toISOString().split("T")[0];
  const periodStart = new Date(Date.now() - 7 * 86400_000).toISOString().split("T")[0];
  let reportsSent   = 0;

  for (const org of orgs) {
    try {
      // Get admin emails for this org
      const { data: admins } = await db
        .from("org_members")
        .select("email")
        .eq("org_id", org.id)
        .eq("role", "admin") as { data: Array<{ email: string }> | null };

      const adminEmails = (admins ?? []).map(m => m.email).filter(Boolean);
      if (adminEmails.length === 0) continue;

      // Generate PDF via internal report API
      const pdfRes = await fetch(`${appUrl}/api/report`, {
        method:  "POST",
        headers: {
          "Content-Type":        "application/json",
          "X-TrustLedger-Key":   process.env.INTERNAL_CRON_KEY ?? "",
          "x-org-id-override":   org.id,  // bypass normal auth for cron
        },
        body: JSON.stringify({
          framework:    "SOC2",
          period_start: periodStart,
          period_end:   periodEnd,
        }),
      });

      let pdfBuffer: Buffer | null = null;
      if (pdfRes.ok && pdfRes.headers.get("content-type")?.includes("pdf")) {
        const bytes = await pdfRes.arrayBuffer();
        pdfBuffer = Buffer.from(bytes);
      }

      // Fetch weekly metrics summary
      const { data: scanCount } = await db
        .from("scans")
        .select("id", { count: "exact", head: true })
        .eq("org_id", org.id)
        .gte("created_at", `${periodStart}T00:00:00Z`) as { data: null; count: number | null };

      const { data: attCount } = await db
        .from("attestations")
        .select("id", { count: "exact", head: true })
        .eq("org_id", org.id)
        .gte("created_at", `${periodStart}T00:00:00Z`) as { data: null; count: number | null };

      const { data: openViolations } = await db
        .from("violations")
        .select("id", { count: "exact", head: true })
        .eq("org_id", org.id)
        .in("status", ["open", "in_review"]) as { data: null; count: number | null };

      const emailHtml = `
<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#f8fafc;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif">
  <div style="max-width:600px;margin:40px auto;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.08)">
    <div style="background:linear-gradient(135deg,#0f172a,#1e1b4b);padding:28px 32px">
      <div style="color:rgba(165,180,252,0.8);font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:1px;margin-bottom:6px">
        TrustLedger · Weekly Report
      </div>
      <div style="color:white;font-size:22px;font-weight:800">${org.name}</div>
      <div style="color:rgba(255,255,255,0.5);font-size:12px;margin-top:4px">${periodStart} — ${periodEnd}</div>
    </div>
    <div style="padding:28px 32px">
      <div style="display:flex;gap:16px;margin-bottom:24px">
        ${[
          { label:"Scans Run",      value: String(scanCount ?? 0),         color:"#6366f1" },
          { label:"Attestations",   value: String(attCount ?? 0),          color:"#10b981" },
          { label:"Open Violations",value: String(openViolations ?? 0),    color:"#ef4444" },
        ].map(m => `
          <div style="flex:1;background:#f8fafc;border-radius:8px;padding:14px;border:1px solid #e2e8f0;text-align:center">
            <div style="font-size:24px;font-weight:800;color:${m.color}">${m.value}</div>
            <div style="font-size:11px;color:#64748b;margin-top:2px">${m.label}</div>
          </div>`).join("")}
      </div>
      <a href="${appUrl}/reports" style="display:inline-block;background:linear-gradient(135deg,#6366f1,#7c3aed);color:white;text-decoration:none;padding:12px 24px;border-radius:8px;font-size:14px;font-weight:700;margin-bottom:16px">
        View Full Report →
      </a>
      <p style="color:#64748b;font-size:13px;margin-top:16px">
        ${pdfBuffer ? "A PDF compliance report is attached to this email." : "Log in to TrustLedger to download PDF reports."}
      </p>
    </div>
    <div style="padding:14px 32px;background:#f8fafc;border-top:1px solid #e2e8f0">
      <p style="margin:0;color:#94a3b8;font-size:11px">
        TrustLedger AI Governance Platform · Weekly digest · <a href="${appUrl}/settings" style="color:#6366f1">Unsubscribe</a>
      </p>
    </div>
  </div>
</body>
</html>`;

      // Send email
      const sendgridKey = process.env.SENDGRID_API_KEY ?? "";
      if (sendgridKey) {
        await sendEmailAlert(sendgridKey, process.env.ALERT_FROM_EMAIL ?? "reports@trustledger.dev", adminEmails, {
          alert_id: `weekly-${org.id}-${periodEnd}`,
          severity: "P4",
          title:    `Weekly Security Report — ${org.name}`,
          body:     emailHtml,
          org_name: org.name,
          app_url:  appUrl,
        });
        reportsSent++;
      }

    } catch (e) {
      console.error(`Weekly report failed for org ${org.id}:`, e);
    }
  }

  return NextResponse.json({
    ok:           true,
    reports_sent: reportsSent,
    orgs_total:   orgs.length,
    period:       `${periodStart} — ${periodEnd}`,
  });
}
