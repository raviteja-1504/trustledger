/**
 * Compliance Deadline Reminder Cron
 * Runs daily at 09:00 UTC — checks for upcoming audit deadlines
 * and emails reminder alerts to org admins.
 * Vercel Cron: "0 9 * * *"
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { sendEmailAlert } from "@/lib/alertDelivery";

// Days-before thresholds that trigger reminders
const REMIND_AT_DAYS = [30, 14, 7, 3, 1];

// Hardcoded compliance deadlines keyed by framework
// In production these would be stored in a `compliance_schedules` table
const FRAMEWORK_DEADLINES: Record<string, { title: string; date: string; framework: string }[]> = {
  soc2:   [
    { title:"SOC 2 Type II Audit Window Opens",  date:"2026-08-01", framework:"SOC 2"    },
    { title:"SOC 2 Report Delivery Deadline",    date:"2026-08-20", framework:"SOC 2"    },
  ],
  euai:   [
    { title:"EU AI Act Compliance Assessment",   date:"2026-07-15", framework:"EU AI Act"},
    { title:"EU AI Act Filing Deadline",         date:"2026-08-01", framework:"EU AI Act"},
  ],
  pcidss: [
    { title:"PCI-DSS QSA Annual Assessment",     date:"2026-09-01", framework:"PCI-DSS"  },
    { title:"PCI-DSS Certificate Expiry",        date:"2026-08-22", framework:"PCI-DSS"  },
  ],
};

export async function GET(req: NextRequest) {
  const auth = req.headers.get("authorization");
  if (auth !== `Bearer ${process.env.CRON_SECRET}`) {
    return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  }

  const db        = createServiceClient();
  const appUrl    = process.env.NEXT_PUBLIC_APP_URL ?? "https://app.trustledger.dev";
  const sendgrid  = process.env.SENDGRID_API_KEY ?? "";
  const fromEmail = process.env.ALERT_FROM_EMAIL ?? "compliance@trustledger.dev";
  const today     = new Date();
  let remindsSent = 0;

  // Get all orgs
  const { data: orgs } = await db
    .from("organizations")
    .select("id, name") as { data: Array<{ id: string; name: string }> | null };

  if (!orgs) return NextResponse.json({ ok: true, reminders_sent: 0 });

  for (const org of orgs) {
    // Get admin emails
    const { data: admins } = await db
      .from("org_members")
      .select("email")
      .eq("org_id", org.id)
      .eq("role", "admin") as { data: Array<{ email: string }> | null };

    const adminEmails = (admins ?? []).map(a => a.email).filter(Boolean);
    if (adminEmails.length === 0 || !sendgrid) continue;

    // Check all deadlines
    const allDeadlines = Object.values(FRAMEWORK_DEADLINES).flat();

    for (const deadline of allDeadlines) {
      const deadlineDate = new Date(deadline.date);
      const daysUntil    = Math.ceil((deadlineDate.getTime() - today.getTime()) / 86400_000);

      if (!REMIND_AT_DAYS.includes(daysUntil)) continue;

      // Check if we already sent this reminder today
      const reminderKey = `${org.id}::${deadline.title}::${daysUntil}d`;
      const { data: existing } = await db
        .from("alerts")
        .select("id")
        .eq("org_id", org.id)
        .eq("alert_type", "compliance-reminder")
        .like("body", `%${reminderKey}%`)
        .gte("fired_at", new Date(today.getFullYear(), today.getMonth(), today.getDate()).toISOString())
        .limit(1) as { data: { id: string }[] | null };

      if (existing && existing.length > 0) continue;

      const urgency  = daysUntil <= 3 ? "🔴" : daysUntil <= 7 ? "🟠" : "🟡";
      const severity = daysUntil <= 7 ? "P2" : "P3";

      const title = `${urgency} ${deadline.title} — ${daysUntil} day${daysUntil !== 1 ? "s" : ""} remaining`;
      const body  = `Your ${deadline.framework} compliance deadline "${deadline.title}" is on ${deadlineDate.toLocaleDateString("en-GB", { day:"numeric", month:"long", year:"numeric" })} — ${daysUntil} day${daysUntil !== 1 ? "s" : ""} from now. Ensure all evidence is collected and controls are documented.`;

      // Log alert
      await db.from("alerts").insert({
        org_id:     org.id,
        alert_type: "compliance-reminder",
        severity,
        status:     "firing",
        title,
        body:       `${body}\n\nReminderKey: ${reminderKey}`,
        fired_at:   new Date().toISOString(),
      });

      // Send email
      await sendEmailAlert(sendgrid, fromEmail, adminEmails, {
        alert_id: `compliance-${org.id}-${daysUntil}d`,
        severity: severity as "P2" | "P3",
        title,
        body,
        org_name: org.name,
        app_url:  appUrl,
        href:     `${appUrl}/compliance-calendar`,
      });

      remindsSent++;
    }
  }

  return NextResponse.json({
    ok:             true,
    reminders_sent: remindsSent,
    ran_at:         new Date().toISOString(),
  });
}
