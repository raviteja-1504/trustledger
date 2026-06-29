/**
 * SLA Breach Monitor
 * Called on a schedule (or on each scan) to detect overdue attestations.
 * When a CRITICAL file hasn't been attested within the org's SLA window,
 * it fires a P1 alert and delivers it via Slack/email.
 */

import type { SupabaseClient } from "@supabase/supabase-js";
import { writeAuditLog } from "./audit";
import { deliverAlert } from "./alertDelivery";

export async function checkSLABreaches(
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  db: SupabaseClient<any>,
): Promise<{ breaches: number }> {
  const now = new Date().toISOString();

  // Find violations past their SLA deadline that are still open
  const { data: overdue } = await db
    .from("violations")
    .select("id, org_id, scan_id, file_path, risk_score, sla_deadline, scans(repo_full_name, pr_number)")
    .in("status", ["open", "in_review"])
    .not("sla_deadline", "is", null)
    .lt("sla_deadline", now) as {
      data: Array<{
        id: string; org_id: string; scan_id: string;
        file_path: string; risk_score: string; sla_deadline: string;
        scans: { repo_full_name: string; pr_number: number } | null;
      }> | null
    };

  if (!overdue || overdue.length === 0) return { breaches: 0 };

  // Deduplicate by org
  const byOrg: Record<string, typeof overdue> = {};
  overdue.forEach((v: (typeof overdue)[0]) => {
    if (!byOrg[v.org_id]) byOrg[v.org_id] = [];
    byOrg[v.org_id].push(v);
  });

  let totalBreaches = 0;

  for (const org_id of Object.keys(byOrg)) {
    const violations = byOrg[org_id];
    // Get org config
    const { data: org } = await db
      .from("organizations")
      .select("name, slug")
      .eq("id", org_id)
      .single() as { data: { name: string; slug: string } | null };

    // Group by scan (1 alert per scan, not per file)
    const byScan: Record<string, typeof violations> = {};
    violations.forEach((v: (typeof violations)[0]) => {
      if (!byScan[v.scan_id]) byScan[v.scan_id] = [];
      byScan[v.scan_id].push(v);
    });

    for (const scan_id of Object.keys(byScan)) {
      const scanViolations = byScan[scan_id];
      const critCount = scanViolations.filter(v => v.risk_score === "CRITICAL").length;
      const highCount = scanViolations.filter(v => v.risk_score === "HIGH").length;
      const severity  = critCount > 0 ? "P1" : "P2";
      const repo      = scanViolations[0]?.scans?.repo_full_name ?? "unknown";
      const pr        = scanViolations[0]?.scans?.pr_number;

      // Skip if there is already an OPEN (firing / acknowledged) SLA alert for this scan.
      // Using open status instead of a time window prevents duplicate rows piling up
      // every time the cron runs while the breach is still unresolved.
      const { data: existing } = await db
        .from("alerts")
        .select("id")
        .eq("org_id", org_id)
        .eq("scan_id", scan_id)
        .eq("alert_type", "sla_breach")
        .in("status", ["firing", "acknowledged", "snoozed"])
        .limit(1) as { data: { id: string }[] | null };

      if (existing && existing.length > 0) continue; // Open alert already exists, skip

      const title = `SLA breach — ${critCount + highCount} file${critCount + highCount > 1 ? "s" : ""} unattested in ${repo.split("/").pop()}`;
      const body  = [
        `${critCount > 0 ? `${critCount} CRITICAL` : ""}${critCount > 0 && highCount > 0 ? " and " : ""}${highCount > 0 ? `${highCount} HIGH` : ""} file${critCount + highCount > 1 ? "s" : ""} in \`${repo}\`${pr ? ` PR #${pr}` : ""} have exceeded their attestation SLA.`,
        "Immediate review required to unblock deployments.",
      ].join(" ");

      // Insert alert
      const { data: alert } = await db
        .from("alerts")
        .insert({
          org_id,
          alert_type:  "sla_breach",
          severity,
          status:      "firing",
          title,
          body,
          repo,
          scan_id,
          fired_at:    now,
          escalation_emails: [],
        })
        .select("id")
        .single() as { data: { id: string } | null };

      if (!alert) continue;

      // Deliver alert
      await deliverAlert(
        {
          slack_webhook:    process.env.SLACK_WEBHOOK_URL,
          sendgrid_api_key: process.env.SENDGRID_API_KEY,
          alert_from_email: process.env.ALERT_FROM_EMAIL ?? "alerts@trustledger.dev",
          alert_emails:     [],
        },
        {
          alert_id: alert.id,
          severity,
          title,
          body,
          repo,
          scan_id,
          org_name: org?.name ?? org_id,
          app_url:  process.env.NEXT_PUBLIC_APP_URL ?? "https://app.trustledger.dev",
        },
      );

      await writeAuditLog(db, {
        org_id,
        event_type:    "sla_breach",
        actor_email:   "system",
        resource_type: "violation",
        resource_id:   scan_id,
        payload: { repo, critCount, highCount, severity },
      });

      totalBreaches += critCount + highCount;
    }
  }

  return { breaches: totalBreaches };
}
