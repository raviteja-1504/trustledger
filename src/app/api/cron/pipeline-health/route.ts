/**
 * Daily pipeline health check (Vercel cron, see vercel.json).
 *
 *  - For each organisation with stuck scans or undelivered webhooks (lib/pipelineHealth.ts), raise one
 *    "pipeline" alert — at most one per organisation per day, so a lasting problem doesn't flood the alerts list.
 *    Alerts go wherever the org's alert channels (Slack, email) already send.
 *  - Deletes ops_events older than 30 days (the Trace page's retention).
 *
 * The Trace page shows the same checks live; this job makes sure someone is told even if nobody looks.
 */
import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { pipelineHealth } from "@/lib/pipelineHealth";
import { recordEvent } from "@/lib/opsEvents";
import { runWithTrace, newTraceId } from "@/lib/trace";
import { logger } from "@/lib/logger";

export const maxDuration = 120;
const RETENTION_DAYS = 30;

export async function GET(req: NextRequest) {
  if (req.headers.get("authorization") !== `Bearer ${process.env.CRON_SECRET}`) {
    return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  }
  return runWithTrace({ trace_id: newTraceId() }, () => run());
}

async function run() {
  const db = createServiceClient();
  const now = Date.now();
  const { data: orgs } = await db.from("organizations").select("id") as { data: Array<{ id: string }> | null };

  let alertsRaised = 0;
  for (const org of orgs ?? []) {
    try {
      const h = await pipelineHealth(db, org.id, now);
      if (h.stuck_scans.length === 0 && h.undelivered_webhooks.length === 0) continue;

      const { data: recent } = await db.from("alerts").select("id")
        .eq("org_id", org.id).eq("alert_type", "pipeline")
        .gte("fired_at", new Date(now - 24 * 3600_000).toISOString()).limit(1);
      if (recent && recent.length > 0) continue;

      const parts = [
        h.stuck_scans.length ? `${h.stuck_scans.length} scan${h.stuck_scans.length !== 1 ? "s" : ""} stuck` : "",
        h.undelivered_webhooks.length ? `${h.undelivered_webhooks.length} webhook${h.undelivered_webhooks.length !== 1 ? "s" : ""} not processed` : "",
      ].filter(Boolean);
      const examples = h.stuck_scans.slice(0, 3).map(s => `${s.repo ?? "?"}#${s.pr_number ?? "?"} (${s.minutes} min)`).join(", ");
      await db.from("alerts").insert({
        org_id: org.id, alert_type: "pipeline", severity: "P2", status: "firing",
        title: `Scan pipeline: ${parts.join(", ")}`,
        body: `Some pull-request scans didn't finish.${examples ? ` Stuck: ${examples}.` : ""} Open the Trace page in TrustLedger to see each one's timeline.`,
        fired_at: new Date(now).toISOString(),
      });
      alertsRaised++;
      await recordEvent({ kind: "pipeline.stuck", org_id: org.id, message: parts.join(", "), data: { stuck: h.stuck_scans.length, undelivered: h.undelivered_webhooks.length } });
    } catch (err) {
      logger.error("Pipeline health check failed for org", { org_id: org.id, detail: err instanceof Error ? err.message : String(err) });
    }
  }

  const cutoff = new Date(now - RETENTION_DAYS * 86400_000).toISOString();
  const { error: purgeErr } = await db.from("ops_events").delete().lt("created_at", cutoff);

  logger.info("Pipeline health check finished", { orgs: orgs?.length ?? 0, alerts_raised: alertsRaised, purged_before: cutoff, purge_error: purgeErr?.message });
  return NextResponse.json({ ok: true, orgs: orgs?.length ?? 0, alerts_raised: alertsRaised });
}
