/**
 * SLA Breach Cron Job — runs every 15 minutes via Vercel Cron.
 * Add to vercel.json crons: path=/api/cron/sla, schedule= every 15 minutes
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { checkSLABreaches } from "@/lib/slaMonitor";
import { cronAuthorized } from "@/lib/cronAuth";

export async function GET(req: NextRequest) {
  // Protect with the cron secret; with no CRON_SECRET configured nobody is let in
  if (!cronAuthorized(req)) return NextResponse.json({ error: "unauthorized" }, { status: 401 });

  const db = createServiceClient();
  const result = await checkSLABreaches(db);

  return NextResponse.json({
    ok:       true,
    breaches: result.breaches,
    ran_at:   new Date().toISOString(),
  });
}
