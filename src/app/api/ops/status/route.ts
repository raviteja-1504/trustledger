/**
 * GET /api/ops/status -- the platform's own health for an uptime monitor.
 *
 * Authorization: Bearer <CRON_SECRET> (the operator's secret; never a customer credential). 200 when every check passes, 503 when any
 * fails, so a plain HTTP monitor (UptimeRobot, Better Stack, a GitHub Actions job) alerts on the status code alone. The body says
 * which check failed and what it measured. Counts and opaque organisation ids only (lib/opsStatus.ts). Nothing is scheduled here.
 */
import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { cronAuthorized } from "@/lib/cronAuth";
import { opsStatus } from "@/lib/opsStatus";

export const dynamic = "force-dynamic";

const NO_STORE = { "Cache-Control": "no-store" };
const down = (note: string) => NextResponse.json({ status: "degraded", checks: [{ name: "database", ok: false, value: null, note }] }, { status: 503, headers: NO_STORE });

export async function GET(req: NextRequest) {
  if (!cronAuthorized(req)) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  let db;
  try { db = createServiceClient(); } catch { return down("The database is not configured"); }
  try {
    const status = await opsStatus(db);
    return NextResponse.json(status, { status: status.status === "ok" ? 200 : 503, headers: NO_STORE });
  } catch {
    return down("The status check itself failed");
  }
}
