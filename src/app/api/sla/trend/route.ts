/**
 * SLA historical trend — GET /api/sla/trend?weeks=12
 *
 * The SLA Dashboard previously showed only a current-snapshot view
 * ("what's overdue right now"). This calls get_sla_trend() (see migration
 * 20260916_sla_trend_rpc.sql) for a real weekly breach-count and MTTR
 * (mean time to resolve) trend, computed server-side from alerts.fired_at
 * (when each breach was first flagged) and violations.resolved_at.
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey } from "../../_middleware";
import { safeError } from "@/lib/errors";

interface TrendRow { week_start: string; breaches: number; avg_resolve_hours: number | null }

export async function GET(req: NextRequest) {
  const { org_id, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  const weeksParam = new URL(req.url).searchParams.get("weeks");
  const weeks = Math.min(52, Math.max(1, parseInt(weeksParam ?? "12", 10) || 12));

  const db = createServiceClient();
  const { data, error: rpcErr } = await db
    .rpc("get_sla_trend", { p_org_id: org_id, p_weeks: weeks }) as { data: TrendRow[] | null; error: unknown };

  if (rpcErr) return safeError(rpcErr, { code: "sla_trend_failed", message: "We couldn't load the SLA trend right now. Please try again." });

  return NextResponse.json({
    trend: (data ?? []).map(r => ({
      date: r.week_start,
      breaches: r.breaches,
      avg_resolve_hours: r.avg_resolve_hours,
    })),
  });
}
