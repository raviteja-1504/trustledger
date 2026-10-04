import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey } from "../_middleware";
import { cached, cacheDel, cacheKeys, TTL } from "@/lib/cache";
import { fetchDashboard, type DashboardPeriod } from "@/lib/dashboardAggregate";

const DEVELOPER_DASHBOARD_TTL = 60;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;

/**
 * GET /api/dashboard?days=7|30|90            → the last N days
 * GET /api/dashboard?start_date=&end_date=   → a custom range (YYYY-MM-DD, inclusive). This used to be ignored, so a
 *                                               custom range silently showed the default 90 days.
 */
export async function GET(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });

  const params   = req.nextUrl.searchParams;
  const noCache  = params.get("nocache") === "1";
  const start    = params.get("start_date");
  const end      = params.get("end_date");
  let period: DashboardPeriod | undefined;
  if (start || end) {
    if (!start || !end || !DATE_RE.test(start) || !DATE_RE.test(end) || isNaN(Date.parse(start)) || isNaN(Date.parse(end)) || start > end) {
      return NextResponse.json({ error: "invalid_date_range", message: "Use start_date and end_date as YYYY-MM-DD, with start on or before end." }, { status: 400 });
    }
    period = { start, end };
  }
  const days = period
    ? Math.max(1, Math.round((Date.parse(period.end) - Date.parse(period.start)) / 86400_000) + 1)
    : Math.min(365, Math.max(1, parseInt(params.get("days") ?? "90") || 90));
  const { org_id, role, user_id } = auth;

  // Developers get a personal view scoped to their own PRs -- cached per developer (keyed by their GitHub
  // login, which is what scopes the view), briefly: every page polls this, and running the full aggregate
  // for each poll of each developer was a steady source of database egress.
  if (role === "developer") {
    const db = createServiceClient();
    let githubLogin: string | null = null;
    if (user_id) {
      const { data: member } = await db
        .from("org_members")
        .select("github_login")
        .eq("user_id", user_id)
        .single();
      githubLogin = member?.github_login ?? null;
    }
    const devKey = `${cacheKeys.dashboard(org_id, days)}:dev:${githubLogin ?? `user:${user_id ?? "-"}`}`;
    const result = noCache || period
      ? await fetchDashboard(org_id, days, githubLogin, period)
      : await cached(devKey, DEVELOPER_DASHBOARD_TTL, () => fetchDashboard(org_id, days, githubLogin));
    return NextResponse.json({ ...result, _scope: "developer" });
  }

  // Custom ranges aren't cached: the cache is keyed (and invalidated) per 7/30/90-day window.
  if (period) {
    return NextResponse.json(await fetchDashboard(org_id, days, null, period), { headers: { "X-Cache": "BYPASS" } });
  }

  // Admin / security_reviewer — org-wide, cacheable
  const cacheKey = cacheKeys.dashboard(org_id, days);
  if (!noCache) {
    const hit = await cached(cacheKey, TTL.DASHBOARD, () => fetchDashboard(org_id, days, null));
    return NextResponse.json(hit, {
      headers: { "X-Cache": "HIT", "Cache-Control": `s-maxage=${TTL.DASHBOARD}` },
    });
  }
  // Fetch fresh data, then DELETE the stale cache entry so all subsequent
  // regular calls (violations page 30s poll, other pages) also get fresh
  // data instead of the old truncated result.
  const result = await fetchDashboard(org_id, days, null);
  await Promise.all([7, 30, 90].map(d => cacheDel(cacheKeys.dashboard(org_id, d))));
  return NextResponse.json(result, {
    headers: { "X-Cache": "MISS", "Cache-Control": `s-maxage=${TTL.DASHBOARD}` },
  });
}
