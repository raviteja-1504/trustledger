import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey } from "../_middleware";
import { cached, cacheDel, cacheKeys, TTL } from "@/lib/cache";
import { fetchDashboard, type DashboardPeriod } from "@/lib/dashboardAggregate";

const DEVELOPER_DASHBOARD_TTL = 60;
// Per-org data behind auth: never storable by a shared cache (the URL is the same for every org, so an edge copy
// could be served to the wrong org, and it outlived the server-side invalidation on attestation). The server-side
// cache (lib/cache, invalidated when a file is attested) is what absorbs repeated loads.
const NO_SHARED_CACHE = "private, no-store";

/**
 * The org's data version: when it last attested, scanned or changed a violation's status. It is part of every cache
 * key, so a copy computed before the change is never served again -- on any server instance. (Deleting keys on
 * attestation wasn't enough: without Redis each instance has its own in-memory cache, and a request in flight during
 * the attestation could write the old numbers back right after the delete.) Null if it can't be read: don't cache.
 */
async function dataVersion(orgId: string): Promise<string | null> {
  const db = createServiceClient();
  const latest = (table: string, column: string) =>
    db.from(table).select(column).eq("org_id", orgId).order(column, { ascending: false }).limit(1).maybeSingle() as unknown as
      Promise<{ data: Record<string, string> | null; error: unknown }>;
  try {
    const rows = await Promise.all([latest("attestations", "created_at"), latest("scans", "created_at"), latest("violation_overrides", "updated_at")]);
    // A table that doesn't exist yet (older database) just contributes nothing; any other error means "unknown".
    if (rows.slice(0, 2).some(r => r.error)) return null;
    return [rows[0].data?.created_at, rows[1].data?.created_at, rows[2].error ? "" : rows[2].data?.updated_at].map(v => v ?? "").join("|");
  } catch { return null; }
}
const versioned = (key: string, version: string) => `${key}:v:${version}`;
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
    const version = noCache || period ? null : await dataVersion(org_id);
    const result = version == null
      ? await fetchDashboard(org_id, days, githubLogin, period)
      : await cached(versioned(devKey, version), DEVELOPER_DASHBOARD_TTL, () => fetchDashboard(org_id, days, githubLogin));
    return NextResponse.json({ ...result, _scope: "developer" }, { headers: { "Cache-Control": NO_SHARED_CACHE } });
  }

  // Custom ranges aren't cached: the cache is keyed (and invalidated) per 7/30/90-day window.
  if (period) {
    return NextResponse.json(await fetchDashboard(org_id, days, null, period), { headers: { "X-Cache": "BYPASS", "Cache-Control": NO_SHARED_CACHE } });
  }

  // Admin / security_reviewer — org-wide, cacheable
  const cacheKey = cacheKeys.dashboard(org_id, days);
  const version = noCache ? null : await dataVersion(org_id);
  if (version != null) {
    const hit = await cached(versioned(cacheKey, version), TTL.DASHBOARD, () => fetchDashboard(org_id, days, null));
    return NextResponse.json(hit, { headers: { "X-Cache": "HIT", "Cache-Control": NO_SHARED_CACHE } });
  }
  // Fetch fresh data, then DELETE the stale cache entry so all subsequent
  // regular calls (violations page 30s poll, other pages) also get fresh
  // data instead of the old truncated result.
  const result = await fetchDashboard(org_id, days, null);
  await Promise.all([7, 30, 90].map(d => cacheDel(cacheKeys.dashboard(org_id, d))));
  return NextResponse.json(result, { headers: { "X-Cache": "MISS", "Cache-Control": NO_SHARED_CACHE } });
}
