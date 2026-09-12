import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey } from "../_middleware";
import { cached, cacheDel, cacheKeys, TTL } from "@/lib/cache";
import { fetchDashboard } from "@/lib/dashboardAggregate";

export async function GET(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });

  const url      = new URL(req.url);
  const days     = parseInt(url.searchParams.get("days") ?? "90");
  const noCache  = url.searchParams.get("nocache") === "1";
  const { org_id, role, user_id } = auth;

  // Developers get a personal view scoped to their own PRs — never cached
  // because it is user-specific (cache key would need user_id).
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
    const result = await fetchDashboard(org_id, days, githubLogin);
    return NextResponse.json({ ...result, _scope: "developer" });
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
