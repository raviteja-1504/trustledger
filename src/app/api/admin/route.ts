/**
 * Platform Admin Analytics API
 * Returns aggregate metrics across ALL orgs for platform admins.
 * Only accessible to users with role="platform_admin" in any org.
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey } from "../_middleware";

export async function GET(req: NextRequest) {
  const { user_id, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  const db = createServiceClient();

  // Verify platform admin role
  const { data: membership } = await db
    .from("org_members")
    .select("role")
    .eq("user_id", user_id ?? "")
    .eq("role", "platform_admin")
    .limit(1)
    .single() as { data: { role: string } | null };

  if (!membership) return NextResponse.json({ error:"forbidden" }, { status:403 });

  const since30d = new Date(Date.now() - 30 * 86400_000).toISOString();
  const since7d  = new Date(Date.now() - 7  * 86400_000).toISOString();

  const [
    { count: totalOrgs },
    { count: activeOrgs30d },
    { count: totalScans30d },
    { count: totalAttestations30d },
    { count: totalViolations },
    { count: totalUsers },
    { data: planBreakdown },
  ] = await Promise.all([
    db.from("organizations").select("*", { count:"exact", head:true }),
    db.from("scans").select("org_id", { count:"exact", head:true }).gte("created_at", since30d),
    db.from("scans").select("*", { count:"exact", head:true }).gte("created_at", since30d),
    db.from("attestations").select("*", { count:"exact", head:true }).gte("created_at", since30d),
    db.from("violations").select("*", { count:"exact", head:true }).in("status", ["open","in_review"]),
    db.from("org_members").select("*", { count:"exact", head:true }),
    db.from("organizations").select("plan"),
  ]);

  // Plan distribution
  const plans: Record<string, number> = {};
  (planBreakdown ?? []).forEach((org: { plan: string }) => {
    plans[org.plan] = (plans[org.plan] ?? 0) + 1;
  });

  // Recent scans timeline (last 7 days by day)
  const { data: recentScans } = await db
    .from("scans")
    .select("created_at, overall_risk")
    .gte("created_at", since7d)
    .order("created_at") as { data: Array<{ created_at: string; overall_risk: string }> | null };

  const byDay: Record<string, { total: number; critical: number }> = {};
  (recentScans ?? []).forEach(s => {
    const day = s.created_at.slice(0, 10);
    if (!byDay[day]) byDay[day] = { total: 0, critical: 0 };
    byDay[day].total++;
    if (s.overall_risk === "CRITICAL") byDay[day].critical++;
  });

  // Top 10 most active orgs
  const { data: topOrgs } = await db
    .from("scans")
    .select("org_id")
    .gte("created_at", since30d) as { data: Array<{ org_id: string }> | null };

  const orgActivity: Record<string, number> = {};
  (topOrgs ?? []).forEach(s => { orgActivity[s.org_id] = (orgActivity[s.org_id] ?? 0) + 1; });
  const topActive = Object.entries(orgActivity)
    .sort(([,a],[,b]) => b - a)
    .slice(0, 10)
    .map(([org_id, scans]) => ({ org_id, scans }));

  return NextResponse.json({
    summary: {
      total_orgs:               totalOrgs ?? 0,
      active_orgs_30d:          activeOrgs30d ?? 0,
      total_scans_30d:          totalScans30d ?? 0,
      total_attestations_30d:   totalAttestations30d ?? 0,
      open_violations:          totalViolations ?? 0,
      total_users:              totalUsers ?? 0,
    },
    plan_distribution: plans,
    scans_by_day:      byDay,
    top_active_orgs:   topActive,
    generated_at:      new Date().toISOString(),
  });
}
