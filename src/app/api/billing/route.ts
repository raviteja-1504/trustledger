import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey } from "../_middleware";

const PLAN_LIMITS: Record<string, { scans: number; attestations: number; repos: number; members: number; reports: number; price: number }> = {
  trial:      { scans:    100, attestations:   500, repos:  3, members:  3, reports:  5,  price:    0 },
  starter:    { scans:  1_000, attestations: 5_000, repos: 10, members:  5, reports: 12,  price:  299 },
  growth:     { scans: 10_000, attestations:50_000, repos: 50, members: 20, reports: 60,  price:  999 },
  enterprise: { scans:     -1, attestations:    -1, repos: -1, members: -1, reports: -1,  price:    0 }, // unlimited
};

export async function GET(req: NextRequest) {
  const { org_id, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  const db = createServiceClient();

  const { data: org } = await db
    .from("organizations")
    .select("name, plan, created_at")
    .eq("id", org_id)
    .single() as { data: { name: string; plan: string; created_at: string } | null };

  if (!org) return NextResponse.json({ error: "org_not_found" }, { status: 404 });

  // Current period: start of current calendar month
  const now         = new Date();
  const periodStart = new Date(now.getFullYear(), now.getMonth(), 1).toISOString();
  const periodEnd   = now.toISOString();

  const [
    { count: scansThisMonth },
    { count: attestationsThisMonth },
    { count: repoCount },
    { count: memberCount },
    { count: reportsThisMonth },
    { count: scansAllTime },
    { count: attestationsAllTime },
  ] = await Promise.all([
    db.from("scans").select("*",        { count:"exact", head:true }).eq("org_id", org_id).gte("created_at", periodStart),
    db.from("attestations").select("*", { count:"exact", head:true }).eq("org_id", org_id).gte("created_at", periodStart),
    db.from("repositories").select("*", { count:"exact", head:true }).eq("org_id", org_id).eq("is_active", true),
    db.from("org_members").select("*",  { count:"exact", head:true }).eq("org_id", org_id),
    db.from("audit_log").select("*",    { count:"exact", head:true }).eq("org_id", org_id).eq("event_type", "report_generated").gte("created_at", periodStart),
    db.from("scans").select("*",        { count:"exact", head:true }).eq("org_id", org_id),
    db.from("attestations").select("*", { count:"exact", head:true }).eq("org_id", org_id),
  ]);

  const limits = PLAN_LIMITS[org.plan] ?? PLAN_LIMITS.trial;

  return NextResponse.json({
    org:    { name: org.name, plan: org.plan, member_since: org.created_at },
    limits,
    usage: {
      scans_this_month:        scansThisMonth ?? 0,
      attestations_this_month: attestationsThisMonth ?? 0,
      repos_active:            repoCount ?? 0,
      members:                 memberCount ?? 0,
      reports_this_month:      reportsThisMonth ?? 0,
      scans_all_time:          scansAllTime ?? 0,
      attestations_all_time:   attestationsAllTime ?? 0,
    },
    period: { start: periodStart, end: periodEnd },
  });
}
