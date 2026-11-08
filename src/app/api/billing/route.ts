import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey } from "../_middleware";
import { planLimits } from "@/lib/limits";


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

  const limits = planLimits(org.plan);

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
