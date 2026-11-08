/**
 * API Usage Dashboard
 * Returns current period usage vs plan limits.
 * Useful for showing usage meters in the billing page and settings.
 *
 * GET /api/usage → current month usage
 * GET /api/usage?days=30 → last N days usage
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey } from "../_middleware";
import { cached, TTL } from "@/lib/cache";
import { planLimits, limitStatus } from "@/lib/limits";



export async function GET(req: NextRequest) {
  const { org_id, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  const url  = new URL(req.url);
  const days = parseInt(url.searchParams.get("days") ?? "30");

  const cacheKey = `usage:${org_id}:${days}`;

  const data = await cached(cacheKey, 300, async () => {
    const db       = createServiceClient();
    const since    = new Date(Date.now() - days * 86400_000).toISOString();
    const monthStart = new Date(new Date().getFullYear(), new Date().getMonth(), 1).toISOString();

    const { data: org } = await db
      .from("organizations")
      .select("plan")
      .eq("id", org_id)
      .single() as { data: { plan: string } | null };

    const plan   = org?.plan ?? "trial";
    const limits = planLimits(plan);

    const [
      { count: scansMonth },
      { count: scansTotal },
      { count: attestMonth },
      { count: attestTotal },
      { count: repoCount },
      { count: memberCount },
    ] = await Promise.all([
      db.from("scans").select("*",{count:"exact",head:true}).eq("org_id",org_id).gte("created_at",monthStart),
      db.from("scans").select("*",{count:"exact",head:true}).eq("org_id",org_id).gte("created_at",since),
      db.from("attestations").select("*",{count:"exact",head:true}).eq("org_id",org_id).gte("created_at",monthStart),
      db.from("attestations").select("*",{count:"exact",head:true}).eq("org_id",org_id).gte("created_at",since),
      db.from("repositories").select("*",{count:"exact",head:true}).eq("org_id",org_id).eq("is_active",true),
      db.from("org_members").select("*",{count:"exact",head:true}).eq("org_id",org_id),
    ]);

    const usage = {
      scans_this_month:        scansMonth  ?? 0,
      scans_period:            scansTotal  ?? 0,
      attestations_this_month: attestMonth ?? 0,
      attestations_period:     attestTotal ?? 0,
      repos_active:            repoCount   ?? 0,
      members:                 memberCount ?? 0,
    };

    const percentages = {
      scans:        limitStatus(usage.scans_this_month, limits.scans).pct,
      attestations: limitStatus(usage.attestations_this_month, limits.attestations).pct,
      repos:        limitStatus(usage.repos_active, limits.repos).pct,
      members:      limitStatus(usage.members, limits.members).pct,
    };

    const warnings = Object.entries(percentages)
      .filter(([, pct]) => pct >= 80)
      .map(([key, pct]) => ({ metric: key, percentage: pct }));

    return { plan, limits, usage, percentages, warnings, period_days: days, generated_at: new Date().toISOString() };
  });

  return NextResponse.json(data);
}
