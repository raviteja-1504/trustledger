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

const PLAN_LIMITS: Record<string, {
  scans:        number;
  attestations: number;
  repos:        number;
  members:      number;
  api_calls:    number;
  storage_mb:   number;
}> = {
  trial:      { scans:100,    attestations:500,   repos:3,  members:3,  api_calls:1000,  storage_mb:100   },
  starter:    { scans:1000,   attestations:5000,  repos:10, members:5,  api_calls:10000, storage_mb:1000  },
  growth:     { scans:10000,  attestations:50000, repos:50, members:20, api_calls:100000,storage_mb:10000 },
  enterprise: { scans:-1,     attestations:-1,    repos:-1, members:-1, api_calls:-1,    storage_mb:-1    },
};

function usagePct(used: number, limit: number): number {
  if (limit < 0) return 0; // unlimited
  return Math.min(100, Math.round((used / limit) * 100));
}

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
    const limits = PLAN_LIMITS[plan] ?? PLAN_LIMITS.trial;

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
      scans:        usagePct(usage.scans_this_month,        limits.scans),
      attestations: usagePct(usage.attestations_this_month, limits.attestations),
      repos:        usagePct(usage.repos_active,             limits.repos),
      members:      usagePct(usage.members,                  limits.members),
    };

    const warnings = Object.entries(percentages)
      .filter(([, pct]) => pct >= 80)
      .map(([key, pct]) => ({ metric: key, percentage: pct }));

    return { plan, limits, usage, percentages, warnings, period_days: days, generated_at: new Date().toISOString() };
  });

  return NextResponse.json(data);
}
