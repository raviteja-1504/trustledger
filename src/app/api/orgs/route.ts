/**
 * Multi-Org MSP API
 * Allows platform admins and MSP users to manage multiple client orgs.
 * A user with role="platform_admin" can see all orgs; others see only their own.
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey } from "../_middleware";

export async function GET(req: NextRequest) {
  const { org_id, user_id, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  const db = createServiceClient();

  // Check if user is a platform admin (can see all orgs)
  const { data: membership } = await db
    .from("org_members")
    .select("role")
    .eq("user_id", user_id ?? "")
    .eq("org_id", org_id)
    .single() as { data: { role: string } | null };

  const isPlatformAdmin = membership?.role === "platform_admin";

  if (!isPlatformAdmin) {
    // Regular users see only their own org
    const { data: org } = await db
      .from("organizations")
      .select("id, slug, name, github_org, plan, created_at")
      .eq("id", org_id)
      .single() as { data: Record<string, unknown> | null };

    return NextResponse.json({ orgs: org ? [org] : [] });
  }

  // Platform admins see all orgs with health metrics
  const { data: orgs } = await db
    .from("organizations")
    .select("id, slug, name, github_org, plan, created_at")
    .order("created_at", { ascending: false }) as { data: Record<string, unknown>[] | null };

  if (!orgs) return NextResponse.json({ orgs: [] });

  // Enrich with recent scan + violation counts
  const enriched = await Promise.all(
    orgs.map(async org => {
      const orgId = org.id as string;

      const [{ count: scans }, { count: openViolations }, { count: members }] = await Promise.all([
        db.from("scans").select("*", { count:"exact", head:true }).eq("org_id", orgId)
          .gte("created_at", new Date(Date.now() - 30*86400_000).toISOString()),
        db.from("violations").select("*", { count:"exact", head:true }).eq("org_id", orgId).in("status", ["open","in_review"]),
        db.from("org_members").select("*", { count:"exact", head:true }).eq("org_id", orgId),
      ]);

      const { data: latestScan } = await db
        .from("scans")
        .select("overall_risk, total_ai_percentage, created_at")
        .eq("org_id", orgId)
        .order("created_at", { ascending: false })
        .limit(1)
        .single() as { data: { overall_risk: string; total_ai_percentage: number; created_at: string } | null };

      return {
        ...org,
        scans_30d:        scans ?? 0,
        open_violations:  openViolations ?? 0,
        member_count:     members ?? 0,
        latest_risk:      latestScan?.overall_risk ?? "UNKNOWN",
        latest_ai_pct:    latestScan?.total_ai_percentage ?? 0,
        last_scan:        latestScan?.created_at ?? null,
      };
    }),
  );

  return NextResponse.json({ orgs: enriched });
}

export async function POST(req: NextRequest) {
  const { user_id, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  const body = await req.json() as { slug: string; name: string; github_org?: string; plan?: string };
  if (!body.slug || !body.name) return NextResponse.json({ error: "missing_fields" }, { status: 400 });

  const db = createServiceClient();

  const { data: org, error: insErr } = await db
    .from("organizations")
    .insert({ slug: body.slug, name: body.name, github_org: body.github_org ?? null, plan: body.plan ?? "starter" })
    .select("id, slug, name")
    .single() as { data: { id: string; slug: string; name: string } | null; error: unknown };

  if (insErr || !org) return NextResponse.json({ error: "create_failed" }, { status: 500 });

  // Add creating user as admin of new org
  if (user_id) {
    const { data: member } = await db
      .from("org_members")
      .select("email")
      .eq("user_id", user_id)
      .limit(1)
      .single() as { data: { email: string } | null };

    await db.from("org_members").insert({
      org_id:  org.id,
      user_id: user_id,
      email:   member?.email ?? "",
      role:    "admin",
    });
  }

  return NextResponse.json({ org });
}
