/**
 * Multi-Org MSP API
 * Allows platform admins and MSP users to manage multiple client orgs.
 * A user with role="platform_admin" can see all orgs; others see only their own.
 * Every organisation comes back with the same health metrics (see lib/orgSummary.ts for how the page reads them).
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey, requirePlatformAdmin } from "../_middleware";
import { CAPS } from "@/lib/limits";
import { measureAll, orgMetrics, type OrgRow } from "@/lib/orgMetrics";

export async function GET(req: NextRequest) {
  const { org_id, user_id, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  const db = createServiceClient();
  const now = new Date();

  const { data: membership } = await db
    .from("org_members")
    .select("role")
    .eq("user_id", user_id ?? "")
    .eq("org_id", org_id)
    .single() as { data: { role: string } | null };
  const isPlatformAdmin = membership?.role === "platform_admin";

  const cols = "id, slug, name, github_org, plan, created_at";
  if (!isPlatformAdmin) {
    // Everyone else sees their own organisation -- with its numbers, like the platform admin's list
    const { data: org } = await db.from("organizations").select(cols).eq("id", org_id).single() as { data: OrgRow | null };
    if (!org) return NextResponse.json({ orgs: [], total: 0, current_org_id: org_id });
    return NextResponse.json({ orgs: [{ ...await orgMetrics(db, org, now), is_current: true }], total: 1, current_org_id: org_id });
  }

  // Platform admins see every organisation, newest first, up to the cap
  const { data: orgs, count } = await db
    .from("organizations")
    .select(cols, { count: "exact" })
    .order("created_at", { ascending: false })
    .limit(CAPS.orgsListed.value) as { data: OrgRow[] | null; count: number | null };
  if (!orgs) return NextResponse.json({ orgs: [], total: 0, current_org_id: org_id });

  const measured = await measureAll(db, orgs, now);
  return NextResponse.json({ orgs: measured.map(o => ({ ...o, is_current: o.id === org_id })), total: count ?? orgs.length, current_org_id: org_id });
}

export async function POST(req: NextRequest) {
  const auth = await verifyApiKey(req);
  const { user_id, error } = auth;
  if (error) return NextResponse.json({ error }, { status: 401 });
  // Creating client orgs is the MSP / platform-admin feature. For anyone else it would hand out an admin seat
  // (and any plan) in a fresh org -- and a second membership breaks their sign-in, which expects one.
  const adminErr = requirePlatformAdmin(auth);
  if (adminErr) return NextResponse.json({ error: adminErr }, { status: 403 });

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
