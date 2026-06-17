/**
 * POST /api/orgs/create
 * Creates a brand-new organisation and sets the caller as its admin.
 * Does NOT require an existing org_members record — uses verifyJWT instead
 * of verifyApiKey so users with no org can call it.
 *
 * Body: { name: string; slug: string; github_org?: string }
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyJWT } from "../../_middleware";

export async function POST(req: NextRequest) {
  const auth = await verifyJWT(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });

  let body: { name?: string; slug?: string; github_org?: string };
  try { body = await req.json(); }
  catch { return NextResponse.json({ error: "invalid_json" }, { status: 400 }); }

  const name       = body.name?.trim();
  const slug       = body.slug?.trim().toLowerCase().replace(/[^a-z0-9-]/g, "-");
  const github_org = body.github_org?.trim() || null;

  if (!name || !slug) {
    return NextResponse.json({ error: "name_and_slug_required" }, { status: 400 });
  }

  const db = createServiceClient();

  // Ensure user doesn't already belong to an org
  const { data: existing } = await db
    .from("org_members")
    .select("org_id")
    .eq("user_id", auth.user_id)
    .maybeSingle();

  if (existing) {
    return NextResponse.json({ error: "already_in_org", org_id: existing.org_id }, { status: 409 });
  }

  // Slug must be unique
  const { data: slugTaken } = await db
    .from("organizations")
    .select("id")
    .eq("slug", slug)
    .maybeSingle();

  if (slugTaken) {
    return NextResponse.json({ error: "slug_taken" }, { status: 409 });
  }

  // Create org
  const { data: org, error: orgErr } = await db
    .from("organizations")
    .insert({ slug, name, github_org, onboarding_complete: false, plan: "trial" })
    .select("id, slug, name")
    .single();

  if (orgErr || !org) {
    return NextResponse.json({ error: "org_create_failed", detail: orgErr?.message }, { status: 500 });
  }

  // Create admin member
  const { error: memberErr } = await db
    .from("org_members")
    .insert({
      org_id:   org.id,
      user_id:  auth.user_id,
      email:    auth.email,
      role:     "admin",
    });

  if (memberErr) {
    // Rollback org
    await db.from("organizations").delete().eq("id", org.id);
    return NextResponse.json({ error: "member_create_failed", detail: memberErr.message }, { status: 500 });
  }

  return NextResponse.json({ org_id: org.id, slug: org.slug, name: org.name }, { status: 201 });
}
