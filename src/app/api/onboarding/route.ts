/**
 * GET  /api/onboarding  → { complete: boolean, org_name: string }
 * POST /api/onboarding  → actions:
 *   { action: "complete" }                          → marks org onboarding_complete = true
 *   { action: "save_github_login", github_login }   → updates caller's org_members.github_login
 *   { action: "save_github_org",   github_org }     → updates organizations.github_org
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey, requireRole } from "../_middleware";

export async function GET(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });

  const db = createServiceClient();
  const { data: org } = await db
    .from("organizations")
    .select("name, onboarding_complete")
    .eq("id", auth.org_id)
    .single();

  return NextResponse.json({
    complete: org?.onboarding_complete ?? false,
    org_name: org?.name ?? "",
  });
}

export async function POST(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });

  let body: { action?: string; github_login?: string; github_org?: string };
  try { body = await req.json(); }
  catch { return NextResponse.json({ error: "invalid_json" }, { status: 400 }); }

  const db = createServiceClient();

  if (body.action === "complete") {
    const roleErr = requireRole(auth, "admin");
    if (roleErr) return NextResponse.json({ error: roleErr }, { status: 403 });

    await db
      .from("organizations")
      .update({ onboarding_complete: true })
      .eq("id", auth.org_id);

    return NextResponse.json({ ok: true });
  }

  if (body.action === "save_github_login") {
    const login = body.github_login?.trim();
    if (!login) return NextResponse.json({ error: "github_login_required" }, { status: 400 });

    await db
      .from("org_members")
      .update({ github_login: login })
      .eq("org_id", auth.org_id)
      .eq("user_id", auth.user_id!);

    return NextResponse.json({ ok: true });
  }

  if (body.action === "save_github_org") {
    const roleErr = requireRole(auth, "admin");
    if (roleErr) return NextResponse.json({ error: roleErr }, { status: 403 });

    const handle = body.github_org?.trim();
    if (!handle) return NextResponse.json({ error: "github_org_required" }, { status: 400 });

    await db
      .from("organizations")
      .update({ github_org: handle })
      .eq("id", auth.org_id);

    return NextResponse.json({ ok: true });
  }

  return NextResponse.json({ error: "unknown_action" }, { status: 400 });
}
