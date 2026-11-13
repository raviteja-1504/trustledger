/**
 * GET  /api/onboarding  → { complete: boolean, org_name: string, github_org: string | null, members: number, has_scans: boolean }
 * POST /api/onboarding  → actions:
 *   { action: "complete" }                          → marks org onboarding_complete = true
 *   { action: "save_github_login", github_login }   → updates caller's org_members.github_login
 *   { action: "save_github_org",   github_org }     → updates organizations.github_org
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey, requireRole } from "../_middleware";
import { normalizeGithubHandle, escapeLike } from "@/lib/githubHandle";

export async function GET(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });

  const db = createServiceClient();
  const { data: org } = await db
    .from("organizations")
    .select("name, onboarding_complete, github_org")
    .eq("id", auth.org_id)
    .single();

  // Whether this organisation is already running: AuthGuard sends only a brand-new one (its creator, alone, nothing
  // scanned) to the setup wizard, and leaves an admin who joined an existing organisation alone.
  const [members, scans] = await Promise.all([
    db.from("org_members").select("id", { count: "exact", head: true }).eq("org_id", auth.org_id),
    db.from("scans").select("id", { count: "exact", head: true }).eq("org_id", auth.org_id),
  ]);

  return NextResponse.json({
    complete: org?.onboarding_complete ?? false,
    org_name: org?.name ?? "",
    // the handle saved today (not the organisation's slug): the setup wizard shows it and pre-fills with it
    github_org: (org as { github_org?: string | null } | null)?.github_org ?? null,
    members: members.count ?? 0,
    has_scans: (scans.count ?? 0) > 0,
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

    // What was typed is cleaned up (a pasted repository URL, an @) and checked: only an owner name is saved
    const parsed = normalizeGithubHandle(body.github_org ?? "");
    if (!parsed.ok) return NextResponse.json({ error: parsed.problem === "empty" ? "github_org_required" : "github_org_invalid", message: parsed.message }, { status: 400 });
    const handle = parsed.handle;

    // A GitHub organisation belongs to one TrustLedger organisation (its pull requests are routed by this handle): refuse a
    // handle another organisation already holds, instead of failing quietly.
    // case-insensitive: GitHub names are, and a handle saved as "Acme-Corp" earlier still counts as held
    const { data: holder } = await db.from("organizations").select("id").ilike("github_org", escapeLike(handle)).neq("id", auth.org_id).limit(1).maybeSingle();
    if (holder) return NextResponse.json({ error: "github_org_taken" }, { status: 409 });

    const { error: updErr } = await db
      .from("organizations")
      .update({ github_org: handle })
      .eq("id", auth.org_id);
    if (updErr) return NextResponse.json({ error: (updErr as { code?: string }).code === "23505" ? "github_org_taken" : "save_failed" }, { status: (updErr as { code?: string }).code === "23505" ? 409 : 500 });

    return NextResponse.json({ ok: true });
  }

  return NextResponse.json({ error: "unknown_action" }, { status: 400 });
}
