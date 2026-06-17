/**
 * Team Management API
 *
 * GET  /api/team              → list all members of the caller's org
 * POST /api/team              → invite a new member by email  (admin only)
 * PATCH /api/team             → change a member's role        (admin only)
 * DELETE /api/team?user_id=x  → remove a member               (admin only)
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey, requireRole } from "../_middleware";
import { writeAuditLog } from "@/lib/audit";

const VALID_ROLES = ["developer", "security_reviewer", "admin"] as const;
type MemberRole = typeof VALID_ROLES[number];

// ── GET — list members (any authenticated member of the org) ──────────────────
export async function GET(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });

  const db = createServiceClient();
  const { data: members } = await db
    .from("org_members")
    .select("id, user_id, email, name, role, github_login, avatar_url, created_at")
    .eq("org_id", auth.org_id)
    .order("created_at", { ascending: true });

  return NextResponse.json({ members: members ?? [] });
}

// ── POST — invite by email ─────────────────────────────────────────────────────
export async function POST(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });
  const roleErr = requireRole(auth, "admin");
  if (roleErr) return NextResponse.json({ error: roleErr }, { status: 403 });

  let body: { email?: string; role?: string; name?: string };
  try { body = await req.json(); } catch { return NextResponse.json({ error: "invalid_json" }, { status: 400 }); }

  const email = body.email?.toLowerCase().trim();
  const role  = body.role as MemberRole | undefined;
  const name  = body.name?.trim() ?? null;

  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return NextResponse.json({ error: "invalid_email" }, { status: 400 });
  }
  if (!role || !VALID_ROLES.includes(role)) {
    return NextResponse.json({ error: "invalid_role", valid: VALID_ROLES }, { status: 400 });
  }

  const db = createServiceClient();

  // Check for duplicate
  const { data: existing } = await db
    .from("org_members")
    .select("id")
    .eq("org_id", auth.org_id)
    .eq("email", email)
    .maybeSingle();

  if (existing) return NextResponse.json({ error: "already_member" }, { status: 409 });

  // Try to find an existing Supabase user by email
  const { data: { users } } = await db.auth.admin.listUsers();
  const existingUser = users.find(u => u.email === email);

  const { data: member, error: insertErr } = await db
    .from("org_members")
    .insert({
      org_id:       auth.org_id,
      user_id:      existingUser?.id ?? null,
      email,
      name,
      role,
      invited_by:   auth.user_id ?? null,
    })
    .select("id, email, name, role, created_at")
    .single();

  if (insertErr || !member) {
    return NextResponse.json({ error: "invite_failed", detail: insertErr?.message }, { status: 500 });
  }

  await writeAuditLog(db, {
    org_id:        auth.org_id,
    event_type:    "member_invited",
    actor_id:      auth.user_id ?? null,
    actor_email:   auth.actor_email ?? "unknown",
    resource_type: "org_member",
    resource_id:   member.id,
    payload:       { email, role },
  });

  return NextResponse.json({ member }, { status: 201 });
}

// ── PATCH — change role ────────────────────────────────────────────────────────
export async function PATCH(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });
  const roleErr = requireRole(auth, "admin");
  if (roleErr) return NextResponse.json({ error: roleErr }, { status: 403 });

  let body: { user_id?: string; role?: string };
  try { body = await req.json(); } catch { return NextResponse.json({ error: "invalid_json" }, { status: 400 }); }

  if (!body.user_id) return NextResponse.json({ error: "user_id_required" }, { status: 400 });
  if (!body.role || !VALID_ROLES.includes(body.role as MemberRole)) {
    return NextResponse.json({ error: "invalid_role", valid: VALID_ROLES }, { status: 400 });
  }

  // Prevent admin from demoting themselves (would lock them out)
  if (body.user_id === auth.user_id && body.role !== "admin") {
    return NextResponse.json({ error: "cannot_demote_self" }, { status: 400 });
  }

  const db = createServiceClient();
  const { data: member, error: updateErr } = await db
    .from("org_members")
    .update({ role: body.role })
    .eq("org_id", auth.org_id)
    .eq("user_id", body.user_id)
    .select("id, email, role")
    .single();

  if (updateErr || !member) return NextResponse.json({ error: "member_not_found" }, { status: 404 });

  await writeAuditLog(db, {
    org_id:        auth.org_id,
    event_type:    "member_role_changed",
    actor_id:      auth.user_id ?? null,
    actor_email:   auth.actor_email ?? "unknown",
    resource_type: "org_member",
    resource_id:   member.id,
    payload:       { target_user_id: body.user_id, new_role: body.role },
  });

  return NextResponse.json({ member });
}

// ── DELETE — remove member ────────────────────────────────────────────────────
export async function DELETE(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });
  const roleErr = requireRole(auth, "admin");
  if (roleErr) return NextResponse.json({ error: roleErr }, { status: 403 });

  const userId = new URL(req.url).searchParams.get("user_id");
  if (!userId) return NextResponse.json({ error: "user_id_required" }, { status: 400 });
  if (userId === auth.user_id) return NextResponse.json({ error: "cannot_remove_self" }, { status: 400 });

  const db = createServiceClient();
  const { data: member } = await db
    .from("org_members")
    .select("id, email")
    .eq("org_id", auth.org_id)
    .eq("user_id", userId)
    .single();

  if (!member) return NextResponse.json({ error: "member_not_found" }, { status: 404 });

  // Ensure at least one admin remains
  const { count: adminCount } = await db
    .from("org_members")
    .select("id", { count: "exact", head: true })
    .eq("org_id", auth.org_id)
    .eq("role", "admin");

  const { data: targetMember } = await db
    .from("org_members")
    .select("role")
    .eq("org_id", auth.org_id)
    .eq("user_id", userId)
    .single();

  if (targetMember?.role === "admin" && (adminCount ?? 0) <= 1) {
    return NextResponse.json({ error: "last_admin" }, { status: 400 });
  }

  await db.from("org_members").delete().eq("org_id", auth.org_id).eq("user_id", userId);

  await writeAuditLog(db, {
    org_id:        auth.org_id,
    event_type:    "member_removed",
    actor_id:      auth.user_id ?? null,
    actor_email:   auth.actor_email ?? "unknown",
    resource_type: "org_member",
    resource_id:   member.id,
    payload:       { removed_email: member.email },
  });

  return NextResponse.json({ ok: true });
}
