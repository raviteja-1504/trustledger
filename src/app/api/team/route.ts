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

  // Ensure the Supabase auth user exists. inviteUserByEmail creates a new
  // user (or returns the existing one) and sends them a magic-link email so
  // they can set their password and log in without a separate sign-up step.
  let authUserId: string | null = null;
  try {
    const { data: invited, error: inviteErr } = await db.auth.admin.inviteUserByEmail(email, {
      redirectTo: `${process.env.NEXT_PUBLIC_APP_URL ?? ""}/dashboard`,
    });
    if (inviteErr) {
      // User may already exist in auth — look them up by email
      const { data: { users } } = await db.auth.admin.listUsers({ perPage: 1000 });
      const existing = users.find(u => u.email?.toLowerCase() === email);
      authUserId = existing?.id ?? null;
    } else {
      authUserId = invited.user?.id ?? null;
    }
  } catch { /* will fail at insert if still null */ }

  if (!authUserId) {
    return NextResponse.json({ error: "auth_user_creation_failed" }, { status: 500 });
  }

  const { data: member, error: insertErr } = await db
    .from("org_members")
    .insert({
      org_id:  auth.org_id,
      user_id: authUserId,
      email,
      name,
      role,
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

// ── DELETE — remove member (by user_id for active members, member_id for pending) ──
export async function DELETE(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });
  const roleErr = requireRole(auth, "admin");
  if (roleErr) return NextResponse.json({ error: roleErr }, { status: 403 });

  const params   = new URL(req.url).searchParams;
  const userId   = params.get("user_id");
  const memberId = params.get("member_id");

  if (!userId && !memberId) {
    return NextResponse.json({ error: "user_id_or_member_id_required" }, { status: 400 });
  }
  if (userId && userId === auth.user_id) {
    return NextResponse.json({ error: "cannot_remove_self" }, { status: 400 });
  }

  const db = createServiceClient();

  // Look up the row — works for both active (user_id) and pending (member_id) members
  const query = db
    .from("org_members")
    .select("id, email, role, user_id")
    .eq("org_id", auth.org_id);

  const { data: member } = await (
    userId ? query.eq("user_id", userId).single()
           : query.eq("id", memberId!).single()
  );

  if (!member) return NextResponse.json({ error: "member_not_found" }, { status: 404 });

  // Prevent removing the last admin
  if (member.role === "admin") {
    const { count: adminCount } = await db
      .from("org_members")
      .select("id", { count: "exact", head: true })
      .eq("org_id", auth.org_id)
      .eq("role", "admin");
    if ((adminCount ?? 0) <= 1) {
      return NextResponse.json({ error: "last_admin" }, { status: 400 });
    }
  }

  await db.from("org_members").delete().eq("org_id", auth.org_id).eq("id", member.id);

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

// ── PUT — resend invite email ──────────────────────────────────────────────────
export async function PUT(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });
  const roleErr = requireRole(auth, "admin");
  if (roleErr) return NextResponse.json({ error: roleErr }, { status: 403 });

  let body: { email?: string };
  try { body = await req.json(); } catch { return NextResponse.json({ error: "invalid_json" }, { status: 400 }); }

  const email = body.email?.toLowerCase().trim();
  if (!email) return NextResponse.json({ error: "email_required" }, { status: 400 });

  const db = createServiceClient();

  // Verify they are a member of this org
  const { data: member } = await db
    .from("org_members")
    .select("id, user_id")
    .eq("org_id", auth.org_id)
    .eq("email", email)
    .maybeSingle();

  if (!member) return NextResponse.json({ error: "member_not_found" }, { status: 404 });

  // Generate a fresh magic link (password recovery type so they can set a password)
  const appUrl = process.env.NEXT_PUBLIC_APP_URL ?? "";
  const { data: linkData, error: linkErr } = await db.auth.admin.generateLink({
    type: "recovery",
    email,
    options: { redirectTo: `${appUrl}/dashboard` },
  });

  if (linkErr || !linkData?.properties?.action_link) {
    return NextResponse.json({ error: "link_generation_failed", detail: linkErr?.message }, { status: 500 });
  }

  // Supabase doesn't expose a "send email" API directly — return the link
  // so the admin can share it, or configure Supabase SMTP to auto-send.
  return NextResponse.json({ ok: true, action_link: linkData.properties.action_link });
}
