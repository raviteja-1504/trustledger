import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey, requireRole } from "../_middleware";
import { writeAuditLog } from "@/lib/audit";
import { checkRateLimit } from "@/lib/rateLimit";

// â”€â”€ GET org settings â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

export async function GET(req: NextRequest) {
  const { org_id, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  const db = createServiceClient();

  const { data: org } = await db
    .from("organizations")
    .select("id, slug, name, github_org, plan, ai_threshold, attest_sla_hours, block_on_critical, block_on_high, require_two_reviewers, created_at")
    .eq("id", org_id)
    .single() as { data: Record<string, unknown> | null };

  if (!org) return NextResponse.json({ error: "org_not_found" }, { status: 404 });

  const { data: members } = await db
    .from("org_members")
    .select("id, email, name, role, github_login, avatar_url, created_at")
    .eq("org_id", org_id)
    .order("created_at", { ascending: true }) as { data: Record<string, unknown>[] | null };

  const { data: repos } = await db
    .from("repositories")
    .select("id, repo_full_name, default_branch, is_active, created_at")
    .eq("org_id", org_id)
    .order("repo_full_name") as { data: Record<string, unknown>[] | null };

  const { data: keys } = await db
    .from("api_keys")
    .select("id, name, key_prefix, created_at, last_used, expires_at, revoked")
    .eq("org_id", org_id)
    .eq("revoked", false)
    .order("created_at", { ascending: false }) as { data: Record<string, unknown>[] | null };

  return NextResponse.json({
    org,
    members:    members ?? [],
    repos:      repos   ?? [],
    api_keys:   keys    ?? [],
  });
}

// â”€â”€ PATCH org settings â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

export async function PATCH(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });
  const roleErr = requireRole(auth, "admin");
  if (roleErr) return NextResponse.json({ error: roleErr }, { status: 403 });
  const { org_id, user_id, actor_email } = auth;

  const body = await req.json() as {
    name?:                   string;
    github_org?:             string;
    ai_threshold?:           number;
    attest_sla_hours?:       number;
    block_on_critical?:      boolean;
    block_on_high?:          boolean;
    require_two_reviewers?:  boolean;
  };

  const allowed = ["name","github_org","ai_threshold","attest_sla_hours",
                   "block_on_critical","block_on_high","require_two_reviewers"];
  const updates = Object.fromEntries(
    Object.entries(body).filter(([k]) => allowed.includes(k))
  );

  if (Object.keys(updates).length === 0) {
    return NextResponse.json({ error: "no_valid_fields" }, { status: 400 });
  }

  const db = createServiceClient();
  const { data, error: upErr } = await db
    .from("organizations")
    .update(updates)
    .eq("id", org_id)
    .select("id")
    .single() as { data: { id: string } | null; error: unknown };

  if (upErr || !data) return NextResponse.json({ error: "update_failed" }, { status: 500 });

  await writeAuditLog(db, {
    org_id,
    event_type:    "org_settings_changed",
    actor_id:      user_id ?? null,
    actor_email:   actor_email ?? null,
    resource_type: "organization",
    resource_id:   org_id,
    payload: updates,
  });

  return NextResponse.json({ ok: true });
}

// â”€â”€ POST â€” invite team member â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

export async function POST(req: NextRequest) {
  const { org_id, user_id, actor_email, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  // Only admins may manage team membership
  const db0 = createServiceClient();
  const { data: caller } = await db0.from("org_members")
    .select("role").eq("org_id", org_id).eq("user_id", user_id ?? "").single();
  if (!caller || !["admin", "owner", "platform_admin"].includes(caller.role)) {
    return NextResponse.json({ error: "forbidden" }, { status: 403 });
  }

  const body = await req.json() as {
    action: "invite_member" | "remove_member" | "update_member_role";
    email?: string;
    user_id?: string;
    role?: string;
  };

  const db = createServiceClient();

  if (body.action === "invite_member") {
    if (!body.email) return NextResponse.json({ error: "missing_email" }, { status: 400 });
    // Rate-limit invitations: max 10 per org per hour to prevent email spam
    const rl = await checkRateLimit(org_id, { limit: 10, windowMs: 60 * 60_000, prefix: "invite" });
    if (!rl.success) {
      return NextResponse.json({ error: "too_many_invites" }, { status: 429, headers: rl.headers });
    }

    // Send Supabase magic link invite
    const { data: invited, error: invErr } = await db.auth.admin.inviteUserByEmail(body.email, {
      data:        { invited_to_org: org_id },
      redirectTo:  `${process.env.NEXT_PUBLIC_APP_URL}/api/auth/callback`,
    });

    if (invErr) return NextResponse.json({ error: invErr.message }, { status: 500 });

    // Pre-create org membership (will be confirmed when user accepts)
    await db.from("org_members").upsert({
      org_id,
      user_id:  invited.user.id,
      email:    body.email,
      role:     body.role ?? "developer",
    }, { onConflict: "org_id,user_id" });

    await writeAuditLog(db, {
      org_id,
      event_type:    "user_added",
      actor_id:      user_id ?? null,
      actor_email:   actor_email ?? null,
      resource_type: "user",
      resource_id:   invited.user.id,
      payload: { email: body.email, role: body.role ?? "developer" },
    });

    return NextResponse.json({ ok: true, user_id: invited.user.id });
  }

  if (body.action === "update_member_role") {
    if (!body.user_id || !body.role) return NextResponse.json({ error: "missing_fields" }, { status: 400 });
    await db.from("org_members").update({ role: body.role }).eq("user_id", body.user_id).eq("org_id", org_id);
    return NextResponse.json({ ok: true });
  }

  if (body.action === "remove_member") {
    if (!body.user_id) return NextResponse.json({ error: "missing_user_id" }, { status: 400 });
    await db.from("org_members").delete().eq("user_id", body.user_id).eq("org_id", org_id);
    await writeAuditLog(db, {
      org_id,
      event_type:    "user_removed",
      actor_id:      user_id ?? null,
      actor_email:   actor_email ?? null,
      resource_type: "user",
      resource_id:   body.user_id,
      payload: {},
    });
    return NextResponse.json({ ok: true });
  }

  return NextResponse.json({ error: "unknown_action" }, { status: 400 });
}

