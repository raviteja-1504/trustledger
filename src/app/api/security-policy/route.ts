/**
 * Organisation security policy: the two-factor requirement.
 *
 *   GET   /api/security-policy                  { require_mfa, you_have_mfa, members_total, members_without_mfa }
 *   PATCH /api/security-policy { require_mfa }  switch the requirement on or off (admin only)
 *
 * With the requirement on, a member without two-factor is refused (mfa_enrollment_required) until they enrol
 * (lib/mfaPolicy.ts, enforced in verifyApiKey). It can only be switched on by an admin who has two-factor themselves, so the
 * setting never locks out the person who made it; it takes effect within a few seconds on every server instance.
 */
import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey, requireRole } from "../_middleware";
import { requireAudit } from "@/lib/auditRequired";
import { safeError } from "@/lib/errors";

async function adminOnly(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return { ok: false as const, res: NextResponse.json({ error: auth.error }, { status: 401 }) };
  const roleErr = requireRole(auth, "admin");
  if (roleErr) return { ok: false as const, res: NextResponse.json({ error: roleErr }, { status: 403 }) };
  return { ok: true as const, auth };
}

export async function GET(req: NextRequest) {
  const a = await adminOnly(req);
  if (!a.ok) return a.res;
  const { org_id, user_id } = a.auth;
  const db = createServiceClient();

  const [{ data: org, error: orgErr }, { data: members }] = await Promise.all([
    db.from("organizations").select("require_mfa").eq("id", org_id).maybeSingle() as unknown as Promise<{ data: { require_mfa?: boolean } | null; error: unknown }>,
    db.from("org_members").select("user_id").eq("org_id", org_id) as unknown as Promise<{ data: Array<{ user_id: string | null }> | null }>,
  ]);
  const ids = (members ?? []).map(m => m.user_id).filter((x): x is string => !!x);
  const { data: enrolled } = ids.length === 0 ? { data: [] } : await db.from("user_2fa").select("user_id").eq("enabled", true).in("user_id", ids) as { data: Array<{ user_id: string }> | null };
  const have = new Set((enrolled ?? []).map(r => r.user_id));
  return NextResponse.json({
    require_mfa: !orgErr && !!org?.require_mfa,
    set_up: !orgErr,
    you_have_mfa: !!user_id && have.has(user_id),
    members_total: (members ?? []).length,
    // invited members with no account yet have no two-factor either
    members_without_mfa: (members ?? []).filter(m => !m.user_id || !have.has(m.user_id)).length,
  }, { headers: { "Cache-Control": "private, no-store" } });
}

export async function PATCH(req: NextRequest) {
  const a = await adminOnly(req);
  if (!a.ok) return a.res;
  const { org_id, user_id, actor_email } = a.auth;
  const body = await req.json().catch(() => ({})) as { require_mfa?: unknown };
  if (typeof body.require_mfa !== "boolean") return NextResponse.json({ error: "require_mfa_boolean" }, { status: 400 });

  const db = createServiceClient();
  if (body.require_mfa) {
    const { data: mine } = user_id ? await db.from("user_2fa").select("enabled").eq("user_id", user_id).maybeSingle() as { data: { enabled?: boolean } | null } : { data: null };
    if (!mine?.enabled) {
      return NextResponse.json({ error: "enable_your_own_2fa_first", message: "Turn on two-factor for your own account first (Profile), so this cannot lock you out." }, { status: 422 });
    }
  }

  const { data: before } = await db.from("organizations").select("require_mfa").eq("id", org_id).maybeSingle() as { data: { require_mfa?: boolean } | null };
  const wasOn = !!before?.require_mfa;
  const { data: saved, error } = await db.from("organizations").update({ require_mfa: body.require_mfa }).eq("id", org_id).select("id") as { data: Array<{ id: string }> | null; error: { code?: string; message?: string } | null };
  if (error) {
    if (error.code === "42703" || /require_mfa/.test(error.message ?? "")) {
      return NextResponse.json({ error: "mfa_policy_not_set_up", message: "This needs a database update first (migration 20261129_require_mfa)." }, { status: 422 });
    }
    return safeError(error, { code: "security_policy_failed", message: "We couldn't save the policy. Please try again." });
  }
  if (!saved || saved.length === 0) return NextResponse.json({ error: "org_not_found" }, { status: 404 });

  // A policy change is recorded, or undone.
  const auditFailed = await requireAudit(db, {
    org_id, event_type: "org_settings_changed", actor_id: user_id ?? null, actor_email: actor_email ?? null,
    resource_type: "mfa_policy", resource_id: org_id, payload: { require_mfa: body.require_mfa, was: wasOn },
  }, { undo: async () => { const { error: undoErr } = await db.from("organizations").update({ require_mfa: wasOn }).eq("id", org_id); if (undoErr) throw undoErr; } });
  if (auditFailed) return auditFailed;
  return NextResponse.json({ ok: true, require_mfa: body.require_mfa });
}
