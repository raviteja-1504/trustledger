import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { getJwtSessionId, getJwtSsoProviderId } from "@/lib/jwt";
import { resolveSsoMembership } from "@/lib/ssoMembership";
import { writeAuditLog } from "@/lib/audit";
import { logger } from "@/lib/logger";

/**
 * POST /api/auth/bootstrap — called right after every sign-in (GitHub, email, reset link).
 *
 * → { has_org, is_new_user, mfa_required }
 *
 * - SSO sign-ins join the org that owns their identity provider (invite, existing seat, or just-in-time
 *   provisioning -- lib/ssoMembership.ts); { sso_status } explains a refusal.
 * - Otherwise never creates or joins an organisation on its own. A user reaches an org only by being invited
 *   (an org_members row for their confirmed email) or by creating one at /create-org. Auto-joining by
 *   GitHub login / a shared "default" slug used to put unrelated users into the same org.
 * - Records this session as the user's sole active session (any older token is then rejected by
 *   verifyApiKey) — except for users with 2FA on: their session becomes active only after the 2FA
 *   step at POST /api/auth/2fa/login, so signing in with a password alone grants nothing.
 */
export async function POST(req: NextRequest) {
  const authHeader = req.headers.get("Authorization") ?? "";
  if (!authHeader.startsWith("Bearer ")) {
    return NextResponse.json({ error: "missing_token" }, { status: 401 });
  }

  const token = authHeader.slice(7);
  const db = createServiceClient();
  const { data: { user }, error } = await db.auth.getUser(token);
  if (error || !user) {
    return NextResponse.json({ error: "invalid_token" }, { status: 401 });
  }

  let { data: member } = await db
    .from("org_members")
    .select("id")
    .eq("user_id", user.id)
    .maybeSingle() as { data: { id: string } | null };

  const ssoProviderId = getJwtSsoProviderId(token);
  if (!member && ssoProviderId) {
    const sso = await resolveSsoMembership(db, user, ssoProviderId);
    if (sso.status !== "member") {
      return NextResponse.json({ has_org: false, is_new_user: false, mfa_required: false, sso_status: sso.status });
    }
    member = { id: "sso" };
  }

  // A pending invite (row added by an admin before this person had an account) is claimed by
  // a confirmed email only.
  if (!member && !ssoProviderId && user.email && user.email_confirmed_at) {
    const { data: linked } = await db
      .from("org_members")
      .update({ user_id: user.id })
      .eq("email", user.email)
      .is("user_id", null)
      .select("id")
      .maybeSingle() as { data: { id: string } | null };
    member = linked;
  }

  if (!member) {
    return NextResponse.json({ has_org: false, is_new_user: true, mfa_required: false });
  }

  const { data: twoFa } = await db.from("user_2fa").select("enabled").eq("user_id", user.id).maybeSingle() as { data: { enabled?: boolean } | null };
  if (twoFa?.enabled) {
    return NextResponse.json({ has_org: true, is_new_user: false, mfa_required: true });
  }

  const sessionId = getJwtSessionId(token);
  if (sessionId) {
    const { data: current } = await db.from("org_members").select("org_id, email, active_session_id").eq("user_id", user.id).maybeSingle() as
      { data: { org_id: string; email: string | null; active_session_id: string | null } | null };
    const previousSession = current?.active_session_id ?? null;
    await db
      .from("org_members")
      .update({ active_session_id: sessionId, active_session_at: new Date().toISOString() })
      .eq("user_id", user.id);
    // One audit entry per new session (a repeated call for the same session is not a new sign-in).
    if (current && previousSession !== sessionId) {
      await writeAuditLog(db, {
        org_id: current.org_id, event_type: "user_login",
        actor_id: user.id, actor_email: current.email ?? user.email ?? null,
        resource_type: "session", resource_id: sessionId,
        payload: { method: loginMethod(user, ssoProviderId), mfa: false },
      }).catch(err => {
        // Never block a sign-in on the audit write -- but don't lose it silently either.
        logger.error("Sign-in audit entry failed", { event: "audit_write_failed", org_id: current.org_id, error: err instanceof Error ? err.message : String(err) });
      });
    }
  }
  return NextResponse.json({ has_org: true, is_new_user: false, mfa_required: false });
}

/** How the user signed in: "sso", or Supabase's provider for this session ("email", "github", ...). */
function loginMethod(user: { app_metadata?: { provider?: unknown } }, ssoProviderId: string | null): string {
  if (ssoProviderId) return "sso";
  return typeof user.app_metadata?.provider === "string" ? user.app_metadata.provider : "unknown";
}
