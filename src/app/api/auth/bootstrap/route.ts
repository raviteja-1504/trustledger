import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { getJwtSessionId } from "@/lib/jwt";

/**
 * POST /api/auth/bootstrap — called right after every sign-in (GitHub, email, reset link).
 *
 * → { has_org, is_new_user, mfa_required }
 *
 * - Never creates or joins an organisation on its own. A user reaches an org only by being invited
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

  // A pending invite (row added by an admin before this person had an account) is claimed by
  // a confirmed email only.
  if (!member && user.email && user.email_confirmed_at) {
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
    await db
      .from("org_members")
      .update({ active_session_id: sessionId, active_session_at: new Date().toISOString() })
      .eq("user_id", user.id);
  }
  return NextResponse.json({ has_org: true, is_new_user: false, mfa_required: false });
}
