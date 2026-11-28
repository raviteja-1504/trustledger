/**
 * POST /api/team/sessions { user_id } -- sign a member out of every session, now.
 *
 * For a lost laptop, a suspected account takeover, or someone leaving. Every token the member holds is refused from the next
 * request (verifyApiKey reports session_revoked) and they must sign in again, with their second factor if they have one. Their
 * role, membership and the organisation's API keys are untouched: this ends sessions, nothing else.
 *
 * Needs can_manage_team. Only an admin may do it to an admin.
 */
import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey, requirePermission } from "../../_middleware";
import { requireAudit } from "@/lib/auditRequired";

export async function POST(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });
  const permErr = await requirePermission(auth, "can_manage_team");
  if (permErr) return NextResponse.json({ error: permErr }, { status: 403 });

  const body = await req.json().catch(() => ({})) as { user_id?: unknown };
  if (typeof body.user_id !== "string" || !body.user_id) return NextResponse.json({ error: "user_id_required" }, { status: 400 });

  const db = createServiceClient();
  const { data: member } = await db.from("org_members").select("id, email, role, active_session_id").eq("org_id", auth.org_id).eq("user_id", body.user_id).maybeSingle() as { data: { id: string; email: string; role: string; active_session_id: string | null } | null };
  if (!member) return NextResponse.json({ error: "member_not_found" }, { status: 404 });
  if (member.role === "admin" && auth.role !== "admin" && auth.role !== "platform_admin") {
    return NextResponse.json({ error: "cannot_revoke_admin_sessions" }, { status: 403 });
  }

  // No session id the member holds can equal this, so every one of them is refused (and a token with no session id is refused too).
  // It names the session that was active: that exact session may not sign itself back in (bootstrap and the 2FA step refuse it), so a
  // stolen token cannot revive itself -- only a NEW sign-in starts a new session.
  const was = member.active_session_id?.startsWith("revoked:") ? member.active_session_id.slice("revoked:".length) : (member.active_session_id ?? "none");
  const { data: changed, error } = await db.from("org_members")
    .update({ active_session_id: `revoked:${was}`, active_session_at: new Date().toISOString() })
    .eq("org_id", auth.org_id).eq("user_id", body.user_id).select("id") as { data: Array<{ id: string }> | null; error: unknown };
  if (error || !changed || changed.length === 0) return NextResponse.json({ error: "revoke_failed" }, { status: 500 });

  // Ending sessions stays in force even if it cannot be recorded (the safe direction); the caller is told it was not recorded.
  const auditFailed = await requireAudit(db, {
    org_id: auth.org_id, event_type: "member_sessions_revoked", actor_id: auth.user_id ?? null, actor_email: auth.actor_email ?? null,
    resource_type: "org_member", resource_id: member.id, payload: { target_user_id: body.user_id, email: member.email },
  });
  if (auditFailed) return auditFailed;
  return NextResponse.json({ ok: true });
}
