/**
 * Sign-in 2FA step.
 *
 * GET  /api/auth/2fa/login          → { required, verified }   is a code needed for this session?
 * POST /api/auth/2fa/login { code } → { ok: true }             authenticator code or a backup code
 *
 * Authenticates the bearer token directly (not verifyApiKey, which refuses unverified 2FA sessions with
 * mfa_required). A correct code makes this session the member's active session, which is what
 * verifyApiKey checks; a backup code works once and is then removed.
 */
import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { getJwtSessionId } from "@/lib/jwt";
import { verifyTOTP } from "@/lib/totp";
import { checkRateLimit } from "@/lib/rateLimit";
import { writeAuditLog } from "@/lib/audit";

type Member = { org_id: string; email: string | null; active_session_id: string | null };
type TwoFa = { enabled: boolean; secret: string | null; backup_codes: string[] | null };

async function load(req: NextRequest) {
  const header = req.headers.get("Authorization") ?? "";
  if (!header.startsWith("Bearer ")) return { error: "missing_token" as const };
  const token = header.slice(7);
  const db = createServiceClient();
  const { data: { user }, error } = await db.auth.getUser(token);
  if (error || !user) return { error: "invalid_token" as const };
  const [{ data: member }, { data: twoFa }] = await Promise.all([
    db.from("org_members").select("org_id, email, active_session_id").eq("user_id", user.id).maybeSingle() as unknown as Promise<{ data: Member | null }>,
    db.from("user_2fa").select("enabled, secret, backup_codes").eq("user_id", user.id).maybeSingle() as unknown as Promise<{ data: TwoFa | null }>,
  ]);
  return { db, user, member, twoFa, sessionId: getJwtSessionId(token) };
}

export async function GET(req: NextRequest) {
  const ctx = await load(req);
  if ("error" in ctx) return NextResponse.json({ error: ctx.error }, { status: 401 });
  const required = !!(ctx.member && ctx.twoFa?.enabled);
  const verified = required && !!ctx.sessionId && ctx.member!.active_session_id === ctx.sessionId;
  return NextResponse.json({ required, verified });
}

export async function POST(req: NextRequest) {
  const ctx = await load(req);
  if ("error" in ctx) return NextResponse.json({ error: ctx.error }, { status: 401 });
  const { db, user, member, twoFa, sessionId } = ctx;
  if (!member || !twoFa?.enabled || !twoFa.secret) return NextResponse.json({ error: "not_enabled" }, { status: 400 });
  if (!sessionId) return NextResponse.json({ error: "invalid_token" }, { status: 401 });

  const rl = await checkRateLimit(user.id, { limit: 10, windowMs: 15 * 60_000, prefix: "2fa-login" });
  if (!rl.success) {
    return NextResponse.json(
      { error: "too_many_attempts", message: "Too many attempts. Wait a few minutes and try again.", retry_after: Math.ceil((rl.reset - Date.now()) / 1000) },
      { status: 429, headers: rl.headers },
    );
  }

  const body = await req.json().catch(() => ({})) as { code?: string };
  const code = (body.code ?? "").replace(/\s/g, "");
  if (!code) return NextResponse.json({ error: "code_required" }, { status: 400 });

  const viaTotp = /^\d{6}$/.test(code) && verifyTOTP(twoFa.secret, code);
  const backup = (twoFa.backup_codes ?? []).find(b => b === code.toUpperCase());
  if (!viaTotp && !backup) {
    return NextResponse.json({ error: "invalid_code", message: "That code didn't match. Check your authenticator app and try again." }, { status: 400 });
  }

  if (!viaTotp && backup) {
    await db.from("user_2fa").update({ backup_codes: (twoFa.backup_codes ?? []).filter(b => b !== backup) }).eq("user_id", user.id);
  }
  await db.from("org_members")
    .update({ active_session_id: sessionId, active_session_at: new Date().toISOString() })
    .eq("user_id", user.id);

  await writeAuditLog(db, {
    // Same event type the 2FA setup/disable route uses (the audit table's event types are fixed).
    org_id: member.org_id, event_type: "org_settings_changed",
    actor_id: user.id, actor_email: member.email ?? user.email ?? null,
    resource_type: "2fa", resource_id: user.id,
    payload: { action: "2fa_login", method: viaTotp ? "totp" : "backup_code" },
  });

  return NextResponse.json({ ok: true, backup_codes_left: viaTotp ? undefined : (twoFa.backup_codes ?? []).length - 1 });
}
