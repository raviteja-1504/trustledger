/**
 * Step-up confirmation for actions that cannot be undone (deleting an organisation).
 *
 * The session being valid is not enough: a stolen or left-open browser session must not be able to destroy an organisation.
 *  - A person with two-factor on must give a current authenticator code (a backup code is not accepted here).
 *  - Otherwise they must have signed in within the last 10 minutes (the sign-in time Supabase puts in the token's `amr` claim),
 *    which also covers GitHub / SSO sign-ins that have no password to re-enter.
 */
import type { SupabaseClient } from "@supabase/supabase-js";
import { decodeJwtPayload } from "@/lib/jwt";
import { verifyTOTP } from "@/lib/totp";
import { openSecret } from "@/lib/secretBox";
import { checkRateLimit } from "@/lib/rateLimit";

export const RECENT_SIGNIN_MS = 10 * 60_000;

export type StepUpResult =
  | { ok: true; method: "totp" | "recent_signin" }
  | { ok: false; status: number; error: "session_required" | "mfa_code_required" | "invalid_code" | "reauth_required" | "too_many_attempts"; message: string };

/** When this session signed in (ms), from the token's amr claim; null if the token does not say. */
export function signInTime(token: string): number | null {
  const amr = decodeJwtPayload(token)?.amr;
  if (!Array.isArray(amr)) return null;
  const times = amr.map(e => Number((e as { timestamp?: unknown } | null)?.timestamp)).filter(n => Number.isFinite(n) && n > 0);
  return times.length ? Math.max(...times) * 1000 : null;
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export async function requireStepUp(db: SupabaseClient<any>, bearer: string | null, userId: string | undefined, code: unknown, now = Date.now()): Promise<StepUpResult> {
  if (!userId || !bearer) {
    return { ok: false, status: 403, error: "session_required", message: "This needs a signed-in person, not an API key." };
  }
  const { data: twoFa } = await db.from("user_2fa").select("enabled, secret").eq("user_id", userId).maybeSingle() as { data: { enabled?: boolean; secret?: string | null } | null };

  if (twoFa?.enabled) {
    const rl = await checkRateLimit(userId, { limit: 5, windowMs: 15 * 60_000, prefix: "stepup" });
    if (!rl.success) return { ok: false, status: 429, error: "too_many_attempts", message: "Too many attempts. Wait a few minutes and try again." };
    const clean = typeof code === "string" ? code.replace(/\s/g, "") : "";
    if (!clean) return { ok: false, status: 401, error: "mfa_code_required", message: "Enter the 6-digit code from your authenticator app." };
    const secret = openSecret(twoFa.secret);
    if (!secret || !/^\d{6}$/.test(clean) || !verifyTOTP(secret, clean)) {
      return { ok: false, status: 401, error: "invalid_code", message: "That code didn't match. Check your authenticator app and try again." };
    }
    return { ok: true, method: "totp" };
  }

  const at = signInTime(bearer);
  if (at === null || now - at > RECENT_SIGNIN_MS || at > now + 60_000) {
    return { ok: false, status: 401, error: "reauth_required", message: "For your security, sign out and sign in again, then repeat this within 10 minutes." };
  }
  return { ok: true, method: "recent_signin" };
}
