/**
 * The organisation-wide two-factor requirement (organizations.require_mfa, migration 20261129_require_mfa.sql).
 *
 * verifyApiKey asks this on every authenticated request, so the answer is kept in this instance's memory for a few seconds
 * (no Redis command): turning the requirement on or off reaches every instance within MFA_POLICY_TTL_SECONDS.
 */
import type { SupabaseClient } from "@supabase/supabase-js";
import { memoryCached } from "@/lib/cache";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Db = SupabaseClient<any>;

export const MFA_POLICY_TTL_SECONDS = 15;

/** Paths a member without two-factor must still be able to use, to turn it on. */
export const MFA_ENROLMENT_PATHS = ["/api/auth/2fa", "/api/me", "/api/auth/bootstrap"];
export const isMfaEnrolmentPath = (pathname: string): boolean => MFA_ENROLMENT_PATHS.some(p => pathname === p || pathname.startsWith(p + "/"));

/** Does this organisation require two-factor? False when the column does not exist yet (migration not run). */
export async function orgRequiresMfa(db: Db, orgId: string): Promise<boolean> {
  return memoryCached(`mfa:policy:${orgId}`, MFA_POLICY_TTL_SECONDS, async () => {
    const { data, error } = await db.from("organizations").select("require_mfa").eq("id", orgId).maybeSingle() as { data: { require_mfa?: boolean } | null; error: unknown };
    return !error && !!data?.require_mfa;
  });
}
