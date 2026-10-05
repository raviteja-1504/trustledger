/**
 * Which org an SSO sign-in belongs to, and the "SSO required" rule.
 *
 * An IdP can assert any email address, so an SSO identity is trusted ONLY:
 *   * for the org that registered that IdP (looked up by the provider id Supabase puts in the session), and
 *   * for emails at a domain that org has verified by DNS.
 * Never by email alone -- otherwise an org could point its own IdP at someone@other-company.com and take over
 * that person's seat elsewhere. (Supabase keeps SSO identities separate from password accounts with the same
 * email, so this is the only place an SSO user gets a membership.)
 */
import type { SupabaseClient } from "@supabase/supabase-js";
import { emailInDomains } from "@/lib/ssoDomains";
import { cached, cacheDel } from "@/lib/cache";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Db = SupabaseClient<any>;

export type SsoMembershipStatus =
  | "member"               // already a member of the IdP's org (or just joined it)
  | "sso_not_configured"   // no org owns this provider (removed since sign-in started)
  | "sso_domain_mismatch"  // the asserted email isn't at one of the org's verified domains
  | "sso_other_org"        // this identity already belongs to a different org
  | "sso_not_invited";     // JIT provisioning is off and there's no invite

export interface SsoUser { id: string; email?: string | null; user_metadata?: Record<string, unknown> | null }

interface Connection { org_id: string; provider_id: string; jit_enabled: boolean; jit_role: string; enforce_sso: boolean }

async function connectionForProvider(db: Db, providerId: string): Promise<Connection | null> {
  const { data } = await db.from("sso_connections").select("org_id, provider_id, jit_enabled, jit_role, enforce_sso")
    .eq("provider_id", providerId).maybeSingle();
  return (data as Connection | null) ?? null;
}

async function verifiedDomains(db: Db, orgId: string): Promise<string[]> {
  const { data } = await db.from("sso_domains").select("domain, verified_at").eq("org_id", orgId);
  return ((data ?? []) as Array<{ domain: string; verified_at: string | null }>).filter(d => d.verified_at).map(d => d.domain);
}

/** Puts an SSO-authenticated user into the org that owns their IdP -- claiming their invite, taking over their
 * existing seat (moving it from their password account to this SSO identity), or provisioning a new seat
 * just-in-time -- or explains why not. */
export async function resolveSsoMembership(db: Db, user: SsoUser, providerId: string): Promise<{ status: SsoMembershipStatus; org_id?: string }> {
  const conn = await connectionForProvider(db, providerId);
  if (!conn) return { status: "sso_not_configured" };
  if (!emailInDomains(user.email, await verifiedDomains(db, conn.org_id))) return { status: "sso_domain_mismatch" };
  const email = user.email!.trim().toLowerCase();

  const { data: own } = await db.from("org_members").select("org_id").eq("user_id", user.id) as { data: Array<{ org_id: string }> | null };
  if (own?.some(m => m.org_id === conn.org_id)) return { status: "member", org_id: conn.org_id };
  if (own && own.length > 0) return { status: "sso_other_org" };

  // An invite or an existing seat for this address in THIS org (a seat held by their password account moves to
  // the SSO identity; it keeps its role and custom role, and the old session is dropped).
  const { data: seat } = await db.from("org_members").select("id, user_id").eq("org_id", conn.org_id).eq("email", email).maybeSingle() as
    { data: { id: string; user_id: string | null } | null };
  if (seat) {
    await db.from("org_members").update({ user_id: user.id, active_session_id: null }).eq("id", seat.id).eq("org_id", conn.org_id);
    return { status: "member", org_id: conn.org_id };
  }

  if (!conn.jit_enabled) return { status: "sso_not_invited" };
  const meta = user.user_metadata ?? {};
  const name = (meta.full_name ?? meta.name ?? null) as string | null;
  await db.from("org_members").insert({ org_id: conn.org_id, user_id: user.id, email, name, role: conn.jit_role });
  return { status: "member", org_id: conn.org_id };
}

const enforcementKey = (orgId: string) => `sso:enforce:${orgId}`;

/** The org's SSO enforcement, cached briefly (it's read on every API request). */
export async function ssoEnforcement(db: Db, orgId: string): Promise<{ enforce: boolean; provider_id: string | null }> {
  return cached(enforcementKey(orgId), 60, async () => {
    const { data, error } = await db.from("sso_connections").select("enforce_sso, provider_id").eq("org_id", orgId).maybeSingle() as
      { data: { enforce_sso: boolean; provider_id: string | null } | null; error: { code?: string } | null };
    // No table yet (migration not run) or no connection: nothing to enforce.
    if (error || !data) return { enforce: false, provider_id: null };
    return { enforce: !!data.enforce_sso && !!data.provider_id, provider_id: data.provider_id };
  });
}

export async function invalidateSsoEnforcement(orgId: string): Promise<void> {
  await cacheDel(enforcementKey(orgId));
}

/** "sso_required" if the org enforces SSO and this session didn't come through the org's IdP. Built-in admins
 * are exempt so an IdP outage or misconfiguration can't lock everyone out (break-glass). */
export function ssoRequiredError(enf: { enforce: boolean; provider_id: string | null }, role: string | undefined, sessionProviderId: string | null): string | null {
  if (!enf.enforce || role === "admin" || role === "platform_admin") return null;
  return sessionProviderId && sessionProviderId === enf.provider_id ? null : "sso_required";
}
