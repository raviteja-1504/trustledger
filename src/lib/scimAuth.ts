/**
 * SCIM 2.0 authentication: each organisation has its own token (scim_tokens; only a SHA-256 hash is stored),
 * and the org is found from the token. Created and rotated by admins at /api/scim-token.
 *
 * SCIM creates confirmed accounts, so it may only provision addresses at the org's DNS-verified domains (the
 * same verification SSO uses) -- otherwise an org could mint accounts for another company's people.
 */
import { createHash, randomBytes } from "crypto";
import type { NextRequest } from "next/server";
import type { SupabaseClient } from "@supabase/supabase-js";
import { emailInDomains } from "@/lib/ssoDomains";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Db = SupabaseClient<any>;

export const SCIM_TOKEN_PREFIX = "tl_scim_";

export function newScimToken(): { token: string; hash: string; prefix: string } {
  const token = SCIM_TOKEN_PREFIX + randomBytes(32).toString("base64url");
  return { token, hash: hashScimToken(token), prefix: token.slice(0, SCIM_TOKEN_PREFIX.length + 6) };
}

export function hashScimToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

/** The org a SCIM request is for, or null (missing, malformed, unknown or revoked token). */
export async function verifyScimRequest(req: NextRequest, db: Db): Promise<{ org_id: string } | null> {
  const header = req.headers.get("Authorization") ?? "";
  const m = /^Bearer\s+(\S+)$/i.exec(header.trim());
  if (!m || !m[1].startsWith(SCIM_TOKEN_PREFIX)) return null;
  const { data } = await db.from("scim_tokens").select("org_id").eq("token_hash", hashScimToken(m[1])).maybeSingle() as
    { data: { org_id: string } | null };
  if (!data) return null;
  void db.from("scim_tokens").update({ last_used_at: new Date().toISOString() }).eq("token_hash", hashScimToken(m[1])).then(() => {}, () => {});
  return { org_id: data.org_id };
}

/** Whether SCIM may provision this address for the org: it must be at one of the org's verified domains. */
export async function scimMayProvision(db: Db, orgId: string, email: string): Promise<boolean> {
  const { data } = await db.from("sso_domains").select("domain, verified_at").eq("org_id", orgId);
  const verified = ((data ?? []) as Array<{ domain: string; verified_at: string | null }>).filter(d => d.verified_at).map(d => d.domain);
  return emailInDomains(email, verified);
}
