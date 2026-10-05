/**
 * Email domains for SSO, proved by DNS (built-in admins only).
 *
 * POST   /api/sso/domains            { domain }  → claim; returns the TXT record to publish
 * PATCH  /api/sso/domains            { domain }  → check DNS now; on success the domain is verified and added
 *                                                  to the org's identity provider
 * DELETE /api/sso/domains?domain=x                → release
 *
 * A domain can be verified by only one org. Consumer mailbox domains (gmail.com, ...) can't be claimed.
 */
import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey, requireRole } from "../../_middleware";
import { writeAuditLog } from "@/lib/audit";
import { safeError } from "@/lib/errors";
import { checkDomainTxt, domainClaimError, newVerificationToken, normalizeDomain, verificationRecord } from "@/lib/ssoDomains";
import { SsoProviderError, setSsoProviderDomains } from "@/lib/supabaseSso";
import { invalidateSsoEnforcement } from "@/lib/ssoMembership";

type Db = ReturnType<typeof createServiceClient>;

async function adminOnly(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return { auth, res: NextResponse.json({ error: auth.error }, { status: 401 }) };
  const roleErr = requireRole(auth, "admin");
  if (roleErr) return { auth, res: NextResponse.json({ error: roleErr }, { status: 403 }) };
  return { auth, res: null };
}

async function domainFromBody(req: NextRequest): Promise<string | null> {
  const body = await req.json().catch(() => null) as { domain?: unknown } | null;
  return typeof body?.domain === "string" ? normalizeDomain(body.domain) : null;
}

/** Keeps the org's Supabase SSO provider in step with its verified domains; with none left, SSO can't be enforced. */
async function syncProvider(db: Db, orgId: string): Promise<void> {
  const { data: conn } = await db.from("sso_connections").select("provider_id, enforce_sso").eq("org_id", orgId).maybeSingle() as
    { data: { provider_id: string | null; enforce_sso: boolean } | null };
  const { data: rows } = await db.from("sso_domains").select("domain, verified_at").eq("org_id", orgId);
  const verified = ((rows ?? []) as Array<{ domain: string; verified_at: string | null }>).filter(r => r.verified_at).map(r => r.domain);
  if (conn?.provider_id) await setSsoProviderDomains(conn.provider_id, verified);
  if (conn?.enforce_sso && verified.length === 0) {
    await db.from("sso_connections").update({ enforce_sso: false }).eq("org_id", orgId);
    await invalidateSsoEnforcement(orgId);
  }
}

export async function POST(req: NextRequest) {
  const { auth, res } = await adminOnly(req);
  if (res) return res;
  const raw = await req.json().catch(() => null) as { domain?: unknown } | null;
  const input = typeof raw?.domain === "string" ? raw.domain : "";
  const claimErr = domainClaimError(input);
  if (claimErr) {
    return NextResponse.json({ error: claimErr, message: claimErr === "public_email_domain"
      ? "Public email domains can't be used for SSO -- use your company's own domain."
      : "Enter a domain like acme.com." }, { status: 400 });
  }
  const domain = normalizeDomain(input)!;
  const db = createServiceClient();

  const { data: taken } = await db.from("sso_domains").select("org_id").eq("domain", domain).not("verified_at", "is", null).maybeSingle() as
    { data: { org_id: string } | null };
  if (taken && taken.org_id !== auth.org_id) {
    return NextResponse.json({ error: "domain_taken", message: "That domain is already verified by another organisation." }, { status: 409 });
  }

  const { data: existing } = await db.from("sso_domains").select("domain, verification_token, verified_at").eq("org_id", auth.org_id).eq("domain", domain).maybeSingle() as
    { data: { domain: string; verification_token: string; verified_at: string | null } | null };
  let row = existing;
  if (!row) {
    const token = newVerificationToken();
    const { error } = await db.from("sso_domains").insert({ org_id: auth.org_id, domain, verification_token: token });
    if (error) return safeError(error, { code: "sso_domain_add_failed", message: "We couldn't add that domain. Please try again." });
    row = { domain, verification_token: token, verified_at: null };
  }
  return NextResponse.json({ domain, verified: !!row.verified_at, record: verificationRecord(domain, row.verification_token) }, { status: existing ? 200 : 201 });
}

export async function PATCH(req: NextRequest) {
  const { auth, res } = await adminOnly(req);
  if (res) return res;
  const domain = await domainFromBody(req);
  if (!domain) return NextResponse.json({ error: "invalid_domain" }, { status: 400 });
  const db = createServiceClient();
  const { data: row } = await db.from("sso_domains").select("domain, verification_token, verified_at").eq("org_id", auth.org_id).eq("domain", domain).maybeSingle() as
    { data: { domain: string; verification_token: string; verified_at: string | null } | null };
  if (!row) return NextResponse.json({ error: "domain_not_found" }, { status: 404 });
  if (row.verified_at) return NextResponse.json({ domain, verified: true });

  const record = verificationRecord(domain, row.verification_token);
  if (!(await checkDomainTxt(domain, row.verification_token))) {
    return NextResponse.json({ domain, verified: false, record,
      message: `We couldn't find the TXT record yet. Add ${record.name} with the value shown, then try again -- DNS changes can take a few minutes.` });
  }

  const { error } = await db.from("sso_domains").update({ verified_at: new Date().toISOString() }).eq("org_id", auth.org_id).eq("domain", domain);
  if (error) {
    if (error.code === "23505") return NextResponse.json({ error: "domain_taken", message: "That domain is already verified by another organisation." }, { status: 409 });
    return safeError(error, { code: "sso_domain_verify_failed", message: "We couldn't verify that domain. Please try again." });
  }
  try { await syncProvider(db, auth.org_id); }
  catch (e) { if (!(e instanceof SsoProviderError)) throw e; /* verified either way; the next IdP save re-sends domains */ }
  await writeAuditLog(db, {
    org_id: auth.org_id, event_type: "org_settings_changed", actor_id: auth.user_id ?? null, actor_email: auth.actor_email ?? null,
    resource_type: "sso_domain", resource_id: domain, payload: { verified: true },
  });
  return NextResponse.json({ domain, verified: true });
}

export async function DELETE(req: NextRequest) {
  const { auth, res } = await adminOnly(req);
  if (res) return res;
  const domain = normalizeDomain(new URL(req.url).searchParams.get("domain") ?? "");
  if (!domain) return NextResponse.json({ error: "invalid_domain" }, { status: 400 });
  const db = createServiceClient();
  await db.from("sso_domains").delete().eq("org_id", auth.org_id).eq("domain", domain);
  try { await syncProvider(db, auth.org_id); }
  catch (e) { if (!(e instanceof SsoProviderError)) throw e; }
  await writeAuditLog(db, {
    org_id: auth.org_id, event_type: "org_settings_changed", actor_id: auth.user_id ?? null, actor_email: auth.actor_email ?? null,
    resource_type: "sso_domain", resource_id: domain, payload: { removed: true },
  });
  return NextResponse.json({ ok: true });
}
