/**
 * SAML SSO for the caller's org (built-in admins only -- sign-in itself is not something a custom role grants).
 *
 * GET    /api/sso   → availability, service-provider details for the IdP, connection, domains
 * PUT    /api/sso   → { metadata_url | metadata_xml }? registers/updates the IdP with Supabase Auth;
 *                      { jit_enabled?, jit_role?, enforce_sso? } settings
 * DELETE /api/sso   → removes the IdP (verified domains are kept)
 *
 * Domains: /api/sso/domains. Sign-in: supabase.auth.signInWithSSO({ domain }) on the login page.
 */
import { NextRequest, NextResponse } from "next/server";
import { z } from "zod";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey, requireRole } from "../_middleware";
import { writeAuditLog } from "@/lib/audit";
import { safeError } from "@/lib/errors";
import {
  SsoProviderError, createSsoProvider, deleteSsoProvider, metadataInputError, serviceProviderDetails,
  ssoAvailability, updateSsoProvider,
} from "@/lib/supabaseSso";
import { verificationRecord } from "@/lib/ssoDomains";
import { invalidateSsoEnforcement } from "@/lib/ssoMembership";

const SETUP_HINT = "SSO needs database migration 20261006_sso.";

type Connection = {
  org_id: string; provider_id: string | null; idp_entity_id: string | null; metadata_url: string | null;
  jit_enabled: boolean; jit_role: string; enforce_sso: boolean;
};
type Domain = { domain: string; verification_token: string; verified_at: string | null };

const PutSchema = z.object({
  metadata_url: z.string().trim().max(2000).optional(),
  metadata_xml: z.string().max(200_000).optional(),
  jit_enabled:  z.boolean().optional(),
  jit_role:     z.enum(["developer", "security_reviewer"]).optional(),
  enforce_sso:  z.boolean().optional(),
}).strict();

async function adminOnly(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return { auth, res: NextResponse.json({ error: auth.error }, { status: 401 }) };
  const roleErr = requireRole(auth, "admin");
  if (roleErr) return { auth, res: NextResponse.json({ error: roleErr }, { status: 403 }) };
  return { auth, res: null };
}

function isNotSetUp(err: { code?: string; message?: string } | null | undefined): boolean {
  return !!err && (err.code === "42P01" || /sso_(connections|domains)/.test(err.message ?? ""));
}

function providerErrorResponse(e: SsoProviderError) {
  const message =
    e.code === "sso_not_on_plan" ? "SAML SSO isn't enabled for this TrustLedger deployment's Supabase project (needs the Pro plan with SAML 2.0 turned on)."
    : e.code === "sso_management_unauthorized" ? "The server's Supabase management token was refused. Check SUPABASE_MANAGEMENT_TOKEN."
    : e.code === "sso_invalid_metadata" ? `Your identity provider's metadata was rejected: ${e.message}`
    : "We couldn't register your identity provider. Please try again.";
  return NextResponse.json({ error: e.code, message }, { status: e.code === "sso_invalid_metadata" ? 400 : 502 });
}

async function load(db: ReturnType<typeof createServiceClient>, orgId: string) {
  const [{ data: conn, error: connErr }, { data: domains, error: domErr }] = await Promise.all([
    db.from("sso_connections").select("*").eq("org_id", orgId).maybeSingle(),
    db.from("sso_domains").select("domain, verification_token, verified_at").eq("org_id", orgId).order("domain"),
  ]);
  return { conn: conn as Connection | null, domains: (domains ?? []) as Domain[], error: connErr ?? domErr };
}

export async function GET(req: NextRequest) {
  const { auth, res } = await adminOnly(req);
  if (res) return res;
  const db = createServiceClient();
  const { conn, domains, error } = await load(db, auth.org_id);
  if (error && !isNotSetUp(error)) return safeError(error, { code: "sso_fetch_failed", message: "We couldn't load SSO settings right now. Please try again." });
  return NextResponse.json({
    set_up:       !error,
    ...(error ? { message: SETUP_HINT } : {}),
    availability: ssoAvailability(),
    sp:           serviceProviderDetails(),
    connection:   conn,
    domains:      domains.map(d => ({ domain: d.domain, verified: !!d.verified_at, verified_at: d.verified_at, record: verificationRecord(d.domain, d.verification_token) })),
  });
}

export async function PUT(req: NextRequest) {
  const { auth, res } = await adminOnly(req);
  if (res) return res;
  const parsed = PutSchema.safeParse(await req.json().catch(() => null));
  if (!parsed.success) return NextResponse.json({ error: "invalid_body", issues: parsed.error.issues.map(i => i.message) }, { status: 400 });
  const body = parsed.data;
  const metadata = body.metadata_url || body.metadata_xml
    ? { metadata_url: body.metadata_url || undefined, metadata_xml: body.metadata_xml || undefined } : null;

  const db = createServiceClient();
  const { conn, domains, error } = await load(db, auth.org_id);
  if (error) {
    if (isNotSetUp(error)) return NextResponse.json({ error: "sso_not_set_up", message: SETUP_HINT }, { status: 422 });
    return safeError(error, { code: "sso_fetch_failed", message: "We couldn't load SSO settings right now. Please try again." });
  }
  const verified = domains.filter(d => d.verified_at).map(d => d.domain);
  const next: Omit<Connection, "org_id"> = {
    provider_id:   conn?.provider_id ?? null,
    idp_entity_id: conn?.idp_entity_id ?? null,
    metadata_url:  conn?.metadata_url ?? null,
    jit_enabled:   body.jit_enabled ?? conn?.jit_enabled ?? true,
    jit_role:      body.jit_role ?? conn?.jit_role ?? "developer",
    enforce_sso:   body.enforce_sso ?? conn?.enforce_sso ?? false,
  };

  if (metadata) {
    const availability = ssoAvailability();
    if (!availability.available) return NextResponse.json({ error: "sso_unavailable", reason: availability.reason }, { status: 422 });
    const inputErr = metadataInputError(metadata);
    if (inputErr) return NextResponse.json({ error: "invalid_metadata", message: inputErr }, { status: 400 });
    // A provider without a verified domain could never be reached from "Sign in with SSO", and its users
    // could never be matched to this org -- so domains come first.
    if (verified.length === 0) return NextResponse.json({ error: "no_verified_domain", message: "Verify at least one email domain before connecting your identity provider." }, { status: 422 });
    try {
      const provider = next.provider_id
        ? await updateSsoProvider(next.provider_id, { ...metadata, domains: verified })
        : await createSsoProvider({ ...metadata, domains: verified });
      next.provider_id   = provider.id;
      next.idp_entity_id = provider.entity_id;
      next.metadata_url  = metadata.metadata_url ?? null;
    } catch (e) {
      if (e instanceof SsoProviderError) return providerErrorResponse(e);
      throw e;
    }
  }

  if (next.enforce_sso && (!next.provider_id || verified.length === 0)) {
    return NextResponse.json({ error: "cannot_enforce", message: "Connect your identity provider before requiring SSO." }, { status: 422 });
  }

  const { data: saved, error: saveErr } = await db.from("sso_connections")
    .upsert({ org_id: auth.org_id, ...next, updated_at: new Date().toISOString() }, { onConflict: "org_id" })
    .select("*").single();
  if (saveErr) return safeError(saveErr, { code: "sso_save_failed", message: "We couldn't save SSO settings. Please try again." });
  await invalidateSsoEnforcement(auth.org_id);

  await writeAuditLog(db, {
    org_id: auth.org_id, event_type: "org_settings_changed", actor_id: auth.user_id ?? null, actor_email: auth.actor_email ?? null,
    resource_type: "sso", resource_id: next.provider_id ?? undefined,
    payload: {
      ...(metadata ? { idp: next.idp_entity_id, registered: true } : {}),
      jit_enabled: next.jit_enabled, jit_role: next.jit_role, enforce_sso: next.enforce_sso,
    },
  });
  return NextResponse.json({ connection: saved });
}

export async function DELETE(req: NextRequest) {
  const { auth, res } = await adminOnly(req);
  if (res) return res;
  const db = createServiceClient();
  const { conn, error } = await load(db, auth.org_id);
  if (error) {
    if (isNotSetUp(error)) return NextResponse.json({ ok: true });
    return safeError(error, { code: "sso_fetch_failed", message: "We couldn't load SSO settings right now. Please try again." });
  }
  if (!conn) return NextResponse.json({ ok: true });
  if (conn.provider_id) {
    try { await deleteSsoProvider(conn.provider_id); }
    catch (e) { if (e instanceof SsoProviderError) return providerErrorResponse(e); throw e; }
  }
  await db.from("sso_connections").delete().eq("org_id", auth.org_id);
  await invalidateSsoEnforcement(auth.org_id);
  await writeAuditLog(db, {
    org_id: auth.org_id, event_type: "org_settings_changed", actor_id: auth.user_id ?? null, actor_email: auth.actor_email ?? null,
    resource_type: "sso", resource_id: conn.provider_id ?? undefined, payload: { removed: true, idp: conn.idp_entity_id },
  });
  return NextResponse.json({ ok: true });
}
