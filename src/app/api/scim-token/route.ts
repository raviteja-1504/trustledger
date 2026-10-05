/**
 * The organisation's SCIM token (built-in admins only: it can add and remove members).
 *
 * GET    /api/scim-token → { exists, prefix, created_at, last_used_at, base_url, verified_domains }
 * POST   /api/scim-token → creates or rotates it; the token is returned ONCE (only its hash is stored)
 * DELETE /api/scim-token → revokes it
 */
import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey, requireRole } from "../_middleware";
import { writeAuditLog } from "@/lib/audit";
import { safeError } from "@/lib/errors";
import { newScimToken } from "@/lib/scimAuth";

const SETUP_HINT = "SCIM tokens need database migration 20261007_scim_tokens.";

async function adminOnly(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return { auth, res: NextResponse.json({ error: auth.error }, { status: 401 }) };
  const roleErr = requireRole(auth, "admin");
  if (roleErr) return { auth, res: NextResponse.json({ error: roleErr }, { status: 403 }) };
  return { auth, res: null };
}

const notSetUp = (e: { code?: string; message?: string } | null | undefined) => !!e && (e.code === "42P01" || /scim_tokens/.test(e.message ?? ""));

export async function GET(req: NextRequest) {
  const { auth, res } = await adminOnly(req);
  if (res) return res;
  const db = createServiceClient();
  const [{ data: row, error }, { data: domains }] = await Promise.all([
    db.from("scim_tokens").select("token_prefix, created_at, last_used_at").eq("org_id", auth.org_id).maybeSingle(),
    db.from("sso_domains").select("domain, verified_at").eq("org_id", auth.org_id),
  ]);
  if (error && !notSetUp(error)) return safeError(error, { code: "scim_token_fetch_failed", message: "We couldn't load the SCIM settings. Please try again." });
  const r = row as { token_prefix: string; created_at: string; last_used_at: string | null } | null;
  return NextResponse.json({
    set_up: !error,
    ...(error ? { message: SETUP_HINT } : {}),
    exists: !!r,
    prefix: r?.token_prefix ?? null,
    created_at: r?.created_at ?? null,
    last_used_at: r?.last_used_at ?? null,
    base_url: `${new URL(req.url).origin}/api/scim/v2`,
    verified_domains: ((domains ?? []) as Array<{ domain: string; verified_at: string | null }>).filter(d => d.verified_at).map(d => d.domain),
  });
}

export async function POST(req: NextRequest) {
  const { auth, res } = await adminOnly(req);
  if (res) return res;
  const db = createServiceClient();
  const { token, hash, prefix } = newScimToken();
  // One token per org: creating a new one replaces (and so revokes) the old one.
  const { error } = await db.from("scim_tokens").upsert(
    { org_id: auth.org_id, token_hash: hash, token_prefix: prefix, created_by: auth.user_id ?? null, created_at: new Date().toISOString(), last_used_at: null },
    { onConflict: "org_id" },
  );
  if (error) {
    if (notSetUp(error)) return NextResponse.json({ error: "scim_not_set_up", message: SETUP_HINT }, { status: 422 });
    return safeError(error, { code: "scim_token_create_failed", message: "We couldn't create a SCIM token. Please try again." });
  }
  await writeAuditLog(db, {
    org_id: auth.org_id, event_type: "api_key_created", actor_id: auth.user_id ?? null, actor_email: auth.actor_email ?? null,
    resource_type: "scim_token", resource_id: prefix, payload: { prefix },
  });
  return NextResponse.json({ token, prefix }, { status: 201 });
}

export async function DELETE(req: NextRequest) {
  const { auth, res } = await adminOnly(req);
  if (res) return res;
  const db = createServiceClient();
  const { error } = await db.from("scim_tokens").delete().eq("org_id", auth.org_id);
  if (error && !notSetUp(error)) return safeError(error, { code: "scim_token_revoke_failed", message: "We couldn't revoke the SCIM token. Please try again." });
  await writeAuditLog(db, {
    org_id: auth.org_id, event_type: "api_key_revoked", actor_id: auth.user_id ?? null, actor_email: auth.actor_email ?? null,
    resource_type: "scim_token", payload: {},
  });
  return NextResponse.json({ ok: true });
}
