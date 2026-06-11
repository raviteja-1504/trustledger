import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey } from "../_middleware";
import { writeAuditLog } from "@/lib/audit";
import crypto from "crypto";

export async function GET(req: NextRequest) {
  const { org_id, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  const db = createServiceClient();
  const { data } = await db
    .from("api_keys")
    .select("id, name, key_prefix, created_at, last_used, expires_at, revoked")
    .eq("org_id", org_id)
    .order("created_at", { ascending: false });

  return NextResponse.json({ keys: data ?? [] });
}

export async function POST(req: NextRequest) {
  const { org_id, user_id, actor_email, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  const body = await req.json() as { name: string; expires_days?: number };
  if (!body.name) return NextResponse.json({ error: "missing_name" }, { status: 400 });

  // Generate the key: "tl_live_" + 40 random hex chars
  const rawKey   = `tl_live_${crypto.randomBytes(20).toString("hex")}`;
  const keyHash  = crypto.createHash("sha256").update(rawKey).digest("hex");
  const prefix   = rawKey.slice(0, 16) + "...";
  const expiresAt = body.expires_days
    ? new Date(Date.now() + body.expires_days * 86400_000).toISOString()
    : null;

  const db = createServiceClient();
  const { data, error: insErr } = await db
    .from("api_keys")
    .insert({ org_id, name: body.name, key_hash: keyHash, key_prefix: prefix, created_by: user_id ?? null, expires_at: expiresAt })
    .select("id, name, key_prefix, created_at")
    .single();

  if (insErr) return NextResponse.json({ error: "api_key_create_failed" }, { status: 500 });

  await writeAuditLog(db, {
    org_id, event_type: "api_key_created",
    actor_id: user_id ?? null, actor_email: actor_email ?? null,
    resource_type: "api_key", resource_id: data!.id,
    payload: { name: body.name },
  });

  // Return raw key ONCE — never stored
  return NextResponse.json({ ...data, raw_key: rawKey });
}

export async function DELETE(req: NextRequest) {
  const { org_id, user_id, actor_email, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  const body = await req.json() as { id: string };
  if (!body.id) return NextResponse.json({ error: "missing_id" }, { status: 400 });

  const db = createServiceClient();
  await db.from("api_keys").update({ revoked: true }).eq("id", body.id).eq("org_id", org_id);

  await writeAuditLog(db, {
    org_id, event_type: "api_key_revoked",
    actor_id: user_id ?? null, actor_email: actor_email ?? null,
    resource_type: "api_key", resource_id: body.id,
    payload: {},
  });

  return NextResponse.json({ ok: true });
}
