/**
 * Evidence Storage API
 * Wraps Supabase Storage for the evidence vault.
 * - GET  /api/storage?path=... → signed download URL
 * - POST /api/storage          → upload a file, return public/signed URL
 * - DELETE /api/storage?path=. → remove a file
 *
 * Bucket: "evidence" — created in Supabase Dashboard with private access.
 * RLS: files are scoped to {org_id}/{control_id}/{filename}
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey } from "../_middleware";
import { writeAuditLog } from "@/lib/audit";

const BUCKET = "evidence";

// ── GET — signed download URL ─────────────────────────────────────────────────

export async function GET(req: NextRequest) {
  const { org_id, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  const url  = new URL(req.url);
  const path = url.searchParams.get("path");

  if (!path) {
    // List files for this org
    const db = createServiceClient();
    const { data: files, error: listErr } = await db.storage
      .from(BUCKET)
      .list(org_id, { limit: 200, sortBy: { column: "created_at", order: "desc" } });

    if (listErr) return NextResponse.json({ error: listErr.message }, { status: 500 });

    // Generate signed URLs for all files
    const signed = await Promise.all(
      (files ?? []).map(async file => {
        const { data } = await db.storage
          .from(BUCKET)
          .createSignedUrl(`${org_id}/${file.name}`, 3600); // 1h expiry
        return {
          name:       file.name,
          size:       file.metadata?.size ?? 0,
          created_at: file.created_at,
          updated_at: file.updated_at,
          url:        data?.signedUrl ?? null,
        };
      }),
    );

    return NextResponse.json({ files: signed });
  }

  // Single file download URL
  const db = createServiceClient();
  const safePath = path.startsWith(org_id) ? path : `${org_id}/${path}`;
  const { data, error: signErr } = await db.storage
    .from(BUCKET)
    .createSignedUrl(safePath, 3600);

  if (signErr) return NextResponse.json({ error: signErr.message }, { status: 404 });
  return NextResponse.json({ url: data.signedUrl });
}

// ── POST — upload file ────────────────────────────────────────────────────────

export async function POST(req: NextRequest) {
  const { org_id, user_id, actor_email, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  const formData = await req.formData();
  const file     = formData.get("file") as File | null;
  const path     = (formData.get("path") as string | null) ?? "";
  const label    = (formData.get("label") as string | null) ?? "";

  if (!file) return NextResponse.json({ error: "missing_file" }, { status: 400 });

  const safeName  = file.name.replace(/[^a-zA-Z0-9._-]/g, "_");
  const storagePath = `${org_id}/${path ? `${path}/` : ""}${Date.now()}_${safeName}`;

  const db = createServiceClient();
  const { error: upErr } = await db.storage
    .from(BUCKET)
    .upload(storagePath, file, {
      contentType: file.type || "application/octet-stream",
      upsert:      false,
    });

  if (upErr) return NextResponse.json({ error: upErr.message }, { status: 500 });

  const { data: signed } = await db.storage
    .from(BUCKET)
    .createSignedUrl(storagePath, 3600);

  await writeAuditLog(db, {
    org_id,
    event_type:    "attestation", // reuse for evidence uploads
    actor_id:      user_id ?? null,
    actor_email:   actor_email ?? null,
    resource_type: "evidence",
    resource_id:   storagePath,
    payload: { filename: file.name, size: file.size, label, path: storagePath },
  });

  return NextResponse.json({
    path:  storagePath,
    name:  file.name,
    size:  file.size,
    url:   signed?.signedUrl ?? null,
  });
}

// ── DELETE — remove file ──────────────────────────────────────────────────────

export async function DELETE(req: NextRequest) {
  const { org_id, user_id, actor_email, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  const url      = new URL(req.url);
  const filePath = url.searchParams.get("path");
  if (!filePath) return NextResponse.json({ error: "missing_path" }, { status: 400 });

  const safePath = filePath.startsWith(org_id) ? filePath : `${org_id}/${filePath}`;
  const db       = createServiceClient();

  const { error: delErr } = await db.storage.from(BUCKET).remove([safePath]);
  if (delErr) return NextResponse.json({ error: delErr.message }, { status: 500 });

  await writeAuditLog(db, {
    org_id,
    event_type:    "report_generated",
    actor_id:      user_id ?? null,
    actor_email:   actor_email ?? null,
    resource_type: "evidence",
    resource_id:   safePath,
    payload: { action: "deleted", path: safePath },
  });

  return NextResponse.json({ ok: true });
}
