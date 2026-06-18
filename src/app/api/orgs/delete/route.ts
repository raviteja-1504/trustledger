/**
 * POST /api/orgs/delete
 * Permanently deletes the entire organisation — all data AND all members.
 * After this the admin will have no org membership and will be redirected
 * to /create-org to start fresh.
 * Admin only.
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey, requireRole } from "../../_middleware";
import { cacheDel, cacheKeys } from "@/lib/cache";

const DASHBOARD_CACHE_DAYS = [7, 30, 90];

export async function POST(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });
  const roleErr = requireRole(auth, "admin");
  if (roleErr) return NextResponse.json({ error: roleErr }, { status: 403 });

  const { org_id } = auth;
  const db = createServiceClient();

  // Delete via raw SQL using the service role to bypass all FK/RLS issues.
  // The JS client deletes fail silently when FK constraints or missing tables
  // cause errors — using rpc with a raw query guarantees the delete completes.
  const { error: deleteErr } = await db.rpc("delete_org_cascade", { target_org_id: org_id });

  if (deleteErr) {
    // rpc not available — fall back to sequential JS deletes
    // Delete by org_id directly — avoids FK subquery mismatches
    await db.from("attestations")      .delete().eq("org_id", org_id);
    await db.from("violations")        .delete().eq("org_id", org_id);
    await db.from("secret_findings")   .delete().eq("org_id", org_id);
    await db.from("scan_files")        .delete().eq("org_id", org_id);
    await db.from("scans")             .delete().eq("org_id", org_id);
    await db.from("repositories")      .delete().eq("org_id", org_id);
    await db.from("webhook_deliveries").delete().eq("org_id", org_id);
    await db.from("api_keys")          .delete().eq("org_id", org_id);
    await db.from("audit_log")         .delete().eq("org_id", org_id);
    await db.from("org_members")       .delete().eq("org_id", org_id);
    await db.from("organizations")     .delete().eq("id", org_id);
  }

  // Bust cache
  await Promise.all(DASHBOARD_CACHE_DAYS.map(d => cacheDel(cacheKeys.dashboard(org_id, d))));

  return NextResponse.json({ ok: true });
}
