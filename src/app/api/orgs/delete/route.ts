/**
 * POST /api/orgs/delete
 * Permanently deletes the organisation's data and members. The immutable audit trail, attestations and audit
 * checkpoints are retained against an anonymised organisation record (see the migration for the policy).
 * Fails with 500 -- never reports success -- if the database function is missing or the deletion does not complete.
 * After this the admin will have no org membership and will be redirected
 * to /create-org to start fresh.
 * Admin only.
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey, requireRole } from "../../_middleware";
import { cacheDel, cacheKeys } from "@/lib/cache";
import { writeAuditLog } from "@/lib/audit";
import { logger } from "@/lib/logger";

const DASHBOARD_CACHE_DAYS = [7, 30, 90];

export async function POST(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });
  const roleErr = requireRole(auth, "admin");
  if (roleErr) return NextResponse.json({ error: roleErr }, { status: 403 });

  const { org_id } = auth;
  const db = createServiceClient();

  // 1. Record the request first, in the immutable audit trail, and refuse to go on if that cannot be written:
  //    the trail is retained when the organisation goes (see the retention policy in the migration).
  try {
    await writeAuditLog(db, {
      org_id, event_type: "org_deletion_requested", actor_id: auth.user_id ?? null, actor_email: auth.actor_email ?? null,
      resource_type: "organization", resource_id: org_id, payload: {},
    }, { strict: true });
  } catch (e) {
    logger.error("Org deletion not started: audit entry could not be written", { event: "org_delete_audit_failed", org_id, error: (e as Error).message });
    return NextResponse.json({ error: "audit_unavailable" }, { status: 500 });
  }

  // 2. Delete in ONE database transaction (supabase/migrations/20261127_delete_org_cascade.sql). There is no
  //    fallback: row-by-row deletes from here cannot be made atomic, and the immutable tables silently ignore
  //    them, which is how organisations used to end up half deleted with a success response.
  const { error: deleteErr } = await db.rpc("delete_org_cascade", { target_org_id: org_id });
  if (deleteErr) {
    const missing = deleteErr.code === "PGRST202" || deleteErr.code === "42883" || /could not find the function/i.test(deleteErr.message ?? "");
    logger.error("Org deletion failed", { event: "org_delete_failed", org_id, error: deleteErr.message, code: deleteErr.code });
    return NextResponse.json(
      { error: missing ? "org_delete_unavailable" : "org_delete_failed" },
      { status: deleteErr.code === "P0002" ? 404 : 500 },
    );
  }

  // 3. Completion record (best effort: the deletion has already happened and cannot be undone).
  try {
    await writeAuditLog(db, {
      org_id, event_type: "org_deleted", actor_id: auth.user_id ?? null, actor_email: auth.actor_email ?? null,
      resource_type: "organization", resource_id: org_id, payload: {},
    }, { strict: true });
  } catch (e) {
    logger.error("Org deleted but completion audit entry failed", { event: "org_delete_audit_failed", org_id, error: (e as Error).message });
  }

  // Bust cache
  await Promise.all(DASHBOARD_CACHE_DAYS.map(d => cacheDel(cacheKeys.dashboard(org_id, d))));
  await cacheDel(cacheKeys.dependencies(org_id));

  return NextResponse.json({ ok: true });
}
