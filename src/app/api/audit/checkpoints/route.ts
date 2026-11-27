import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey, requirePermission } from "../../_middleware";
import { createCheckpoint, exportAuditBundle, loadCheckpoints, verifyOrgCheckpoints } from "@/lib/auditCheckpoint";
import { writeAuditLog } from "@/lib/audit";
import { safeError } from "@/lib/errors";

const NO_STORE = { "Cache-Control": "private, no-store" };

/**
 * GET /api/audit/checkpoints          → the org's signed checkpoints and the result of verifying the audit log against
 *                                       them (status VALID / TRUNCATED / HISTORY_MODIFIED / CHECKPOINT_INVALID / ...).
 * GET /api/audit/checkpoints?bundle=1 → the audit entries, checkpoints and public keys as one JSON file that
 *                                       scripts/verify-audit-bundle.cjs verifies without this application.
 *
 * Checkpoints held only in this database cannot prove the database itself was not rewritten: keep exported bundles,
 * or set AUDIT_CHECKPOINT_SINK_URL, so a copy exists somewhere its owner cannot change.
 */
export async function GET(req: NextRequest) {
  const auth = await verifyApiKey(req);
  const { org_id, error } = auth;
  if (error) return NextResponse.json({ error }, { status: 401 });
  const permErr = await requirePermission(auth, "can_view_audit_log");
  if (permErr) return NextResponse.json({ error: permErr }, { status: 403 });

  const db = createServiceClient();
  try {
    if (req.nextUrl.searchParams.get("bundle") === "1") {
      const bundle = await exportAuditBundle(db, org_id);
      return new NextResponse(JSON.stringify(bundle), {
        headers: { ...NO_STORE, "Content-Type": "application/json", "Content-Disposition": `attachment; filename="audit-bundle-${org_id}.json"` },
      });
    }
    const [verification, checkpoints] = await Promise.all([verifyOrgCheckpoints(db, org_id), loadCheckpoints(db, org_id)]);
    return NextResponse.json({ verification, checkpoints }, { headers: NO_STORE });
  } catch (err) {
    return safeError(err, { code: "audit_checkpoints_failed", message: "We couldn't load the audit checkpoints right now. Please try again." });
  }
}

/** POST /api/audit/checkpoints → record a checkpoint now (unless nothing changed, or the log already fails verification). */
export async function POST(req: NextRequest) {
  const auth = await verifyApiKey(req);
  const { org_id, error } = auth;
  if (error) return NextResponse.json({ error }, { status: 401 });
  const permErr = await requirePermission(auth, "can_view_audit_log");
  if (permErr) return NextResponse.json({ error: permErr }, { status: 403 });

  const db = createServiceClient();
  try {
    const result = await createCheckpoint(db, org_id);
    if (result.created) {
      // audit: best-effort (checkpoint bookkeeping, not a security decision: not one of the actions that must fail without a record)
      await writeAuditLog(db, {
        org_id, event_type: "org_settings_changed", actor_id: auth.user_id ?? null, actor_email: auth.actor_email ?? null,
        resource_type: "audit_checkpoint", resource_id: String(result.checkpoint.payload.sequence),
        payload: { sequence: result.checkpoint.payload.sequence, entry_count: result.checkpoint.payload.entry_count, payload_hash: result.checkpoint.payload_hash, external: result.external },
      });
    }
    return NextResponse.json(result, { status: result.created ? 201 : 200, headers: NO_STORE });
  } catch (err) {
    return safeError(err, { code: "audit_checkpoint_failed", message: "We couldn't record an audit checkpoint right now. Please try again." });
  }
}
