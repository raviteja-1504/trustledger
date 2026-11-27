/**
 * POST /api/audit/forks -- an admin records that the forks in the audit chain were reviewed.
 *
 * A fork (two entries with the same parent) cannot be repaired: audit entries are immutable. What can be done is to look at
 * them and say so, durably and tamper-evidently. This writes one "audit_forks_reviewed" entry INTO the chain, naming the
 * exact entries reviewed; chain verification then counts those forks as reviewed (a later fork is not covered), and
 * checkpoints can be signed again. It never papers over damage: only a chain whose ONLY problem is unreviewed forks is accepted.
 */
import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey, requireRole, requirePermission } from "../../_middleware";
import { checkAuditChain, loadAuditRows, writeAuditLog } from "@/lib/audit";
import { safeError } from "@/lib/errors";

export async function POST(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });
  const roleErr = requireRole(auth, "admin") ?? await requirePermission(auth, "can_view_audit_log");
  if (roleErr) return NextResponse.json({ error: roleErr }, { status: 403 });

  const body = await req.json().catch(() => ({})) as { note?: unknown };
  const note = typeof body.note === "string" ? body.note.trim().slice(0, 500) : "";

  const db = createServiceClient();
  try {
    const { rows, complete } = await loadAuditRows(db, auth.org_id);
    if (!complete) return NextResponse.json({ error: "audit_unreadable", message: "The audit log could not be read in full, so nothing was recorded." }, { status: 503 });
    const chain = checkAuditChain(rows);
    if (chain.status === "VALID") return NextResponse.json({ ok: true, reviewed: 0 });
    if (chain.status !== "FORK_DETECTED") {
      return NextResponse.json({ error: "chain_not_reviewable", message: "The audit log has a problem other than forks. That has to be investigated; it cannot be marked as reviewed." }, { status: 409 });
    }
    const ids = chain.unreviewed_fork_ids ?? [];
    await writeAuditLog(db, {
      org_id: auth.org_id, event_type: "audit_forks_reviewed", actor_id: auth.user_id ?? null, actor_email: auth.actor_email ?? null,
      resource_type: "audit_log", payload: { fork_entry_ids: ids, count: ids.length, ...(note ? { note } : {}) },
    }, { strict: true });
    return NextResponse.json({ ok: true, reviewed: ids.length });
  } catch (err) {
    return safeError(err, { code: "audit_fork_review_failed", message: "We couldn't record the review. Please try again." });
  }
}
