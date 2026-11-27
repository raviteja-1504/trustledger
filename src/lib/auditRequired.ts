/**
 * Writing an audit entry that MUST exist (REQUIRED_AUDIT_EVENTS in lib/audit.ts).
 *
 * writeAuditLog() alone is best effort: if the insert fails it logs and moves on, so the action would be reported as a success
 * with no record of it. For a required event the route calls requireAudit() right after the action and returns its response
 * when it is not null:
 *
 *     const failed = await requireAudit(db, { org_id, event_type: "api_key_created", ... }, { undo: () => removeTheKey() });
 *     if (failed) return failed;
 *
 * If the entry cannot be written, `undo` (when given) reverses the action, and the caller gets a 500 "audit_unavailable"
 * either way -- never a success. `action_completed` in the body says whether the action is still in effect, so a client does
 * not blindly repeat something that happened.
 */
import { NextResponse } from "next/server";
import type { SupabaseClient } from "@supabase/supabase-js";
import type { Database } from "@/types/supabase";
import { writeAuditLog, type AuditEntry } from "@/lib/audit";
import { logger } from "@/lib/logger";

export async function requireAudit(
  db: SupabaseClient<Database>, entry: AuditEntry, opts: { undo?: () => PromiseLike<unknown> | unknown } = {},
): Promise<NextResponse | null> {
  try {
    await writeAuditLog(db, entry, { strict: true });
    return null;
  } catch (e) {
    let undone = false;
    if (opts.undo) {
      try { await opts.undo(); undone = true; }
      catch (undoErr) { logger.error("Could not undo an action whose audit entry failed", { event: "audit_undo_failed", org_id: entry.org_id, event_type: entry.event_type, error: undoErr instanceof Error ? undoErr.message : String(undoErr) }); }
    }
    logger.error("Required audit entry not written", { event: "audit_required_failed", org_id: entry.org_id, event_type: entry.event_type, undone, error: e instanceof Error ? e.message : String(e) });
    return NextResponse.json({
      error: "audit_unavailable",
      action_completed: !undone,
      message: undone
        ? "This was not done: it could not be recorded in the audit log. Please try again."
        : "This took effect, but it could not be recorded in the audit log, so it is reported as failed. Check the Audit page before repeating it, and contact support if this continues.",
    }, { status: 500 });
  }
}
