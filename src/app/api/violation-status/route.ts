/**
 * Violation Status Overrides API
 *
 * GET   /api/violation-status → all status overrides for the org (real DB read)
 * PATCH /api/violation-status → set status/note/assignee for one violation (real DB write)
 *
 * "Violations" shown on the Violations page and the Sidebar badge are derived
 * live from dashboard data (deriveViolations() in src/lib/violations.ts) --
 * some of them (deploy_blocked, ai_threshold, no_reviewer) are repo-level
 * rollups with no single row to attach a status to, so there's no natural
 * place in the existing `violations` table to persist "resolved" for all of
 * them uniformly. Previously that status lived ONLY in localStorage
 * (tl_violation_statuses), which is exactly why resolving a violation on one
 * device/browser never showed up on another. This table stores the override
 * keyed by the same synthetic violation id the client already computes, so
 * it's a real, org-scoped, server-side source of truth instead.
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey } from "../_middleware";
import { writeAuditLog } from "@/lib/audit";
import { validateBody, ViolationOverrideSchema } from "@/lib/validation";
import { safeError } from "@/lib/errors";

export async function GET(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });
  const { org_id } = auth;

  const db = createServiceClient();
  const { data, error } = await db
    .from("violation_overrides")
    .select("violation_id, status, assigned_email, note, escalated, updated_by, updated_at")
    .eq("org_id", org_id);

  if (error) return safeError(error, { code: "violation_status_fetch_failed", message: "We couldn't load violation status right now. Please try again." });

  const overrides: Record<string, { status: string; assigned_email: string | null; note: string | null; escalated: boolean; updated_at: string }> = {};
  for (const row of data ?? []) {
    overrides[row.violation_id] = {
      status:         row.status,
      assigned_email: row.assigned_email,
      note:           row.note,
      escalated:      row.escalated,
      updated_at:     row.updated_at,
    };
  }

  return NextResponse.json({ overrides });
}

export async function PATCH(req: NextRequest) {
  const { org_id, user_id, actor_email, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  const validation = await validateBody(req, ViolationOverrideSchema);
  if (!validation.ok) return validation.response;
  const body = validation.data;

  const db = createServiceClient();

  const { error: upErr } = await db
    .from("violation_overrides")
    .upsert({
      org_id,
      violation_id:   body.violation_id,
      status:         body.status,
      assigned_email: body.assigned_email ?? null,
      note:           body.note ?? null,
      escalated:      body.escalated ?? false,
      updated_by:     user_id ?? null,
      updated_at:     new Date().toISOString(),
    }, { onConflict: "org_id,violation_id" });

  if (upErr) return safeError(upErr, { code: "violation_status_update_failed", message: "We couldn't update that violation. Please try again." });

  if (body.status === "resolved") {
    await writeAuditLog(db, {
      org_id,
      event_type:    "violation_resolved",
      actor_id:      user_id ?? null,
      actor_email:   actor_email ?? null,
      resource_type: "violation",
      resource_id:   body.violation_id,
      payload: { note: body.note ?? null },
    });
  }

  return NextResponse.json({ ok: true });
}
