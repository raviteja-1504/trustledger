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
import { syncAutoIncidents } from "@/lib/autoIncidents";
import { verifyApiKey, requirePermission } from "../_middleware";
import { writeAuditLog } from "@/lib/audit";
import { validateBody, ViolationOverrideSchema } from "@/lib/validation";
import { safeError } from "@/lib/errors";

const PAGE = 1000;
const MAX_ROWS = 20_000;

export async function GET(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });
  const { org_id } = auth;

  const db = createServiceClient();
  // One override per file per scan accumulates quickly; page past the 1000-row response cap so none are dropped
  // (a dropped "resolved" would show the file as open again).
  type Row = { violation_id: string; status: string; assigned_email: string | null; note: string | null; escalated: boolean; updated_at: string };
  const data: Row[] = [];
  for (let from = 0; from < MAX_ROWS; from += PAGE) {
    const { data: page, error } = await db
      .from("violation_overrides")
      .select("violation_id, status, assigned_email, note, escalated, updated_by, updated_at")
      .eq("org_id", org_id)
      .order("violation_id", { ascending: true })
      .range(from, from + PAGE - 1);
    if (error) return safeError(error, { code: "violation_status_fetch_failed", message: "We couldn't load violation status right now. Please try again." });
    data.push(...((page ?? []) as Row[]));
    if ((page ?? []).length < PAGE) break;
  }

  // The repository of each file's override (from its scan), so the page can keep an assignee on the file when a
  // newer push re-keys its violation -- the id names the scan, not the repo.
  const scanIds = [...new Set(data.map(r => r.violation_id.split("::")[1]).filter(s => !!s && /^[0-9a-f-]{36}$/i.test(s)))];
  const repoByScan = new Map<string, string>();
  for (let i = 0; i < scanIds.length; i += 200) {
    const { data: scans } = await db.from("scans").select("id, repo_full_name").eq("org_id", org_id).in("id", scanIds.slice(i, i + 200));
    for (const s of (scans ?? []) as { id: string; repo_full_name: string }[]) repoByScan.set(s.id, s.repo_full_name);
  }

  const overrides: Record<string, { status: string; assigned_email: string | null; note: string | null; escalated: boolean; updated_at: string; repo?: string }> = {};
  for (const row of data) {
    overrides[row.violation_id] = {
      status:         row.status,
      assigned_email: row.assigned_email,
      note:           row.note,
      escalated:      row.escalated,
      updated_at:     row.updated_at,
      repo:           repoByScan.get(row.violation_id.split("::")[1]),
    };
  }

  return NextResponse.json({ overrides }, { headers: { "Cache-Control": "private, no-store" } });
}

export async function PATCH(req: NextRequest) {
  const auth = await verifyApiKey(req);
  const { org_id, user_id, actor_email, error } = auth;
  if (error) return NextResponse.json({ error }, { status: 401 });
  const permErr = await requirePermission(auth, "can_resolve_violations");
  if (permErr) return NextResponse.json({ error: permErr }, { status: 403 });

  const validation = await validateBody(req, ViolationOverrideSchema);
  if (!validation.ok) return validation.response;
  const body = validation.data;

  const db = createServiceClient();

  // An assignee must be someone in this organisation: the reviewer list only offers members, and an arbitrary
  // address would put a finding in the hands of nobody who can act on it.
  if (body.assigned_email) {
    const { data: member } = await db.from("org_members").select("id")
      .eq("org_id", org_id).eq("email", body.assigned_email.toLowerCase()).maybeSingle();
    if (!member) return NextResponse.json({ error: "not_a_member", message: "Assign someone in your organisation." }, { status: 400 });
  }
  const { data: before } = await db.from("violation_overrides").select("status, assigned_email, escalated")
    .eq("org_id", org_id).eq("violation_id", body.violation_id).maybeSingle() as { data: { status: string | null; assigned_email: string | null; escalated: boolean | null } | null };

  // Only the fields the caller sent are written: a status change must not wipe the note, assignee or escalation
  // set earlier (an upsert leaves columns it isn't given untouched on update, and uses defaults on insert).
  // An empty string clears a note / assignee.
  const row: Record<string, unknown> = {
    violation_id: body.violation_id,
    status:       body.status,
    updated_by:   user_id ?? null,
    updated_at:   new Date().toISOString(),
  };
  if (body.assigned_email !== undefined) row.assigned_email = body.assigned_email ? body.assigned_email.toLowerCase() : null;
  if (body.note !== undefined)           row.note = body.note || null;
  if (body.escalated !== undefined)      row.escalated = body.escalated;
  const { error: upErr } = await db
    .from("violation_overrides")
    .upsert({ ...row, org_id }, { onConflict: "org_id,violation_id" });

  if (upErr) return safeError(upErr, { code: "violation_status_update_failed", message: "We couldn't update that violation. Please try again." });

  // A resolved (or reopened) finding can end or restart its auto-incident; keep incidents in step. Best-effort.
  await syncAutoIncidents(db, org_id);

  // "<risk>::<scan>::<path>" for a file's violation -- named in the audit entries so they say which file.
  const [, scanPart, ...pathParts] = body.violation_id.split("::");
  const fileRef = pathParts.length > 0 ? { scan_id: scanPart, file_path: pathParts.join("::") } : {};
  const audit = (event_type: "violation_resolved" | "violation_assigned" | "violation_escalated", payload: Record<string, unknown>) =>
    writeAuditLog(db, {
      org_id, event_type,
      actor_id:      user_id ?? null,
      actor_email:   actor_email ?? null,
      resource_type: "violation",
      resource_id:   body.violation_id,
      payload: { ...fileRef, ...payload },
    });

  if (body.status === "resolved" && before?.status !== "resolved") await audit("violation_resolved", { status: "resolved", note: body.note ?? null });
  // Who is responsible for a finding, and who flagged it for attention, are part of the record too.
  const assignedNow = row.assigned_email as string | null | undefined;
  if (assignedNow !== undefined && assignedNow !== (before?.assigned_email ?? null)) await audit("violation_assigned", { assigned_email: assignedNow });
  if (body.escalated !== undefined && body.escalated !== (before?.escalated ?? false)) await audit("violation_escalated", { escalated: body.escalated });

  return NextResponse.json({ ok: true });
}
