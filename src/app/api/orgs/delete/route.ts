/**
 * Organisation deletion: a request, a waiting period, an explicit execution.
 *
 *   GET  /api/orgs/delete                     what would be deleted and kept, the exports to take first, the open request (if any)
 *   POST /api/orgs/delete { action: "request", confirm, code? }   start the waiting period (confirm = the organisation's slug)
 *   POST /api/orgs/delete { action: "cancel" }                    stop it (any time before it runs; also after a failed run)
 *   POST /api/orgs/delete { action: "execute", confirm, code? }   delete, once the waiting period is over
 *
 * Admin only. Requesting and executing also need a step-up (lib/stepUp.ts): a current authenticator code, or a sign-in within
 * the last 10 minutes. Nothing is scheduled -- the waiting period only means "not before"; a person runs the deletion.
 *
 * The deletion itself is one database transaction (delete_org_cascade): it completes or changes nothing, so a failure leaves
 * the request "failed" (and the organisation intact) to be run again or cancelled -- never half done. Immutable evidence (audit
 * log, attestations, signed checkpoints) is retained against an anonymised organisation record.
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey, requireRole } from "../../_middleware";
import { cacheDel, cacheKeys } from "@/lib/cache";
import { requireAudit } from "@/lib/auditRequired";
import { requireStepUp } from "@/lib/stepUp";
import { deletionDelayHours, deletionPreview, openRequest } from "@/lib/orgDeletion";
import { logger } from "@/lib/logger";

const DASHBOARD_CACHE_DAYS = [7, 30, 90];
const bearerOf = (req: NextRequest) => { const h = req.headers.get("Authorization") ?? ""; return h.startsWith("Bearer ") ? h.slice(7) : null; };

async function authorize(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return { ok: false as const, res: NextResponse.json({ error: auth.error }, { status: 401 }) };
  const roleErr = requireRole(auth, "admin");
  if (roleErr) return { ok: false as const, res: NextResponse.json({ error: roleErr }, { status: 403 }) };
  return { ok: true as const, auth };
}

export async function GET(req: NextRequest) {
  const a = await authorize(req);
  if (!a.ok) return a.res;
  const { org_id } = a.auth;
  const db = createServiceClient();

  const [{ data: org }, preview, request, { data: twoFa }] = await Promise.all([
    db.from("organizations").select("name, slug").eq("id", org_id).maybeSingle() as unknown as Promise<{ data: { name: string; slug: string } | null }>,
    deletionPreview(db, org_id),
    openRequest(db, org_id),
    a.auth.user_id ? db.from("user_2fa").select("enabled").eq("user_id", a.auth.user_id).maybeSingle() as unknown as Promise<{ data: { enabled?: boolean } | null }> : Promise.resolve({ data: null }),
  ]);
  return NextResponse.json({
    organization: org ? { name: org.name, slug: org.slug } : null,
    preview, request, delay_hours: deletionDelayHours(),
    step_up: twoFa?.enabled ? "totp" : "recent_signin",
  }, { headers: { "Cache-Control": "private, no-store" } });
}

export async function POST(req: NextRequest) {
  const a = await authorize(req);
  if (!a.ok) return a.res;
  const { auth } = a;
  const { org_id } = auth;
  const db = createServiceClient();

  const body = await req.json().catch(() => ({})) as { action?: string; confirm?: unknown; code?: unknown };
  const actor = { actor_id: auth.user_id ?? null, actor_email: auth.actor_email ?? null };

  // ── request ────────────────────────────────────────────────────────────────
  if (body.action === "request") {
    const { data: org } = await db.from("organizations").select("slug").eq("id", org_id).maybeSingle() as { data: { slug: string } | null };
    if (!org || body.confirm !== org.slug) {
      return NextResponse.json({ error: "confirmation_mismatch", message: "Type the organisation's name exactly as shown to confirm." }, { status: 400 });
    }
    if (await openRequest(db, org_id)) return NextResponse.json({ error: "already_requested" }, { status: 409 });
    const step = await requireStepUp(db, bearerOf(req), auth.user_id, body.code);
    if (!step.ok) return NextResponse.json({ error: step.error, message: step.message }, { status: step.status });

    const delay = deletionDelayHours();
    const executeAfter = new Date(Date.now() + delay * 3600_000).toISOString();
    const preview = await deletionPreview(db, org_id);
    const { data: created, error: insErr } = await db.from("org_deletion_requests").insert({
      org_id, requested_by: auth.user_id ?? null, requested_by_email: auth.actor_email ?? null, execute_after: executeAfter, status: "pending",
      preview: { deleted: preview.deleted, retained: preview.retained },
    }).select("id").single() as { data: { id: string } | null; error: { code?: string } | null };
    if (insErr || !created) return NextResponse.json({ error: insErr?.code === "23505" ? "already_requested" : "request_failed" }, { status: insErr?.code === "23505" ? 409 : 500 });

    const failed = await requireAudit(db, {
      org_id, event_type: "org_deletion_requested", ...actor, resource_type: "organization", resource_id: org_id,
      payload: { request_id: created.id, execute_after: executeAfter, delay_hours: delay, step_up: step.method },
    }, { undo: async () => { const { error } = await db.from("org_deletion_requests").delete().eq("id", created.id).eq("org_id", org_id); if (error) throw error; } });
    if (failed) return failed;
    return NextResponse.json({ ok: true, status: "pending", execute_after: executeAfter, delay_hours: delay });
  }

  // ── cancel ─────────────────────────────────────────────────────────────────
  if (body.action === "cancel") {
    const open = await openRequest(db, org_id);
    if (!open) return NextResponse.json({ error: "no_open_request" }, { status: 404 });
    const { data: cancelled } = await db.from("org_deletion_requests")
      .update({ status: "cancelled", cancelled_at: new Date().toISOString(), cancelled_by_email: auth.actor_email ?? null })
      .eq("id", open.id).eq("org_id", org_id).in("status", ["pending", "failed"]).select("id") as { data: Array<{ id: string }> | null };
    if (!cancelled || cancelled.length === 0) return NextResponse.json({ error: "cannot_cancel", message: "The deletion is running and can no longer be cancelled." }, { status: 409 });
    // Cancelling stays in force even if it cannot be recorded (the safe direction); the caller is told it was not recorded.
    const failed = await requireAudit(db, { org_id, event_type: "org_deletion_cancelled", ...actor, resource_type: "organization", resource_id: org_id, payload: { request_id: open.id } });
    if (failed) return failed;
    return NextResponse.json({ ok: true, status: "cancelled" });
  }

  // ── execute ────────────────────────────────────────────────────────────────
  if (body.action === "execute") {
    const open = await openRequest(db, org_id);
    if (!open) return NextResponse.json({ error: "no_open_request", message: "Request the deletion first." }, { status: 404 });
    if (open.status === "executing") return NextResponse.json({ error: "already_running" }, { status: 409 });
    if (Date.now() < Date.parse(open.execute_after)) {
      return NextResponse.json({ error: "waiting_period", execute_after: open.execute_after, message: "The waiting period is not over yet. You can cancel until then." }, { status: 409 });
    }
    const { data: org } = await db.from("organizations").select("slug").eq("id", org_id).maybeSingle() as { data: { slug: string } | null };
    if (!org || body.confirm !== org.slug) return NextResponse.json({ error: "confirmation_mismatch", message: "Type the organisation's name exactly as shown to confirm." }, { status: 400 });
    const step = await requireStepUp(db, bearerOf(req), auth.user_id, body.code);
    if (!step.ok) return NextResponse.json({ error: step.error, message: step.message }, { status: step.status });

    // Claim it: only one execution at a time, and only from pending / failed.
    const previous = open.status;
    const { data: claimed } = await db.from("org_deletion_requests")
      .update({ status: "executing", started_at: new Date().toISOString(), error: null })
      .eq("id", open.id).eq("org_id", org_id).in("status", ["pending", "failed"]).select("id") as { data: Array<{ id: string }> | null };
    if (!claimed || claimed.length === 0) return NextResponse.json({ error: "already_running" }, { status: 409 });
    const release = async (status: string, error: string | null) => { await db.from("org_deletion_requests").update({ status, error }).eq("id", open.id).eq("org_id", org_id); };

    // Recorded BEFORE the deletion: nothing is deleted unless this is on record.
    const started = await requireAudit(db, {
      org_id, event_type: "org_deletion_started", ...actor, resource_type: "organization", resource_id: org_id, payload: { request_id: open.id, step_up: step.method },
    }, { undo: () => release(previous, null) });
    if (started) return started;

    // One transaction (delete_org_cascade): it completes or changes nothing. No row-by-row fallback.
    const { error: deleteErr } = await db.rpc("delete_org_cascade", { target_org_id: org_id });
    if (deleteErr) {
      const missing = deleteErr.code === "PGRST202" || deleteErr.code === "42883" || /could not find the function/i.test(deleteErr.message ?? "");
      logger.error("Org deletion failed", { event: "org_delete_failed", org_id, request_id: open.id, error: deleteErr.message, code: deleteErr.code });
      await release("failed", (missing ? "delete function missing" : (deleteErr.message ?? "deletion failed")).slice(0, 300)).catch(() => {});
      return NextResponse.json({ error: missing ? "org_delete_unavailable" : "org_delete_failed", request_status: "failed", message: "Nothing was deleted. You can run it again or cancel." }, { status: 500 });
    }

    await db.from("org_deletion_requests").update({ status: "completed", completed_at: new Date().toISOString(), error: null }).eq("id", open.id).eq("org_id", org_id);
    // The deletion is done and cannot be undone: a failure to record the completion is logged loudly, not reported as a failure.
    const completionFailed = await requireAudit(db, { org_id, event_type: "org_deleted", ...actor, resource_type: "organization", resource_id: org_id, payload: { request_id: open.id } });
    if (completionFailed) logger.error("Org deleted but completion audit entry failed", { event: "org_delete_audit_failed", org_id });
    await Promise.all(DASHBOARD_CACHE_DAYS.map(d => cacheDel(cacheKeys.dashboard(org_id, d))));
    await cacheDel(cacheKeys.dependencies(org_id));
    return NextResponse.json({ ok: true, status: "completed" });
  }

  return NextResponse.json({ error: "action_required", valid: ["request", "cancel", "execute"] }, { status: 400 });
}
