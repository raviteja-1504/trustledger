/**
 * The organisation's scan queue.
 *
 *   GET  /api/scan-jobs          counts for the last 7 days, the jobs that need attention (failed, dead, stuck) and the latest jobs
 *   POST /api/scan-jobs { id }   replay a failed or dead job: the ORIGINAL job is queued again with fresh attempts
 *
 * Every member can look; replaying needs can_trigger_scans and the plan's scan allowance, like any other scan. A job that is
 * already queued, running or finished cannot be replayed (it would only be a duplicate).
 */
import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey, requirePermission } from "../_middleware";
import { queueOverview, resetForReplay } from "@/lib/scanJobs";
import { requeueJob } from "@/lib/queue";
import { checkScanAllowed } from "@/lib/planGate";
import { safeError } from "@/lib/errors";

export async function GET(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });
  const db = createServiceClient();
  return NextResponse.json(await queueOverview(db, auth.org_id), { headers: { "Cache-Control": "private, no-store" } });
}

export async function POST(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });
  const permErr = await requirePermission(auth, "can_trigger_scans");
  if (permErr) return NextResponse.json({ error: permErr }, { status: 403 });
  const body = await req.json().catch(() => ({})) as { id?: unknown };
  if (typeof body.id !== "string" || !body.id) return NextResponse.json({ error: "id_required" }, { status: 400 });

  const db = createServiceClient();
  // The same plan allowance as any other scan (a failed job stored no scan, so replaying it uses one).
  const { data: row } = await db.from("scan_jobs").select("repo_full_name").eq("id", body.id).eq("org_id", auth.org_id).maybeSingle() as { data: { repo_full_name: string } | null };
  if (!row) return NextResponse.json({ error: "job_not_found" }, { status: 404 });
  const verdict = await checkScanAllowed(db, auth.org_id, row.repo_full_name);
  if (!verdict.allowed) return NextResponse.json({ error: `plan_limit_${verdict.reason}`, message: `${verdict.title}. ${verdict.summary}` }, { status: 403 });

  const reset = await resetForReplay(db, auth.org_id, body.id);
  if ("error" in reset) {
    const status = reset.error === "not_found" ? 404 : reset.error === "not_replayable" ? 409 : 503;
    return NextResponse.json({ error: reset.error === "not_replayable" ? "job_not_replayable" : reset.error === "not_found" ? "job_not_found" : "queue_unavailable",
      message: reset.error === "not_replayable" ? "Only a failed job can be replayed; this one is queued, running or finished." : undefined }, { status });
  }
  try {
    await requeueJob(reset.job);
    return NextResponse.json({ ok: true, status: "queued" });
  } catch (err) {
    return safeError(err, { code: "replay_failed", message: "We couldn't queue that job again. It is still listed as failed; please try again." });
  }
}
