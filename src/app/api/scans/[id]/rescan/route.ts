/**
 * Rescan API
 *
 * POST /api/scans/:id/rescan → queue a full rescan of this scan's PR with the current engine.
 *
 * Used after an engine upgrade (the PR page shows when a scan came from an older engine), after triage
 * decisions (they apply to merge gating from the next scan), or after a degraded scan. Goes through the
 * same queue and worker as a webhook scan, at GitHub's current head of the PR, with a fresh check run so the
 * PR's merge gate reflects the new result. At most one rescan per PR per minute.
 */
import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey, requirePermission } from "../../../_middleware";
import { writeAuditLog } from "@/lib/audit";
import { safeError } from "@/lib/errors";
import { enqueueScan } from "@/lib/queue";
import { getInstallationToken, getPRHeadSha, createCheckRun } from "@/lib/github";
import { runWithTrace, traceIdFrom, currentTrace } from "@/lib/trace";
import { recordEvent } from "@/lib/opsEvents";

const MIN_INTERVAL_MS = 60_000;

export async function POST(req: NextRequest, ctx: { params: { id: string } }) {
  return runWithTrace({ trace_id: traceIdFrom(req.headers.get("x-request-id")) }, () => handle(req, ctx));
}

async function handle(req: NextRequest, { params }: { params: { id: string } }) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });
  const permErr = await requirePermission(auth, "can_trigger_scans");
  if (permErr) return NextResponse.json({ error: permErr }, { status: 403 });
  const db = createServiceClient();

  const { data: scan } = await db
    .from("scans")
    .select("id, repo_full_name, pr_number, commit_sha, branch, pr_author, installation_id")
    .eq("id", params.id)
    .eq("org_id", auth.org_id)
    .single();
  if (!scan) return NextResponse.json({ error: "scan_not_found" }, { status: 404 });
  if (!scan.installation_id || !scan.pr_number) {
    return NextResponse.json({ error: "rescan_unavailable", message: "This scan didn't come from the GitHub App, so it can't be rescanned from here. Submit it again through the API." }, { status: 409 });
  }

  const { data: recent } = await db
    .from("scans")
    .select("created_at")
    .eq("org_id", auth.org_id)
    .eq("repo_full_name", scan.repo_full_name)
    .eq("pr_number", scan.pr_number)
    .order("created_at", { ascending: false })
    .limit(1);
  const last = recent?.[0]?.created_at ? Date.parse(recent[0].created_at) : 0;
  if (Date.now() - last < MIN_INTERVAL_MS) {
    return NextResponse.json({ error: "rescan_too_soon", message: "This PR was scanned less than a minute ago. Try again shortly." }, { status: 429 });
  }

  try {
    const [owner, repo] = scan.repo_full_name.split("/");
    const { token } = await getInstallationToken(scan.installation_id);
    // Rescan what the PR is NOW -- a stored commit the PR has moved past would be skipped as superseded.
    const headSha = (await getPRHeadSha(token, owner, repo, scan.pr_number)) ?? scan.commit_sha;
    let checkRunId: number | null = null;
    try {
      const check = await createCheckRun(token, owner, repo, {
        name: "TrustLedger AI Governance", head_sha: headSha, status: "in_progress",
        output: { title: "Rescanning…", summary: "A rescan with the current TrustLedger engine was requested from the dashboard." },
      });
      checkRunId = check.id;
    } catch { /* the scan still runs; only the check run is missing */ }

    await enqueueScan({
      org_id: auth.org_id, installation_id: scan.installation_id, repo_full_name: scan.repo_full_name,
      pr_number: scan.pr_number, head_sha: headSha, branch: scan.branch ?? "main", pr_author: scan.pr_author ?? null,
      before_sha: null, action: "rescan", check_run_id: checkRunId, delivery_id: null, force: true,
      trace_id: currentTrace()?.trace_id,
    });
    await recordEvent({ kind: "scan.queued", org_id: auth.org_id, repo: scan.repo_full_name, pr_number: scan.pr_number, message: "Rescan requested", data: { head_sha: headSha, check_run_id: checkRunId, previous_scan_id: scan.id } });

    await writeAuditLog(db, {
      org_id: auth.org_id, event_type: "scan_rescan_requested",
      actor_id: auth.user_id ?? null, actor_email: auth.actor_email ?? null,
      resource_type: "scan", resource_id: scan.id,
      payload: { repo: scan.repo_full_name, pr_number: scan.pr_number, head_sha: headSha },
    });
    return NextResponse.json({ ok: true, queued: true, head_sha: headSha });
  } catch (err) {
    return safeError(err, { code: "rescan_failed", message: "We couldn't start the rescan. Check that the TrustLedger GitHub App is still installed on this repository." });
  }
}
