/**
 * Scan a pull request from the dashboard (the New Scan panel).
 *
 * POST /api/scans/pr { repo: "owner/name", pr_number, force? }
 *   → { status: "queued", repo, pr_number, head_sha }                       scan queued; poll GET /api/scans?repo=
 *   → { status: "already_scanned", scan_id, repo, pr_number, head_sha }     the PR's current head already has a scan
 *
 * Same pipeline as a GitHub webhook scan: the PR's files are fetched from GitHub at its current head and
 * scanned by the queue worker, with a check run on the PR. `force` scans again even when that head commit
 * was already scanned (at most once a minute per PR, like a rescan).
 */
import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey, requirePermission } from "../../_middleware";
import { resolveConnectedRepo } from "@/lib/connectedRepo";
import { getInstallationToken, getPullRequest, createCheckRun } from "@/lib/github";
import { enqueueScan } from "@/lib/queue";
import { writeAuditLog } from "@/lib/audit";
import { safeError } from "@/lib/errors";
import { runWithTrace, traceIdFrom, currentTrace } from "@/lib/trace";
import { recordEvent } from "@/lib/opsEvents";

const MIN_INTERVAL_MS = 60_000;

export async function POST(req: NextRequest) {
  return runWithTrace({ trace_id: traceIdFrom(req.headers.get("x-request-id")) }, () => handle(req));
}

async function handle(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });
  const permErr = await requirePermission(auth, "can_trigger_scans");
  if (permErr) return NextResponse.json({ error: permErr }, { status: 403 });

  const body = await req.json().catch(() => ({})) as { repo?: string; pr_number?: unknown; force?: unknown };
  const prNumber = Number(body.pr_number);
  if (!Number.isInteger(prNumber) || prNumber < 1) {
    return NextResponse.json({ error: "invalid_pr_number", message: "Choose a pull request (a positive PR number)." }, { status: 400 });
  }
  const force = body.force === true;

  const db = createServiceClient();
  const target = await resolveConnectedRepo(db, auth.org_id, body.repo);
  if (!target.ok) return NextResponse.json({ error: target.error, message: target.message }, { status: target.status });

  try {
    const { token } = await getInstallationToken(target.installationId);
    const pr = await getPullRequest(token, target.owner, target.name, prNumber);
    if (!pr) {
      return NextResponse.json({ error: "pr_not_found", message: `Pull request #${prNumber} wasn't found in ${target.repo}.` }, { status: 404 });
    }

    const { data: recent } = await db
      .from("scans")
      .select("id, commit_sha, created_at")
      .eq("org_id", auth.org_id)
      .eq("repo_full_name", target.repo)
      .eq("pr_number", prNumber)
      .order("created_at", { ascending: false })
      .limit(1) as { data: Array<{ id: string; commit_sha: string; created_at: string }> | null };
    const last = recent?.[0];

    if (last && last.commit_sha === pr.head_sha && !force) {
      return NextResponse.json({ status: "already_scanned", scan_id: last.id, repo: target.repo, pr_number: prNumber, head_sha: pr.head_sha });
    }
    if (last && Date.now() - Date.parse(last.created_at) < MIN_INTERVAL_MS) {
      return NextResponse.json({ error: "scan_too_soon", message: "This PR was scanned less than a minute ago. Try again shortly." }, { status: 429 });
    }

    let checkRunId: number | null = null;
    try {
      const check = await createCheckRun(token, target.owner, target.name, {
        name: "TrustLedger AI Governance", head_sha: pr.head_sha, status: "in_progress",
        output: { title: "Scanning…", summary: "A scan of this pull request was started from the TrustLedger dashboard." },
      });
      checkRunId = check.id;
    } catch { /* the scan still runs; only the check run is missing */ }

    await enqueueScan({
      trace_id: currentTrace()?.trace_id,
      org_id: auth.org_id, installation_id: target.installationId, repo_full_name: target.repo,
      pr_number: prNumber, head_sha: pr.head_sha, branch: pr.branch, pr_author: pr.author,
      before_sha: null, action: "manual", check_run_id: checkRunId, delivery_id: null,
      // The worker skips a commit that already has a scan; scanning that head again is what `force` asks for.
      force: force && last?.commit_sha === pr.head_sha,
      pr_additions: pr.additions, pr_deletions: pr.deletions, pr_commits: pr.commits,
      pr_changed_files: pr.changed_files, pr_created_at: pr.created_at,
    });

    await writeAuditLog(db, {
      org_id: auth.org_id, event_type: "scan_rescan_requested",
      actor_id: auth.user_id ?? null, actor_email: auth.actor_email ?? null,
      resource_type: "pull_request", resource_id: `${target.repo}#${prNumber}`,
      payload: { kind: "dashboard_scan", repo: target.repo, pr_number: prNumber, head_sha: pr.head_sha, force },
    });

    await recordEvent({ kind: "scan.queued", org_id: auth.org_id, repo: target.repo, pr_number: prNumber, message: "Scan started from the dashboard", data: { head_sha: pr.head_sha, check_run_id: checkRunId, force } });
    return NextResponse.json({ status: "queued", repo: target.repo, pr_number: prNumber, head_sha: pr.head_sha });
  } catch (err) {
    return safeError(err, { code: "scan_start_failed", message: "We couldn't start that scan. Check that the TrustLedger GitHub App can access this repository." });
  }
}
