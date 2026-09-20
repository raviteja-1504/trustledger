/**
 * GitHub App Webhook Receiver
 *
 * Intentionally thin — heavy work is offloaded to /api/scan-worker via QStash:
 *   1. Verify HMAC-SHA256 signature
 *   2. Rate-limit by installation ID
 *   3. Look up org, create GitHub check run (in_progress)
 *   4. Enqueue scan job → return 200 immediately (< 500ms)
 *
 * The scan-worker route does: fetch files, run scanner, persist, update check run, post comment.
 */

import { NextRequest, NextResponse } from "next/server";
import { waitUntil } from "@vercel/functions";
import { createServiceClient } from "@/lib/supabase";
import { checkRateLimit, RATE_LIMITS } from "@/lib/rateLimit";
import { verifyWebhookSignature, getInstallationToken, createCheckRun, updateCheckRun } from "@/lib/github";
import { enqueueScan } from "@/lib/queue";

export async function POST(req: NextRequest) {
  const rawBody = await req.text();
  const sig     = req.headers.get("x-hub-signature-256");
  const event   = req.headers.get("x-github-event");
  // Trim any stray \r characters added by Windows CLI piping into Vercel env vars
  const secret  = (process.env.GITHUB_WEBHOOK_SECRET ?? "").trim();

  // ── 1. Verify signature ────────────────────────────────────────────────────
  if (!verifyWebhookSignature(rawBody, sig, secret)) {
    return NextResponse.json({ error: "invalid_signature" }, { status: 401 });
  }

  const payload = JSON.parse(rawBody) as Record<string, unknown>;

  // ── 2. Rate-limit by installation ID ──────────────────────────────────────
  const installationId = (payload.installation as Record<string, unknown>)?.id as number | undefined;
  const rl = await checkRateLimit(String(installationId ?? "unknown"), RATE_LIMITS.webhook);
  if (!rl.success) {
    return NextResponse.json({ error: "rate_limit_exceeded" }, { status: 429, headers: rl.headers });
  }

  // ── 3. Handle PR events ────────────────────────────────────────────────────
  if (event === "pull_request") {
    const action = payload.action as string;
    if (!["opened", "synchronize", "reopened"].includes(action)) {
      return NextResponse.json({ ok: true, skipped: true });
    }

    const pr    = payload.pull_request as Record<string, unknown>;
    const repo  = payload.repository   as Record<string, unknown>;

    const repoFullName  = repo.full_name as string;
    const prNumber      = pr.number     as number;
    const headSha       = (pr.head as Record<string, string>).sha;
    const branch        = (pr.head as Record<string, string>).ref;
    const prAuthor      = (pr.user as Record<string, string> | null)?.login ?? null;
    const beforeSha     = (payload.before as string | undefined) ?? null;
    // PR behavior metadata for multi-signal AI evidence scoring
    const prAdditions   = pr.additions   as number | undefined;
    const prDeletions   = pr.deletions   as number | undefined;
    const prCommits     = pr.commits     as number | undefined;
    const prChangedFiles = pr.changed_files as number | undefined;
    const prCreatedAt   = pr.created_at  as string | undefined;
    const [owner, repoName] = repoFullName.split("/");

    const db = createServiceClient();

    // Look up org
    const { data: orgRecord } = await db
      .from("organizations")
      .select("id")
      .eq("github_org", owner)
      .maybeSingle();

    const orgId = orgRecord?.id ?? null;

    let checkRunId: number | null = null;

    // Create "in_progress" check run immediately so GitHub shows a spinner
    if (installationId) {
      try {
        const { token } = await getInstallationToken(installationId);
        const check = await createCheckRun(token, owner, repoName, {
          name:     "TrustLedger AI Governance",
          head_sha: headSha,
          status:   "in_progress",
          output: {
            title:   "Scanning for AI-generated code…",
            summary: "TrustLedger is analysing files in this pull request.",
          },
        });
        checkRunId = check.id;
      } catch (err) {
        console.error("[webhook] check run creation failed:", err);
      }
    }

    // Log delivery receipt — include check_run_id so recovery is possible
    // even if the scan-worker crashes before persisting the scan row.
    // Captures its own id so scan-worker can report processed/scan_id/error
    // back onto this same row once the job finishes, instead of leaving
    // those columns permanently at their insert-time defaults.
    const { data: deliveryRow } = await db.from("webhook_deliveries").insert({
      org_id:          orgId,
      source:          "github",
      event_type:      `pull_request.${action}`,
      repo_full_name:  repoFullName,
      payload:         { ...payload, tl_check_run_id: checkRunId },
      signature_ok:    true,
      processed:       false,
    }).select("id").single();

    // ── 4. Enqueue scan job ────────────────────────────────────────────────
    // Deferred via waitUntil rather than awaited: the response below doesn't
    // depend on enqueueScan's outcome (it already reports queued: true
    // unconditionally), so there's no reason to hold the webhook response on
    // it. This matters even with QStash working correctly, because
    // enqueueScan() has its own directFetch() fallback that runs the entire
    // scan inline if QStash is ever unavailable for any reason -- awaiting
    // that here is exactly what caused real GitHub webhook deliveries to
    // time out ("context deadline exceeded... awaiting headers") the last
    // time QStash's publish call started failing. waitUntil keeps this
    // function alive to finish the work after the response is already sent,
    // instead of a bare un-awaited promise that Vercel could kill outright.
    waitUntil(
      enqueueScan({
        org_id:           orgId,
        installation_id:  installationId!,
        repo_full_name:   repoFullName,
        pr_number:        prNumber,
        head_sha:         headSha,
        branch,
        pr_author:        prAuthor,
        before_sha:       beforeSha,
        action,
        check_run_id:     checkRunId,
        delivery_id:      deliveryRow?.id ?? null,
        pr_additions:     prAdditions,
        pr_deletions:     prDeletions,
        pr_commits:       prCommits,
        pr_changed_files: prChangedFiles,
        pr_created_at:    prCreatedAt,
      }).catch(err => console.error("[webhook] enqueueScan failed:", err)),
    );

    return NextResponse.json({ ok: true, queued: true, check_run_id: checkRunId });
  }

  // ── Handle a developer clicking GitHub's native "Re-run" button ───────────
  // GitHub sends check_run/rerequested for this -- previously unhandled, so
  // the button was a dead click. Looks up the scan this check run belongs
  // to (check_run_id is globally unique) and re-enqueues a scan the same
  // way a fresh pull_request event does.
  if (event === "check_run") {
    const action = payload.action as string;
    if (action !== "rerequested") {
      return NextResponse.json({ ok: true, skipped: true });
    }

    const checkRun     = payload.check_run as Record<string, unknown>;
    const checkRunId   = checkRun.id as number;
    const headSha      = checkRun.head_sha as string;
    const checkSuite   = checkRun.check_suite as Record<string, unknown> | undefined;
    const branch       = (checkSuite?.head_branch as string | undefined) ?? "";
    const repo         = payload.repository as Record<string, unknown>;
    const repoFullName = repo.full_name as string;

    const db = createServiceClient();
    const { data: scan } = await db
      .from("scans")
      .select("org_id, pr_number, installation_id, repo_full_name")
      .eq("check_run_id", checkRunId)
      .eq("repo_full_name", repoFullName)
      .order("created_at", { ascending: false })
      .limit(1)
      .maybeSingle();

    if (!scan || !scan.installation_id) {
      return NextResponse.json({ ok: true, skipped: true, reason: "scan_not_found" });
    }

    const [owner, repoName] = repoFullName.split("/");
    try {
      const { token } = await getInstallationToken(scan.installation_id);
      await updateCheckRun(token, owner, repoName, checkRunId, {
        name:   "TrustLedger AI Governance",
        status: "in_progress",
        output: {
          title:   "Re-scanning for AI-generated code…",
          summary: "TrustLedger is re-analysing files in this pull request.",
        },
      });
    } catch (err) {
      console.error("[webhook] check run re-run update failed:", err);
    }

    waitUntil(
      enqueueScan({
        org_id:           scan.org_id,
        installation_id:  scan.installation_id,
        repo_full_name:   repoFullName,
        pr_number:        scan.pr_number,
        head_sha:         headSha,
        branch,
        pr_author:        null,
        before_sha:       null,
        action:           "rerequested",
        check_run_id:     checkRunId,
        delivery_id:      null,
      }).catch(err => console.error("[webhook] enqueueScan (rerequested) failed:", err)),
    );

    return NextResponse.json({ ok: true, queued: true, check_run_id: checkRunId });
  }

  // Unknown event — ack
  return NextResponse.json({ ok: true, event });
}
