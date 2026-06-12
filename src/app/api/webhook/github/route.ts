/**
 * GitHub App Webhook Receiver
 * Handles: pull_request (opened/synchronize/reopened), push
 * 1. Verifies HMAC-SHA256 signature
 * 2. Fetches changed file contents from GitHub
 * 3. Runs the TrustLedger scanner
 * 4. Persists scan results to Supabase
 * 5. Posts a GitHub Check Run with pass/fail result
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { checkRateLimit, RATE_LIMITS } from "@/lib/rateLimit";
import {
  verifyWebhookSignature,
  getInstallationToken,
  getPRFiles,
  fetchFileContents,
  createCheckRun,
  updateCheckRun,
  buildCheckSummary,
} from "@/lib/github";
import { runScan } from "@/lib/scanner";
import { writeAuditLog } from "@/lib/audit";

// File extensions we scan
const SCANNABLE_EXTS = new Set([
  "py", "ts", "tsx", "js", "jsx", "rb", "go", "rs",
  "java", "kt", "cs", "php", "cpp", "c", "swift",
]);

function isScannable(path: string): boolean {
  const ext = path.split(".").pop()?.toLowerCase() ?? "";
  return SCANNABLE_EXTS.has(ext);
}

export async function POST(req: NextRequest) {
  const rawBody  = await req.text();
  const sig      = req.headers.get("x-hub-signature-256");
  const event    = req.headers.get("x-github-event");
  const secret   = process.env.GITHUB_WEBHOOK_SECRET ?? "";

  // ── 1. Verify signature ────────────────────────────────────────────────────
  if (!verifyWebhookSignature(rawBody, sig, secret)) {
    return NextResponse.json({ error: "invalid_signature" }, { status: 401 });
  }

  const payload = JSON.parse(rawBody) as Record<string, unknown>;
  const db      = createServiceClient();

  // Rate limit by GitHub installation ID (prevents abuse if webhook secret leaks)
  const installationId = String((payload.installation as Record<string,unknown>)?.id ?? "unknown");
  const rl = await checkRateLimit(installationId, RATE_LIMITS.webhook);
  if (!rl.success) {
    return NextResponse.json({ error: "rate_limit_exceeded" }, { status: 429, headers: rl.headers });
  }

  // Log all deliveries for debugging
  const delivery: Record<string, unknown> = {
    org_id:       null,
    source:       "github",
    event_type:   event ?? "unknown",
    payload,
    signature_ok: true,
    processed:    false,
  };

  // ── 2. Handle PR events ────────────────────────────────────────────────────
  if (event === "pull_request") {
    const action = payload.action as string;
    if (!["opened", "synchronize", "reopened"].includes(action)) {
      return NextResponse.json({ ok: true, skipped: true });
    }

    const pr          = payload.pull_request as Record<string, unknown>;
    const repo        = (payload.repository as Record<string, unknown>);
    const installation = payload.installation as { id: number } | null;

    const repoFullName = repo.full_name as string;
    const prNumber     = pr.number as number;
    const headSha      = (pr.head as Record<string, string>).sha;
    const branch       = (pr.head as Record<string, string>).ref;
    const [owner, repoName] = repoFullName.split("/");

    // Look up org by GitHub org name
    const { data: orgRecord } = await db
      .from("organizations")
      .select("id")
      .eq("github_org", owner)
      .single();

    const orgId = orgRecord?.id ?? null;
    delivery.org_id = orgId;

    let token: string | null = null;
    let checkRunId: number | null = null;

    try {
      // Get installation token
      if (installation?.id) {
        const t = await getInstallationToken(installation.id);
        token = t.token;
      }

      // Post "queued" check run immediately
      if (token) {
        const check = await createCheckRun(token, owner, repoName, {
          name:     "TrustLedger AI Governance",
          head_sha: headSha,
          status:   "in_progress",
          output: {
            title:   "Scanning for AI-generated code...",
            summary: "TrustLedger is analysing files in this pull request.",
          },
        });
        checkRunId = check.id;
      }

      // Fetch changed files
      const prFiles = token
        ? await getPRFiles(token, owner, repoName, prNumber)
        : [];

      const scannableFiles = prFiles
        .filter(f => f.status !== "removed" && isScannable(f.filename))
        .map(f => f.filename);

      // Fetch file contents
      const fileContents = token && scannableFiles.length > 0
        ? await fetchFileContents(token, owner, repoName, headSha, scannableFiles)
        : [];

      if (fileContents.length === 0) {
        if (token && checkRunId) {
          await updateCheckRun(token, owner, repoName, checkRunId, {
            name:       "TrustLedger AI Governance",
            status:     "completed",
            conclusion: "neutral",
            output: { title: "No scannable files", summary: "No source files to analyse in this PR." },
          });
        }
        delivery.processed = true;
        await db.from("webhook_deliveries").insert(delivery);
        return NextResponse.json({ ok: true, files_scanned: 0 });
      }

      // ── 3. Run scanner ───────────────────────────────────────────────────
      const result = runScan({
        repo:       repoFullName,
        pr_number:  prNumber,
        commit_sha: headSha,
        branch,
        files:      fileContents.map(f => ({ path: f.path, content: f.content })),
      });

      // ── 4. Persist scan ──────────────────────────────────────────────────
      if (orgId) {
        // Upsert repo
        const { data: repoRec } = await db
          .from("repositories")
          .upsert({ org_id: orgId, repo_full_name: repoFullName, default_branch: "main" },
            { onConflict: "org_id,repo_full_name" })
          .select("id").single();

        const { data: scan } = await db.from("scans").insert({
          id:                  result.scan_id,
          org_id:              orgId,
          repo_id:             repoRec?.id ?? null,
          repo_full_name:      repoFullName,
          pr_number:           prNumber,
          commit_sha:          headSha,
          branch,
          overall_risk:        result.overall_risk,
          total_ai_percentage: result.total_ai_percentage,
          file_count:          result.files.length,
          triggered_by:        "webhook",
          duration_ms:         result.duration_ms,
          check_run_id:        checkRunId,
          installation_id:     installation?.id ?? null,
        }).select("id").single();

        if (scan) {
          if (result.files.length > 0) {
            const contentByPath = new Map(fileContents.map(f => [f.path, f.content]));
            await db.from("scan_files").insert(result.files.map(f => ({
              scan_id: scan.id, org_id: orgId,
              file_path: f.file_path, language: f.language,
              ai_percentage: f.ai_percentage, risk_score: f.risk_score,
              risk_indicators: f.risk_indicators, content_hash: f.content_hash, line_count: f.line_count,
              content: contentByPath.get(f.file_path) ?? null,
            })));
          }

          const violationFiles = result.files.filter(
            f => f.risk_score === "CRITICAL" || f.risk_score === "HIGH"
          );
          if (violationFiles.length > 0) {
            const slaH = result.overall_risk === "CRITICAL" ? 24 : 48;
            await db.from("violations").insert(violationFiles.map(f => ({
              org_id: orgId, scan_id: scan.id, file_path: f.file_path, risk_score: f.risk_score,
              sla_deadline: new Date(Date.now() + slaH * 3600_000).toISOString(),
            })));
          }

          await writeAuditLog(db, {
            org_id:      orgId,
            event_type:  "scan_complete",
            actor_email: "github-webhook",
            resource_type: "scan", resource_id: scan.id,
            payload: { repo: repoFullName, pr_number: prNumber, overall_risk: result.overall_risk },
          });

          delivery.scan_id = scan.id;
        }
      }

      // ── 5. Update GitHub Check Run ───────────────────────────────────────
      if (token && checkRunId) {
        const { title, summary, conclusion } = buildCheckSummary(result);
        await updateCheckRun(token, owner, repoName, checkRunId, {
          name:       "TrustLedger AI Governance",
          status:     "completed",
          conclusion,
          output: { title, summary },
        });
      }

      // ── 6. Post/update PR comment with rich risk breakdown ───────────────
      if (token && prNumber && orgId) {
        try {
          const appUrl = process.env.NEXT_PUBLIC_APP_URL ?? "https://app.trustledger.dev";
          const { buildPRCommentDirect } = await import("@/lib/githubComment");
          const comment = buildPRCommentDirect({
            scan_id:             result.scan_id,
            repo:                repoFullName,
            pr_number:           prNumber,
            overall_risk:        result.overall_risk,
            total_ai_percentage: result.total_ai_percentage,
            files:               result.files.map(f => ({ file_path:f.file_path, risk_score:f.risk_score, ai_percentage:f.ai_percentage, risk_indicators:f.risk_indicators, attested:false })),
            appUrl,
          });
          // Find existing comment to update (deduplicate)
          const commentsRes = await fetch(
            `https://api.github.com/repos/${repoFullName}/issues/${prNumber}/comments?per_page=30`,
            { headers: { Authorization:`token ${token}`, Accept:"application/vnd.github+json" } },
          );
          let existingCommentId: number | null = null;
          if (commentsRes.ok) {
            const comments = await commentsRes.json() as Array<{ id:number; body:string }>;
            existingCommentId = comments.find(c => c.body.includes("TrustLedger AI Governance"))?.id ?? null;
          }
          const commentUrl = existingCommentId
            ? `https://api.github.com/repos/${repoFullName}/issues/comments/${existingCommentId}`
            : `https://api.github.com/repos/${repoFullName}/issues/${prNumber}/comments`;
          await fetch(commentUrl, {
            method:  existingCommentId ? "PATCH" : "POST",
            headers: { Authorization:`token ${token}`, Accept:"application/vnd.github+json", "Content-Type":"application/json" },
            body:    JSON.stringify({ body: comment }),
          });
        } catch { /* Non-fatal — comment posting is best-effort */ }
      }

      delivery.processed = true;
      await db.from("webhook_deliveries").insert(delivery);

      return NextResponse.json({
        ok:             true,
        scan_id:        result.scan_id,
        overall_risk:   result.overall_risk,
        files_scanned:  result.files.length,
        check_run_id:   checkRunId,
      });

    } catch (err) {
      delivery.error = String(err);
      await db.from("webhook_deliveries").insert(delivery);
      if (token && checkRunId) {
        try {
          await updateCheckRun(token, owner, repoName, checkRunId, {
            name: "TrustLedger AI Governance", status: "completed", conclusion: "neutral",
            output: { title: "Scan error", summary: "TrustLedger encountered an error. Please retry." },
          });
        } catch { /* ignore */ }
      }
      console.error("Webhook error:", err);
      return NextResponse.json({ error: "scan_failed" }, { status: 500 });
    }
  }

  // Unknown event — log and ack
  await db.from("webhook_deliveries").insert({ ...delivery, processed: true });
  return NextResponse.json({ ok: true, event });
}
