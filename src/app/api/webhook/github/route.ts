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
  getCommitDiff,
  fetchFileContents,
  createCheckRun,
  updateCheckRun,
  buildCheckSummary,
} from "@/lib/github";
import { runScan } from "@/lib/scanner";
import { writeAuditLog } from "@/lib/audit";
import { cacheDel, cacheKeys } from "@/lib/cache";
import { isScannablePath as isScannable } from "@/lib/scannableFiles";

// Day windows the dashboard UI requests (src/app/dashboard/page.tsx DAYS_OPTIONS)
const DASHBOARD_CACHE_DAYS = [7, 30, 90];

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

    const pr           = payload.pull_request as Record<string, unknown>;
    const repo         = (payload.repository as Record<string, unknown>);
    const installation = payload.installation as { id: number } | null;

    const repoFullName = repo.full_name as string;
    const prNumber     = pr.number as number;
    const headSha      = (pr.head as Record<string, string>).sha;
    const branch       = (pr.head as Record<string, string>).ref;
    // `before` is only present on synchronize events — the SHA before the push
    const beforeSha    = (payload.before as string | undefined) ?? null;
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

      // Post "in_progress" check run immediately so GitHub shows a spinner
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

      // ── Delta scanning on synchronize ──────────────────────────────────────
      // On "opened"/"reopened" we scan all PR files.
      // On "synchronize" (new commit pushed) we only scan files that changed in
      // that specific push and inherit results + attestations for everything else.
      const isDelta = action === "synchronize" && !!beforeSha && !!orgId;

      // Find the previous scan for this PR (only needed for delta mode)
      type PrevScanFile = {
        file_path: string; language: string; ai_percentage: number;
        risk_score: string; risk_indicators: unknown; content_hash: string;
        line_count: number; content: string | null;
      };
      type PrevScan = { id: string; files: PrevScanFile[] };
      let prevScan: PrevScan | null = null;

      if (isDelta) {
        const { data: prevScanRow } = await db
          .from("scans")
          .select("id")
          .eq("org_id", orgId)
          .eq("repo_full_name", repoFullName)
          .eq("pr_number", prNumber)
          .order("created_at", { ascending: false })
          .limit(1)
          .single();

        if (prevScanRow) {
          const { data: prevFiles } = await db
            .from("scan_files")
            .select("file_path, language, ai_percentage, risk_score, risk_indicators, content_hash, line_count, content")
            .eq("scan_id", prevScanRow.id);
          prevScan = { id: prevScanRow.id, files: (prevFiles ?? []) as PrevScanFile[] };
        }
      }

      // Determine which files need to be (re-)scanned
      let changedPaths: Set<string> = new Set();

      if (isDelta && prevScan && token && beforeSha) {
        // Only files that changed in the push between beforeSha → headSha
        changedPaths = await getCommitDiff(token, owner, repoName, beforeSha, headSha);
        // Fall back to full scan if compare API failed (empty set)
        if (changedPaths.size === 0) prevScan = null;
      }

      // All scannable files in the PR (used for full scan and for building the
      // complete file list when inheriting unchanged files)
      const prFiles = token
        ? await getPRFiles(token, owner, repoName, prNumber)
        : [];

      const allScannablePaths = prFiles
        .filter(f => f.status !== "removed" && isScannable(f.filename))
        .map(f => f.filename);

      // In delta mode, only fetch content for files that changed in this push.
      // In full mode, fetch content for all scannable PR files.
      const pathsToFetch = (isDelta && prevScan && changedPaths.size > 0)
        ? allScannablePaths.filter(p => changedPaths.has(p))
        : allScannablePaths;

      const fileContents = token && pathsToFetch.length > 0
        ? await fetchFileContents(token, owner, repoName, headSha, pathsToFetch)
        : [];

      // If nothing at all is scannable (and nothing to inherit), bail out
      if (fileContents.length === 0 && (!prevScan || allScannablePaths.length === 0)) {
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

      // ── 3. Run scanner (delta or full) ───────────────────────────────────
      const result = runScan({
        repo:       repoFullName,
        pr_number:  prNumber,
        commit_sha: headSha,
        branch,
        files:      fileContents.map(f => ({ path: f.path, content: f.content })),
      });

      // In delta mode: build the full file list by merging new scan results with
      // inherited (unchanged) files from the previous scan.
      const inheritedFiles: PrevScanFile[] = (isDelta && prevScan)
        ? prevScan.files.filter(f => !changedPaths.has(f.file_path))
        : [];

      // Tracks files auto-attested by the cross-PR content-hash step.
      // Populated during DB persistence; used when building the PR comment.
      const autoAttestedPaths = new Set<string>();

      // ── 4. Persist scan ──────────────────────────────────────────────────
      if (orgId) {
        // Upsert repo
        const { data: repoRec } = await db
          .from("repositories")
          .upsert({ org_id: orgId, repo_full_name: repoFullName, default_branch: "main" },
            { onConflict: "org_id,repo_full_name" })
          .select("id").single();

        // Compute overall risk across both new and inherited files
        const riskOrder = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
        const inheritedMaxRisk = inheritedFiles.reduce<string>((max, f) => {
          return riskOrder.indexOf(f.risk_score) > riskOrder.indexOf(max) ? f.risk_score : max;
        }, "LOW");
        const overallRisk = riskOrder.indexOf(result.overall_risk) >= riskOrder.indexOf(inheritedMaxRisk)
          ? result.overall_risk : inheritedMaxRisk as typeof result.overall_risk;

        const totalFileCount = result.files.length + inheritedFiles.length;

        const { data: scan } = await db.from("scans").insert({
          id:                  result.scan_id,
          org_id:              orgId,
          repo_id:             repoRec?.id ?? null,
          repo_full_name:      repoFullName,
          pr_number:           prNumber,
          commit_sha:          headSha,
          branch,
          overall_risk:        overallRisk,
          total_ai_percentage: result.total_ai_percentage,
          file_count:          totalFileCount,
          triggered_by:        "webhook",
          duration_ms:         result.duration_ms,
          check_run_id:        checkRunId,
          installation_id:     installation?.id ?? null,
        }).select("id").single();

        if (scan) {
          await Promise.all(DASHBOARD_CACHE_DAYS.map(days => cacheDel(cacheKeys.dashboard(orgId, days))));

          // Insert newly scanned files
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

          // Inherit unchanged files from the previous scan
          if (inheritedFiles.length > 0) {
            await db.from("scan_files").insert(inheritedFiles.map(f => ({
              scan_id: scan.id, org_id: orgId,
              file_path: f.file_path, language: f.language,
              ai_percentage: f.ai_percentage, risk_score: f.risk_score,
              risk_indicators: f.risk_indicators, content_hash: f.content_hash, line_count: f.line_count,
              content: f.content,
            })));

            // Carry over attestations for inherited files from the previous scan
            if (prevScan) {
              const { data: prevAttestations } = await db
                .from("attestations")
                .select("file_path, risk_score, reviewer_id, reviewer_email, reviewer_github, payload_hash")
                .eq("scan_id", prevScan.id)
                .in("file_path", inheritedFiles.map(f => f.file_path));

              if (prevAttestations && prevAttestations.length > 0) {
                await db.from("attestations").insert(prevAttestations.map(a => ({
                  org_id: orgId,
                  scan_id:         scan.id,
                  file_path:       a.file_path,
                  risk_score:      a.risk_score,
                  reviewer_id:     a.reviewer_id,
                  reviewer_email:  a.reviewer_email,
                  reviewer_github: a.reviewer_github,
                  payload_hash:    a.payload_hash,
                })));
              }
            }
          }

          // Create violations only for newly scanned CRITICAL/HIGH files.
          // Inherited files keep their old violation records (already exist in DB).
          const violationFiles = result.files.filter(
            f => f.risk_score === "CRITICAL" || f.risk_score === "HIGH"
          );
          if (violationFiles.length > 0) {
            const slaH = overallRisk === "CRITICAL" ? 24 : 48;
            await db.from("violations").insert(violationFiles.map(f => ({
              org_id: orgId, scan_id: scan.id, file_path: f.file_path, risk_score: f.risk_score,
              sla_deadline: new Date(Date.now() + slaH * 3600_000).toISOString(),
            })));
          }

          // ── Cross-PR attestation inheritance ─────────────────────────────
          // For every file in this scan (newly scanned OR inherited), if the
          // exact same content (matching content_hash) was previously attested
          // in any scan in this org, auto-attest it here too.
          // This means reviewers only need to attest genuinely new/changed files
          // — unchanged files carry their attestation forward automatically.
          const allScanFiles = [
            ...result.files.map(f => ({ file_path: f.file_path, content_hash: f.content_hash, risk_score: f.risk_score })),
            ...inheritedFiles.map(f => ({ file_path: f.file_path, content_hash: f.content_hash, risk_score: f.risk_score })),
          ];

          if (allScanFiles.length > 0) {
            const uniqueHashes = [...new Set(allScanFiles.map(f => f.content_hash))];

            // Find scan_files in this org with the same content_hash (across any previous scan)
            const { data: prevScanFileMatches } = await db
              .from("scan_files")
              .select("file_path, content_hash, scan_id")
              .eq("org_id", orgId)
              .neq("scan_id", scan.id)
              .in("content_hash", uniqueHashes);

            if (prevScanFileMatches && prevScanFileMatches.length > 0) {
              const prevScanIds = [...new Set(prevScanFileMatches.map(f => f.scan_id as string))];

              // Find which of those previous files have attestations
              const { data: prevAttestations } = await db
                .from("attestations")
                .select("scan_id, file_path, risk_score, reviewer_email, reviewer_github")
                .eq("org_id", orgId)
                .in("scan_id", prevScanIds);

              // Build a map: file_path → attestation (most recent match)
              const autoAttest = new Map<string, { risk_score: string; reviewer_email: string; reviewer_github: string | null }>();
              for (const att of (prevAttestations ?? [])) {
                // Find the matching scan_file record: same file_path AND same content_hash as our current file
                const match = prevScanFileMatches.find(
                  pf => pf.scan_id === att.scan_id && pf.file_path === att.file_path,
                );
                if (!match) continue;
                // Check this hash is indeed the same as what we just scanned for this path
                const ourFile = allScanFiles.find(
                  f => f.file_path === att.file_path && f.content_hash === match.content_hash,
                );
                if (ourFile && !autoAttest.has(att.file_path)) {
                  autoAttest.set(att.file_path, {
                    risk_score:      att.risk_score as string,
                    reviewer_email:  att.reviewer_email as string,
                    reviewer_github: att.reviewer_github as string | null,
                  });
                }
              }

              if (autoAttest.size > 0) {
                const now = new Date().toISOString();
                // Record which paths are being auto-attested so the PR comment
                // can mark them as attested rather than counting them as pending.
                autoAttest.forEach((_, fp) => autoAttestedPaths.add(fp));
                // Insert auto-inherited attestation records (ignore conflicts — file may already be attested)
                await db.from("attestations").upsert(
                  [...autoAttest.entries()].map(([fp, att]) => ({
                    org_id:          orgId,
                    scan_id:         scan.id,
                    file_path:       fp,
                    risk_score:      att.risk_score,
                    reviewer_email:  att.reviewer_email,
                    reviewer_github: att.reviewer_github,
                    payload_hash:    `inherited:${scan.id}:${fp}`,
                  })),
                  { onConflict: "scan_id,file_path", ignoreDuplicates: true },
                );

                // Resolve violations for auto-attested files
                await db.from("violations")
                  .update({ status: "resolved", resolved_at: now })
                  .eq("scan_id", scan.id)
                  .in("file_path", [...autoAttest.keys()]);
              }
            }
          }

          await writeAuditLog(db, {
            org_id:      orgId,
            event_type:  "scan_complete",
            actor_email: "github-webhook",
            resource_type: "scan", resource_id: scan.id,
            payload: {
              repo: repoFullName, pr_number: prNumber, overall_risk: overallRisk,
              delta: isDelta, files_rescanned: result.files.length, files_inherited: inheritedFiles.length,
            },
          });

          delivery.scan_id = scan.id;
        }
      }

      // ── 5. Update GitHub Check Run ───────────────────────────────────────
      // Pass the merged result (new + inherited) so the conclusion reflects the
      // full PR, not just the delta files scanned in this push.
      const mergedResult = {
        ...result,
        overall_risk: (isDelta && prevScan) ? (
          (() => {
            const riskOrder = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
            const inheritedMax = inheritedFiles.reduce<string>((max, f) => {
              return riskOrder.indexOf(f.risk_score) > riskOrder.indexOf(max) ? f.risk_score : max;
            }, "LOW");
            return riskOrder.indexOf(result.overall_risk) >= riskOrder.indexOf(inheritedMax)
              ? result.overall_risk : inheritedMax as typeof result.overall_risk;
          })()
        ) : result.overall_risk,
        files: [
          ...result.files,
          ...inheritedFiles.map(f => ({
            file_path: f.file_path, language: f.language,
            ai_percentage: f.ai_percentage,
            risk_score: f.risk_score as "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
            risk_indicators: f.risk_indicators as typeof result.files[0]["risk_indicators"],
            content_hash: f.content_hash, line_count: f.line_count,
            attested: true,
          })),
        ],
      };

      if (token && checkRunId) {
        // Query remaining unresolved violations so auto-attested files don't
        // cause a false "action_required" conclusion.
        let conclusion: "success" | "action_required" | "neutral" = "success";
        const scanId = result.scan_id;
        if (orgId) {
          const { count: unresolvedCount } = await db
            .from("violations")
            .select("id", { count: "exact", head: true })
            .eq("scan_id", scanId)
            .neq("status", "resolved")
            .in("risk_score", ["CRITICAL", "HIGH"]);
          if ((unresolvedCount ?? 0) > 0) conclusion = "action_required";
        } else {
          // No org — fall back to risk-based conclusion
          const { conclusion: c } = buildCheckSummary(mergedResult);
          conclusion = c === "action_required" ? "action_required" : c === "neutral" ? "neutral" : "success";
        }

        const { title, summary } = buildCheckSummary(mergedResult);
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
            overall_risk:        mergedResult.overall_risk,
            total_ai_percentage: result.total_ai_percentage,
            files:               mergedResult.files.map(f => ({
              file_path: f.file_path, risk_score: f.risk_score,
              ai_percentage: f.ai_percentage, risk_indicators: f.risk_indicators,
              attested: autoAttestedPaths.has(f.file_path) ||
                        (("attested" in f) ? !!(f as { attested?: boolean }).attested : false),
            })),
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
        ok:               true,
        scan_id:          result.scan_id,
        overall_risk:     mergedResult.overall_risk,
        files_scanned:    result.files.length,
        files_inherited:  inheritedFiles.length,
        delta:            isDelta,
        check_run_id:     checkRunId,
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
