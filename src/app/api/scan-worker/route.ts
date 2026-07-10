/**
 * POST /api/scan-worker
 *
 * Invoked asynchronously by Upstash QStash (or directly in local dev).
 * Runs the full scan pipeline for one PR event:
 *   fetch files → scanner → persist → update check run → post PR comment
 *
 * The webhook handler enqueues a job and returns 200 immediately; this
 * endpoint does all the CPU-heavy work in its own Vercel function invocation
 * with a 300s timeout budget, isolated per org.
 */

import { NextRequest, NextResponse } from "next/server";
import { Receiver } from "@upstash/qstash";
import { createServiceClient } from "@/lib/supabase";
import {
  getInstallationToken,
  getPRFiles,
  getCommitDiff,
  fetchFileContents,
  updateCheckRun,
  buildCheckSummary,
} from "@/lib/github";
import { runScan } from "@/lib/scanner";
import { writeAuditLog } from "@/lib/audit";
import { cacheDel, cacheKeys } from "@/lib/cache";
import { isScannablePath as isScannable } from "@/lib/scannableFiles";
import { hasOpenRepoViolations } from "@/lib/repoViolations";
import type { ScanJob } from "@/lib/queue";

const DASHBOARD_CACHE_DAYS = [7, 30, 90];

async function verifyRequest(req: NextRequest, rawBody: string): Promise<boolean> {
  // Internal secret always accepted (webhook fallback when QStash isn't used)
  // Strip BOM (﻿) that Windows CLI piping adds to env vars in Vercel
  const expectedSecret = (process.env.INTERNAL_SECRET ?? "dev").replace(/^﻿/, "").trim();
  if (req.headers.get("x-internal-secret") === expectedSecret) {
    return true;
  }
  // QStash signature verification
  if (process.env.QSTASH_CURRENT_SIGNING_KEY && process.env.QSTASH_NEXT_SIGNING_KEY) {
    try {
      const receiver = new Receiver({
        currentSigningKey: process.env.QSTASH_CURRENT_SIGNING_KEY,
        nextSigningKey:    process.env.QSTASH_NEXT_SIGNING_KEY,
      });
      // The signature JWT embeds the destination URL as a claim — verify()
      // needs it to check that claim against the actual request, otherwise
      // it fails closed (every delivery gets rejected with 401).
      return await receiver.verify({
        signature: req.headers.get("upstash-signature") ?? "",
        body:      rawBody,
        url:       req.url,
      });
    } catch (err) {
      console.error("[scan-worker] QStash signature verification failed:", err);
      return false;
    }
  }
  return false;
}

export async function POST(req: NextRequest) {
  const rawBody = await req.text();

  if (!await verifyRequest(req, rawBody)) {
    return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  }

  const job = JSON.parse(rawBody) as ScanJob;
  const {
    org_id:           orgId,
    installation_id:  installationId,
    repo_full_name:   repoFullName,
    pr_number:        prNumber,
    head_sha:         headSha,
    branch,
    pr_author:        prAuthor,
    before_sha:       beforeSha,
    action,
    check_run_id:     checkRunId,
    pr_additions,
    pr_deletions,
    pr_commits,
    pr_changed_files,
    pr_created_at,
  } = job;

  const [owner, repoName] = repoFullName.split("/");
  const db = createServiceClient();

  // Idempotency: if a scan for this commit already exists, skip (QStash retry safety)
  const { data: existing } = await db
    .from("scans")
    .select("id")
    .eq("repo_full_name", repoFullName)
    .eq("commit_sha", headSha)
    .eq("pr_number", prNumber)
    .maybeSingle();

  if (existing) {
    // Scan already persisted — this is a QStash retry after the first
    // invocation timed out. The check run may still show "in_progress" if
    // the previous invocation timed out after persisting the scan but before
    // calling updateCheckRun. Recover it here so the PR isn't left stuck.
    if (checkRunId) {
      try {
        const { token: retryToken } = await getInstallationToken(installationId);
        const { count: openViolations } = await db
          .from("violations")
          .select("id", { count: "exact", head: true })
          .eq("scan_id", existing.id)
          .neq("status", "resolved")
          .in("risk_score", ["CRITICAL", "HIGH"]);
        const retryConcl: "success" | "action_required" =
          (openViolations ?? 0) > 0 ? "action_required" : "success";
        await updateCheckRun(retryToken, owner, repoName, checkRunId, {
          name: "TrustLedger AI Governance", status: "completed",
          conclusion: retryConcl,
          output: { title: "Scan complete", summary: "TrustLedger has finished analysing this pull request." },
        });
      } catch { /* best-effort — don't block the 200 response */ }
    }
    return NextResponse.json({ ok: true, skipped: true, reason: "already_scanned" });
  }

  try {
    const { token } = await getInstallationToken(installationId);

    // ── Delta scanning ────────────────────────────────────────────────────────
    const isDelta = action === "synchronize" && !!beforeSha && !!orgId;

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
        .eq("org_id", orgId!)
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

    let changedPaths = new Set<string>();
    if (isDelta && prevScan && beforeSha) {
      changedPaths = await getCommitDiff(token, owner, repoName, beforeSha, headSha);
      if (changedPaths.size === 0) prevScan = null;
    }

    const prFiles = await getPRFiles(token, owner, repoName, prNumber);
    const allScannablePaths = prFiles
      .filter(f => f.status !== "removed" && isScannable(f.filename))
      .map(f => f.filename);

    const pathsToFetch = (isDelta && prevScan && changedPaths.size > 0)
      ? allScannablePaths.filter(p => changedPaths.has(p))
      : allScannablePaths;

    const fileContents = pathsToFetch.length > 0
      ? await fetchFileContents(token, owner, repoName, headSha, pathsToFetch)
      : [];

    if (fileContents.length === 0 && (!prevScan || allScannablePaths.length === 0)) {
      if (checkRunId) {
        await updateCheckRun(token, owner, repoName, checkRunId, {
          name: "TrustLedger AI Governance", status: "completed", conclusion: "neutral",
          output: { title: "No scannable files", summary: "No source files to analyse in this PR." },
        });
      }
      return NextResponse.json({ ok: true, files_scanned: 0 });
    }

    // ── Git provenance: fetch PR commit history ───────────────────────────────
    // Build a git log string from the GitHub commits API so analyzeGitProvenance()
    // can score commit velocity, AI commit messages, and signing rate.
    let gitLog: string | undefined;
    try {
      const commitsRes = await fetch(
        `https://api.github.com/repos/${repoFullName}/pulls/${prNumber}/commits?per_page=50`,
        { headers: { Authorization: `token ${token}`, Accept: "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28" } },
      );
      if (commitsRes.ok) {
        const commits = await commitsRes.json() as Array<{
          sha: string;
          commit: { author: { name: string; email: string; date: string }; message: string };
        }>;
        // Format: "%H|%an|%ae|%at|%G?|%s"  (G? = GPG status, use N = no sig)
        gitLog = commits.map(c => {
          const ts = Math.floor(new Date(c.commit.author.date).getTime() / 1000);
          const subject = c.commit.message.split("\n")[0].replace(/\|/g, " ");
          return `${c.sha}|${c.commit.author.name}|${c.commit.author.email}|${ts}|N|${subject}`;
        }).join("\n");
      }
    } catch { /* non-fatal — git provenance just won't be scored */ }

    // ── Developer baseline (Phase 3) ─────────────────────────────────────────
    // Fetch the PR author's historical patterns to detect deviation
    let developerBaseline = null;
    if (orgId && prAuthor) {
      const { data: baselineRow } = await db
        .from("developer_baselines")
        .select("pr_count, avg_loc_per_pr, avg_commits_per_pr, avg_files_per_pr, avg_ai_percentage")
        .eq("org_id", orgId)
        .eq("github_login", prAuthor)
        .maybeSingle();
      developerBaseline = baselineRow ?? null;
    }

    // ── Run scanner ───────────────────────────────────────────────────────────
    const prMeta = pr_additions != null ? {
      additions:     pr_additions,
      deletions:     pr_deletions ?? 0,
      commits:       pr_commits ?? 1,
      changed_files: pr_changed_files ?? 0,
      created_at:    pr_created_at,
    } : undefined;

    const result = runScan({
      repo: repoFullName, pr_number: prNumber, commit_sha: headSha, branch,
      pr_metadata:         prMeta,
      developer_baseline:  developerBaseline ?? undefined,
      git_log:             gitLog,
      // Pass ALL PR file paths (not just scannable) so .claude/, .cursorrules etc. are detected
      all_file_paths:      prFiles.map(f => f.filename),
      files: fileContents.map(f => ({ path: f.path, content: f.content })),
    });

    const inheritedFiles: PrevScanFile[] = (isDelta && prevScan)
      ? prevScan.files.filter(f => !changedPaths.has(f.file_path))
      : [];

    const autoAttestedPaths = new Set<string>();

    // ── Persist ───────────────────────────────────────────────────────────────
    if (orgId) {
      const { data: repoRec } = await db
        .from("repositories")
        .upsert({ org_id: orgId, repo_full_name: repoFullName, default_branch: "main" },
          { onConflict: "org_id,repo_full_name" })
        .select("id").single();

      const riskOrder = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
      const inheritedMaxRisk = inheritedFiles.reduce<string>((max, f) =>
        riskOrder.indexOf(f.risk_score) > riskOrder.indexOf(max) ? f.risk_score : max, "LOW");
      const overallRisk = riskOrder.indexOf(result.overall_risk) >= riskOrder.indexOf(inheritedMaxRisk)
        ? result.overall_risk : inheritedMaxRisk as typeof result.overall_risk;

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
        file_count:          result.files.length + inheritedFiles.length,
        pr_author:           prAuthor,
        triggered_by:        "webhook",
        duration_ms:         result.duration_ms,
        check_run_id:        checkRunId,
        installation_id:     installationId,
        evidence_breakdown:  result.evidence_breakdown,
      }).select("id").single();

      if (scan) {
        await Promise.all(DASHBOARD_CACHE_DAYS.map(days => cacheDel(cacheKeys.dashboard(orgId, days))));

        if (result.files.length > 0) {
          const contentByPath = new Map(fileContents.map(f => [f.path, f.content]));
          await db.from("scan_files").insert(result.files.map(f => ({
            scan_id: scan.id, org_id: orgId,
            file_path: f.file_path, language: f.language,
            ai_percentage: f.ai_percentage, risk_score: f.risk_score,
            risk_indicators: f.risk_indicators, content_hash: f.content_hash, line_count: f.line_count,
            content: contentByPath.get(f.file_path) ?? null,
            // Store detailed indicators (with line numbers) so the PR page
            // can show exact locations without re-running the scanner.
            indicators: f.indicators
              ? f.indicators
                  .filter(i => i.line)
                  .map(i => ({ id: i.id, label: i.label, severity: i.severity, line: i.line, detail: i.detail }))
              : [],
          })));
        }

        if (inheritedFiles.length > 0) {
          await db.from("scan_files").insert(inheritedFiles.map(f => ({
            scan_id: scan.id, org_id: orgId,
            file_path: f.file_path, language: f.language,
            ai_percentage: f.ai_percentage, risk_score: f.risk_score,
            risk_indicators: f.risk_indicators, content_hash: f.content_hash, line_count: f.line_count,
            content: f.content,
          })));

          // For inherited (unchanged) files, copy attestations from any prior
          // scan of this same PR — not just the immediately previous scan.
          // Checking only prevScan.id meant that if the prior scan had zero
          // attestation rows (e.g. due to the now-fixed ON CONFLICT insert bug),
          // no attestations were inherited even though the files are guaranteed
          // unchanged and were attested in some earlier scan of the same PR.
          if (prevScan) {
            const unInherited = new Set(inheritedFiles.map(f => f.file_path));

            const { data: prScans } = await db
              .from("scans")
              .select("id, created_at")
              .eq("org_id", orgId)
              .eq("repo_full_name", repoFullName)
              .eq("pr_number", prNumber)
              .neq("id", scan.id)
              .order("created_at", { ascending: false });

            // Pre-load which file_paths already have attestation rows for this
            // new scan (single query) instead of checking per-file inside the
            // loop. Previously each file did a separate SELECT+INSERT which
            // produced O(prior_scans × inherited_files) sequential DB roundtrips
            // — ~2600 queries for a PR with 8 prior scans and 166 files, making
            // the scan-worker extremely slow. One upfront query reduces this to
            // O(prior_scans + inherited_files).
            const { data: existingForScan } = await db
              .from("attestations")
              .select("file_path")
              .eq("scan_id", scan.id);
            const alreadyInherited = new Set((existingForScan ?? []).map(a => a.file_path as string));

            for (const priorScan of (prScans ?? [])) {
              if (unInherited.size === 0) break;
              const { data: priorAtts } = await db
                .from("attestations")
                .select("file_path, risk_score, reviewer_id, reviewer_email, reviewer_github, payload_hash")
                .eq("scan_id", priorScan.id)
                .in("file_path", [...unInherited]);
              if (!priorAtts || priorAtts.length === 0) continue;
              // Batch insert all new attestations in one query instead of one
              // per file. The table rule blocks ON CONFLICT (upsert) but plain
              // INSERT is fine — .insert([array]) generates a single multi-row
              // INSERT with no ON CONFLICT clause.
              const toInsert = priorAtts.filter(a => !alreadyInherited.has(a.file_path as string));
              if (toInsert.length > 0) {
                await db.from("attestations").insert(
                  toInsert.map(a => ({
                    org_id: orgId, scan_id: scan.id,
                    file_path: a.file_path, risk_score: a.risk_score,
                    reviewer_id: a.reviewer_id, reviewer_email: a.reviewer_email,
                    reviewer_github: a.reviewer_github, payload_hash: a.payload_hash,
                  }))
                );
                toInsert.forEach(a => alreadyInherited.add(a.file_path as string));
              }
              priorAtts.forEach(a => unInherited.delete(a.file_path as string));
            }
          }
        }

        const violationFiles = result.files.filter(
          f => f.risk_score === "CRITICAL" || f.risk_score === "HIGH"
        );
        if (violationFiles.length > 0) {
          const slaH = overallRisk === "CRITICAL" ? 24 : 48;
          await db.from("violations").insert(violationFiles.map(f => ({
            org_id: orgId, scan_id: scan.id, file_path: f.file_path, risk_score: f.risk_score,
            sla_deadline: new Date(Date.now() + slaH * 3600_000).toISOString(),
          })));

          // ── Create a single alert per scan for the sidebar badge ──────────
          // One P1/P2 alert per scan (not per file) so the alerts page shows
          // a meaningful entry and the sidebar badge reflects the real state.
          // Skip if an open alert already exists for this scan (idempotent).
          const { data: existingAlert } = await db
            .from("alerts")
            .select("id")
            .eq("org_id", orgId)
            .eq("scan_id", scan.id)
            .in("status", ["firing", "acknowledged", "snoozed"])
            .limit(1);

          if (!existingAlert || existingAlert.length === 0) {
            const critCount = violationFiles.filter(f => f.risk_score === "CRITICAL").length;
            const highCount = violationFiles.filter(f => f.risk_score === "HIGH").length;
            const severity  = critCount > 0 ? "P1" : "P2";
            const repoShort = repoFullName.split("/").pop() ?? repoFullName;
            await db.from("alerts").insert({
              org_id:     orgId,
              alert_type: "policy",
              severity,
              status:     "firing",
              title:      `${critCount + highCount} unattested file${critCount + highCount > 1 ? "s" : ""} in ${repoShort} PR #${prNumber}`,
              body:       [
                critCount > 0 ? `${critCount} CRITICAL` : "",
                highCount > 0 ? `${highCount} HIGH` : "",
              ].filter(Boolean).join(" and ") + ` file${critCount + highCount > 1 ? "s" : ""} require attestation before merge.`,
              repo:       repoFullName,
              scan_id:    scan.id,
              fired_at:   new Date().toISOString(),
            });
          }
        }

        // ── Cross-PR attestation inheritance ──────────────────────────────────
        const allScanFiles = [
          ...result.files.map(f => ({ file_path: f.file_path, content_hash: f.content_hash, risk_score: f.risk_score })),
          ...inheritedFiles.map(f => ({ file_path: f.file_path, content_hash: f.content_hash, risk_score: f.risk_score })),
        ];

        if (allScanFiles.length > 0) {
          const uniqueHashes = [...new Set(allScanFiles.map(f => f.content_hash))];
          const { data: prevScanFileMatches } = await db
            .from("scan_files")
            .select("file_path, content_hash, scan_id")
            .eq("org_id", orgId)
            .neq("scan_id", scan.id)
            .in("content_hash", uniqueHashes);

          if (prevScanFileMatches && prevScanFileMatches.length > 0) {
            const prevScanIds = [...new Set(prevScanFileMatches.map(f => f.scan_id as string))];
            const { data: prevAtts } = await db
              .from("attestations")
              .select("scan_id, file_path, risk_score, reviewer_email, reviewer_github")
              .eq("org_id", orgId)
              .in("scan_id", prevScanIds)
              .limit(10000);

            const autoAttest = new Map<string, { risk_score: string; reviewer_email: string; reviewer_github: string | null }>();
            for (const att of (prevAtts ?? [])) {
              const match = prevScanFileMatches.find(pf => pf.scan_id === att.scan_id && pf.file_path === att.file_path);
              if (!match) continue;
              const ourFile = allScanFiles.find(f => f.file_path === att.file_path && f.content_hash === match.content_hash);
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
              autoAttest.forEach((_, fp) => autoAttestedPaths.add(fp));
              // Batch insert all inherited attestations in one query.
              // The table rule blocks ON CONFLICT (upsert) but plain INSERT
              // works fine. Pre-filter against existing rows (loaded once
              // above in the within-PR inheritance block via existingForScan).
              const { data: existingCrossPR } = await db
                .from("attestations").select("file_path").eq("scan_id", scan.id);
              const existingCrossPRSet = new Set((existingCrossPR ?? []).map(a => a.file_path as string));
              const crossPRToInsert = [...autoAttest.entries()]
                .filter(([fp]) => !existingCrossPRSet.has(fp));
              if (crossPRToInsert.length > 0) {
                await db.from("attestations").insert(
                  crossPRToInsert.map(([fp, att]) => ({
                    org_id: orgId, scan_id: scan.id, file_path: fp,
                    risk_score: att.risk_score, reviewer_email: att.reviewer_email,
                    reviewer_github: att.reviewer_github,
                    payload_hash: `inherited:${scan.id}:${fp}`,
                  }))
                );
              }
              await db.from("violations")
                .update({ status: "resolved", resolved_at: now })
                .eq("scan_id", scan.id)
                .in("file_path", [...autoAttest.keys()]);

              // Resolve ALL policy alerts for this repo if no open violations remain
              // (check repo-wide, not just this scan, because multiple scans of the
              // same PR each create their own alert). Dedup-aware: see
              // lib/repoViolations.ts for why a naive row count is wrong here.
              if (!(await hasOpenRepoViolations(db, orgId, repoFullName))) {
                await db.from("alerts")
                  .update({ status: "resolved", resolved_at: now })
                  .eq("org_id", orgId)
                  .eq("repo", repoFullName)
                  .eq("alert_type", "policy")
                  .in("status", ["firing", "acknowledged", "snoozed"]);
              }
            }
          }
        }

        await writeAuditLog(db, {
          org_id: orgId, event_type: "scan_complete", actor_email: "github-webhook",
          resource_type: "scan", resource_id: scan.id,
          payload: {
            repo: repoFullName, pr_number: prNumber, overall_risk: overallRisk,
            delta: isDelta, files_rescanned: result.files.length, files_inherited: inheritedFiles.length,
          },
        });

        // ── Update developer baseline (rolling average) ───────────────────
        // After each scan, update the author's historical metrics so future
        // scans can detect deviation. Uses exponential moving average to
        // give more weight to recent PRs and handle new developers gracefully.
        if (prAuthor && prMeta) {
          const prev = developerBaseline;
          const n    = (prev?.pr_count ?? 0) + 1;
          const alpha = Math.min(0.3, 1 / n); // decaying weight; caps at 30%
          const newBaseline = {
            org_id:              orgId,
            github_login:        prAuthor,
            pr_count:            n,
            avg_loc_per_pr:      prev ? prev.avg_loc_per_pr    * (1 - alpha) + prMeta.additions   * alpha : prMeta.additions,
            avg_commits_per_pr:  prev ? prev.avg_commits_per_pr * (1 - alpha) + prMeta.commits    * alpha : prMeta.commits,
            avg_files_per_pr:    prev ? prev.avg_files_per_pr   * (1 - alpha) + prMeta.changed_files * alpha : prMeta.changed_files,
            avg_ai_percentage:   prev ? prev.avg_ai_percentage  * (1 - alpha) + result.total_ai_percentage * alpha : result.total_ai_percentage,
            last_updated:        new Date().toISOString(),
          };
          await db.from("developer_baselines")
            .upsert(newBaseline, { onConflict: "org_id,github_login" });
        }
      }
    }

    // ── Update check run ──────────────────────────────────────────────────────
    const mergedFiles = [
      ...result.files,
      ...inheritedFiles.map(f => ({
        file_path: f.file_path, language: f.language,
        ai_percentage: f.ai_percentage,
        risk_score: f.risk_score as "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
        risk_indicators: f.risk_indicators as typeof result.files[0]["risk_indicators"],
        content_hash: f.content_hash, line_count: f.line_count, attested: true,
      })),
    ];
    const mergedResult = { ...result, files: mergedFiles };

    if (checkRunId) {
      let conclusion: "success" | "action_required" | "neutral" = "success";
      if (orgId) {
        const { count } = await db
          .from("violations")
          .select("id", { count: "exact", head: true })
          .eq("scan_id", result.scan_id)
          .neq("status", "resolved")
          .in("risk_score", ["CRITICAL", "HIGH"]);
        if ((count ?? 0) > 0) conclusion = "action_required";
      } else {
        const { conclusion: c } = buildCheckSummary(mergedResult);
        conclusion = c === "action_required" ? "action_required" : c === "neutral" ? "neutral" : "success";
      }
      const { title, summary } = buildCheckSummary(mergedResult);
      await updateCheckRun(token, owner, repoName, checkRunId, {
        name: "TrustLedger AI Governance", status: "completed", conclusion,
        output: { title, summary },
      });
    }

    // ── Post PR comment ───────────────────────────────────────────────────────
    if (prNumber && orgId) {
      try {
        const appUrl = process.env.NEXT_PUBLIC_APP_URL ?? "https://app.trustledger.dev";
        const { buildPRCommentDirect } = await import("@/lib/githubComment");
        const comment = buildPRCommentDirect({
          scan_id: result.scan_id, repo: repoFullName, pr_number: prNumber,
          overall_risk: mergedResult.overall_risk,
          total_ai_percentage: result.total_ai_percentage,
          evidence_breakdown: result.evidence_breakdown,
          files: mergedResult.files.map(f => ({
            file_path: f.file_path, risk_score: f.risk_score,
            ai_percentage: f.ai_percentage, risk_indicators: f.risk_indicators,
            attested: autoAttestedPaths.has(f.file_path) ||
              (("attested" in f) ? !!(f as { attested?: boolean }).attested : false),
          })),
          appUrl,
        });
        const commentsRes = await fetch(
          `https://api.github.com/repos/${repoFullName}/issues/${prNumber}/comments?per_page=30`,
          { headers: { Authorization: `token ${token}`, Accept: "application/vnd.github+json" } },
        );
        let existingId: number | null = null;
        if (commentsRes.ok) {
          const comments = await commentsRes.json() as Array<{ id: number; body: string }>;
          existingId = comments.find(c => c.body.includes("TrustLedger AI Governance"))?.id ?? null;
        }
        const commentUrl = existingId
          ? `https://api.github.com/repos/${repoFullName}/issues/comments/${existingId}`
          : `https://api.github.com/repos/${repoFullName}/issues/${prNumber}/comments`;
        await fetch(commentUrl, {
          method:  existingId ? "PATCH" : "POST",
          headers: { Authorization: `token ${token}`, Accept: "application/vnd.github+json", "Content-Type": "application/json" },
          body:    JSON.stringify({ body: comment }),
        });
      } catch { /* non-fatal */ }
    }

    return NextResponse.json({
      ok:              true,
      scan_id:         result.scan_id,
      files_scanned:   result.files.length,
      files_inherited: inheritedFiles.length,
      delta:           isDelta,
    });

  } catch (err) {
    console.error("[scan-worker] error:", err);
    // Best-effort: mark the check run as failed so the PR isn't left stuck
    // in "Scanning…" indefinitely. Do this before returning 500 (which
    // causes QStash to retry) — on retry the idempotency block above
    // handles updating the check run if the scan was already persisted.
    if (checkRunId) {
      try {
        const { token: errToken } = await getInstallationToken(installationId);
        await updateCheckRun(errToken, owner, repoName, checkRunId, {
          name: "TrustLedger AI Governance", status: "completed", conclusion: "neutral",
          output: {
            title: "Scan error",
            summary: "TrustLedger encountered an error while analysing this PR. Push a new commit to trigger a fresh scan.",
          },
        });
      } catch { /* don't mask the original error */ }
    }
    return NextResponse.json({ error: "scan_failed", detail: String(err) }, { status: 500 });
  }
}
