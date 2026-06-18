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
      return await receiver.verify({
        signature: req.headers.get("upstash-signature") ?? "",
        body:      rawBody,
      });
    } catch {
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
    org_id:          orgId,
    installation_id: installationId,
    repo_full_name:  repoFullName,
    pr_number:       prNumber,
    head_sha:        headSha,
    branch,
    pr_author:       prAuthor,
    before_sha:      beforeSha,
    action,
    check_run_id:    checkRunId,
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

    // ── Run scanner ───────────────────────────────────────────────────────────
    const result = runScan({
      repo: repoFullName, pr_number: prNumber, commit_sha: headSha, branch,
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

          if (prevScan) {
            const { data: prevAtts } = await db
              .from("attestations")
              .select("file_path, risk_score, reviewer_id, reviewer_email, reviewer_github, payload_hash")
              .eq("scan_id", prevScan.id)
              .in("file_path", inheritedFiles.map(f => f.file_path));

            if (prevAtts && prevAtts.length > 0) {
              await db.from("attestations").insert(prevAtts.map(a => ({
                org_id: orgId, scan_id: scan.id,
                file_path: a.file_path, risk_score: a.risk_score,
                reviewer_id: a.reviewer_id, reviewer_email: a.reviewer_email,
                reviewer_github: a.reviewer_github, payload_hash: a.payload_hash,
              })));
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
              .in("scan_id", prevScanIds);

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
              await db.from("attestations").upsert(
                [...autoAttest.entries()].map(([fp, att]) => ({
                  org_id: orgId, scan_id: scan.id, file_path: fp,
                  risk_score: att.risk_score, reviewer_email: att.reviewer_email,
                  reviewer_github: att.reviewer_github,
                  payload_hash: `inherited:${scan.id}:${fp}`,
                })),
                { onConflict: "scan_id,file_path", ignoreDuplicates: true },
              );
              await db.from("violations")
                .update({ status: "resolved", resolved_at: now })
                .eq("scan_id", scan.id)
                .in("file_path", [...autoAttest.keys()]);
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
    // Return 500 so QStash retries the job
    return NextResponse.json({ error: "scan_failed", detail: String(err) }, { status: 500 });
  }
}
