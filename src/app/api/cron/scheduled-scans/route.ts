/**
 * Scheduled Repository Scan Cron
 * Runs every hour — checks scan_schedules for repos due for a scan.
 * Uses GitHub App installation token to fetch files and run the scanner.
 * Vercel Cron: "0 * * * *" (every hour)
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { getInstallationToken, getPRFiles, fetchFileContents } from "@/lib/github";
import { runScan } from "@/lib/scanner";
import { writeAuditLog } from "@/lib/audit";
import { fireOrgWebhooks } from "@/lib/outboundWebhook";
import { cacheDel, cacheKeys } from "@/lib/cache";
import { isScannablePath as isScannable } from "@/lib/scannableFiles";

// Day windows the dashboard UI requests (src/app/dashboard/page.tsx DAYS_OPTIONS)
const DASHBOARD_CACHE_DAYS = [7, 30, 90];

export async function GET(req: NextRequest) {
  const auth = req.headers.get("authorization");
  if (auth !== `Bearer ${process.env.CRON_SECRET}`) {
    return NextResponse.json({ error:"unauthorized" }, { status: 401 });
  }

  const db  = createServiceClient();
  const now = new Date();

  // Find schedules due for a scan
  // A schedule is "due" when: last_run_at is null OR last_run_at + cron interval < now
  // For simplicity: run if not run in the last 23 hours (for daily "0 2 * * *" schedules)
  const cutoff23h = new Date(now.getTime() - 23 * 3600_000).toISOString();

  const { data: schedules } = await db
    .from("scan_schedules")
    .select(`
      id, org_id, branch,
      repositories(id, repo_full_name, default_branch),
      organizations(id, github_org)
    `)
    .eq("enabled", true)
    .or(`last_run_at.is.null,last_run_at.lt.${cutoff23h}`)
    .limit(20) as {
      data: Array<{
        id:             string;
        org_id:         string;
        branch:         string;
        repositories:   { id: string; repo_full_name: string } | null;
        organizations:  { id: string; github_org: string | null } | null;
      }> | null
    };

  if (!schedules || schedules.length === 0) {
    return NextResponse.json({ ok: true, scans_triggered: 0 });
  }

  let triggered = 0;
  const errors: string[] = [];

  for (const schedule of schedules) {
    if (!schedule.repositories || !schedule.organizations) continue;

    const repo     = schedule.repositories.repo_full_name;
    const orgId    = schedule.org_id;
    const [owner]  = repo.split("/");

    try {
      // Get GitHub installation
      const { data: installation } = await db
        .from("github_installations")
        .select("installation_id")
        .eq("org_id", orgId)
        .single() as { data: { installation_id: number } | null };

      if (!installation) continue;

      const { token } = await getInstallationToken(installation.installation_id);

      // Get latest commit on branch
      const branchRes = await fetch(
        `https://api.github.com/repos/${repo}/branches/${schedule.branch}`,
        { headers: { Authorization: `token ${token}`, Accept: "application/vnd.github+json" } },
      );
      if (!branchRes.ok) continue;
      const branchData = await branchRes.json() as { commit: { sha: string } };
      const headSha    = branchData.commit.sha;

      // Get recently changed files (last 24h)
      const recentFiles = await fetch(
        `https://api.github.com/repos/${repo}/commits?sha=${schedule.branch}&per_page=10`,
        { headers: { Authorization: `token ${token}`, Accept: "application/vnd.github+json" } },
      ).then(r => r.json() as Promise<Array<{ sha: string }>>);

      // Get unique files changed in recent commits
      const changedPaths = new Set<string>();
      for (const commit of recentFiles.slice(0, 3)) {
        const detail = await fetch(
          `https://api.github.com/repos/${repo}/commits/${commit.sha}`,
          { headers: { Authorization: `token ${token}` } },
        ).then(r => r.json() as Promise<{ files: Array<{ filename: string; status: string }> }>);
        (detail.files ?? [])
          .filter(f => f.status !== "removed" && isScannable(f.filename))
          .forEach(f => changedPaths.add(f.filename));
      }

      if (changedPaths.size === 0) {
        // Update last_run_at even if no files changed
        await db.from("scan_schedules").update({ last_run_at: now.toISOString() }).eq("id", schedule.id);
        continue;
      }

      // Fetch file contents
      const fileContents = await fetchFileContents(
        token, owner, repo.split("/")[1], headSha,
        Array.from(changedPaths).slice(0, 30),
      );

      if (fileContents.length === 0) continue;

      // Run scanner
      const result = runScan({
        repo,
        pr_number:  0,
        commit_sha: headSha,
        branch:     schedule.branch,
        files:      fileContents.map(f => ({ path: f.path, content: f.content })),
      });

      // Persist scan
      const { data: scanRow } = await db.from("scans").insert({
        id:                  result.scan_id,
        org_id:              orgId,
        repo_full_name:      repo,
        commit_sha:          headSha,
        branch:              schedule.branch,
        overall_risk:        result.overall_risk,
        total_ai_percentage: result.total_ai_percentage,
        file_count:          result.files.length,
        triggered_by:        "scheduled",
        duration_ms:         result.duration_ms,
      }).select("id").single() as { data: { id: string } | null };

      if (scanRow) {
        // Invalidate cached dashboard stats so this scan shows up immediately
        await Promise.all(DASHBOARD_CACHE_DAYS.map(days => cacheDel(cacheKeys.dashboard(orgId, days))));
      }

      if (scanRow && result.files.length > 0) {
        await db.from("scan_files").insert(result.files.map(f => ({
          scan_id:         scanRow.id,
          org_id:          orgId,
          file_path:       f.file_path,
          language:        f.language,
          ai_percentage:   f.ai_percentage,
          risk_score:      f.risk_score,
          risk_indicators: f.risk_indicators,
          content_hash:    f.content_hash,
          line_count:      f.line_count,
        })));

        // Create violations for high-risk files
        const highRisk = result.files.filter(f => f.risk_score === "CRITICAL" || f.risk_score === "HIGH");
        if (highRisk.length > 0) {
          await db.from("violations").insert(highRisk.map(f => ({
            org_id:       orgId,
            scan_id:      scanRow.id,
            file_path:    f.file_path,
            risk_score:   f.risk_score,
            sla_deadline: new Date(Date.now() + (f.risk_score === "CRITICAL" ? 24 : 48) * 3600_000).toISOString(),
          })));
        }

        // ── Attestation carry-over ──────────────────────────────────────────
        // If a file with the same content_hash was previously attested in any
        // scan in this org, auto-inherit that attestation. This prevents a
        // scheduled re-scan from wiping attestations on unchanged files.
        if (result.files.length > 0) {
          const hashes = result.files.map(f => f.content_hash).filter(Boolean);
          if (hashes.length > 0) {
            const { data: prevMatches } = await db
              .from("scan_files")
              .select("file_path, content_hash, scan_id")
              .eq("org_id", orgId)
              .neq("scan_id", scanRow.id)
              .in("content_hash", hashes);

            if (prevMatches && prevMatches.length > 0) {
              const prevScanIds = [...new Set(prevMatches.map(p => p.scan_id as string))];
              const { data: prevAtts } = await db
                .from("attestations")
                .select("scan_id, file_path, risk_score, reviewer_email, reviewer_github")
                .eq("org_id", orgId)
                .in("scan_id", prevScanIds);

              const autoAttest = new Map<string, { risk_score: string; reviewer_email: string; reviewer_github: string | null }>();
              for (const att of (prevAtts ?? [])) {
                const match = prevMatches.find(p => p.scan_id === att.scan_id && p.file_path === att.file_path);
                if (!match) continue;
                const ourFile = result.files.find(f => f.file_path === att.file_path && f.content_hash === match.content_hash);
                if (ourFile && !autoAttest.has(att.file_path)) {
                  autoAttest.set(att.file_path, {
                    risk_score:      att.risk_score as string,
                    reviewer_email:  att.reviewer_email as string,
                    reviewer_github: att.reviewer_github as string | null,
                  });
                }
              }

              if (autoAttest.size > 0) {
                const ts = new Date().toISOString();
                await db.from("attestations").upsert(
                  [...autoAttest.entries()].map(([fp, att]) => ({
                    org_id: orgId, scan_id: scanRow.id, file_path: fp,
                    risk_score: att.risk_score, reviewer_email: att.reviewer_email,
                    reviewer_github: att.reviewer_github,
                    payload_hash: `inherited-scheduled:${scanRow.id}:${fp}`,
                  })),
                  { onConflict: "scan_id,file_path", ignoreDuplicates: true },
                );
                // Auto-resolve violations for inherited files
                await db.from("violations")
                  .update({ status: "resolved", resolved_at: ts })
                  .eq("scan_id", scanRow.id)
                  .in("file_path", [...autoAttest.keys()]);
                await db.from("scan_files")
                  .update({ attested: true })
                  .eq("scan_id", scanRow.id)
                  .in("file_path", [...autoAttest.keys()]);
              }
            }
          }
        }
        // ─────────────────────────────────────────────────────────────────
      }

      // Update last_run_at
      await db.from("scan_schedules").update({ last_run_at: now.toISOString() }).eq("id", schedule.id);

      // Audit log + outbound webhooks
      await writeAuditLog(db, {
        org_id:      orgId,
        event_type:  "scan_complete",
        actor_email: "scheduled-cron",
        resource_type: "scan",
        resource_id:   result.scan_id,
        payload: { repo, branch: schedule.branch, overall_risk: result.overall_risk, scheduled: true },
      });

      await fireOrgWebhooks(db, orgId, {
        type: "scan.completed",
        data: {
          scan_id:      result.scan_id,
          repo,
          overall_risk: result.overall_risk,
          file_count:   result.files.length,
          triggered_by: "scheduled",
        },
      });

      triggered++;

    } catch (e) {
      errors.push(`${repo}: ${e instanceof Error ? e.message : String(e)}`);
    }
  }

  return NextResponse.json({
    ok:         true,
    triggered,
    schedules:  schedules.length,
    errors:     errors.length > 0 ? errors : undefined,
    ran_at:     now.toISOString(),
  });
}
