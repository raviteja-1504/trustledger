/**
 * GitLab Webhook Receiver
 * Handles: Merge Request events (opened/updated)
 *
 * Setup in GitLab:
 *   Settings → Webhooks → URL: https://app.trustledger.dev/api/webhook/gitlab
 *   Token: Your GITLAB_WEBHOOK_TOKEN env var
 *   Trigger: Merge requests events
 *
 * Differences from GitHub:
 *   - Auth: X-Gitlab-Token header (not HMAC, just token equality)
 *   - API: GitLab REST API v4 (not GitHub API)
 *   - Status: Commit status API (not Check Runs)
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { runScan } from "@/lib/scanner";
import { writeAuditLog } from "@/lib/audit";
import { fireOrgWebhooks } from "@/lib/outboundWebhook";
import { checkRateLimit, RATE_LIMITS } from "@/lib/rateLimit";
import { cacheDel, cacheKeys } from "@/lib/cache";
import { isScannablePath as isScannable } from "@/lib/scannableFiles";
import crypto from "crypto";

// Day windows the dashboard UI requests (src/app/dashboard/page.tsx DAYS_OPTIONS)
const DASHBOARD_CACHE_DAYS = [7, 30, 90];

async function getGitLabToken(db: ReturnType<typeof createServiceClient>, orgId: string): Promise<string | null> {
  const { data } = await db
    .from("github_installations") // reuse table — add gitlab_token column via migration
    .select("access_token")
    .eq("org_id", orgId)
    .eq("github_org", "__gitlab__")
    .single() as { data: { access_token: string | null } | null };
  return data?.access_token ?? process.env.GITLAB_API_TOKEN ?? null;
}

async function fetchGitLabFiles(
  token: string,
  projectId: string | number,
  mrIid: number,
  headSha: string,
): Promise<Array<{ path: string; content: string }>> {
  const GITLAB_API = "https://gitlab.com/api/v4";
  const headers = { "PRIVATE-TOKEN": token };

  // Get MR changes
  const changesRes = await fetch(`${GITLAB_API}/projects/${projectId}/merge_requests/${mrIid}/changes`, { headers });
  if (!changesRes.ok) return [];

  const changesData = await changesRes.json() as { changes?: Array<{ new_path: string; deleted_file: boolean }> };
  const paths = (changesData.changes ?? [])
    .filter(c => !c.deleted_file && isScannable(c.new_path))
    .map(c => c.new_path)
    .slice(0, 50);

  if (paths.length === 0) return [];

  // Fetch file contents
  const files = await Promise.all(
    paths.map(async p => {
      try {
        const encodedPath = encodeURIComponent(p);
        const res = await fetch(
          `${GITLAB_API}/projects/${projectId}/repository/files/${encodedPath}/raw?ref=${headSha}`,
          { headers },
        );
        if (!res.ok) return null;
        return { path: p, content: await res.text() };
      } catch { return null; }
    }),
  );

  return files.filter(Boolean) as Array<{ path: string; content: string }>;
}

async function postGitLabStatus(
  token: string,
  projectId: string | number,
  sha: string,
  state: "pending" | "running" | "success" | "failed",
  description: string,
  targetUrl?: string,
) {
  const GITLAB_API = "https://gitlab.com/api/v4";
  await fetch(`${GITLAB_API}/projects/${projectId}/statuses/${sha}`, {
    method:  "POST",
    headers: { "PRIVATE-TOKEN": token, "Content-Type": "application/json" },
    body:    JSON.stringify({
      state,
      description: description.slice(0, 140),
      name:        "TrustLedger AI Governance",
      target_url:  targetUrl,
    }),
  });
}

export async function POST(req: NextRequest) {
  const rawBody  = await req.text();
  const token    = req.headers.get("x-gitlab-token") ?? "";
  const event    = req.headers.get("x-gitlab-event") ?? "";
  const secret   = process.env.GITLAB_WEBHOOK_TOKEN ?? "";

  // ── 1. Verify token ───────────────────────────────────────────────────────
  if (secret && token !== secret) {
    return NextResponse.json({ error: "invalid_token" }, { status: 401 });
  }

  const payload = JSON.parse(rawBody) as Record<string, unknown>;
  const db      = createServiceClient();

  // Rate limit by project path
  const projectPath = String((payload.project as Record<string, unknown>)?.path_with_namespace ?? "unknown");
  const rl = await checkRateLimit(projectPath, RATE_LIMITS.webhook);
  if (!rl.success) {
    return NextResponse.json({ error: "rate_limit_exceeded" }, { status: 429, headers: rl.headers });
  }

  // Only handle MR events
  if (!event.toLowerCase().includes("merge_request")) {
    return NextResponse.json({ ok: true, skipped: true, event });
  }

  const mr          = payload.object_attributes as Record<string, unknown>;
  const action      = mr?.action as string;
  if (!["open","reopen","update"].includes(action)) {
    return NextResponse.json({ ok: true, skipped: true, action });
  }

  const project     = payload.project as Record<string, unknown>;
  const projectId   = project?.id as number;
  const mrIid       = mr?.iid as number;
  const headSha     = (mr?.last_commit as Record<string, string>)?.id ?? "";
  const repoPath    = project?.path_with_namespace as string;
  const [namespace] = repoPath.split("/");

  // Find org by GitLab namespace
  const { data: orgRecord } = await db
    .from("organizations")
    .select("id")
    .eq("github_org", namespace)
    .single() as { data: { id: string } | null };

  const orgId  = orgRecord?.id ?? null;
  const apiUrl = process.env.NEXT_PUBLIC_APP_URL ?? "https://app.trustledger.dev";

  let gitlabToken: string | null = null;
  if (orgId) {
    gitlabToken = await getGitLabToken(db, orgId);
  } else {
    gitlabToken = process.env.GITLAB_API_TOKEN ?? null;
  }

  // Post "running" status immediately
  if (gitlabToken && headSha) {
    await postGitLabStatus(gitlabToken, projectId, headSha, "running", "TrustLedger: Scanning files…");
  }

  try {
    // Fetch files
    const files = gitlabToken
      ? await fetchGitLabFiles(gitlabToken, projectId, mrIid, headSha)
      : [];

    if (files.length === 0) {
      if (gitlabToken) {
        await postGitLabStatus(gitlabToken, projectId, headSha, "success", "TrustLedger: No scannable files");
      }
      return NextResponse.json({ ok: true, files_scanned: 0 });
    }

    // Run scanner
    const result = runScan({
      repo:       repoPath,
      pr_number:  mrIid,
      commit_sha: headSha,
      branch:     mr?.source_branch as string,
      files,
    });

    // Persist scan
    if (orgId) {
      const { data: repoRec } = await db
        .from("repositories")
        .upsert({ org_id: orgId, repo_full_name: repoPath, default_branch: "main" },
          { onConflict: "org_id,repo_full_name" })
        .select("id").single() as { data: { id: string } | null };

      const { data: scan } = await db.from("scans").insert({
        id:                  result.scan_id,
        org_id:              orgId,
        repo_id:             repoRec?.id ?? null,
        repo_full_name:      repoPath,
        pr_number:           mrIid,
        commit_sha:          headSha,
        branch:              mr?.source_branch as string,
        overall_risk:        result.overall_risk,
        total_ai_percentage: result.total_ai_percentage,
        file_count:          result.files.length,
        triggered_by:        "webhook",
        duration_ms:         result.duration_ms,
      }).select("id").single() as { data: { id: string } | null };

      if (scan) {
        // Invalidate cached dashboard stats so this scan shows up immediately
        await Promise.all(DASHBOARD_CACHE_DAYS.map(days => cacheDel(cacheKeys.dashboard(orgId, days))));
      }

      if (scan && result.files.length > 0) {
        await db.from("scan_files").insert(result.files.map(f => ({
          scan_id: scan.id, org_id: orgId,
          file_path: f.file_path, language: f.language,
          ai_percentage: f.ai_percentage, risk_score: f.risk_score,
          risk_indicators: f.risk_indicators, content_hash: f.content_hash, line_count: f.line_count,
        })));

        const highRisk = result.files.filter(f => f.risk_score === "CRITICAL" || f.risk_score === "HIGH");
        if (highRisk.length > 0) {
          await db.from("violations").insert(highRisk.map(f => ({
            org_id: orgId, scan_id: scan.id, file_path: f.file_path, risk_score: f.risk_score,
            sla_deadline: new Date(Date.now() + (f.risk_score === "CRITICAL" ? 24 : 48) * 3600_000).toISOString(),
          })));
        }
      }

      await writeAuditLog(db, {
        org_id:      orgId,
        event_type:  "scan_complete",
        actor_email: "gitlab-webhook",
        resource_type: "scan", resource_id: result.scan_id,
        payload: { repo: repoPath, mr: mrIid, overall_risk: result.overall_risk, source: "gitlab" },
      });

      await fireOrgWebhooks(db, orgId, {
        type: "scan.completed",
        data: { scan_id: result.scan_id, repo: repoPath, overall_risk: result.overall_risk, source: "gitlab" },
      });
    }

    // Post status back to GitLab
    if (gitlabToken && headSha) {
      const blocked   = result.overall_risk === "CRITICAL" || result.overall_risk === "HIGH";
      const critFiles = result.files.filter(f => f.risk_score === "CRITICAL").length;
      const highFiles = result.files.filter(f => f.risk_score === "HIGH").length;
      const desc      = blocked
        ? `Blocked: ${critFiles + highFiles} file(s) need attestation (${result.overall_risk})`
        : `Passed: ${result.files.length} files · ${(result.total_ai_percentage * 100).toFixed(0)}% AI`;

      await postGitLabStatus(
        gitlabToken, projectId, headSha,
        blocked ? "failed" : "success",
        desc,
        `${apiUrl}/pr/${result.scan_id}`,
      );
    }

    return NextResponse.json({
      ok:           true,
      scan_id:      result.scan_id,
      overall_risk: result.overall_risk,
      files_scanned: result.files.length,
    });

  } catch (err) {
    if (gitlabToken && headSha) {
      await postGitLabStatus(gitlabToken, projectId, headSha, "failed", "TrustLedger: Scan error — retry");
    }
    console.error("GitLab webhook error:", err);
    return NextResponse.json({ error: "scan_failed" }, { status: 500 });
  }
}
