/**
 * POST /api/repo-scan-worker
 *
 * Invoked asynchronously (via QStash, or a direct fallback — see
 * lib/queue.ts's enqueueRepoScan) to do the actual work of a whole-
 * repository scan: resolve a token, list the repo tree, fetch every
 * candidate file's content, run it through the scanner, and persist
 * results — mirroring api/scan-worker/route.ts's persistence shape, but as
 * a self-contained one-shot pass rather than reusing scan-worker's delta/
 * cross-PR-attestation-inheritance logic, which is specific to a single PR
 * evolving over multiple pushes and doesn't apply to a one-time repo scan.
 */
import { NextRequest, NextResponse } from "next/server";
import { Receiver } from "@upstash/qstash";
import { createServiceClient } from "@/lib/supabase";
import { getInstallationToken, getDefaultBranch, resolveCommitSha, listRepoTree, fetchFileContents } from "@/lib/github";
import { analyzeFile } from "@/lib/scanner";
import { writeAuditLog } from "@/lib/audit";
import { cacheDel, cacheKeys, invalidateSecretsCache, invalidateViolationsCache } from "@/lib/cache";
import { syncAutoIncidents } from "@/lib/autoIncidents";
import { isRepoScanCandidate, REPO_SCAN_MAX_FILES, REPO_SCAN_MAX_FILE_BYTES } from "@/lib/scannableFiles";
import { safeError } from "@/lib/errors";
import crypto from "crypto";
import type { RepoScanJob } from "@/lib/queue";

export const maxDuration = 300;

const DASHBOARD_CACHE_DAYS = [7, 30, 90];
const RISK_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];

async function verifyRequest(req: NextRequest, rawBody: string): Promise<boolean> {
  const expectedSecret = (process.env.INTERNAL_SECRET ?? "dev").replace(/^﻿/, "").trim();
  if (req.headers.get("x-internal-secret") === expectedSecret) return true;

  const currentSigningKey = (process.env.QSTASH_CURRENT_SIGNING_KEY ?? "").replace(/^﻿/, "").replace(/\r/g, "").trim();
  const nextSigningKey    = (process.env.QSTASH_NEXT_SIGNING_KEY ?? "").replace(/^﻿/, "").replace(/\r/g, "").trim();
  if (currentSigningKey && nextSigningKey) {
    try {
      const receiver = new Receiver({ currentSigningKey, nextSigningKey });
      return await receiver.verify({ signature: req.headers.get("upstash-signature") ?? "", body: rawBody, url: req.url });
    } catch (err) {
      console.error("[repo-scan-worker] QStash signature verification failed:", err);
      return false;
    }
  }
  return false;
}

/** Installation token if this org has the GitHub App connected to `owner`; undefined otherwise. */
async function resolveToken(db: ReturnType<typeof createServiceClient>, orgId: string, owner: string): Promise<string | undefined> {
  const { data } = await db
    .from("github_installations")
    .select("installation_id")
    .eq("org_id", orgId)
    .eq("github_org", owner)
    .maybeSingle();
  if (data?.installation_id) {
    try {
      const { token } = await getInstallationToken(data.installation_id);
      return token;
    } catch (err) {
      console.error("[repo-scan-worker] installation token fetch failed, falling back:", err);
    }
  }
  const envToken = (process.env.GITHUB_API_TOKEN ?? "").trim();
  return envToken || undefined;
}

async function markFailed(db: ReturnType<typeof createServiceClient>, scanId: string, message: string): Promise<void> {
  await db.from("scans").update({ status: "failed", error_message: message.slice(0, 500) }).eq("id", scanId);
}

export async function POST(req: NextRequest) {
  const rawBody = await req.text();
  if (!await verifyRequest(req, rawBody)) {
    return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  }

  const job = JSON.parse(rawBody) as RepoScanJob;
  const { scan_id: scanId, org_id: orgId, owner, repo } = job;
  const repoFullName = `${owner}/${repo}`;
  const db = createServiceClient();
  const startedAt = Date.now();

  await db.from("scans").update({ status: "analyzing" }).eq("id", scanId);

  try {
    const token = await resolveToken(db, orgId, owner);
    const branch = job.branch ?? await getDefaultBranch(token, owner, repo);
    const headSha = await resolveCommitSha(token, owner, repo, branch);

    const { entries, truncated } = await listRepoTree(token, owner, repo, headSha);
    if (truncated) console.warn(`[repo-scan-worker] tree truncated for ${repoFullName} — scanning a partial listing`);

    const candidates = entries
      .filter(e => isRepoScanCandidate(e.path))
      .filter(e => (e.size ?? 0) <= REPO_SCAN_MAX_FILE_BYTES)
      .slice(0, REPO_SCAN_MAX_FILES);

    // Unauthenticated GitHub API access is capped at 60 requests/hour per IP
    // — nowhere near enough for a real repo scan beyond a handful of files.
    // Fail fast with an actionable message instead of quietly rate-limiting
    // partway through and returning a misleadingly incomplete scan.
    if (!token && candidates.length > 50) {
      await markFailed(db, scanId,
        `${repoFullName} has ${candidates.length} scannable files but no GitHub token is available (not connected via the GitHub App, and GITHUB_API_TOKEN is unset). ` +
        "Unauthenticated GitHub API access is limited to 60 requests/hour, which isn't enough for a repo this size. Set GITHUB_API_TOKEN or connect the GitHub App to this org.");
      return NextResponse.json({ ok: false, reason: "no_token_repo_too_large" });
    }

    const files = await fetchFileContents(token, owner, repo, headSha, candidates.map(c => c.path));

    // Incremental reuse: a file whose content is byte-identical to one
    // already scanned for this org (same content_hash) doesn't need
    // analyzeFile() run again — reuse the prior result. Cheap win for
    // re-scanning a repo that's mostly unchanged since last time.
    const hashed = files.map(f => ({ ...f, hash: crypto.createHash("sha256").update(f.content).digest("hex") }));
    const hashes = [...new Set(hashed.map(f => f.hash))];
    const { data: priorRows } = hashes.length > 0
      ? await db.from("scan_files")
          .select("content_hash, language, ai_percentage, risk_score, risk_indicators, indicators, line_count")
          .eq("org_id", orgId)
          .in("content_hash", hashes)
          .limit(hashes.length * 2)
      : { data: [] as never[] };
    const priorByHash = new Map((priorRows ?? []).map(r => [r.content_hash as string, r]));

    interface Analyzed {
      file_path: string; language: string; ai_percentage: number; risk_score: string;
      risk_indicators: string[]; indicators: unknown[]; content_hash: string; line_count: number;
      // null for a reused (content_hash already stored elsewhere for this
      // org) file -- same dedup rationale as scan-worker.ts's "inherited
      // files" path: no reason to store the same source text twice. Stored
      // directly for a newly-analysed file, or the page has nothing to
      // display in the code viewer for it.
      content: string | null;
      reused: boolean;
    }
    const analyzed: Analyzed[] = hashed.map(f => {
      const prior = priorByHash.get(f.hash);
      if (prior) {
        return {
          file_path: f.path, language: prior.language ?? "text", ai_percentage: prior.ai_percentage ?? 0,
          risk_score: prior.risk_score ?? "LOW", risk_indicators: prior.risk_indicators ?? [],
          indicators: prior.indicators ?? [], content_hash: f.hash, line_count: prior.line_count ?? 0,
          content: null, reused: true,
        };
      }
      const result = analyzeFile(f.path, f.content);
      return {
        file_path: f.path, language: result.language, ai_percentage: result.ai_percentage,
        risk_score: result.risk_score, risk_indicators: result.risk_indicators,
        indicators: result.indicators, content_hash: result.content_hash, line_count: result.line_count,
        content: f.content, reused: false,
      };
    });

    const { data: repoRec } = await db
      .from("repositories")
      .upsert({ org_id: orgId, repo_full_name: repoFullName, default_branch: branch }, { onConflict: "org_id,repo_full_name" })
      .select("id").single();

    if (analyzed.length > 0) {
      await db.from("scan_files").insert(analyzed.map(f => ({
        scan_id: scanId, org_id: orgId, file_path: f.file_path, language: f.language,
        ai_percentage: f.ai_percentage, risk_score: f.risk_score, risk_indicators: f.risk_indicators,
        indicators: f.indicators, content_hash: f.content_hash, line_count: f.line_count,
        content: f.content,
      })));
    }

    const violationFiles = analyzed.filter(f => f.risk_score === "CRITICAL" || f.risk_score === "HIGH");
    if (violationFiles.length > 0) {
      const slaH = violationFiles.some(f => f.risk_score === "CRITICAL") ? 24 : 48;
      await db.from("violations").insert(violationFiles.map(f => ({
        org_id: orgId, scan_id: scanId, file_path: f.file_path, risk_score: f.risk_score,
        sla_deadline: new Date(Date.now() + slaH * 3600_000).toISOString(),
      })));
      await invalidateViolationsCache(orgId);
    }

    const secretFiles = analyzed.filter(f => f.risk_indicators.includes("hardcoded-secret"));
    if (secretFiles.length > 0) {
      await db.from("secret_findings").insert(
        secretFiles.flatMap(f =>
          (f.indicators as Array<{ id: string; severity: string; label: string; line?: number }>)
            .filter(i => i.id === "hardcoded-secret")
            .map(i => ({
              org_id: orgId, scan_id: scanId, file_path: f.file_path, secret_type: "detected",
              severity: (i.severity === "critical" ? "CRITICAL" : i.severity === "high" ? "HIGH" : "MEDIUM") as "CRITICAL" | "HIGH" | "MEDIUM",
              label: i.label, masked_value: "detected", line_number: i.line ?? null,
            })),
        ),
      );
      await invalidateSecretsCache(orgId);
    }

    const overallRisk = analyzed.reduce<string>((max, f) =>
      RISK_ORDER.indexOf(f.risk_score) > RISK_ORDER.indexOf(max) ? f.risk_score : max, "LOW");
    const avgAi = analyzed.length > 0 ? analyzed.reduce((s, f) => s + f.ai_percentage, 0) / analyzed.length : 0;
    const reusedCount = analyzed.filter(f => f.reused).length;

    await db.from("scans").update({
      commit_sha: headSha, branch, status: "completed", repo_id: repoRec?.id ?? null,
      overall_risk: overallRisk, total_ai_percentage: avgAi, file_count: analyzed.length,
      files_total: candidates.length, files_scanned: analyzed.length,
      duration_ms: Date.now() - startedAt,
    }).eq("id", scanId);

    await Promise.all(DASHBOARD_CACHE_DAYS.map(days => cacheDel(cacheKeys.dashboard(orgId, days))));
    await cacheDel(cacheKeys.dependencies(orgId));
    await syncAutoIncidents(db, orgId);

    await writeAuditLog(db, {
      org_id: orgId, event_type: "scan_complete", actor_email: "repo-scan",
      resource_type: "scan", resource_id: scanId,
      payload: {
        repo: repoFullName, branch, commit_sha: headSha, overall_risk: overallRisk,
        files_total: candidates.length, files_scanned: analyzed.length, files_reused: reusedCount,
        truncated, scan_mode: "repo",
      },
    });

    return NextResponse.json({ ok: true, scan_id: scanId, files_scanned: analyzed.length, overall_risk: overallRisk });
  } catch (err) {
    console.error("[repo-scan-worker] error:", err);
    await markFailed(db, scanId, err instanceof Error ? err.message : String(err));
    return safeError(err, { code: "repo_scan_failed", message: "The repository scan could not be completed." });
  }
}
