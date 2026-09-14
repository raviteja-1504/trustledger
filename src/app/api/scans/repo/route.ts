/**
 * POST /api/scans/repo
 *
 * Whole-repository scan (Phase 2 of the scanner-hardening plan) — as
 * opposed to /api/scans, which requires the caller to paste in file content
 * directly, and the GitHub-webhook path, which only ever sees a single PR's
 * changed files. This fetches and scans every candidate file in a repo at a
 * given branch/commit.
 *
 * Returns immediately with a QUEUED scan row; the actual fetch+analyse work
 * happens in /api/repo-scan-worker, invoked via QStash (or a direct
 * synchronous fallback — see lib/queue.ts). Poll GET /api/scans/{id} for
 * status (queued -> analyzing -> completed|failed).
 */
import { NextRequest, NextResponse } from "next/server";
import { waitUntil } from "@vercel/functions";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey } from "../../_middleware";
import { checkRateLimit, RATE_LIMITS } from "@/lib/rateLimit";
import { enqueueRepoScan } from "@/lib/queue";
import { safeError } from "@/lib/errors";

interface RepoScanRequest { owner?: string; repo?: string; branch?: string }

export async function POST(req: NextRequest) {
  const auth = await verifyApiKey(req);
  if (auth.error) return NextResponse.json({ error: auth.error }, { status: 401 });
  const { org_id } = auth;

  const rl = await checkRateLimit(org_id, RATE_LIMITS.repoScan);
  if (!rl.success) return NextResponse.json({ error: "rate_limit_exceeded" }, { status: 429, headers: rl.headers });

  let body: RepoScanRequest;
  try { body = await req.json() as RepoScanRequest; }
  catch { return NextResponse.json({ error: "invalid_json" }, { status: 400 }); }

  const owner  = body.owner?.trim();
  const repo   = body.repo?.trim();
  const branch = body.branch?.trim() || null;
  if (!owner || !repo || !/^[\w.-]+$/.test(owner) || !/^[\w.-]+$/.test(repo)) {
    return NextResponse.json({ error: "invalid_repo", message: "owner and repo are required (GitHub org/user and repository name, not a full URL)." }, { status: 400 });
  }

  const db = createServiceClient();
  const repoFullName = `${owner}/${repo}`;

  // One in-flight repo scan per repo per org at a time -- otherwise two
  // concurrent triggers race to write the same scan_files/violations rows.
  const { data: inFlight } = await db
    .from("scans")
    .select("id")
    .eq("org_id", org_id)
    .eq("repo_full_name", repoFullName)
    .eq("scan_mode", "repo")
    .in("status", ["queued", "analyzing"])
    .limit(1)
    .maybeSingle();
  if (inFlight) {
    return NextResponse.json({ error: "scan_already_running", scan_id: inFlight.id }, { status: 409 });
  }

  const { data: scan, error: insertErr } = await db
    .from("scans")
    .insert({
      org_id, repo_full_name: repoFullName, commit_sha: "pending",
      branch, triggered_by: "manual", scan_mode: "repo", status: "queued",
      overall_risk: "LOW", total_ai_percentage: 0, file_count: 0,
    })
    .select("id")
    .single();

  if (insertErr || !scan) {
    return safeError(insertErr, { code: "scan_create_failed", message: "Could not start the repository scan. Please try again." });
  }

  // Deferred via waitUntil rather than awaited -- the response below doesn't
  // depend on the scan actually finishing (the caller polls scan status
  // separately), and enqueueRepoScan has its own synchronous directFetch
  // fallback that would otherwise block this response for the full scan
  // duration if QStash is ever unavailable. Same reasoning as the GitHub
  // webhook handler's waitUntil (see api/webhook/github/route.ts).
  waitUntil(
    enqueueRepoScan({ scan_id: scan.id, org_id, owner, repo, branch })
      .catch(err => console.error("[scans/repo] enqueueRepoScan failed:", err)),
  );

  return NextResponse.json({ ok: true, scan_id: scan.id, status: "queued" });
}
