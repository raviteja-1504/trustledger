/**
 * Bitbucket Webhook Receiver
 * Handles: pullrequest:created, pullrequest:updated
 *
 * Setup in Bitbucket:
 *   Repository Settings → Webhooks → Add webhook
 *   URL: https://app.trustledger.dev/api/webhook/bitbucket
 *   Triggers: Pull Request Created, Pull Request Updated
 *
 * Auth: X-Hub-Signature (HMAC-SHA256 of request body, same pattern as GitHub)
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { runScan } from "@/lib/scanner";
import { writeAuditLog } from "@/lib/audit";
import { fireOrgWebhooks } from "@/lib/outboundWebhook";
import { checkRateLimit, RATE_LIMITS } from "@/lib/rateLimit";
import crypto from "crypto";

const SCANNABLE_EXTS = new Set([
  "py","ts","tsx","js","jsx","rb","go","rs","java","kt","cs","php","cpp","c","swift",
]);

function verifyBitbucketSignature(rawBody: string, signature: string | null, secret: string): boolean {
  if (!signature || !secret) return !secret; // if no secret configured, allow all
  const expected = `sha256=${crypto.createHmac("sha256", secret).update(rawBody).digest("hex")}`;
  try { return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected)); } catch { return false; }
}

async function getBitbucketToken(orgId: string): Promise<{ token: string; type: "app_password" | "oauth" } | null> {
  const db = createServiceClient();
  const { data } = await db
    .from("github_installations")
    .select("access_token")
    .eq("org_id", orgId)
    .eq("github_org", "__bitbucket__")
    .single() as { data: { access_token: string | null } | null };
  if (data?.access_token) return { token: data.access_token, type: "app_password" };
  const envToken = process.env.BITBUCKET_APP_PASSWORD ?? "";
  if (envToken) return { token: envToken, type: "app_password" };
  return null;
}

async function fetchBitbucketFiles(
  token: string,
  workspace: string,
  repoSlug: string,
  prId: number,
  headSha: string,
): Promise<Array<{ path: string; content: string }>> {
  const BBAPI  = "https://api.bitbucket.org/2.0";
  const user   = process.env.BITBUCKET_USERNAME ?? "";
  const authHdr = `Basic ${Buffer.from(`${user}:${token}`).toString("base64")}`;
  const headers  = { Authorization: authHdr };

  // Get PR diff stat
  const diffRes = await fetch(
    `${BBAPI}/repositories/${workspace}/${repoSlug}/pullrequests/${prId}/diffstat`,
    { headers },
  );
  if (!diffRes.ok) return [];
  const diff = await diffRes.json() as { values?: Array<{ new: { path: string }; status: string }> };

  const paths = (diff.values ?? [])
    .filter(f => f.status !== "removed" && SCANNABLE_EXTS.has(f.new?.path?.split(".").pop()?.toLowerCase() ?? ""))
    .map(f => f.new.path)
    .slice(0, 50);

  if (paths.length === 0) return [];

  const files = await Promise.all(
    paths.map(async p => {
      try {
        const res = await fetch(
          `${BBAPI}/repositories/${workspace}/${repoSlug}/src/${headSha}/${encodeURIComponent(p)}`,
          { headers },
        );
        if (!res.ok) return null;
        return { path: p, content: await res.text() };
      } catch { return null; }
    }),
  );
  return files.filter(Boolean) as Array<{ path: string; content: string }>;
}

async function postBitbucketBuildStatus(
  token: string,
  workspace: string,
  repoSlug: string,
  sha: string,
  state: "INPROGRESS" | "SUCCESSFUL" | "FAILED",
  description: string,
  url?: string,
) {
  const user    = process.env.BITBUCKET_USERNAME ?? "";
  const authHdr = `Basic ${Buffer.from(`${user}:${token}`).toString("base64")}`;
  await fetch(
    `https://api.bitbucket.org/2.0/repositories/${workspace}/${repoSlug}/commit/${sha}/statuses/build`,
    {
      method:  "POST",
      headers: { Authorization: authHdr, "Content-Type": "application/json" },
      body:    JSON.stringify({
        state,
        key:         "trustledger",
        name:        "TrustLedger AI Governance",
        description: description.slice(0, 140),
        url:         url ?? "https://app.trustledger.dev",
      }),
    },
  );
}

export async function POST(req: NextRequest) {
  const rawBody = await req.text();
  const sig     = req.headers.get("x-hub-signature-256") ?? req.headers.get("x-hub-signature");
  const event   = req.headers.get("x-event-key") ?? "";
  const secret  = process.env.BITBUCKET_WEBHOOK_SECRET ?? "";

  if (!verifyBitbucketSignature(rawBody, sig, secret)) {
    return NextResponse.json({ error: "invalid_signature" }, { status: 401 });
  }

  const payload = JSON.parse(rawBody) as Record<string, unknown>;
  const db      = createServiceClient();

  // Only handle PR events
  if (!event.startsWith("pullrequest:")) {
    return NextResponse.json({ ok: true, skipped: true, event });
  }

  const pr        = payload.pullrequest as Record<string, unknown>;
  const repo      = payload.repository as Record<string, unknown>;
  const workspace = (repo?.full_name as string)?.split("/")?.[0] ?? "";
  const repoSlug  = (repo?.full_name as string)?.split("/")?.[1] ?? "";
  const repoFull  = repo?.full_name as string;
  const prId      = pr?.id as number;
  const headSha   = ((pr?.source as Record<string, unknown>)?.commit as Record<string, string>)?.hash ?? "";

  if (!workspace || !repoSlug || !prId || !headSha) {
    return NextResponse.json({ ok: true, skipped: true, reason: "missing_fields" });
  }

  // Rate limit
  const rl = await checkRateLimit(`bb:${repoFull}`, RATE_LIMITS.webhook);
  if (!rl.success) return NextResponse.json({ error: "rate_limit_exceeded" }, { status: 429 });

  // Find org
  const { data: orgRecord } = await db
    .from("organizations")
    .select("id")
    .eq("github_org", workspace)
    .single() as { data: { id: string } | null };
  const orgId  = orgRecord?.id ?? null;
  const apiUrl = process.env.NEXT_PUBLIC_APP_URL ?? "https://app.trustledger.dev";

  let bbToken: string | null = null;
  if (orgId) {
    const tokenInfo = await getBitbucketToken(orgId);
    bbToken = tokenInfo?.token ?? null;
  } else {
    bbToken = process.env.BITBUCKET_APP_PASSWORD ?? null;
  }

  if (bbToken && headSha) {
    await postBitbucketBuildStatus(bbToken, workspace, repoSlug, headSha, "INPROGRESS", "TrustLedger: Scanning…");
  }

  try {
    const files = bbToken ? await fetchBitbucketFiles(bbToken, workspace, repoSlug, prId, headSha) : [];

    if (files.length === 0) {
      if (bbToken) await postBitbucketBuildStatus(bbToken, workspace, repoSlug, headSha, "SUCCESSFUL", "No scannable files");
      return NextResponse.json({ ok: true, files_scanned: 0 });
    }

    const result = runScan({ repo: repoFull, pr_number: prId, commit_sha: headSha, files });

    if (orgId) {
      const { data: repoRec } = await db.from("repositories").upsert(
        { org_id: orgId, repo_full_name: repoFull, default_branch: "main" },
        { onConflict: "org_id,repo_full_name" },
      ).select("id").single() as { data: { id: string } | null };

      const { data: scan } = await db.from("scans").insert({
        id: result.scan_id, org_id: orgId, repo_id: repoRec?.id ?? null,
        repo_full_name: repoFull, pr_number: prId, commit_sha: headSha,
        overall_risk: result.overall_risk, total_ai_percentage: result.total_ai_percentage,
        file_count: result.files.length, triggered_by: "webhook", duration_ms: result.duration_ms,
      }).select("id").single() as { data: { id: string } | null };

      if (scan) {
        await db.from("scan_files").insert(result.files.map(f => ({
          scan_id: scan.id, org_id: orgId, file_path: f.file_path, language: f.language,
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
        org_id: orgId, event_type: "scan_complete", actor_email: "bitbucket-webhook",
        resource_type: "scan", resource_id: result.scan_id,
        payload: { repo: repoFull, pr: prId, overall_risk: result.overall_risk, source: "bitbucket" },
      });

      await fireOrgWebhooks(db, orgId, {
        type: "scan.completed",
        data: { scan_id: result.scan_id, repo: repoFull, overall_risk: result.overall_risk, source: "bitbucket" },
      });
    }

    if (bbToken && headSha) {
      const blocked = result.overall_risk === "CRITICAL" || result.overall_risk === "HIGH";
      const count   = result.files.filter(f => f.risk_score === "CRITICAL" || f.risk_score === "HIGH").length;
      await postBitbucketBuildStatus(
        bbToken, workspace, repoSlug, headSha,
        blocked ? "FAILED" : "SUCCESSFUL",
        blocked ? `${count} file(s) need attestation — ${result.overall_risk}` : `Passed · ${result.files.length} files · ${(result.total_ai_percentage*100).toFixed(0)}% AI`,
        `${apiUrl}/pr/${result.scan_id}`,
      );
    }

    return NextResponse.json({ ok: true, scan_id: result.scan_id, overall_risk: result.overall_risk });
  } catch (err) {
    if (bbToken) await postBitbucketBuildStatus(bbToken, workspace, repoSlug, headSha, "FAILED", "TrustLedger: Error — retry");
    console.error("Bitbucket webhook error:", err);
    return NextResponse.json({ error: "scan_failed" }, { status: 500 });
  }
}
