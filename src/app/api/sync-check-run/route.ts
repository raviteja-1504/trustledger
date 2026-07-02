import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey } from "../_middleware";
import { getInstallationToken, updateCheckRun } from "@/lib/github";

/**
 * POST /api/sync-check-run
 *
 * Manually syncs the GitHub Check Run status for a scan.
 * Useful when the scan-worker timed out and left the check run in "in_progress".
 *
 * Body options:
 *   { scan_id: string }                          — look up by scan ID
 *   { repo_full_name: string, pr_number: number } — look up by repo + PR (latest scan)
 *
 * Optional flags:
 *   force: true          — update to "success" even if files are unattested
 *   force_neutral: true  — mark the check run "neutral" (scan failed, no result)
 */
export async function POST(req: NextRequest) {
  const { org_id, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  let body: {
    scan_id?: string;
    repo_full_name?: string;
    pr_number?: number;
    force?: boolean;
    force_neutral?: boolean;
  };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "invalid_json" }, { status: 400 });
  }

  if (!body.scan_id && !(body.repo_full_name && body.pr_number)) {
    return NextResponse.json(
      { error: "provide scan_id or repo_full_name + pr_number" },
      { status: 400 },
    );
  }

  const db = createServiceClient();

  // ── Resolve the scan row ──────────────────────────────────────────────────
  let scan: { id: string; repo_full_name: string; check_run_id: number | null; installation_id: number | null } | null = null;

  if (body.scan_id) {
    const { data } = await db
      .from("scans")
      .select("id, repo_full_name, check_run_id, installation_id")
      .eq("id", body.scan_id)
      .eq("org_id", org_id)
      .single();
    scan = data;
  } else {
    // Latest scan for this repo + PR
    const { data } = await db
      .from("scans")
      .select("id, repo_full_name, check_run_id, installation_id")
      .eq("org_id", org_id)
      .eq("repo_full_name", body.repo_full_name!)
      .eq("pr_number", body.pr_number!)
      .order("created_at", { ascending: false })
      .limit(1)
      .maybeSingle();
    scan = data;
  }

  // ── No scan in DB — worker may have crashed before persisting anything.
  // Try to recover the check_run_id from the webhook_deliveries table
  // (we store it there since we can't guarantee the scan row exists).
  if (!scan && body.repo_full_name && body.pr_number) {
    const repoPayloadFilter = `%"full_name":"${body.repo_full_name}"%`;
    const { data: delivery } = await db
      .from("webhook_deliveries")
      .select("payload, org_id")
      .eq("org_id", org_id)
      .ilike("payload::text", repoPayloadFilter)
      .order("created_at", { ascending: false })
      .limit(5)
      .maybeSingle();

    const deliveryPayload = delivery?.payload as Record<string, unknown> | null;
    const recoveredRunId  = deliveryPayload?.tl_check_run_id ? Number(deliveryPayload.tl_check_run_id) : null;
    const recoveredInstId = (deliveryPayload?.installation as Record<string, unknown> | null)?.id
      ? Number((deliveryPayload!.installation as Record<string, unknown>).id) : null;

    if (recoveredRunId && recoveredInstId) {
      try {
        const { token } = await getInstallationToken(recoveredInstId);
        const [owner, repoName] = body.repo_full_name.split("/");
        await updateCheckRun(token, owner, repoName, String(recoveredRunId), {
          name:       "TrustLedger AI Governance",
          status:     "completed",
          conclusion: "neutral",
          output: {
            title:   "Scan incomplete",
            summary: "TrustLedger encountered an error and could not complete the scan. Push a new commit to re-trigger.",
          },
        });
        return NextResponse.json({
          synced:    true,
          conclusion: "neutral",
          recovered: true,
          message:   "Recovered check run from webhook_deliveries — scan was never persisted.",
        });
      } catch (e) {
        return NextResponse.json({ error: "github_update_failed", detail: String(e) }, { status: 502 });
      }
    }

    return NextResponse.json({
      error:  "scan_not_found",
      detail: `No scan or webhook delivery found for ${body.repo_full_name} PR #${body.pr_number}. Push a new commit to re-trigger.`,
    }, { status: 404 });
  }

  if (!scan) {
    return NextResponse.json({ error: "scan_not_found" }, { status: 404 });
  }

  if (!scan.check_run_id || !scan.installation_id) {
    return NextResponse.json({
      synced:  false,
      reason:  "no_check_run",
      message: "This scan has no associated GitHub Check Run.",
    });
  }

  // ── force_neutral: mark stuck check run as neutral (scan failed) ──────────
  if (body.force_neutral) {
    try {
      const { token } = await getInstallationToken(scan.installation_id);
      const [owner, repoName] = scan.repo_full_name.split("/");
      await updateCheckRun(token, owner, repoName, scan.check_run_id, {
        name:       "TrustLedger AI Governance",
        status:     "completed",
        conclusion: "neutral",
        output: {
          title:   "Scan incomplete",
          summary: "TrustLedger encountered an error and could not complete the scan. Push a new commit to re-trigger.",
        },
      });
      return NextResponse.json({ synced: true, conclusion: "neutral", scan_id: scan.id });
    } catch (e) {
      return NextResponse.json({ error: "github_update_failed", detail: String(e) }, { status: 502 });
    }
  }

  // ── Count CRITICAL/HIGH files and their attestations ─────────────────────
  const { count: totalHighCrit } = await db
    .from("scan_files")
    .select("id", { count: "exact", head: true })
    .eq("scan_id", scan.id)
    .in("risk_score", ["CRITICAL", "HIGH"]);

  const { count: attestedCount } = await db
    .from("attestations")
    .select("id", { count: "exact", head: true })
    .eq("scan_id", scan.id)
    .in("risk_score", ["CRITICAL", "HIGH"]);

  const total    = totalHighCrit ?? 0;
  const attested = attestedCount ?? 0;

  if (total > 0 && attested < total && !body.force) {
    return NextResponse.json({
      synced:   false,
      reason:   "files_pending",
      message:  `${total - attested} of ${total} HIGH/CRITICAL files still need attestation. Pass force:true to override.`,
      attested,
      total,
      scan_id:  scan.id,
    });
  }

  // ── All files attested (or forced) — update check run to success ──────────
  try {
    const { token } = await getInstallationToken(scan.installation_id);
    const [owner, repoName] = scan.repo_full_name.split("/");
    const conclusion = (total > 0 && attested >= total) ? "success" : "neutral";
    await updateCheckRun(token, owner, repoName, scan.check_run_id, {
      name:       "TrustLedger AI Governance",
      status:     "completed",
      conclusion,
      output: {
        title:   conclusion === "success"
          ? "TrustLedger: All required files attested"
          : "TrustLedger: No CRITICAL/HIGH files detected",
        summary: conclusion === "success"
          ? "All CRITICAL and HIGH risk files in this PR have been reviewed and attested."
          : "No CRITICAL or HIGH risk AI-generated files were detected in this PR.",
      },
    });

    // Resolve any open violations for this scan
    await db
      .from("violations")
      .update({ status: "resolved", resolved_at: new Date().toISOString() })
      .eq("scan_id", scan.id)
      .neq("status", "resolved")
      .in("risk_score", ["CRITICAL", "HIGH"]);

    return NextResponse.json({
      synced:     true,
      conclusion,
      scan_id:    scan.id,
      message:    "GitHub Check Run updated.",
      attested,
      total,
    });
  } catch (e) {
    console.error("[sync-check-run] Failed to update GitHub check run:", e);
    return NextResponse.json(
      { error: "github_update_failed", detail: String(e) },
      { status: 502 },
    );
  }
}
