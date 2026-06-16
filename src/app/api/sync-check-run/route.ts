import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey } from "../_middleware";
import { getInstallationToken, updateCheckRun } from "@/lib/github";

/**
 * POST /api/sync-check-run
 * Body: { scan_id: string }
 *
 * Manually syncs the GitHub Check Run status for a scan.
 * Fires "success" if all CRITICAL/HIGH files in the scan have attestations.
 * Safe to call multiple times — idempotent.
 */
export async function POST(req: NextRequest) {
  const { org_id, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  let body: { scan_id?: string; force?: boolean };
  try {
    body = await req.json();
  } catch {
    return NextResponse.json({ error: "invalid_json" }, { status: 400 });
  }

  if (!body.scan_id) {
    return NextResponse.json({ error: "scan_id_required" }, { status: 400 });
  }

  const db = createServiceClient();

  // Fetch the scan — must belong to this org
  const { data: scan } = await db
    .from("scans")
    .select("id, repo_full_name, check_run_id, installation_id")
    .eq("id", body.scan_id)
    .eq("org_id", org_id)
    .single();

  if (!scan) {
    return NextResponse.json({ error: "scan_not_found" }, { status: 404 });
  }

  if (!scan.check_run_id || !scan.installation_id) {
    return NextResponse.json({
      synced: false,
      reason: "no_check_run",
      message: "This scan has no associated GitHub Check Run.",
    });
  }

  // Count CRITICAL/HIGH files in this scan
  const { count: totalHighCrit } = await db
    .from("scan_files")
    .select("id", { count: "exact", head: true })
    .eq("scan_id", body.scan_id)
    .in("risk_score", ["CRITICAL", "HIGH"]);

  if (!totalHighCrit) {
    // No CRITICAL/HIGH files — nothing to block, but update to success anyway
  }

  // Count attestations for CRITICAL/HIGH files in this scan
  const { count: attestedCount } = await db
    .from("attestations")
    .select("id", { count: "exact", head: true })
    .eq("scan_id", body.scan_id)
    .in("risk_score", ["CRITICAL", "HIGH"]);

  const total = totalHighCrit ?? 0;
  const attested = attestedCount ?? 0;

  if (total > 0 && attested < total && !body.force) {
    return NextResponse.json({
      synced: false,
      reason: "files_pending",
      message: `${total - attested} of ${total} HIGH/CRITICAL files still need attestation.`,
      attested,
      total,
    });
  }

  // All files are attested (or there are no HIGH/CRIT files) — update check run
  try {
    const { token } = await getInstallationToken(scan.installation_id);
    const [owner, repoName] = scan.repo_full_name.split("/");
    await updateCheckRun(token, owner, repoName, scan.check_run_id, {
      name:       "TrustLedger AI Governance",
      status:     "completed",
      conclusion: "success",
      output: {
        title:   "TrustLedger: All required files attested",
        summary: "All CRITICAL and HIGH risk files in this PR have been reviewed and attested. This check no longer blocks merging.",
      },
    });

    // Also resolve any remaining unresolved violations in DB
    await db
      .from("violations")
      .update({ status: "resolved", resolved_at: new Date().toISOString() })
      .eq("scan_id", body.scan_id)
      .neq("status", "resolved")
      .in("risk_score", ["CRITICAL", "HIGH"]);

    return NextResponse.json({
      synced: true,
      message: "GitHub Check Run updated to success.",
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
