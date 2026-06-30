import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey } from "../../_middleware";
import { hasOpenRepoViolations } from "@/lib/repoViolations";

/**
 * POST /api/alerts/recheck
 *
 * Re-checks whether a repo's policy alerts should be resolved, after the
 * fact. /api/attest does this same check inline on every individual file
 * attestation, but under concurrent writes (Attest All firing N requests in
 * parallel, or two reviewers attesting different files around the same
 * time) every one of those inline checks can race: each request can see
 * "N-1 others still open" at the exact moment it checks, even though by the
 * time all requests have settled the true count is zero. None of the
 * individual checks ever observes zero, so the alert never resolves.
 *
 * This endpoint runs the same "0 open violations -> resolve alerts" check
 * once, after the caller has confirmed all of its attestation requests have
 * already completed (Promise.allSettled), so it sees the final, correct
 * state rather than a mid-flight snapshot.
 */
export async function POST(req: NextRequest) {
  const { org_id, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });

  let body: { scan_id?: string };
  try { body = await req.json(); } catch { return NextResponse.json({ error: "invalid_json" }, { status: 400 }); }
  if (!body.scan_id) return NextResponse.json({ error: "scan_id_required" }, { status: 400 });

  const db  = createServiceClient();
  const now = new Date().toISOString();

  const { data: scan } = await db
    .from("scans")
    .select("id, repo_full_name")
    .eq("id", body.scan_id)
    .eq("org_id", org_id)
    .single();

  if (!scan) return NextResponse.json({ error: "scan_not_found" }, { status: 404 });

  // Dedup-aware check: a naive "any violation row != resolved across all
  // scan_ids" count is wrong for a repo scanned repeatedly (one scan per PR
  // commit) — a dangling open row from an EARLIER scan, for a file_path that
  // a LATER scan no longer flags (renamed/removed/fixed), is never touched
  // since the user only ever attests files visible in the current scan's
  // file list. That stale row kept the count above zero forever.
  if (await hasOpenRepoViolations(db, org_id, scan.repo_full_name)) {
    return NextResponse.json({ resolved: false });
  }

  const { data: resolvedAlerts } = await db
    .from("alerts")
    .update({ status: "resolved", resolved_at: now })
    .eq("org_id", org_id)
    .eq("repo", scan.repo_full_name)
    .eq("alert_type", "policy")
    .in("status", ["firing", "acknowledged", "snoozed"])
    .select("id");

  return NextResponse.json({ resolved: true, alerts_resolved: resolvedAlerts?.length ?? 0 });
}
