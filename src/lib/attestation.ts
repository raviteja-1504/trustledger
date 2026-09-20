/**
 * Shared attestation logic — used by both POST /api/attest and the Slack
 * `/trustledger attest` command, so the two callers can't drift out of sync
 * and a reliability fix (see syncCheckRunToSuccess below) only needs to
 * live in one place.
 */

import type { SupabaseClient } from "@supabase/supabase-js";
import { buildAttestationHash } from "@/lib/scanner";
import { writeAuditLog } from "@/lib/audit";
import { cacheDel, cacheKeys } from "@/lib/cache";
import { getInstallationToken, updateCheckRun } from "@/lib/github";
import { hasOpenRepoViolations } from "@/lib/repoViolations";
import { syncAutoIncidents } from "@/lib/autoIncidents";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Db = SupabaseClient<any>;

export interface AttestParams {
  org_id:          string;
  user_id?:        string | null;
  scan_id:         string;
  file_path:       string;
  reviewer_email:  string;
  reviewer_github?: string;
}

export type AttestOutcome =
  | { ok: true; attestation_id: string; payload_hash: string; attested_at: string }
  | { ok: false; reason: "scan_not_found" | "insert_failed"; detail?: unknown };

/**
 * Retries the check-run-to-success flip once before giving up — a
 * transient GitHub API blip (rate limit, brief token issue) shouldn't
 * leave a fully-attested PR stuck red with no recourse. On final failure,
 * persists the error to scans.check_run_sync_error instead of only
 * logging it, so the PR review page can surface a visible "GitHub status
 * update failed — Retry" banner (which reuses the existing
 * /api/sync-check-run recovery endpoint) rather than the failure being
 * silently swallowed the way it was before this file existed.
 */
/** Best-effort write of the sync-status diagnostic column -- deliberately
 * isolated in its own try/catch so a failure writing check_run_sync_error
 * itself (e.g. the column doesn't exist yet because this environment's
 * migration hasn't run) can never crash the attestation this function is
 * only meant to be reporting on. Worst case the banner just doesn't appear;
 * the attestation itself (already recorded before this ever runs) is
 * unaffected either way. */
async function recordCheckRunSyncStatus(db: Db, scan_id: string, error: string | null): Promise<void> {
  try {
    await db.from("scans").update({ check_run_sync_error: error }).eq("id", scan_id);
  } catch (err) {
    console.error("Failed to record check_run_sync_error itself (non-fatal, diagnostic only):", err);
  }
}

async function syncCheckRunToSuccess(
  db: Db, scan_id: string, installationId: number, repoFullName: string, checkRunId: number,
): Promise<void> {
  const attempt = async () => {
    const { token } = await getInstallationToken(installationId);
    const [owner, repoName] = repoFullName.split("/");
    await updateCheckRun(token, owner, repoName, checkRunId, {
      name:       "TrustLedger AI Governance",
      status:     "completed",
      conclusion: "success",
      output: {
        title:   "TrustLedger: All required files attested",
        summary: "All CRITICAL and HIGH risk files in this PR have been reviewed and attested. This check no longer blocks merging.",
      },
    });
  };

  try {
    await attempt();
    await recordCheckRunSyncStatus(db, scan_id, null);
  } catch {
    try {
      await attempt();
      await recordCheckRunSyncStatus(db, scan_id, null);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.error("Failed to update check run after attestation (retried once):", err);
      await recordCheckRunSyncStatus(db, scan_id, message.slice(0, 500));
    }
  }
}

export async function performAttestation(db: Db, params: AttestParams): Promise<AttestOutcome> {
  const { org_id, user_id, scan_id, file_path, reviewer_email, reviewer_github } = params;
  const now = new Date().toISOString();

  const { data: scan } = await db
    .from("scans")
    .select("id, repo_full_name, overall_risk, check_run_id, installation_id")
    .eq("id", scan_id)
    .eq("org_id", org_id)
    .single();

  if (!scan) return { ok: false, reason: "scan_not_found" };

  const { data: file } = await db
    .from("scan_files")
    .select("risk_score")
    .eq("scan_id", scan_id)
    .eq("file_path", file_path)
    .single();

  const payloadHash = buildAttestationHash(scan_id, file_path, reviewer_email, now);

  // The attestations table has a PostgreSQL rule that blocks any INSERT with
  // an ON CONFLICT clause (Supabase's .upsert() uses this internally). Use a
  // SELECT-then-INSERT pattern instead: if the record already exists (duplicate
  // click, retry after network error, attest-all re-run) just return the
  // existing row; otherwise insert a fresh one.
  const { data: existing } = await db
    .from("attestations")
    .select("id, created_at")
    .eq("scan_id", scan_id)
    .eq("file_path", file_path)
    .maybeSingle();

  let attestation: { id: string; created_at: string };
  if (existing) {
    attestation = existing as { id: string; created_at: string };
  } else {
    const { data: inserted, error: insErr } = await db
      .from("attestations")
      .insert({
        org_id,
        scan_id,
        file_path,
        risk_score:      file?.risk_score ?? "UNKNOWN",
        reviewer_id:     user_id ?? null,
        reviewer_email,
        reviewer_github: reviewer_github ?? null,
        payload_hash:    payloadHash,
      })
      .select("id, created_at")
      .single();

    if (insErr || !inserted) return { ok: false, reason: "insert_failed", detail: insErr };
    attestation = inserted as { id: string; created_at: string };
  }

  // Mark the file as attested in scan_files so the PR page shows the correct
  // state on reload without relying on localStorage.
  await db
    .from("scan_files")
    .update({ attested: true })
    .eq("scan_id", scan_id)
    .eq("file_path", file_path);

  // Resolve violations for this file across ALL scans in this repo, not just
  // the current scan — the SLA dashboard deduplicates by repo+file_path and
  // keeps the latest scan's violation, so a stale open violation from an
  // earlier scan would still trigger a false SLA breach.
  const { data: repoScans } = await db
    .from("scans")
    .select("id")
    .eq("org_id", org_id)
    .eq("repo_full_name", scan.repo_full_name);

  const scanIds = (repoScans ?? []).map((s: { id: string }) => s.id);
  if (scanIds.length > 0) {
    await db
      .from("violations")
      .update({ status: "resolved", resolved_at: now, resolved_by: user_id ?? null })
      .eq("org_id", org_id)
      .eq("file_path", file_path)
      .in("scan_id", scanIds);
  }

  // Resolve alerts when there are no remaining open violations for the whole
  // repo (see hasOpenRepoViolations' own docs for why repo-scoped, not
  // scan-scoped — multiple scans of the same PR each create their own alert).
  if (!(await hasOpenRepoViolations(db, org_id, scan.repo_full_name))) {
    await db.from("alerts")
      .update({ status: "resolved", resolved_at: now })
      .eq("org_id", org_id)
      .eq("repo", scan.repo_full_name)
      .eq("alert_type", "policy")
      .in("status", ["firing", "acknowledged", "snoozed"]);
  }

  // If this scan came from a GitHub PR and all CRITICAL/HIGH files are now
  // attested, flip the Check Run from "action_required" to "success" so the
  // PR is unblocked.
  if (scan.check_run_id && scan.installation_id) {
    const { count: remaining } = await db
      .from("violations")
      .select("id", { count: "exact", head: true })
      .eq("scan_id", scan_id)
      .neq("status", "resolved")
      .in("risk_score", ["CRITICAL", "HIGH"]);

    if (!remaining) {
      await syncCheckRunToSuccess(db, scan_id, scan.installation_id, scan.repo_full_name, scan.check_run_id);
    }
  }

  await writeAuditLog(db, {
    org_id,
    event_type:    "attestation",
    actor_id:      user_id ?? null,
    actor_email:   reviewer_email,
    resource_type: "attestation",
    resource_id:   attestation.id,
    payload: {
      scan_id, file_path,
      repo:         scan.repo_full_name,
      risk_score:   file?.risk_score ?? "UNKNOWN",
      payload_hash: payloadHash,
    },
  });

  // Invalidate dashboard cache so new attestation is reflected immediately —
  // must cover every day-window the dashboard UI can request (7/30/90).
  await Promise.all([7, 30, 90].map(days => cacheDel(cacheKeys.dashboard(org_id, days))));

  // Attesting a file can clear the trigger for an auto-generated incident —
  // best-effort. Only CRITICAL/HIGH files can ever affect incident state.
  if (file?.risk_score === "CRITICAL" || file?.risk_score === "HIGH") {
    await syncAutoIncidents(db, org_id);
  }

  return { ok: true, attestation_id: attestation.id, payload_hash: payloadHash, attested_at: attestation.created_at };
}
