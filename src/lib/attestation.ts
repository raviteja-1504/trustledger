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
import { blockingRisks, countOpenBlocking, loadGate } from "@/lib/mergeGate";
import { syncAutoIncidents } from "@/lib/autoIncidents";
import { attestPermissionFor, type Permissions } from "@/lib/permissions";

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Db = SupabaseClient<any>;

export interface AttestParams {
  org_id:          string;
  user_id?:        string | null;
  scan_id:         string;
  file_path:       string;
  reviewer_email:  string;
  reviewer_github?: string;
  /** The attester's effective permissions; the file's risk score decides which attest flag is needed. */
  permissions:     Permissions;
}

export type AttestOutcome =
  | { ok: true; attestation_id: string; payload_hash: string; attested_at: string }
  | { ok: false; reason: "scan_not_found" | "insert_failed"; detail?: unknown }
  | { ok: false; reason: "forbidden"; risk_score: string };

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

/**
 * How a caller runs work that doesn't decide the response (the org-wide incident sync): POST /api/attest hands it
 * to next/server's after(), so the reviewer isn't kept waiting on it; by default it runs inline.
 */
export type Defer = (task: () => Promise<void>) => void;

export async function performAttestation(db: Db, params: AttestParams, opts: { defer?: Defer } = {}): Promise<AttestOutcome> {
  const { org_id, user_id, scan_id, file_path, reviewer_email, reviewer_github, permissions } = params;
  const now = new Date().toISOString();

  // Independent reads, at once: the scan, the file, an existing sign-off, and the org's merge gate.
  const [{ data: scan }, { data: file }, { data: existing }, gate] = await Promise.all([
    db.from("scans").select("id, repo_full_name, overall_risk, check_run_id, installation_id").eq("id", scan_id).eq("org_id", org_id).single(),
    db.from("scan_files").select("risk_score, content_hash").eq("scan_id", scan_id).eq("file_path", file_path).single(),
    db.from("attestations").select("id, created_at").eq("scan_id", scan_id).eq("file_path", file_path).maybeSingle(),
    loadGate(db, org_id),
  ]);

  if (!scan) return { ok: false, reason: "scan_not_found" };

  // Checked against the file's stored risk, not anything the client sends: a role may sign off HIGH files
  // but not CRITICAL ones. A file with no row is treated as lower-risk (UNKNOWN), as it is recorded below.
  const risk = (file?.risk_score as string | undefined) ?? "UNKNOWN";
  if (!permissions[attestPermissionFor(risk)]) return { ok: false, reason: "forbidden", risk_score: risk };

  const payloadHash = buildAttestationHash(scan_id, file_path, reviewer_email, now);

  // The attestations table has a PostgreSQL rule that blocks any INSERT with
  // an ON CONFLICT clause (Supabase's .upsert() uses this internally). Use a
  // SELECT-then-INSERT pattern instead: if the record already exists (duplicate
  // click, retry after network error, attest-all re-run) just return the
  // existing row (read above); otherwise insert a fresh one.
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

  // The sign-off covers this file's CONTENT: every scan of this repo where the file is byte-identical (the same
  // content_hash) -- a newer push or PR that didn't touch it, or an older scan of the same code. It used to resolve
  // the file's violations in EVERY scan of the repo, so another PR's different version of the file lost its
  // violation without anyone reviewing it; and attesting through an older scan's link never reached the newer scan
  // whose check, alert and incident were waiting on it.
  // Found from the copies of this content (few), then kept to this repo -- not by listing every scan of the repo and
  // sending all their ids back in the next query, which grew with every scan.
  const contentHash = (file as { content_hash?: string | null } | null)?.content_hash ?? null;
  const findSameContent = async (): Promise<string[]> => {
    if (!contentHash) return [];
    const { data: copies } = await db.from("scan_files").select("scan_id")
      .eq("org_id", org_id).eq("file_path", file_path).eq("content_hash", contentHash);
    const ids = [...new Set((copies ?? []).map((r: { scan_id: string }) => r.scan_id))].filter(id => id !== scan_id);
    if (ids.length === 0) return [];
    const { data: inRepo } = await db.from("scans").select("id")
      .eq("org_id", org_id).eq("repo_full_name", scan.repo_full_name).in("id", ids);
    return [...new Set((inRepo ?? []).map((s: { id: string }) => s.id))];
  };
  const [, sameContent] = await Promise.all([
    // Mark the file as attested in scan_files so the PR page shows the correct state on reload without relying on
    // localStorage.
    db.from("scan_files").update({ attested: true }).eq("scan_id", scan_id).eq("file_path", file_path),
    findSameContent(),
  ]);
  if (sameContent.length > 0) {
    const { data: already } = await db.from("attestations").select("scan_id")
      .eq("org_id", org_id).eq("file_path", file_path).in("scan_id", sameContent);
    const have = new Set((already ?? []).map((a: { scan_id: string }) => a.scan_id));
    const missing = sameContent.filter(id => !have.has(id));
    if (missing.length > 0) {
      // Plain INSERT: the table's rule blocks ON CONFLICT. Marked as carried from this attestation.
      await db.from("attestations").insert(missing.map(id => ({
        org_id, scan_id: id, file_path,
        risk_score:      file?.risk_score ?? "UNKNOWN",
        reviewer_id:     user_id ?? null,
        reviewer_email,
        reviewer_github: reviewer_github ?? null,
        payload_hash:    `inherited:${attestation.id}`,
      })));
      await db.from("scan_files").update({ attested: true }).eq("org_id", org_id).eq("file_path", file_path).in("scan_id", missing);
    }
  }
  const covered = [scan_id, ...sameContent];
  await db
    .from("violations")
    .update({ status: "resolved", resolved_at: now, resolved_by: user_id ?? null })
    .eq("org_id", org_id)
    .eq("file_path", file_path)
    .in("scan_id", covered);

  // Each covered scan whose blocking files (the org's merge gate: CRITICAL, and HIGH unless the org turned that
  // off) are now all signed off: its PR alert is done and its GitHub check unblocks. Newest first, bounded -- a
  // file unchanged across many pushes is covered by every one of them.
  const { data: coveredScans } = await db
    .from("scans")
    .select("id, check_run_id, installation_id, created_at")
    .eq("org_id", org_id)
    .in("id", covered)
    .order("created_at", { ascending: false })
    .limit(20);
  // Each covered scan independently: they used to be checked one after another, a GitHub call apiece.
  await Promise.all(((coveredScans ?? []) as { id: string; check_run_id: number | null; installation_id: number | null }[]).map(async s => {
    if (await countOpenBlocking(db, s.id, gate, org_id)) return;
    await Promise.all([
      db.from("alerts")
        .update({ status: "resolved", resolved_at: now })
        .eq("org_id", org_id)
        .eq("scan_id", s.id)
        .eq("alert_type", "policy")
        .in("status", ["firing", "acknowledged", "snoozed"]),
      s.check_run_id && s.installation_id ? syncCheckRunToSuccess(db, s.id, s.installation_id, scan.repo_full_name, s.check_run_id) : null,
    ]);
  }));

  await Promise.all([
    // And every policy alert of the repo once nothing in it is open (alerts of superseded scans included).
    hasOpenRepoViolations(db, org_id, scan.repo_full_name, blockingRisks(gate)).then(open => open ? null : db.from("alerts")
      .update({ status: "resolved", resolved_at: now })
      .eq("org_id", org_id)
      .eq("repo", scan.repo_full_name)
      .eq("alert_type", "policy")
      .in("status", ["firing", "acknowledged", "snoozed"])),
    writeAuditLog(db, {
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
    }),
    // Invalidate dashboard cache so new attestation is reflected immediately —
    // must cover every day-window the dashboard UI can request (7/30/90).
    ...[7, 30, 90].map(days => cacheDel(cacheKeys.dashboard(org_id, days))),
  ]);

  // Attesting a file can clear the trigger for an auto-generated incident — best-effort, and an org-wide
  // aggregation: deferred past the response when the caller can, so the reviewer isn't kept waiting on it.
  // Only CRITICAL/HIGH files can ever affect incident state.
  if (file?.risk_score === "CRITICAL" || file?.risk_score === "HIGH") {
    if (opts.defer) opts.defer(() => syncAutoIncidents(db, org_id));
    else await syncAutoIncidents(db, org_id);
  }

  return { ok: true, attestation_id: attestation.id, payload_hash: payloadHash, attested_at: attestation.created_at };
}
