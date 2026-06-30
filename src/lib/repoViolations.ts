/**
 * Repo-wide "is there any real open violation" check, used to decide
 * whether to resolve a repo's policy alerts after an attestation.
 *
 * A naive "count rows where status != resolved across all scan_ids for this
 * repo" is WRONG: when a repo is scanned repeatedly (each PR commit creates
 * a new scan), an earlier scan's violation for a file_path that was later
 * renamed, deleted, or simply no longer flagged CRITICAL/HIGH in a newer
 * scan is left dangling — its row is never touched because the user only
 * ever attests files visible in the CURRENT scan's file list. That stale
 * row keeps the naive count above zero forever, so the alert never
 * resolves even though every file in the latest scan is genuinely clean.
 *
 * The correct check, mirrored from /api/dashboard's currentViolations
 * logic: dedupe violations by file_path, keep only the row from the most
 * recently created scan for each file_path, and check whether ANY of
 * those latest-per-file rows is still open. Superseded rows from older
 * scans are ignored entirely.
 */

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type DB = any;

export async function hasOpenRepoViolations(db: DB, orgId: string, repoFullName: string): Promise<boolean> {
  const { data: repoScans } = await db
    .from("scans")
    .select("id, created_at")
    .eq("org_id", orgId)
    .eq("repo_full_name", repoFullName);

  const scanIds = (repoScans ?? []).map((s: { id: string }) => s.id);
  if (scanIds.length === 0) return false;

  const scanCreatedAt = new Map<string, string>(
    (repoScans ?? []).map((s: { id: string; created_at: string }) => [s.id, s.created_at]),
  );

  const { data: violations } = await db
    .from("violations")
    .select("file_path, status, scan_id")
    .eq("org_id", orgId)
    .in("scan_id", scanIds);

  const latestByFile = new Map<string, { status: string; scan_id: string }>();
  for (const v of (violations ?? []) as { file_path: string; status: string; scan_id: string }[]) {
    const created  = scanCreatedAt.get(v.scan_id) ?? "";
    const existing = latestByFile.get(v.file_path);
    const existingCreated = existing ? (scanCreatedAt.get(existing.scan_id) ?? "") : "";
    if (!existing || created > existingCreated) {
      latestByFile.set(v.file_path, { status: v.status, scan_id: v.scan_id });
    }
  }

  for (const v of latestByFile.values()) {
    if (v.status !== "resolved") return true;
  }
  return false;
}
