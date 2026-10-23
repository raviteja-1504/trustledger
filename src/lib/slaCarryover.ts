/**
 * A file's review deadline belongs to the pull request, not to one scan of it: while the file still waits for a
 * sign-off from an earlier scan of the same PR, a new scan (a rescan, a push) keeps that deadline. Restarting it
 * on every scan postponed the overdue-CRITICAL incident (lib/autoIncidents.ts) each time someone rescanned.
 * A file whose earlier violation was resolved (signed off, closed) starts a new clock.
 */

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Db = any;

const IN_CHUNK = 200;

/** file_path -> the earliest deadline among this PR's earlier, still-open violations of it. */
export async function openSlaDeadlines(
  db: Db, orgId: string, repo: string, prNumber: number | null | undefined, exceptScanId: string, paths: readonly string[],
): Promise<Map<string, string>> {
  const out = new Map<string, string>();
  if (!prNumber || paths.length === 0) return out;
  try {
    const { data: scans } = await db.from("scans").select("id")
      .eq("org_id", orgId).eq("repo_full_name", repo).eq("pr_number", prNumber).neq("id", exceptScanId);
    const ids = ((scans ?? []) as Array<{ id: string }>).map(s => s.id);
    if (ids.length === 0) return out;
    const wanted = new Set(paths);
    for (let i = 0; i < ids.length; i += IN_CHUNK) {
      const { data } = await db.from("violations").select("file_path, sla_deadline")
        .eq("org_id", orgId).in("scan_id", ids.slice(i, i + IN_CHUNK)).neq("status", "resolved");
      for (const v of (data ?? []) as Array<{ file_path: string; sla_deadline: string | null }>) {
        if (!v.sla_deadline || !wanted.has(v.file_path)) continue;
        const cur = out.get(v.file_path);
        if (!cur || Date.parse(v.sla_deadline) < Date.parse(cur)) out.set(v.file_path, v.sla_deadline);
      }
    }
  } catch { /* best-effort: a new deadline is the old behaviour */ }
  return out;
}
