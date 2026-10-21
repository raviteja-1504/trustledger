/**
 * The pull request a file incident is about: the newest scan of its repository that contains the file, so the
 * Incidents page can open that PR with all its files (an incident only stores the repo and the file path).
 *
 * Pure: GET /api/incidents loads the rows.
 */

export interface ScanRef { id: string; repo_full_name: string; pr_number: number | null; created_at: string }
export interface IncidentPr { scan_id: string; pr_number: number | null }

export const fileKey = (repo: string, file: string) => `${repo}::${file}`;

/** For each "repo::file", the newest scan of that repo whose files include it. */
export function latestScanPerFile(
  scans: readonly ScanRef[],
  filesByScan: ReadonlyArray<{ scan_id: string; file_path: string }>,
): Map<string, IncidentPr> {
  const scanById = new Map(scans.map(s => [s.id, s]));
  const best = new Map<string, ScanRef>();
  for (const f of filesByScan) {
    const s = scanById.get(f.scan_id);
    if (!s) continue;
    const k = fileKey(s.repo_full_name, f.file_path);
    const b = best.get(k);
    if (!b || s.created_at > b.created_at) best.set(k, s);
  }
  return new Map([...best].map(([k, s]) => [k, { scan_id: s.id, pr_number: s.pr_number }]));
}
