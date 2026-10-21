/**
 * Live state of a PR's policy alert ("N unattested files in repo PR #n").
 *
 * The scan worker writes that alert once, when the scan finishes, and its count never changed: after five of six
 * files were signed off it still said six. And it only resolved when the WHOLE repository had nothing open. Read
 * time is where it gets its real state:
 *   - progress: how many of the scan's CRITICAL/HIGH files still need a sign-off, of how many;
 *   - done when its own scan has none left, or when a newer scan of the same PR has replaced it (a newer push
 *     raises its own alert if anything still needs a sign-off, so the old one only repeats it).
 *
 * Pure: GET /api/alerts loads the rows and applies the result.
 */

export interface AlertProgress { open: number; total: number }

/** Per scan: CRITICAL/HIGH violations still open, of all of them. */
export function progressByScan(violations: ReadonlyArray<{ scan_id: string; status: string | null }>): Map<string, AlertProgress> {
  const out = new Map<string, AlertProgress>();
  for (const v of violations) {
    const p = out.get(v.scan_id) ?? { open: 0, total: 0 };
    p.total += 1;
    if (v.status !== "resolved") p.open += 1;
    out.set(v.scan_id, p);
  }
  return out;
}

/** The newest scan id of each PR ("repo#pr"), from scans of those PRs. */
export function latestScanByPr(scans: ReadonlyArray<{ id: string; repo_full_name: string; pr_number: number | null; created_at: string }>): Map<string, string> {
  const best = new Map<string, { id: string; at: string }>();
  for (const s of scans) {
    if (!s.pr_number) continue;
    const k = `${s.repo_full_name}#${s.pr_number}`;
    const b = best.get(k);
    if (!b || s.created_at > b.at) best.set(k, { id: s.id, at: s.created_at });
  }
  return new Map([...best].map(([k, v]) => [k, v.id]));
}

export type AlertVerdict =
  | { state: "active"; progress: AlertProgress }
  | { state: "done"; reason: "signed_off" | "superseded"; progress?: AlertProgress };

/** What a still-active policy alert tied to `scanId` really is now. */
export function policyAlertVerdict(
  scanId: string,
  progress: ReadonlyMap<string, AlertProgress>,
  scanPr: { repo_full_name: string; pr_number: number | null } | undefined,
  latestByPr: ReadonlyMap<string, string>,
): AlertVerdict | null {
  const p = progress.get(scanId);
  if (scanPr?.pr_number) {
    const latest = latestByPr.get(`${scanPr.repo_full_name}#${scanPr.pr_number}`);
    if (latest && latest !== scanId) return { state: "done", reason: "superseded", progress: p };
  }
  if (!p) return null;                       // no violation rows to judge by: leave it to the repo-wide check
  if (p.open === 0) return { state: "done", reason: "signed_off", progress: p };
  return { state: "active", progress: p };
}

/** The alert's title for its current progress. */
export function progressTitle(p: AlertProgress, repoShort: string, prNumber: number | null): string {
  const where = `${repoShort}${prNumber ? ` PR #${prNumber}` : ""}`;
  if (p.open === 0) return `All ${p.total} file${p.total !== 1 ? "s" : ""} signed off in ${where}`;
  return `${p.open} of ${p.total} file${p.total !== 1 ? "s" : ""} still need${p.open === 1 ? "s" : ""} sign-off in ${where}`;
}
