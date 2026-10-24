/**
 * How much of a merge/pull request a scan actually read. "No files to scan" and "couldn't read the files" must
 * never look alike: the GitLab and Bitbucket webhooks reported both as a passing status, and silently read only
 * the first 50 files of a larger request, so an unscanned change could merge.
 */
export type Coverage = "unlisted" | "none" | "unreadable" | "partial" | "complete";

/**
 * `listed` false: the request's file list itself couldn't be fetched. `wanted`: scannable files in the request.
 * `read`: files whose content was read.
 */
export function scanCoverage(listed: boolean, wanted: number, read: number): Coverage {
  if (!listed) return "unlisted";
  if (wanted === 0) return "none";
  if (read === 0) return "unreadable";
  return read < wanted ? "partial" : "complete";
}

/** A short status line for a coverage that must fail the status (null when the scan may report its own result). */
export function coverageFailure(c: Coverage, wanted: number, read: number): string | null {
  switch (c) {
    case "unlisted":   return "TrustLedger: couldn't list this request's files — not scanned, retry";
    case "unreadable": return `TrustLedger: couldn't read any of ${wanted} files — not scanned, retry`;
    case "partial":    return `TrustLedger: scanned ${read} of ${wanted} files — the rest weren't read`;
    default:           return null;
  }
}
