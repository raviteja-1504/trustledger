/**
 * How many files of a scan are attested, as the scan-history list shows it.
 *
 * Two sources describe the same attestations: the server (attestation rows, as distinct file paths) and this
 * browser's tl_violation_statuses, which records a file the moment it is attested here -- before the next fetch.
 * They overlap: a file attested here is in BOTH once the list is refetched. Adding the two counts showed every
 * such file twice ("1 attested" became 2), so they are combined as a SET of file paths.
 *
 * Client-safe: no imports.
 */

/** File paths of `scanId` that this browser has recorded as attested ("resolved" or "in_review").
 *  Keys are "{riskPrefix}::{scan_id}::{file_path}". */
export function locallyAttestedFiles(scanId: string, statuses: Record<string, string>): Set<string> {
  const files = new Set<string>();
  for (const [key, val] of Object.entries(statuses)) {
    if (val !== "resolved" && val !== "in_review") continue;
    const first = key.indexOf("::");
    if (first < 0) continue;
    const second = key.indexOf("::", first + 2);
    if (second < 0) continue;
    if (key.slice(first + 2, second) !== scanId) continue;
    const path = key.slice(second + 2);
    if (path) files.add(path);
  }
  return files;
}

export interface AttestedCountInput {
  scan_id: string;
  file_count: number;
  /** Distinct attested files per the server. */
  attested_count: number;
  /** The server's attested file paths, when it sends them (live data). Absent for demo data. */
  attested_files?: readonly string[];
}

/** Attested files for the list: the union of server and local paths, never more than the scan's file count. */
export function effectiveAttestedCount(s: AttestedCountInput, statuses: Record<string, string>): number {
  const local = locallyAttestedFiles(s.scan_id, statuses);
  let attested: number;
  if (s.attested_files) {
    const all = new Set(s.attested_files);
    local.forEach(f => all.add(f));
    attested = all.size;
  } else {
    // Only a count: the larger of the two can't double-count (it may under-count a file attested here that the
    // server doesn't know yet AND a different one it does, which the next fetch corrects).
    attested = Math.max(s.attested_count, local.size);
  }
  return Math.max(0, Math.min(s.file_count, attested));
}
