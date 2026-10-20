/**
 * Attestation records for a period, explained: WHAT was signed off (repository, pull request, commit, file), WHY
 * it needed a sign-off (its risk level and the findings that made it HIGH/CRITICAL), HOW (who signed off, whether
 * that person was independent of the pull request's author, how long after the scan, and the record's tamper-evident
 * hash), and WHEN. Pure -- api/attest (GET) fetches the rows.
 *
 * Attestation rows are permanent (the table refuses updates and deletes), so this is the audit evidence itself.
 */

export interface RecordAttestationRow {
  id: string; scan_id: string; file_path: string; risk_score: string; reviewer_email: string | null;
  reviewer_github: string | null; payload_hash: string | null; created_at: string;
}
export interface RecordScanRow { id: string; repo_full_name: string; pr_number: number | null; commit_sha: string | null; branch: string | null; pr_author: string | null; created_at: string }
export interface RecordFileRow { scan_id: string; file_path: string; risk_indicators: unknown; ai_percentage: number | null }

export interface AttestationRecord {
  id: string;
  signed_at: string;
  repo: string; pr_number: number; commit_sha: string | null; branch: string | null; scan_id: string; scanned_at: string | null;
  file_path: string; risk_score: string; findings: string[]; ai_percentage: number | null;
  reviewer_email: string | null; reviewer_github: string | null; pr_author: string | null;
  /** independent: the reviewer isn't the PR's author; self: they are; unknown: one of the two GitHub logins is missing. */
  independence: "independent" | "self" | "unknown";
  /** Hours from the scan to this sign-off (null if the scan's time is unknown). */
  hours_to_signoff: number | null;
  payload_hash: string | null;
  /** A second (or later) sign-off of the same file in the same scan. */
  repeat: boolean;
}

export interface AttestationRecordSummary {
  records: number; files: number; repos: string[]; reviewers: string[];
  independent: number; self: number; unknown: number;
  first: string | null; last: string | null; median_hours: number | null;
  by_risk: Record<string, number>;
}

export function independenceOf(reviewerGithub: string | null | undefined, prAuthor: string | null | undefined): AttestationRecord["independence"] {
  const r = reviewerGithub?.trim().toLowerCase(), a = prAuthor?.trim().toLowerCase();
  if (!r || !a) return "unknown";
  return r === a ? "self" : "independent";
}

const median = (xs: number[]) => {
  if (xs.length === 0) return null;
  const s = [...xs].sort((a, b) => a - b), m = Math.floor(s.length / 2);
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
};

export function buildAttestationRecords(input: {
  attestations: readonly RecordAttestationRow[];
  scans: readonly RecordScanRow[];
  files: readonly RecordFileRow[];
}): { records: AttestationRecord[]; summary: AttestationRecordSummary } {
  const scanById = new Map(input.scans.map(s => [s.id, s]));
  const fileByKey = new Map(input.files.map(f => [`${f.scan_id}::${f.file_path}`, f]));
  const seen = new Set<string>();
  const records = [...input.attestations]
    .sort((a, b) => a.created_at.localeCompare(b.created_at) || a.id.localeCompare(b.id))
    .map((a): AttestationRecord => {
      const s = scanById.get(a.scan_id);
      const f = fileByKey.get(`${a.scan_id}::${a.file_path}`);
      const key = `${a.scan_id}::${a.file_path}`;
      const repeat = seen.has(key);
      seen.add(key);
      const scannedAt = s?.created_at ?? null;
      const hours = scannedAt ? Math.max(0, (Date.parse(a.created_at) - Date.parse(scannedAt)) / 3_600_000) : null;
      return {
        id: a.id, signed_at: a.created_at,
        repo: s?.repo_full_name ?? "unknown", pr_number: s?.pr_number ?? 0, commit_sha: s?.commit_sha ?? null, branch: s?.branch ?? null,
        scan_id: a.scan_id, scanned_at: scannedAt,
        file_path: a.file_path, risk_score: a.risk_score,
        findings: Array.isArray(f?.risk_indicators) ? (f!.risk_indicators as unknown[]).filter((x): x is string => typeof x === "string") : [],
        ai_percentage: f?.ai_percentage ?? null,
        reviewer_email: a.reviewer_email, reviewer_github: a.reviewer_github, pr_author: s?.pr_author ?? null,
        independence: independenceOf(a.reviewer_github, s?.pr_author),
        hours_to_signoff: hours == null || !Number.isFinite(hours) ? null : Math.round(hours * 10) / 10,
        payload_hash: a.payload_hash, repeat,
      };
    })
    .reverse();                                  // newest first

  const firsts = records.filter(r => !r.repeat);
  const by_risk: Record<string, number> = {};
  for (const r of records) by_risk[r.risk_score] = (by_risk[r.risk_score] ?? 0) + 1;
  return {
    records,
    summary: {
      records: records.length,
      files: firsts.length,
      repos: [...new Set(records.map(r => r.repo))].sort(),
      reviewers: [...new Set(records.map(r => r.reviewer_email ?? r.reviewer_github ?? "unknown"))].sort(),
      independent: records.filter(r => r.independence === "independent").length,
      self: records.filter(r => r.independence === "self").length,
      unknown: records.filter(r => r.independence === "unknown").length,
      first: records.length ? records[records.length - 1].signed_at : null,
      last: records[0]?.signed_at ?? null,
      median_hours: median(firsts.map(r => r.hours_to_signoff).filter((h): h is number => h != null)),
      by_risk,
    },
  };
}
