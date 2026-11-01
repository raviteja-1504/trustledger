/**
 * The parts of the change-management register (lib/changeRegister.ts) the browser uses too: the row shape, what each
 * exception means, the reproducible auditor sample, and the CSV. No Node APIs here, so the Reports page can re-draw a
 * sample for any seed an auditor types, and save the CSV, from the register it already loaded.
 */
import type { BranchProtection } from "@/lib/branchProtection";

export type ExceptionCode = "no_approval" | "approved_after_merge" | "stale_approval" | "not_scanned" | "unsigned_high_risk";

/** What each exception means, in the words that go in the report. */
export const EXCEPTION_INFO: Record<ExceptionCode, { label: string; severity: "exception" | "observation" }> = {
  no_approval:          { label: "Merged without an approval from someone other than the author", severity: "exception" },
  approved_after_merge: { label: "Approved only after it was merged", severity: "exception" },
  stale_approval:       { label: "Approved on an earlier commit than the one merged (later changes were not re-approved)", severity: "observation" },
  not_scanned:          { label: "No TrustLedger scan before it was merged", severity: "exception" },
  unsigned_high_risk:   { label: "A HIGH or CRITICAL file was merged without a named reviewer's sign-off", severity: "exception" },
};

export interface RegisterRow {
  repo: string;
  number: number;
  title: string;
  url: string;
  author: string | null;
  merged_at: string;
  merged_by: string | null;
  /** Approvals by someone other than the author, given before the merge. */
  approvals: Array<{ reviewer: string; at: string; on_merged_commit: boolean }>;
  /** The last TrustLedger scan of the pull request at or before the merge. */
  scan: { scan_id: string; at: string; overall_risk: string } | null;
  high_risk_files: number;
  high_risk_signed_off: number;
  exceptions: ExceptionCode[];
  /** SHA-256 of this row's canonical JSON (without this field): a CSV / JSON row can be checked on its own. */
  row_sha256: string;
}

export interface RepoCoverage { repo: string; read: boolean; pulls: number; reason?: string; truncated?: boolean }

export interface ChangeRegister {
  period_start: string;
  period_end: string;
  rows: RegisterRow[];
  summary: {
    merged: number;
    approved_before_merge: number;
    scanned: number;
    with_exceptions: number;
    exceptions: Record<ExceptionCode, number>;
  };
  /** Which repositories were read; any that were not make the population incomplete, and the report says so. */
  coverage: RepoCoverage[];
  complete: boolean;
  /** Each repository's default-branch protection when the register was built (lib/branchProtection.ts). */
  branch_protection?: BranchProtection[];
}

/** The control each framework's register evidences. Only these frameworks carry a change register. */
export const REGISTER_CONTROL: Readonly<Record<string, string>> = { soc2: "CC8.1", iso27001: "A.8.32", pcidss: "6.2.3" };

export const pullKey =(repo: string, number: number) => `${repo.toLowerCase()}#${number}`;

/** UTF-8 bytes of a string (TextEncoder isn't in every runtime this module runs in). */
function utf8(s: string): number[] {
  const out: number[] = [];
  for (const ch of s) {
    const c = ch.codePointAt(0)!;
    if (c < 0x80) out.push(c);
    else if (c < 0x800) out.push(0xc0 | (c >> 6), 0x80 | (c & 63));
    else if (c < 0x10000) out.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
    else out.push(0xf0 | (c >> 18), 0x80 | ((c >> 12) & 63), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
  }
  return out;
}

/**
 * A small deterministic PRNG (mulberry32), seeded with the 32-bit FNV-1a hash of the seed's UTF-8 bytes: the same seed
 * always draws the same sample, in the browser and on the server, and the algorithm is short enough to re-implement.
 */
function seededRandom(seed: string): () => number {
  let a = 0x811c9dc5;
  for (const byte of utf8(seed)) a = Math.imul(a ^ byte, 0x01000193) >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** The default sample size for a control that operates many times a day (25 items: the low end of common audit
 * guidance for such controls). The auditor chooses the size; this is only the starting value. */
export const DEFAULT_SAMPLE_SIZE = 25;

/**
 * A random sample of the register, reproducible from `seed`: anyone with the register and the seed draws exactly the
 * same rows. Returned in merge order. A population smaller than the sample is returned whole.
 */
export function drawSample<R>(rows: readonly R[], size: number, seed: string): R[] {
  const n = Math.max(0, Math.min(Math.floor(size), rows.length));
  const idx = rows.map((_, i) => i);
  const rand = seededRandom(seed);
  // partial Fisher–Yates: the first n positions end up a uniform random selection
  for (let i = 0; i < n; i++) {
    const j = i + Math.floor(rand() * (idx.length - i));
    [idx[i], idx[j]] = [idx[j], idx[i]];
  }
  return idx.slice(0, n).sort((a, b) => a - b).map(i => rows[i]);
}

const CSV_COLUMNS = ["repo", "pull_request", "title", "author", "merged_at", "merged_by", "approvers", "first_approval_at",
  "approved_merged_commit", "scan_id", "scanned_at", "scan_risk", "high_risk_files", "high_risk_signed_off", "exceptions", "url", "row_sha256"] as const;

function csvCell(v: string | number | boolean | null | undefined): string {
  const s = v == null ? "" : String(v);
  // a leading = + - @ would be read as a formula by a spreadsheet: neutralise it
  const safe = /^[=+\-@\t\r]/.test(s) ? `'${s}` : s;
  return /[",\n\r]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe;
}

/** The register as CSV (one row per merged pull request), with each row's SHA-256. */
export function registerToCsv(rows: readonly RegisterRow[]): string {
  const lines = [CSV_COLUMNS.join(",")];
  for (const r of rows) {
    const first = [...r.approvals].sort((a, b) => a.at.localeCompare(b.at))[0];
    lines.push([
      r.repo, r.number, r.title, r.author, r.merged_at, r.merged_by,
      r.approvals.map(a => a.reviewer).join(" "), first?.at ?? "", r.approvals.some(a => a.on_merged_commit),
      r.scan?.scan_id ?? "", r.scan?.at ?? "", r.scan?.overall_risk ?? "", r.high_risk_files, r.high_risk_signed_off,
      r.exceptions.join(" "), r.url, r.row_sha256,
    ].map(csvCell).join(","));
  }
  return lines.join("\n") + "\n";
}
