/**
 * The change-management register: every pull request merged in an audit period, with the evidence an auditor checks
 * for each one (SOC 2 CC8.1, ISO 27001 A.8.32, PCI DSS 6.2.3 / 6.2.3.1) -- who approved it and when relative to the
 * merge, whether TrustLedger scanned it, and whether its HIGH/CRITICAL files were signed off before it merged -- and
 * the exceptions where that evidence is missing.
 *
 * Auditors start from the complete population of changes, then test a sample. So this lists every merged pull
 * request (not only risky ones), says which repositories could not be read (an incomplete population is stated, not
 * hidden), and draws a reproducible random sample from a seed anyone can re-run.
 *
 * Pure: no I/O. lib/changeRegisterLoader.ts fetches the pull requests and reviews from GitHub and the scans and
 * sign-offs from the database. The row shape, exception wording, sample and CSV live in lib/changeRegisterShared.ts,
 * which the browser uses too.
 */
import crypto from "crypto";
import { canonicalJson } from "@/lib/trustRecord";
import {
  DEFAULT_SAMPLE_SIZE, EXCEPTION_INFO, drawSample, pullKey,
  type ChangeRegister, type ExceptionCode, type RegisterRow, type RepoCoverage,
} from "@/lib/changeRegisterShared";

export {
  DEFAULT_SAMPLE_SIZE, EXCEPTION_INFO, REGISTER_CONTROL, drawSample, pullKey, registerToCsv,
  type ChangeRegister, type ExceptionCode, type RegisterRow, type RepoCoverage,
} from "@/lib/changeRegisterShared";

export interface MergedPull {
  repo: string;
  number: number;
  title: string;
  author: string | null;
  merged_at: string;
  merged_by: string | null;
  /** The commit that was merged (the pull request's head when it merged). */
  head_sha: string;
  url: string;
}

export interface PullReview {
  reviewer: string | null;
  state: string;            // APPROVED | CHANGES_REQUESTED | COMMENTED | DISMISSED | PENDING
  submitted_at: string | null;
  /** The commit the review was given on. */
  commit_id: string | null;
}

export interface RegisterScan { scan_id: string; repo: string; pr_number: number; commit_sha: string | null; created_at: string; overall_risk: string }
export interface RegisterRiskyFile { scan_id: string; file_path: string; risk_score: string }
export interface RegisterSignoff { scan_id: string; file_path: string; reviewer_github: string | null; created_at: string }

export interface RegisterInput {
  period_start: string;
  period_end: string;
  pulls: readonly MergedPull[];
  reviews: ReadonlyMap<string, readonly PullReview[]>;   // key: `${repo}#${number}`
  scans: readonly RegisterScan[];
  riskyFiles: readonly RegisterRiskyFile[];
  signoffs: readonly RegisterSignoff[];
  coverage: readonly RepoCoverage[];
}

const same = (a: string | null, b: string | null) => !!a && !!b && a.toLowerCase() === b.toLowerCase();
const HIGH_RISK = new Set(["HIGH", "CRITICAL"]);
const sha256 = (s: string) => crypto.createHash("sha256").update(s).digest("hex");

/** The register for a period: one row per merged pull request, oldest merge first. */
export function buildRegister(input: RegisterInput): ChangeRegister {
  const scansByPull = new Map<string, RegisterScan[]>();
  for (const s of input.scans) {
    const k = pullKey(s.repo, s.pr_number);
    scansByPull.set(k, [...(scansByPull.get(k) ?? []), s]);
  }
  const riskyByScan = new Map<string, RegisterRiskyFile[]>();
  for (const f of input.riskyFiles) if (HIGH_RISK.has(f.risk_score)) riskyByScan.set(f.scan_id, [...(riskyByScan.get(f.scan_id) ?? []), f]);
  const signoffs = new Map<string, RegisterSignoff[]>();
  for (const a of input.signoffs) {
    const k = `${a.scan_id}::${a.file_path}`;
    signoffs.set(k, [...(signoffs.get(k) ?? []), a]);
  }

  const rows = [...input.pulls]
    .filter(p => p.merged_at >= input.period_start && p.merged_at <= input.period_end)
    .sort((a, b) => a.merged_at.localeCompare(b.merged_at) || a.repo.localeCompare(b.repo) || a.number - b.number)
    .map(p => {
      const merged = p.merged_at;
      const reviews = input.reviews.get(pullKey(p.repo, p.number)) ?? [];
      // an approval counts when it is by someone other than the author (GitHub forbids self-approval, but the author's
      // login may be recorded differently) and was given before the merge
      const approvalsAll = reviews.filter(r => r.state === "APPROVED" && r.reviewer && r.submitted_at && !same(r.reviewer, p.author));
      const approvals = approvalsAll.filter(r => r.submitted_at! <= merged)
        .map(r => ({ reviewer: r.reviewer!, at: r.submitted_at!, on_merged_commit: !!r.commit_id && r.commit_id === p.head_sha }));
      const scan = (scansByPull.get(pullKey(p.repo, p.number)) ?? []).filter(s => s.created_at <= merged)
        .sort((a, b) => b.created_at.localeCompare(a.created_at))[0] ?? null;
      const risky = scan ? riskyByScan.get(scan.scan_id) ?? [] : [];
      // signed off by someone other than the author, before the merge
      const signedOff = risky.filter(f => (signoffs.get(`${f.scan_id}::${f.file_path}`) ?? [])
        .some(a => a.created_at <= merged && !same(a.reviewer_github, p.author)));

      const exceptions: ExceptionCode[] = [];
      if (approvals.length === 0) exceptions.push(approvalsAll.length > 0 ? "approved_after_merge" : "no_approval");
      else if (!approvals.some(a => a.on_merged_commit)) exceptions.push("stale_approval");
      if (!scan) exceptions.push("not_scanned");
      if (signedOff.length < risky.length) exceptions.push("unsigned_high_risk");

      const row: Omit<RegisterRow, "row_sha256"> = {
        repo: p.repo, number: p.number, title: p.title, url: p.url, author: p.author, merged_at: merged, merged_by: p.merged_by,
        approvals, scan: scan ? { scan_id: scan.scan_id, at: scan.created_at, overall_risk: scan.overall_risk } : null,
        high_risk_files: risky.length, high_risk_signed_off: signedOff.length, exceptions,
      };
      return { ...row, row_sha256: sha256(canonicalJson(row)) };
    });

  const exceptions = Object.fromEntries((Object.keys(EXCEPTION_INFO) as ExceptionCode[]).map(c => [c, rows.filter(r => r.exceptions.includes(c)).length])) as Record<ExceptionCode, number>;
  return {
    period_start: input.period_start, period_end: input.period_end, rows,
    summary: {
      merged: rows.length,
      approved_before_merge: rows.filter(r => r.approvals.length > 0).length,
      scanned: rows.filter(r => r.scan).length,
      with_exceptions: rows.filter(r => r.exceptions.length > 0).length,
      exceptions,
    },
    coverage: [...input.coverage],
    complete: input.coverage.every(c => c.read && !c.truncated),
  };
}

/** A sample by reference: which register rows were drawn (each with its hash), and the seed and size to re-draw it. */
export interface RegisterSample { seed: string; size: number; picked: Array<{ repo: string; number: number; row_sha256: string }> }

/** The register as it goes into a signed report: the whole population, plus the sample drawn with the report's id as seed. */
export type ReportChangeRegister = (ChangeRegister & { sample: RegisterSample }) | { error: string };

export function registerForReport(reg: ChangeRegister, seed: string, size = DEFAULT_SAMPLE_SIZE): ChangeRegister & { sample: RegisterSample } {
  const picked = drawSample(reg.rows, size, seed).map(r => ({ repo: r.repo, number: r.number, row_sha256: r.row_sha256 }));
  return { ...reg, sample: { seed, size, picked } };
}
