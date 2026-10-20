/**
 * One repository, from its real records: the current state (files in the latest scan, each with its sign-off
 * status), its pull requests (latest scan of each, with how many high-risk files are signed off), the full scan
 * history (older scans of a PR marked superseded), and totals. Pure -- the route (api/repos/summary) fetches rows.
 */

export interface SummaryScanRow {
  id: string; pr_number: number | null; commit_sha: string; branch: string | null; overall_risk: string;
  total_ai_percentage: number | null; file_count: number | null; created_at: string; triggered_by: string | null; pr_author: string | null;
}
export interface SummaryFileRow { scan_id: string; file_path: string; language: string | null; risk_score: string; ai_percentage: number | null; risk_indicators: unknown }
export interface SummaryAttestationRow { scan_id: string; file_path: string; reviewer_email: string | null; created_at: string }
export interface SummaryViolationRow { scan_id: string; file_path: string; status: string; sla_deadline: string | null }

export type FileStatus = "attested" | "resolved" | "in_review" | "waiting" | "not_required";

export interface RepoFile {
  file_path: string; language: string | null; risk_score: string; ai_percentage: number; indicators: string[];
  status: FileStatus; attested_by?: string | null; attested_at?: string; sla_deadline?: string | null; overdue?: boolean;
}
export interface RepoPr {
  pr_number: number; latest_scan_id: string; scans: number; first_scan_at: string; last_scan_at: string;
  overall_risk: string; author: string | null; high_crit: number; signed_off: number;
}
export interface RepoScan {
  scan_id: string; pr_number: number; commit_sha: string; branch: string | null; overall_risk: string; ai_share: number;
  file_count: number; created_at: string; triggered_by: string; author: string | null; superseded: boolean; latest: boolean;
}
export interface RepoSummary {
  latest_scan: RepoScan | null;
  files: RepoFile[];
  signoff: { required: number; attested: number; resolved: number; in_review: number; waiting: number; overdue: number };
  prs: RepoPr[];
  scans: RepoScan[];
  stats: { scans: number; prs: number; direct_pushes: number; first_scan: string | null; last_scan: string | null; ai_share: number; contributors: Array<{ login: string; scans: number }> };
}

const RISK_RANK: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
const needsSignoff = (risk: string) => risk === "CRITICAL" || risk === "HIGH";
const prefix = (r: string) => (r === "CRITICAL" ? "crit" : r === "HIGH" ? "high" : r === "MEDIUM" ? "med" : "low");

/** The violation-override key the violations page uses for a file of a scan. */
export const overrideKey = (risk: string, scanId: string, path: string) => `${prefix(risk)}::${scanId}::${path}`;

/** File-weighted AI share (a 2-file scan doesn't count as much as a 200-file one); plain mean when no file counts. */
export function weightedAi(scans: ReadonlyArray<{ total_ai_percentage: number | null; file_count: number | null }>): number {
  if (scans.length === 0) return 0;
  const w = scans.reduce((s, x) => s + Math.max(0, x.file_count ?? 0), 0);
  return w > 0
    ? scans.reduce((s, x) => s + (x.total_ai_percentage ?? 0) * Math.max(0, x.file_count ?? 0), 0) / w
    : scans.reduce((s, x) => s + (x.total_ai_percentage ?? 0), 0) / scans.length;
}

export function buildRepoSummary(input: {
  scans: readonly SummaryScanRow[];           // any order
  latestFiles: readonly SummaryFileRow[];     // files of the latest scan
  prFiles: readonly SummaryFileRow[];         // HIGH/CRITICAL files of each PR's latest scan
  attestations: readonly SummaryAttestationRow[]; // for those scans
  violations: readonly SummaryViolationRow[]; // for the latest scan
  overrides: Readonly<Record<string, string>>; // violation_overrides status by key
  now?: number;
}): RepoSummary {
  const now = input.now ?? Date.now();
  const scans = [...input.scans].sort((a, b) => b.created_at.localeCompare(a.created_at) || a.id.localeCompare(b.id));
  const latestPerPr = new Map<number, SummaryScanRow>();
  for (const s of scans) { const k = s.pr_number ?? 0; if (!latestPerPr.has(k)) latestPerPr.set(k, s); }
  const latestIds = new Set([...latestPerPr.values()].map(s => s.id));
  const toScan = (s: SummaryScanRow, i: number): RepoScan => ({
    scan_id: s.id, pr_number: s.pr_number ?? 0, commit_sha: s.commit_sha, branch: s.branch, overall_risk: s.overall_risk,
    ai_share: s.total_ai_percentage ?? 0, file_count: s.file_count ?? 0, created_at: s.created_at, triggered_by: s.triggered_by ?? "api",
    author: s.pr_author, superseded: !latestIds.has(s.id), latest: i === 0,
  });
  const scanViews = scans.map(toScan);
  const latest = scanViews[0] ?? null;

  // Attestations: one per file per scan (the earliest says who signed off first).
  const attested = new Map<string, SummaryAttestationRow>();
  for (const a of [...input.attestations].sort((x, y) => x.created_at.localeCompare(y.created_at))) {
    const k = `${a.scan_id}::${a.file_path}`;
    if (!attested.has(k)) attested.set(k, a);
  }
  const violation = new Map(input.violations.map(v => [`${v.scan_id}::${v.file_path}`, v]));

  const files: RepoFile[] = latest ? input.latestFiles.filter(f => f.scan_id === latest.scan_id).map(f => {
    const k = `${f.scan_id}::${f.file_path}`;
    const a = attested.get(k);
    const v = violation.get(k);
    const ov = input.overrides[overrideKey(f.risk_score, f.scan_id, f.file_path)];
    const required = needsSignoff(f.risk_score);
    const status: FileStatus = a ? "attested"
      : !required ? "not_required"
      : ov === "resolved" || v?.status === "resolved" || v?.status === "accepted" ? "resolved"
      : ov === "in_review" || v?.status === "in_review" ? "in_review"
      : "waiting";
    const open = status === "waiting" || status === "in_review";
    return {
      file_path: f.file_path, language: f.language, risk_score: f.risk_score, ai_percentage: f.ai_percentage ?? 0,
      indicators: Array.isArray(f.risk_indicators) ? (f.risk_indicators as unknown[]).filter((x): x is string => typeof x === "string") : [],
      status, attested_by: a?.reviewer_email ?? undefined, attested_at: a?.created_at,
      sla_deadline: required ? v?.sla_deadline ?? null : undefined,
      overdue: open && !!v?.sla_deadline && Date.parse(v.sla_deadline) < now,
    };
  }).sort((a, b) => (RISK_RANK[a.risk_score] ?? 9) - (RISK_RANK[b.risk_score] ?? 9) || b.ai_percentage - a.ai_percentage || a.file_path.localeCompare(b.file_path)) : [];

  const req = files.filter(f => needsSignoff(f.risk_score));
  const signoff = {
    required: req.length,
    attested: req.filter(f => f.status === "attested").length,
    resolved: req.filter(f => f.status === "resolved").length,
    in_review: req.filter(f => f.status === "in_review").length,
    waiting: req.filter(f => f.status === "waiting").length,
    overdue: req.filter(f => f.overdue).length,
  };

  const byPr = new Map<number, SummaryScanRow[]>();
  for (const s of scans) { const k = s.pr_number ?? 0; byPr.set(k, [...(byPr.get(k) ?? []), s]); }
  const prs: RepoPr[] = [...latestPerPr.entries()].filter(([n]) => n > 0).map(([n, s]) => {
    const hc = input.prFiles.filter(f => f.scan_id === s.id && needsSignoff(f.risk_score));
    const all = byPr.get(n)!;
    return {
      pr_number: n, latest_scan_id: s.id, scans: all.length, first_scan_at: all[all.length - 1].created_at, last_scan_at: s.created_at,
      overall_risk: s.overall_risk, author: s.pr_author, high_crit: hc.length,
      signed_off: hc.filter(f => attested.has(`${s.id}::${f.file_path}`) || input.overrides[overrideKey(f.risk_score, s.id, f.file_path)] === "resolved").length,
    };
  });

  const authors = new Map<string, number>();
  for (const s of scans) if (s.pr_author) authors.set(s.pr_author, (authors.get(s.pr_author) ?? 0) + 1);

  return {
    latest_scan: latest, files, signoff, prs, scans: scanViews,
    stats: {
      scans: scans.length, prs: prs.length, direct_pushes: byPr.get(0)?.length ?? 0,
      first_scan: scans.length ? scans[scans.length - 1].created_at : null, last_scan: scans[0]?.created_at ?? null,
      ai_share: weightedAi(scans),
      contributors: [...authors].map(([login, n]) => ({ login, scans: n })).sort((a, b) => b.scans - a.scans || a.login.localeCompare(b.login)).slice(0, 5),
    },
  };
}
