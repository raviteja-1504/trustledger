/**
 * Scan history: which scans are the latest for their pull request (older pushes are superseded), the period's
 * stats from the scans themselves, and daily activity. Pure, client-safe.
 */
import type { RiskLevel } from "@/types";

export interface ScanRow {
  scan_id: string;
  repo: string;
  pr_number: number;
  commit_sha: string;
  branch: string;
  overall_risk: RiskLevel;
  total_ai_percentage: number;
  file_count: number;
  high_crit_count?: number;
  attested_count: number;
  attested_files?: string[];
  created_at: string;
  triggered_by: string;
}

export const prKey = (s: Pick<ScanRow, "repo" | "pr_number" | "scan_id">) => s.pr_number > 0 ? `${s.repo}#${s.pr_number}` : `${s.repo}@${s.scan_id}`;

/** scan_ids that are NOT the latest scan of their pull request (direct pushes are each their own). */
export function supersededIds(scans: readonly ScanRow[]): Set<string> {
  const latest = new Map<string, ScanRow>();
  for (const s of scans) {
    const k = prKey(s);
    const cur = latest.get(k);
    if (!cur || s.created_at > cur.created_at) latest.set(k, s);
  }
  const keep = new Set([...latest.values()].map(s => s.scan_id));
  return new Set(scans.filter(s => !keep.has(s.scan_id)).map(s => s.scan_id));
}

/** Signed-off HIGH/CRITICAL files of a scan: server attestations plus findings resolved since (deduplicated). */
export function reviewedCount(s: ScanRow, resolvedKeys: ReadonlySet<string>): number {
  const files = new Set(s.attested_files ?? []);
  for (const k of resolvedKeys) {
    const first = k.indexOf("::"), second = first < 0 ? -1 : k.indexOf("::", first + 2);
    if (second < 0 || k.slice(first + 2, second) !== s.scan_id) continue;
    files.add(k.slice(second + 2));
  }
  const total = s.high_crit_count ?? 0;
  return Math.min(total, s.attested_files ? files.size : Math.max(s.attested_count, files.size));
}

export interface HistoryStats {
  scans: number;
  prs: number;
  repos: number;
  files: number;
  critical: number;
  high: number;
  /** Latest scans per PR with HIGH/CRITICAL files, and how many of those have every such file signed off. */
  needsReview: number;
  fullyReviewed: number;
  /** Files-weighted AI share; null without files. */
  ai_share: number | null;
}

export function historyStats(scans: readonly ScanRow[], resolvedKeys: ReadonlySet<string>): HistoryStats {
  const superseded = supersededIds(scans);
  const latest = scans.filter(s => !superseded.has(s.scan_id) && (s.high_crit_count ?? 0) > 0);
  const files = scans.reduce((a, s) => a + Math.max(0, s.file_count), 0);
  return {
    scans: scans.length,
    prs: new Set(scans.map(prKey)).size,
    repos: new Set(scans.map(s => s.repo)).size,
    files,
    critical: scans.filter(s => s.overall_risk === "CRITICAL").length,
    high: scans.filter(s => s.overall_risk === "HIGH").length,
    needsReview: latest.length,
    fullyReviewed: latest.filter(s => reviewedCount(s, resolvedKeys) >= (s.high_crit_count ?? 0)).length,
    ai_share: files ? scans.reduce((a, s) => a + s.total_ai_percentage * Math.max(0, s.file_count), 0) / files : null,
  };
}

const RANK: Record<RiskLevel, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, UNKNOWN: 0 };

/** One bucket per UTC day from `start` to `end` inclusive, with counts per worst-risk level. */
export function dailyActivity(scans: readonly ScanRow[], start: Date, end: Date) {
  const day = (d: Date) => d.toISOString().slice(0, 10);
  const out: Array<{ day: string; total: number; byRisk: Record<"CRITICAL" | "HIGH" | "MEDIUM" | "LOW", number>; worst: RiskLevel | null }> = [];
  const index = new Map<string, number>();
  for (let t = Date.UTC(start.getUTCFullYear(), start.getUTCMonth(), start.getUTCDate()); t <= end.getTime(); t += 86400_000) {
    index.set(day(new Date(t)), out.length);
    out.push({ day: day(new Date(t)), total: 0, byRisk: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 }, worst: null });
  }
  for (const s of scans) {
    const i = index.get(s.created_at.slice(0, 10));
    if (i == null) continue;
    const b = out[i];
    b.total++;
    if (s.overall_risk !== "UNKNOWN") b.byRisk[s.overall_risk]++;
    if (!b.worst || RANK[s.overall_risk] > RANK[b.worst]) b.worst = s.overall_risk;
  }
  return out;
}
