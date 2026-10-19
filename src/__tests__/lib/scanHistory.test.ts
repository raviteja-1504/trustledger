/**
 * Scan history (lib/scanHistory.ts): superseded scans, sign-off counts from server + resolved findings, period stats,
 * daily buckets.
 */
import { dailyActivity, historyStats, reviewedCount, supersededIds, type ScanRow } from "@/lib/scanHistory";

const s = (o: Partial<ScanRow>): ScanRow => ({
  scan_id: "x", repo: "acme/api", pr_number: 1, commit_sha: "abcdef1234", branch: "main", overall_risk: "LOW", total_ai_percentage: 0.5,
  file_count: 10, high_crit_count: 0, attested_count: 0, attested_files: [], created_at: "2026-10-19T10:00:00Z", triggered_by: "webhook", ...o,
});

describe("scan history", () => {
  it("older scans of the same PR are superseded; direct pushes never are", () => {
    const scans = [
      s({ scan_id: "a1", pr_number: 1, created_at: "2026-10-18T10:00:00Z" }),
      s({ scan_id: "a2", pr_number: 1, created_at: "2026-10-19T10:00:00Z" }),
      s({ scan_id: "b1", pr_number: 1, repo: "acme/web" }),
      s({ scan_id: "p1", pr_number: 0, created_at: "2026-10-17T10:00:00Z" }),
      s({ scan_id: "p2", pr_number: 0, created_at: "2026-10-18T10:00:00Z" }),
    ];
    expect([...supersededIds(scans)]).toEqual(["a1"]);
  });

  it("signed-off count: server attestations plus resolved findings, each file once, capped at the risky total", () => {
    const scan = s({ scan_id: "s1", high_crit_count: 3, attested_files: ["a.ts"], attested_count: 1 });
    expect(reviewedCount(scan, new Set())).toBe(1);
    expect(reviewedCount(scan, new Set(["crit::s1::a.ts", "high::s1::b.ts", "high::other::c.ts"]))).toBe(2);
    expect(reviewedCount({ ...scan, attested_files: ["a.ts", "b.ts", "c.ts", "d.ts"] }, new Set())).toBe(3);
    // Count only (no file list): never double-counts.
    expect(reviewedCount({ ...scan, attested_files: undefined, attested_count: 2 }, new Set(["crit::s1::a.ts"]))).toBe(2);
  });

  it("period stats come from the scans: PRs, repos, risk, files-weighted AI, fully signed off on latest scans only", () => {
    const resolved = new Set(["crit::b::y.ts"]);
    const st = historyStats([
      s({ scan_id: "a-old", pr_number: 1, overall_risk: "CRITICAL", high_crit_count: 2, created_at: "2026-10-18T10:00:00Z", total_ai_percentage: 1, file_count: 10 }),
      s({ scan_id: "a", pr_number: 1, overall_risk: "HIGH", high_crit_count: 1, attested_files: ["x.ts"], total_ai_percentage: 0, file_count: 30 }),
      s({ scan_id: "b", pr_number: 2, repo: "acme/web", overall_risk: "CRITICAL", high_crit_count: 2, attested_files: ["z.ts"] }),
      s({ scan_id: "c", pr_number: 3, high_crit_count: 0 }),
    ], resolved);
    expect(st).toMatchObject({ scans: 4, prs: 3, repos: 2, files: 60, critical: 2, high: 1, needsReview: 2, fullyReviewed: 2 });
    expect(st.ai_share).toBeCloseTo((10 + 0 + 5 + 5) / 60);
    expect(historyStats([], new Set())).toMatchObject({ scans: 0, ai_share: null, needsReview: 0 });
  });

  it("daily buckets cover every day of the period, with the day's worst result", () => {
    const days = dailyActivity([
      s({ created_at: "2026-10-17T09:00:00Z", overall_risk: "LOW" }),
      s({ created_at: "2026-10-17T11:00:00Z", overall_risk: "CRITICAL" }),
      s({ created_at: "2026-10-19T08:00:00Z", overall_risk: "MEDIUM" }),
      s({ created_at: "2026-10-01T08:00:00Z", overall_risk: "HIGH" }),   // outside
    ], new Date("2026-10-16T12:00:00Z"), new Date("2026-10-19T12:00:00Z"));
    expect(days.map(d => [d.day, d.total, d.worst])).toEqual([
      ["2026-10-16", 0, null], ["2026-10-17", 2, "CRITICAL"], ["2026-10-18", 0, null], ["2026-10-19", 1, "MEDIUM"]]);
    expect(days[1].byRisk).toEqual({ CRITICAL: 1, HIGH: 0, MEDIUM: 0, LOW: 1 });
  });
});
