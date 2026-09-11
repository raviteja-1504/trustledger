import { scoreBaselineDeviation } from "@/lib/scanner";

const baseMeta = { additions: 50, deletions: 5, commits: 5, changed_files: 3 };
const usualBaseline = { pr_count: 10, avg_loc_per_pr: 50, avg_commits_per_pr: 5, avg_files_per_pr: 3, avg_ai_percentage: 0.1 };

describe("scoreBaselineDeviation", () => {
  it("returns 0 when the baseline has no prior PRs at all", () => {
    const result = scoreBaselineDeviation(baseMeta, { ...usualBaseline, pr_count: 0 });
    expect(result.score).toBe(0);
    expect(result.reasons).toEqual([]);
  });

  it("still produces a non-zero score on a clear deviation with only 1 prior PR (reduced confidence, not zero)", () => {
    // 10x the usual LOC in a single commit -- an obvious deviation even with thin history
    const meta = { additions: 500, deletions: 0, commits: 1, changed_files: 3 };
    const result = scoreBaselineDeviation(meta, { ...usualBaseline, pr_count: 1 });
    expect(result.score).toBeGreaterThan(0);
  });

  it("scores higher with 2 prior PRs than with 1, for the identical deviation", () => {
    const meta = { additions: 500, deletions: 0, commits: 1, changed_files: 3 };
    const withOne = scoreBaselineDeviation(meta, { ...usualBaseline, pr_count: 1 });
    const withTwo = scoreBaselineDeviation(meta, { ...usualBaseline, pr_count: 2 });
    expect(withTwo.score).toBeGreaterThan(withOne.score);
  });

  it("reaches full confidence at 3+ prior PRs (matches the pre-fix behavior for well-established authors)", () => {
    const meta = { additions: 500, deletions: 0, commits: 1, changed_files: 3 };
    const withThree = scoreBaselineDeviation(meta, { ...usualBaseline, pr_count: 3 });
    const withTen    = scoreBaselineDeviation(meta, { ...usualBaseline, pr_count: 10 });
    expect(withThree.score).toBe(withTen.score);
  });

  it("scores 0 for a PR that matches the author's usual pattern, regardless of history depth", () => {
    const result = scoreBaselineDeviation(baseMeta, usualBaseline);
    expect(result.score).toBe(0);
  });

  it("notes reduced confidence in the reasons when history is thin", () => {
    const meta = { additions: 500, deletions: 0, commits: 1, changed_files: 3 };
    const result = scoreBaselineDeviation(meta, { ...usualBaseline, pr_count: 1 });
    expect(result.reasons.some(r => r.includes("limited confidence"))).toBe(true);
  });
});
