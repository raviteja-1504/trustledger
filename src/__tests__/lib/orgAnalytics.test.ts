/**
 * Analytics (lib/orgAnalytics.ts): every figure is measured from rows -- weekly counts, review time from scan to
 * sign-off, backlog age from the finding's created_at, files-weighted AI share.
 */
import { computeAnalytics, quantile, type AnalyticsRows } from "@/lib/orgAnalytics";

const NOW = "2026-10-19T12:00:00.000Z"; // Monday
const H = 3600_000;
const at = (base: string, hours: number) => new Date(Date.parse(base) + hours * H).toISOString();

function rows(over: Partial<AnalyticsRows> = {}): AnalyticsRows {
  return {
    now: NOW, start: "2026-10-05T12:00:00.000Z", end: NOW,
    scans: [
      { id: "s1", repo: "acme/api", pr_number: 1, pr_author: "alice", created_at: "2026-10-06T10:00:00Z", total_ai_percentage: 0.5, file_count: 10 },
      { id: "s2", repo: "acme/api", pr_number: 1, pr_author: "alice", created_at: "2026-10-07T10:00:00Z", total_ai_percentage: 1, file_count: 30 },  // same PR
      { id: "s3", repo: "acme/web", pr_number: 2, pr_author: "bob", created_at: "2026-10-14T10:00:00Z", total_ai_percentage: 0, file_count: 10 },
      { id: "old", repo: "acme/web", pr_number: 9, pr_author: "bob", created_at: "2026-09-01T10:00:00Z", total_ai_percentage: 1, file_count: 99 }, // before the period
    ],
    violations: [
      { id: "v1", scan_id: "s1", file_path: "a.ts", risk_score: "CRITICAL", status: "resolved", created_at: "2026-10-06T10:00:00Z", resolved_at: "2026-10-14T09:00:00Z", sla_deadline: "2026-10-07T10:00:00Z" },
      { id: "v2", scan_id: "s2", file_path: "b.ts", risk_score: "HIGH", status: "open", created_at: "2026-10-07T10:00:00Z", resolved_at: null, sla_deadline: "2026-10-09T10:00:00Z" },
      { id: "v3", scan_id: "s3", file_path: "c.ts", risk_score: "MEDIUM", status: "in_review", created_at: "2026-10-19T02:00:00Z", resolved_at: null, sla_deadline: null },
      // Older finding on the same file as v2's repo? No -- an old finding on web/x.ts, still open, created before the period.
      { id: "v4", scan_id: "old", file_path: "x.ts", risk_score: "HIGH", status: "open", created_at: "2026-09-01T10:00:00Z", resolved_at: null, sla_deadline: "2026-09-03T10:00:00Z" },
    ],
    attestations: [
      { scan_id: "s1", file_path: "a.ts", risk_score: "CRITICAL", reviewer_email: "carol@acme.test", reviewer_github: "carol", created_at: at("2026-10-06T10:00:00Z", 2) },   // 2h, before deadline
      { scan_id: "s2", file_path: "b.ts", risk_score: "HIGH", reviewer_email: "alice@acme.test", reviewer_github: "Alice", created_at: at("2026-10-07T10:00:00Z", 72) }, // 72h, after deadline, self
      { scan_id: "s3", file_path: "c.ts", risk_score: "HIGH", reviewer_email: "carol@acme.test", reviewer_github: "carol", created_at: at("2026-10-14T10:00:00Z", 6) },  // 6h, no deadline
    ],
    ...over,
  };
}

describe("files, not rows: rescans and sign-offs that cover several scans count once", () => {
  it("one sign-off resolving the file in three scans of its content is one closed; three rescans flagging it, one found", () => {
    const scans = ["r1", "r2", "r3"].map((id, i) => ({ id, repo: "acme/juice", pr_number: 1, pr_author: "dev", created_at: at("2026-10-06T10:00:00Z", i), total_ai_percentage: 0, file_count: 1 }));
    const v = (id: string, scan_id: string, h: number) => ({ id, scan_id, file_path: "login.ts", risk_score: "CRITICAL", status: "resolved", created_at: at("2026-10-06T10:00:00Z", h), resolved_at: at("2026-10-08T10:00:00Z", h), sla_deadline: null });
    const r = computeAnalytics(rows({ scans, violations: [v("a", "r1", 0), v("b", "r2", 1), v("c", "r3", 2)], attestations: [] }));
    expect([r.totals.opened, r.totals.closed]).toEqual([1, 1]);
    expect(r.repos.find(x => x.repo === "acme/juice")).toMatchObject({ opened: 1, closed: 1, open: 0 });
    // and counted in the week the file was FIRST flagged / closed
    expect(r.weeks[0]).toMatchObject({ closed: 1, opened: { total: 1, critical: 1 } });
  });
});

describe("computeAnalytics", () => {
  const a = computeAnalytics(rows());

  it("weeks cover the period to today, each counted from its own rows", () => {
    expect(a.weeks.map(w => [w.week, w.label])).toEqual([["2026-10-05", "Oct 5"], ["2026-10-12", "Oct 12"], ["2026-10-19", "This week"]]);
    expect(a.weeks.map(w => [w.scans, w.prs, w.files])).toEqual([[2, 1, 40], [1, 1, 10], [0, 0, 0]]);
    expect(a.weeks[0].ai_share).toBeCloseTo((0.5 * 10 + 1 * 30) / 40);   // files-weighted
    expect(a.weeks[2].ai_share).toBeNull();
    expect(a.weeks.map(w => w.opened.total)).toEqual([2, 0, 1]);
    expect(a.weeks[0].opened).toEqual({ critical: 1, high: 1, medium: 0, total: 2 });
    expect(a.weeks.map(w => w.closed)).toEqual([0, 1, 0]);
    expect(a.weeks.map(w => w.signoffs)).toEqual([2, 1, 0]); // Oct 6, Oct 10 (72h after Oct 7), Oct 14
    expect(a.weeks[0].range).toBe("Oct 5 – Oct 11");
  });

  it("totals only count the period (the September scan and finding are outside it)", () => {
    expect(a.totals).toMatchObject({ scans: 3, prs: 2, files: 50, opened: 3, closed: 1, signoffs: 3 });
  });

  it("review time is sign-off minus scan time, per severity, with deadline adherence", () => {
    const crit = a.review_time.find(r => r.severity === "CRITICAL")!;
    const high = a.review_time.find(r => r.severity === "HIGH")!;
    expect(crit).toEqual({ severity: "CRITICAL", count: 1, median_hours: 2, p90_hours: 2, with_deadline: 1, on_time: 1 });
    expect(high).toMatchObject({ count: 2, median_hours: 39, with_deadline: 1, on_time: 0 });
    expect(high.p90_hours).toBeCloseTo(65.4);
  });

  it("backlog is the latest open finding per file, aged from when it was opened", () => {
    expect(a.backlog.open).toBe(3);       // v2, v3, v4 (v1 resolved)
    expect(a.backlog.overdue).toBe(2);    // v2 and v4 are past their deadlines; v3 has none
    expect(a.backlog.by_age.map(b => [b.key, b.count])).toEqual([["lt1d", 1], ["d1_2", 0], ["d2_7", 0], ["gt7d", 2]]);
    expect(a.backlog.closed_per_day).toBe(0.1); // 1 closed over 14 days
    expect(a.backlog.days_to_clear).toBe(42);
  });

  it("a newer finding on the same file supersedes the older one", () => {
    const r = computeAnalytics(rows({ violations: [
      { id: "old", scan_id: "s1", file_path: "a.ts", risk_score: "HIGH", status: "open", created_at: "2026-10-06T10:00:00Z", resolved_at: null, sla_deadline: null },
      { id: "new", scan_id: "s2", file_path: "a.ts", risk_score: "HIGH", status: "resolved", created_at: "2026-10-07T10:00:00Z", resolved_at: "2026-10-08T10:00:00Z", sla_deadline: null },
    ] }));
    expect(r.backlog.open).toBe(0);
    expect(r.backlog.days_to_clear).toBe(0);
  });

  it("reviewers by sign-offs with their median, and self-approvals (case-insensitive)", () => {
    expect(a.reviewers).toEqual([
      { reviewer: "carol@acme.test", signoffs: 2, median_hours: 4 },
      { reviewer: "alice@acme.test", signoffs: 1, median_hours: 72 },
    ]);
    expect(a.self_approvals).toBe(1);
  });

  it("repositories: period activity plus the current backlog", () => {
    expect(a.repos).toEqual([
      { repo: "acme/web", scans: 1, prs: 1, opened: 1, closed: 0, open: 2, ai_share: 0 },
      { repo: "acme/api", scans: 2, prs: 1, opened: 2, closed: 1, open: 1, ai_share: (0.5 * 10 + 30) / 40 },
    ]);
  });

  it("nothing closed → no projection; nothing at all → zeros, not made-up numbers", () => {
    const r = computeAnalytics(rows({ violations: rows().violations.map(v => ({ ...v, status: "open", resolved_at: null })) }));
    expect(r.backlog.days_to_clear).toBeNull();
    const empty = computeAnalytics({ now: NOW, start: "2026-10-12T12:00:00.000Z", end: NOW, scans: [], violations: [], attestations: [] });
    expect(empty.totals).toEqual({ scans: 0, prs: 0, files: 0, opened: 0, closed: 0, signoffs: 0, ai_share: null });
    expect(empty.review_time.every(r => r.median_hours === null && r.count === 0)).toBe(true);
    expect(empty.backlog).toMatchObject({ open: 0, days_to_clear: 0, closed_per_day: 0 });
  });

  it("sign-offs on scans outside the period still get a review time when that scan is supplied", () => {
    const r = computeAnalytics(rows({
      attestations: [{ scan_id: "older", file_path: "z.ts", risk_score: "CRITICAL", reviewer_email: "x@a.test", reviewer_github: null, created_at: "2026-10-10T10:00:00Z" }],
      extraScans: [{ id: "older", repo: "acme/api", pr_number: 5, pr_author: null, created_at: "2026-10-09T10:00:00Z", total_ai_percentage: 0, file_count: 1 }],
    }));
    expect(r.review_time[0]).toMatchObject({ count: 1, median_hours: 24 });
    expect(r.totals.scans).toBe(3); // the extra scan isn't counted as period activity
  });

  it("edge cases: reopened findings aren't closed, clock skew is ignored, deadline and 7-day boundaries, AI share without file counts", () => {
    const r = computeAnalytics(rows({
      scans: [{ id: "s1", repo: "acme/api", pr_number: 1, pr_author: null, created_at: "2026-10-10T00:00:00Z", total_ai_percentage: 0.6, file_count: 0 },
              { id: "s2", repo: "acme/api", pr_number: 2, pr_author: null, created_at: "2026-10-11T00:00:00Z", total_ai_percentage: 0.2, file_count: 0 }],
      violations: [
        // Was resolved, then reopened: resolved_at is set but it's open -- not "closed".
        { id: "re", scan_id: "s1", file_path: "a.ts", risk_score: "HIGH", status: "open", created_at: "2026-10-10T00:00:00Z", resolved_at: "2026-10-11T00:00:00Z", sla_deadline: "2026-10-10T05:00:00Z" },
        // Exactly 7 days old.
        { id: "seven", scan_id: "s2", file_path: "b.ts", risk_score: "HIGH", status: "open", created_at: "2026-10-12T12:00:00.000Z", resolved_at: null, sla_deadline: null },
      ],
      attestations: [
        { scan_id: "s1", file_path: "a.ts", risk_score: "HIGH", reviewer_email: "x", reviewer_github: null, created_at: "2026-10-10T05:00:00Z" },   // exactly at deadline
        { scan_id: "s2", file_path: "b.ts", risk_score: "HIGH", reviewer_email: "y", reviewer_github: null, created_at: "2026-10-10T23:00:00Z" },   // before its scan: skew
      ],
    }));
    expect(r.totals.closed).toBe(0);
    expect(r.review_time.find(x => x.severity === "HIGH")).toMatchObject({ count: 1, median_hours: 5, with_deadline: 1, on_time: 1 });
    // "re" is 9.5 days old; "seven" is exactly 7.0 days old and also counts as over 7 days (not 2-7).
    expect(r.backlog.by_age.map(b => [b.key, b.count])).toEqual([["lt1d", 0], ["d1_2", 0], ["d2_7", 0], ["gt7d", 2]]);
    expect(r.totals.ai_share).toBeCloseTo(0.4);
  });

  it("quantile interpolates", () => {
    expect(quantile([], 0.5)).toBeNull();
    expect(quantile([1, 3], 0.5)).toBe(2);
    expect(quantile([1, 2, 3, 4], 0.9)).toBeCloseTo(3.7);
  });
});
