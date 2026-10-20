/**
 * Repository summary (lib/repoSummary.ts): current files with their sign-off status, PRs, history, totals.
 */
import { buildRepoSummary, overrideKey, weightedAi, type SummaryScanRow } from "@/lib/repoSummary";

const scan = (id: string, pr: number | null, at: string, o: Partial<SummaryScanRow> = {}): SummaryScanRow => ({
  id, pr_number: pr, commit_sha: `${id}abcdef12345`, branch: "feat", overall_risk: "HIGH", total_ai_percentage: 0.5, file_count: 10,
  created_at: at, triggered_by: "webhook", pr_author: "ada", ...o,
});
const f = (scan_id: string, path: string, risk: string, ai = 0.5, ind: unknown = []) => ({ scan_id, file_path: path, language: "ts", risk_score: risk, ai_percentage: ai, risk_indicators: ind });
const NOW = Date.parse("2026-10-20T12:00:00Z");

const input = () => ({
  scans: [
    scan("s1", 7, "2026-10-01T00:00:00Z", { total_ai_percentage: 0.9, file_count: 30 }),
    scan("s3", 8, "2026-10-19T00:00:00Z", { total_ai_percentage: 0.1, file_count: 10, pr_author: "bob" }),
    scan("s2", 7, "2026-10-10T00:00:00Z"),
    scan("p1", null, "2026-09-01T00:00:00Z", { pr_author: null }),
  ],
  latestFiles: [
    f("s3", "src/pay.ts", "CRITICAL", 0.8, ["sql-injection", 3]), f("s3", "src/auth.ts", "HIGH", 0.6), f("s3", "src/db.ts", "HIGH", 0.4),
    f("s3", "src/late.ts", "HIGH", 0.3), f("s3", "src/util.ts", "LOW", 0.9), f("s3", "src/rev.ts", "CRITICAL", 0.2),
  ],
  prFiles: [f("s3", "src/pay.ts", "CRITICAL"), f("s3", "src/auth.ts", "HIGH"), f("s3", "src/db.ts", "HIGH"), f("s3", "src/late.ts", "HIGH"), f("s3", "src/rev.ts", "CRITICAL"), f("s2", "a.ts", "HIGH"), f("s2", "b.ts", "HIGH")],
  attestations: [
    { scan_id: "s3", file_path: "src/pay.ts", reviewer_email: "second@x", created_at: "2026-10-19T09:00:00Z" },
    { scan_id: "s3", file_path: "src/pay.ts", reviewer_email: "first@x", created_at: "2026-10-19T08:00:00Z" },
    { scan_id: "s2", file_path: "a.ts", reviewer_email: "r@x", created_at: "2026-10-11T00:00:00Z" },
  ],
  violations: [
    { scan_id: "s3", file_path: "src/db.ts", status: "accepted", sla_deadline: "2026-10-01T00:00:00Z" },   // past, but closed: not overdue
    { scan_id: "s3", file_path: "src/late.ts", status: "open", sla_deadline: "2026-10-19T12:00:00Z" },
    { scan_id: "s3", file_path: "src/rev.ts", status: "open", sla_deadline: "2026-10-25T00:00:00Z" },
    { scan_id: "s3", file_path: "src/auth.ts", status: "open", sla_deadline: "2026-10-25T00:00:00Z" },
  ],
  overrides: { [overrideKey("CRITICAL", "s3", "src/rev.ts")]: "in_review", [overrideKey("HIGH", "s2", "b.ts")]: "resolved" },
  now: NOW,
});

describe("buildRepoSummary", () => {
  it("the latest scan's files, each with its sign-off status; who signed off first, and when", () => {
    const s = buildRepoSummary(input());
    expect(s.latest_scan).toMatchObject({ scan_id: "s3", pr_number: 8, latest: true, superseded: false });
    const by = Object.fromEntries(s.files.map(x => [x.file_path, x]));
    expect(by["src/pay.ts"]).toMatchObject({ status: "attested", attested_by: "first@x", attested_at: "2026-10-19T08:00:00Z", indicators: ["sql-injection"] });
    expect(by["src/db.ts"]).toMatchObject({ status: "resolved", overdue: false });   // accepted on the violations page
    expect(by["src/rev.ts"].status).toBe("in_review");          // override
    expect(by["src/auth.ts"]).toMatchObject({ status: "waiting", overdue: false });
    expect(by["src/late.ts"]).toMatchObject({ status: "waiting", overdue: true });
    expect(by["src/util.ts"].status).toBe("not_required");
    expect(s.files.map(x => x.file_path)).toEqual(["src/pay.ts", "src/rev.ts", "src/auth.ts", "src/db.ts", "src/late.ts", "src/util.ts"]);
    expect(s.signoff).toEqual({ required: 5, attested: 1, resolved: 1, in_review: 1, waiting: 2, overdue: 1 });
  });

  it("pull requests: latest scan each, sign-offs counting attestations and resolved overrides", () => {
    const s = buildRepoSummary(input());
    expect(s.prs.map(p => [p.pr_number, p.latest_scan_id, p.scans, p.high_crit, p.signed_off, p.author])).toEqual([
      [8, "s3", 1, 5, 1, "bob"], [7, "s2", 2, 2, 2, "ada"],
    ]);
    expect(s.prs[1].first_scan_at).toBe("2026-10-01T00:00:00Z");
  });

  it("history newest first with superseded scans marked; totals file-weighted", () => {
    const s = buildRepoSummary(input());
    expect(s.scans.map(x => [x.scan_id, x.superseded])).toEqual([["s3", false], ["s2", false], ["s1", true], ["p1", false]]);
    expect(s.stats).toMatchObject({ scans: 4, prs: 2, direct_pushes: 1, first_scan: "2026-09-01T00:00:00Z", last_scan: "2026-10-19T00:00:00Z" });
    expect(s.stats.ai_share).toBeCloseTo((0.9 * 30 + 0.1 * 10 + 0.5 * 10 + 0.5 * 10) / 60, 6);
    expect(s.stats.contributors).toEqual([{ login: "ada", scans: 2 }, { login: "bob", scans: 1 }]);
  });

  it("no scans → empty, nothing invented", () => {
    const s = buildRepoSummary({ scans: [], latestFiles: [], prFiles: [], attestations: [], violations: [], overrides: {} });
    expect(s.latest_scan).toBeNull();
    expect(s.files).toEqual([]);
    expect(s.stats).toMatchObject({ scans: 0, first_scan: null, ai_share: 0 });
  });

  it("weightedAi falls back to the plain mean without file counts", () => {
    expect(weightedAi([{ total_ai_percentage: 0.2, file_count: 0 }, { total_ai_percentage: 0.6, file_count: null }])).toBeCloseTo(0.4);
  });
});
