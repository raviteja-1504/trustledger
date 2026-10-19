/**
 * Review debt (lib/reviewDebt.ts): real waiting hours × severity weight, for unresolved HIGH/CRITICAL findings only.
 */
import { computeReviewDebt, DEBT_WEIGHT, type DebtFinding } from "@/lib/reviewDebt";

const NOW = Date.parse("2026-10-19T12:00:00Z");
const f = (o: Partial<DebtFinding>): DebtFinding => ({
  id: "v", file_path: "a.ts", risk_score: "HIGH", status: "open", created_at: "2026-10-19T02:00:00Z", sla_deadline: null, scan_id: "s1", repo: "acme/api", pr_number: 1, ...o,
});

describe("computeReviewDebt", () => {
  it("hours waiting since the finding opened, weighted by severity; largest first", () => {
    const d = computeReviewDebt([
      f({ id: "h", created_at: "2026-10-19T02:00:00Z" }),                                // 10h × 4 = 40
      f({ id: "c", risk_score: "CRITICAL", file_path: "c.ts", created_at: "2026-10-19T09:00:00Z", sla_deadline: "2026-10-19T10:00:00Z" }), // 3h × 10 = 30
      f({ id: "later", file_path: "l.ts", created_at: "2026-10-19T11:00:00Z", sla_deadline: "2026-10-20T11:00:00Z" }),                   // 1h × 4 = 4, deadline ahead
    ], new Set(), NOW);
    expect(d.items.map(i => [i.id, i.hours, i.debt, i.overdue])).toEqual([["h", 10, 40, false], ["c", 3, 30, true], ["later", 1, 4, false]]);
    expect(d).toMatchObject({ total: 74, perHour: DEBT_WEIGHT.HIGH * 2 + DEBT_WEIGHT.CRITICAL, oldestHours: 10, overdue: 1, critical: 1 });
  });

  it("only open / in-review HIGH or CRITICAL, and not ones resolved on the violations page", () => {
    const d = computeReviewDebt([
      f({ id: "med", risk_score: "MEDIUM" }),
      f({ id: "done", status: "resolved" }),
      f({ id: "acc", status: "accepted" }),
      f({ id: "rev", status: "in_review" }),
      f({ id: "ovr", file_path: "o.ts", scan_id: "s9" }),
    ], new Set(["high::s9::o.ts"]), NOW);
    expect(d.items.map(i => i.id)).toEqual(["rev"]);
  });

  it("nothing waiting → zero", () => {
    expect(computeReviewDebt([], new Set(), NOW)).toMatchObject({ total: 0, perHour: 0, oldestHours: 0, items: [] });
  });
});
