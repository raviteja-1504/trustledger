import { computeInsights, daysUntil, levelOf, FOCUS_LIMIT } from "@/lib/riskInsights";
import { closedHistory, deriveRisksFrom, type RiskItem, type RiskRow } from "@/lib/riskRegister";

const NOW = new Date("2026-11-08T10:00:00Z");
const risk = (o: Partial<RiskItem> & { id: string }): RiskItem => ({
  title: o.id, description: "", category: "ai-code", likelihood: 3, impact: 3, status: "open", treatment: "mitigate", owner: "unassigned",
  mitigation: "", identified_at: "2026-11-01", auto_derived: true, notes: [], ...o,
});

describe("levelOf / daysUntil", () => {
  it("bands the score", () => {
    expect([1, 5, 6, 11, 12, 19, 20, 25].map(levelOf)).toEqual(["LOW", "LOW", "MEDIUM", "MEDIUM", "HIGH", "HIGH", "CRITICAL", "CRITICAL"]);
  });
  it("counts whole days, negative when overdue, nothing for no or a bad date", () => {
    expect(daysUntil("2026-11-08", NOW)).toBe(0);
    expect(daysUntil("2026-11-10", NOW)).toBe(2);
    expect(daysUntil("2026-11-05", NOW)).toBe(-3);
    expect(daysUntil(undefined, NOW)).toBeNull();
    expect(daysUntil("nonsense", NOW)).toBeNull();
  });
});

describe("computeInsights", () => {
  const risks = [
    risk({ id: "crit-unowned", likelihood: 5, impact: 5, repo: "o/api" }),
    risk({ id: "high-overdue", likelihood: 4, impact: 4, owner: "a@x.com", due_date: "2026-11-01", repo: "o/api", status: "mitigating", residual_likelihood: 2, residual_impact: 2 }),
    risk({ id: "med-soon", likelihood: 2, impact: 3, owner: "b@x.com", due_date: "2026-11-12", repo: "o/web", category: "compliance", identified_at: "2026-10-01" }),
    risk({ id: "accepted-bare", status: "accepted", owner: "a@x.com" }),
    risk({ id: "accepted-noted", status: "accepted", owner: "a@x.com", notes: ["approved by CISO"] }),
    risk({ id: "done", status: "closed", likelihood: 5, impact: 5, repo: "o/api" }),
    risk({ id: "manual", auto_derived: false, likelihood: 1, impact: 1, owner: "b@x.com", mitigation: "plan" }),
  ];
  const i = computeInsights(risks, NOW);

  it("counts by status, with closed risks out of the active total", () => {
    expect(i).toMatchObject({ total: 7, open: 3, mitigating: 1, accepted: 2, closed: 1, active: 6 });
  });
  it("counts what needs attention among active risks only", () => {
    expect(i).toMatchObject({ critical: 1, high: 1, overdue: 1, dueSoon: 1, unassigned: 1 });     // the closed 25 is not counted
    expect(i.highWithoutDueDate).toBe(1);                                                          // crit-unowned
  });
  it("flags accepted risks nobody explained", () => {
    expect(i.acceptedUnexplained).toBe(1);                                                         // accepted-bare; accepted-noted has a note
  });
  it("averages inherent over active, residual over those that have one, and the reduction", () => {
    expect(i.avgInherent).toBe(11);                                                                // (25+16+6+9+9+1)/6
    expect(i.avgResidual).toBe(4);
    expect(i.withResidual).toBe(1);
    expect(i.reductionPct).toBe(75);                                                               // 16 -> 4
  });
  it("without residual scores there is no reduction claimed", () => {
    expect(computeInsights([risk({ id: "a" })], NOW)).toMatchObject({ avgResidual: null, reductionPct: null, withResidual: 0 });
  });
  it("ages active risks from when they were identified", () => {
    expect(i.oldest).toEqual({ id: "med-soon", title: "med-soon", days: 38 });
    expect(i.avgAgeDays).toBeGreaterThan(0);
  });
  it("counts derived risks and those since closed", () => {
    expect(i).toMatchObject({ autoDerived: 6, autoClosed: 1 });
  });
  it("shows where the exposure is, most exposed first", () => {
    expect(i.byRepo[0]).toEqual({ key: "o/api", active: 2, critical: 1, score: 41 });
    expect(i.byRepo.map(r => r.key)).toEqual(["o/api", "o/web"]);
    expect(i.byCategory.find(c => c.key === "compliance")).toMatchObject({ active: 1 });
  });
  it("picks the few to act on first: overdue and critical lead, with the reasons", () => {
    expect(i.focus.map(f => f.id)).toEqual(["high-overdue", "crit-unowned", "med-soon"]);
    expect(i.focus[0].reasons).toEqual(["Overdue by 7 days", "High (16)"]);
    expect(i.focus[2].reasons).toEqual(["Due in 4 days"]);
    expect(i.focus[1]).toMatchObject({ level: "CRITICAL", reasons: ["Critical (25)", "Nobody owns it", "No due date"] });
  });
  it("a risk one day overdue is already overdue; due today is not", () => {
    const one = computeInsights([risk({ id: "a", likelihood: 5, impact: 5, due_date: "2026-11-07" }), risk({ id: "b", likelihood: 5, impact: 5, due_date: "2026-11-08" })], NOW);
    expect(one.overdue).toBe(1);
    expect(one.focus.find(f => f.id === "a")!.reasons[0]).toBe("Overdue by 1 day");
    expect(one.focus.find(f => f.id === "b")!.reasons[0]).toBe("Due today");
  });
  it("never lists more than the limit", () => {
    const many = Array.from({ length: 12 }, (_, n) => risk({ id: `r${n}`, likelihood: 5, impact: 5 }));
    expect(computeInsights(many, NOW).focus).toHaveLength(FOCUS_LIMIT);
  });
  it("an empty register is all zeros and nulls", () => {
    expect(computeInsights([], NOW)).toMatchObject({ total: 0, active: 0, avgInherent: null, oldest: null, byRepo: [], focus: [] });
  });
});

describe("deriveRisksFrom / closedHistory", () => {
  it("builds file risks from the waiting files and pattern risks from indicators", () => {
    const got = deriveRisksFrom({
      waiting: [{ repo: "o/api", file_path: "a.ts", risk_score: "CRITICAL", ai_pct: 0.5 }, { repo: "o/api", file_path: "b.ts", risk_score: "HIGH", ai_pct: 0.5 }],
      repos: [{ repo: "o/api", attestation_rate: 0.25, high_crit_count: 4 }],
      patternFiles: [{ repo: "o/api", file_path: "a.ts", risk_indicators: ["sql-injection"] }],
    }, "2026-11-08T00:00:00Z");
    expect(got.map(r => r.id)).toEqual(["DR-CRIT-UNATT-o-api", "DR-HIGH-UNATT-o-api", "DR-SQL-INJECT-o-api", "DR-DEPLOY-BLOCK", "DR-LOW-ATT-o-api"]);
    expect(got.every(r => r.status === "open" && r.owner === "unassigned" && r.identified_at === "2026-11-08")).toBe(true);
  });
  it("nothing waiting and every repo attested: no file, deploy or attestation risks", () => {
    const got = deriveRisksFrom({ waiting: [], repos: [{ repo: "o/api", attestation_rate: 1, high_crit_count: 3 }], patternFiles: [] });
    expect(got).toEqual([]);
  });
  const row = (o: Partial<RiskRow>): RiskRow => ({ external_id: "DR-X", auto_derived: true, title: "T", description: null, category: "ai-code", likelihood: 4, impact: 4, residual_likelihood: null, residual_impact: null,
    status: "closed", treatment: "mitigate", owner_email: "a@x.com", due_date: null, mitigation: null, related_cve: null, related_cwe: null, related_link: null, repo: "o/api", notes: ["n"], created_at: "2026-10-01T00:00:00Z", ...o });
  it("keeps closed derived risks that are no longer derived, as history, with their owner and notes", () => {
    const got = closedHistory([row({}), row({ external_id: "DR-OPEN", status: "open" }), row({ external_id: "DR-LIVE" }), row({ external_id: "MR-1", auto_derived: false })], new Set(["DR-LIVE"]));
    expect(got).toHaveLength(1);
    expect(got[0]).toMatchObject({ id: "DR-X", status: "closed", owner: "a@x.com", notes: ["n"], identified_at: "2026-10-01", repo: "o/api" });
  });
});
