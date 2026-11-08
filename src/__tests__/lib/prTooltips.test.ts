import { RISK_TIP, SEVERITY_TIP, COUNT_TIP, ACTION_TIP, STATUS_TIP, COLUMN_TIP, FILTER_TIP, EVIDENCE_TIP, OVERALL_TIP } from "@/lib/prTooltips";

const all = (o: Record<string, string>) => Object.entries(o);

describe("PR page tooltip wording", () => {
  it("every tooltip is a real sentence: non-empty, ends with punctuation, no placeholder text", () => {
    for (const [group, map] of Object.entries({ RISK_TIP, SEVERITY_TIP, COUNT_TIP, ACTION_TIP, STATUS_TIP, COLUMN_TIP, FILTER_TIP, EVIDENCE_TIP, OVERALL_TIP })) {
      for (const [key, text] of all(map as Record<string, string>)) {
        expect({ group, key, ok: text.trim().length > 15 && /[.)]$/.test(text.trim()) && !/TODO|lorem|undefined|\{\}/i.test(text) }).toEqual({ group, key, ok: true });
      }
    }
  });

  it("covers every risk level and severity the page shows", () => {
    expect(Object.keys(RISK_TIP).sort()).toEqual(["CRITICAL", "HIGH", "LOW", "MEDIUM", "UNKNOWN"]);
    expect(Object.keys(SEVERITY_TIP).sort()).toEqual(["critical", "high", "low", "medium"]);
  });

  it("covers the table's columns, the filters and the five evidence bars", () => {
    expect(Object.keys(COLUMN_TIP)).toEqual(["File", "Lang", "AI Content", "Risk", "Signals", "Status", "Action"]);
    expect(Object.keys(FILTER_TIP).sort()).toEqual(["all", "high", "unattested"]);
    expect(Object.keys(EVIDENCE_TIP).sort()).toEqual(["baseline_evidence", "code_evidence", "git_evidence", "pr_evidence", "tool_evidence"]);
  });

  it("the evidence weights match the percentages the page shows next to each bar", () => {
    expect(EVIDENCE_TIP.code_evidence).toMatch(/25%/);
    expect(EVIDENCE_TIP.pr_evidence).toMatch(/25%/);
    expect(EVIDENCE_TIP.git_evidence).toMatch(/25%/);
    expect(EVIDENCE_TIP.baseline_evidence).toMatch(/15%/);
    expect(EVIDENCE_TIP.tool_evidence).toMatch(/10%/);
  });

  it("the keys named in action tooltips are the keys that actually work", () => {
    expect(ACTION_TIP.nextFinding).toMatch(/\(n\)/);
    expect(ACTION_TIP.prevFinding).toMatch(/\(p\)/);
    expect(ACTION_TIP.nextReviewFile).toMatch(/\(\]\)/);
    expect(ACTION_TIP.prevReviewFile).toMatch(/\(\[\)/);
    expect(ACTION_TIP.closeReview).toMatch(/Esc/);
  });
});
