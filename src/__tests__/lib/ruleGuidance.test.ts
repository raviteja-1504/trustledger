import { EFFORT_LABEL, SEVERITY_GUIDANCE, cweUrl, fixSteps, guidanceFor, relatedRules, verifySteps } from "@/lib/ruleGuidance";
import {
  countRuleUsage, groupByRepo, fileHref, locationsForRule, previousScanPerRepo, viewRules, DEFAULT_VIEW, type IndicatorRow,
} from "@/lib/ruleUsage";

describe("ruleGuidance", () => {
  it("says when each severity should be fixed, and critical is the most urgent", () => {
    expect(SEVERITY_GUIDANCE.critical.sla).toBe("Same day");
    expect(SEVERITY_GUIDANCE.low.sla).toBe("Within a quarter");
    expect(guidanceFor("high")).toBe(SEVERITY_GUIDANCE.high);
    expect(guidanceFor(null)).toBeNull();
  });
  it("verification depends on how the rule detects", () => {
    expect(verifySteps("data-flow")[0]).toMatch(/break the path between the input and the dangerous call/);
    expect(verifySteps("configuration")[2]).toMatch(/overridden elsewhere/);
    expect(verifySteps("pattern")[2]).toMatch(/false positive/);
    for (const d of ["data-flow", "configuration", "pattern"] as const) expect(verifySteps(d).some(s => /rescan/i.test(s))).toBe(true);
  });
  it("turns a fix description into steps at sentence ends, not inside abbreviations like e.g. or file.ts", () => {
    expect(fixSteps("Use bound parameters. Never concatenate input into the query. Validate the type, e.g. an integer id.")).toEqual([
      "Use bound parameters.", "Never concatenate input into the query.", "Validate the type, e.g. an integer id.",
    ]);
    expect(fixSteps("Single sentence only")).toEqual(["Single sentence only"]);
    expect(fixSteps("")).toEqual([]);
  });
  it("caps the steps", () => {
    expect(fixSteps("One. Two. Three. Four. Five. Six. Seven.", 3)).toHaveLength(3);
  });
  it("related rules share the CWE, exclude the rule itself, and are capped", () => {
    const rs: Array<{ id: string; title: string; cwe: string | null }> = [1, 2, 3, 4, 5, 6, 7].map(n => ({ id: `r${n}`, title: `R${n}`, cwe: n <= 6 ? "CWE-89" : "CWE-79" }));
    expect(relatedRules(rs[0], rs).map(r => r.id)).toEqual(["r2", "r3", "r4", "r5", "r6"]);
    expect(relatedRules(rs[6], rs)).toEqual([]);
    expect(relatedRules({ id: "x", title: "X", cwe: null }, rs)).toEqual([]);
  });
  it("links the CWE, or nothing", () => {
    expect(cweUrl("CWE-89")).toBe("https://cwe.mitre.org/data/definitions/89.html");
    expect(cweUrl(null)).toBeNull();
    expect(cweUrl("n/a")).toBeNull();
  });
  it("effort labels cover every level", () => {
    expect(Object.keys(EFFORT_LABEL)).toEqual(["low", "medium", "high"]);
  });
});

const row = (scan_id: string, file_path: string, risk_indicators: unknown): IndicatorRow => ({ scan_id, file_path, risk_indicators });

describe("countRuleUsage: new and fixed against the previous scan", () => {
  // o/api: latest scan L1, previous P1.  o/web: only a latest scan L2 (nothing to compare with).
  const latest = new Map([["L1", "o/api"], ["L2", "o/web"]]);
  const previous = { scanRepo: new Map([["P1", "o/api"]]), rows: [row("P1", "a.ts", ["xss", "sqli"]), row("P1", "b.ts", ["xss"]), row("P1", "gone.ts", ["xss"]), row("P1", "c.ts", ["secret"])] };
  const rows = [row("L1", "a.ts", ["xss"]), row("L1", "b.ts", []), row("L1", "d.ts", ["xss"]), row("L1", "c.ts", ["secret"]), row("L2", "w.ts", ["xss"])];

  it("a file where a rule fires now and did not before is new; one that stopped is fixed", () => {
    const u = countRuleUsage(rows, latest, previous);
    // xss now: a.ts (was firing), d.ts (new), o/web w.ts (no previous scan: not counted as new)
    expect(u.xss).toMatchObject({ files: 3, repos: 2, new: 1, compared: true });
    expect(u.xss.fixed).toBe(1);                       // b.ts: was firing, still scanned, no longer fires. gone.ts was not rescanned: not counted
  });
  it("a rule that fired before and fires nowhere now still gets a row, saying it is fixed", () => {
    const u = countRuleUsage(rows, latest, previous);
    expect(u.sqli).toEqual({ files: 0, repos: 0, new: 0, fixed: 1, compared: true });
  });
  it("an unchanged rule is neither new nor fixed", () => {
    expect(countRuleUsage(rows, latest, previous).secret).toMatchObject({ new: 0, fixed: 0 });
  });
  it("a repository's first scan contributes no 'new': everything would be new", () => {
    const u = countRuleUsage([row("L2", "w.ts", ["xss"])], new Map([["L2", "o/web"]]), previous);
    expect(u.xss.new).toBe(0);
  });
  it("without a previous scan at all, nothing is claimed about change", () => {
    const u = countRuleUsage(rows, latest);
    expect(u.xss).toEqual({ files: 3, repos: 2, where: expect.any(Array) });
    expect(u.xss.new).toBeUndefined();
    expect(u.xss.compared).toBeUndefined();
  });
  it("a repeated id in one file counts once", () => {
    expect(countRuleUsage([row("L1", "a.ts", ["xss", "xss"])], latest).xss.files).toBe(1);
  });
});

describe("previousScanPerRepo", () => {
  it("is each repository's second newest scan, in any input order", () => {
    const scans = [
      { id: "a1", repo_full_name: "o/a", created_at: "2026-01-01T00:00:00Z" }, { id: "a3", repo_full_name: "o/a", created_at: "2026-03-01T00:00:00Z" }, { id: "a2", repo_full_name: "o/a", created_at: "2026-02-01T00:00:00Z" },
      { id: "b1", repo_full_name: "o/b", created_at: "2026-01-01T00:00:00Z" },
    ];
    expect(previousScanPerRepo(scans)).toEqual(new Map([["a2", "o/a"]]));          // o/b has only one scan
  });
});

describe("locationsForRule", () => {
  const latest = new Map([["L1", "o/api"], ["L2", "o/web"]]);
  const rows = [row("L1", "b.ts", ["xss"]), row("L1", "a.ts", ["xss"]), row("L2", "c.ts", ["xss"]), row("L1", "z.ts", ["other"]), row("OLD", "q.ts", ["xss"])];
  it("lists every file for the rule, sorted, from the latest scans only", () => {
    const r = locationsForRule(rows, latest, "xss");
    expect(r.locations.map(l => `${l.repo}:${l.file_path}`)).toEqual(["o/api:a.ts", "o/api:b.ts", "o/web:c.ts"]);
    expect(r).toMatchObject({ total: 3, truncated: false });
  });
  it("can be limited to one repository", () => {
    expect(locationsForRule(rows, latest, "xss", { repo: "o/web" }).locations.map(l => l.file_path)).toEqual(["c.ts"]);
  });
  it("past the limit it says it was cut, with the real total", () => {
    expect(locationsForRule(rows, latest, "xss", { limit: 2 })).toMatchObject({ total: 3, truncated: true, locations: expect.any(Array) });
    expect(locationsForRule(rows, latest, "xss", { limit: 2 }).locations).toHaveLength(2);
  });
  it("an unknown rule has none", () => {
    expect(locationsForRule(rows, latest, "nope")).toEqual({ locations: [], total: 0, truncated: false });
  });
});

describe("groupByRepo and fileHref", () => {
  it("groups by repository, the one with most files first", () => {
    const g = groupByRepo([{ repo: "o/a", file_path: "1", scan_id: "s" }, { repo: "o/b", file_path: "2", scan_id: "s" }, { repo: "o/b", file_path: "3", scan_id: "s" }]);
    expect(g.map(x => [x.repo, x.files.length])).toEqual([["o/b", 2], ["o/a", 1]]);
  });
  it("links to the review page opened on that file, with the path encoded", () => {
    expect(fileHref({ repo: "o/a", file_path: "src/a b/c#d.ts", scan_id: "s9" })).toBe("/pr/s9?file=src%2Fa%20b%2Fc%23d.ts");
  });
});

describe("viewRules: sorting by new findings", () => {
  const rules = [
    { id: "a", title: "A", description: "", cwe: null, severity: "low", detection: "pattern", appliesTo: [] },
    { id: "b", title: "B", description: "", cwe: null, severity: "high", detection: "pattern", appliesTo: [] },
    { id: "c", title: "C", description: "", cwe: null, severity: "critical", detection: "pattern", appliesTo: [] },
  ];
  it("most new files first, then most files, then severity", () => {
    const usage = { a: { files: 9, repos: 1, new: 0 }, b: { files: 2, repos: 1, new: 5 }, c: { files: 2, repos: 1, new: 5 } };
    expect(viewRules(rules, usage, { ...DEFAULT_VIEW, sort: "new" }).map(r => r.id)).toEqual(["c", "b", "a"]);
  });
});
