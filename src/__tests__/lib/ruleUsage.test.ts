/**
 * Where rules fire (lib/ruleUsage.ts) and how the catalog is filtered and sorted.
 */
import { appliesToOptions, countRuleUsage, DEFAULT_VIEW, latestScanPerRepo, MAX_LOCATIONS, viewRules } from "@/lib/ruleUsage";

describe("latestScanPerRepo", () => {
  it("keeps each repository's newest scan, whatever the input order", () => {
    const m = latestScanPerRepo([
      { id: "a1", repo_full_name: "o/api", created_at: "2026-10-01" }, { id: "a2", repo_full_name: "o/api", created_at: "2026-10-05" },
      { id: "w1", repo_full_name: "o/web", created_at: "2026-10-03" }, { id: "a0", repo_full_name: "o/api", created_at: "2026-09-01" },
    ]);
    expect([...m]).toEqual([["a2", "o/api"], ["w1", "o/web"]]);
  });
});

describe("countRuleUsage", () => {
  const latest = new Map([["a2", "o/api"], ["w1", "o/web"]]);
  it("counts distinct files and repos per rule in the latest scans only, with sorted locations", () => {
    const u = countRuleUsage([
      { scan_id: "a2", file_path: "src/z.py", risk_indicators: ["sql-injection", "sql-injection", "eval-exec"] },
      { scan_id: "a2", file_path: "src/a.py", risk_indicators: ["sql-injection"] },
      { scan_id: "w1", file_path: "db.ts", risk_indicators: ["sql-injection"] },
      { scan_id: "a1", file_path: "old.py", risk_indicators: ["sql-injection"] },     // an older scan: ignored
      { scan_id: "w1", file_path: "x.ts", risk_indicators: null },
      { scan_id: "w1", file_path: "y.ts", risk_indicators: [7, "", "jwt-none-alg"] },
    ], latest);
    expect(u["sql-injection"]).toEqual({ files: 3, repos: 2, where: [
      { repo: "o/api", file_path: "src/a.py", scan_id: "a2" }, { repo: "o/api", file_path: "src/z.py", scan_id: "a2" }, { repo: "o/web", file_path: "db.ts", scan_id: "w1" },
    ] });
    expect(u["eval-exec"]).toMatchObject({ files: 1, repos: 1 });
    expect(Object.keys(u).sort()).toEqual(["eval-exec", "jwt-none-alg", "sql-injection"]);
  });

  it("lists at most a few locations but counts them all", () => {
    const rows = Array.from({ length: 25 }, (_, i) => ({ scan_id: "a2", file_path: `f${String(i).padStart(2, "0")}.py`, risk_indicators: ["sql-injection"] }));
    const u = countRuleUsage(rows, latest)["sql-injection"];
    expect(u.files).toBe(25);
    expect(u.where).toHaveLength(MAX_LOCATIONS);
    expect(u.where![0].file_path).toBe("f00.py");
  });
});

describe("viewRules", () => {
  const r = (id: string, o: Partial<{ title: string; severity: string | null; detection: string; appliesTo: string[]; cwe: string | null }> = {}) =>
    ({ id, title: id.toUpperCase(), description: `${id} desc`, cwe: null, severity: "high", detection: "pattern", appliesTo: [], ...o });
  const rules = [
    r("b-rule", { severity: "low", detection: "data-flow", appliesTo: ["Python"] }),
    r("a-rule", { severity: "critical", detection: "configuration", appliesTo: ["Terraform"], cwe: "CWE-284" }),
    r("c-rule", { severity: null }),
    r("d-rule", { severity: "medium", detection: "data-flow", appliesTo: ["Python", "Java"] }),
  ];
  const usage = { "c-rule": { files: 2, repos: 1 }, "d-rule": { files: 5, repos: 2 } };
  const ids = (v: Partial<typeof DEFAULT_VIEW>) => viewRules(rules, usage, { ...DEFAULT_VIEW, ...v }).map(x => x.id);

  it("relevance: rules firing in your code first (most files first), then the catalog order (data flow, config, pattern; A-Z)", () => {
    expect(ids({})).toEqual(["d-rule", "c-rule", "b-rule", "a-rule"]);
  });
  it("other sorts", () => {
    expect(ids({ sort: "findings" })).toEqual(["d-rule", "c-rule", "a-rule", "b-rule"]);
    expect(ids({ sort: "severity" })).toEqual(["a-rule", "d-rule", "b-rule", "c-rule"]);
    expect(ids({ sort: "name" })).toEqual(["a-rule", "b-rule", "c-rule", "d-rule"]);
  });
  it("filters: detection, severity (incl. varies), applies-to, firing only, search over id/title/CWE/description/languages", () => {
    expect(ids({ detection: "data-flow" })).toEqual(["d-rule", "b-rule"]);
    expect(ids({ severity: "critical" })).toEqual(["a-rule"]);
    expect(ids({ severity: "varies" })).toEqual(["c-rule"]);
    expect(ids({ appliesTo: "Python" })).toEqual(["d-rule", "b-rule"]);
    expect(ids({ appliesTo: "Java" })).toEqual(["d-rule"]);
    expect(ids({ firingOnly: true })).toEqual(["d-rule", "c-rule"]);
    expect(ids({ q: "cwe-284" })).toEqual(["a-rule"]);
    expect(ids({ q: "  JAVA " })).toEqual(["d-rule"]);
    expect(ids({ q: "b-rule desc" })).toEqual(["b-rule"]);
    expect(ids({ detection: "data-flow", firingOnly: true, severity: "low" })).toEqual([]);
  });
  it("appliesToOptions lists every value once, sorted", () => {
    expect(appliesToOptions(rules)).toEqual(["Java", "Python", "Terraform"]);
  });
});
