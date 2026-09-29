import { buildSarifReport } from "@/lib/sarif";
import { FINDING_CATALOG } from "@/lib/findingCatalog";
import { analyzeFile, getFixSuggestions } from "@/lib/scanner";
import { toStoredIndicators } from "@/lib/indicatorStorage";

describe("buildSarifReport", () => {
  it("produces a well-formed SARIF 2.1.0 log", () => {
    const sarif = buildSarifReport([
      {
        file_path: "src/api/query.ts",
        indicators: [
          { id: "sql-injection", label: "SQL Injection", severity: "critical", line: 42, detail: "String-interpolated query" },
        ],
      },
    ]) as { version: string; runs: Array<{ tool: { driver: { rules: unknown[] } }; results: unknown[] }> };

    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs).toHaveLength(1);
    expect(sarif.runs[0].tool.driver.rules).toHaveLength(1);
    expect(sarif.runs[0].results).toHaveLength(1);
  });

  it("maps severity to the correct SARIF level", () => {
    const sarif = buildSarifReport([
      {
        file_path: "a.ts",
        indicators: [
          { id: "sql-injection", label: "x", severity: "critical", line: 1 },
          { id: "xss",           label: "x", severity: "high",     line: 1 },
          { id: "weak-crypto",   label: "x", severity: "medium",   line: 1 },
          { id: "ai-model-attribution", label: "x", severity: "info", line: 1 },
        ],
      },
    ]) as { runs: [{ results: Array<{ ruleId: string; level: string }> }] };

    const byId = Object.fromEntries(sarif.runs[0].results.map(r => [r.ruleId, r.level]));
    expect(byId["sql-injection"]).toBe("error");
    expect(byId["xss"]).toBe("error");
    expect(byId["weak-crypto"]).toBe("warning");
    expect(byId["ai-model-attribution"]).toBe("note");
  });

  it("attaches CWE tags from the shared rule metadata where known", () => {
    const sarif = buildSarifReport([
      { file_path: "a.ts", indicators: [{ id: "hardcoded-secret", label: "x", severity: "critical", line: 3 }] },
    ]) as { runs: [{ tool: { driver: { rules: Array<{ id: string; properties: { cwe?: string } }> } } }] };

    const rule = sarif.runs[0].tool.driver.rules[0];
    expect(rule.id).toBe("hardcoded-secret");
    expect(rule.properties.cwe).toBe(FINDING_CATALOG["hardcoded-secret"].cwe);
  });

  it("deduplicates rules across multiple files with the same finding type", () => {
    const sarif = buildSarifReport([
      { file_path: "a.ts", indicators: [{ id: "xss", label: "x", severity: "high", line: 1 }] },
      { file_path: "b.ts", indicators: [{ id: "xss", label: "x", severity: "high", line: 5 }] },
    ]) as { runs: [{ tool: { driver: { rules: unknown[] } }; results: unknown[] }] };

    expect(sarif.runs[0].tool.driver.rules).toHaveLength(1);
    expect(sarif.runs[0].results).toHaveLength(2);
  });

  it("clamps missing/invalid line numbers to line 1 rather than emitting 0 or undefined", () => {
    const sarif = buildSarifReport([
      { file_path: "a.ts", indicators: [{ id: "xss", label: "x", severity: "high" }] },
    ]) as { runs: [{ results: Array<{ locations: Array<{ physicalLocation: { region: { startLine: number } } }> }> }] };

    expect(sarif.runs[0].results[0].locations[0].physicalLocation.region.startLine).toBe(1);
  });

  it("returns an empty results array for a scan with no findings", () => {
    const sarif = buildSarifReport([{ file_path: "clean.ts", indicators: [] }]) as { runs: [{ results: unknown[] }] };
    expect(sarif.runs[0].results).toHaveLength(0);
  });
});

// The export as it actually runs: real scanner output -> stored projection -> SARIF.
describe("buildSarifReport: unified finding evidence", () => {
  const PATH = "src/routes/users.ts";
  const ROUTE = [
    `function listUsers(req, res) {`,
    `  const name = req.query.name;`,
    `  const sql = "SELECT * FROM users WHERE name = '" + name + "'";`,
    `  db.query(sql);`,
    `}`,
    `app.get("/users", listUsers);`,
    ``,
  ].join("\n");
  type Result = {
    ruleId: string; message: { text: string };
    partialFingerprints?: Record<string, string>;
    codeFlows?: Array<{ threadFlows: Array<{ locations: Array<{ location: { physicalLocation: { region: { startLine: number } }; message: { text: string } } }> }> }>;
    properties: Record<string, unknown>;
  };
  type Log = { runs: [{ tool: { driver: { rules: Array<{ id: string; name: string; help: { text: string; markdown: string } }> } }; results: Result[] }] };

  const indicators = toStoredIndicators(analyzeFile(PATH, ROUTE).indicators);
  const fixes = new Map(getFixSuggestions(indicators).map(f => [f.vuln_id, f]));
  const sarif = buildSarifReport([{ file_path: PATH, indicators }], {}, fixes) as Log;
  const flowResult = sarif.runs[0].results.find(r => r.ruleId === "sql-injection" && r.codeFlows)!;

  it("carries the source -> sink path as codeFlows, source first", () => {
    expect(flowResult).toBeDefined();
    const steps = flowResult.codeFlows![0].threadFlows[0].locations;
    expect(steps[0].location.physicalLocation.region.startLine).toBe(2);
    expect(steps[0].location.message.text).toContain("req.query.name");
    expect(steps[steps.length - 1].location.physicalLocation.region.startLine).toBe(4);
  });

  it("uses the unified explanation as the message, not the engine's internal template", () => {
    expect(flowResult.message.text).toContain("req.query.name");
    expect(flowResult.message.text).toContain("SQL query");
    expect(flowResult.message.text).not.toContain("real data-flow match");
    expect(String(flowResult.properties["trustledger/evidence"])).toContain("Why this was flagged:");
  });

  it("keeps a stable fingerprint so Code Scanning tracks the alert across runs", () => {
    const stored = indicators.find(i => i.id === "sql-injection" && i.sourceExpr)!;
    expect(flowResult.partialFingerprints).toEqual({ "trustledgerFinding/v1": stored.fingerprint });
  });

  it("puts the recommended fix in the rule help", () => {
    const rule = sarif.runs[0].tool.driver.rules.find(r => r.id === "sql-injection")!;
    expect(rule.name).toBe("SQL Injection");
    expect(rule.help.markdown).toContain("Recommended fix");
    expect(rule.help.markdown).toContain(fixes.get("sql-injection")!.code_after!);
  });

  it("the pattern match on the line that builds the query is one result with the flow, as a related location", () => {
    expect(sarif.runs[0].results.filter(r => r.ruleId === "sql-injection")).toHaveLength(1);
    const related = (flowResult as Result & { relatedLocations?: Array<{ physicalLocation: { region: { startLine: number } }; message: { text: string } }> }).relatedLocations;
    expect(related?.map(r => r.physicalLocation.region.startLine)).toEqual([3]);
    expect(related?.[0].message.text).toMatch(/^Same issue: .*data-flow path/);
  });

  it("a pattern-only result gets no codeFlows", () => {
    const path = "src/digest.ts";
    const content = `import crypto from "crypto";\nexport function digest(data: string) {\n  return crypto.createHash("md5").update(data).digest("hex");\n}\n`;
    const log = buildSarifReport([{ file_path: path, indicators: toStoredIndicators(analyzeFile(path, content).indicators) }]) as Log;
    const pattern = log.runs[0].results.find(r => r.ruleId === "weak-crypto");
    expect(pattern).toBeDefined();
    expect(pattern!.codeFlows).toBeUndefined();
    expect(pattern!.properties["trustledger/analysis"]).toBe("Pattern match");
  });
});
