import { buildSarifReport, SARIF_RULE_META } from "@/lib/sarif";

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
    expect(rule.properties.cwe).toBe(SARIF_RULE_META["hardcoded-secret"].cwe);
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
