import { buildCallGraph } from "@/lib/callGraph";
import { scoreExploitability } from "@/lib/reachability";
import { parseSourceFile, findNodeAtPosition, findEnclosingFunctionName } from "@/lib/astTaint";
import type { ScanIndicator } from "@/lib/scanner";

// Regression test for a real bug found via direct investigation: scoreExploitability
// used to take a single `containingFunction` string applied to EVERY indicator in
// the file, and its one call site (scanner.ts) never passed it at all -- silently
// defaulting to the literal "unknown" for every finding in every file, forever,
// which made classifyReachability() return "unreachable" unconditionally regardless
// of what the real BFS/taint graph actually computed. The fix changes the signature
// to a per-indicator resolver callback -- this test proves reachability is now
// classified per-line, not once for the whole file.

const FIXTURE = `
export function handleSearch(req) {
  const query = "SELECT * FROM users WHERE id = " + req.id;
  return query;
}

function deadCode(input) {
  document.write(input);
  return input;
}
`;

describe("scoreExploitability -- per-indicator reachability resolution", () => {
  it("classifies a reachable (exported) function's finding differently from an unreachable one's", () => {
    const graph = buildCallGraph(FIXTURE);
    expect(graph.entry_points).toContain("handleSearch");
    expect(graph.entry_points).not.toContain("deadCode");

    const sourceFile = parseSourceFile(FIXTURE, "fixture.ts");
    const resolveContainingFunction = (line: number): string => {
      const pos = sourceFile.getPositionOfLineAndCharacter(Math.max(0, line - 1), 0);
      return findEnclosingFunctionName(findNodeAtPosition(sourceFile, pos));
    };

    const indicators: ScanIndicator[] = [
      { id: "sql-injection", label: "SQL Injection", severity: "critical", line: 3 },  // inside handleSearch
      { id: "xss",           label: "Reflected XSS",  severity: "critical", line: 8 },  // inside deadCode
    ];

    const report = scoreExploitability(indicators, FIXTURE, graph, resolveContainingFunction);
    const sqlScore = report.scores.find(s => s.vuln_id === "sql-injection")!;
    const xssScore = report.scores.find(s => s.vuln_id === "xss")!;

    expect(sqlScore.reachability).toBe("entry-point");
    expect(xssScore.reachability).toBe("unreachable");
    // Different classifications must produce different multipliers -- the
    // actual symptom of the old bug was these always being identical.
    expect(sqlScore.exploitability_score).not.toBe(xssScore.exploitability_score);
  });

  it("falls back to the old 'unreachable for everything' behavior only when no resolver is supplied at all", () => {
    const graph = buildCallGraph(FIXTURE);
    const indicators: ScanIndicator[] = [
      { id: "sql-injection", label: "SQL Injection", severity: "critical", line: 3 },
    ];
    const report = scoreExploitability(indicators, FIXTURE, graph); // no 4th arg
    expect(report.scores[0].reachability).toBe("unreachable");
  });

  it("findEnclosingFunctionName's naming convention matches callGraph.ts's own function-name extraction", () => {
    const graph = buildCallGraph(FIXTURE);
    const sourceFile = parseSourceFile(FIXTURE, "fixture.ts");
    const pos = sourceFile.getPositionOfLineAndCharacter(2, 0); // line 3 (0-based)
    const name = findEnclosingFunctionName(findNodeAtPosition(sourceFile, pos));
    expect(graph.functions.some(f => f.name === name)).toBe(true);
  });
});
