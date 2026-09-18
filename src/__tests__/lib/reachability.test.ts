import { buildCallGraph } from "@/lib/callGraph";
import { scoreExploitability } from "@/lib/reachability";
import { parseSourceFile, findNodeAtPosition, findEnclosingFunctionName } from "@/lib/astTaint";
import { analyzeFile, type ScanIndicator } from "@/lib/scanner";

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

// Regression tests for wiring exploitability into the UI: reachability was
// computed correctly here but silently dropped before it ever reached
// FileAnalysis.indicators (and, from there, persistence/SARIF/the PR page) --
// the same bug class codeCategory/cwe had before being fixed. These prove
// the merge in analyzeFile() actually attaches per-instance reachability to
// the right finding, matched by (id, line) rather than array position or
// vuln_id alone -- required because scoreExploitability() filters out
// AI-signal ids and then sorts its output by exploitability_score before
// returning, so its scores[] has neither the same length nor order as the
// indicators array it was given.
describe("scoreExploitability -- ExploitabilityScore carries line, for unambiguous re-matching", () => {
  it("each score's `line` matches the indicator it was computed from", () => {
    const content = `
export function handleSearch(req) {
  const query = "SELECT * FROM users WHERE id = " + req.id;
  return query;
}
`;
    const graph = buildCallGraph(content);
    const indicators: ScanIndicator[] = [
      { id: "sql-injection", label: "SQL Injection", severity: "critical", line: 3 },
    ];
    const report = scoreExploitability(indicators, content, graph);
    expect(report.scores[0].line).toBe(3);
  });
});

describe("analyzeFile() -- per-instance reachability merged onto the real indicators array", () => {
  it("gives an entry-point-reachable finding a high score and a dead-code finding of the SAME id a low one", () => {
    // handleSearch is exported (a real entry point); deadCode is never
    // called from anywhere in this file -- both fire the same detector
    // class, so this proves matching is per (id, line), not per id.
    const content = `
export function handleSearch(req, res) {
  const query = "SELECT * FROM users WHERE id = " + req.query.id;
  db.query(query);
}

function deadCode(req) {
  const query2 = "SELECT * FROM logs WHERE id = " + req.query.id;
  db.query(query2);
}
`;
    const result = analyzeFile("app.js", content);
    const reachable = result.indicators.find(i => i.id === "sql-injection" && i.line === 4);
    const dead       = result.indicators.find(i => i.id === "sql-injection" && i.line === 9);
    expect(reachable?.reachability).toBe("entry-point");
    expect(dead?.reachability).toBe("unreachable");
    expect((reachable?.exploitability_score ?? 0)).toBeGreaterThan(dead?.exploitability_score ?? 0);
    expect(reachable?.remediation_urgency).toBe("immediate");
  });

  it("leaves AI-signal indicators (never scored) with reachability undefined, not a wrong default", () => {
    const content = `
export function handleSearch(req) {
  const query = "SELECT * FROM users WHERE id = " + req.id;
  return query;
}
`;
    const result = analyzeFile("app.js", content);
    const aiSignal = result.indicators.find(i => i.id === "line-length" || i.id === "naming-consistency");
    if (aiSignal) expect(aiSignal.reachability).toBeUndefined();
  });
});
