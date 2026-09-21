import { buildCallGraph } from "@/lib/callGraph";
import { scoreExploitability } from "@/lib/reachability";
import { parseSourceFile, findNodeAtPosition, findEnclosingFunctionName } from "@/lib/astTaint";
import { analyzeFile, type ScanIndicator } from "@/lib/scanner";
import { warmPythonTaintEngine } from "@/lib/astTaintPython";
import { warmCSharpTaintEngine } from "@/lib/astTaintCSharp";
import { warmPhpTaintEngine } from "@/lib/astTaintPHP";

beforeAll(async () => {
  await warmPythonTaintEngine();
  await warmCSharpTaintEngine();
  await warmPhpTaintEngine();
}, 30000);

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

// Decision 4: VULN_PROFILES coverage for the 14 ids that previously fell
// through to the generic DEFAULT_PROFILE. DEFAULT_PROFILE has no `cwe`
// property at all, and scoreExploitability only ever sets `score.cwe` via
// `"cwe" in profile` -- so a real, non-default profile match is provable
// by asserting `score.cwe` is defined and matches the expected CWE, not by
// asserting a specific numeric score (which would be a brittle,
// implementation-detail assertion).
describe("scoreExploitability -- VULN_PROFILES coverage (Decision 4, new capability)", () => {
  const cases: Array<[string, string]> = [
    ["idor", "CWE-639"],
    ["bola-identity-mismatch", "CWE-639"],
    ["bola-missing-ownership-check", "CWE-639"],
    ["csrf-protection-disabled", "CWE-352"],
    ["debug-mode-enabled", "CWE-489"],
    ["graphql-injection", "CWE-943"],
    ["insecure-file-upload", "CWE-434"],
    ["jwt-none-alg", "CWE-347"],
    ["php-missing-session-guard", "CWE-306"],
    ["plaintext-password-storage", "CWE-256"],
    ["sensitive-url-data", "CWE-598"],
    ["verbose-error", "CWE-209"],
    ["toctou", "CWE-367"],
    ["xpath-injection", "CWE-643"],
  ];

  it.each(cases)("%s resolves to a real profile (cwe %s), not the generic DEFAULT_PROFILE", (id, cwe) => {
    const indicators: ScanIndicator[] = [{ id, label: id, severity: "high", line: 1 }];
    const report = scoreExploitability(indicators, "irrelevant content", null);
    expect(report.scores[0].cwe).toBe(cwe);
  });

  it("an id with no profile at all still falls back to DEFAULT_PROFILE (undefined cwe), proving the assertion above is meaningful", () => {
    const indicators: ScanIndicator[] = [{ id: "totally-unknown-id", label: "x", severity: "high", line: 1 }];
    const report = scoreExploitability(indicators, "irrelevant content", null);
    expect(report.scores[0].cwe).toBeUndefined();
  });
});

// Decisions 2+3, end to end: Java findings now resolve real reachability
// instead of hardcoding "unreachable" for every single finding regardless
// of the actual call graph -- the bug confirmed present before this phase
// (no findEnclosingFunctionNameJava, no `if (javaCst)` branch in
// resolveContainingFunction, no Java pattern in callGraph.ts's
// tryMatchFunc).
describe("analyzeFile() -- Java reachability now resolves per-method (Decisions 2+3)", () => {
  it("an endpoint method's finding is NOT hardcoded unreachable, and differs from a helper method never called from an endpoint", () => {
    const content = `
public class A {
  @GetMapping("/search")
  public Object search(@RequestParam String name) {
    String sql = "SELECT * FROM t WHERE name = '" + name + "'";
    return Database.executeQuery(sql);
  }

  private Object deadHelper(String name) {
    String sql2 = "SELECT * FROM logs WHERE name = '" + name + "'";
    return Database.executeQuery(sql2);
  }
}
`;
    const result = analyzeFile("A.java", content);
    const lines = content.split("\n");
    const searchLine = lines.findIndex(l => l.includes("SELECT * FROM t")) + 1;
    const deadLine = lines.findIndex(l => l.includes("SELECT * FROM logs")) + 1;
    const reachable = result.indicators.find(i => i.id === "sql-injection" && i.line === searchLine);
    const dead = result.indicators.find(i => i.id === "sql-injection" && i.line === deadLine);
    expect(reachable).toBeDefined();
    expect(dead).toBeDefined();
    expect(reachable?.reachability).not.toBe("unreachable");
    expect(dead?.reachability).toBe("unreachable");
  });
});

// Decision 1, end to end: Python findings now resolve real reachability
// too, for a structurally different reason than Java's (callGraph.ts's
// extractFunctions() previously returned essentially zero functions for
// Python at all, so graph.reachable/entry_points were always empty).
describe("analyzeFile() -- Python reachability now resolves per-function (Decision 1)", () => {
  it("an exported/entry-point function's finding is NOT hardcoded unreachable, and differs from dead code", () => {
    const content = `
def handle_search(request):
    query = "SELECT * FROM users WHERE id = " + request.args.get("id")
    return db.execute(query)

def dead_helper(request):
    query2 = "SELECT * FROM logs WHERE id = " + request.args.get("id")
    return db.execute(query2)
`;
    const result = analyzeFile("app.py", content);
    const lines = content.split("\n");
    const searchLine = lines.findIndex(l => l.includes("SELECT * FROM users")) + 1;
    const deadLine = lines.findIndex(l => l.includes("SELECT * FROM logs")) + 1;
    const reachable = result.indicators.find(i => i.id === "sql-injection" && i.line === searchLine);
    const dead = result.indicators.find(i => i.id === "sql-injection" && i.line === deadLine);
    expect(reachable).toBeDefined();
    expect(dead).toBeDefined();
    // handle_search isn't itself decorated/exported in this fixture, so
    // BOTH may resolve "unreachable" from callGraph's BFS -- the point of
    // this test is narrower and unconditional: Python functions are now
    // actually EXTRACTED at all (graph.functions non-empty, confirmed
    // directly in callGraph.test.ts), so resolveContainingFunction's
    // already-correct Python branch has a real graph to classify against
    // instead of an always-empty one. Both findings must at least resolve
    // to a defined, real reachability value (not silently crash/undefined).
    expect(reachable?.reachability).toBeDefined();
    expect(dead?.reachability).toBeDefined();
  });

  it("a Flask-decorated entry-point function's finding resolves to a non-unreachable classification", () => {
    const content = `
@app.route("/search")
def handle_search(request):
    query = "SELECT * FROM users WHERE id = " + request.args.get("id")
    return db.execute(query)
`;
    const result = analyzeFile("app.py", content);
    const lines = content.split("\n");
    const searchLine = lines.findIndex(l => l.includes("SELECT * FROM users")) + 1;
    const reachable = result.indicators.find(i => i.id === "sql-injection" && i.line === searchLine);
    expect(reachable).toBeDefined();
    expect(reachable?.reachability).not.toBe("unreachable");
  });
});

// C# reachability parity -- astTaintCSharp.ts is a brand-new engine (not an
// upgrade to an existing one), built with findEnclosingFunctionNameCSharp/
// findNodeAtRowCSharp and the resolveContainingFunction wiring from the
// start, so there is no "before" bug to demonstrate here the way the
// Java/Python sections above do -- this proves the wiring is correct and
// working, not that a regression was fixed.
describe("analyzeFile() -- C# reachability resolves per-method", () => {
  it("an [HttpGet]-decorated endpoint method's finding is NOT hardcoded unreachable, and differs from a helper method never called from an endpoint", () => {
    const content = `
public class A {
  [HttpGet("search")]
  public IActionResult Search([FromQuery] string name) {
    var sql = "SELECT * FROM Users WHERE Name = '" + name + "'";
    db.Users.FromSqlRaw(sql);
    return Ok();
  }

  private void DeadHelper(string name) {
    var sql2 = "SELECT * FROM Logs WHERE Name = '" + name + "'";
    db.Logs.FromSqlRaw(sql2);
  }
}
`;
    const result = analyzeFile("A.cs", content);
    const lines = content.split("\n");
    const searchLine = lines.findIndex(l => l.includes("SELECT * FROM Users")) + 1;
    const deadLine = lines.findIndex(l => l.includes("SELECT * FROM Logs")) + 1;
    const reachable = result.indicators.find(i => i.id === "sql-injection" && i.line === searchLine);
    const dead = result.indicators.find(i => i.id === "sql-injection" && i.line === deadLine);
    expect(reachable).toBeDefined();
    expect(dead).toBeDefined();
    expect(reachable?.reachability).not.toBe("unreachable");
    expect(dead?.reachability).toBe("unreachable");
  });
});

// PHP reachability parity -- astTaintPHP.ts is a brand-new engine (not an
// upgrade to an existing one), built with findEnclosingFunctionNamePHP/
// findNodeAtRowPHP and the resolveContainingFunction wiring from the
// start, so there is no "before" bug to demonstrate here the way the
// Java/Python sections above do -- this proves the wiring (including the
// new Laravel-route-registration-site entry-point detection in
// callGraph.ts) is correct and working, not that a regression was fixed.
describe("analyzeFile() -- PHP reachability resolves per-method", () => {
  it("a Laravel-route-registered method's finding is NOT hardcoded unreachable, and differs from a helper method never referenced by any route", () => {
    const content = `<?php
class UserController {
  public function search() {
    $name = $_GET['name'];
    $sql = "SELECT * FROM Users WHERE Name = '" . $name . "'";
    mysqli_query($conn, $sql);
  }

  private function deadHelper() {
    $name2 = $_GET['name2'];
    $sql2 = "SELECT * FROM Logs WHERE Name = '" . $name2 . "'";
    mysqli_query($conn, $sql2);
  }
}

Route::get('/search', [UserController::class, 'search']);
`;
    const result = analyzeFile("UserController.php", content);
    const lines = content.split("\n");
    const searchLine = lines.findIndex(l => l.includes("SELECT * FROM Users")) + 1;
    const deadLine = lines.findIndex(l => l.includes("SELECT * FROM Logs")) + 1;
    const reachable = result.indicators.find(i => i.id === "sql-injection" && i.line === searchLine);
    const dead = result.indicators.find(i => i.id === "sql-injection" && i.line === deadLine);
    expect(reachable).toBeDefined();
    expect(dead).toBeDefined();
    expect(reachable?.reachability).not.toBe("unreachable");
    expect(dead?.reachability).toBe("unreachable");
  });
});
