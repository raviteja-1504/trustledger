import { correlateFindings } from "@/lib/findingCorrelation";
import { analyzeFile, type ScanIndicator } from "@/lib/scanner";
import { toStoredIndicators } from "@/lib/indicatorStorage";
import { buildSarifReport } from "@/lib/sarif";
import { warmPhpTaintEngine } from "@/lib/astTaintPHP";
import { warmPythonTaintEngine } from "@/lib/astTaintPython";

beforeAll(async () => { await warmPhpTaintEngine(); await warmPythonTaintEngine(); }, 120000);

const ind = (o: Partial<ScanIndicator> & { id: string; line: number }): ScanIndicator =>
  ({ label: o.id, severity: "high", detail: "", cwe: "CWE-89", ...o } as ScanIndicator);
const step = (line: number, kind: "source" | "assignment" | "sink" = "assignment") => ({ file: "a.php", line, kind, label: "", snippet: "" });

describe("correlateFindings", () => {
  it("merges the same CWE on the same line into the stronger finding", () => {
    const out = correlateFindings([
      ind({ id: "idor", label: "IDOR", line: 18, cwe: "CWE-639", severity: "medium", confidence: 70 }),
      ind({ id: "bola-missing-ownership-check", label: "BOLA", line: 18, cwe: "CWE-639", severity: "high", confidence: 95, sourceExpr: "req.params.id" }),
    ], "a.ts");
    expect(out.map(i => i.id)).toEqual(["bola-missing-ownership-check"]);
    expect(out[0].relatedLocations).toEqual([{ line: 18, id: "idor", label: "IDOR", detector: "pattern", reason: "same-line" }]);
    expect(out[0].supportingDetectors).toEqual(["IDOR"]);
  });

  it("merges a finding on another's data-flow path into the downstream one", () => {
    const sink = ind({ id: "sql-injection", line: 13, sourceExpr: "$_GET['id']", severity: "high", trace: [step(10, "source"), step(11), step(13, "sink")] });
    const build = ind({ id: "sql-injection", label: "SQL built by concatenation", line: 11, severity: "critical" });
    const out = correlateFindings([build, sink], "a.php");
    expect(out).toEqual([sink]);
    expect(sink.relatedLocations).toEqual([{ line: 11, id: "sql-injection", label: "SQL built by concatenation", detector: "pattern", reason: "on-path" }]);
  });

  it("severity: a pattern match never overrules the data-flow engine's grading, equal evidence takes the higher", () => {
    // BOLA on a read-only GET is deliberately MEDIUM; the regex IDOR rule's fixed HIGH must not undo that
    const bola = ind({ id: "bola-missing-ownership-check", line: 2, cwe: "CWE-639", severity: "medium", sourceExpr: "req.params.id" });
    correlateFindings([bola, ind({ id: "idor", line: 2, cwe: "CWE-639", severity: "high" })], "a.ts");
    expect(bola.severity).toBe("medium");
    const flow = ind({ id: "sql-injection", line: 9, severity: "high", sourceExpr: "x", trace: [step(8, "source"), step(9, "sink")] });
    const shape = ind({ id: "sql-injection", line: 8, severity: "critical", sourceExpr: "x" });
    correlateFindings([flow, shape], "a.php");
    expect(flow.severity).toBe("critical");
  });

  it("resolves a chain to the most downstream finding", () => {
    const join = ind({ id: "path-traversal", line: 5, cwe: "CWE-22", sourceExpr: "x", trace: [step(4, "source"), step(5, "sink")] });
    const file = ind({ id: "path-traversal", line: 6, cwe: "CWE-22", sourceExpr: "x", trace: [step(4, "source"), step(5), step(6, "sink")] });
    const open = ind({ id: "path-traversal", line: 8, cwe: "CWE-22", sourceExpr: "x", trace: [step(4, "source"), step(5), step(6), step(8, "sink")] });
    const out = correlateFindings([join, file, open], "a.php");
    expect(out).toEqual([open]);
    expect(open.relatedLocations?.map(r => r.line)).toEqual([5, 6]);
  });

  it("a chain whose first link is only on the middle finding's path still ends in the last one", () => {
    const concat = ind({ id: "sql-injection", line: 5 });
    const shape = ind({ id: "sql-injection", line: 6, sourceExpr: "x", trace: [step(4, "source"), step(5), step(6, "sink")] });
    const exec = ind({ id: "sql-injection", line: 8, sourceExpr: "x", trace: [step(4, "source"), step(6), step(7), step(8, "sink")] });
    expect(correlateFindings([concat, shape, exec], "a.php")).toEqual([exec]);
    expect(exec.relatedLocations?.map(r => r.line)).toEqual([5, 6]);
  });

  it("resolves a chain whose lines run out of order (the path passes through a helper defined above)", () => {
    const helper = ind({ id: "sql-injection", line: 9 });                                                     // on shape's path only
    const shape = ind({ id: "sql-injection", line: 6, sourceExpr: "x", trace: [step(4, "source"), step(9), step(6, "sink")] });
    const exec = ind({ id: "sql-injection", line: 8, sourceExpr: "x", trace: [step(4, "source"), step(6), step(7), step(8, "sink")] });
    expect(correlateFindings([helper, shape, exec], "a.php")).toEqual([exec]);
    expect(exec.relatedLocations?.map(r => r.line)).toEqual([6, 9]);
  });

  it("a finding of another weakness on the path is a different issue", () => {
    const sql = ind({ id: "sql-injection", line: 13, sourceExpr: "x", trace: [step(10, "source"), step(11), step(13, "sink")] });
    const path = ind({ id: "path-traversal", line: 11, cwe: "CWE-22" });
    expect(correlateFindings([sql, path], "a.php")).toHaveLength(2);
  });

  it("leaves distinct issues alone: another CWE, another file's trace step, a source-only step, the same function", () => {
    const sink = ind({ id: "sql-injection", line: 13, sourceExpr: "x", trace: [step(10, "source"), { ...step(11), file: "other.php" }, step(13, "sink")] });
    const xss = ind({ id: "xss", line: 13, cwe: "CWE-79" });                       // same line, other CWE
    const otherFile = ind({ id: "sql-injection", line: 11 });                        // step 11 is in another file
    const unrelated = ind({ id: "sql-injection", line: 20, functionName: "f" });     // same CWE, not on the path
    const out = correlateFindings([sink, xss, otherFile, unrelated], "a.php");
    expect(out).toHaveLength(4);
    expect(sink.relatedLocations).toBeUndefined();
  });

  it("does not merge two findings that are each on the other's path (ambiguous)", () => {
    const a = ind({ id: "sql-injection", line: 5, sourceExpr: "x", trace: [step(3, "source"), step(7), step(5, "sink")] });
    const b = ind({ id: "sql-injection", line: 7, sourceExpr: "x", trace: [step(3, "source"), step(5), step(7, "sink")] });
    expect(correlateFindings([a, b], "a.php")).toHaveLength(2);
  });
});

describe("the full scanner reports one issue once", () => {
  const sqlFindings = (path: string, src: string) =>
    analyzeFile(path, src).indicators.filter(i => i.cwe === "CWE-89");

  it("PHP: the line that builds the query and the line that runs it (DVWA's shape)", () => {
    const src = `<?php\nif (isset($_GET['Submit'])) {\n  $id = $_GET['id'];\n  $query = "SELECT first_name FROM users WHERE user_id = '$id';";\n  $result = mysqli_query($GLOBALS["___mysqli_ston"], $query);\n}\n`;
    const found = sqlFindings("low.php", src);
    expect(found).toHaveLength(1);
    expect(found[0].line).toBe(5);
    expect(found[0].relatedLocations?.map(r => r.line)).toEqual([4]);
  });

  it("Python: a query built on one line and executed on another (PyGoat's shape)", () => {
    const src = `from django.db import connection\ndef v(request):\n    name = request.POST.get("name")\n    sql = "SELECT * FROM users WHERE name = '" + name + "'"\n    with connection.cursor() as c:\n        c.execute(sql)\n`;
    const found = sqlFindings("views.py", src);
    expect(found).toHaveLength(1);
    expect(found[0].line).toBe(6);
    expect(found[0].relatedLocations?.map(r => r.line)).toEqual([4]);
  });

  it("the merged location reaches storage and SARIF", () => {
    const src = `<?php\n$id = $_GET['id'];\n$query = "SELECT * FROM users WHERE user_id = '$id';";\nmysqli_query($conn, $query);\n`;
    const a = analyzeFile("low.php", src);
    const stored = toStoredIndicators(a.indicators).filter(i => i.cwe === "CWE-89");
    expect(stored).toHaveLength(1);
    expect(stored[0].relatedLocations?.[0]).toMatchObject({ line: 3, reason: "on-path" });
    const sarif = buildSarifReport([{ file_path: "low.php", indicators: stored }] as never) as { runs: Array<{ results: Array<{ relatedLocations?: Array<{ physicalLocation: { region: { startLine: number } } }> }> }> };
    const withRelated = sarif.runs[0].results.filter(r => r.relatedLocations?.length);
    expect(withRelated).toHaveLength(1);
    expect(withRelated[0].relatedLocations![0].physicalLocation.region.startLine).toBe(3);
  });
});
