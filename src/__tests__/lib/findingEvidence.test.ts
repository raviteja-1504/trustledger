import { analyzeFile } from "@/lib/scanner";
import { warmPythonTaintEngine } from "@/lib/astTaintPython";
import { warmPhpTaintEngine } from "@/lib/astTaintPHP";
import { toStoredIndicators, toStoredIndicator } from "@/lib/indicatorStorage";
import { buildFindingEvidence, classifyInput, type Part } from "@/lib/findingEvidence";
import type { FileIndicator } from "@/types";

// The inline evidence panel on the PR page is built from exactly what the browser receives: scanner output
// passed through toStoredIndicators(). These tests drive the REAL pipeline (analyzeFile -> stored projection
// -> evidence builder) so a field silently dropped at the persistence boundary shows up here.

beforeAll(async () => { await warmPythonTaintEngine(); await warmPhpTaintEngine(); }, 60000);

const text = (parts: Part[]) => parts.map(p => (typeof p === "string" ? p : p.code)).join("");

function storedAll(path: string, content: string): FileIndicator[] {
  return toStoredIndicators(analyzeFile(path, content).indicators);
}
/** The finding the AST engine produced (it carries sourceExpr); pattern detectors may flag nearby lines too. */
function storedFor(path: string, content: string, id: string, dataFlow = true): FileIndicator {
  const found = storedAll(path, content).find(i => i.id === id && !!i.sourceExpr === dataFlow);
  if (!found) throw new Error(`no ${dataFlow ? "data-flow" : "pattern"} ${id} finding produced for ${path}`);
  return found;
}

const SQL_ROUTE = [
  `function listUsers(req, res) {`,
  `  const name = req.query.name;`,
  `  const sql = "SELECT * FROM users WHERE name = '" + name + "'";`,
  `  db.query(sql);`,
  `  res.send("ok");`,
  `}`,
  `app.get("/users", listUsers);`,
  ``,
].join("\n");

describe("data-flow finding (real scanner output)", () => {
  const ind = storedFor("src/routes/users.ts", SQL_ROUTE, "sql-injection");
  const ev = buildFindingEvidence(ind, "src/routes/users.ts");

  it("the stored projection keeps the trace and the enclosing function the UI renders", () => {
    expect(ind.trace?.length).toBeGreaterThan(1);
    expect(ind.functionName).toBe("listUsers");
  });

  it("the path runs from the request input to the sink on the flagged line", () => {
    expect(ev.isDataFlow).toBe(true);
    expect(ev.flow[0].kind).toBe("source");
    expect(ev.flow[0].text).toContain("req.query.name");
    const last = ev.flow[ev.flow.length - 1];
    expect(last.kind).toBe("sink");
    expect(last.line).toBe(ind.line);
    expect(last.text).toContain("db.query");
    expect(ev.flowFromEndpointsOnly).toBe(false);
  });

  it("explains the flow in plain language, naming the input kind and what the sink does", () => {
    const s = text(ev.summary);
    expect(s).toContain("URL query parameter");
    expect(s).toContain("SQL query");
    expect(s).not.toContain("real data-flow match");
  });

  it("states the missing defence only because the AST engine proved taint survived to the sink", () => {
    expect(ev.checks.some(c => c.tone === "absent" && text(c.parts) === "No SQL parameterisation or escaping on this path")).toBe(true);
  });
});

describe("a defence that is present but in the wrong position", () => {
  it("is reported as a caution, not as 'no defence'", () => {
    const content = [
      `app.get("/u", (req, res) => {`,
      `  db.query("SELECT * FROM users WHERE id = " + mysql.escape(req.query.id));`,
      `});`,
      ``,
    ].join("\n");
    const ind = storedFor("src/u.ts", content, "sql-injection");
    const ev = buildFindingEvidence(ind, "src/u.ts");
    expect(ev.checks.some(c => c.tone === "caution" && /defence is applied/.test(text(c.parts)))).toBe(true);
    expect(ev.checks.some(c => c.tone === "absent")).toBe(false);
    // The engine's own specific explanation is shown instead of the generic sentence.
    expect(text(ev.summary)).toMatch(/escap/i);
  });
});

describe("pattern-only finding", () => {
  it("never gets a data-flow path or a 'no defence on this path' claim", () => {
    const content = `import crypto from "crypto";\nexport function digest(data: string) {\n  return crypto.createHash("md5").update(data).digest("hex");\n}\n`;
    const ind = storedFor("src/digest.ts", content, "weak-crypto", false);
    const ev = buildFindingEvidence(ind, "src/digest.ts");
    expect(ev.isDataFlow).toBe(false);
    expect(ev.flow).toEqual([]);
    expect(ev.checks.some(c => c.tone === "absent")).toBe(false);
    expect(ev.checks.some(c => c.tone === "caution" && /Pattern match only/.test(text(c.parts)))).toBe(true);
  });
});

describe("pattern finding on the same flow as a confirmed data-flow finding", () => {
  it("a fresh scan merges the two into the confirmed finding, which says so", () => {
    const all = storedAll("src/routes/users.ts", SQL_ROUTE);
    const sql = all.filter(i => i.cwe === "CWE-89");
    expect(sql).toHaveLength(1);
    expect(sql[0].sourceExpr).toBeDefined();
    const buildLine = SQL_ROUTE.split("\n").findIndex(l => l.includes("SELECT")) + 1;
    expect(sql[0].relatedLocations).toEqual([expect.objectContaining({ line: buildLine, reason: "on-path", detector: "pattern" })]);
    const ev = buildFindingEvidence(sql[0], "src/routes/users.ts", all);
    expect(ev.checks.some(c => new RegExp(`Also reported at line ${buildLine}, on this same data-flow path`).test(text(c.parts)))).toBe(true);
  });

  it("links to the confirmed finding instead of saying no data flow was traced (a scan stored before correlation)", () => {
    const confirmed = storedAll("src/routes/users.ts", SQL_ROUTE).find(i => i.id === "sql-injection" && !!i.sourceExpr)!;
    // Scans stored before findingCorrelation.ts still hold the pattern finding as its own row.
    const buildLine = confirmed.relatedLocations![0].line;
    const pattern = { id: "sql-injection", label: "SQL Injection", severity: "critical", line: buildLine, detail: "pattern", cwe: "CWE-89" } as FileIndicator;
    const all = [pattern, { ...confirmed, relatedLocations: undefined }];
    expect(pattern.line).not.toBe(confirmed.line);
    const ev = buildFindingEvidence(pattern, "src/routes/users.ts", all);
    expect(ev.onPathOf?.line).toBe(confirmed.line);
    expect(ev.checks.some(c => /Pattern match only/.test(text(c.parts)))).toBe(false);
    expect(ev.checks.some(c => c.tone === "confirmed" && /on the confirmed data-flow path of the finding at line/.test(text(c.parts)))).toBe(true);
  });
});

describe("traces start at the real request input, not at the expression built from it", () => {
  const originOf = (path: string, content: string) => {
    const ev = buildFindingEvidence(storedFor(path, content, "sql-injection"), path);
    return ev.flow[0];
  };
  it("Python: concatenation", () => {
    const o = originOf("app/views.py", [
      "def search(request):",
      "    name = request.GET.get(\"name\")",
      "    sql = \"SELECT * FROM users WHERE name = '\" + name + \"'\"",
      "    cursor.execute(sql)", ""].join("\n"));
    expect(o.kind).toBe("source");
    expect(o.text).toBe("request.GET.get(\"name\")");
    expect(o.line).toBe(2);
  });
  it("Python: f-string", () => {
    const o = originOf("app/v2.py", [
      "def search(request):",
      "    q = f\"SELECT * FROM t WHERE id = {request.args.get('id')}\"",
      "    cursor.execute(q)", ""].join("\n"));
    expect(o.text).toBe("request.args.get('id')");
  });
  it("PHP: top-level script", () => {
    const o = originOf("index.php", [
      "<?php",
      "$id = $_GET['id'];",
      "$sql = \"SELECT * FROM users WHERE id = \" . $id;",
      "mysqli_query($conn, $sql);", ""].join("\n"));
    expect(o.text).toBe("$_GET['id']");
    expect(o.line).toBe(2);
  });
  it("JS: template literal with a method call on the input", () => {
    const o = originOf("src/t.ts", [
      "app.get(\"/t\", (req, res) => {",
      "  const q = `SELECT * FROM t WHERE id = ${req.params.id.trim()}`;",
      "  db.query(q);",
      "});", ""].join("\n"));
    expect(o.text).toBe("req.params.id");
  });
});

describe("builder details", () => {
  const base: FileIndicator = { id: "xss", label: "Reflected XSS", severity: "critical", line: 9 };

  it("assembles an endpoints-only path when the trace is missing but source/sink are known", () => {
    const ev = buildFindingEvidence({ ...base, sourceExpr: "req.body.bio", sinkExpr: "res.send" }, "a.ts");
    expect(ev.flowFromEndpointsOnly).toBe(true);
    expect(ev.flow.map(s => s.kind)).toEqual(["source", "sink"]);
    expect(ev.flow[1].line).toBe(9);
    expect(ev.inputKind).toBe("request body");
  });

  it("marks steps from another file and turns bracketed engine notes into checks", () => {
    const ev = buildFindingEvidence({
      ...base, id: "sql-injection", sourceExpr: "id", sinkExpr: "runQuery",
      detail: `Tainted expression 'id' is passed to runQuery(...), which reaches db.execute(...) at src/db.ts:3 [crosses file boundary via "runQuery" imported from ./db] — real data-flow match across files, not a line-pattern guess`,
      trace: [
        { file: "a.ts", line: 4, kind: "source", label: "req.query.id", snippet: "req.query.id" },
        { file: "src/db.ts", line: 3, kind: "sink", label: "db.execute", snippet: "db.execute(sql)" },
      ],
    }, "a.ts");
    expect(ev.flow[0].otherFile).toBeUndefined();
    expect(ev.flow[1].otherFile).toBe("src/db.ts");
    expect(text(ev.summary)).not.toContain("[crosses");
    expect(ev.checks.some(c => c.tone === "confirmed" && /^Crosses file boundary via/.test(text(c.parts)))).toBe(true);
  });

  it("reports supporting detectors and unreachable code honestly", () => {
    const ev = buildFindingEvidence({ ...base, supportingDetectors: ["Named-taint XSS"], reachability: "unreachable" }, "a.ts");
    expect(ev.checks.some(c => /Independently flagged by 1 other detector: Named-taint XSS/.test(text(c.parts)))).toBe(true);
    expect(ev.checks.some(c => c.tone === "caution" && /possibly dead code/.test(text(c.parts)))).toBe(true);
  });

  it("classifies common request inputs across frameworks", () => {
    expect(classifyInput("req.params.id")).toBe("URL path parameter");
    expect(classifyInput("request.GET.get('q')")).toBe("URL query parameter");
    expect(classifyInput("$_POST['name']")).toBe("request body");
    expect(classifyInput("req.headers['x-forwarded-for']")).toBe("HTTP header");
    expect(classifyInput("req.cookies.token")).toBe("cookie");
    expect(classifyInput("someLocal")).toBeUndefined();
  });
});

describe("stored trace cap", () => {
  it("keeps the sink step when a long trace is truncated", () => {
    const steps = Array.from({ length: 20 }, (_, i) => ({ file: "a.ts", line: i + 1, kind: "assignment" as const, label: `v${i}`, snippet: `v${i}` }));
    steps.push({ file: "a.ts", line: 99, kind: "sink" as unknown as "assignment", label: "exec", snippet: "exec(v19)" });
    const stored = toStoredIndicator({ id: "command-injection", label: "x", severity: "critical", line: 99, trace: steps as never });
    expect(stored.trace).toHaveLength(12);
    expect(stored.trace![11].line).toBe(99);
  });
});
