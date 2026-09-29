import { runScan, type ScanIndicator } from "@/lib/scanner";
import { scanAstTaint } from "@/lib/astTaint";
import { scanAstTaintPython, warmPythonTaintEngine } from "@/lib/astTaintPython";
import { scanAstTaintJava, parseJavaSource } from "@/lib/astTaintJava";
import { scanAstTaintCSharp, parseCSharpSourceSync, warmCSharpTaintEngine } from "@/lib/astTaintCSharp";
import { scanAstTaintPHP, parsePhpSourceSync, warmPhpTaintEngine } from "@/lib/astTaintPHP";
import { buildFindingEvidence } from "@/lib/findingEvidence";
import { toStoredIndicators } from "@/lib/indicatorStorage";
import { crossFileMarks } from "@/lib/dataFlowEvidence";
import { filesWithCrossFileContext } from "@/lib/findingCorrelation";
import { buildSarifReport } from "@/lib/sarif";

beforeAll(async () => { await warmPythonTaintEngine(); await warmCSharpTaintEngine(); await warmPhpTaintEngine(); }, 120000);

type F = { path: string; content: string };
const scan = (files: F[]) => runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files });
const checksOf = (ind: ScanIndicator, path: string) =>
  buildFindingEvidence(toStoredIndicators([ind])[0], path).checks.map(c => c.parts.map(p => (typeof p === "string" ? p : p.code)).join(""));

describe("fixed point: helper chains of any depth are followed", () => {
  it("an 8-level chain, same file (JS, Python)", () => {
    const js = `${Array.from({ length: 8 }, (_, i) => `function l${i}(x) { return ${i === 7 ? "x" : `l${i + 1}(x)`}; }`).join("\n")}\napp.get("/a", (req, res) => { cp.exec(l0(req.query.c)); });\n`;
    expect(scanAstTaint(js, "a.js").some(f => f.id === "command-injection")).toBe(true);
    const py = `${Array.from({ length: 8 }, (_, i) => `def l${i}(x):\n    return ${i === 7 ? "x" : `l${i + 1}(x)`}\n`).join("\n")}\ndef v():\n    os.system(l0(request.args.get("c")))\n`;
    expect(scanAstTaintPython(py, "a.py").some(f => f.id === "command-injection")).toBe(true);
  });

  it("a chain of 5 files, route -> f1 -> f2 -> f3 -> f4 (sink)", () => {
    const files: F[] = [{ path: "src/f4.ts", content: `export function f4(x) { return db.query("SELECT * FROM t WHERE id = " + x); }\n` }];
    for (let i = 3; i >= 1; i--) files.push({ path: `src/f${i}.ts`, content: `import { f${i + 1} } from "./f${i + 1}";\nexport function f${i}(x) { return f${i + 1}(x); }\n` });
    files.push({ path: "src/r.ts", content: `import { f1 } from "./f1";\napp.get("/u", (req, res) => { f1(req.query.id); });\n` });
    const r = scan(files);
    const f = r.files.find(x => x.file_path === "src/r.ts")!.indicators.find(i => i.id === "sql-injection" && i.sourceExpr)!;
    expect(f.flow?.files).toEqual(["src/r.ts", "src/f1.ts", "src/f2.ts", "src/f3.ts", "src/f4.ts"]);
  });
});

describe("exact sink modeling", () => {
  const javaIds = (body: string) => {
    const src = `@RestController public class C {\n  @GetMapping("/x") public void a(@RequestParam String x) throws Exception {\n    ${body}\n  }\n}\n`;
    return scanAstTaintJava(src, "C.java", parseJavaSource(src)!).map(f => f.id);
  };
  it("LDAP: the filter, not the bound filter arguments; XPath: the expression, not the context node", () => {
    expect(javaIds(`ctx.search("ou=people", "(uid={0})", new Object[] { x }, controls);`)).not.toContain("ldap-injection");
    expect(javaIds(`ctx.search("ou=people", "(uid=" + x + ")", controls);`)).toContain("ldap-injection");
    expect(javaIds(`ctx.search("ou=" + x, "(uid=admin)", controls);`)).not.toContain("ldap-injection");
    expect(javaIds(`xpath.evaluate("//user[@id='1']", doc(x));`)).not.toContain("xpath-injection");
    expect(javaIds(`xpath.evaluate("//user[@id='" + x + "']", doc);`)).toContain("xpath-injection");
  });
  it("C# XPath and PHP NoSQL options; Python exec/spawn program and LDAP filter", () => {
    const cs = (b: string) => { const s = `[ApiController] public class C : ControllerBase {\n  [HttpGet] public IActionResult A([FromQuery] string x) {\n    ${b}\n    return Ok();\n  }\n}\n`; return scanAstTaintCSharp(s, "C.cs", parseCSharpSourceSync(s, "C.cs")!).map(f => f.id); };
    expect(cs(`doc.SelectNodes("//user", Ns(x));`)).not.toContain("xpath-injection");
    expect(cs(`doc.SelectNodes("//user[@name='" + x + "']");`)).toContain("xpath-injection");
    const php = (b: string) => { const s = `<?php\n$x = $_GET['x'];\n${b}\n`; return scanAstTaintPHP(s, "a.php", parsePhpSourceSync(s, "a.php")!).map(f => f.id); };
    expect(php(`$users->find(['active' => true], ['limit' => $x]);`)).not.toContain("nosql-injection");
    expect(php(`$users->find($x);`)).toContain("nosql-injection");
    const py = (b: string) => scanAstTaintPython(`import os, ldap\nfrom flask import request\n@app.route("/x")\ndef v():\n    x = request.args.get("x")\n    ${b}\n`, "v.py").map(f => f.id);
    expect(py(`os.execvp("git", ["git", "log", x])`)).not.toContain("command-injection");
    expect(py(`os.execvp(x, ["--version"])`)).toContain("command-injection");
    expect(py(`os.spawnl(os.P_WAIT, "/usr/bin/git", "git", x)`)).not.toContain("command-injection");
    expect(py(`conn.search_s("dc=" + x, ldap.SCOPE_SUBTREE, "(uid=admin)")`)).not.toContain("ldap-injection");
    expect(py(`conn.search_s("dc=x", ldap.SCOPE_SUBTREE, "(uid=" + x + ")")`)).toContain("ldap-injection");
  });
  it("the evidence names the argument the value reached", () => {
    const r = scan([{ path: "a.js", content: `app.get("/u", (req, res) => { db.query("SELECT * FROM u WHERE id = " + req.query.id); });\n` }]);
    const f = r.files[0].indicators.find(i => i.id === "sql-injection" && i.sourceExpr)!;
    expect(f.flow?.sink.role).toBe("the SQL query text");
    expect(checksOf(f, "a.js").some(c => /as the SQL query text/.test(c))).toBe(true);
  });
});

describe("sanitizer evidence", () => {
  it("a sanitiser of the wrong class is shown on the path, with what it does and doesn't protect", () => {
    const src = `<?php\n$name = $_GET['name'];\n$clean = htmlspecialchars($name);\nmysqli_query($c, "SELECT * FROM u WHERE name = '" . $clean . "'");\n`;
    const r = scan([{ path: "a.php", content: src }]);
    const f = r.files[0].indicators.find(i => i.id === "sql-injection" && i.sourceExpr)!;
    expect(f.flow?.sanitizers).toEqual([{ file: "a.php", line: 3, call: "htmlspecialchars", neutralises: ["HTML output"], protectsSink: false }]);
    expect(f.trace!.find(s => s.line === 3)?.kind).toBe("sanitizer");
    expect(checksOf(f, "a.php")).toContain("htmlspecialchars() (line 3) neutralises HTML output — not the SQL query text");
  });

  it("a sanitiser of the right class that still doesn't protect this position says so", () => {
    const src = `<?php\n$id = mysqli_real_escape_string($c, $_GET['id']);\nmysqli_query($c, "SELECT * FROM u WHERE id = " . $id);\n`;
    const r = scan([{ path: "a.php", content: src }]);
    const f = r.files[0].indicators.find(i => i.id === "sql-injection" && i.sourceExpr)!;
    expect(f.flow?.sanitizers[0]).toMatchObject({ call: "mysqli_real_escape_string", protectsSink: true });
    const checks = checksOf(f, "a.php");
    expect(checks.some(c => /mysqli_real_escape_string\(\).*neutralises SQL string contents, but the value is used where that escaping does not apply/.test(c))).toBe(true);
    expect(checks).toContain("A defence is applied, but not one that protects this position (see explanation)");
  });

  it("SARIF carries the sanitisers and the canonical sink identity", () => {
    const src = `<?php\n$name = $_GET['name'];\n$clean = htmlspecialchars($name);\nmysqli_query($c, "SELECT * FROM u WHERE name = '" . $clean . "'");\n`;
    const r = scan([{ path: "a.php", content: src }]);
    const log = buildSarifReport([{ file_path: "a.php", indicators: toStoredIndicators(r.files[0].indicators) }]) as { runs: Array<{ results: Array<{ ruleId: string; properties: Record<string, unknown> }> }> };
    const res = log.runs[0].results.find(x => x.ruleId === "sql-injection")!;
    expect(res.properties["trustledger/sinkKey"]).toBe("a.php:4:CWE-89");
    expect(res.properties["trustledger/sinkArgument"]).toBe("the SQL query text");
    expect(res.properties["trustledger/sanitizers"]).toEqual(["htmlspecialchars (HTML output) — does not protect this sink"]);
  });
});

describe("canonical data-flow evidence", () => {
  const files: F[] = [
    { path: "src/routes/users.ts", content: `import { userService } from "../services/userService";\napp.get("/users", (req, res) => {\n  const id = req.query.id;\n  res.json(userService.find(id));\n});\n` },
    { path: "src/services/userService.ts", content: `import { repo } from "../db/userRepo";\nexport class UserService {\n  find(id) {\n    return repo.byId(id.trim());\n  }\n}\nexport const userService = new UserService();\n` },
    { path: "src/db/userRepo.ts", content: `export class UserRepo {\n  byId(id) {\n    const sql = "SELECT * FROM users WHERE id = '" + id + "'";\n    return db.query(sql);\n  }\n}\nexport const repo = new UserRepo();\n` },
  ];

  it("one object: source (observed), exact sink, files crossed, canonical sink key", () => {
    const f = scan(files).files.find(x => x.file_path === "src/routes/users.ts")!.indicators.find(i => i.id === "sql-injection" && i.sourceExpr)!;
    expect(f.flow).toMatchObject({
      source: { file: "src/routes/users.ts", line: 3, expr: "req.query.id", inputKind: "URL query parameter", assumed: false },
      sink: { file: "src/db/userRepo.ts", line: 4, expr: "db.query", role: "the SQL query text", cwe: "CWE-89" },
      files: ["src/routes/users.ts", "src/services/userService.ts", "src/db/userRepo.ts"],
      crossesFiles: true,
      sinkKey: "src/db/userRepo.ts:4:CWE-89",
    });
  });

  it("a flow that starts at a parameter the engine only assumes untrusted is marked, and the evidence says so", () => {
    const src = `@Repository public class UserRepo {\n  public void byId(String id) throws Exception {\n    String q = "SELECT * FROM u WHERE id = " + id;\n    stmt.executeQuery(q);\n  }\n}\n`;
    const f = scan([{ path: "UserRepo.java", content: src }]).files[0].indicators.find(i => i.id === "sql-injection" && i.sourceExpr);
    expect(f?.flow?.source.assumed).toBe(true);
    expect(checksOf(f!, "UserRepo.java").some(c => /a parameter treated as untrusted — no request read was traced to it here/.test(c))).toBe(true);
    // The same class behind a controller that hands it request input: one finding, at the controller, observed.
    const ctl = `@RestController public class C {\n  @Autowired private UserRepo repo;\n  @GetMapping("/u") public void a(@RequestParam String id) throws Exception {\n    repo.byId(id);\n  }\n}\n`;
    const both = scan([{ path: "UserRepo.java", content: src }, { path: "C.java", content: ctl }]);
    expect(both.files.find(x => x.file_path === "UserRepo.java")!.indicators.filter(i => i.cwe === "CWE-89")).toEqual([]);
    expect(both.files.find(x => x.file_path === "C.java")!.indicators.find(i => i.id === "sql-injection")?.flow?.source.assumed).toBe(false);
  });

  it("the files the flow crosses get line marks linking back to it", () => {
    const r = scan(files);
    const marks = crossFileMarks(r.files.map(x => ({ file_path: x.file_path, indicators: toStoredIndicators(x.indicators) })));
    expect(marks.get("src/db/userRepo.ts")).toEqual(expect.arrayContaining([
      expect.objectContaining({ line: 4, fromFile: "src/routes/users.ts", fromLine: 4, role: "sink" }),
      expect.objectContaining({ line: 3, fromFile: "src/routes/users.ts", role: "merged" }),
    ]));
    expect(marks.get("src/services/userService.ts")).toEqual(expect.arrayContaining([expect.objectContaining({ role: "parameter" })]));
    expect(marks.has("src/routes/users.ts")).toBe(false);
  });

  it("the PR page keeps the stored result for every file tied into a cross-file flow", () => {
    const r = scan([...files, { path: "src/other.ts", content: `export const x = 1;\n` }]);
    const ctx = filesWithCrossFileContext(r.files.map(x => ({ file_path: x.file_path, indicators: toStoredIndicators(x.indicators) })));
    expect([...ctx].sort()).toEqual(["src/db/userRepo.ts", "src/routes/users.ts", "src/services/userService.ts"]);
  });
});
