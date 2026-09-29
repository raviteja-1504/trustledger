import { runScan } from "@/lib/scanner";
import { buildFindingEvidence } from "@/lib/findingEvidence";
import { toStoredIndicators } from "@/lib/indicatorStorage";
import { mergeSinkFacts, type ParamSinkFact, type TraceStep } from "@/lib/taint/taintCore";
import { warmPythonTaintEngine } from "@/lib/astTaintPython";
import { warmGoTaintEngine } from "@/lib/astTaintGo";
import { warmCSharpTaintEngine } from "@/lib/astTaintCSharp";
import { warmPhpTaintEngine } from "@/lib/astTaintPHP";

beforeAll(async () => {
  await warmPythonTaintEngine(); await warmGoTaintEngine(); await warmCSharpTaintEngine(); await warmPhpTaintEngine();
}, 120000);

// Cross-file evidence: a finding reported where the request data is passed into another file carries the
// WHOLE path -- the caller's own steps, the call, and inside each callee its parameter, assignments and the
// call forwarding it on -- down to the real sink, so the UI and SARIF can show every hop with its own file.

type F = { path: string; content: string };
const scan = (files: F[], prev?: ReturnType<typeof runScan>["file_cache"]) =>
  runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files, prev_results: prev });
const flowAt = (r: ReturnType<typeof runScan>, path: string, id = "sql-injection") =>
  (r.files.find(f => f.file_path === path)?.indicators ?? []).find(i => i.id === id && i.sourceExpr);
const hops = (trace: readonly TraceStep[] | undefined) => (trace ?? []).map(s => `${s.kind}@${s.file}:${s.line}`);

describe("the path continues through every callee, file by file", () => {
  it("JS/TS: route -> service -> repository", () => {
    const r = scan([
      { path: "src/repo.ts", content: `export class Repo {\n  byId(id) {\n    const q = "SELECT * FROM u WHERE id = " + id;\n    return db.query(q);\n  }\n}\nexport const repo = new Repo();\n` },
      { path: "src/svc.ts", content: `import { repo } from "./repo";\nexport class UserService {\n  find(id) {\n    const key = id.trim();\n    return repo.byId(key);\n  }\n}\nexport const userService = new UserService();\n` },
      { path: "src/r.ts", content: `import { userService } from "./svc";\napp.get("/u", (req, res) => {\n  const id = req.query.id;\n  userService.find(id);\n});\n` },
    ]);
    const f = flowAt(r, "src/r.ts")!;
    expect(hops(f.trace)).toEqual([
      "source@src/r.ts:3", "cross-file@src/r.ts:4",
      "parameter@src/svc.ts:3", "assignment@src/svc.ts:4", "call@src/svc.ts:5",
      "parameter@src/repo.ts:2", "assignment@src/repo.ts:3", "sink@src/repo.ts:4",
    ]);
    expect(f.trace![1].label).toBe("calls userService.find(…) in src/svc.ts");
    expect(f.trace![2].label).toBe("id — parameter of UserService.find");
    expect(JSON.stringify(f)).not.toMatch(/\bq:/);
  });

  it("Python: view -> service -> repository", () => {
    const r = scan([
      { path: "app/repo.py", content: `class Repo:\n    def by_id(self, i):\n        q = "SELECT * FROM u WHERE id = " + i\n        cursor.execute(q)\n` },
      { path: "app/svc.py", content: `from app.repo import Repo\nclass UserService:\n    def find(self, i):\n        key = i.strip()\n        Repo().by_id(key)\n` },
      { path: "app/views.py", content: `from app.svc import UserService\ndef v(request):\n    i = request.GET.get("id")\n    UserService().find(i)\n` },
    ]);
    expect(hops(flowAt(r, "app/views.py")!.trace)).toEqual([
      "source@app/views.py:3", "cross-file@app/views.py:4",
      "parameter@app/svc.py:3", "assignment@app/svc.py:4", "call@app/svc.py:5",
      "parameter@app/repo.py:2", "assignment@app/repo.py:3", "sink@app/repo.py:4",
    ]);
  });

  it("Java: controller -> service -> repository, ending at the executed query, not the concatenation", () => {
    const r = scan([
      { path: "UserRepo.java", content: `@Repository public class UserRepo {\n  public void byId(String id) throws Exception {\n    String q = "SELECT * FROM u WHERE id = " + id;\n    stmt.executeQuery(q);\n  }\n}\n` },
      { path: "UserService.java", content: `@Service public class UserService {\n  @Autowired private UserRepo repo;\n  public void find(String id) throws Exception {\n    String key = id.trim();\n    repo.byId(key);\n  }\n}\n` },
      { path: "UserController.java", content: `@RestController public class UserController {\n  @Autowired private UserService userService;\n  @GetMapping("/u") public void a(@RequestParam String id) throws Exception {\n    userService.find(id);\n  }\n}\n` },
    ]);
    const f = flowAt(r, "UserController.java")!;
    expect(hops(f.trace).slice(-5)).toEqual([
      "assignment@UserService.java:4", "cross-file@UserService.java:5",
      "parameter@UserRepo.java:2", "assignment@UserRepo.java:3", "sink@UserRepo.java:4",
    ]);
    expect(f.trace![f.trace!.length - 1].label).toBe("stmt.executeQuery");
  });

  it("C#: controller -> injected service", () => {
    const r = scan([
      { path: "UserService.cs", content: `public class UserService {\n  public void Find(string id) {\n    var q = "SELECT * FROM u WHERE id = " + id;\n    new SqlCommand(q, conn).ExecuteReader();\n  }\n}\n` },
      { path: "UserController.cs", content: `[ApiController] public class UserController : ControllerBase {\n  private readonly UserService _svc;\n  public UserController(UserService svc) { _svc = svc; }\n  [HttpGet] public IActionResult A([FromQuery] string id) { _svc.Find(id); return Ok(); }\n}\n` },
    ]);
    const kinds = (flowAt(r, "UserController.cs")!.trace ?? []).map(s => `${s.kind}@${s.file}`);
    expect(kinds).toEqual(expect.arrayContaining(["cross-file@UserController.cs", "parameter@UserService.cs", "sink@UserService.cs"]));
    expect(kinds.indexOf("parameter@UserService.cs")).toBe(kinds.indexOf("cross-file@UserController.cs") + 1);
  });

  it("Go and PHP: a same-file helper the callee hands the value to is shown as its own hop", () => {
    const go = scan([
      { path: "api/models/m.go", content: `package models\nfunc Chain(db *sql.DB, id string) {\n\tkey := strings.TrimSpace(id)\n\tFind(db, key)\n}\nfunc Find(db *sql.DB, id string) {\n\tq := "SELECT * FROM u WHERE id = " + id\n\tdb.Query(q)\n}\n` },
      { path: "api/c/h.go", content: `package c\nimport "example.com/app/api/models"\nfunc H(w http.ResponseWriter, r *http.Request) {\n\tid := r.URL.Query().Get("id")\n\tmodels.Chain(db, id)\n}\n` },
    ]);
    const goTrace = flowAt(go, "api/c/h.go")!.trace!;
    expect(hops(goTrace).slice(2)).toEqual([
      "parameter@api/models/m.go:2", "assignment@api/models/m.go:3", "call@api/models/m.go:4",
      "parameter@api/models/m.go:6", "assignment@api/models/m.go:7", "sink@api/models/m.go:8",
    ]);
    expect(goTrace[3].label).toBe("key = strings.TrimSpace(id)");
    const php = scan([
      { path: "lib/db.php", content: `<?php\nfunction find($c, $id) {\n  $q = "SELECT * FROM u WHERE id = " . $id;\n  mysqli_query($c, $q);\n}\nfunction chain($c, $id) {\n  $key = trim($id);\n  find($c, $key);\n}\n` },
      { path: "index.php", content: `<?php\nrequire __DIR__ . '/lib/db.php';\n$id = $_GET['id'];\nchain($c, $id);\n` },
    ]);
    const t = flowAt(php, "index.php")!.trace!;
    expect(hops(t).slice(2)).toEqual([
      "parameter@lib/db.php:6", "assignment@lib/db.php:7", "call@lib/db.php:8", "parameter@lib/db.php:2", "assignment@lib/db.php:3", "sink@lib/db.php:4",
    ]);
    expect(t[3].label).toBe("$key = trim($id)");
    expect(t[4].label).toBe("passes it to find(…)");
  });
});

describe("the callee file's own findings know what reaches them", () => {
  const files = [
    { path: "src/routes/users.ts", content: `import { userService } from "../services/userService";\nexport function register(app) {\n  app.get("/users/:id", (req, res) => {\n    const id = req.query.id;\n    res.json(userService.find(id));\n  });\n}\n` },
    { path: "src/services/userService.ts", content: `import { repo } from "../db/userRepo";\nexport class UserService {\n  find(id) {\n    return repo.byId(id.trim());\n  }\n}\nexport const userService = new UserService();\n` },
    { path: "src/db/userRepo.ts", content: `export class UserRepo {\n  byId(id) {\n    const sql = "SELECT * FROM users WHERE id = '" + id + "'";\n    return db.query(sql);\n  }\n}\nexport const repo = new UserRepo();\n` },
  ];

  it("the repository's pattern finding links back to the flow, is reachable, and says so", () => {
    const r = scan(files);
    const repoFinding = r.files.find(f => f.file_path === "src/db/userRepo.ts")!.indicators.find(i => i.cwe === "CWE-89" && i.line === 3)!;
    expect(repoFinding.reachedFrom).toEqual([{ file: "src/routes/users.ts", line: 5, id: "sql-injection", source: "req.query.id" }]);
    expect(repoFinding.reachability).toBe("tainted-path");
    const [stored] = toStoredIndicators([repoFinding]);
    expect(stored.reachedFrom?.[0]).toMatchObject({ file: "src/routes/users.ts", line: 5 });
    const text = buildFindingEvidence(stored, "src/db/userRepo.ts").checks.map(c => c.parts.map(p => (typeof p === "string" ? p : p.code)).join(""));
    expect(text).toContain("Reached by req.query.id through the confirmed data flow reported at src/routes/users.ts:5");
    expect(text.some(t => /Pattern match only|possibly dead code/.test(t))).toBe(false);
  });

  it("a finding still marked unreachable by its own file's call graph doesn't claim dead code once a flow reaches it", () => {
    const ev = buildFindingEvidence({
      id: "sql-injection", label: "SQL Injection", severity: "critical", line: 3, detail: "Query built with string interpolation", cwe: "CWE-89",
      reachability: "unreachable", reachedFrom: [{ file: "src/routes/users.ts", line: 5, id: "sql-injection" }],
    }, "src/db/userRepo.ts");
    const checks = ev.checks.map(c => c.parts.map(p => (typeof p === "string" ? p : p.code)).join(""));
    expect(checks.some(c => /possibly dead code/.test(c))).toBe(false);
    expect(checks).toContain("Reached by the confirmed data flow reported at src/routes/users.ts:5");
  });

  it("the caller's explanation names the callee, the sink and its file, without repeating the crossing", () => {
    const r = scan(files);
    const [stored] = toStoredIndicators([flowAt(r, "src/routes/users.ts")!]);
    const ev = buildFindingEvidence(stored, "src/routes/users.ts");
    const summary = ev.summary.map(p => (typeof p === "string" ? p : p.code)).join("");
    expect(summary).toBe("Untrusted input req.query.id (URL query parameter) is passed to userService.find() and reaches db.query() in src/db/userRepo.ts, where it is used to build a SQL query.");
    const checks = ev.checks.map(c => c.parts.map(p => (typeof p === "string" ? p : p.code)).join(""));
    expect(checks.filter(c => /crosses file boundary via/i.test(c))).toEqual([]);
    expect(checks).toContain("Reaches db.query() at src/db/userRepo.ts:4, where it is used to build a SQL query");
  });
});

describe("fact paths", () => {
  const fact = (steps?: TraceStep[]): ParamSinkFact => ({ index: 0, isRest: false, id: "sql-injection", sinkClass: 1, sinkExpr: "db.query", file: "a.ts", line: 4, via: ["f"], steps });
  const step = (line: number): TraceStep => ({ file: "a.ts", line, kind: "assignment", label: "", snippet: "" });

  it("the same fact found again with a longer path upgrades it (and counts as growth, so a fixed point continues)", () => {
    const list = [fact([step(1)])];
    expect(mergeSinkFacts(list, [fact([step(1), step(2)])])).toBe(true);
    expect(list[0].steps).toHaveLength(2);
    expect(mergeSinkFacts(list, [fact([step(9)])])).toBe(false);
    expect(list[0].steps).toHaveLength(2);
  });

  it("an edit two files away that only moves a step re-analyzes the caller (its direct import is unchanged)", () => {
    const repo = { path: "src/repo.ts", content: `export function byId(id) {\n  const q = "SELECT * FROM u WHERE id = " + id;\n  return db.query(q);\n}\n` };
    const svc = { path: "src/svc.ts", content: `import { byId } from "./repo";\nexport function find(id) {\n  return byId(id);\n}\n` };
    const caller = { path: "src/r.ts", content: `import { find } from "./svc";\napp.get("/u", (req, res) => { find(req.query.id); });\n` };
    const first = scan([repo, svc, caller]);
    const moved = { ...repo, content: `export function byId(id) { const q = "SELECT * FROM u WHERE id = " + id;\n\n  return db.query(q);\n}\n` };
    const second = scan([moved, svc, caller], first.file_cache);
    const repoSteps = (r: ReturnType<typeof scan>) => flowAt(r, "src/r.ts")!.trace!.filter(s => s.file === "src/repo.ts").map(s => `${s.kind}:${s.line}`);
    expect(repoSteps(first)).toEqual(["parameter:1", "assignment:2", "sink:3"]);
    expect(repoSteps(second)).toEqual(["parameter:1", "assignment:1", "sink:3"]);
  });

  it("same for a package-level summary (Go): moving only an assignment in the callee package re-analyzes the handler", () => {
    const models = (body: string) => ({ path: "api/models/m.go", content: `package models\nfunc Find(db *sql.DB, id string) {\n${body}\n\tdb.Query(q)\n}\n` });
    const handler = { path: "api/c/h.go", content: `package c\nimport "example.com/app/api/models"\nfunc H(w http.ResponseWriter, r *http.Request) {\n\tmodels.Find(db, r.URL.Query().Get("id"))\n}\n` };
    const first = scan([models(`\tq := "SELECT * FROM u WHERE id = " +\n\t\tid`), handler]);
    const second = scan([models(`\t_ = 0\n\tq := "SELECT * FROM u WHERE id = " + id`), handler], first.file_cache);
    const assign = (r: ReturnType<typeof scan>) => flowAt(r, "api/c/h.go")!.trace!.filter(s => s.kind === "assignment").map(s => s.line);
    expect(flowAt(first, "api/c/h.go")!.trace!.slice(-1)[0].line).toBe(flowAt(second, "api/c/h.go")!.trace!.slice(-1)[0].line);
    expect(assign(first)).not.toEqual(assign(second));
  });

  it("a callee edit that only moves an intermediate step re-analyzes the unchanged caller", () => {
    const repo = { path: "src/repo.ts", content: `export function byId(id) {\n  const q = "SELECT * FROM u WHERE id = " + id;\n  return db.query(q);\n}\n` };
    const caller = { path: "src/r.ts", content: `import { byId } from "./repo";\napp.get("/u", (req, res) => { byId(req.query.id); });\n` };
    const first = scan([repo, caller]);
    // The query is now built on line 1 instead of 2; the sink stays on line 3.
    const moved = { ...repo, content: `export function byId(id) { const q = "SELECT * FROM u WHERE id = " + id;\n\n  return db.query(q);\n}\n` };
    const second = scan([moved, caller], first.file_cache);
    const lines = (r: ReturnType<typeof scan>) => flowAt(r, "src/r.ts")!.trace!.filter(s => s.file === "src/repo.ts").map(s => `${s.kind}:${s.line}`);
    expect(lines(first)).toEqual(["parameter:1", "assignment:2", "sink:3"]);
    expect(lines(second)).toEqual(["parameter:1", "assignment:1", "sink:3"]);
  });
});
