/**
 * Cross-file benchmark cases: small multi-file programs, one per case, each either a real flow that only
 * exists ACROSS files (a positive: request input in one file reaches a sink in another) or a look-alike that
 * must stay quiet (a negative: parameterised callee, sanitised in the callee, constant argument, same-named
 * method on an unrelated type, input the callee reads itself, ...).
 *
 * Scored by runCrossFileBenchmark.ts; the committed per-case outcome is crossFileBaseline.json.
 */
export interface BenchFile { path: string; content: string }

export interface CrossFileCase {
  name: string;
  language: "typescript" | "python" | "java" | "csharp" | "go" | "php";
  files: BenchFile[];
  /** Positive: a data-flow finding with this id in `file`, whose evidence crosses files and whose sink is in
   * `sinkFile`. Negative: NO data-flow finding with this id in `file` (or in any file when omitted). */
  expect: { kind: "tp"; file: string; id: string; sinkFile: string } | { kind: "tn"; id: string; file?: string };
}

const SQL_TS = (fn: string) => `export function ${fn}(id) {\n  return db.query("SELECT * FROM u WHERE id = " + id);\n}\n`;

const TS: CrossFileCase[] = [
  { name: "imported function", language: "typescript", expect: { kind: "tp", file: "src/r.ts", id: "sql-injection", sinkFile: "src/db.ts" }, files: [
    { path: "src/db.ts", content: SQL_TS("runQuery") },
    { path: "src/r.ts", content: `import { runQuery } from "./db";\napp.get("/u", (req, res) => runQuery(req.query.id));\n` }] },
  { name: "three files: handler -> forward -> sink", language: "typescript", expect: { kind: "tp", file: "src/a.ts", id: "sql-injection", sinkFile: "src/c.ts" }, files: [
    { path: "src/c.ts", content: SQL_TS("runQuery") },
    { path: "src/b.ts", content: `import { runQuery } from "./c";\nexport function forward(id) {\n  return runQuery(id);\n}\n` },
    { path: "src/a.ts", content: `import { forward } from "./b";\napp.get("/u", (req, res) => forward(req.query.id));\n` }] },
  { name: "re-export barrel", language: "typescript", expect: { kind: "tp", file: "src/api.ts", id: "sql-injection", sinkFile: "src/db.ts" }, files: [
    { path: "src/db.ts", content: SQL_TS("runQuery") },
    { path: "src/index.ts", content: `export { runQuery } from "./db";\n` },
    { path: "src/api.ts", content: `import { runQuery } from "./index";\napp.get("/u", (req, res) => runQuery(req.query.id));\n` }] },
  { name: "service -> repository (two hops, methods)", language: "typescript", expect: { kind: "tp", file: "src/r.ts", id: "sql-injection", sinkFile: "src/repo.ts" }, files: [
    { path: "src/repo.ts", content: `export class Repo {\n  byId(id) { return db.query("SELECT * FROM u WHERE id = " + id); }\n}\nexport const repo = new Repo();\n` },
    { path: "src/svc.ts", content: `import { repo } from "./repo";\nexport class UserService {\n  find(id) { return repo.byId(id); }\n}\nexport const userService = new UserService();\n` },
    { path: "src/r.ts", content: `import { userService } from "./svc";\napp.get("/u", (req, res) => userService.find(req.query.id));\n` }] },
  { name: "sink in a private helper of the imported function", language: "typescript", expect: { kind: "tp", file: "src/r.ts", id: "sql-injection", sinkFile: "src/db.ts" }, files: [
    { path: "src/db.ts", content: `function helper(id) {\n  return db.query("SELECT * FROM u WHERE id = " + id);\n}\nexport function runQuery(id) {\n  return helper(id);\n}\n` },
    { path: "src/r.ts", content: `import { runQuery } from "./db";\napp.get("/u", (req, res) => runQuery(req.query.id));\n` }] },
  { name: "command injection through a helper module", language: "typescript", expect: { kind: "tp", file: "src/r.ts", id: "command-injection", sinkFile: "src/sh.ts" }, files: [
    { path: "src/sh.ts", content: `import { exec } from "child_process";\nexport function listDir(dir) {\n  return exec("ls " + dir);\n}\n` },
    { path: "src/r.ts", content: `import { listDir } from "./sh";\napp.get("/ls", (req, res) => listDir(req.query.dir));\n` }] },
  { name: "negative: parameterised callee", language: "typescript", expect: { kind: "tn", id: "sql-injection" }, files: [
    { path: "src/db.ts", content: `export function runQuery(id) {\n  return db.query("SELECT * FROM u WHERE id = ?", [id]);\n}\n` },
    { path: "src/r.ts", content: `import { runQuery } from "./db";\napp.get("/u", (req, res) => runQuery(req.query.id));\n` }] },
  { name: "negative: callee coerces to an integer", language: "typescript", expect: { kind: "tn", id: "sql-injection" }, files: [
    { path: "src/db.ts", content: `export function runQuery(id) {\n  const n = parseInt(id, 10);\n  return db.query("SELECT * FROM u WHERE id = " + n);\n}\n` },
    { path: "src/r.ts", content: `import { runQuery } from "./db";\napp.get("/u", (req, res) => runQuery(req.query.id));\n` }] },
  { name: "negative: constant argument", language: "typescript", expect: { kind: "tn", id: "sql-injection", file: "src/r.ts" }, files: [
    { path: "src/db.ts", content: SQL_TS("runQuery") },
    { path: "src/r.ts", content: `import { runQuery } from "./db";\napp.get("/u", (req, res) => runQuery("1"));\n` }] },
  { name: "negative: array .find is not the service's find", language: "typescript", expect: { kind: "tn", id: "sql-injection", file: "src/r.ts" }, files: [
    { path: "src/svc.ts", content: `export class UserService {\n  find(id) { return db.query("SELECT * FROM u WHERE id = " + id); }\n}\nexport const userService = new UserService();\n` },
    { path: "src/r.ts", content: `import { userService } from "./svc";\napp.get("/u", (req, res) => { const users = []; return users.find(req.query.id); });\n` }] },
];

const SQL_PY = (fn: string) => `def ${fn}(i):\n    cursor.execute("SELECT * FROM u WHERE id = " + i)\n`;

const PY: CrossFileCase[] = [
  { name: "imported function", language: "python", expect: { kind: "tp", file: "app/views.py", id: "sql-injection", sinkFile: "app/db.py" }, files: [
    { path: "app/db.py", content: SQL_PY("run_query") },
    { path: "app/views.py", content: `from app.db import run_query\ndef v(request):\n    run_query(request.GET.get("id"))\n` }] },
  { name: "three modules: view -> forward -> sink", language: "python", expect: { kind: "tp", file: "app/views.py", id: "sql-injection", sinkFile: "app/db.py" }, files: [
    { path: "app/db.py", content: SQL_PY("run_query") },
    { path: "app/mid.py", content: `from app.db import run_query\ndef forward(i):\n    run_query(i)\n` },
    { path: "app/views.py", content: `from app.mid import forward\ndef v(request):\n    forward(request.GET.get("id"))\n` }] },
  { name: "namespace import (from . import db)", language: "python", expect: { kind: "tp", file: "app/views.py", id: "sql-injection", sinkFile: "app/db.py" }, files: [
    { path: "app/db.py", content: SQL_PY("run_query") },
    { path: "app/views.py", content: `from . import db\ndef v(request):\n    db.run_query(request.GET.get("id"))\n` }] },
  { name: "service -> repository (two hops, methods)", language: "python", expect: { kind: "tp", file: "app/views.py", id: "sql-injection", sinkFile: "app/repo.py" }, files: [
    { path: "app/repo.py", content: `class Repo:\n    def by_id(self, i):\n        cursor.execute("SELECT * FROM u WHERE id = " + i)\n` },
    { path: "app/svc.py", content: `from app.repo import Repo\nclass UserService:\n    def __init__(self):\n        self.repo = Repo()\n    def find(self, i):\n        self.repo.by_id(i)\n` },
    { path: "app/views.py", content: `from app.svc import UserService\ndef v(request):\n    UserService().find(request.GET.get("id"))\n` }] },
  { name: "command injection through a helper module", language: "python", expect: { kind: "tp", file: "app/views.py", id: "command-injection", sinkFile: "app/sh.py" }, files: [
    { path: "app/sh.py", content: `import os\ndef list_dir(d):\n    os.system("ls " + d)\n` },
    { path: "app/views.py", content: `from app.sh import list_dir\ndef v(request):\n    list_dir(request.GET.get("dir"))\n` }] },
  { name: "negative: parameterised callee", language: "python", expect: { kind: "tn", id: "sql-injection" }, files: [
    { path: "app/db.py", content: `def run_query(i):\n    cursor.execute("SELECT * FROM u WHERE id = %s", (i,))\n` },
    { path: "app/views.py", content: `from app.db import run_query\ndef v(request):\n    run_query(request.GET.get("id"))\n` }] },
  { name: "negative: callee coerces to int", language: "python", expect: { kind: "tn", id: "sql-injection" }, files: [
    { path: "app/db.py", content: `def run_query(i):\n    n = int(i)\n    cursor.execute("SELECT * FROM u WHERE id = " + str(n))\n` },
    { path: "app/views.py", content: `from app.db import run_query\ndef v(request):\n    run_query(request.GET.get("id"))\n` }] },
  { name: "negative: constant argument", language: "python", expect: { kind: "tn", id: "sql-injection", file: "app/views.py" }, files: [
    { path: "app/db.py", content: SQL_PY("run_query") },
    { path: "app/views.py", content: `from app.db import run_query\ndef v(request):\n    run_query("1")\n` }] },
  { name: "negative: str.find is not the service's find", language: "python", expect: { kind: "tn", id: "sql-injection", file: "app/views.py" }, files: [
    { path: "app/svc.py", content: `class UserService:\n    def find(self, i):\n        cursor.execute("SELECT * FROM u WHERE id = " + i)\n` },
    { path: "app/views.py", content: `from app.svc import UserService\ndef v(request):\n    s = "abc"\n    s.find(request.GET.get("id"))\n` }] },
];

const JAVA_CTL = (field: string, call: string) => ({ path: "UserController.java", content: `@RestController public class UserController {\n${field}\n  @GetMapping("/u") public void a(@RequestParam String id) throws Exception { ${call}; }\n}\n` });
const JAVA_SVC = { path: "UserService.java", content: `@Service public class UserService {\n  public void find(String id) throws Exception { stmt.executeQuery("SELECT * FROM u WHERE id = " + id); }\n}\n` };

const JAVA: CrossFileCase[] = [
  { name: "@Autowired service", language: "java", expect: { kind: "tp", file: "UserController.java", id: "sql-injection", sinkFile: "UserService.java" }, files: [
    JAVA_SVC, JAVA_CTL(`  @Autowired private UserService userService;`, `userService.find(id)`)] },
  { name: "constructor-injected service", language: "java", expect: { kind: "tp", file: "UserController.java", id: "sql-injection", sinkFile: "UserService.java" }, files: [
    JAVA_SVC, JAVA_CTL(`  private final UserService s;\n  public UserController(UserService s) { this.s = s; }`, `this.s.find(id)`)] },
  { name: "controller -> service -> repository", language: "java", expect: { kind: "tp", file: "UserController.java", id: "sql-injection", sinkFile: "UserRepo.java" }, files: [
    { path: "UserRepo.java", content: `@Repository public class UserRepo {\n  public void byId(String id) throws Exception { stmt.executeQuery("SELECT * FROM u WHERE id = " + id); }\n}\n` },
    { path: "UserService.java", content: `@Service public class UserService {\n  @Autowired private UserRepo repo;\n  public void find(String id) throws Exception { repo.byId(id); }\n}\n` },
    JAVA_CTL(`  @Autowired private UserService userService;`, `userService.find(id)`)] },
  { name: "command injection in a service", language: "java", expect: { kind: "tp", file: "UserController.java", id: "command-injection", sinkFile: "ShellService.java" }, files: [
    { path: "ShellService.java", content: `@Service public class ShellService {\n  public void list(String dir) throws Exception { Runtime.getRuntime().exec("ls " + dir); }\n}\n` },
    JAVA_CTL(`  @Autowired private ShellService shell;`, `shell.list(id)`)] },
  { name: "negative: PreparedStatement service", language: "java", expect: { kind: "tn", id: "sql-injection" }, files: [
    { path: "UserService.java", content: `@Service public class UserService {\n  public void find(String id) throws Exception { PreparedStatement p = conn.prepareStatement("SELECT * FROM u WHERE id = ?"); p.setString(1, id); p.executeQuery(); }\n}\n` },
    JAVA_CTL(`  @Autowired private UserService userService;`, `userService.find(id)`)] },
  { name: "negative: same-named method on an unrelated type", language: "java", expect: { kind: "tn", id: "sql-injection", file: "UserController.java" }, files: [
    JAVA_SVC, JAVA_CTL(`  @Autowired private OtherService other;`, `other.find(id)`)] },
  { name: "negative: service parses an integer first", language: "java", expect: { kind: "tn", id: "sql-injection", file: "UserController.java" }, files: [
    { path: "UserService.java", content: `@Service public class UserService {\n  public void find(String id) throws Exception { int n = Integer.parseInt(id); stmt.executeQuery("SELECT * FROM u WHERE id = " + n); }\n}\n` },
    JAVA_CTL(`  @Autowired private UserService userService;`, `userService.find(id)`)] },
  { name: "negative: constant argument", language: "java", expect: { kind: "tn", id: "sql-injection", file: "UserController.java" }, files: [
    JAVA_SVC, JAVA_CTL(`  @Autowired private UserService userService;`, `userService.find("1")`)] },
];

const CS_CTL = (members: string, call: string) => ({ path: "UserController.cs", content: `[ApiController] public class UserController : ControllerBase {\n${members}\n  [HttpGet] public IActionResult A([FromQuery] string id) { ${call}; return Ok(); }\n}\n` });
const CS_SVC = { path: "UserService.cs", content: `public class UserService : IUserService {\n  public void Find(string id) { new SqlCommand("SELECT * FROM u WHERE id = " + id, conn).ExecuteReader(); }\n}\n` };

const CSHARP: CrossFileCase[] = [
  { name: "constructor-injected field", language: "csharp", expect: { kind: "tp", file: "UserController.cs", id: "sql-injection", sinkFile: "UserService.cs" }, files: [
    CS_SVC, CS_CTL(`  private readonly UserService _svc;\n  public UserController(UserService svc) { _svc = svc; }`, `_svc.Find(id)`)] },
  { name: "interface-typed field", language: "csharp", expect: { kind: "tp", file: "UserController.cs", id: "sql-injection", sinkFile: "UserService.cs" }, files: [
    CS_SVC, CS_CTL(`  private readonly IUserService _svc;`, `_svc.Find(id)`)] },
  { name: "primary-constructor parameter", language: "csharp", expect: { kind: "tp", file: "UserController.cs", id: "sql-injection", sinkFile: "UserService.cs" }, files: [
    CS_SVC, { path: "UserController.cs", content: `[ApiController] public class UserController([FromServices] UserService svc) : ControllerBase {\n  [HttpGet] public IActionResult A([FromQuery] string id) { svc.Find(id); return Ok(); }\n}\n` }] },
  { name: "negative: EF-parameterised service", language: "csharp", expect: { kind: "tn", id: "sql-injection" }, files: [
    { path: "UserService.cs", content: `public class UserService {\n  public void Find(string id) { db.Users.FromSqlInterpolated($"SELECT * FROM u WHERE id = {id}").ToList(); }\n}\n` },
    CS_CTL(`  private readonly UserService _svc;`, `_svc.Find(id)`)] },
  { name: "negative: same-named method on an unrelated type", language: "csharp", expect: { kind: "tn", id: "sql-injection", file: "UserController.cs" }, files: [
    CS_SVC, CS_CTL(`  private readonly OtherThing _o;`, `_o.Find(id)`)] },
  { name: "negative: service parses an integer first", language: "csharp", expect: { kind: "tn", id: "sql-injection", file: "UserController.cs" }, files: [
    { path: "UserService.cs", content: `public class UserService {\n  public void Find(string id) { var n = int.Parse(id); new SqlCommand("SELECT * FROM u WHERE id = " + n, conn).ExecuteReader(); }\n}\n` },
    CS_CTL(`  private readonly UserService _svc;`, `_svc.Find(id)`)] },
  { name: "negative: constant argument", language: "csharp", expect: { kind: "tn", id: "sql-injection", file: "UserController.cs" }, files: [
    CS_SVC, CS_CTL(`  private readonly UserService _svc;`, `_svc.Find("1")`)] },
];

const GO_MODELS = { path: "api/models/store.go", content: `package models\ntype Store struct{ db *sql.DB }\nfunc (s *Store) Find(id string) { s.db.Query("SELECT * FROM u WHERE id = " + id) }\nfunc Safe(db *sql.DB, id string) { db.Query("SELECT * FROM u WHERE id = ?", id) }\nfunc Chain(db *sql.DB, id string) { Find(db, id) }\nfunc Find(db *sql.DB, id string) { db.Query("SELECT * FROM u WHERE id = " + id) }\nfunc Num(db *sql.DB, id string) { n, _ := strconv.Atoi(id); db.Query(fmt.Sprintf("SELECT * FROM u WHERE id = %d", n)) }\n` };
const GO_CTL = (body: string, head = `import "example.com/app/api/models"`) => ({ path: "api/c/user.go", content: `package c\n${head}\n${body}\n` });
const GO_H = (call: string) => `func H(w http.ResponseWriter, r *http.Request) { ${call} }`;
const GO_TP = { kind: "tp" as const, file: "api/c/user.go", id: "sql-injection", sinkFile: "api/models/store.go" };

const GO: CrossFileCase[] = [
  { name: "package function", language: "go", expect: GO_TP, files: [GO_MODELS, GO_CTL(GO_H(`models.Find(db, r.URL.Query().Get("id"))`))] },
  { name: "aliased import", language: "go", expect: GO_TP, files: [GO_MODELS, GO_CTL(GO_H(`m.Find(db, r.URL.Query().Get("id"))`), `import m "example.com/app/api/models"`)] },
  { name: "same-package forwarder in the callee package", language: "go", expect: GO_TP, files: [GO_MODELS, GO_CTL(GO_H(`models.Chain(db, r.URL.Query().Get("id"))`))] },
  { name: "method through a struct field", language: "go", expect: GO_TP, files: [GO_MODELS,
    GO_CTL(`type Server struct { Store *models.Store }\nfunc (s *Server) H(w http.ResponseWriter, r *http.Request) { s.Store.Find(r.URL.Query().Get("id")) }`)] },
  { name: "decoded filter document into a mongo lookup", language: "go", expect: { kind: "tp", file: "api/c/coupon.go", id: "nosql-injection", sinkFile: "api/models/coupon.go" }, files: [
    { path: "api/models/coupon.go", content: `package models\nfunc ValidateCode(client *mongo.Client, bsonMap bson.M) error {\n\tcollection := client.Database("crapi").Collection("coupons")\n\treturn collection.FindOne(context.TODO(), bsonMap).Err()\n}\n` },
    { path: "api/c/coupon.go", content: `package c\nimport "example.com/app/api/models"\nfunc V(w http.ResponseWriter, r *http.Request) {\n\tvar bsonMap bson.M\n\tbody, _ := ioutil.ReadAll(r.Body)\n\tjson.Unmarshal(body, &bsonMap)\n\tmodels.ValidateCode(client, bsonMap)\n}\n` }] },
  { name: "negative: parameterised callee", language: "go", expect: { kind: "tn", id: "sql-injection", file: "api/c/user.go" }, files: [GO_MODELS, GO_CTL(GO_H(`models.Safe(db, r.URL.Query().Get("id"))`))] },
  { name: "negative: constant argument", language: "go", expect: { kind: "tn", id: "sql-injection", file: "api/c/user.go" }, files: [GO_MODELS, GO_CTL(GO_H(`models.Find(db, "1")`))] },
  { name: "negative: callee converts with strconv.Atoi", language: "go", expect: { kind: "tn", id: "sql-injection", file: "api/c/user.go" }, files: [GO_MODELS, GO_CTL(GO_H(`models.Num(db, r.URL.Query().Get("id"))`))] },
  { name: "negative: callee sinks its own input, not the caller's argument", language: "go", expect: { kind: "tn", id: "sql-injection", file: "api/c/user.go" }, files: [
    { path: "api/models/p.go", content: `package models\nfunc Page(r *http.Request, x string) { db.Query("SELECT * FROM u WHERE id = " + r.URL.Query().Get("q")) }\n` },
    GO_CTL(GO_H(`models.Page(r, r.URL.Query().Get("id"))`))] },
];

const PHP_LIB = { path: "lib/db.php", content: `<?php\nfunction find($c, $id) { mysqli_query($c, "SELECT * FROM u WHERE id = " . $id); }\nfunction safe($c, $id) { mysqli_query($c, "SELECT * FROM u WHERE id = " . intval($id)); }\nfunction chain($c, $id) { return find($c, $id); }\n` };
const PHP_PAGE = (path: string, body: string) => ({ path, content: `<?php\n${body}\n` });

const PHP: CrossFileCase[] = [
  { name: "__DIR__-anchored include", language: "php", expect: { kind: "tp", file: "index.php", id: "sql-injection", sinkFile: "lib/db.php" }, files: [
    PHP_LIB, PHP_PAGE("index.php", `require_once __DIR__ . '/lib/db.php';\nfind($c, $_GET['id']);`)] },
  { name: "relative include + forwarder", language: "php", expect: { kind: "tp", file: "app/index.php", id: "sql-injection", sinkFile: "lib/db.php" }, files: [
    PHP_LIB, PHP_PAGE("app/index.php", `include '../lib/db.php';\nfunction h() { chain($c, $_POST['id']); }`)] },
  { name: "constant-prefixed include", language: "php", expect: { kind: "tp", file: "app/index.php", id: "sql-injection", sinkFile: "lib/db.php" }, files: [
    PHP_LIB, PHP_PAGE("app/index.php", `require_once APP_ROOT . 'lib/db.php';\nfind($c, $_GET['id']);`)] },
  { name: "transitive include, case-insensitive call", language: "php", expect: { kind: "tp", file: "index.php", id: "sql-injection", sinkFile: "lib/db.php" }, files: [
    PHP_LIB, PHP_PAGE("lib/boot.php", `require __DIR__ . '/db.php';`), PHP_PAGE("index.php", `require __DIR__ . '/lib/boot.php';\nFIND($c, $_GET['id']);`)] },
  { name: "command injection in an included helper", language: "php", expect: { kind: "tp", file: "index.php", id: "command-injection", sinkFile: "lib/sh.php" }, files: [
    { path: "lib/sh.php", content: `<?php\nfunction list_dir($d) { system("ls " . $d); }\n` },
    PHP_PAGE("index.php", `require __DIR__ . '/lib/sh.php';\nlist_dir($_GET['dir']);`)] },
  { name: "negative: file never included", language: "php", expect: { kind: "tn", id: "sql-injection", file: "index.php" }, files: [
    PHP_LIB, PHP_PAGE("index.php", `find($c, $_GET['id']);`)] },
  { name: "negative: callee applies intval", language: "php", expect: { kind: "tn", id: "sql-injection", file: "index.php" }, files: [
    PHP_LIB, PHP_PAGE("index.php", `require __DIR__ . '/lib/db.php';\nsafe($c, $_GET['id']);`)] },
  { name: "negative: constant argument", language: "php", expect: { kind: "tn", id: "sql-injection", file: "index.php" }, files: [
    PHP_LIB, PHP_PAGE("index.php", `require __DIR__ . '/lib/db.php';\nfind($c, 5);`)] },
  { name: "negative: ambiguous include suffix", language: "php", expect: { kind: "tn", id: "sql-injection", file: "app/index.php" }, files: [
    PHP_LIB, { path: "other/lib/db.php", content: `<?php\nfunction find($c, $id) { echo "noop"; }\n` },
    PHP_PAGE("app/index.php", `require_once APP_ROOT . 'lib/db.php';\nfind($c, $_GET['id']);`)] },
];

// Harder shapes: module systems, static helpers, interface implementations, classes in included files, and
// sanitisers of the wrong class on the way (they must not hide the flow). Some of these are known gaps --
// the baseline records which, so closing one shows up as an improvement.
const HARD: CrossFileCase[] = [
  { name: "CommonJS require + module.exports", language: "typescript", expect: { kind: "tp", file: "src/r.js", id: "sql-injection", sinkFile: "src/db.js" }, files: [
    { path: "src/db.js", content: `function runQuery(id) {\n  return db.query("SELECT * FROM u WHERE id = " + id);\n}\nmodule.exports = { runQuery };\n` },
    { path: "src/r.js", content: `const { runQuery } = require("./db");\napp.get("/u", (req, res) => runQuery(req.query.id));\n` }] },
  { name: "namespace import (import * as db)", language: "typescript", expect: { kind: "tp", file: "src/r.ts", id: "sql-injection", sinkFile: "src/db.ts" }, files: [
    { path: "src/db.ts", content: SQL_TS("runQuery") },
    { path: "src/r.ts", content: `import * as dbm from "./db";\napp.get("/u", (req, res) => dbm.runQuery(req.query.id));\n` }] },
  { name: "default-exported function, awaited", language: "typescript", expect: { kind: "tp", file: "src/r.ts", id: "sql-injection", sinkFile: "src/db.ts" }, files: [
    { path: "src/db.ts", content: `export default async function runQuery(id) {\n  return db.query("SELECT * FROM u WHERE id = " + id);\n}\n` },
    { path: "src/r.ts", content: `import runQuery from "./db";\napp.get("/u", async (req, res) => { await runQuery(req.query.id); });\n` }] },
  { name: "wrong-class sanitiser in the caller (basename before SQL)", language: "typescript", expect: { kind: "tp", file: "src/r.ts", id: "sql-injection", sinkFile: "src/db.ts" }, files: [
    { path: "src/db.ts", content: SQL_TS("runQuery") },
    { path: "src/r.ts", content: `import path from "path";\nimport { runQuery } from "./db";\napp.get("/u", (req, res) => runQuery(path.basename(req.query.id)));\n` }] },
  { name: "negative: right-class sanitiser in the caller (basename before a file read)", language: "typescript", expect: { kind: "tn", id: "path-traversal", file: "src/r.ts" }, files: [
    { path: "src/fsu.ts", content: `import fs from "fs";\nexport function readUpload(name) {\n  return fs.readFileSync("/uploads/" + name);\n}\n` },
    { path: "src/r.ts", content: `import path from "path";\nimport { readUpload } from "./fsu";\napp.get("/f", (req, res) => readUpload(path.basename(req.query.f)));\n` }] },

  { name: "renamed import (as rq)", language: "python", expect: { kind: "tp", file: "app/views.py", id: "sql-injection", sinkFile: "app/db.py" }, files: [
    { path: "app/db.py", content: SQL_PY("run_query") },
    { path: "app/views.py", content: `from .db import run_query as rq\ndef v(request):\n    rq(request.GET.get("id"))\n` }] },
  { name: "service injected through __init__", language: "python", expect: { kind: "tp", file: "app/views.py", id: "sql-injection", sinkFile: "app/svc.py" }, files: [
    { path: "app/svc.py", content: `class UserService:\n    def find(self, i):\n        cursor.execute("SELECT * FROM u WHERE id = " + i)\n` },
    { path: "app/views.py", content: `from app.svc import UserService\nclass V:\n    def __init__(self, svc: UserService):\n        self.svc = svc\n    def get(self, request):\n        self.svc.find(request.GET.get("id"))\n` }] },
  { name: "wrong-class sanitiser in the caller (html.escape before SQL)", language: "python", expect: { kind: "tp", file: "app/views.py", id: "sql-injection", sinkFile: "app/db.py" }, files: [
    { path: "app/db.py", content: SQL_PY("run_query") },
    { path: "app/views.py", content: `import html\nfrom app.db import run_query\ndef v(request):\n    run_query(html.escape(request.GET.get("id")))\n` }] },
  { name: "negative: self.run_query is not the imported function", language: "python", expect: { kind: "tn", id: "sql-injection", file: "app/views.py" }, files: [
    { path: "app/db.py", content: SQL_PY("run_query") },
    { path: "app/views.py", content: `from app.db import run_query\nclass V:\n    def run_query(self, x):\n        return x\n    def get(self, request):\n        self.run_query(request.GET.get("id"))\n` }] },

  { name: "static utility method", language: "java", expect: { kind: "tp", file: "UserController.java", id: "sql-injection", sinkFile: "DbUtil.java" }, files: [
    { path: "DbUtil.java", content: `public class DbUtil {\n  public static void find(String id) throws Exception { stmt.executeQuery("SELECT * FROM u WHERE id = " + id); }\n}\n` },
    JAVA_CTL(``, `DbUtil.find(id)`)] },
  { name: "interface field, implementation in another file", language: "java", expect: { kind: "tp", file: "UserController.java", id: "sql-injection", sinkFile: "UserServiceImpl.java" }, files: [
    { path: "UserService.java", content: `public interface UserService {\n  void find(String id) throws Exception;\n}\n` },
    { path: "UserServiceImpl.java", content: `@Service public class UserServiceImpl implements UserService {\n  public void find(String id) throws Exception { stmt.executeQuery("SELECT * FROM u WHERE id = " + id); }\n}\n` },
    JAVA_CTL(`  @Autowired private UserService userService;`, `userService.find(id)`)] },
  { name: "XPath query built in a service", language: "java", expect: { kind: "tp", file: "UserController.java", id: "xpath-injection", sinkFile: "XmlService.java" }, files: [
    { path: "XmlService.java", content: `@Service public class XmlService {\n  public Object byName(String n) throws Exception { return xpath.evaluate("//user[@name='" + n + "']", doc); }\n}\n` },
    JAVA_CTL(`  @Autowired private XmlService xml;`, `xml.byName(id)`)] },

  { name: "static helper class", language: "csharp", expect: { kind: "tp", file: "UserController.cs", id: "sql-injection", sinkFile: "DbHelper.cs" }, files: [
    { path: "DbHelper.cs", content: `public static class DbHelper {\n  public static void Find(string id) { new SqlCommand("SELECT * FROM u WHERE id = " + id, conn).ExecuteReader(); }\n}\n` },
    CS_CTL(``, `DbHelper.Find(id)`)] },
  { name: "command injection in a service", language: "csharp", expect: { kind: "tp", file: "UserController.cs", id: "command-injection", sinkFile: "ShellService.cs" }, files: [
    { path: "ShellService.cs", content: `public class ShellService {\n  public void List(string dir) { Process.Start("cmd.exe", "/c dir " + dir); }\n}\n` },
    CS_CTL(`  private readonly ShellService _sh;`, `_sh.List(id)`)] },

  { name: "method through a typed parameter", language: "go", expect: GO_TP, files: [GO_MODELS,
    GO_CTL(`func H(st *models.Store, r *http.Request) { st.Find(r.URL.Query().Get("id")) }`)] },
  { name: "path traversal in a helper package", language: "go", expect: { kind: "tp", file: "api/c/user.go", id: "path-traversal", sinkFile: "api/files/files.go" }, files: [
    { path: "api/files/files.go", content: `package files\nfunc Read(name string) ([]byte, error) { return os.ReadFile("/uploads/" + name) }\n` },
    GO_CTL(GO_H(`files.Read(r.URL.Query().Get("f"))`), `import "example.com/app/api/files"`)] },

  { name: "class method from an included file", language: "php", expect: { kind: "tp", file: "index.php", id: "sql-injection", sinkFile: "lib/repo.php" }, files: [
    { path: "lib/repo.php", content: `<?php\nclass Repo {\n  public function find($id) { mysqli_query($this->c, "SELECT * FROM u WHERE id = " . $id); }\n}\n` },
    PHP_PAGE("index.php", `require __DIR__ . '/lib/repo.php';\n$repo = new Repo();\n$repo->find($_GET['id']);`)] },
  { name: "static method from an included file", language: "php", expect: { kind: "tp", file: "index.php", id: "sql-injection", sinkFile: "lib/repo.php" }, files: [
    { path: "lib/repo.php", content: `<?php\nclass Repo {\n  public static function find($c, $id) { mysqli_query($c, "SELECT * FROM u WHERE id = " . $id); }\n}\n` },
    PHP_PAGE("index.php", `require __DIR__ . '/lib/repo.php';\nRepo::find($c, $_GET['id']);`)] },
  { name: "negative: a user class's find() is not a MongoDB find()", language: "php", expect: { kind: "tn", id: "nosql-injection" }, files: [
    { path: "lib/repo.php", content: `<?php\nclass Repo {\n  public function find($id) { return $this->items[(int) $id] ?? null; }\n}\n` },
    PHP_PAGE("index.php", `require __DIR__ . '/lib/repo.php';\n$repo = new Repo();\n$repo->find($_GET['id']);`)] },
  { name: "wrong-class sanitiser in the caller (htmlspecialchars before SQL)", language: "php", expect: { kind: "tp", file: "index.php", id: "sql-injection", sinkFile: "lib/db.php" }, files: [
    PHP_LIB, PHP_PAGE("index.php", `require __DIR__ . '/lib/db.php';\nfind($c, htmlspecialchars($_GET['id']));`)] },
];

export const CROSS_FILE_CASES: CrossFileCase[] = [...TS, ...PY, ...JAVA, ...CSHARP, ...GO, ...PHP, ...HARD];
