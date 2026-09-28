import { runScan } from "@/lib/scanner";
import { scanAstTaint } from "@/lib/astTaint";
import { warmPythonTaintEngine } from "@/lib/astTaintPython";
import { warmGoTaintEngine } from "@/lib/astTaintGo";
import { warmCSharpTaintEngine } from "@/lib/astTaintCSharp";
import { warmPhpTaintEngine } from "@/lib/astTaintPHP";

beforeAll(async () => {
  await warmPythonTaintEngine(); await warmGoTaintEngine(); await warmCSharpTaintEngine(); await warmPhpTaintEngine();
}, 60000);

// Cross-file taint through the SERVICE LAYER (controller -> service -> repository): methods of exported
// classes, instances and object literals, resolved at the call site from the receiver -- an imported instance
// or class, `new C()`, a typed parameter, or an injected field (NestJS/Angular constructor parameter
// properties). Only plain exported functions used to carry summaries across files.

type F = { path: string; content: string };
const dataFlowLines = (files: F[], path: string, id = "sql-injection") => {
  const r = runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files });
  return (r.files.find(f => f.file_path === path)?.indicators ?? []).filter(i => i.id === id && i.sourceExpr).map(i => i.line);
};

const SVC = `export class UserService {\n  find(id) { return db.query("SELECT * FROM u WHERE id = " + id); }\n}\nexport const userService = new UserService();\n`;
const svcFile = { path: "src/svc.ts", content: SVC };

describe("JS/TS service-layer calls across files", () => {
  it("an imported singleton instance", () => {
    expect(dataFlowLines([svcFile, { path: "src/r.ts", content: `import { userService } from "./svc";\napp.get("/u", (req, res) => userService.find(req.query.id));\n` }], "src/r.ts")).toEqual([2]);
  });
  it("an imported class instantiated at the call site, including under an alias", () => {
    expect(dataFlowLines([svcFile, { path: "src/r.ts", content: `import { UserService } from "./svc";\nconst svc = new UserService();\napp.get("/u", (req, res) => svc.find(req.query.id));\n` }], "src/r.ts")).toEqual([3]);
    expect(dataFlowLines([svcFile, { path: "src/r.ts", content: `import { UserService as Svc } from "./svc";\napp.get("/u", (req, res) => new Svc().find(req.query.id));\n` }], "src/r.ts")).toEqual([2]);
  });
  it("a default-exported class", () => {
    const svc = { path: "src/svc.ts", content: `export default class UserService {\n  find(id) { return db.query("SELECT * FROM u WHERE id = " + id); }\n}\n` };
    expect(dataFlowLines([svc, { path: "src/r.ts", content: `import UserService from "./svc";\nconst s = new UserService();\napp.get("/u", (req, res) => s.find(req.query.id));\n` }], "src/r.ts")).toEqual([3]);
  });
  it("static methods and object-literal modules", () => {
    const repo = { path: "src/repo.ts", content: `export class Repo {\n  static find(id) { return db.query("SELECT * FROM u WHERE id = " + id); }\n}\nexport const store = {\n  find(id) { return db.query("SELECT * FROM u WHERE id = " + id); },\n};\n` };
    expect(dataFlowLines([repo, { path: "src/r.ts", content: `import { Repo, store } from "./repo";\napp.get("/a", (req, res) => Repo.find(req.query.id));\napp.get("/b", (req, res) => store.find(req.query.id));\n` }], "src/r.ts")).toEqual([2, 3]);
  });
  it("a typed parameter, and a NestJS-style injected constructor parameter property", () => {
    expect(dataFlowLines([svcFile, { path: "src/r.ts", content: `import { UserService } from "./svc";\nexport function route(svc: UserService) { return (req, res) => svc.find(req.query.id); }\n` }], "src/r.ts")).toEqual([2]);
    const nestSvc = { path: "src/users.service.ts", content: "export class UsersService {\n  findOne(id: string) { return this.repo.query(`SELECT * FROM users WHERE id = ${id}`); }\n}\n" };
    const nestCtl = { path: "src/users.controller.ts", content: `import { UsersService } from "./users.service";\nexport class UsersController {\n  constructor(private readonly usersService: UsersService) {}\n  get(req) { return this.usersService.findOne(req.query.id); }\n}\n` };
    expect(dataFlowLines([nestSvc, nestCtl], "src/users.controller.ts")).toEqual([4]);
  });
  it("two hops: controller -> service -> repository", () => {
    const repo = { path: "src/repo.ts", content: `export class Repo {\n  byId(id) { return db.query("SELECT * FROM u WHERE id = " + id); }\n}\nexport const repo = new Repo();\n` };
    const svc = { path: "src/svc.ts", content: `import { repo } from "./repo";\nexport class UserService {\n  find(id) { return repo.byId(id); }\n}\nexport const userService = new UserService();\n` };
    expect(dataFlowLines([repo, svc, { path: "src/r.ts", content: `import { userService } from "./svc";\napp.get("/u", (req, res) => userService.find(req.query.id));\n` }], "src/r.ts")).toEqual([2]);
  });
  it("never matches by bare method name: an array's .find() is not the service's find()", () => {
    expect(dataFlowLines([svcFile, { path: "src/r.ts", content: `import { userService } from "./svc";\napp.get("/u", (req, res) => { const users = []; users.find(req.query.id); });\n` }], "src/r.ts")).toEqual([]);
  });
  it("...even when a sinking FUNCTION named find is imported into the same file", () => {
    const db = { path: "src/db.ts", content: `export function find(id) { return db.query("SELECT * FROM u WHERE id = " + id); }\n` };
    expect(dataFlowLines([db, { path: "src/r.ts", content: `import { find } from "./db";\napp.get("/u", (req, res) => { const users = []; users.find(req.query.id); });\n` }], "src/r.ts")).toEqual([]);
  });
  it("a service method that uses a parameterized query is not reported", () => {
    const safe = { path: "src/svc.ts", content: `export class UserService {\n  find(id) { return db.query("SELECT * FROM u WHERE id = ?", [id]); }\n}\nexport const userService = new UserService();\n` };
    expect(dataFlowLines([safe, { path: "src/r.ts", content: `import { userService } from "./svc";\napp.get("/u", (req, res) => userService.find(req.query.id));\n` }], "src/r.ts")).toEqual([]);
  });
});

describe("JS/TS SQL sink precision", () => {
  const ids = (src: string) => scanAstTaint(src, "x.ts").map(f => f.id);
  it("bound values are parameters, not SQL text", () => {
    expect(ids(`app.get("/u", (req, res) => { db.query("SELECT * FROM u WHERE id = ?", [req.query.id]); })`)).toEqual([]);
    expect(ids(`app.get("/u", (req, res) => { pool.query({ text: "SELECT * FROM u WHERE id = $1", values: [req.query.id] }); })`)).toEqual([]);
    expect(ids(`app.get("/u", (req, res) => { sequelize.query("SELECT * FROM u WHERE id = :id", { replacements: { id: req.query.id } }); })`)).toEqual([]);
  });
  it("tainted SQL text is still reported, including inside an options object", () => {
    expect(ids(`app.get("/u", (req, res) => { db.query("SELECT * FROM u WHERE id = " + req.query.id); })`)).toEqual(["sql-injection"]);
    expect(ids(`app.get("/u", (req, res) => { pool.query({ text: "SELECT * FROM u WHERE id = " + req.query.id }); })`)).toEqual(["sql-injection"]);
  });
  it("a database client held on the class (this.db / this.repo / this.users)", () => {
    expect(ids(`class S { find(req) { this.db.query("SELECT * FROM u WHERE id = " + req.query.id); } }`)).toEqual(["sql-injection"]);
    expect(ids(`class S { find(req) { this.users.find({ name: req.body.name }); } }`)).toEqual(["nosql-injection"]);
  });
  it("...but not the class's own method, nor a non-DB method on a field", () => {
    expect(ids(`class S { find(req) { this.query("x" + req.query.id); } query(s) {} }`)).toEqual([]);
    expect(ids(`class S { find(req) { this.pattern.exec(req.query.id); } }`)).toEqual([]);
  });
});

// ── Other engines: the same service-layer shapes, each keyed the way that language resolves a callee ──

describe("Python service-layer calls across files", () => {
  const svc = { path: "app/svc.py", content: `class UserService:\n    def find(self, i):\n        cursor.execute("SELECT * FROM u WHERE id = " + i)\n\nuser_service = UserService()\n` };
  const view = (body: string, imp = "from app.svc import UserService") => ({ path: "app/views.py", content: `${imp}\ndef v(request):\n${body}\n` });
  it("instance at the call site, a local instance, an imported module-level instance, an aliased class", () => {
    expect(dataFlowLines([svc, view(`    UserService().find(request.GET.get("id"))`)], "app/views.py")).toEqual([3]);
    expect(dataFlowLines([svc, view(`    s = UserService()\n    s.find(request.GET.get("id"))`)], "app/views.py")).toEqual([4]);
    expect(dataFlowLines([svc, view(`    user_service.find(request.GET.get("id"))`, "from app.svc import user_service")], "app/views.py")).toEqual([3]);
    expect(dataFlowLines([svc, view(`    S().find(request.GET.get("id"))`, "from app.svc import UserService as S")], "app/views.py")).toEqual([3]);
  });
  it("a service injected through __init__ with a type annotation, and two hops view -> service -> repo", () => {
    expect(dataFlowLines([svc, { path: "app/views.py", content: `from app.svc import UserService\nclass V:\n    def __init__(self, svc: UserService):\n        self.svc = svc\n    def get(self, request):\n        self.svc.find(request.GET.get("id"))\n` }], "app/views.py")).toEqual([6]);
    const repo = { path: "app/repo.py", content: `class Repo:\n    def by_id(self, i):\n        cursor.execute("SELECT * FROM u WHERE id = " + i)\n` };
    const svc2 = { path: "app/svc.py", content: `from app.repo import Repo\nclass UserService:\n    def __init__(self):\n        self.repo = Repo()\n    def find(self, i):\n        self.repo.by_id(i)\n` };
    expect(dataFlowLines([repo, svc2, view(`    UserService().find(request.GET.get("id"))`)], "app/views.py")).toEqual([3]);
  });
  it("a parameterized service query, and an unrelated str.find, are not reported", () => {
    const safe = { path: "app/svc.py", content: `class UserService:\n    def find(self, i):\n        cursor.execute("SELECT * FROM u WHERE id = %s", (i,))\n` };
    expect(dataFlowLines([safe, view(`    UserService().find(request.GET.get("id"))`)], "app/views.py")).toEqual([]);
    expect(dataFlowLines([svc, view(`    s = "abc"\n    s.find(request.GET.get("id"))`)], "app/views.py")).toEqual([]);
  });
});

describe("Java service-layer calls across files", () => {
  const svc = { path: "UserService.java", content: `@Service public class UserService {\n  public void find(String id) throws Exception { stmt.executeQuery("SELECT * FROM u WHERE id = " + id); }\n}\n` };
  const ctl = (field: string, call: string) => ({ path: "UserController.java", content: `@RestController public class UserController {\n${field}\n  @GetMapping("/u") public void a(@RequestParam String id) throws Exception { ${call}; }\n}\n` });
  it("an @Autowired field and a constructor-injected final field", () => {
    expect(dataFlowLines([svc, ctl(`  @Autowired private UserService userService;`, `userService.find(id)`)], "UserController.java")).toEqual([3]);
    expect(dataFlowLines([svc, ctl(`  private final UserService s;\n  public UserController(UserService s) { this.s = s; }`, `this.s.find(id)`)], "UserController.java")).toEqual([4]);
  });
  it("two hops: controller -> service -> repository", () => {
    const repo = { path: "UserRepo.java", content: `@Repository public class UserRepo {\n  public void byId(String id) throws Exception { stmt.executeQuery("SELECT * FROM u WHERE id = " + id); }\n}\n` };
    const svc2 = { path: "UserService.java", content: `@Service public class UserService {\n  @Autowired private UserRepo repo;\n  public void find(String id) throws Exception { repo.byId(id); }\n}\n` };
    expect(dataFlowLines([repo, svc2, ctl(`  @Autowired private UserService userService;`, `userService.find(id)`)], "UserController.java")).toEqual([3]);
  });
  it("a PreparedStatement service, and a same-named method on an unrelated type, are not reported", () => {
    const safe = { path: "UserService.java", content: `@Service public class UserService {\n  public void find(String id) throws Exception { PreparedStatement p = conn.prepareStatement("SELECT * FROM u WHERE id = ?"); p.setString(1, id); p.executeQuery(); }\n}\n` };
    expect(dataFlowLines([safe, ctl(`  @Autowired private UserService userService;`, `userService.find(id)`)], "UserController.java")).toEqual([]);
    expect(dataFlowLines([svc, ctl(`  @Autowired private OtherService other;`, `other.find(id)`)], "UserController.java")).toEqual([]);
  });
});

describe("C# service-layer calls across files", () => {
  const svc = { path: "UserService.cs", content: `public class UserService {\n  public void Find(string id) { new SqlCommand("SELECT * FROM u WHERE id = " + id, conn).ExecuteReader(); }\n}\n` };
  const ctl = (members: string, call: string) => ({ path: "UserController.cs", content: `[ApiController] public class UserController : ControllerBase {\n${members}\n  [HttpGet] public IActionResult A([FromQuery] string id) { ${call}; return Ok(); }\n}\n` });
  it("a constructor-injected readonly field, and an interface-typed field", () => {
    expect(dataFlowLines([svc, ctl(`  private readonly UserService _svc;\n  public UserController(UserService svc) { _svc = svc; }`, `_svc.Find(id)`)], "UserController.cs")).toEqual([4]);
    const iface = { path: "UserService.cs", content: `public class UserService : IUserService {\n  public void Find(string id) { new SqlCommand("SELECT * FROM u WHERE id = " + id, conn).ExecuteReader(); }\n}\n` };
    expect(dataFlowLines([iface, ctl(`  private readonly IUserService _svc;`, `_svc.Find(id)`)], "UserController.cs")).toEqual([3]);
  });
  it("a C# 12 primary-constructor parameter (attributes included)", () => {
    const primary = { path: "UserController.cs", content: `[ApiController] public class UserController([FromServices] UserService svc) : ControllerBase {\n  [HttpGet] public IActionResult A([FromQuery] string id) { svc.Find(id); return Ok(); }\n}\n` };
    expect(dataFlowLines([svc, primary], "UserController.cs")).toEqual([2]);
  });
  it("an EF-parameterized service query, and an unrelated type's Find, are not reported", () => {
    const safe = { path: "UserService.cs", content: `public class UserService {\n  public void Find(string id) { db.Users.FromSqlInterpolated($"SELECT * FROM u WHERE id = {id}").ToList(); }\n}\n` };
    expect(dataFlowLines([safe, ctl(`  private readonly UserService _svc;`, `_svc.Find(id)`)], "UserController.cs")).toEqual([]);
    expect(dataFlowLines([svc, ctl(`  private readonly OtherThing _o;`, `_o.Find(id)`)], "UserController.cs")).toEqual([]);
  });
});

describe("Go calls into another package", () => {
  const models = { path: "api/models/store.go", content: `package models\ntype Store struct{ db *sql.DB }\nfunc (s *Store) Find(id string) { s.db.Query("SELECT * FROM u WHERE id = " + id) }\nfunc Safe(db *sql.DB, id string) { db.Query("SELECT * FROM u WHERE id = ?", id) }\nfunc Chain(db *sql.DB, id string) { Find(db, id) }\nfunc Find(db *sql.DB, id string) { db.Query("SELECT * FROM u WHERE id = " + id) }\n` };
  const ctl = (body: string, head = `import "example.com/app/api/models"`) => ({ path: "api/c/user.go", content: `package c\n${head}\n${body}\n` });
  const H = (call: string) => `func H(w http.ResponseWriter, r *http.Request) { ${call} }`;
  it("a package function, including through an aliased import and a same-package forwarder", () => {
    expect(dataFlowLines([models, ctl(H(`models.Find(db, r.URL.Query().Get("id"))`))], "api/c/user.go")).toEqual([3]);
    expect(dataFlowLines([models, ctl(H(`m.Find(db, r.URL.Query().Get("id"))`), `import m "example.com/app/api/models"`)], "api/c/user.go")).toEqual([3]);
    expect(dataFlowLines([models, ctl(H(`models.Chain(db, r.URL.Query().Get("id"))`))], "api/c/user.go")).toEqual([3]);
  });
  it("a method, through a struct field or a typed parameter", () => {
    expect(dataFlowLines([models, ctl(`type Server struct { Store *models.Store }\nfunc (s *Server) H(w http.ResponseWriter, r *http.Request) { s.Store.Find(r.URL.Query().Get("id")) }`)], "api/c/user.go")).toEqual([4]);
    expect(dataFlowLines([models, ctl(`func H(st *models.Store, r *http.Request) { st.Find(r.URL.Query().Get("id")) }`)], "api/c/user.go")).toEqual([3]);
  });
  it("a parameterized callee, and a constant argument, are not reported", () => {
    expect(dataFlowLines([models, ctl(H(`models.Safe(db, r.URL.Query().Get("id"))`))], "api/c/user.go")).toEqual([]);
    expect(dataFlowLines([models, ctl(H(`models.Find(db, "1")`))], "api/c/user.go")).toEqual([]);
  });
  it("a callee that sinks its OWN request input isn't blamed on the caller's argument", () => {
    const own = { path: "api/models/p.go", content: `package models\nfunc Page(r *http.Request, x string) { db.Query("SELECT * FROM u WHERE id = " + r.URL.Query().Get("q")) }\n` };
    expect(dataFlowLines([own, ctl(H(`models.Page(r, r.URL.Query().Get("id"))`))], "api/c/user.go")).toEqual([]);
  });
  it("a decoded filter document passed into a mongo lookup in another package (crAPI's coupon validation)", () => {
    const coupon = { path: "api/models/coupon.go", content: `package models\nfunc ValidateCode(client *mongo.Client, bsonMap bson.M) error {\n\tcollection := client.Database("crapi").Collection("coupons")\n\treturn collection.FindOne(context.TODO(), bsonMap).Err()\n}\n` };
    const handler = (arg: string) => ({ path: "api/c/coupon.go", content: `package c\nimport "example.com/app/api/models"\nfunc V(w http.ResponseWriter, r *http.Request) {\n\tvar bsonMap bson.M\n\tvar c Coupon\n\tbody, _ := ioutil.ReadAll(r.Body)\n\tjson.Unmarshal(body, &bsonMap)\n\tjson.Unmarshal(body, &c)\n\tmodels.ValidateCode(client, ${arg})\n}\n` });
    expect(dataFlowLines([coupon, handler("bsonMap")], "api/c/coupon.go", "nosql-injection")).toEqual([9]);
    // A typed string field inside a literal document can't carry operators.
    expect(dataFlowLines([coupon, handler(`bson.M{"coupon_code": c.CouponCode}`)], "api/c/coupon.go", "nosql-injection")).toEqual([]);
  });
});

describe("PHP functions from included files", () => {
  const lib = { path: "lib/db.php", content: `<?php\nfunction find($c, $id) { mysqli_query($c, "SELECT * FROM u WHERE id = " . $id); }\nfunction safe($c, $id) { mysqli_query($c, "SELECT * FROM u WHERE id = " . intval($id)); }\nfunction chain($c, $id) { return find($c, $id); }\n` };
  const page = (path: string, body: string) => ({ path, content: `<?php\n${body}\n` });
  it("__DIR__-anchored, relative, and constant-prefixed (suffix-matched) includes", () => {
    expect(dataFlowLines([lib, page("index.php", `require_once __DIR__ . '/lib/db.php';\nfind($c, $_GET['id']);`)], "index.php")).toEqual([3]);
    expect(dataFlowLines([lib, page("app/index.php", `include '../lib/db.php';\nfunction h() { chain($c, $_POST['id']); }`)], "app/index.php")).toEqual([3]);
    expect(dataFlowLines([lib, page("app/index.php", `require_once APP_ROOT . 'lib/db.php';\nfind($c, $_GET['id']);`)], "app/index.php")).toEqual([3]);
  });
  it("a transitive include, called case-insensitively", () => {
    expect(dataFlowLines([lib, page("lib/boot.php", `require __DIR__ . '/db.php';`), page("index.php", `require __DIR__ . '/lib/boot.php';\nFIND($c, $_GET['id']);`)], "index.php")).toEqual([3]);
  });
  it("not when the file isn't included, the callee sanitizes, or the argument is constant", () => {
    expect(dataFlowLines([lib, page("index.php", `find($c, $_GET['id']);`)], "index.php")).toEqual([]);
    expect(dataFlowLines([lib, page("index.php", `require __DIR__ . '/lib/db.php';\nsafe($c, $_GET['id']);`)], "index.php")).toEqual([]);
    expect(dataFlowLines([lib, page("index.php", `require __DIR__ . '/lib/db.php';\nfind($c, 5);`)], "index.php")).toEqual([]);
  });
  it("a callee that sinks its OWN request input isn't blamed on the caller's argument", () => {
    const own = { path: "lib/db.php", content: `<?php\nfunction page($c, $x) { mysqli_query($c, "SELECT * FROM u WHERE id = " . $_GET['q']); }\n` };
    expect(dataFlowLines([own, page("index.php", `require __DIR__ . '/lib/db.php';\npage($c, $_GET['id']);`)], "index.php")).toEqual([]);
    expect(dataFlowLines([own, page("index.php", `require __DIR__ . '/lib/db.php';`)], "lib/db.php")).toEqual([2]);
  });
  it("an ambiguous suffix resolves to nothing rather than a guess", () => {
    const other = { path: "other/lib/db.php", content: `<?php\nfunction find($c, $id) { echo "noop"; }\n` };
    expect(dataFlowLines([lib, other, page("app/index.php", `require_once APP_ROOT . 'lib/db.php';\nfind($c, $_GET['id']);`)], "app/index.php")).toEqual([]);
  });
});

describe("incremental cache: a callee's summary change re-analyzes an unchanged caller", () => {
  const scan = (files: F[], prev?: ReturnType<typeof runScan>["file_cache"]) =>
    runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files, prev_results: prev });
  it.each([
    ["Go", { path: "api/models/m.go", content: `package models\nfunc Find(db *sql.DB, id string) { db.Query("SELECT * FROM u WHERE id = " + id) }\n` },
      { path: "api/models/m.go", content: `package models\nfunc Find(db *sql.DB, id string) { db.Query("SELECT * FROM u WHERE id = ?", id) }\n` },
      { path: "api/c/h.go", content: `package c\nimport "example.com/app/api/models"\nfunc H(w http.ResponseWriter, r *http.Request) { models.Find(db, r.URL.Query().Get("id")) }\n` }],
    ["PHP", { path: "lib/db.php", content: `<?php\nfunction find($c, $id) { mysqli_query($c, "SELECT * FROM u WHERE id = " . $id); }\n` },
      { path: "lib/db.php", content: `<?php\nfunction find($c, $id) { mysqli_query($c, "SELECT * FROM u WHERE id = " . intval($id)); }\n` },
      { path: "index.php", content: `<?php\nrequire __DIR__ . '/lib/db.php';\nfind($c, $_GET['id']);\n` }],
  ])("%s", (_lang, vulnerable, fixed, caller) => {
    const hits = (r: ReturnType<typeof runScan>) =>
      (r.files.find(f => f.file_path === caller.path)?.indicators ?? []).filter(i => i.id === "sql-injection" && i.sourceExpr).length;
    const first = scan([vulnerable, caller]);
    expect(hits(first)).toBe(1);
    expect(hits(scan([fixed, caller], first.file_cache))).toBe(0);
  });
});
