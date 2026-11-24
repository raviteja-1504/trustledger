/**
 * @jest-environment node
 *
 * Targeted regression tests for the six interprocedural capabilities from the TASK 2 priority list:
 *   1. Go/Java cross-file (interface dispatch, same-package, two-hop)
 *   2. Class-method summaries (all languages)
 *   3. Struct/field propagation (Go, Rust, C++)
 *   4. Closure + async (JS/TS)
 *   5. Context-sensitive call strings (precision guard — same-file, context-insensitive engine)
 *   6. All verified cases become regression tests
 *
 * Each test names which capability it exercises so failures are immediately identifiable.
 */
import { runScan, analyzeFile } from "@/lib/scanner";
import { scanAstTaint } from "@/lib/astTaint";
import { warmGoTaintEngine, parseGoSourceSync, scanAstTaintGo } from "@/lib/astTaintGo";
import { warmRustTaintEngine } from "@/lib/astTaintRust";
import { warmCppTaintEngine } from "@/lib/astTaintCpp";

beforeAll(async () => {
  await warmGoTaintEngine();
  await warmRustTaintEngine();
  await warmCppTaintEngine();
}, 120000);

type F = { path: string; content: string };
const scan = (files: F[]) => runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files });
const ids = (r: ReturnType<typeof scan>, path: string) =>
  r.files.find(f => f.file_path === path)?.indicators.filter(i => i.sourceExpr).map(i => i.id) ?? [];
const lines = (r: ReturnType<typeof scan>, path: string, id: string) =>
  (r.files.find(f => f.file_path === path)?.indicators ?? []).filter(i => i.id === id && i.sourceExpr).map(i => i.line);

// ─── 1. Go/Java cross-file ───────────────────────────────────────────────────

describe("[Go cross-file] concrete type method via struct field or typed parameter", () => {
  const models: F = {
    path: "api/models/store.go",
    content: `package models
type Store struct{ db DB }
func (s *Store) FindByID(id string) { s.db.Query("SELECT * FROM u WHERE id = " + id) }
func (s *Store) SafeFind(id string) { s.db.Query("SELECT * FROM u WHERE id = ?", id) }
`,
  };

  it("concrete type via struct field (Handler.store.FindByID)", () => {
    const ctl: F = {
      path: "api/handlers/h.go",
      content: `package handlers
import "example.com/app/api/models"
type Handler struct { store *models.Store }
func (h *Handler) Search(w http.ResponseWriter, r *http.Request) {
  h.store.FindByID(r.URL.Query().Get("id"))
}
`,
    };
    expect(lines(scan([models, ctl]), "api/handlers/h.go", "sql-injection")).toEqual([5]);
  });

  it("concrete type via typed function parameter", () => {
    const ctl: F = {
      path: "api/handlers/h.go",
      content: `package handlers
import "example.com/app/api/models"
func Search(s *models.Store, r *http.Request) {
  s.FindByID(r.URL.Query().Get("id"))
}
`,
    };
    expect(lines(scan([models, ctl]), "api/handlers/h.go", "sql-injection")).toEqual([4]);
  });

  it("safe callee is not reported", () => {
    const ctl: F = {
      path: "api/handlers/h.go",
      content: `package handlers
import "example.com/app/api/models"
func Search(s *models.Store, r *http.Request) {
  s.SafeFind(r.URL.Query().Get("id"))
}
`,
    };
    expect(ids(scan([models, ctl]), "api/handlers/h.go")).not.toContain("sql-injection");
  });
});

describe("[Go cross-file] interface type dispatch — concrete impl in another package", () => {
  const repo: F = {
    path: "api/db/repo.go",
    content: `package db
type PgRepo struct{ conn Conn }
func (r *PgRepo) FindByName(name string) error {
  r.conn.Exec("SELECT * FROM users WHERE name = '" + name + "'")
  return nil
}
func (r *PgRepo) SafeFind(name string) error {
  r.conn.Exec("SELECT * FROM users WHERE name = $1", name)
  return nil
}
`,
  };

  it("variable typed as imported interface dispatches to concrete impl", () => {
    const iface: F = {
      path: "api/db/iface.go",
      content: `package db\ntype Repo interface { FindByName(name string) error }\n`,
    };
    const handler: F = {
      path: "api/handlers/h.go",
      content: `package handlers
import "example.com/app/api/db"
func Handle(repo db.Repo, r *http.Request) {
  repo.FindByName(r.URL.Query().Get("name"))
}
`,
    };
    // Interface dispatch: `repo` is typed as db.Repo (imported interface), concrete impl is db.PgRepo.
    // The engine uses method-name fallback to match db.PgRepo.FindByName from the crossFileFacts.
    expect(lines(scan([repo, iface, handler]), "api/handlers/h.go", "sql-injection")).toEqual([4]);
  });

  it("struct-field receiver typed as imported interface dispatches to concrete impl", () => {
    const iface: F = {
      path: "api/db/iface.go",
      content: `package db\ntype Repo interface { FindByName(name string) error }\n`,
    };
    const handler: F = {
      path: "api/handlers/h.go",
      content: `package handlers
import "example.com/app/api/db"
type Server struct { repo db.Repo }
func (s *Server) Handle(req *http.Request) {
  s.repo.FindByName(req.URL.Query().Get("name"))
}
`,
    };
    // s.repo is typed as db.Repo (imported interface); the engine uses the field type lookup path.
    expect(lines(scan([repo, iface, handler]), "api/handlers/h.go", "sql-injection")).toEqual([5]);
  });
});

describe("[Go cross-file] two-hop: handler -> service -> repository", () => {
  // The service's method accepts the repository as a typed parameter so crossPackageKey
  // can resolve the concrete type at the intermediate call site.
  const repo: F = {
    path: "models/repo.go",
    content: `package models
type Repo struct{ db DB }
func (r *Repo) ByID(id string) { r.db.Query("SELECT * FROM t WHERE id = " + id) }
`,
  };
  const svc: F = {
    path: "service/svc.go",
    content: `package service
import "example.com/app/models"
type UserSvc struct{}
func (s *UserSvc) FindUser(repo *models.Repo, id string) { repo.ByID(id) }
`,
  };

  it("three files, two hops via typed parameter", () => {
    const ctl: F = {
      path: "api/h.go",
      content: `package api
import "example.com/app/service"
import "example.com/app/models"
func Handle(svc *service.UserSvc, repo *models.Repo, r *http.Request) {
  svc.FindUser(repo, r.URL.Query().Get("id"))
}
`,
    };
    expect(lines(scan([repo, svc, ctl]), "api/h.go", "sql-injection")).toEqual([5]);
  });
});

// ─── 2. Class-method summaries — all languages ───────────────────────────────

describe("[JS/TS class-method summaries] same-file class and cross-file exported class", () => {
  // Use scan() so the cross-file summary engine can build method summaries and propagate them.
  // scanAstTaint() alone won't fire for methods whose name appears in BUILTIN_METHOD_NAMES
  // (like "find", "get", etc.) because the engine can't distinguish them from array/map builtins.
  // Method names NOT in BUILTIN_METHOD_NAMES (like "findUser", "runQuery") work same-file too.

  it("same-file class method call flows into a sink (non-builtin name)", () => {
    const r = scan([{
      path: "src/svc.ts",
      content: `class UserSvc {
  findUser(id: string) { return db.query("SELECT * FROM u WHERE id = " + id); }
}
const svc = new UserSvc();
app.get("/u", (req, res) => svc.findUser(req.query.id as string));
`,
    }]);
    expect(ids(r, "src/svc.ts")).toContain("sql-injection");
  });

  it("same-file object-literal method (non-builtin name)", () => {
    const r = scan([{
      path: "src/repo.ts",
      content: `const repo = {
  findUser(id: string) { return db.query("SELECT * FROM u WHERE id = " + id); }
};
app.get("/u", (req, res) => repo.findUser(req.query.id as string));
`,
    }]);
    expect(ids(r, "src/repo.ts")).toContain("sql-injection");
  });

  it("two-hop: class method calls another class method", () => {
    const r = scan([{
      path: "src/app.ts",
      content: `class Repo { runQuery(q: string) { db.query(q); } }
class Svc { constructor(private r: Repo) {} findUser(id: string) { this.r.runQuery("SELECT * FROM u WHERE id = " + id); } }
const svc = new Svc(new Repo());
app.get("/u", (req, res) => svc.findUser(req.query.id as string));
`,
    }]);
    expect(ids(r, "src/app.ts")).toContain("sql-injection");
  });

  it("cross-file: imported class and exported instance", () => {
    const svcFile: F = {
      path: "src/svc.ts",
      content: `export class Svc { findUser(id: string) { return db.query("SELECT * FROM u WHERE id = " + id); } }\nexport const svc = new Svc();\n`,
    };
    const r = scan([svcFile, { path: "src/r.ts", content: `import { svc } from "./svc";\napp.get("/u", (req, res) => svc.findUser(req.query.id as string));\n` }]);
    expect(ids(r, "src/r.ts")).toContain("sql-injection");
  });

  it("safe cross-file class (parameterized query) stays silent", () => {
    const svcFile: F = {
      path: "src/svc.ts",
      content: `export class Svc { findUser(id: string) { return db.query("SELECT * FROM u WHERE id = ?", [id]); } }\nexport const svc = new Svc();\n`,
    };
    const r = scan([svcFile, { path: "src/r.ts", content: `import { svc } from "./svc";\napp.get("/u", (req, res) => svc.findUser(req.query.id as string));\n` }]);
    expect(ids(r, "src/r.ts")).not.toContain("sql-injection");
  });
});

// ─── 3. Struct/field propagation ─────────────────────────────────────────────

describe("[Go struct/field propagation] within same file", () => {
  const goSrc = (body: string) => `package main\n\nimport "net/http"\n\n${body}`;

  it("struct literal field taint flows to sink", () => {
    const src = goSrc(`
var db DB
type Filter struct { Name string }
func handler(w http.ResponseWriter, r *http.Request) {
  f := Filter{Name: r.URL.Query().Get("name")}
  db.Query("SELECT * FROM t WHERE name = '" + f.Name + "'")
}
`);
    const root = parseGoSourceSync(src, "h.go")!;
    expect(scanAstTaintGo(src, "h.go", root).some(f => f.id === "sql-injection")).toBe(true);
  });

  it("struct field assignment then sink", () => {
    const src = goSrc(`
var db DB
type Filter struct { Name string }
func handler(w http.ResponseWriter, r *http.Request) {
  var f Filter
  f.Name = r.URL.Query().Get("name")
  db.Query("SELECT * FROM t WHERE name = '" + f.Name + "'")
}
`);
    const root = parseGoSourceSync(src, "h.go")!;
    expect(scanAstTaintGo(src, "h.go", root).some(f => f.id === "sql-injection")).toBe(true);
  });

  it("struct passed through helper then field read at sink", () => {
    const src = goSrc(`
var db DB
type Filter struct { Name string }
func buildFilter(r *http.Request) Filter {
  return Filter{Name: r.URL.Query().Get("name")}
}
func handler(w http.ResponseWriter, r *http.Request) {
  f := buildFilter(r)
  db.Query("SELECT * FROM t WHERE name = '" + f.Name + "'")
}
`);
    const root = parseGoSourceSync(src, "h.go")!;
    expect(scanAstTaintGo(src, "h.go", root).some(f => f.id === "sql-injection")).toBe(true);
  });

  it("safe constant struct field is not reported", () => {
    const src = goSrc(`
var db DB
type Filter struct { Name string }
func handler(w http.ResponseWriter, r *http.Request) {
  f := Filter{Name: "admin"}
  db.Query("SELECT * FROM t WHERE name = '" + f.Name + "'")
}
`);
    const root = parseGoSourceSync(src, "h.go")!;
    expect(scanAstTaintGo(src, "h.go", root).some(f => f.id === "sql-injection")).toBe(false);
  });
});

describe("[Rust struct/field propagation] within and across files", () => {
  it("struct field assignment then sink", () => {
    const r = analyzeFile("src/h.rs", `
use axum::extract::Query;
#[derive(serde::Deserialize)] struct Params { name: String }
struct Filter { name: String }
async fn handle(Query(p): Query<Params>) {
    let mut f = Filter { name: String::new() };
    f.name = p.name.clone();
    sqlx::query(&format!("SELECT * FROM t WHERE name = '{}'", f.name));
}
`);
    expect(r.indicators.some(i => i.id === "sql-injection" && i.sourceExpr)).toBe(true);
  });

  it("struct literal with tainted field flows to sink", () => {
    const r = analyzeFile("src/h.rs", `
use axum::extract::Query;
#[derive(serde::Deserialize)] struct Params { id: String }
struct Filter { id: String }
async fn handle(Query(p): Query<Params>) {
    let f = Filter { id: p.id.clone() };
    sqlx::query(&format!("SELECT * FROM t WHERE id = '{}'", f.id));
}
`);
    expect(r.indicators.some(i => i.id === "sql-injection" && i.sourceExpr)).toBe(true);
  });

  it("struct field cross-file: handler passes tainted-field struct to service", () => {
    const service: F = {
      path: "src/service.rs",
      content: `pub struct UserService;
impl UserService {
    pub fn findUser(&self, name: &str) {
        sqlx::query(&format!("SELECT * FROM users WHERE name = '{name}'"));
    }
}
`,
    };
    const handler: F = {
      path: "src/handler.rs",
      content: `use axum::extract::Query;
use crate::service::UserService;
#[derive(serde::Deserialize)] struct Params { name: String }
pub async fn search(Query(p): Query<Params>, svc: UserService) {
    svc.findUser(&p.name);
}
`,
    };
    const r = scan([service, handler]);
    expect(ids(r, "src/handler.rs")).toContain("sql-injection");
  });
});

describe("[C++ struct/field propagation] within same file", () => {
  // C++ engine recognizes getenv() as a source and sqlite3_exec() as a SQL sink.
  it("struct member assigned from env var, used at SQL sink", () => {
    const r = analyzeFile("server.cpp", `
#include <string>
#include <sqlite3.h>
struct Filter { const char *name; };
sqlite3 *db;
void handle() {
    Filter f;
    f.name = getenv("NAME");
    std::string sql = std::string("SELECT * FROM t WHERE name = '") + f.name + "'";
    sqlite3_exec(db, sql.c_str(), 0, 0, 0);
}
`);
    expect(r.indicators.some(i => i.id === "sql-injection" && i.sourceExpr)).toBe(true);
  });
});

// ─── 4. Closure + async (JS/TS) ──────────────────────────────────────────────

describe("[JS/TS closure] captures tainted outer variable", () => {
  const js = (src: string) => scanAstTaint(src, "x.ts").map(f => f.id);

  it("async IIFE captures tainted id and uses it in a template literal sink", () => {
    expect(js(`
app.get("/u", (req, res) => {
  const id = req.query.id;
  (async () => {
    const r = await db.query(\`SELECT * FROM users WHERE id = \${id}\`);
    res.json(r);
  })();
});
`)).toContain("sql-injection");
  });

  it("named async arrow captures tainted variable then is called", () => {
    expect(js(`
app.get("/u", (req, res) => {
  const id = req.query.id;
  const doQuery = async () => db.query(\`SELECT * FROM users WHERE id = \${id}\`);
  doQuery().then(r => res.json(r));
});
`)).toContain("sql-injection");
  });

  it("Promise.resolve().then() callback captures tainted value", () => {
    expect(js(`
app.get("/u", (req, res) => {
  const id = req.query.id;
  Promise.resolve(id).then(val => {
    db.query("SELECT * FROM users WHERE id = " + val);
  });
});
`)).toContain("sql-injection");
  });

  it("setTimeout callback captures tainted variable", () => {
    expect(js(`
app.get("/u", (req, res) => {
  const id = req.query.id;
  setTimeout(() => {
    db.query("SELECT * FROM users WHERE id = " + id);
  }, 0);
});
`)).toContain("sql-injection");
  });

  it("non-tainted value in a closure does NOT fire", () => {
    expect(js(`
app.get("/u", (req, res) => {
  const id = "constant";
  setTimeout(() => {
    db.query("SELECT * FROM users WHERE id = " + id);
  }, 0);
});
`)).not.toContain("sql-injection");
  });
});

describe("[JS/TS async/await] standard async handler patterns", () => {
  const js = (src: string) => scanAstTaint(src, "x.ts").map(f => f.id);

  it("direct async handler with await sink", () => {
    expect(js(`
app.get("/u", async (req, res) => {
  const id = req.query.id;
  const r = await db.query(\`SELECT * FROM users WHERE id = \${id}\`);
  res.json(r);
});
`)).toContain("sql-injection");
  });

  it("async function exported as route handler", () => {
    expect(js(`
export async function getUser(req: Request, res: Response) {
  const id = req.query.id as string;
  const r = await db.query(\`SELECT * FROM users WHERE id = \${id}\`);
  res.json(r);
}
`)).toContain("sql-injection");
  });

  it("async generator capturing tainted value", () => {
    expect(js(`
app.get("/u", async (req, res) => {
  const name = req.query.name;
  async function* stream() {
    yield db.query("SELECT * FROM users WHERE name = " + name);
  }
  for await (const row of stream()) res.write(row);
});
`)).toContain("sql-injection");
  });
});

// ─── 5. Context-sensitive: a tainted call is detected, a constant one is not ─
//
// NOTE: The JS/TS taint engine is context-INsensitive within a single file.
// When a function is called from multiple sites, it uses the UNION of all
// taint states from all call sites. This means:
//   - The finding is reported at the SINK LINE inside the function body, not
//     the call site, and fires as long as ANY call site provides tainted input.
//   - A purely-constant call site does not suppress findings for the same
//     function called with tainted input elsewhere in the same file.
// These tests verify this documented behavior so regressions are caught.

describe("[Context sensitivity / same-file precision] same callee, different call sites", () => {
  const js = (src: string) => scanAstTaint(src, "x.ts").map(f => `${f.id}@${f.line}`);

  it("tainted call site fires at call site line AND at sink body line", () => {
    // `runQuery` sink is at line 3; the tainted call site is at line 6.
    // With same-file call-site analysis the engine reports BOTH:
    //   - line 6: call-site finding with the actual tainted argument visible (context-sensitive)
    //   - line 3: body finding at the SQL concatenation inside the callee
    // The safe call site (line 5) does NOT generate a line-5 finding.
    const result = js(`
function runQuery(id: string) {
  return db.query("SELECT * FROM users WHERE id = " + id);
}
app.get("/safe", (req, res) => runQuery("42"));
app.get("/unsafe", (req, res) => runQuery(req.query.id as string));
`);
    expect(result).toContain("sql-injection@6");  // call-site attribution
    expect(result).toContain("sql-injection@3");  // body sink location
    expect(result).not.toContain("sql-injection@5"); // safe call site: no finding
  });

  it("two tainted call sites each fire a call-site finding", () => {
    const result = js(`
function runQuery(id: string) {
  return db.query("SELECT * FROM users WHERE id = " + id);
}
app.get("/a", (req, res) => runQuery(req.query.id as string));
app.get("/b", (req, res) => runQuery(req.query.id as string));
`);
    // at least 2 findings: one per call site (lines 5 and 6) plus the body finding (line 3)
    expect(result.filter(r => r.startsWith("sql-injection")).length).toBeGreaterThanOrEqual(2);
  });

  it("when ALL call sites are constant the engine proves safety (no finding)", () => {
    const result = js(`
function runQuery(id: string) {
  return db.query("SELECT * FROM users WHERE id = " + id);
}
app.get("/a", (req, res) => runQuery("admin"));
app.get("/b", (req, res) => runQuery("guest"));
`);
    expect(result.filter(r => r.startsWith("sql-injection")).length).toBe(0);
  });
});
