/**
 * @jest-environment node
 *
 * Rust engine precision checks from an external review, each with a twin:
 *  - a call runs the function / method of ITS type: `s.build(x)` by s's type (unit struct, `T::new()`, `T { }`,
 *    a typed parameter), `Type::assoc(x)` that impl's, and a sink inside the resolved method is reached;
 *  - local types belong to one function (two functions' `svc` of different types);
 *  - `x.f = v` taints that field, not its siblings -- the object as a whole still carries it;
 *  - a canonicalized path's starts_with only proves containment when the base wasn't chosen by the request;
 *  - BOLA ownership evidence must be about the record the path id loaded.
 */
import { analyzeFile } from "@/lib/scanner";
import { warmRustTaintEngine } from "@/lib/astTaintRust";

beforeAll(async () => { await warmRustTaintEngine(); }, 120000);

const engine = (code: string) => analyzeFile("src/handlers.rs", code).indicators.filter(i => !!i.sourceExpr).map(i => i.id);
const linesOf = (code: string, id: string) => analyzeFile("src/handlers.rs", code).indicators.filter(i => !!i.sourceExpr && i.id === id).map(i => i.line);
const use = `use axum::extract::{Query, Path, Extension, State};\nuse std::process::Command;\n\n`;
const h = (body: string, before = "") => `${use}${before}async fn handler(Query(q): Query<Search>) -> String {\n${body}\n    String::new()\n}\n`;
const sqlLine = (code: string) => code.split("\n").findIndex(l => l.includes("sqlx::query(")) + 1;
const SQL = (v: string) => `    sqlx::query(&${v}).execute(&pool).await.unwrap();`;

describe("a call runs the function or method of its own type", () => {
  const SU = `struct Safe;\nstruct Unsafe;\n\nimpl Safe {\n    fn build(&self, x: &str) -> String {\n        "fixed".to_string()\n    }\n    fn make(x: &str) -> String {\n        "k".into()\n    }\n}\n\nimpl Unsafe {\n    fn build(&self, x: &str) -> String {\n        format!("SELECT * FROM users WHERE id = {}", x)\n    }\n    fn make(x: &str) -> String {\n        format!("SELECT {}", x)\n    }\n}\n\n`;
  it("s.build(x) by s's type: a unit struct, T::new(), T { }", () => {
    for (const ctor of ["Unsafe", "Unsafe::new()", "Unsafe {}"]) {
      const bad = h(`    let s = ${ctor};\n    let query = s.build(&q.name);\n${SQL("query")}`, SU);
      expect(linesOf(bad, "sql-injection")).toContain(sqlLine(bad));
      const good = bad.replace(`let s = ${ctor}`, `let s = ${ctor.replace("Unsafe", "Safe")}`);
      expect(linesOf(good, "sql-injection")).not.toContain(sqlLine(good));
    }
  });
  it("Type::assoc(x) runs that impl's function", () => {
    const bad = h(`    let query = Unsafe::make(&q.name);\n${SQL("query")}`, SU);
    expect(linesOf(bad, "sql-injection")).toContain(sqlLine(bad));
    const good = h(`    let query = Safe::make(&q.name);\n${SQL("query")}`, SU);
    expect(linesOf(good, "sql-injection")).not.toContain(sqlLine(good));
  });
  it("a typed parameter's method, and a sink inside the resolved method", () => {
    const QS = `struct QueryService;\nimpl QueryService {\n    fn build(&self, input: &str) -> String {\n        format!("SELECT * FROM users WHERE name = '{}'", input)\n    }\n}\n\n`;
    const code = `${use}${QS}async fn handler(Extension(service): Extension<QueryService>, Query(q): Query<Search>) -> String {\n    let query = service.build(&q.name);\n${SQL("query")}\n    String::new()\n}\n`;
    expect(linesOf(code, "sql-injection")).toContain(sqlLine(code));
    const RN = `struct Runner;\nstruct Noop;\nimpl Runner { fn run(&self, c: &str) { Command::new("sh").arg("-c").arg(c).status().unwrap(); } }\nimpl Noop { fn run(&self, c: &str) { let _ = c; } }\n\n`;
    expect(engine(h(`    let r = Runner;\n    r.run(&q.cmd);`, RN))).toContain("command-injection");
    expect(engine(h(`    let r = Noop;\n    r.run(&q.cmd);`, RN))).not.toContain("command-injection");
  });
  it("two functions' same-named parameters have their own types", () => {
    const code = use + `struct Safe;\nstruct Unsafe;\nimpl Safe { fn build(&self, x: &str) -> String { "k".to_string() } }\nimpl Unsafe { fn build(&self, x: &str) -> String { format!("SELECT * FROM t WHERE a = '{}'", x) } }\n\nfn query_a(svc: Safe, v: &str) -> String {\n    svc.build(v)\n}\n\nfn query_b(svc: Unsafe, v: &str) -> String {\n    svc.build(v)\n}\n\nasync fn h1(Query(q): Query<Search>) -> String {\n    let s = query_a(Safe, &q.name);\n    sqlx::query(&s).execute(&pool).await.unwrap();\n    String::new()\n}\n\nasync fn h2(Query(q): Query<Search>) -> String {\n    let s = query_b(Unsafe, &q.name);\n    sqlx::query(&s).execute(&pool).await.unwrap();\n    String::new()\n}\n`;
    const lines = code.split("\n");
    const at = (needle: string) => lines.findIndex(l => l.includes(needle)) + 2;
    const found = linesOf(code, "sql-injection");
    expect(found).toContain(at("query_b(Unsafe"));
    expect(found).not.toContain(at("query_a(Safe"));
  });
  it("another function's local type doesn't carry over to a name this one binds differently", () => {
    // (`shape`, not a builder-style name: an unknown receiver's `.build(v)` deliberately carries its argument)
    const code = use + `struct Safe;\nstruct Unsafe;\nimpl Safe { fn shape(&self, x: &str) -> String { "k".to_string() } }\nimpl Unsafe { fn shape(&self, x: &str) -> String { format!("SELECT * FROM t WHERE a = '{}'", x) } }\n\nfn other() -> String {\n    let s = Unsafe;\n    s.shape("x")\n}\n\nfn pick((s, n): (Safe, u8), v: &str) -> String {\n    s.shape(v)\n}\n\nasync fn h(Query(q): Query<Search>) -> String {\n    let query = pick((Safe, 1), &q.name);\n    sqlx::query(&query).execute(&pool).await.unwrap();\n    String::new()\n}\n`;
    expect(linesOf(code, "sql-injection")).not.toContain(code.split("\n").findIndex(l => l.includes("sqlx::query(")) + 1);
  });
});

describe("struct fields", () => {
  const user = `    let mut user = User { name: "a".into(), role: "user".into() };\n    user.name = q.name.clone();\n`;
  it("a field written from input is tainted; its sibling is not; the whole object carries it", () => {
    expect(engine(h(`${user}${SQL("user.name")}`))).toContain("sql-injection");
    expect(engine(h(`${user}${SQL("user.role")}`))).not.toContain("sql-injection");
    expect(engine(h(`${user}    let s = format!("SELECT * FROM t WHERE u = '{:?}'", user);\n${SQL("s")}`))).toContain("sql-injection");
  });
  it("a reassigned object forgets its fields' writes", () => {
    expect(engine(h(`${user}    user = User { name: "b".into(), role: "x".into() };\n${SQL("user.name")}`))).not.toContain("sql-injection");
  });
});

describe("a canonicalized path's containment check", () => {
  it("against a base the request chose proves nothing; against a fixed base it confines", () => {
    expect(engine(h(`    let base = std::path::PathBuf::from(&q.base);\n    let path = std::path::Path::new(&q.file).canonicalize().unwrap();\n    if path.starts_with(&base) {\n        std::fs::read(&path).unwrap();\n    }`))).toContain("path-traversal");
    expect(engine(h(`    let base = std::path::PathBuf::from("/srv/files");\n    let path = std::path::Path::new("/srv/files").join(&q.file).canonicalize().unwrap();\n    if path.starts_with(&base) {\n        std::fs::read(&path).unwrap();\n    }`))).not.toContain("path-traversal");
  });
  it("a configured base (State) is not request input", () => {
    expect(engine(`${use}async fn handler(State(cfg): State<Config>, Query(q): Query<Search>) -> String {\n    let path = cfg.root.join(&q.file).canonicalize().unwrap();\n    if path.starts_with(&cfg.root) {\n        std::fs::read(&path).unwrap();\n    }\n    String::new()\n}\n`)).not.toContain("path-traversal");
  });
});

describe("BOLA ownership evidence is about the record", () => {
  const del = (check: string) => `use sqlx::PgPool;\nasync fn h(Path(id): Path<i64>, Extension(user): Extension<User>) -> impl IntoResponse {\n${check}    diesel::delete(posts.find(id)).execute(&mut conn);\n}\n`;
  it("the record the id loaded, compared to the principal, clears it", () => {
    expect(engine(del(`    let post = posts.find(id).first::<Post>(&mut conn).unwrap();\n    if post.owner_id != user.id { return; }\n`))).not.toContain("bola-missing-ownership-check");
  });
  it("another record's owner check does not", () => {
    expect(engine(del(`    let profile = profiles.find(user.id).first::<Profile>(&mut conn).unwrap();\n    if profile.owner_id != user.id { return; }\n`))).toContain("bola-missing-ownership-check");
  });
});
