/**
 * @jest-environment node
 *
 * Rust AST taint engine: recall (every sink family, Actix / Axum / Rocket idioms, values built with format!) and
 * precision (bind parameters, argv vs shell, scalar extractors, parse/cast/file_name, guards, canonicalize +
 * starts_with), propagation (closures, Option/Result adaptors, helpers, push_str/write!), and BOLA on writes.
 */
import { warmRustTaintEngine, parseRustSourceSync, scanAstTaintRust } from "@/lib/astTaintRust";
import { SinkClass, type SuppressedSink } from "@/lib/taint/taintCore";

beforeAll(async () => { await warmRustTaintEngine(); }, 120000);

function scan(code: string, entryPoints = false, crossFileFacts?: Map<string, never[]>) {
  const root = parseRustSourceSync(code, "src/handlers.rs");
  if (!root) throw new Error("parse failed");
  const suppressed: SuppressedSink[] = [];
  const findings = scanAstTaintRust(code, "src/handlers.rs", root, suppressed, { entryPoints, crossFileFacts });
  return { findings, suppressed, ids: findings.map(f => f.id as string) };
}
const has = (code: string, id: string) => scan(code).ids.includes(id);
/** An Axum handler with the given parameters and body. */
const axum = (params: string, body: string) => `use sqlx::PgPool;\nasync fn h(${params}) -> impl IntoResponse {\n${body}\n}\n`;
/** An Actix handler. */
const actix = (params: string, body: string) => `#[get("/x")]\nasync fn h(${params}) -> impl Responder {\n${body}\n}\n`;

describe("SQL injection", () => {
  it("format! / concatenation into sqlx, diesel, rusqlite, postgres", () => {
    expect(has(axum(`Query(p): Query<Search>, State(pool): State<PgPool>`, `    let sql = format!("SELECT * FROM users WHERE name = '{}'", p.name);\n    sqlx::query(&sql).fetch_all(&pool).await.unwrap();`), "sql-injection")).toBe(true);
    expect(has(axum(`Query(p): Query<Search>`, `    let name = &p.name;\n    sqlx::query(&format!("SELECT * FROM t WHERE n = '{name}'")).execute(&pool).await;`), "sql-injection")).toBe(true);
    expect(has(`use diesel::prelude::*;\n#[post("/x")]\nasync fn h(body: String, conn: DbConn) {\n    diesel::sql_query(format!("DELETE FROM t WHERE a = '{}'", body)).execute(&mut conn);\n}\n`, "sql-injection")).toBe(true);
    expect(has(actix(`q: web::Query<Search>, conn: web::Data<Connection>`, `    let s = "SELECT * FROM t WHERE a = '".to_string() + &q.term + "'";\n    conn.execute(&s, []).unwrap();\n    HttpResponse::Ok()`), "sql-injection")).toBe(true);
    expect(has(axum(`Path(name): Path<String>, client: Client`, `    client.query(&format!("SELECT * FROM t WHERE a = '{name}'"), &[]).await;`), "sql-injection")).toBe(true);
  });

  it("bound parameters, checked macros, scalar extractors and parsing are safe", () => {
    expect(has(axum(`Query(p): Query<Search>, State(pool): State<PgPool>`, `    sqlx::query("SELECT * FROM users WHERE name = $1").bind(&p.name).fetch_all(&pool).await;`), "sql-injection")).toBe(false);
    expect(has(axum(`Query(p): Query<Search>, State(pool): State<PgPool>`, `    sqlx::query!("SELECT * FROM users WHERE name = $1", p.name).fetch_all(&pool).await;`), "sql-injection")).toBe(false);
    expect(has(axum(`Path(id): Path<i64>, State(pool): State<PgPool>`, `    sqlx::query(&format!("SELECT * FROM t WHERE id = {}", id)).fetch_all(&pool).await;`), "sql-injection")).toBe(false);
    expect(has(axum(`Path(id): Path<String>, State(pool): State<PgPool>`, `    let n: i64 = id.parse().unwrap();\n    sqlx::query(&format!("SELECT * FROM t WHERE id = {}", n)).fetch_all(&pool).await;`), "sql-injection")).toBe(false);
    expect(has(axum(`Path(id): Path<String>, State(pool): State<PgPool>`, `    let n = id.parse::<u32>()?;\n    sqlx::query(&format!("SELECT * FROM t WHERE id = {n}")).fetch_all(&pool).await;`), "sql-injection")).toBe(false);
  });

  it("format! placeholders map to their own arguments (a safe one first)", () => {
    expect(has(axum(`Query(p): Query<Search>, conn: Connection`, `    conn.execute(&format!("SELECT * FROM {} WHERE a = '{}'", TABLE, p.a), []);`), "sql-injection")).toBe(true);
    expect(has(axum(`Query(p): Query<Search>, conn: Connection`, `    conn.execute(&format!("SELECT * FROM {} WHERE a = '{}'", p.table_id.parse::<i64>().unwrap(), "x"), []);`), "sql-injection")).toBe(false);
  });

  it("a numeric let annotation coerces whatever it is assigned", () => {
    expect(has(axum(`Json(b): Json<String>, conn: Connection`, `    let n: i64 = serde_json::from_str(&b).unwrap();\n    conn.execute(&format!("SELECT * FROM t WHERE id = {}", n), []);`), "sql-injection")).toBe(false);
    expect(has(axum(`Json(b): Json<String>, conn: Connection`, `    let n: String = serde_json::from_str(&b).unwrap();\n    conn.execute(&format!("SELECT * FROM t WHERE id = {}", n), []);`), "sql-injection")).toBe(true);
  });

  it("an unrelated `execute`/`query` method is not SQL", () => {
    expect(has(axum(`Json(job): Json<Job>, runner: Runner`, `    runner.execute(&job.name);`), "sql-injection")).toBe(false);
  });
});

describe("command injection", () => {
  it("a tainted program, or an argument after sh -c, is command injection; other arguments are argument injection", () => {
    expect(has(axum(`Query(p): Query<P>`, `    Command::new(&p.bin).output().unwrap();`), "command-injection")).toBe(true);
    expect(has(axum(`Query(p): Query<P>`, `    Command::new("sh").arg("-c").arg(format!("ping {}", p.host)).output().unwrap();`), "command-injection")).toBe(true);
    expect(has(axum(`Query(p): Query<P>`, `    Command::new("bash").args(["-c", &p.cmd]).output().unwrap();`), "command-injection")).toBe(true);
    const argv = scan(axum(`Query(p): Query<P>`, `    Command::new("git").arg("clone").arg(&p.repo).output().unwrap();`)).ids;
    expect(argv).not.toContain("command-injection");
    expect(argv).toContain("argument-injection");
    expect(has(axum(`Query(p): Query<P>`, `    Command::new("git").arg("clone").arg("--").arg(&p.repo).output().unwrap();`), "argument-injection")).toBe(false);
  });

  it("a Command built up in a variable", () => {
    expect(has(axum(`Query(p): Query<P>`, `    let mut cmd = Command::new("sh");\n    cmd.arg("-c");\n    cmd.arg(&p.cmd);\n    cmd.output().unwrap();`), "command-injection")).toBe(true);
  });
});

describe("path traversal", () => {
  it("fs / File / NamedFile with a request path", () => {
    expect(has(axum(`Path(name): Path<String>`, `    let p = PathBuf::from("/data").join(&name);\n    tokio::fs::read_to_string(p).await.unwrap()`), "path-traversal")).toBe(true);
    expect(has(actix(`path: web::Path<String>`, `    NamedFile::open(format!("./static/{}", path.into_inner()))`), "path-traversal")).toBe(true);
    expect(has(axum(`Query(q): Query<Q>`, `    std::fs::remove_file(&q.file).unwrap();`), "path-traversal")).toBe(true);
  });

  it("file_name() and a canonicalize + starts_with guard are safe", () => {
    expect(has(axum(`Path(name): Path<String>`, `    let f = Path::new(&name).file_name().unwrap();\n    fs::read(Path::new("/data").join(f)).unwrap()`), "path-traversal")).toBe(false);
    expect(has(axum(`Path(name): Path<String>`, `    let p = Path::new("/data").join(&name).canonicalize().unwrap();\n    if !p.starts_with("/data") { return StatusCode::FORBIDDEN; }\n    fs::read(&p).unwrap()`), "path-traversal")).toBe(false);
  });
});

describe("SSRF, redirects, XSS, templates", () => {
  it("reqwest / client.get with a request-chosen host; a pinned host is fine", () => {
    expect(has(axum(`Query(p): Query<HashMap<String, String>>`, `    let u = p.get("url").unwrap();\n    reqwest::get(u).await.unwrap();`), "ssrf")).toBe(true);
    expect(has(axum(`Query(p): Query<P>`, `    let client = reqwest::Client::new();\n    client.get(format!("https://{}/x", p.host)).send().await;`), "ssrf")).toBe(true);
    expect(has(axum(`Query(p): Query<P>`, `    reqwest::get(format!("https://api.example.com/items/{}", p.id)).await;`), "ssrf")).toBe(false);
    // each {} takes its own argument: the host is the constant, the request value only fills the path
    expect(has(axum(`Query(p): Query<P>`, `    reqwest::get(format!("https://{}/items/{}", API_HOST, p.id)).await;`), "ssrf")).toBe(false);
    expect(has(axum(`Query(p): Query<P>`, `    reqwest::get(format!("https://{}/items/{}", p.host, ITEM)).await;`), "ssrf")).toBe(true);
  });

  it("Redirect::to / Location headers", () => {
    expect(has(axum(`Query(p): Query<P>`, `    Redirect::to(&p.next)`), "open-redirect")).toBe(true);
    expect(has(actix(`q: web::Query<P>`, `    HttpResponse::Found().append_header((header::LOCATION, q.next.clone())).finish()`), "open-redirect")).toBe(true);
    expect(has(axum(`Query(p): Query<P>`, `    Redirect::to(&format!("/items/{}", p.id))`), "open-redirect")).toBe(false);
  });

  it("Html / RawHtml / text/html bodies with request input", () => {
    expect(has(axum(`Query(p): Query<P>`, `    Html(format!("<h1>Hello {}</h1>", p.name))`), "xss")).toBe(true);
    expect(has(actix(`q: web::Query<P>`, `    HttpResponse::Ok().content_type("text/html").body(format!("<p>{}</p>", q.name))`), "xss")).toBe(true);
    expect(has(axum(`Query(p): Query<P>`, `    Html(format!("<h1>Hello {}</h1>", html_escape::encode_text(&p.name)))`), "xss")).toBe(false);
    expect(has(`#[get("/hello/<name>")]\nfn hello(name: &str) -> RawHtml<String> {\n    RawHtml(format!("<b>{name}</b>"))\n}\n`, "xss")).toBe(true);
  });

  it("template strings, script engines, fancy_regex, Mongo $where", () => {
    expect(has(axum(`Json(b): Json<B>`, `    Tera::one_off(&b.template, &Context::new(), true).unwrap()`), "ssti")).toBe(true);
    expect(has(axum(`Json(b): Json<B>`, `    let engine = Engine::new();\n    engine.eval::<i64>(&b.expr).unwrap();`), "eval-exec")).toBe(true);
    expect(has(axum(`Query(p): Query<P>`, `    let re = fancy_regex::Regex::new(&p.pattern).unwrap();`), "redos")).toBe(true);
    expect(has(axum(`Query(p): Query<P>`, `    let re = regex::Regex::new(&p.pattern).unwrap();`), "redos")).toBe(false);
    expect(has(axum(`Query(p): Query<P>, coll: Collection<Document>`, `    let js = p.cond.clone();\n    coll.find(doc! { "$where": js }, None).await;`), "nosql-injection")).toBe(true);
    expect(has(axum(`Query(p): Query<P>, coll: Collection<Document>`, `    coll.find(doc! { "name": p.name.clone() }, None).await;`), "nosql-injection")).toBe(false);
    expect(has(axum(`Json(filter): Json<Document>, users: Collection<Document>`, `    users.find(filter, None).await;`), "nosql-injection")).toBe(true);
  });

  it("timing, weak digest, JWT signature validation disabled", () => {
    expect(has(axum(`headers: HeaderMap`, `    let k = headers.get("x-api-key").unwrap().to_str().unwrap();\n    if k == api_secret { }`), "timing-attack")).toBe(true);
    expect(has(axum(`Json(b): Json<B>`, `    let d = md5::compute(&b.password);`), "weak-crypto")).toBe(true);
    expect(has(axum(`headers: HeaderMap`, `    let mut v = Validation::default();\n    v.insecure_disable_signature_validation();`), "jwt-none-alg")).toBe(true);
  });
});

describe("sources", () => {
  it("HttpRequest accessors, HeaderMap, a String body in a handler, Rocket route params", () => {
    expect(has(actix(`req: HttpRequest, conn: web::Data<Connection>`, `    let q = req.query_string();\n    conn.execute(&format!("SELECT {}", q), []).unwrap();\n    HttpResponse::Ok()`), "sql-injection")).toBe(true);
    expect(has(actix(`req: HttpRequest, conn: web::Data<Connection>`, `    let id = req.match_info().get("id").unwrap();\n    conn.execute(&format!("DELETE FROM t WHERE id = '{}'", id), []).unwrap();\n    HttpResponse::Ok()`), "sql-injection")).toBe(true);
    expect(has(`#[post("/x")]\nasync fn h(body: String) -> impl Responder {\n    Command::new(&body).spawn();\n    ""\n}\n`, "command-injection")).toBe(true);
    expect(has(`#[get("/f/<name>")]\nfn f(name: String) -> Option<NamedFile> {\n    NamedFile::open(Path::new("static/").join(name)).ok()\n}\n`, "path-traversal")).toBe(true);
  });

  it("a plain library function is a source only as a lower-confidence entry point", () => {
    const lib = `pub fn run_query(conn: &Connection, term: &str) {\n    conn.execute(&format!("SELECT * FROM t WHERE a = '{}'", term), []).unwrap();\n}\n`;
    expect(scan(lib).ids).not.toContain("sql-injection");
    const relaxed = scan(lib, true).findings.filter(f => f.id === "sql-injection");
    expect(relaxed).toHaveLength(1);
    expect(relaxed[0].entryPointSeeded).toBe(true);
  });

  it("a private function nothing in the file calls is an entry point too (shell command, SQL, SSRF)", () => {
    // These three (from a real PR scan) were missed: only `pub` functions used to count as entry points.
    const command = `use std::process::Command;\nfn run_tool(user_value: &str) {\n    let command = format!("reporter --input {}", user_value);\n    let _ = Command::new("sh").arg("-c").arg(command).status();\n}\n`;
    const sql = `fn get_user(input: &str, db: &dyn QueryDb) {\n    let query = format!("SELECT * FROM users WHERE name = '{}'", input);\n    db.query(&query);\n}\ntrait QueryDb { fn query(&self, sql: &str); }\n`;
    const ssrf = `fn fetch(user_url: &str) { let _request = reqwest::blocking::get(user_url); }\n`;
    const only = (code: string) => scan(code, true).findings.map(f => [f.id, f.line, !!f.entryPointSeeded]);
    expect(only(command)).toEqual([["command-injection", 4, true]]);
    expect(only(sql)).toEqual([["sql-injection", 3, true]]);
    expect(only(ssrf)).toEqual([["ssrf", 1, true]]);
    expect(scan(command).ids).toEqual([]);                    // strict mode still needs a real request source
  });

  it("a private function this file calls, or passes as a value, is internal: its parameters aren't input", () => {
    const helper = `fn run_tool(v: &str) {\n    Command::new("sh").arg("-c").arg(format!("reporter {}", v)).status();\n}\npub fn main_entry() { run_tool("fixed"); }\n`;
    expect(scan(helper, true).ids).not.toContain("command-injection");
    const asValue = `fn run_tool(v: &str) {\n    Command::new("sh").arg("-c").arg(format!("reporter {}", v)).status();\n}\npub fn all() { ["a", "b"].iter().for_each(|x| run_tool(x)); ["c"].into_iter().for_each(run_tool); }\n`;
    expect(scan(asValue, true).ids).not.toContain("command-injection");
    const referencedOnly = `fn run_tool(v: &str) {\n    Command::new("sh").arg("-c").arg(format!("reporter {}", v)).status();\n}\npub fn all() { ["c"].into_iter().for_each(run_tool); }\n`;
    expect(scan(referencedOnly, true).ids).not.toContain("command-injection");
    const pubCalled = `pub fn run_tool(v: &str) {\n    Command::new("sh").arg("-c").arg(format!("reporter {}", v)).status();\n}\npub fn main_entry() { run_tool("fixed"); }\n`;
    expect(scan(pubCalled, true).ids).not.toContain("command-injection");
    const test = `#[test]\nfn t(v: &str) {\n    Command::new("sh").arg("-c").arg(format!("x {}", v)).status();\n}\n`;
    expect(scan(test, true).ids).not.toContain("command-injection");
  });
});

describe("propagation", () => {
  it("closures, Option/Result adaptors, push_str, write!, struct fields", () => {
    expect(has(axum(`Query(p): Query<P>, conn: Connection`, `    let v = p.name.as_ref().map(|n| n.trim().to_string()).unwrap_or_default();\n    conn.execute(&format!("SELECT '{}'", v), []);`), "sql-injection")).toBe(true);
    expect(has(axum(`Json(b): Json<B>, conn: Connection`, `    b.ids.iter().for_each(|id| { conn.execute(&format!("DELETE FROM t WHERE id = '{}'", id), []); });`), "sql-injection")).toBe(true);
    expect(has(axum(`Query(p): Query<P>, conn: Connection`, `    let mut s = String::from("SELECT * FROM t WHERE a = '");\n    s.push_str(&p.a);\n    conn.execute(&s, []);`), "sql-injection")).toBe(true);
    expect(has(axum(`Query(p): Query<P>, conn: Connection`, `    let mut s = String::new();\n    write!(s, "SELECT * FROM t WHERE a = '{}'", p.a).unwrap();\n    conn.execute(&s, []);`), "sql-injection")).toBe(true);
    expect(has(axum(`Query(p): Query<P>, conn: Connection`, `    let f = Filter { name: p.name.clone(), limit: 10 };\n    conn.execute(&format!("SELECT '{}'", f.name), []);`), "sql-injection")).toBe(true);
    expect(has(axum(`Query(p): Query<P>, conn: Connection`, `    if let Some(n) = &p.name { conn.execute(&format!("SELECT '{n}'"), []); }`), "sql-injection")).toBe(true);
    expect(has(axum(`Query(p): Query<P>, conn: Connection`, `    let Some(n) = p.name.clone() else { return; };\n    conn.execute(&format!("SELECT '{n}'"), []);`), "sql-injection")).toBe(true);
    // a sink inside the let-else's else block
    expect(has(axum(`Query(p): Query<P>, conn: Connection`, `    let Some(n) = p.name.clone() else {\n        conn.execute(&format!("INSERT INTO misses VALUES ('{}')", p.other), []);\n        return;\n    };`), "sql-injection")).toBe(true);
  });

  it("same-file helpers: return summaries and seeded re-walks (sink reported in the helper)", () => {
    const ret = `fn build(s: &str) -> String { format!("SELECT * FROM t WHERE a = '{}'", s) }\n${axum(`Query(p): Query<P>, conn: Connection`, `    conn.execute(&build(&p.a), []);`)}`;
    expect(has(ret, "sql-injection")).toBe(true);
    const sink = `fn run(conn: &Connection, s: &str) {\n    conn.execute(&format!("DELETE FROM t WHERE a = '{}'", s), []).unwrap();\n}\n${axum(`Query(p): Query<P>, conn: Connection`, `    run(&conn, &p.a);`)}`;
    expect(scan(sink).findings.find(f => f.id === "sql-injection")?.line).toBe(2);
    const safe = `fn build(s: &str) -> String { let n: i64 = s.parse().unwrap(); format!("SELECT {}", n) }\n${axum(`Query(p): Query<P>, conn: Connection`, `    conn.execute(&build(&p.a), []);`)}`;
    expect(has(safe, "sql-injection")).toBe(false);
  });

  it("a sink inside a macro argument is reported on the macro's line", () => {
    const code = axum(`Query(p): Query<P>`, `    let a = 1;\n    println!("{}", std::fs::read_to_string(&p.file).unwrap());`);
    expect(scan(code).findings.find(f => f.id === "path-traversal")?.line).toBe(4);
  });

  it("the reported source is the tainted format! argument", () => {
    const f = scan(axum(`Query(p): Query<Search>, conn: Connection`, `    let sql = format!("SELECT * FROM users WHERE name = '{}'", p.name);\n    conn.execute(&sql, []);`)).findings.find(x => x.id === "sql-injection")!;
    expect(f.sourceExpr).toBe("sql");
    expect(f.trace!.length).toBeGreaterThan(1);
  });
});

describe("guards", () => {
  it("allow-lists, literal equality, matches!, digit checks, anchored regex, match on literals", () => {
    const sort = (guard: string) => axum(`Query(p): Query<P>, conn: Connection`, `    let col = p.sort.clone();\n${guard}\n    conn.execute(&format!("SELECT * FROM t ORDER BY {}", col), []);`);
    expect(has(sort(`    if !["name", "date"].contains(&col.as_str()) { return; }`), "sql-injection")).toBe(false);
    expect(has(`const ALLOWED: &[&str] = &["name", "date"];\n${sort(`    if !ALLOWED.contains(&col.as_str()) { return; }`)}`, "sql-injection")).toBe(false);
    expect(has(sort(`    if !matches!(col.as_str(), "name" | "date") { return; }`), "sql-injection")).toBe(false);
    expect(has(sort(`    if !col.chars().all(|c| c.is_ascii_digit()) { return; }`), "sql-injection")).toBe(false);
    expect(has(sort(`    if !Regex::new(r"^[a-z_]+$").unwrap().is_match(&col) { return; }`), "sql-injection")).toBe(false);
    expect(has(sort(`    let col = match col.as_str() { "name" | "date" => col, _ => "id".to_string() };`), "sql-injection")).toBe(false);
    // match as a statement: inside a literal arm the subject is that literal
    expect(has(axum(`Query(p): Query<P>, conn: Connection`, `    let col = p.sort.clone();\n    match col.as_str() {\n        "name" | "date" => { conn.execute(&format!("SELECT * FROM t ORDER BY {}", col), []); }\n        _ => {}\n    }`), "sql-injection")).toBe(false);
    expect(has(axum(`Query(p): Query<P>, conn: Connection`, `    let col = p.sort.clone();\n    match col.as_str() {\n        "" => {}\n        _ => { conn.execute(&format!("SELECT * FROM t ORDER BY {}", col), []); }\n    }`), "sql-injection")).toBe(true);
    // a check that is not a guard
    expect(has(sort(`    if col.is_empty() { return; }`), "sql-injection")).toBe(true);
    // an unanchored / wide regex is not a guard
    expect(has(sort(`    if !Regex::new(r"[a-z]").unwrap().is_match(&col) { return; }`), "sql-injection")).toBe(true);
  });

  it("a sanitized flow records the regex-layer veto", () => {
    const r = scan(axum(`Query(p): Query<P>`, `    Html(format!("<p>{}</p>", html_escape::encode_text(&p.name)))`));
    expect(r.ids).not.toContain("xss");
    expect(r.suppressed.some(s => s.id === "xss")).toBe(true);
  });
});

describe("cross-file facts at the call site", () => {
  it("a typed service receiver resolves Type.method; Trait.method and module::fn too", () => {
    const fact = { index: 0, isRest: false, id: "sql-injection", sinkClass: SinkClass.SQL, sinkExpr: "conn.execute", file: "src/services/user.rs", line: 7, via: ["UserService.find"] };
    const facts = new Map([["UserService.find", [fact]], ["Repo.raw", [fact]], ["user::lookup", [fact]]]) as unknown as Map<string, never[]>;
    const viaState = `use crate::services::user::lookup;\nasync fn h(Query(p): Query<P>, State(svc): State<Arc<UserService>>, repo: Arc<dyn Repo>) {\n    svc.find(&p.name).await;\n    repo.raw(&p.q);\n    lookup(&p.x);\n}\n`;
    const found = scan(viaState, false, facts).findings.filter(f => f.id === "sql-injection");
    expect(found.map(f => f.line).sort()).toEqual([3, 4, 5]);
    expect(found[0].calleeSink?.file).toBe("src/services/user.rs");
  });
});

describe("BOLA", () => {
  it("an UPDATE/DELETE by a path id with no owner condition is reported", () => {
    const code = axum(`Path(id): Path<i64>, State(pool): State<PgPool>`, `    sqlx::query("DELETE FROM posts WHERE id = $1").bind(id).execute(&pool).await.unwrap();`);
    expect(scan(code).findings.find(f => f.id === "bola-missing-ownership-check")?.severityOverride).toBe("high");
    expect(has(axum(`Path(id): Path<i64>, State(pool): State<PgPool>`, `    diesel::delete(posts.find(id)).execute(&mut conn);`), "bola-missing-ownership-check")).toBe(true);
  });

  it("an owner column in the statement, or an owner comparison, suppresses it", () => {
    expect(has(axum(`Path(id): Path<i64>, user: AuthUser, State(pool): State<PgPool>`, `    sqlx::query("DELETE FROM posts WHERE id = $1 AND user_id = $2").bind(id).bind(user.id).execute(&pool).await;`), "bola-missing-ownership-check")).toBe(false);
    expect(has(axum(`Path(id): Path<i64>, user: AuthUser, State(pool): State<PgPool>`, `    let post = load(id).await;\n    if post.user_id != user.id { return StatusCode::FORBIDDEN; }\n    sqlx::query("DELETE FROM posts WHERE id = $1").bind(id).execute(&pool).await;`), "bola-missing-ownership-check")).toBe(false);
  });

  it("a write that the path id does not select is not reported", () => {
    expect(has(axum(`Path(id): Path<i64>, State(pool): State<PgPool>`, `    let _ = id;\n    sqlx::query("DELETE FROM sessions WHERE expired = true").execute(&pool).await;`), "bola-missing-ownership-check")).toBe(false);
  });

  it("reads are not reported", () => {
    expect(has(axum(`Path(id): Path<i64>, State(pool): State<PgPool>`, `    sqlx::query("SELECT * FROM posts WHERE id = $1").bind(id).fetch_one(&pool).await;`), "bola-missing-ownership-check")).toBe(false);
  });
});

describe("more frameworks: warp, tonic, lambda_http", () => {
  const warp = (handler: string) => `use warp::Filter;\nuse sqlx::PgPool;\n${handler}\nfn routes(pool: PgPool) {\n    let db = warp::any().map(move || pool.clone());\n    let search = warp::path("s").and(warp::query::<Search>()).and(db.clone()).and_then(h);\n    let name = warp::path::param::<String>();\n    let users = warp::path("u").and(name).and_then(by_name);\n}\n`;
  it("a function a warp filter chain hands to and_then gets the extracted values as request input", () => {
    expect(has(warp(`async fn h(q: Search, pool: PgPool) -> Result<impl warp::Reply, warp::Rejection> {\n    sqlx::query(&format!("SELECT * FROM t WHERE a = '{}'", q.term)).fetch_all(&pool).await;\n    Ok("x")\n}\nasync fn by_name(n: String) -> Result<impl warp::Reply, warp::Rejection> { Ok("x") }`), "sql-injection")).toBe(true);
    // a filter bound to a variable (`name`) and passed into the chain counts too
    expect(has(warp(`async fn h(q: Search) -> Result<impl warp::Reply, warp::Rejection> { Ok("x") }\nasync fn by_name(n: String) -> Result<impl warp::Reply, warp::Rejection> {\n    std::process::Command::new(n).spawn();\n    Ok("x")\n}`), "command-injection")).toBe(true);
  });
  it("warp's injected state, scalar values, and functions no filter chain names are not request input", () => {
    // the pool is the app's own state
    expect(has(warp(`async fn h(q: Search, pool: PgPool) -> Result<impl warp::Reply, warp::Rejection> {\n    let p = pool.to_string();\n    sqlx::query(&p).fetch_all(&pool).await;\n    Ok("x")\n}\nasync fn by_name(n: String) -> Result<impl warp::Reply, warp::Rejection> { Ok("x") }`), "sql-injection")).toBe(false);
    // shared state recognised by its name alone (its type says nothing)
    expect(has(`use warp::Filter;\nfn routes(store: Arc<Mutex<HashMap<String, String>>>) {\n    let s = warp::any().map(move || store.clone());\n    let r = warp::path::param::<String>().and(s).and_then(h);\n}\nasync fn h(key: String, store: Arc<Mutex<HashMap<String, String>>>) -> Result<impl warp::Reply, warp::Rejection> {\n    let prog = store.lock().unwrap().get("tool").cloned().unwrap();\n    std::process::Command::new(prog).spawn();\n    Ok("x")\n}\n`, "command-injection")).toBe(false);
    expect(has(`use warp::Filter;\nuse sqlx::PgPool;\nfn routes() {\n    let r = warp::path::param::<u32>().and_then(h);\n}\nasync fn h(id: u32) -> Result<impl warp::Reply, warp::Rejection> {\n    sqlx::query(&format!("SELECT * FROM t WHERE id = {}", id)).execute(&pool).await;\n    Ok("x")\n}\n`, "sql-injection")).toBe(false);
    expect(has(`use warp::Filter;\nfn routes() { let r = warp::path("x").map(|| "ok"); }\nasync fn other(n: String) {\n    std::process::Command::new(n).spawn();\n}\nfn main() { other(String::from("ls")); }\n`, "command-injection")).toBe(false);
  });
  it("tonic request messages and lambda_http events are request input", () => {
    expect(has(`use tonic::{Request, Response, Status};\n#[tonic::async_trait]\nimpl Greeter for MyGreeter {\n    async fn say(&self, request: Request<HelloRequest>) -> Result<Response<HelloReply>, Status> {\n        let req = request.into_inner();\n        std::process::Command::new("sh").arg("-c").arg(&req.name).spawn();\n        Ok(Response::new(HelloReply {}))\n    }\n}\n`, "command-injection")).toBe(true);
    expect(has(`use lambda_http::{run, service_fn, Error, Request, RequestExt};\nasync fn handler(event: Request) -> Result<String, Error> {\n    let q = event.query_string_parameters();\n    let path = q.first("file").unwrap();\n    std::fs::read_to_string(path)?;\n    Ok("x".into())\n}\n`, "path-traversal")).toBe(true);
  });
});

describe("mass assignment", () => {
  const user = `use diesel::prelude::*;\n#[derive(Deserialize, Insertable)]\nstruct NewUser {\n    name: String,\n    email: String,\n    role: String,\n}\n#[derive(Deserialize, Insertable)]\nstruct Signup {\n    name: String,\n    email: String,\n    #[serde(skip_deserializing)]\n    role: String,\n}\n`;
  it("a request body with a privileged field written as-is by diesel insert_into(..).values / update(..).set", () => {
    const r = scan(user + `async fn create(Json(new_user): Json<NewUser>, State(pool): State<DbPool>) {\n    diesel::insert_into(users::table).values(&new_user).execute(&mut conn);\n}\n`);
    expect(r.ids).toContain("mass-assignment");
    expect(r.findings.find(f => f.id === "mass-assignment")!.detail).toMatch(/role/);
    expect(has(user + `#[put("/u/{id}")]\nasync fn upd(path: web::Path<i32>, body: web::Json<NewUser>) {\n    diesel::update(users.find(path.into_inner())).set(&body.into_inner()).execute(&mut conn);\n}\n`, "mass-assignment")).toBe(true);
    expect(has(user + `#[post("/u")]\nasync fn create(body: String) {\n    let u: NewUser = serde_json::from_str(&body).unwrap();\n    diesel::insert_into(users::table).values(&u).execute(&mut conn);\n}\n`, "mass-assignment")).toBe(true);
    expect(has(`use sea_orm::*;\nasync fn create(Json(payload): Json<serde_json::Value>, State(db): State<DatabaseConnection>) {\n    let m = user::ActiveModel::from_json(payload)?;\n    m.insert(&db).await;\n}\n`, "mass-assignment")).toBe(true);
    expect(has(`use sea_orm::*;\nasync fn upd(Json(payload): Json<serde_json::Value>) {\n    let mut m: user::ActiveModel = found.into();\n    m.set_from_json(payload)?;\n}\n`, "mass-assignment")).toBe(true);
  });
  it("no privileged field, a field serde skips, or a server-built value is not reported", () => {
    const plain = `use diesel::prelude::*;\n#[derive(Deserialize, Insertable)]\nstruct NewPost { title: String, body: String }\n`;
    expect(has(plain + `async fn create(Json(p): Json<NewPost>) {\n    diesel::insert_into(posts::table).values(&p).execute(&mut conn);\n}\n`, "mass-assignment")).toBe(false);
    expect(has(user + `async fn create(Json(s): Json<Signup>) {\n    diesel::insert_into(users::table).values(&s).execute(&mut conn);\n}\n`, "mass-assignment")).toBe(false);
    expect(has(user + `async fn create(Json(s): Json<Signup>) {\n    let u = NewUser { name: s.name.clone(), email: s.email.clone(), role: "user".into() };\n    diesel::insert_into(users::table).values(&u).execute(&mut conn);\n}\n`, "mass-assignment")).toBe(false);
    // JSON the server wrote itself
    expect(has(`use sea_orm::*;\nasync fn create(Json(payload): Json<serde_json::Value>) {\n    let m = user::ActiveModel::from_json(json!({ "name": "guest" }))?;\n}\n`, "mass-assignment")).toBe(false);
    // .values() on something that isn't an insert
    expect(has(user + `async fn create(Json(u): Json<NewUser>) {\n    let v = map.values(&u);\n}\n`, "mass-assignment")).toBe(false);
  });
});

describe("insecure deserialization, XPath, header injection", () => {
  it("unbounded bincode and serde_pickle on request bytes", () => {
    expect(has(axum(`body: Bytes`, `    let v: Msg = bincode::deserialize(&body).unwrap();`), "insecure-deserialization")).toBe(true);
    expect(has(axum(`body: Bytes`, `    let v: serde_pickle::Value = serde_pickle::from_slice(&body, Default::default()).unwrap();`), "insecure-deserialization")).toBe(true);
    // a size limit configured in the file, or constant bytes
    expect(has(axum(`body: Bytes`, `    let v: Msg = bincode::options().with_limit(4096).deserialize(&body).unwrap();\n    let w: Msg = bincode::deserialize(&body).unwrap();`), "insecure-deserialization")).toBe(false);
    expect(has(axum(`body: Bytes`, `    let v: Msg = bincode::deserialize(&CACHED).unwrap();`), "insecure-deserialization")).toBe(false);
  });
  it("request input in an XPath expression (sxd_xpath, libxml)", () => {
    expect(has(`use sxd_xpath::evaluate_xpath;\n` + axum(`Query(q): Query<Search>`, `    let expr = format!("//user[name='{}']", q.name);\n    evaluate_xpath(&doc, &expr).unwrap();`), "xpath-injection")).toBe(true);
    expect(has(`use sxd_xpath::{Factory, Context};\n` + axum(`Query(q): Query<Search>`, `    let factory = Factory::new();\n    let x = factory.build(&format!("//u[@id='{}']", q.id)).unwrap();`), "xpath-injection")).toBe(true);
    expect(has(`use libxml::xpath::Context;\n` + axum(`Query(q): Query<Search>`, `    let ctx = Context::new(&doc).unwrap();\n    ctx.evaluate(&format!("//u[name='{}']", q.name)).unwrap();`), "xpath-injection")).toBe(true);
    expect(has(`use sxd_xpath::evaluate_xpath;\n` + axum(`Query(q): Query<Search>`, `    evaluate_xpath(&doc, "//user[@active='1']").unwrap();`), "xpath-injection")).toBe(false);
    // no XPath library: an unrelated evaluate()
    expect(has(axum(`Query(q): Query<Search>`, `    ctx.evaluate(&q.name);`), "xpath-injection")).toBe(false);
  });
  it("only the unchecked HeaderValue constructors are header injection", () => {
    expect(has(axum(`Query(q): Query<Search>`, `    let v = unsafe { HeaderValue::from_maybe_shared_unchecked(q.next.clone()) };`), "header-injection")).toBe(true);
    expect(has(axum(`Query(q): Query<Search>`, `    let v = HeaderValue::from_str(&q.next).unwrap();`), "header-injection")).toBe(false);
  });
});

describe("more sinks: maud, subprocess, duct, sea-query", () => {
  it("are reported with request input", () => {
    expect(has(axum(`Query(q): Query<Search>`, `    let m = PreEscaped(q.bio.clone());`), "xss")).toBe(true);
    expect(has(`use maud::{html, PreEscaped};\n` + axum(`Query(q): Query<Search>`, `    html! { p { (PreEscaped(q.bio)) } }`), "xss")).toBe(true);
    expect(has(`use subprocess::Exec;\n` + axum(`Query(q): Query<Search>`, `    Exec::shell(format!("ls {}", q.dir)).join();`), "command-injection")).toBe(true);
    expect(has(`use subprocess::Exec;\n` + axum(`Query(q): Query<Search>`, `    Exec::cmd(&q.tool).arg("-v").join();`), "command-injection")).toBe(true);
    expect(has(`use duct::cmd;\n` + axum(`Query(q): Query<Search>`, `    cmd(&q.tool, &["-v"]).run();`), "command-injection")).toBe(true);
    expect(has(`use sea_query::Expr;\n` + axum(`Query(q): Query<Search>`, `    let e = Expr::cust(&format!("name = '{}'", q.name));`), "sql-injection")).toBe(true);
    expect(has(`use sea_orm::Statement;\n` + axum(`Query(q): Query<Search>`, `    let s = Statement::from_sql_and_values(DbBackend::Postgres, &format!("SELECT * FROM t WHERE a = '{}'", q.a), []);`), "sql-injection")).toBe(true);
  });
  it("are not reported with constants, escaped markup, or bound values", () => {
    expect(has(`use maud::{html, PreEscaped};\n` + axum(`Query(q): Query<Search>`, `    html! { p { (q.bio) } (PreEscaped("<br>")) }`), "xss")).toBe(false);
    expect(has(`use subprocess::Exec;\n` + axum(`Query(q): Query<Search>`, `    Exec::cmd("ls").arg("--").arg(&q.dir).join();`), "command-injection")).toBe(false);
    expect(has(`use sea_orm::Statement;\n` + axum(`Query(q): Query<Search>`, `    let s = Statement::from_sql_and_values(DbBackend::Postgres, "SELECT * FROM t WHERE a = $1", [q.a.into()]);`), "sql-injection")).toBe(false);
  });
});
