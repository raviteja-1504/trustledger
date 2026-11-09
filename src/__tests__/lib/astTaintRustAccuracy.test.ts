/**
 * @jest-environment node
 *
 * Rust AST taint engine accuracy: deferred closure execution, finding identity per sink call, object-level
 * authorization order (BOLA), scan status / parser lifecycle.
 */
import { warmRustTaintEngine, parseRustSourceSync, scanAstTaintRust, isRustParserReady, getRustEngineStatus } from "@/lib/astTaintRust";
import type { SuppressedSink } from "@/lib/taint/taintCore";

beforeAll(async () => { await warmRustTaintEngine(); }, 120000);

function scan(code: string, path = "src/handlers.rs") {
  const root = parseRustSourceSync(code, path);
  if (!root) throw new Error("parse failed");
  const suppressed: SuppressedSink[] = [];
  return scanAstTaintRust(code, path, root, suppressed, {});
}
const ids = (code: string) => scan(code).map(f => f.id as string);

/** An axum-style handler with the request input in `params.command`. */
const handler = (body: string) =>
  `use std::process::Command;\nuse axum::extract::Query;\n\n#[derive(serde::Deserialize)]\npub struct P { pub command: String }\n\npub async fn run(Query(params): Query<P>) -> String {\n${body}\n    "ok".to_string()\n}\n`;

describe("closures are deferred execution", () => {
  it("a closure that is never called does not run", () => {
    expect(ids(handler(`    let task = || { Command::new(&params.command).spawn() };`))).not.toContain("command-injection");
    expect(ids(handler(`    let task = move || { Command::new(&params.command).spawn() };\n    let _ = &task;`))).not.toContain("command-injection");
  });
  it("a closure that is called does", () => {
    expect(ids(handler(`    let task = || { Command::new(&params.command).spawn() };\n    let _ = task();`))).toContain("command-injection");
  });
  it("a closure called conditionally still counts (a branch can run it)", () => {
    expect(ids(handler(`    let task = || { Command::new(&params.command).spawn() };\n    if params.command.len() > 3 { let _ = task(); }`))).toContain("command-injection");
  });
  it("a closure handed to a library function runs there", () => {
    expect(ids(handler(`    let task = || { Command::new(&params.command).spawn() };\n    std::thread::spawn(task);`))).toContain("command-injection");
    expect(ids(handler(`    std::thread::spawn(|| { Command::new(&params.command).spawn() });`))).toContain("command-injection");
  });
  it("a closure handed to a local function that never calls it does not run", () => {
    const code = `fn ignore<F: Fn()>(_f: F) {}\n` + handler(`    ignore(|| { Command::new(&params.command).spawn().unwrap(); });`);
    expect(ids(code)).not.toContain("command-injection");
  });
  it("a closure handed to a local function that calls it does", () => {
    const code = `fn apply<F: Fn()>(f: F) { f(); }\n` + handler(`    apply(|| { Command::new(&params.command).spawn().unwrap(); });`);
    expect(ids(code)).toContain("command-injection");
  });
  it("an iterator-adaptor closure over tainted elements runs", () => {
    const code = handler(`    let v = vec![params.command.clone()];\n    v.iter().for_each(|c| { let _ = Command::new(c).spawn(); });`);
    expect(ids(code)).toContain("command-injection");
  });
  it("re-binding the name drops the old closure", () => {
    expect(ids(handler(`    let task = || { Command::new(&params.command).spawn() };\n    let task = || { Command::new("ls").spawn() };\n    let _ = task();`))).not.toContain("command-injection");
  });
});

describe("finding identity", () => {
  it("two sink calls of one class on a line are two findings", () => {
    const code = handler(`    let _ = (Command::new(&params.command).spawn(), Command::new(&params.command).spawn());`);
    expect(scan(code).filter(f => f.id === "command-injection").length).toBe(2);
  });
  it("one sink call is still one finding", () => {
    expect(scan(handler(`    let _ = Command::new(&params.command).spawn();`)).filter(f => f.id === "command-injection").length).toBe(1);
  });
});

describe("BOLA: the check must come before the write", () => {
  const sqlx = (body: string) =>
    `use axum::extract::{Path, State};\n\npub async fn delete_post(State(pool): State<sqlx::PgPool>, user: AuthUser, Path(id): Path<i64>) -> String {\n${body}\n    "ok".to_string()\n}\n`;
  it("no ownership check flags", () => {
    expect(ids(sqlx(`    sqlx::query("DELETE FROM posts WHERE id = $1").bind(id).execute(&pool).await.unwrap();`))).toContain("bola-missing-ownership-check");
  });
  it("owner in the WHERE clause is safe", () => {
    expect(ids(sqlx(`    sqlx::query("DELETE FROM posts WHERE id = $1 AND user_id = $2").bind(id).bind(user.id).execute(&pool).await.unwrap();`))).not.toContain("bola-missing-ownership-check");
  });
  it("a record owner check before the write is safe", () => {
    const body = `    let post = sqlx::query_as::<_, Post>("SELECT * FROM posts WHERE id = $1").bind(id).fetch_one(&pool).await.unwrap();\n    if post.user_id != user.id { return "no".to_string(); }\n    sqlx::query("DELETE FROM posts WHERE id = $1").bind(id).execute(&pool).await.unwrap();`;
    expect(ids(sqlx(body))).not.toContain("bola-missing-ownership-check");
  });
  it("an owner check AFTER the write protects nothing", () => {
    const body = `    let post = sqlx::query_as::<_, Post>("SELECT * FROM posts WHERE id = $1").bind(id).fetch_one(&pool).await.unwrap();\n    sqlx::query("DELETE FROM posts WHERE id = $1").bind(id).execute(&pool).await.unwrap();\n    if post.user_id != user.id { return "no".to_string(); }`;
    expect(ids(sqlx(body))).toContain("bola-missing-ownership-check");
  });
});

describe("scan status and parser lifecycle", () => {
  it("reports the parser ready after warm-up", () => {
    expect(isRustParserReady()).toBe(true);
    expect(getRustEngineStatus().status).toBe("ready");
  });
  it("records an analysis failure instead of silently returning clean", () => {
    const root = parseRustSourceSync("fn main() {}", "src/a.rs")!;
    const bad = { get type(): string { throw new Error("boom"); } } as unknown as typeof root;
    expect(scanAstTaintRust("fn main() {}", "src/a.rs", bad, [], {})).toEqual([]);
    const st = getRustEngineStatus();
    expect(st.lastError).toMatch(/analysis_failed/);
  });
});
