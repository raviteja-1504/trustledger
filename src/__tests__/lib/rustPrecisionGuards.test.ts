/**
 * @jest-environment node
 *
 * Rust engine guards and value tracking ported from the Python/Java work (found scoring the 0llino sast-benchmark
 * Rust suite): an app's own request wrapper as a source, `contains("..")` / character-allowlist / helper-function /
 * boolean-local guards, canonicalize + strip_prefix, constant-folded `if`, literal-key HashMaps, straight-line Vecs,
 * and argument injection that respects validation (numbers, `-`-free alphabets) but not quoting.
 */
import { warmRustTaintEngine, parseRustSourceSync, scanAstTaintRust } from "@/lib/astTaintRust";
import type { SuppressedSink } from "@/lib/taint/taintCore";

beforeAll(async () => { await warmRustTaintEngine(); }, 120000);

function ids(code: string): string[] {
  const root = parseRustSourceSync(code, "src/handlers.rs");
  if (!root) throw new Error("parse failed");
  const suppressed: SuppressedSink[] = [];
  return scanAstTaintRust(code, "src/handlers.rs", root, suppressed, {}).map(f => f.id as string);
}
/** A handler taking the app's own request wrapper. */
const handler = (body: string, helpers = "") =>
  `use std::process::Command;\nuse std::collections::HashMap;\n${helpers}\npub fn handle(req: &super::shared::ApiRequest) -> super::shared::ApiResponse {\n${body}\n    super::shared::ApiResponse::ok("done")\n}\n`;
const readsFile = (expr: string) => `    let _ = std::fs::read_to_string(${expr});`;

describe("request wrapper sources", () => {
  it("accessors on a parameter whose type is an app's own *Request are request input", () => {
    expect(ids(handler(`    let p = req.param("p");\n${readsFile("&p")}`))).toContain("path-traversal");
    expect(ids(handler(`    let c = req.cookie("c");\n${readsFile("&c")}`))).toContain("path-traversal");
  });

  it("the same accessor names on a non-request type are not", () => {
    const code = `pub fn handle(cfg: &super::shared::AppConfig) {\n    let p = cfg.param("p");\n    let _ = std::fs::read_to_string(&p);\n}\n`;
    expect(ids(code)).not.toContain("path-traversal");
  });
});

describe("guards", () => {
  it("contains(\"..\") rules out traversal, not SQL", () => {
    const guard = `    let p = req.param("p");\n    if p.contains("..") || p.contains('/') {\n        return super::shared::ApiResponse::forbidden("no");\n    }\n`;
    expect(ids(handler(`${guard}${readsFile(`format!("/var/data/{}", p)`)}`))).not.toContain("path-traversal");
    expect(ids(handler(`${guard}    let sql = format!("SELECT * FROM t WHERE a = '{}'", p);\n    conn.execute(&sql, []).unwrap();`))).toContain("sql-injection");
    // a quote check rules out breaking a quoted SQL literal, not traversal
    const quote = `    let p = req.param("p");\n    if p.contains('\\'') { return super::shared::ApiResponse::forbidden("no"); }\n`;
    expect(ids(handler(`${quote}    let sql = format!("SELECT * FROM t WHERE a = '{}'", p);\n    conn.execute(&sql, []).unwrap();`))).not.toContain("sql-injection");
    expect(ids(handler(`${quote}${readsFile(`format!("/d/{}", p)`)}`))).toContain("path-traversal");
    // an unrelated substring proves nothing
    expect(ids(handler(`    let p = req.param("p");\n    if p.contains("x") { return super::shared::ApiResponse::forbidden("no"); }\n${readsFile(`format!("/d/{}", p)`)}`))).toContain("path-traversal");
  });

  it("a literal list bound by let is an allowlist", () => {
    const body = (list: string) => `    let f = req.param("f");\n    let allowed = ${list};\n    if !allowed.contains(&f.as_str()) {\n        return super::shared::ApiResponse::forbidden("no");\n    }\n${readsFile(`format!("/files/{}", f)`)}`;
    expect(ids(handler(body(`["a.pdf", "b.txt"]`)))).not.toContain("path-traversal");
    expect(ids(handler(body(`load_list()`)))).toContain("path-traversal");
  });

  it("a boolean local bound to a character allowlist guards like the check itself", () => {
    const body = `    let f = req.param("f");\n    let is_safe = f.chars().all(|c| c.is_alphanumeric() || c == '_');\n    if !is_safe {\n        return super::shared::ApiResponse::bad_request("bad");\n    }\n${readsFile(`format!("/d/{}", f)`)}`;
    expect(ids(handler(body))).not.toContain("path-traversal");
    expect(ids(handler(body.replace("if !is_safe", "if is_safe")))).toContain("path-traversal");
  });

  it("an alphabet that admits '/' still allows nested paths", () => {
    const body = `    let f = req.param("f");\n    if !f.chars().all(|c| c.is_alphanumeric() || c == '/') {\n        return super::shared::ApiResponse::bad_request("bad");\n    }\n${readsFile(`format!("/d/{}", f)`)}`;
    expect(ids(handler(body))).toContain("path-traversal");
  });

  it("a same-file boolean helper over its parameter guards the caller's argument", () => {
    const helper = `fn is_safe_name(s: &str) -> bool {\n    !s.contains("..") && s.chars().all(|c| c.is_alphanumeric() || c == '.')\n}`;
    const body = (cond: string) => `    let f = req.param("f");\n    if ${cond} {\n        return super::shared::ApiResponse::forbidden("no");\n    }\n${readsFile(`format!("/up/{}", f)`)}`;
    expect(ids(handler(body("!is_safe_name(&f)"), helper))).not.toContain("path-traversal");
    expect(ids(handler(body("is_safe_name(&f)"), helper))).toContain("path-traversal");
  });

  it("a starts_with helper only counts for a canonicalized argument", () => {
    const helper = `fn within(full: &std::path::Path, base: &str) -> bool {\n    full.starts_with(base)\n}`;
    const body = (def: string) => `    let p = req.param("p");\n    let joined = format!("/base/{}", p);\n    let full = ${def};\n    if !within(&full, "/base") {\n        return super::shared::ApiResponse::forbidden("no");\n    }\n${readsFile("&full")}`;
    expect(ids(handler(body(`std::path::Path::new(&joined).canonicalize().unwrap()`), helper))).not.toContain("path-traversal");
    expect(ids(handler(body(`std::path::PathBuf::from(&joined)`), helper))).toContain("path-traversal");
  });

  it("resolving a path (the defence itself) is not a file access", () => {
    expect(ids(handler(`    let p = req.param("p");\n    let _c = std::fs::canonicalize(&p);`))).not.toContain("path-traversal");
    expect(ids(handler(`    let p = req.param("p");\n    let _c = std::fs::metadata(&p);`))).toContain("path-traversal");
  });

  it("canonicalize + strip_prefix(..).is_err() rejects paths outside the base", () => {
    const body = (check: string) => `    let p = req.param("p");\n    let base = std::path::Path::new("/var/data");\n    let canonical = base.join(&p).canonicalize().unwrap();\n    if ${check} {\n        return super::shared::ApiResponse::forbidden("no");\n    }\n${readsFile("&canonical")}`;
    expect(ids(handler(body("canonical.strip_prefix(base).is_err()")))).not.toContain("path-traversal");
    expect(ids(handler(body("canonical.strip_prefix(base).is_ok()")))).toContain("path-traversal");
  });
});

describe("value tracking", () => {
  it("an if with a constant condition only takes its live arm (expression and statement)", () => {
    const expr = (cond: string) => `    let p = req.param("p");\n    let path = if ${cond} {\n        "/app/index.html".to_string()\n    } else {\n        p\n    };\n${readsFile("&path")}`;
    expect(ids(handler(expr("7 * 6 > 40")))).not.toContain("path-traversal");
    expect(ids(handler(expr("7 * 6 < 40")))).toContain("path-traversal");
    const stmt = (cond: string) => `    let p = req.param("p");\n    if ${cond} {\n        let _ = std::fs::read_to_string("/fixed");\n    } else {\n${readsFile("&p")}\n    }`;
    expect(ids(handler(stmt("99 > 0")))).not.toContain("path-traversal");
    expect(ids(handler(stmt("99 < 0")))).toContain("path-traversal");
    // a constant-false condition never runs its arm
    expect(ids(handler(`    let p = req.param("p");\n    if 1 > 2 {\n${readsFile("&p")}\n    }`))).not.toContain("path-traversal");
  });

  it("a guard inside an if-expression clears only its own classes for the value", () => {
    const body = `    let p = req.param("p");\n    let v = if p.contains("..") { "x".to_string() } else { p };\n`;
    expect(ids(handler(`${body}${readsFile(`format!("/d/{}", v)`)}`))).not.toContain("path-traversal");
    expect(ids(handler(`${body}    let sql = format!("SELECT * FROM t WHERE a = '{}'", v);\n    conn.execute(&sql, []).unwrap();`))).toContain("sql-injection");
  });

  it("a HashMap read under a literal key carries only what was stored there", () => {
    const body = (key: string) => `    let mut m: HashMap<&str, String> = HashMap::new();\n    m.insert("user", req.param("f"));\n    m.insert("safe", "/files/report.txt".to_string());\n    let p = m.get("${key}").unwrap();\n${readsFile("p")}`;
    expect(ids(handler(body("safe")))).not.toContain("path-traversal");
    expect(ids(handler(body("user")))).toContain("path-traversal");
    // the map as a whole still carries the request value
    expect(ids(handler(`    let mut m: HashMap<&str, String> = HashMap::new();\n    m.insert("user", req.param("f"));\n    for (_, v) in m.iter() {\n${readsFile("v")}\n    }`))).toContain("path-traversal");
  });

  it("a Vec built by push/remove in straight-line code is followed element by element", () => {
    const body = (idx: number) => `    let mut paths = vec!["/safe/a.txt".to_string()];\n    paths.push(req.param("f"));\n    paths.push("/safe/b.txt".to_string());\n    paths.remove(1);\n    let path = &paths[${idx}];\n${readsFile("path")}`;
    expect(ids(handler(body(0)))).not.toContain("path-traversal");
    expect(ids(handler(body(1)))).not.toContain("path-traversal");
    expect(ids(handler(body(0).replace("paths.remove(1);", "paths.remove(0);")))).toContain("path-traversal");
  });
});

describe("argument injection", () => {
  const run = (prep: string, program: string, arg: string) =>
    handler(`    let a = req.param("a");\n${prep}    let _ = Command::new("${program}").arg(${arg}).output();`);

  it("a raw request value as an argument can be an option", () => {
    expect(ids(run("", "ls", "&a"))).toContain("argument-injection");
  });

  it("a number, a clamped number, or a '-'-free alphabet cannot start with '-'", () => {
    expect(ids(run(`    let n: u32 = a.parse().unwrap_or(5).min(20);\n`, "last", "n.to_string()"))).not.toContain("argument-injection");
    expect(ids(run(`    if !a.chars().all(|c| c.is_alphanumeric() || c == '_') { return super::shared::ApiResponse::bad_request("x"); }\n`, "ls", "&a"))).not.toContain("argument-injection");
  });

  it("an anchored regex class guards arguments unless it admits '-'", () => {
    const body = (cls: string) => `    let a = req.param("a");\n    let re = Regex::new(r"^[${cls}]+$").unwrap();\n    if !re.is_match(&a) { return super::shared::ApiResponse::bad_request("x"); }\n    let _ = Command::new("ls").arg(&a).output();`;
    // the hyphens of a-z are ranges; only a leading, trailing or escaped one is a literal dash
    expect(ids(handler(body("a-z0-9_")))).not.toContain("argument-injection");
    expect(ids(handler(body("a-z0-9_-")))).toContain("argument-injection");
    expect(ids(handler(body("a-z0-9\\-_")))).toContain("argument-injection");
    expect(ids(handler(body("a-z0-9-_")))).toContain("argument-injection");
  });

  it("an alphabet that admits '-' still lets the value be an option", () => {
    expect(ids(run(`    if !a.chars().all(|c| c.is_alphanumeric() || c == '-') { return super::shared::ApiResponse::bad_request("x"); }\n`, "ls", "&a"))).toContain("argument-injection");
  });

  it("echo has no option worth injecting", () => {
    expect(ids(run("", "echo", "&a"))).not.toContain("argument-injection");
  });
});

describe("shell quoting", () => {
  it("the POSIX single-quote idiom makes the value one shell word", () => {
    const helper = (replacement: string) => `fn shell_escape(input: &str) -> String {\n    format!("'{}'", input.replace('\\'', "${replacement}"))\n}`;
    const body = `    let a = req.param("a");\n    let cmd = format!("echo {}", shell_escape(&a));\n    let _ = Command::new("sh").arg("-c").arg(&cmd).output();`;
    expect(ids(handler(body, helper(String.raw`'\\''`)))).not.toContain("command-injection");
    expect(ids(handler(body, helper("")))).toContain("command-injection");
  });
});
