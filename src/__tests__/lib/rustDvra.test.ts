/**
 * @jest-environment node
 *
 * Coverage found scoring the Damn Vulnerable Rust Application (DVRA-1 oracle): an app's own Request type read through
 * `query_get` / `header_value`-style helpers, a store's own `query_*` method fed SQL text built in the handler, and a
 * secret-named field formatted into a log message across lines (CWE-532).
 */
import { analyzeFile } from "@/lib/scanner";
import { warmRustTaintEngine } from "@/lib/astTaintRust";

beforeAll(async () => { await warmRustTaintEngine(); }, 120000);

const ids = (code: string) => analyzeFile("src/features/handler.rs", code).indicators.map(i => i.id);
const handler = (body: string) => `use crate::{App, Request, Response};\n\npub fn handle(app: &App, req: &Request) -> Response {\n${body}\n    Response::ok("x")\n}\n`;

describe("DVRA shapes", () => {
  it("query_get on an app Request, into a store's query helper with SQL text", () => {
    expect(ids(handler(`    let username = req.query_get("username").unwrap_or("");\n    let query = format!("SELECT id FROM users WHERE username = '{}'", username);\n    let rows = app.db.query_users(&query);`))).toContain("sql-injection");
    // a helper that isn't fed SQL text is not a SQL sink
    expect(ids(handler(`    let username = req.query_get("username").unwrap_or("");\n    let rows = app.db.query_users(&username);`))).not.toContain("sql-injection");
    // the same names on something that isn't the request read nothing from the client
    expect(ids(handler(`    let username = app.query_get("username").unwrap_or("");\n    let query = format!("SELECT id FROM users WHERE username = '{}'", username);\n    let rows = app.db.query_users(&query);`))).not.toContain("sql-injection");
  });
  it("a secret-named field formatted into a log call, on the call line or the one after", () => {
    expect(ids(handler(`    let t = req.header("x-token").unwrap_or("");\n    audit_log(&format!(\n        "login attempt token={} path={}",\n        t, req.path\n    ));`))).toContain("pii-in-logs");
    expect(ids(handler(`    let t = req.header("x-token").unwrap_or("");\n    eprintln!("[audit] password={}", t);`))).toContain("pii-in-logs");
    // a labeled field that isn't secret, or a secret word outside any log call
    expect(ids(handler(`    let p = req.path.clone();\n    eprintln!("[audit] path={}", p);`))).not.toContain("pii-in-logs");
    expect(ids(handler(`    let msg = format!("token={}", "redacted");\n    let _ = msg;`))).not.toContain("pii-in-logs");
  });
});
