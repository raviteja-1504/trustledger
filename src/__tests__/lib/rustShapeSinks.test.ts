/**
 * @jest-environment node
 *
 * Rust sinks found scoring the 0llino Rust SAST benchmark: request data in log macros, SQL / LDAP filters /
 * Location headers built with format! (sinks by shape, as the Java engine treats `+` chains), HTML handed to an
 * application's own response type, and TLS verification switched off. Each has a safe twin.
 */
import { analyzeFile } from "@/lib/scanner";
import { warmRustTaintEngine } from "@/lib/astTaintRust";

beforeAll(async () => { await warmRustTaintEngine(); }, 120000);

const handler = (body: string, extra = "") => `pub fn handle(req: &super::shared::BenchmarkRequest) -> super::shared::BenchmarkResponse {
${body}
}
${extra}`;
const ids = (code: string) => analyzeFile("src/handlers/h.rs", code).indicators.filter(i => !!i.sourceExpr).map(i => i.id);
const has = (code: string, id: string) => ids(code).includes(id);

describe("log injection", () => {
  it("request data in a log macro, directly or through a helper; CR/LF stripped or a constant is not", () => {
    expect(has(handler(`    let ip = req.header("X-Forwarded-For");\n    log::warn!("Request from: {}", ip);\n    super::shared::BenchmarkResponse::ok("OK")`), "log-injection")).toBe(true);
    expect(has(handler(`    let ip = req.header("X-Forwarded-For");\n    log_warn(&format!("Request from: {}", ip));\n    super::shared::BenchmarkResponse::ok("OK")`, `fn log_warn(msg: &str) {\n    eprintln!("[WARN] {}", msg);\n}`), "log-injection")).toBe(true);
    expect(has(handler(`    let ip = req.header("X-Forwarded-For");\n    tracing::info!("Request from: {ip}");\n    super::shared::BenchmarkResponse::ok("OK")`), "log-injection")).toBe(true);
    expect(has(handler(`    let ip = req.header("X-Forwarded-For").replace('\\n', "").replace('\\r', "");\n    log::warn!("Request from: {}", ip);\n    super::shared::BenchmarkResponse::ok("OK")`), "log-injection")).toBe(false);
    expect(has(handler(`    let _ip = req.header("X-Forwarded-For");\n    log::warn!("Request received");\n    super::shared::BenchmarkResponse::ok("OK")`), "log-injection")).toBe(false);
  });
  it("a newline escaped to a visible \\n is safe; one replaced by another line break is not", () => {
    const esc = (to: string) => handler(`    let d = req.param("data");\n    let e = d.replace('\\n', ${to});\n    eprintln!("{}", e);\n    super::shared::BenchmarkResponse::ok("OK")`);
    expect(has(esc(`"\\\\n"`), "log-injection")).toBe(false);
    expect(has(esc(`"\\r\\n"`), "log-injection")).toBe(true);
  });
});

describe("guards and escapers", () => {
  it("a structural HTML escaper helper; a helper that escapes nothing still reports", () => {
    const esc = (body: string) => handler(`    let name = html_escape(&req.param("name"));\n    let html = format!("<h2>{}</h2>", name);\n    super::shared::BenchmarkResponse::ok(&html)`, `fn html_escape(s: &str) -> String {\n    ${body}\n}`);
    expect(has(esc(`s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")`), "xss")).toBe(false);
    expect(has(esc(`s.replace('&', "&amp;")`), "xss")).toBe(true);
  });
  it("a trusted-prefix predicate (two prefixes OR'ed) guards a redirect; a prefix without a path does not", () => {
    const red = (cond: string) => handler(`    let url = req.param("url");\n    if is_trusted_host(&url) {\n        let location = format!("Location: {}", url);\n        super::shared::BenchmarkResponse::ok(&location)\n    } else {\n        super::shared::BenchmarkResponse::bad_request("no")\n    }`, `fn is_trusted_host(url: &str) -> bool {\n    ${cond}\n}`);
    expect(has(red(`url.starts_with("https://example.com/") || url.starts_with("https://app.example.com/")`), "open-redirect")).toBe(false);
    // "https://example.com" also matches https://example.com.evil.net
    expect(has(red(`url.starts_with("https://example.com")`), "open-redirect")).toBe(true);
    expect(has(red(`url.starts_with("https://example.com/") || url.len() > 3`), "open-redirect")).toBe(true);
  });
});

describe("sinks by shape", () => {
  it("SQL built with format! around request text; a parsed number is not", () => {
    expect(has(handler(`    let q = req.param("q");\n    let sql = format!("SELECT * FROM items WHERE name LIKE '%{}%'", q);\n    super::shared::BenchmarkResponse::ok(&sql)`), "sql-injection")).toBe(true);
    expect(has(handler(`    let raw = req.param("offset");\n    let offset: u32 = match raw.parse::<u32>() { Ok(v) => v, Err(_) => return super::shared::BenchmarkResponse::bad_request("bad") };\n    let sql = format!("SELECT * FROM items LIMIT 20 OFFSET {}", offset);\n    super::shared::BenchmarkResponse::ok(&sql)`), "sql-injection")).toBe(false);
  });
  it("a format! that is not a statement is not SQL", () => {
    expect(has(handler(`    let q = req.param("q");\n    let msg = format!("You searched for select items from {}", q);\n    super::shared::BenchmarkResponse::ok(&msg)`), "sql-injection")).toBe(false);
  });
  it("an LDAP filter and a Location header built from request text", () => {
    expect(has(handler(`    let name = req.param("name");\n    let filter = format!("(&(cn={})(department=Engineering))", name);\n    super::shared::BenchmarkResponse::ok(&filter)`), "ldap-injection")).toBe(true);
    expect(has(handler(`    let name = req.param("name");\n    let filter = format!("(&(cn={})(department=Engineering))", "fixed");\n    let _ = name;\n    super::shared::BenchmarkResponse::ok(&filter)`), "ldap-injection")).toBe(false);
    expect(has(handler(`    let url = req.param("url");\n    let location = format!("Location: {}", url);\n    super::shared::BenchmarkResponse::ok(&location)`), "open-redirect")).toBe(true);
    expect(has(handler(`    let url = req.param("url");\n    let location = format!("Location: /home?next={}", url.len());\n    super::shared::BenchmarkResponse::ok(&location)`), "open-redirect")).toBe(false);
  });
  it("a shape that also reaches sqlx is reported once, at the query", () => {
    const code = `use sqlx::PgPool;\npub async fn h(axum::extract::Query(p): axum::extract::Query<std::collections::HashMap<String, String>>, pool: axum::extract::State<PgPool>) {\n    let name = p.get("n").cloned().unwrap_or_default();\n    let sql = format!("SELECT * FROM users WHERE name = '{}'", name);\n    let _ = sqlx::query(&sql).fetch_all(&*pool).await;\n}\n`;
    const sqli = analyzeFile("src/handlers/h.rs", code).indicators.filter(i => i.id === "sql-injection" && !!i.sourceExpr).map(i => i.line);
    expect(sqli).toEqual([5]);
  });
});

describe("HTML handed to the application's response type", () => {
  it("HTML around request text; escaped text is not", () => {
    expect(has(handler(`    let username = req.param("username");\n    let html = format!("<script>var user = \\"{}\\";</script>", username);\n    super::shared::BenchmarkResponse::ok(&html)`), "xss")).toBe(true);
    expect(has(handler(`    let username = html_escape::encode_text(&req.param("username")).to_string();\n    let html = format!("<p>{}</p>", username);\n    super::shared::BenchmarkResponse::ok(&html)`), "xss")).toBe(false);
    expect(has(handler(`    let username = req.param("username");\n    let text = format!("Hello {}", username);\n    super::shared::BenchmarkResponse::ok(&text)`), "xss")).toBe(false);
  });
});

describe("TLS verification switched off", () => {
  const tls = (code: string) => analyzeFile("src/client.rs", `use std::sync::Arc;\n\npub fn client() {\n    ${code}\n}\n`).indicators.some(i => i.id === "tls-verification-disabled");
  it("reqwest's builder, a struct literal, rustls' custom verifier; verification kept on is not", () => {
    expect(tls(`let c = reqwest::Client::builder().danger_accept_invalid_certs(true).build()?;`)).toBe(true);
    expect(tls(`fn get_http_client() -> TlsClient { TlsClient { danger_accept_invalid_certs: true } }`)).toBe(true);
    expect(tls(`let cfg = ClientConfig::builder().dangerous().set_certificate_verifier(Arc::new(NoVerify));`)).toBe(true);
    expect(tls(`let c = reqwest::Client::builder().danger_accept_invalid_certs(false).build()?;`)).toBe(false);
  });
  it("verify-named switches set false, accept-invalid-named ones set true, OpenSSL's NONE mode", () => {
    expect(tls(`let cfg = TlsConfig { verify_tls: false, timeout: 30 };`)).toBe(true);
    expect(tls(`let cfg = Opts { verify_hostname: false, verify_cert: true };`)).toBe(true);
    expect(tls(`let c = Client { accept_invalid_certs: true };`)).toBe(true);
    expect(tls(`ctx.set_verify(SslVerifyMode::NONE);`)).toBe(true);
    expect(tls(`let cfg = TlsConfig { verify_tls: true, verify_hostname: true };`)).toBe(false);
    expect(tls(`struct TlsConfig { verify_tls: bool, accept_invalid_certs: bool }`)).toBe(false);
  });
  it("the same switch in PHP, Ruby and C#", () => {
    expect(analyzeFile("a.php", `<?php curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);`).indicators.some(i => i.id === "tls-verification-disabled")).toBe(true);
    expect(analyzeFile("a.php", `<?php curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);`).indicators.some(i => i.id === "tls-verification-disabled")).toBe(false);
    const rb = (mode: string) => analyzeFile("lib/client.rb", `require 'net/http'\nhttp = Net::HTTP.new(host, 443)\nhttp.use_ssl = true\nhttp.verify_mode = ${mode}\n`).indicators.some(i => i.id === "tls-verification-disabled");
    expect(rb("OpenSSL::SSL::VERIFY_NONE")).toBe(true);
    expect(rb("OpenSSL::SSL::VERIFY_PEER")).toBe(false);
    expect(analyzeFile("a.cs", `handler.ServerCertificateCustomValidationCallback = (m, c, ch, e) => true;`).indicators.some(i => i.id === "tls-verification-disabled")).toBe(true);
  });
});
