/**
 * @jest-environment node
 *
 * Rust checks for categories that scored zero or near it on the sast-benchmark suite: an upload saved under the
 * client's file name, a session cookie sent by a hand-built Set-Cookie header without HttpOnly / Secure (the cookie
 * string built on an earlier line), a hand-written LDAP escaper, allocations sized by data already received, and a
 * host taken out of a URL and checked against a literal allow-list. Each has a twin that stays silent.
 */
import { analyzeFile } from "@/lib/scanner";
import { warmRustTaintEngine } from "@/lib/astTaintRust";

beforeAll(async () => { await warmRustTaintEngine(); }, 120000);

const handler = (body: string, helpers = "") =>
  `${helpers}\npub fn handle(req: &super::shared::BenchmarkRequest) -> super::shared::BenchmarkResponse {\n${body}\n}\n`;
const ids = (code: string) => analyzeFile("src/handlers.rs", code).indicators.map(i => i.id);

describe("file upload", () => {
  it("request content written under the client's file name; a server-chosen name is not", () => {
    expect(ids(handler(`    let filename = req.param("filename");\n    let content = req.body_str();\n    let path = format!("uploads/{}", filename);\n    let _ = std::fs::write(&path, content.as_bytes());\n    super::shared::BenchmarkResponse::ok("saved")`))).toContain("insecure-file-upload");
    expect(ids(handler(`    let content = req.body_str();\n    let id = req.param("id");\n    let path = format!("uploads/{}.bin", id);\n    let _ = std::fs::write(&path, content.as_bytes());\n    super::shared::BenchmarkResponse::ok("saved")`))).not.toContain("insecure-file-upload");
    // reading a file the client names is path traversal, not an upload
    expect(ids(handler(`    let filename = req.param("filename");\n    let data = std::fs::read_to_string(format!("docs/{}", filename));\n    super::shared::BenchmarkResponse::ok("read")`))).not.toContain("insecure-file-upload");
  });
});

describe("hand-built Set-Cookie headers", () => {
  const send = (cookie: string) => handler(`    let token = req.param("token");\n    let cookie = format!("${cookie}", token);\n    super::shared::BenchmarkResponse::ok(&format!("Set-Cookie: {}", cookie))`);
  it("a session cookie without HttpOnly or Secure, built on the line before", () => {
    expect(ids(send("session={}; Path=/"))).toContain("cookie-no-httponly");
    expect(ids(send("session={}; HttpOnly"))).toContain("cookie-no-secure");
  });
  it("one with both flags, a preference cookie, or a CSRF token (script must read it) needs no HttpOnly", () => {
    expect(ids(send("session={}; Path=/; Secure; HttpOnly; SameSite=Strict"))).not.toContain("cookie-no-httponly");
    expect(ids(send("session={}; Path=/; Secure; HttpOnly; SameSite=Strict"))).not.toContain("cookie-no-secure");
    expect(ids(send("theme={}"))).not.toContain("cookie-no-httponly");
    expect(ids(send("csrf_token={}; Path=/; Secure; SameSite=Strict"))).not.toContain("cookie-no-httponly");
    // ...but a CSRF cookie still needs Secure
    expect(ids(send("csrf_token={}; Path=/"))).toContain("cookie-no-secure");
  });
  it("a cookie that went through a helper is not judged by its raw text", () => {
    expect(ids(handler(`    let token = req.param("token");\n    let raw = format!("session={}", token);\n    let cookie = with_flags(&raw);\n    super::shared::BenchmarkResponse::ok(&format!("Set-Cookie: {}", cookie))`))).not.toContain("cookie-no-httponly");
  });
});

describe("LDAP", () => {
  const ESCAPER = `fn ldap_escape(s: &str) -> String {\n    let mut out = String::with_capacity(s.len());\n    for c in s.chars() {\n        match c {\n            '*' => out.push_str("\\\\2a"),\n            '(' => out.push_str("\\\\28"),\n            ')' => out.push_str("\\\\29"),\n            '\\\\' => out.push_str("\\\\5c"),\n            other => out.push(other),\n        }\n    }\n    out\n}\nfn ldap_search(base: &str, filter: &str) -> String { format!("{} {}", base, filter) }`;
  const search = (value: string) => handler(`    let email = req.param("email");\n    let filter = format!("(mail={})", ${value});\n    let r = ldap_search("dc=example,dc=com", &filter);\n    super::shared::BenchmarkResponse::ok(&r)`, ESCAPER);
  it("a hand-written RFC 4515 escaper clears the filter; the raw value does not", () => {
    expect(ids(search("ldap_escape(&email)"))).not.toContain("ldap-injection");
    expect(ids(search("email"))).toContain("ldap-injection");
  });
  it("an escaper that misses a metacharacter is not one", () => {
    const partial = ESCAPER.replace(`            '*' => out.push_str("\\\\2a"),\n`, "");
    expect(ids(handler(`    let email = req.param("email");\n    let filter = format!("(mail={})", ldap_escape(&email));\n    let r = ldap_search("dc=example,dc=com", &filter);\n    super::shared::BenchmarkResponse::ok(&r)`, partial))).toContain("ldap-injection");
  });
  it("String::with_capacity(s.len()) is not an attacker-sized allocation; a parsed size is", () => {
    expect(ids(search("ldap_escape(&email)"))).not.toContain("integer-overflow");
    expect(ids(handler(`    let n: usize = req.param("n").parse().unwrap_or(0);\n    let buf: Vec<u8> = Vec::with_capacity(n);\n    super::shared::BenchmarkResponse::ok(&format!("{}", buf.len()))`))).toContain("integer-overflow");
  });
});

describe("open redirect", () => {
  const HELPERS = `fn extract_host(url: &str) -> String { url.split('/').nth(2).unwrap_or("").to_string() }\nfn is_allowed_host(host: &str) -> bool { matches!(host, "example.com" | "app.example.com") }`;
  it("a host extracted from the URL and matched against literals vets the URL", () => {
    const go = (guard: string) => handler(`    let url = req.param("url");\n    let host = extract_host(&url);\n    if ${guard} {\n        super::shared::BenchmarkResponse::ok(&format!("Location: {}", url))\n    } else {\n        super::shared::BenchmarkResponse::bad_request("no")\n    }`, HELPERS);
    expect(ids(go("is_allowed_host(&host)"))).not.toContain("open-redirect");
    expect(ids(go("!host.is_empty()"))).toContain("open-redirect");
  });
});
