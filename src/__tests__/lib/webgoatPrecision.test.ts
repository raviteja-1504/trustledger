/**
 * Precision fixes from scanning OWASP WebGoat, each with the real bug it must keep catching:
 *   - execute()/evaluate() are SQL/XPath sinks only on a receiver that can be one (not the class's own method)
 *   - a file-path call written inside a string literal is text, not a call
 *   - a PEM header with no key, and "API_KEY=" + UUID, are not hardcoded secrets
 *   - the PHP $_SESSION-guard rule runs on PHP only
 *   - header injection needs a header holder, not any map with an "origin" key
 *   - a PrintWriter opened on a file is not an XSS sink
 *   - a lookup in an immutable Map.of(...) table is not a BOLA store, and its result isn't the request's value
 *   - new: jjwt parse() (accepts unsigned tokens) and Spring "redirect:" + input open redirects
 */
import { analyzeFile } from "@/lib/scanner";
import { ensureTaintEngines } from "@/lib/engineWarmup";

jest.setTimeout(60_000);
beforeAll(async () => { await ensureTaintEngines(); });

const lines = (path: string, src: string, id: string) => analyzeFile(path, src).indicators.filter(i => i.id === id).map(i => i.line);
const ctrl = (body: string, extra = "") => `import org.springframework.web.bind.annotation.*;
@RestController
public class C extends Base {
${extra}
  @PostMapping("/x")
  public Object x(@RequestParam String name) {
${body}
  }
}
`;
// The body starts on line 7 of ctrl().
const L = 7;

describe("execute()/evaluate() only on a receiver that can be a JDBC statement / XPath", () => {
  it("the class's own method (bare, super., this.) is not SQL injection -- WebGoat's super.execute(file, name, user)", () => {
    for (const call of ["super.execute(file, name, user);", "execute(name);", "this.execute(name);"]) {
      expect(lines("C.java", ctrl(`    return ${call}`), "sql-injection")).toEqual([]);
    }
  });

  it("a receiver declared as something else is not either; a Statement / Connection chain still is", () => {
    const typed = (t: string, call: string) => ctrl(`    return svc.${call};`, `  private final ${t} svc;`);
    expect(lines("C.java", typed("CommandService", "execute(name)"), "sql-injection")).toEqual([]);
    expect(lines("C.java", typed("ConfigService", "evaluate(name)"), "xpath-injection")).toEqual([]);
    expect(lines("C.java", typed("Statement", "execute(\"SELECT * FROM t WHERE n='\" + name + \"'\")"), "sql-injection")).toEqual([L]);
    expect(lines("C.java", typed("XPath", "evaluate(\"//user[@name='\" + name + \"']\", doc)"), "xpath-injection")).toEqual([L]);
    expect(lines("C.java", ctrl(`    return connection.createStatement().execute("SELECT * FROM t WHERE n='" + name + "'");`), "sql-injection")).toEqual([L]);
  });
});

describe("path traversal: the call, not text that mentions it", () => {
  it("an answer check containing \"new File(...)\" in a string is not a file operation", () => {
    const src = ctrl(`    String editor = name;\n    return editor.contains(".scan(c, new File(\\"antisamy.xml\\"))");`);
    expect(lines("C.java", src, "path-traversal")).toEqual([]);
    expect(lines("C.java", ctrl(`    String editor = name;\n    return new File("/data/" + editor);`), "path-traversal")).toContain(L + 1);
  });
});

describe("hardcoded secrets", () => {
  it("a PEM header alone (building or stripping one) is not a key; a header followed by key material is", () => {
    const body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj";
    expect(lines("src/Crypto.java", `class Crypto {\n  String h = "-----BEGIN PRIVATE KEY-----\\n";\n  String s(String p) { return p.replace("-----BEGIN PRIVATE KEY-----", ""); }\n}\n`, "hardcoded-secret")).toEqual([]);
    expect(lines("src/Crypto.java", `class Crypto {\n  String k = "-----BEGIN PRIVATE KEY-----\\n${body}";\n}\n`, "hardcoded-secret")).toEqual([2]);
    expect(lines("src/Crypto.java", `class Crypto {\n  String k = "-----BEGIN PRIVATE KEY-----\\n"\n    + "${body}";\n}\n`, "hardcoded-secret")).toEqual([2]);
  });

  it("a literal that only starts a runtime-built value is not the secret; a whole literal still is", () => {
    expect(lines("src/Keys.java", `class Keys {\n  String k() { String apiKey = "API_KEY=" + java.util.UUID.randomUUID(); return apiKey; }\n}\n`, "hardcoded-secret")).toEqual([]);
    expect(lines("src/Keys.java", `class Keys {\n  String apiKey = "Zx9Kq2Lm7Pw4Rt8Vb3Nc";\n}\n`, "hardcoded-secret")).toEqual([2]);
  });
});

describe("the PHP session-guard rule runs on PHP only", () => {
  it("an INSERT in Java is not 'missing a $_SESSION check'; the same in PHP still is", () => {
    const java = `class Repo {\n  void save() {\n    jdbc.update("INSERT INTO users(name) VALUES(:name)", p);\n  }\n}\n`;
    expect(lines("src/Repo.java", java, "php-missing-session-guard")).toEqual([]);
    const php = `<?php\n$db->query("INSERT INTO users(name) VALUES('x')");\n`;
    expect(lines("save.php", php, "php-missing-session-guard")).toEqual([2]);
  });
});

describe("header injection needs something that holds headers", () => {
  it("a JSON map with an origin key is not a response header (WebAuthn clientData); response headers still are", () => {
    expect(lines("C.java", ctrl(`    java.util.Map<String, Object> clientData = new java.util.HashMap<>();\n    clientData.put("origin", name);\n    return clientData;`), "header-injection")).toEqual([]);
    expect(lines("C.java", ctrl(`    HttpHeaders headers = new HttpHeaders();\n    headers.set("X-User", name);\n    return headers;`), "header-injection")).toEqual([L + 1]);
  });
});

describe("XSS: a writer opened on a file writes to disk", () => {
  it("new PrintWriter(logFile) is not a browser response; response.getWriter() still is", () => {
    const toFile = ctrl(`    java.io.File logFile = new java.io.File("/tmp/log.txt");\n    try (java.io.PrintWriter pw = new java.io.PrintWriter(logFile)) { pw.println(name); }\n    return null;`);
    expect(lines("C.java", toFile, "xss")).toEqual([]);
    const toBrowser = ctrl(`    java.io.PrintWriter pw = response.getWriter();\n    pw.println("<p>" + name);\n    return null;`, "  private javax.servlet.http.HttpServletResponse response;");
    expect(lines("C.java", toBrowser, "xss")).toContain(L + 1);
  });
});

describe("a fixed Map.of(...) allowlist", () => {
  const SAFE = `  private static final java.util.Map<Integer, String> DESTINATIONS =\n      java.util.Map.of(1, "/a", 2, "/b");`;
  const STORE = `  private final java.util.Map<Integer, String> DESTINATIONS = new java.util.HashMap<>();`;
  const redirect = (field: string) => `import org.springframework.web.bind.annotation.*;
@RestController
public class R {
${field}
  @GetMapping("/go")
  public org.springframework.web.servlet.ModelAndView go(@RequestParam Integer destId) {
    String dest = DESTINATIONS.getOrDefault(destId, "/welcome");
    return new org.springframework.web.servlet.ModelAndView("redirect:" + dest);
  }
}
`;
  it("is not a BOLA store, and the looked-up value isn't the request's own (no open redirect)", () => {
    expect(lines("R.java", redirect(SAFE), "bola-missing-ownership-check")).toEqual([]);
    expect(lines("R.java", redirect(SAFE), "open-redirect")).toEqual([]);
    // a mutable map of records is still a store an id must own
    expect(lines("R.java", redirect(STORE), "bola-missing-ownership-check")).toEqual([7]);
  });
});

describe("new detections", () => {
  it("jjwt parse() accepts an unsigned token; parseClaimsJws() does not", () => {
    const jwt = (call: string) => `class J {\n  Object c(String token) {\n    return Jwts.parser().setSigningKey(KEY).${call}(token);\n  }\n}\n`;
    const parse = analyzeFile("J.java", jwt("parse")).indicators.filter(i => i.id === "jwt-none-alg");
    expect(parse.map(i => i.line)).toEqual([3]);
    expect(parse[0].detail).toMatch(/unsigned token/);
    expect(lines("J.java", jwt("parseClaimsJws"), "jwt-none-alg")).toEqual([]);
  });

  it("Spring redirects: ModelAndView(\"redirect:\" + input) and RedirectView(input); a plain view name is not", () => {
    const mv = (expr: string) => ctrl(`    return new org.springframework.web.servlet.ModelAndView(${expr});`);
    expect(lines("C.java", mv(`"redirect:" + name`), "open-redirect")).toEqual([L]);
    expect(lines("C.java", mv(`"profile/" + name`), "open-redirect")).toEqual([]);
    expect(lines("C.java", ctrl(`    return new org.springframework.web.servlet.view.RedirectView(name);`), "open-redirect")).toEqual([L]);
  });
});
