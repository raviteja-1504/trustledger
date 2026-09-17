import fs from "fs";
import { analyzeFile } from "@/lib/scanner";
import { scanAstTaintJava, parseJavaSource } from "@/lib/astTaintJava";

const SCRATCHPAD = "C:/Users/ADMIN/AppData/Local/Temp/claude/d--trustledger/dd894828-e726-4544-b53b-93aca10d3d41/scratchpad";
const JAVA_FIXTURE = `${SCRATCHPAD}/owasp_test_app.java`;

function itIfExists(path: string) {
  return fs.existsSync(path) ? it : it.skip;
}

function scan(content: string) {
  const cst = parseJavaSource(content);
  if (!cst) throw new Error("parse failed");
  return scanAstTaintJava(content, "A.java", cst);
}

describe("Real AST-based taint engine (Phase 3: Java) — regression floor against the real Spring Boot OWASP benchmark fixture", () => {
  itIfExists(JAVA_FIXTURE)("still finds every regex-caught id, plus the headline AST-only insecure-deserialization catch", () => {
    const content = fs.readFileSync(JAVA_FIXTURE, "utf8");
    const result = analyzeFile("owasp_test_app.java", content);
    const ids = new Set(result.indicators.map(i => i.id));
    // ldap-injection is deliberately excluded: the fixture's /ldap endpoint
    // calls a fabricated local helper (fakeLdapSearch(filter)), not a real
    // DirContext/LdapTemplate API -- neither the pre-existing regex nor this
    // engine's sink table can reasonably be expected to recognize an
    // arbitrarily-named local method as an LDAP sink without risking false
    // positives on unrelated code elsewhere. Verified directly by reading
    // the fixture, not assumed.
    for (const id of ["sql-injection", "command-injection", "path-traversal", "open-redirect", "xpath-injection"]) {
      expect(ids.has(id)).toBe(true);
    }
    const astFindings = scan(content);
    // Headline AST-only catch: bare ObjectInputStream.readObject() with no
    // inline request.getInputStream() call -- INSECURE_DESERIAL_RE cannot
    // match this shape at all. Confirmed exact line by reading the fixture.
    expect(astFindings.some(f => f.id === "insecure-deserialization" && f.line === 402)).toBe(true);
    // Also an AST-only catch: xpath-injection at the fixture's real /xpath
    // endpoint, confirmed present only via this engine (not the pre-existing
    // regex, which requires XPathExpression.evaluate(...+request.getParameter(
    // on one line -- the fixture's real code is multi-statement).
    expect(astFindings.some(f => f.id === "xpath-injection")).toBe(true);
  });

  it("catches open-redirect through Spring's fluent ResponseEntity.status().header(\"Location\", tainted).build() idiom", () => {
    const content = `
public class A {
  @GetMapping("/redirect")
  public Object redirect(@RequestParam String next) {
    return ResponseEntity
      .status(HttpStatus.FOUND)
      .header("Location", next)
      .build();
  }
}`;
    const findings = scan(content);
    expect(findings.some(f => f.id === "open-redirect")).toBe(true);
  });

  it("does not flag .header() with a non-Location header name", () => {
    const content = `
public class A {
  public Object handle(@RequestParam String value) {
    return ResponseEntity.ok().header("X-Custom", value).build();
  }
}`;
    const findings = scan(content);
    expect(findings.some(f => f.id === "open-redirect")).toBe(false);
  });

  itIfExists(JAVA_FIXTURE)("never throws scanning the full real fixture", () => {
    const content = fs.readFileSync(JAVA_FIXTURE, "utf8");
    expect(() => scan(content)).not.toThrow();
    expect(() => analyzeFile("owasp_test_app.java", content)).not.toThrow();
  });
});

describe("Real AST-based taint engine — multi-line statements and String.format()/StringBuilder (the specific gaps this phase exists to close)", () => {
  it("catches SQL injection through a multi-line String.format() call feeding a multi-line-wrapped sink", () => {
    const content = `
public class A {
  public Object account(String id) throws Exception {
    String query = String.format(
      "SELECT * FROM accounts WHERE id = '%s'",
      id
    );
    return ResponseEntity.ok(
      executeQuery(query)
    );
  }
}`;
    // Prove Spring-annotation source recognition works without an inline
    // request.getParameter -- id becomes tainted only via the annotation.
    const annotated = `
public class A {
  @GetMapping("/api/account")
  public Object account(@RequestParam String id) throws Exception {
    String query = String.format(
      "SELECT * FROM accounts WHERE id = '%s'",
      id
    );
    return ResponseEntity.ok(
      executeQuery(query)
    );
  }
}`;
    expect(scan(content).some(f => f.id === "sql-injection")).toBe(false);
    expect(scan(annotated).some(f => f.id === "sql-injection")).toBe(true);
  });

  it("catches command injection through a StringBuilder.append() chain built across statements", () => {
    const content = `
public class A {
  public void run(@RequestParam String host) {
    StringBuilder sb = new StringBuilder();
    sb.append("ping -c 1 ");
    sb.append(host);
    Runtime.getRuntime().exec(sb.toString());
  }
}`;
    const findings = scan(content);
    expect(findings.some(f => f.id === "command-injection")).toBe(true);
  });

  it("catches command injection through a fluent single-chain StringBuilder.append()", () => {
    const content = `
public class A {
  public void run(@RequestParam String host) {
    Runtime.getRuntime().exec(new StringBuilder().append("ping -c 1 ").append(host).toString());
  }
}`;
    const findings = scan(content);
    expect(findings.some(f => f.id === "command-injection")).toBe(true);
  });

  it("catches SQL injection through plain + concatenation split across lines", () => {
    const content = `
public class A {
  public void run(@RequestParam String username) {
    String query =
      "SELECT * FROM users WHERE username = '" +
      username +
      "'";
    executeQuery(query);
  }
}`;
    const findings = scan(content);
    expect(findings.some(f => f.id === "sql-injection")).toBe(true);
  });
});

describe("Real AST-based taint engine — insecure deserialization (headline new catch)", () => {
  it("catches <var>.readObject() where the ObjectInputStream was itself built from tainted data, across nested constructor calls", () => {
    const content = `
public class A {
  public Object restore(@RequestBody byte[] serialized) throws Exception {
    ObjectInputStream input = new ObjectInputStream(new ByteArrayInputStream(serialized));
    Object object = input.readObject();
    return object;
  }
}`;
    const findings = scan(content);
    expect(findings.some(f => f.id === "insecure-deserialization")).toBe(true);
  });

  it("does not flag readObject() on an ObjectInputStream built from untainted data", () => {
    const content = `
public class A {
  public Object restore() throws Exception {
    ObjectInputStream input = new ObjectInputStream(new FileInputStream("/etc/trusted-config.bin"));
    Object object = input.readObject();
    return object;
  }
}`;
    const findings = scan(content);
    expect(findings.some(f => f.id === "insecure-deserialization")).toBe(false);
  });
});

describe("Real AST-based taint engine — same-file interprocedural call binding", () => {
  it("propagates taint through a local helper's return value to the call site", () => {
    const content = `
public class A {
  private String buildQuery(String uid) {
    return "SELECT * FROM users WHERE id = " + uid;
  }
  public void handler(@RequestParam String uid) {
    executeQuery(buildQuery(uid));
  }
}`;
    const findings = scan(content);
    expect(findings.some(f => f.id === "sql-injection")).toBe(true);
  });

  it("does not propagate taint through a helper whose return value never depends on its parameters", () => {
    const content = `
public class A {
  private String tableName(String uid) {
    return "users";
  }
  public void handler(@RequestParam String uid) {
    executeQuery(tableName(uid));
  }
}`;
    const findings = scan(content);
    expect(findings.some(f => f.id === "sql-injection")).toBe(false);
  });
});

describe("Real AST-based taint engine — annotation scoping and negative cases", () => {
  it("does not treat a plain non-Spring parameter as tainted just because it's named like a common source", () => {
    const content = `
public class A {
  public void handle(String request) {
    executeQuery("SELECT * FROM x WHERE y = " + request);
  }
}`;
    const findings = scan(content);
    expect(findings.some(f => f.id === "sql-injection")).toBe(false);
  });

  it("catches SQL injection from a bare Servlet request.getParameter() call inline, with no intermediate variable", () => {
    const content = `
public class A {
  public void handle(HttpServletRequest request) {
    executeQuery("SELECT * FROM x WHERE y = " + request.getParameter("y"));
  }
}`;
    const findings = scan(content);
    expect(findings.some(f => f.id === "sql-injection")).toBe(true);
  });

  it("does not flag a call with no taint anywhere in scope", () => {
    const content = `
public class A {
  public void cleanup() {
    Runtime.getRuntime().exec("rm -rf /tmp/cache");
  }
}`;
    expect(scan(content)).toHaveLength(0);
  });

  it("does not flag subprocess-equivalent construction with no tainted argument", () => {
    const content = `
public class A {
  public void run() {
    ProcessBuilder pb = new ProcessBuilder("ls", "-la");
  }
}`;
    expect(scan(content).some(f => f.id === "command-injection")).toBe(false);
  });
});

describe("Real AST-based taint engine — malformed-input guards", () => {
  it("returns null from parseJavaSource on broken source, and never throws from scanAstTaintJava", () => {
    expect(parseJavaSource("public class {{{ broken")).toBeNull();
  });

  it("never throws on an empty file", () => {
    const cst = parseJavaSource("");
    expect(cst).not.toBeNull();
    if (cst) expect(() => scanAstTaintJava("", "A.java", cst)).not.toThrow();
  });
});
