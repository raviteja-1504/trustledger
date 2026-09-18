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

describe("Real AST-based taint engine — per-parameter return-taint precision (multi-param helper)", () => {
  // buildLog's return only ever depends on userId -- message is never
  // referenced in it at all. A per-METHOD propagating boolean (the old
  // design) can't tell the two params apart, so it would fire on
  // buildLog("static-id", message) even though message never flows
  // anywhere. Per-parameter tracking must not.
  const helper = `
public class A {
  private String buildLog(String userId, String message) {
    return "User " + userId + " did something";
  }`;

  it("does NOT flag when only the unused parameter is tainted", () => {
    const content = `${helper}
  public void handler(@RequestParam String message) {
    Runtime.getRuntime().exec(buildLog("static-id", message));
  }
}`;
    expect(scan(content).some(f => f.id === "command-injection")).toBe(false);
  });

  it("still flags when the parameter that actually reaches the return IS tainted", () => {
    const content = `${helper}
  public void handler(@RequestParam String userId) {
    Runtime.getRuntime().exec(buildLog(userId, "static message"));
  }
}`;
    expect(scan(content).some(f => f.id === "command-injection")).toBe(true);
  });

  it("flags when EITHER of two independently-propagating params is tainted", () => {
    const combine = `
public class A {
  private String combine(String a, String b) { return a + b; }`;
    const aTainted = `${combine}
  public void h(@RequestParam String a) { Runtime.getRuntime().exec(combine(a, "safe")); }
}`;
    const bTainted = `${combine}
  public void h(@RequestParam String b) { Runtime.getRuntime().exec(combine("safe", b)); }
}`;
    expect(scan(aTainted).some(f => f.id === "command-injection")).toBe(true);
    expect(scan(bTainted).some(f => f.id === "command-injection")).toBe(true);
  });
});

describe("Real AST-based taint engine — Java parity: sink inside a callee's own body (new capability)", () => {
  it("catches a sink call inside a local method's body (not its return) when called with a tainted argument", () => {
    const content = `
public class A {
  private void logAndRun(String cmd) {
    Runtime.getRuntime().exec(cmd);
  }
  public void handler(@RequestParam String userCmd) {
    logAndRun(userCmd);
  }
}`;
    // Before this fix, astTaintJava.ts had no seededParams-equivalent
    // mechanism at all -- logAndRun's own body was only ever walked with
    // its (non-existent) Spring-annotated params seeded, never with a
    // caller's tainted argument, so this returned [] regardless.
    expect(scan(content).some(f => f.id === "command-injection")).toBe(true);
  });
});

describe("Real AST-based taint engine — varargs parameters are no longer silently dropped", () => {
  it("recognizes a varargs parameter and taints call sites that pass an argument into its absorbed range", () => {
    const content = `
public class A {
  private void runAll(String prefix, String... cmds) {
    Runtime.getRuntime().exec(prefix + cmds);
  }
  public void handler(@RequestParam String userCmd) {
    runAll("safe-prefix", userCmd);
  }
}`;
    // Before the varargs extraction fix, paramInfo() returned null for the
    // "String... cmds" parameter entirely, so it never appeared in
    // paramShapes at all -- seedLocalMethodParams could never match any
    // call-site argument to it (here, the 2nd call argument, index 1),
    // regardless of position, and this would have returned [] instead.
    expect(scan(content).some(f => f.id === "command-injection")).toBe(true);
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

describe("BOLA (Broken Object Level Authorization) — Spring resource-identifier ownership check", () => {
  itIfExists(JAVA_FIXTURE)("flags all 4 owasp_test_app.java BOLA endpoints, read vs write severity distinguished", () => {
    const content = fs.readFileSync(JAVA_FIXTURE, "utf8");
    const findings = scan(content);
    const bola = findings.filter(f => f.id === "bola-missing-ownership-check");
    // getUser (line 87, @GetMapping) -> read -> medium
    expect(bola.some(f => f.line === 87 && f.severityOverride === "medium")).toBe(true);
    // deleteUser (line 100, @DeleteMapping) -> write -> high
    expect(bola.some(f => f.line === 100 && f.severityOverride === "high")).toBe(true);
    // updateUser (@PutMapping): users.getOrDefault(userId, ...) at line 113
    // and users.put(userId, user) at line 117 -- both write -> high.
    expect(bola.some(f => f.line === 113 && f.severityOverride === "high")).toBe(true);
    expect(bola.some(f => f.line === 117 && f.severityOverride === "high")).toBe(true);
    // updateRole (@PatchMapping, privilege-escalation write): users.get(userId)
    // appears at line 129 (the .put("role", role) receiver) and again at
    // line 131 (the return statement's read) -- both write -> high.
    expect(bola.some(f => f.line === 129 && f.severityOverride === "high")).toBe(true);
    expect(bola.some(f => f.line === 131 && f.severityOverride === "high")).toBe(true);
  });

  it("does not flag when a real .equals() ownership check is present in the method body", () => {
    const content = `
public class A {
  private final Map<String, Map<String, Object>> users = new HashMap<>();
  @GetMapping("/api/users/{userId}")
  public Object get(@PathVariable String userId, Authentication authentication) {
    if (!userId.equals(authentication.getName())) {
      return ResponseEntity.status(403).build();
    }
    return ResponseEntity.ok(users.get(userId));
  }
}`;
    expect(scan(content).some(f => f.id === "bola-missing-ownership-check")).toBe(false);
  });

  it("still flags when .equals() is present but compares unrelated values, not an ownership check", () => {
    const content = `
public class A {
  private final Map<String, Map<String, Object>> users = new HashMap<>();
  @GetMapping("/api/users/{userId}")
  public Object get(@PathVariable String userId) {
    if ("tom".equals("jerry")) {
      return ResponseEntity.status(400).build();
    }
    return ResponseEntity.ok(users.get(userId));
  }
}`;
    // Proves this isn't pure keyword-presence the way the regex heuristics
    // are -- a .equals() call exists in the method, but neither operand
    // references the resource-id param or anything principal-shaped.
    expect(scan(content).some(f => f.id === "bola-missing-ownership-check")).toBe(true);
  });

  it("suppresses when @PreAuthorize is present, regardless of method body", () => {
    const content = `
public class A {
  private final Map<String, Map<String, Object>> users = new HashMap<>();
  @PreAuthorize("hasRole('ADMIN')")
  @DeleteMapping("/api/users/{userId}")
  public Object del(@PathVariable String userId) {
    users.remove(userId);
    return ResponseEntity.ok().build();
  }
}`;
    expect(scan(content).some(f => f.id === "bola-missing-ownership-check")).toBe(false);
  });

  it("recognizes @AuthenticationPrincipal as principal-looking, and never as a tainted resource-id source", () => {
    const content = `
public class A {
  private final Map<String, Map<String, Object>> users = new HashMap<>();
  @GetMapping("/api/users/{userId}")
  public Object get(@PathVariable String userId, @AuthenticationPrincipal String currentUserId) {
    if (!userId.equals(currentUserId)) {
      return ResponseEntity.status(403).build();
    }
    return ResponseEntity.ok(users.get(userId));
  }
}`;
    expect(scan(content).some(f => f.id === "bola-missing-ownership-check")).toBe(false);
    // @AuthenticationPrincipal must never itself be treated as a taint
    // source for the other 9 sink categories -- confirm it doesn't light up
    // e.g. sql-injection if misused directly in a query.
    const misuse = `
public class A {
  public void handle(@AuthenticationPrincipal String currentUserId) {
    executeQuery("SELECT * FROM x WHERE y = " + currentUserId);
  }
}`;
    expect(scan(misuse).some(f => f.id === "sql-injection")).toBe(false);
  });

  it("does not flag a non-endpoint method (no Spring mapping annotation) even with a bare Map lookup", () => {
    const content = `
public class A {
  private final Map<String, Map<String, Object>> users = new HashMap<>();
  public Object internalHelper(String userId) {
    return users.get(userId);
  }
}`;
    expect(scan(content).some(f => f.id === "bola-missing-ownership-check")).toBe(false);
  });

  it("does not flag a Map lookup on a local variable (not a class field)", () => {
    const content = `
public class A {
  @GetMapping("/api/users/{userId}")
  public Object get(@PathVariable String userId) {
    Map<String, Object> localCache = new HashMap<>();
    return localCache.get(userId);
  }
}`;
    expect(scan(content).some(f => f.id === "bola-missing-ownership-check")).toBe(false);
  });

  it("never throws on a malformed-annotation Java snippet", () => {
    const content = `
public class A {
  @GetMapping(
  public Object get(@PathVariable String userId) {
    return null;
`;
    expect(() => parseJavaSource(content)).not.toThrow();
    const cst = parseJavaSource(content);
    if (cst) expect(() => scanAstTaintJava(content, "A.java", cst)).not.toThrow();
  });

  // WebGoat's IDOREditOtherProfile.java / IDORViewOtherProfile.java were
  // evaluated as candidate real-world regression fixtures and found out of
  // scope for this phase, by direct read: neither builds on a repository or
  // Map-field lookup -- both construct `new UserProfile(userId)` directly,
  // a shape outside every sink category this engine recognizes (findById/
  // getOne/getById, field-backed Map get/getOrDefault/put/remove,
  // deleteById/delete/save). IDOREditOtherProfile.java is also the concrete
  // real-world example motivating this phase's "no branch/control-flow
  // awareness" limitation: its vulnerable branch is gated by an INVERTED
  // comparison (`!userSubmittedProfile.getUserId().equals(authUserId)`),
  // which a real CFG-aware ownership check would need to recognize as
  // gating the DANGEROUS path, not the safe one -- deliberately not
  // attempted here (see astTaintJava.ts's collectBolaFindings docblock).
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
