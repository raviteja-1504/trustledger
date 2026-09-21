import fs from "fs";
import { analyzeFile } from "@/lib/scanner";
import { scanAstTaintJava, parseJavaSource, findEnclosingFunctionNameJava } from "@/lib/astTaintJava";

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

describe("Real AST-based taint engine — field-sensitive taint tracking (Decision 1, new capability)", () => {
  it("flags a sink using a field that was itself assigned a tainted value", () => {
    const content = `
public class A {
  @GetMapping("/x")
  public Object get(@RequestParam String name) {
    User user = new User();
    user.name = name;
    executeQuery("SELECT * FROM t WHERE x = " + user.name);
    return null;
  }
}`;
    expect(scan(content).some(f => f.id === "sql-injection")).toBe(true);
  });

  it("does NOT flag a sibling field on the same object that was never assigned taint", () => {
    // Before this phase, Java's env lookup collapsed any field read to its
    // root variable's own taint (rootVar = parts[0] only) -- `user` itself
    // was never marked tainted here (its constructor took no args), so this
    // already passed for the wrong reason (object-level under-approximation
    // masking the question). The field-taint pair above now proves the
    // engine is actually field-sensitive, not just accidentally silent.
    const content = `
public class A {
  public void handle(@RequestParam String name) {
    User user = new User();
    user.name = name;
    executeQuery("SELECT * FROM t WHERE x = " + user.email);
  }
}`;
    expect(scan(content).some(f => f.id === "sql-injection")).toBe(false);
  });

  it("also newly tracks plain-identifier reassignment (not just field writes) -- assignment of any kind was previously untracked entirely", () => {
    const content = `
public class A {
  public void handle(@RequestParam String input) {
    String x = "safe";
    x = input;
    executeQuery("SELECT * FROM t WHERE y = " + x);
  }
}`;
    expect(scan(content).some(f => f.id === "sql-injection")).toBe(true);
  });
});

describe("Real AST-based taint engine — sanitizer/de-taint recognition (Decision 2, new capability)", () => {
  it("still flags an unsanitized tainted argument reaching a sink (baseline)", () => {
    const content = `
public class A {
  public void handle(@RequestParam String input) {
    Runtime.getRuntime().exec(input);
  }
}`;
    expect(scan(content).some(f => f.id === "command-injection")).toBe(true);
  });

  // These two used to assert the opposite -- that an HTML encoder cleared
  // COMMAND-injection taint. That was a false negative: HTML-escaping does
  // nothing to stop shell metacharacters. Sanitizers are now keyed by the
  // sink classes they actually neutralize, so the command sink still fires.
  it("STILL flags command injection after the OWASP Java Encoder (Encode.forHtml) -- an HTML encoder is the wrong class", () => {
    const content = `
public class A {
  public void handle(@RequestParam String input) {
    String clean = Encode.forHtml(input);
    Runtime.getRuntime().exec(clean);
  }
}`;
    expect(scan(content).some(f => f.id === "command-injection")).toBe(true);
  });

  it("STILL flags command injection after Commons Text (StringEscapeUtils.escapeHtml4) -- wrong class", () => {
    const content = `
public class A {
  public void handle(@RequestParam String input) {
    String clean = StringEscapeUtils.escapeHtml4(input);
    Runtime.getRuntime().exec(clean);
  }
}`;
    expect(scan(content).some(f => f.id === "command-injection")).toBe(true);
  });

  it("does not flag command injection after ESAPI encodeForOS (the right class for a command sink)", () => {
    const content = `
public class A {
  public void handle(@RequestParam String input) {
    String clean = ESAPI.encoder().encodeForOS(codec, input);
    Runtime.getRuntime().exec(clean);
  }
}`;
    expect(scan(content).some(f => f.id === "command-injection")).toBe(false);
  });

  it("does not flag SQL injection after Integer.parseInt (numeric coercion clears injection classes)", () => {
    const content = `
public class A {
  public void handle(@RequestParam String input) {
    int id = Integer.parseInt(input);
    stmt.executeQuery("SELECT * FROM t WHERE id = " + id);
  }
}`;
    expect(scan(content).some(f => f.id === "sql-injection")).toBe(false);
  });
});

describe("Real AST-based taint engine — bounded interprocedural propagation (Decision 3, MAX_PROPAGATION_ROUNDS = 3)", () => {
  // Caller-declared-first chain (levelA declared before the levelB it calls,
  // and so on): the fixed-point pre-pass processes methods in declaration
  // order each round, so a method can only see a callee's propagating status
  // from an EARLIER point in the SAME or a PRIOR round, never one declared
  // later in the same round. Traced by hand (and confirmed by running this
  // suite) that levelD resolves round 0, levelC round 1, levelB round 2, and
  // levelA would only resolve in a would-be round 3 -- one past the cap.
  const chain = `
public class A {
  private String levelA(String x) { return levelB(x); }
  private String levelB(String x) { return levelC(x); }
  private String levelC(String x) { return levelD(x); }
  private String levelD(String x) { return x; }`;

  it("resolves a chain called at its base case (0 hops from a param reference)", () => {
    const content = `${chain}
  public void handler(@RequestParam String input) {
    Runtime.getRuntime().exec(levelD(input));
  }
}`;
    expect(scan(content).some(f => f.id === "command-injection")).toBe(true);
  });

  it("resolves levelB, 2 hops deep, within the 3-round cap", () => {
    const content = `${chain}
  public void handler(@RequestParam String input) {
    Runtime.getRuntime().exec(levelB(input));
  }
}`;
    expect(scan(content).some(f => f.id === "command-injection")).toBe(true);
  });

  it("does NOT resolve levelA, the outermost 3-hop caller, proving the round cap is real (not accidentally unbounded)", () => {
    const content = `${chain}
  public void handler(@RequestParam String input) {
    Runtime.getRuntime().exec(levelA(input));
  }
}`;
    expect(scan(content).some(f => f.id === "command-injection")).toBe(false);
  });
});

describe("BOLA — constructor-sink vocabulary fix (Decision 4, closes the WebGoat IDOREditOtherProfile.java gap)", () => {
  it("flags `new ClassName(id)` fed a resource-id param with no auth annotation or ownership comparison in scope", () => {
    const content = `
public class A {
  @GetMapping("/api/profile/{userId}")
  public Object get(@PathVariable String userId) {
    UserProfile profile = new UserProfile(userId);
    return profile;
  }
}`;
    // Before this fix, checkBolaSinkCandidate's vocabulary (findById/save/
    // Map get-put/etc) had no notion of a constructor call at all -- this
    // returned [] regardless of how directly userId flowed into `new
    // UserProfile(...)`.
    expect(scan(content).some(f => f.id === "bola-missing-ownership-check")).toBe(true);
  });

  it("does not flag a constructor call whose argument doesn't reference the resource-id param", () => {
    const content = `
public class A {
  @GetMapping("/api/profile/{userId}")
  public Object get(@PathVariable String userId) {
    UserProfile profile = new UserProfile("anonymous");
    return profile;
  }
}`;
    expect(scan(content).some(f => f.id === "bola-missing-ownership-check")).toBe(false);
  });

  // Formerly a documented gap: the engine asked "is there ANY ownership
  // comparison in the method". The inverted WebGoat IDOREditOtherProfile.java
  // shape -- the lookup runs in the arm where `!id.equals(principal)` is TRUE,
  // i.e. exactly when ownership FAILED -- is now reported, because the
  // comparison must DOMINATE the sink (path-sensitivity phase).
  it("reports a lookup in the branch that runs when the ownership comparison FAILS", () => {
    const content = `
public class A {
  @GetMapping("/api/profile/{userId}")
  public Object get(@PathVariable String userId, Authentication authentication) {
    if (!userId.equals(authentication.getName())) {
      UserProfile profile = new UserProfile(userId);
      return profile;
    }
    return ResponseEntity.status(403).build();
  }
}`;
    expect(scan(content).some(f => f.id === "bola-missing-ownership-check")).toBe(true);
  });
});

describe("findEnclosingFunctionNameJava — reachability resolver parity (Decision 2, new capability)", () => {
  const content = `
public class A {
  public Object getUser(String id) {
    Object user = Database.find(id);
    return user;
  }

  public Object deleteUser(String id) {
    Database.delete(id);
    return null;
  }
}`;
  const cst = parseJavaSource(content);
  const lines = content.split("\n");

  it("resolves a row inside the first method's body to that method's name", () => {
    if (!cst) throw new Error("parse failed");
    const row = lines.findIndex(l => l.includes("Database.find"));
    expect(findEnclosingFunctionNameJava(cst, row)).toBe("getUser");
  });

  it("resolves a row inside the second method's body to that method's name, not the first", () => {
    if (!cst) throw new Error("parse failed");
    const row = lines.findIndex(l => l.includes("Database.delete"));
    expect(findEnclosingFunctionNameJava(cst, row)).toBe("deleteUser");
  });

  it("returns \"unknown\" for a row outside any method body", () => {
    if (!cst) throw new Error("parse failed");
    const row = lines.findIndex(l => l.includes("public class A"));
    expect(findEnclosingFunctionNameJava(cst, row)).toBe("unknown");
  });

  it("never throws on a malformed Java snippet", () => {
    const broken = parseJavaSource("public class {{{ broken");
    expect(broken).toBeNull();
  });
});
