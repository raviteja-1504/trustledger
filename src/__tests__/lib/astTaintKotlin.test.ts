/**
 * @jest-environment node
 *
 * Kotlin AST taint engine: recall (every sink family, Spring / Ktor / Servlet idioms) and precision (bind
 * parameters, argv form, typed parameters, sanitizers, guards, name-only path use), propagation (scope functions,
 * collection lambdas, helpers, class properties), Spring view names, and BOLA.
 */
import { warmKotlinTaintEngine, parseKotlinSourceSync, scanAstTaintKotlin } from "@/lib/astTaintKotlin";
import { SinkClass, type SuppressedSink } from "@/lib/taint/taintCore";

beforeAll(async () => { await warmKotlinTaintEngine(); }, 120000);

function scan(code: string, entryPoints = false) {
  const root = parseKotlinSourceSync(code, "Api.kt");
  if (!root) throw new Error("parse failed");
  const suppressed: SuppressedSink[] = [];
  const findings = scanAstTaintKotlin(code, "Api.kt", root, suppressed, { entryPoints });
  return { findings, suppressed, ids: findings.map(f => f.id as string) };
}
const has = (code: string, id: string) => scan(code).ids.includes(id);
const ctl = (body: string, extra = "") =>
  `@RestController\nclass Api(private val jdbc: JdbcTemplate, private val rest: RestTemplate) {\n${extra}\n${body}\n}\n`;
const get = (params: string, body: string) => ctl(`  @GetMapping("/x")\n  fun x(${params}): Any {\n${body}\n  }`);

describe("SQL injection", () => {
  it("templates and concatenation into JDBC, JPA and raw statements", () => {
    expect(has(get(`@RequestParam name: String`, `    return jdbc.queryForList("SELECT * FROM u WHERE n = '$name'")`), "sql-injection")).toBe(true);
    expect(has(get(`@RequestParam name: String`, `    val q = "SELECT * FROM u WHERE n = '" + name + "'"\n    return jdbc.queryForList(q)`), "sql-injection")).toBe(true);
    expect(has(get(`@RequestParam name: String, em: EntityManager`, `    return em.createNativeQuery("SELECT * FROM u WHERE n = '\${name.trim()}'").resultList`), "sql-injection")).toBe(true);
    expect(has(get(`@RequestParam s: String, conn: Connection`, `    return conn.createStatement().executeQuery("SELECT * FROM t ORDER BY $s")`), "sql-injection")).toBe(true);
  });

  it("bind parameters, typed ids and conversions are safe", () => {
    expect(has(get(`@RequestParam name: String`, `    return jdbc.queryForList("SELECT * FROM u WHERE n = ?", name)`), "sql-injection")).toBe(false);
    expect(has(get(`@PathVariable id: Long`, `    return jdbc.queryForList("SELECT * FROM u WHERE id = $id")`), "sql-injection")).toBe(false);
    expect(has(get(`@RequestParam id: String`, `    val n = id.toInt()\n    return jdbc.queryForList("SELECT * FROM u WHERE id = $n")`), "sql-injection")).toBe(false);
  });

  it("ambiguous names only count on a database receiver", () => {
    expect(has(get(`@RequestParam job: String, executor: Executor`, `    executor.execute(job)\n    return ""`), "sql-injection")).toBe(false);
    expect(has(get(`@RequestParam q: String`, `    return jdbc.execute("DELETE FROM t WHERE a = $q")`), "sql-injection")).toBe(true);
  });

  it("Exposed exec inside transaction {} and jOOQ plain SQL", () => {
    expect(has(get(`@RequestParam q: String`, `    return transaction { exec("SELECT * FROM t WHERE a = '$q'") }`), "sql-injection")).toBe(true);
    expect(has(get(`@RequestParam q: String`, `    return DSL.condition("a = '$q'")`), "sql-injection")).toBe(true);
  });
});

describe("command injection", () => {
  it("Runtime.exec and ProcessBuilder with a shell; argv form is argument injection at most", () => {
    expect(has(get(`@RequestParam host: String`, `    Runtime.getRuntime().exec("ping " + host)\n    return ""`), "command-injection")).toBe(true);
    expect(has(get(`@RequestParam cmd: String`, `    ProcessBuilder("sh", "-c", cmd).start()\n    return ""`), "command-injection")).toBe(true);
    expect(has(get(`@RequestParam cmd: String`, `    Runtime.getRuntime().exec(arrayOf("/bin/bash", "-c", "echo $cmd"))\n    return ""`), "command-injection")).toBe(true);
    const argv = scan(get(`@RequestParam f: String`, `    ProcessBuilder("gzip", "-k", f).start()\n    return ""`)).ids;
    expect(argv).not.toContain("command-injection");
    expect(argv).toContain("argument-injection");
    expect(has(get(`@RequestParam f: String`, `    ProcessBuilder("gzip", "--", f).start()\n    return ""`), "argument-injection")).toBe(false);
    expect(has(get(`@RequestParam f: String`, `    ProcessBuilder(listOf("sh", "-c", f)).start()\n    return ""`), "command-injection")).toBe(true);
  });
});

describe("path traversal", () => {
  it("File / Paths / Files with request input", () => {
    expect(has(get(`@RequestParam name: String`, `    return File("/data/" + name).readText()`), "path-traversal")).toBe(true);
    expect(has(get(`@RequestParam name: String`, `    return File(baseDir, name).readBytes()`), "path-traversal")).toBe(true);
    expect(has(get(`@RequestParam name: String`, `    return Files.readAllBytes(Paths.get("/data", name))`), "path-traversal")).toBe(true);
    expect(has(get(`@RequestParam name: String`, `    return Paths.get("/data").resolve(name).toFile()`), "path-traversal")).toBe(true);
  });

  it("only the file name used, or File.name / FilenameUtils.getName applied, is safe", () => {
    expect(has(get(`@RequestParam p: String`, `    return File(p).name`), "path-traversal")).toBe(false);
    expect(has(get(`@RequestParam p: String`, `    val n = File(p).name\n    return File("/data", n).readText()`), "path-traversal")).toBe(false);
    expect(has(get(`@RequestParam p: String`, `    val n = FilenameUtils.getName(p)\n    return File("/data", n).readText()`), "path-traversal")).toBe(false);
  });
});

describe("SSRF and redirects", () => {
  it("RestTemplate / URL / WebClient / Ktor client with a request-chosen host", () => {
    expect(has(get(`@RequestParam url: String`, `    return rest.getForObject(url, String::class.java)`), "ssrf")).toBe(true);
    expect(has(get(`@RequestParam url: String`, `    return URL(url).readText()`), "ssrf")).toBe(true);
    expect(has(get(`@RequestParam u: String, webClient: WebClient`, `    return webClient.get().uri(u).retrieve()`), "ssrf")).toBe(true);
    expect(has(get(`@RequestParam host: String, client: HttpClient`, `    return client.get("https://$host/api")`), "ssrf")).toBe(true);
  });

  it("a fixed host with input only in the path or query is not SSRF", () => {
    expect(has(get(`@RequestParam id: String`, `    return rest.getForObject("https://api.example.com/items/$id", String::class.java)`), "ssrf")).toBe(false);
  });

  it("sendRedirect / respondRedirect / redirect: view / ResponseEntity Location", () => {
    expect(has(get(`@RequestParam next: String, response: HttpServletResponse`, `    response.sendRedirect(next)\n    return ""`), "open-redirect")).toBe(true);
    expect(has(ctl(`  @GetMapping("/go")\n  fun go(@RequestParam next: String): String {\n    return "redirect:$next"\n  }`), "open-redirect")).toBe(true);
    expect(has(ctl(`  @GetMapping("/go")\n  fun go(@RequestParam next: String) = "redirect:" + next`), "open-redirect")).toBe(true);
    expect(has(get(`@RequestParam next: String`, `    return ResponseEntity.status(302).header("Location", next).build<Any>()`), "open-redirect")).toBe(true);
    expect(has(get(`@RequestParam tab: String, response: HttpServletResponse`, `    response.sendRedirect("/settings?tab=$tab")\n    return ""`), "open-redirect")).toBe(false);
  });
});

describe("other sinks", () => {
  it("deserialization, reflection, SpEL, template, LDAP, XPath, NoSQL", () => {
    expect(has(get(`@RequestBody body: ByteArray`, `    return ObjectInputStream(ByteArrayInputStream(body)).readObject()`), "insecure-deserialization")).toBe(true);
    expect(has(get(`@RequestBody xml: String`, `    return XStream().fromXML(xml)`), "insecure-deserialization")).toBe(true);
    expect(has(get(`@RequestParam cls: String`, `    return Class.forName(cls).getDeclaredConstructor().newInstance()`), "eval-exec")).toBe(true);
    expect(has(get(`@RequestParam e: String`, `    return SpelExpressionParser().parseExpression(e).value!!`), "eval-exec")).toBe(true);
    expect(has(get(`@RequestParam u: String, ctx: DirContext`, `    return ctx.search("dc=x", "(uid=$u)", SearchControls())`), "ldap-injection")).toBe(true);
    expect(has(get(`@RequestParam u: String, xpath: XPath`, `    return xpath.evaluate("//user[name='$u']", doc)`), "xpath-injection")).toBe(true);
    expect(has(get(`@RequestParam q: String`, `    return mongo.find(BasicQuery(q), User::class.java)`), "nosql-injection")).toBe(true);
    expect(has(get(`@RequestParam p: String`, `    return Regex(p).matches("x")`), "redos")).toBe(true);
    expect(has(get(`@RequestParam p: String`, `    return Regex(Regex.escape(p)).matches("x")`), "redos")).toBe(false);
  });

  it("headers, timing, weak digest, JWT", () => {
    expect(has(get(`@RequestParam v: String, response: HttpServletResponse`, `    response.setHeader("X-Trace", v)\n    return ""`), "header-injection")).toBe(true);
    expect(has(get(`@RequestHeader("X-Key") key: String`, `    return key == apiSecret`, ), "timing-attack")).toBe(true);
    expect(has(get(``, `    return MessageDigest.getInstance("MD5")`), "weak-crypto")).toBe(true);
    expect(has(get(`@RequestHeader("Authorization") t: String`, `    return Jwts.parser().setSigningKey(k).parseClaimsJwt(t).body`), "jwt-none-alg")).toBe(true);
  });

  it("XSS: servlet writer, HTML body, Ktor respondText(Html), kotlinx.html unsafe", () => {
    expect(has(get(`@RequestParam n: String, response: HttpServletResponse`, `    response.writer.write("<p>$n</p>")\n    return ""`), "xss")).toBe(true);
    expect(has(ctl(`  @GetMapping("/h")\n  fun h(@RequestParam n: String): String {\n    return "<h1>Hello $n</h1>"\n  }`), "xss")).toBe(true);
    expect(has(ctl(`  @GetMapping("/h")\n  fun h(@RequestParam n: String): String {\n    return "Hello $n"\n  }`), "xss")).toBe(false);
    const ktor = `fun Application.m() {\n  routing {\n    get("/h") {\n      val n = call.parameters["n"]\n      call.respondText("<b>$n</b>", ContentType.Text.Html)\n    }\n  }\n}\n`;
    expect(has(ktor, "xss")).toBe(true);
    const unsafeHtml = `fun Application.m() {\n  routing {\n    get("/h") {\n      val n = call.request.queryParameters["n"]\n      call.respondHtml { body { unsafe { +n!! } } }\n    }\n  }\n}\n`;
    expect(has(unsafeHtml, "xss")).toBe(true);
  });
});

describe("Spring view names", () => {
  it("a @Controller handler returning a request-chosen view name is template injection; a @RestController's is not", () => {
    const mvc = `@Controller\nclass Pages {\n  @GetMapping("/p")\n  fun page(@RequestParam section: String): String {\n    return "pages/" + section\n  }\n}\n`;
    expect(has(mvc, "ssti")).toBe(true);
    expect(has(mvc.replace("@Controller", "@RestController"), "ssti")).toBe(false);
    expect(has(`@Controller\nclass Pages {\n  @GetMapping("/p")\n  fun page(@RequestParam s: String): String {\n    return "pages/home"\n  }\n}\n`, "ssti")).toBe(false);
  });

  it("class annotations the grammar detaches from the class are still read", () => {
    // A later top-level declaration makes tree-sitter-kotlin parse `@Controller @RequestMapping(...)` as a
    // statement BEFORE the class rather than as its modifiers.
    const mvc = `@Controller\n@RequestMapping("/app")\nclass Pages {\n  @GetMapping("/p")\n  fun page(@RequestParam section: String): String {\n    return "pages/" + section\n  }\n}\ninterface Marker\n`;
    expect(has(mvc, "ssti")).toBe(true);
    // with a primary constructor the class survives, but its annotations still become the statement before it
    const withCtor = mvc.replace("class Pages {", "class Pages(private val svc: Svc) {");
    expect(has(withCtor, "ssti")).toBe(true);
  });
});

describe("sources", () => {
  it("Ktor parameters / receive and Servlet getters (call and property form)", () => {
    const ktor = `fun Application.m(db: Connection) {\n  routing {\n    post("/x") {\n      val body = call.receiveText()\n      db.createStatement().executeQuery("SELECT * FROM t WHERE a = '$body'")\n    }\n  }\n}\n`;
    expect(has(ktor, "sql-injection")).toBe(true);
    expect(has(`class S {\n  fun h(request: HttpServletRequest, jdbc: JdbcTemplate) {\n    val q = request.getParameter("q")\n    jdbc.queryForList("SELECT $q")\n  }\n}\n`, "sql-injection")).toBe(true);
    expect(has(`class S {\n  fun h(request: HttpServletRequest, jdbc: JdbcTemplate) {\n    jdbc.queryForList("SELECT " + request.queryString)\n  }\n}\n`, "sql-injection")).toBe(true);
  });

  it("an un-annotated parameter is a source only as a (lower-confidence) entry point", () => {
    const lib = `class Svc(private val jdbc: JdbcTemplate) {\n  fun search(term: String) = jdbc.queryForList("SELECT * FROM t WHERE a = '$term'")\n}\n`;
    expect(scan(lib).ids).not.toContain("sql-injection");
    const relaxed = scan(lib, true).findings.filter(f => f.id === "sql-injection");
    expect(relaxed).toHaveLength(1);
    expect(relaxed[0].entryPointSeeded).toBe(true);
  });
});

describe("propagation", () => {
  it("scope functions, collection lambdas, StringBuilder, buildString, elvis", () => {
    expect(has(get(`@RequestParam n: String?`, `    return n?.let { jdbc.queryForList("SELECT '$it'") } ?: emptyList<Any>()`), "sql-injection")).toBe(true);
    expect(has(get(`@RequestParam ids: List<String>`, `    ids.forEach { jdbc.update("DELETE FROM t WHERE id = '$it'") }\n    return ""`), "sql-injection")).toBe(true);
    expect(has(get(`@RequestParam n: String`, `    val sb = StringBuilder("SELECT * FROM t WHERE a = '")\n    sb.append(n)\n    return jdbc.queryForList(sb.toString())`), "sql-injection")).toBe(true);
    expect(has(get(`@RequestParam n: String`, `    val q = buildString { append("SELECT * FROM t WHERE a = '"); append(n) }\n    return jdbc.queryForList(q)`), "sql-injection")).toBe(true);
    expect(has(get(`@RequestParam n: String?`, `    val v = n ?: "x"\n    return jdbc.queryForList("SELECT '$v'")`), "sql-injection")).toBe(true);
    expect(has(get(`@RequestParam n: String`, `    val q = n.trim().lowercase().let { "SELECT '$it'" }\n    return jdbc.queryForList(q)`), "sql-injection")).toBe(true);
  });

  it("same-file helpers: return summaries and seeded re-walks", () => {
    const helperReturn = ctl(`  @GetMapping("/x")\n  fun x(@RequestParam n: String) = jdbc.queryForList(build(n))`, `  private fun build(s: String) = "SELECT * FROM t WHERE a = '$s'"`);
    expect(has(helperReturn, "sql-injection")).toBe(true);
    const helperSink = ctl(`  @GetMapping("/x")\n  fun x(@RequestParam n: String): Any { run(n); return "" }`, `  private fun run(s: String) { jdbc.update("DELETE FROM t WHERE a = '$s'") }`);
    const r = scan(helperSink);
    expect(r.findings.find(f => f.id === "sql-injection")?.line).toBe(3);   // the sink inside the helper
    const safeHelper = ctl(`  @GetMapping("/x")\n  fun x(@RequestParam n: String) = jdbc.queryForList(build(n))`, `  private fun build(s: String) = "SELECT * FROM t WHERE a = '\${s.toInt()}'"`);
    expect(has(safeHelper, "sql-injection")).toBe(false);
  });

  it("a class property written by one handler and read by another", () => {
    const code = `@RestController\nclass Api(private val jdbc: JdbcTemplate) {\n  private var last: String = ""\n  @PostMapping("/a") fun a(@RequestBody b: String) { last = b }\n  @GetMapping("/b") fun b() = jdbc.queryForList("SELECT '$last'")\n}\n`;
    expect(has(code, "sql-injection")).toBe(true);
  });

  it("a data class from @RequestBody carries its fields", () => {
    expect(has(get(`@RequestBody req: SearchRequest`, `    return jdbc.queryForList("SELECT * FROM t WHERE a = '\${req.term}'")`), "sql-injection")).toBe(true);
  });

  it("reported source names the tainted operand, with a trace", () => {
    const f = scan(get(`@RequestParam name: String`, `    val q = "SELECT * FROM u WHERE n = '" + name + "'"\n    return jdbc.queryForList(q)`)).findings.find(x => x.id === "sql-injection")!;
    expect(f.sourceExpr).toBe("q");
    expect(f.trace!.length).toBeGreaterThan(1);
  });
});

describe("branches and guards", () => {
  it("allow-list, literal equality, numeric type check, when on literals", () => {
    expect(has(get(`@RequestParam s: String`, `    if (s in setOf("name", "date")) return jdbc.queryForList("SELECT * FROM t ORDER BY $s")\n    return ""`), "sql-injection")).toBe(false);
    expect(has(get(`@RequestParam s: String`, `    if (s !in ALLOWED) throw IllegalArgumentException()\n    return jdbc.queryForList("SELECT * FROM t ORDER BY $s")`, ).replace("class Api(", "val ALLOWED = setOf(\"a\", \"b\")\nclass Api("), "sql-injection")).toBe(false);
    expect(has(get(`@RequestParam s: String`, `    val col = when (s) { "a", "b" -> s; else -> "id" }\n    return jdbc.queryForList("SELECT * FROM t ORDER BY $col")`), "sql-injection")).toBe(false);
    // a non-guard check must still report
    expect(has(get(`@RequestParam s: String`, `    if (s.isNotBlank()) return jdbc.queryForList("SELECT * FROM t ORDER BY $s")\n    return ""`), "sql-injection")).toBe(true);
  });

  it("an if used as a value takes the guard its condition proves", () => {
    expect(has(get(`@RequestParam s: String`, `    val o = if (s in setOf("name", "date")) s else "id"\n    return jdbc.queryForList("SELECT * FROM t ORDER BY $o")`), "sql-injection")).toBe(false);
    expect(has(get(`@RequestParam s: String`, `    val o = if (s !in setOf("name", "date")) "id" else s\n    return jdbc.queryForList("SELECT * FROM t ORDER BY $o")`), "sql-injection")).toBe(false);
  });

  it("require(...) before the sink is a guard clause too", () => {
    expect(has(get(`@RequestParam s: String`, `    require(s in setOf("a", "b"))\n    return jdbc.queryForList("SELECT * FROM t ORDER BY $s")`), "sql-injection")).toBe(false);
  });

  it("branch merge: tainted in one arm, constant in the other, still reported", () => {
    expect(has(get(`@RequestParam s: String, @RequestParam f: Boolean`, `    val o = if (f) s else "id"\n    return jdbc.queryForList("SELECT * FROM t ORDER BY $o")`), "sql-injection")).toBe(true);
  });

  it("a sanitized flow records the regex-layer veto", () => {
    const r = scan(get(`@RequestParam n: String, response: HttpServletResponse`, `    response.writer.write(HtmlUtils.htmlEscape(n))\n    return ""`));
    expect(r.ids).not.toContain("xss");
    expect(r.suppressed.some(s => s.id === "xss")).toBe(true);
  });
});

describe("cross-file facts at the call site", () => {
  it("two facts for the same finding id at one call line are reported once", () => {
    const code = `@RestController\nclass C(private val users: UserService) {\n  @GetMapping("/u")\n  fun u(@RequestParam a: String) = users.both(a, a)\n}\n`;
    const fact = (index: number, line: number) => ({
      index, isRest: false, id: "sql-injection", sinkClass: SinkClass.SQL, sinkExpr: "jdbc.update", file: "Svc.kt", line, via: ["UserService.both"],
    });
    const root = parseKotlinSourceSync(code, "C.kt")!;
    const found = scanAstTaintKotlin(code, "C.kt", root, [], { crossFileFacts: new Map([["UserService.both", [fact(0, 3), fact(1, 4)]]]) });
    expect(found.filter(f => f.id === "sql-injection")).toHaveLength(1);
    expect(found[0].calleeSink?.file).toBe("Svc.kt");
  });
});

describe("BOLA", () => {
  const bola = (annotation: string, body: string, params = `@PathVariable id: Long`) =>
    `@RestController\nclass Orders(private val repo: OrderRepository) {\n  ${annotation}\n  fun handle(${params}): Any {\n${body}\n  }\n}\n`;

  it("an unscoped write by a request id is reported", () => {
    const f = scan(bola(`@DeleteMapping("/o/{id}")`, `    repo.deleteById(id)\n    return ""`)).findings.find(x => x.id === "bola-missing-ownership-check");
    expect(f?.severityOverride).toBe("high");
  });

  it("an owner check on the loaded record, before or after, suppresses it", () => {
    expect(has(bola(`@PutMapping("/o/{id}")`, `    val o = repo.findById(id).orElseThrow()\n    if (o.ownerId != me.id) throw AccessDeniedException("no")\n    return repo.save(o)`, `@PathVariable id: Long, @AuthenticationPrincipal me: User`), "bola-missing-ownership-check")).toBe(false);
    expect(has(bola(`@PreAuthorize("@perm.isOwner(#id, authentication)")\n  @DeleteMapping("/o/{id}")`, `    repo.deleteById(id)\n    return ""`), "bola-missing-ownership-check")).toBe(false);
    const me = `@PathVariable id: Long, @AuthenticationPrincipal me: User`;
    // the arm that does NOT establish ownership throws (else-arm form)
    expect(has(bola(`@PutMapping("/o/{id}")`, `    val o = repo.findById(id).orElseThrow()\n    if (o.ownerId == me.id) { o.touch() } else { throw AccessDeniedException("no") }\n    return repo.save(o)`, me), "bola-missing-ownership-check")).toBe(false);
    // require(...) as the guard clause
    expect(has(bola(`@PutMapping("/o/{id}")`, `    val o = repo.findById(id).orElseThrow()\n    require(o.ownerId == me.id)\n    return repo.save(o)`, me), "bola-missing-ownership-check")).toBe(false);
    // ...but a check on something else does not protect it
    expect(has(bola(`@PutMapping("/o/{id}")`, `    val o = repo.findById(id).orElseThrow()\n    require(o.status == "open")\n    return repo.save(o)`, me), "bola-missing-ownership-check")).toBe(true);
  });

  it("a role check alone downgrades to medium; a read is medium", () => {
    const role = scan(bola(`@PreAuthorize("hasRole('USER')")\n  @DeleteMapping("/o/{id}")`, `    repo.deleteById(id)\n    return ""`)).findings.find(x => x.id === "bola-missing-ownership-check");
    expect(role?.severityOverride).toBe("medium");
    const read = scan(bola(`@GetMapping("/o/{id}")`, `    return repo.findById(id)`)).findings.find(x => x.id === "bola-missing-ownership-check");
    expect(read?.severityOverride).toBe("medium");
  });
});
