/**
 * Kotlin taint detection through the full scanner (analyzeFile): the same vulnerabilities the Java engine finds,
 * written the Kotlin way -- and the safe Kotlin forms stay clean.
 */
import { analyzeFile } from "@/lib/scanner";
import { firstArg, kotlinTaintedNames, referencedNames } from "@/lib/kotlinTaint";
import { SCANNABLE_EXTS } from "@/lib/scannableFiles";

const ids = (code: string, file = "Api.kt") => [...new Set((analyzeFile(file, code).indicators ?? []).map((i: { id: string }) => i.id))];
const has = (code: string, id: string, file?: string) => ids(code, file).includes(id);
const ctl = (body: string) => `@RestController\nclass C(val jdbc: JdbcTemplate, val rt: RestTemplate) {\n${body}\n}\n`;

describe("parity with Java on the common web vulnerabilities", () => {
  it("SQL injection -- concatenation and string templates", () => {
    expect(has(ctl(`  @GetMapping("/u") fun u(@RequestParam id: String) = jdbc.queryForList("SELECT * FROM users WHERE id = '" + id + "'")`), "sql-injection")).toBe(true);
    expect(has(ctl(`  @GetMapping("/u") fun u(@RequestParam id: String) = jdbc.queryForList("SELECT * FROM users WHERE id = '$id'")`), "sql-injection")).toBe(true);
    expect(has(ctl(`  @GetMapping("/u") fun u(@RequestParam name: String) = jdbc.queryForList("SELECT * FROM users WHERE name = '\${name.trim()}'")`), "sql-injection")).toBe(true);
  });

  it("command injection", () => {
    expect(has(ctl(`  @GetMapping("/p") fun p(@RequestParam host: String): String { Runtime.getRuntime().exec("ping " + host); return "ok" }`), "command-injection")).toBe(true);
    expect(has(ctl(`  @PostMapping("/p") fun p(@RequestBody cmd: String) { ProcessBuilder("sh -c $cmd").start() }`), "command-injection")).toBe(true);
    // a shell runs a later argument as a whole command line
    expect(has(ctl(`  @PostMapping("/p") fun p(@RequestBody cmd: String) { ProcessBuilder("sh", "-c", cmd).start() }`), "command-injection")).toBe(true);
    expect(has(ctl(`  @PostMapping("/p") fun p(@RequestBody cmd: String) { ProcessBuilder("/bin/bash", "-c", "echo " + cmd).start() }`), "command-injection")).toBe(true);
    // no shell: a fixed program with the value as one argument is not a command injection
    expect(has(ctl(`  @PostMapping("/p") fun p(@RequestBody file: String) { ProcessBuilder("gzip", "-k", file).start() }`), "command-injection")).toBe(false);
  });

  it("path traversal -- any argument", () => {
    expect(has(ctl(`  @GetMapping("/f") fun f(@RequestParam name: String) = File("/data/" + name).readText()`), "path-traversal")).toBe(true);
    expect(has(ctl(`  @GetMapping("/f") fun f(@RequestParam name: String) = File(baseDir, name).readText()`), "path-traversal")).toBe(true);
    expect(has(ctl(`  @GetMapping("/f") fun f(@PathVariable name: String) = Files.readString(Paths.get("/data", name))`), "path-traversal")).toBe(true);
  });

  it("SSRF", () => {
    expect(has(ctl(`  @GetMapping("/x") fun x(@RequestParam url: String) = rt.getForObject(url, String::class.java)`), "ssrf")).toBe(true);
    expect(has(ctl(`  @GetMapping("/x") fun x(@RequestParam host: String) = URL("https://$host/api").readText()`), "ssrf")).toBe(true);
  });

  it("open redirect -- sendRedirect and Spring's \"redirect:\" view", () => {
    expect(has(`@Controller\nclass C {\n  @GetMapping("/r") fun r(@RequestParam next: String, resp: HttpServletResponse) { resp.sendRedirect(next) }\n}`, "open-redirect")).toBe(true);
    expect(has(`@Controller\nclass C {\n  @GetMapping("/r") fun r(@RequestParam next: String) = "redirect:$next"\n}`, "open-redirect")).toBe(true);
    expect(has(`@Controller\nclass C {\n  @GetMapping("/r") fun r(@RequestParam next: String): String { return "redirect:" + next }\n}`, "open-redirect")).toBe(true);
  });
});

describe("sources and propagation", () => {
  it("Ktor and Servlet input, through val chains", () => {
    expect(has(`fun Route.users(db: Database) {\n  get("/u") {\n    val id = call.parameters["id"]\n    val q = "SELECT * FROM users WHERE id = $id"\n    db.exec(q)\n  }\n}`, "sql-injection")).toBe(true);
    expect(has(`class S : HttpServlet() {\n  override fun doGet(request: HttpServletRequest, response: HttpServletResponse) {\n    val target = request.getParameter("to")\n    response.sendRedirect(target)\n  }\n}`, "open-redirect")).toBe(true);
    expect(has(`fun Route.f() {\n  post("/f") {\n    val name = call.receiveText()\n    File("/uploads/$name").writeText("x")\n  }\n}`, "path-traversal")).toBe(true);
  });

  it("reads names from code and from string templates, not from plain string text", () => {
    expect(referencedNames(`"SELECT $id FROM t" + other`)).toEqual(expect.arrayContaining(["id", "other"]));
    expect(referencedNames(`"name is id"`)).toEqual([]);
    expect(referencedNames(`"\${user.name}"`)).toEqual(["user", "name"]);
    expect(firstArg(`"SELECT ?, (a, b)", id, other`)).toBe(`"SELECT ?, (a, b)"`);
  });
});

describe("safe Kotlin stays clean", () => {
  it("bound SQL parameters", () => {
    expect(has(ctl(`  @GetMapping("/u") fun u(@RequestParam id: String) = jdbc.queryForList("SELECT * FROM users WHERE id = ?", id)`), "sql-injection")).toBe(false);
    expect(has(ctl(`  @GetMapping("/u") fun u(@RequestParam id: String) = jdbc.queryForList("SELECT * FROM users WHERE id = :id", mapOf("id" to id))`), "sql-injection")).toBe(false);
  });

  it("numeric / UUID parameters and converted values", () => {
    expect(kotlinTaintedNames([`fun u(@PathVariable id: Long, @RequestParam page: Int?, @RequestParam ref: UUID) {}`]).size).toBe(0);
    expect(has(ctl(`  @GetMapping("/u") fun u(@PathVariable id: Long) = jdbc.queryForList("SELECT * FROM users WHERE id = $id")`), "sql-injection")).toBe(false);
    expect(has(ctl(`  @GetMapping("/u") fun u(@RequestParam raw: String): Any {\n    val n = raw.toInt()\n    return jdbc.queryForList("SELECT * FROM t LIMIT $n")\n  }`), "sql-injection")).toBe(false);
  });

  it("constants, unrelated maps and comments", () => {
    expect(has(ctl(`  @GetMapping("/u") fun u() = jdbc.queryForList("SELECT * FROM users")`), "sql-injection")).toBe(false);
    expect(ids(ctl(`  @GetMapping("/m") fun m(@RequestParam k: String) { cache.put(k, "v"); cache.remove(k) }`))).not.toContain("ssrf");
    expect(has(ctl(`  @GetMapping("/u") fun u(@RequestParam id: String): Any {\n    // jdbc.queryForList("SELECT * FROM t WHERE id = $id")\n    return emptyList<Any>()\n  }`), "sql-injection")).toBe(false);
  });

  it("only Kotlin files get this pass", () => {
    const kotlinSql = ctl(`  @GetMapping("/u") fun u(@RequestParam id: String) = jdbc.queryForList("SELECT * FROM users WHERE id = '$id'")`);
    expect(has(kotlinSql, "sql-injection", "Api.kt")).toBe(true);
    expect(has(kotlinSql, "sql-injection", "Api.ts")).toBe(false);
  });
});

describe(".kts", () => {
  it("Kotlin scripts are scanned as Kotlin", () => {
    expect(SCANNABLE_EXTS.has("kts")).toBe(true);
    expect(analyzeFile("deploy.main.kts", `val x = 1`).language).toBe("kotlin");
  });
});
