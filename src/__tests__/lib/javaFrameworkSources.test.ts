/**
 * @jest-environment node
 *
 * Java frameworks: request sources and sinks of Spring MVC / Boot, the Servlet API, JAX-RS (Jakarta EE, Java EE, Dropwizard), Quarkus, Micronaut,
 * Vert.x, Struts, Wicket, with Hibernate / JPA / MyBatis / JdbcTemplate SQL and the HTTP clients, plus controller -> service -> repository flows through
 * Spring dependency injection. Safe cases (bound parameters, converted parameter types, fixed URLs, HTML encoders) must stay quiet.
 * (Known gap: Wicket page logic written inside a constructor; the engine analyses method bodies.)
 */
import { runScan } from "@/lib/scanner";
import { ensureTaintEngines } from "@/lib/engineWarmup";

jest.setTimeout(300_000);
beforeAll(async () => { await ensureTaintEngines(); }, 180_000);

type F = { path: string; content: string };
// [name, files, expectation]: "VULN:<rule>" must be found in any file; "SAFE" must have no injection/ssrf/path/redirect/xss/deserialization finding
const C: Array<[string, F[], string]> = [];
let n = 0;
const J = (name: string, body: string, exp: string, imports = "") =>
  C.push([name, [{ path: `src/main/java/app/C${n++}.java`, content: `package app;\n${imports}\n${body}` }], exp]);
const CTRL = `import org.springframework.web.bind.annotation.*;\nimport org.springframework.beans.factory.annotation.Autowired;\nimport javax.servlet.http.*;\nimport java.io.*;\nimport java.sql.*;\nimport java.util.*;\n`;

// ---------------- Spring MVC / Boot sources
J("spring @RequestParam->Runtime.exec", `@RestController public class A { @GetMapping("/a") public String a(@RequestParam String d) throws Exception { Runtime.getRuntime().exec("ls " + d); return "ok"; } }`, "VULN:command-injection", CTRL);
J("spring @PathVariable->Statement", `@RestController public class A { @GetMapping("/a/{id}") public String a(@PathVariable String id, Connection c) throws Exception { Statement s = c.createStatement(); s.executeQuery("SELECT * FROM t WHERE id = '" + id + "'"); return "ok"; } }`, "VULN:sql-injection", CTRL);
J("spring @RequestBody dto->jdbcTemplate", `@RestController public class A { @Autowired JdbcTemplate jdbc; public static class Dto { public String name; public String getName(){return name;} } @PostMapping("/a") public Object a(@RequestBody Dto d) { return jdbc.queryForList("SELECT * FROM t WHERE n = '" + d.getName() + "'"); } }`, "VULN:sql-injection", CTRL + "import org.springframework.jdbc.core.JdbcTemplate;\n");
J("spring @RequestHeader->exec", `@RestController public class A { @GetMapping("/a") public String a(@RequestHeader("X-Cmd") String c) throws Exception { Runtime.getRuntime().exec(c); return "ok"; } }`, "VULN:command-injection", CTRL);
J("spring @CookieValue->sql", `@RestController public class A { @GetMapping("/a") public String a(@CookieValue("u") String u, Statement s) throws Exception { s.execute("DELETE FROM t WHERE u = '" + u + "'"); return "ok"; } }`, "VULN:sql-injection", CTRL);
J("spring @ModelAttribute->exec", `@RestController public class A { public static class F { String cmd; public String getCmd(){return cmd;} } @PostMapping("/a") public String a(@ModelAttribute F f) throws Exception { Runtime.getRuntime().exec(f.getCmd()); return "ok"; } }`, "VULN:command-injection", CTRL + "import org.springframework.web.bind.annotation.ModelAttribute;\n");
J("servlet getParameter->ProcessBuilder", `public class A extends HttpServlet { protected void doGet(HttpServletRequest req, HttpServletResponse res) throws Exception { new ProcessBuilder("sh", "-c", "ls " + req.getParameter("d")).start(); } }`, "VULN:command-injection", CTRL);
J("servlet getHeader->exec", `public class A extends HttpServlet { protected void doGet(HttpServletRequest req, HttpServletResponse res) throws Exception { Runtime.getRuntime().exec(req.getHeader("X-C")); } }`, "VULN:command-injection", CTRL);
J("servlet getInputStream->ObjectInputStream", `public class A extends HttpServlet { protected void doPost(HttpServletRequest req, HttpServletResponse res) throws Exception { Object o = new ObjectInputStream(req.getInputStream()).readObject(); } }`, "VULN:insecure-deserialization", CTRL);
J("ScriptEngine.eval", `public class A extends HttpServlet { protected void doGet(HttpServletRequest req, HttpServletResponse res) throws Exception { new javax.script.ScriptEngineManager().getEngineByName("js").eval(req.getParameter("e")); } }`, "VULN:eval-exec", CTRL);
// ---------------- SQL
J("jdbcTemplate.query concat", `@RestController public class A { @Autowired JdbcTemplate jdbc; @GetMapping("/a") public Object a(@RequestParam String n) { return jdbc.query("SELECT * FROM t WHERE n = '" + n + "'", (rs, i) -> rs.getString(1)); } }`, "VULN:sql-injection", CTRL + "import org.springframework.jdbc.core.JdbcTemplate;\n");
J("jdbcTemplate.update concat", `@RestController public class A { @Autowired JdbcTemplate jdbc; @PostMapping("/a") public void a(@RequestParam String n) { jdbc.update("DELETE FROM t WHERE n = '" + n + "'"); } }`, "VULN:sql-injection", CTRL + "import org.springframework.jdbc.core.JdbcTemplate;\n");
J("jdbcTemplate.queryForObject concat", `@RestController public class A { @Autowired JdbcTemplate jdbc; @GetMapping("/a") public Object a(@RequestParam String n) { return jdbc.queryForObject("SELECT count(*) FROM t WHERE n = '" + n + "'", Integer.class); } }`, "VULN:sql-injection", CTRL + "import org.springframework.jdbc.core.JdbcTemplate;\n");
J("em.createNativeQuery concat", `@RestController public class A { @javax.persistence.PersistenceContext javax.persistence.EntityManager em; @GetMapping("/a") public Object a(@RequestParam String n) { return em.createNativeQuery("SELECT * FROM t WHERE n = '" + n + "'").getResultList(); } }`, "VULN:sql-injection", CTRL);
J("em.createQuery JPQL concat", `@RestController public class A { @javax.persistence.PersistenceContext javax.persistence.EntityManager em; @GetMapping("/a") public Object a(@RequestParam String n) { return em.createQuery("SELECT t FROM T t WHERE t.n = '" + n + "'").getResultList(); } }`, "VULN:sql-injection", CTRL);
J("hibernate session.createSQLQuery", `@RestController public class A { @Autowired org.hibernate.Session session; @GetMapping("/a") public Object a(@RequestParam String n) { return session.createSQLQuery("SELECT * FROM t WHERE n = '" + n + "'").list(); } }`, "VULN:sql-injection", CTRL);
J("hibernate createQuery HQL concat", `@RestController public class A { @Autowired org.hibernate.Session session; @GetMapping("/a") public Object a(@RequestParam String n) { return session.createQuery("from T where n = '" + n + "'").list(); } }`, "VULN:sql-injection", CTRL);
J("mybatis ${} annotation", `public interface M { @org.apache.ibatis.annotations.Select("SELECT * FROM t WHERE n = '\${name}'") java.util.List<String> find(@org.apache.ibatis.annotations.Param("name") String name); }`, "VULN:sql-injection");
J("namedParameterJdbcTemplate concat", `@RestController public class A { @Autowired org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate jdbc; @GetMapping("/a") public Object a(@RequestParam String n) { return jdbc.queryForList("SELECT * FROM t WHERE n = '" + n + "'", new java.util.HashMap<String,Object>()); } }`, "VULN:sql-injection", CTRL);
// ---------------- SSRF
J("RestTemplate.getForObject", `@RestController public class A { @Autowired org.springframework.web.client.RestTemplate rt; @GetMapping("/a") public String a(@RequestParam String u) { return rt.getForObject(u, String.class); } }`, "VULN:ssrf", CTRL);
J("RestTemplate.exchange", `@RestController public class A { @Autowired org.springframework.web.client.RestTemplate rt; @GetMapping("/a") public Object a(@RequestParam String u) { return rt.exchange(u, org.springframework.http.HttpMethod.GET, null, String.class); } }`, "VULN:ssrf", CTRL);
J("WebClient.uri", `@RestController public class A { @Autowired org.springframework.web.reactive.function.client.WebClient wc; @GetMapping("/a") public Object a(@RequestParam String u) { return wc.get().uri(u).retrieve().bodyToMono(String.class).block(); } }`, "VULN:ssrf", CTRL);
J("java.net.http.HttpClient", `@RestController public class A { @GetMapping("/a") public Object a(@RequestParam String u) throws Exception { return HttpClient.newHttpClient().send(HttpRequest.newBuilder(URI.create(u)).build(), HttpResponse.BodyHandlers.ofString()).body(); } }`, "VULN:ssrf", CTRL + "import java.net.URI;\nimport java.net.http.*;\n");
J("new URL().openStream", `@RestController public class A { @GetMapping("/a") public Object a(@RequestParam String u) throws Exception { return new java.net.URL(u).openStream().read(); } }`, "VULN:ssrf", CTRL);
J("apache HttpGet", `@RestController public class A { @GetMapping("/a") public Object a(@RequestParam String u) throws Exception { return org.apache.http.impl.client.HttpClients.createDefault().execute(new org.apache.http.client.methods.HttpGet(u)); } }`, "VULN:ssrf", CTRL);
J("okhttp Request.Builder", `@RestController public class A { @GetMapping("/a") public Object a(@RequestParam String u) throws Exception { return new okhttp3.OkHttpClient().newCall(new okhttp3.Request.Builder().url(u).build()).execute(); } }`, "VULN:ssrf", CTRL);
// ---------------- XSS / redirect / path
J("response.getWriter().write", `public class A extends HttpServlet { protected void doGet(HttpServletRequest req, HttpServletResponse res) throws Exception { res.getWriter().write("<h1>" + req.getParameter("n") + "</h1>"); } }`, "VULN:xss", CTRL);
J("out.println", `public class A extends HttpServlet { protected void doGet(HttpServletRequest req, HttpServletResponse res) throws Exception { PrintWriter out = res.getWriter(); out.println("<h1>" + req.getParameter("n") + "</h1>"); } }`, "VULN:xss", CTRL);
J("spring @ResponseBody html string", `@RestController public class A { @GetMapping(value="/a", produces="text/html") public String a(@RequestParam String n) { return "<h1>" + n + "</h1>"; } }`, "VULN:xss", CTRL);
J("response.sendRedirect", `public class A extends HttpServlet { protected void doGet(HttpServletRequest req, HttpServletResponse res) throws Exception { res.sendRedirect(req.getParameter("next")); } }`, "VULN:open-redirect", CTRL);
J("spring redirect: prefix", `@Controller public class A { @GetMapping("/a") public String a(@RequestParam String n) { return "redirect:" + n; } }`, "VULN:open-redirect", CTRL);
J("new File(param)", `@RestController public class A { @GetMapping("/a") public Object a(@RequestParam String f) throws Exception { return new FileInputStream(new File("/data/" + f)).read(); } }`, "VULN:path-traversal", CTRL);
J("Files.readAllBytes(Paths.get)", `@RestController public class A { @GetMapping("/a") public Object a(@RequestParam String f) throws Exception { return Files.readAllBytes(Paths.get("/data/" + f)); } }`, "VULN:path-traversal", CTRL + "import java.nio.file.*;\n");
// ---------------- other frameworks' sources
const JX = `import javax.ws.rs.*;\nimport java.sql.*;\n`;
J("jax-rs @QueryParam->sql", `@Path("/a") public class A { @GET public String a(@QueryParam("n") String n, Statement s) throws Exception { s.executeQuery("SELECT * FROM t WHERE n = '" + n + "'"); return "ok"; } }`, "VULN:sql-injection", JX);
J("jax-rs @PathParam->exec", `@Path("/a/{c}") public class A { @GET public String a(@PathParam("c") String c) throws Exception { Runtime.getRuntime().exec(c); return "ok"; } }`, "VULN:command-injection", JX);
J("jax-rs @FormParam->exec", `@Path("/a") public class A { @POST public String a(@FormParam("c") String c) throws Exception { Runtime.getRuntime().exec(c); return "ok"; } }`, "VULN:command-injection", JX);
J("jax-rs @HeaderParam->ssrf", `@Path("/a") public class A { @GET public String a(@HeaderParam("X-U") String u) throws Exception { return new java.net.URL(u).openStream().toString(); } }`, "VULN:ssrf", JX);
J("jax-rs @BeanParam", `@Path("/a") public class A { public static class P { @QueryParam("c") public String c; } @GET public String a(@BeanParam P p) throws Exception { Runtime.getRuntime().exec(p.c); return "ok"; } }`, "VULN:command-injection", JX);
J("quarkus @RestQuery", `@jakarta.ws.rs.Path("/a") public class A { @jakarta.ws.rs.GET public String a(@org.jboss.resteasy.reactive.RestQuery String c) throws Exception { Runtime.getRuntime().exec(c); return "ok"; } }`, "VULN:command-injection");
J("micronaut @QueryValue", `@io.micronaut.http.annotation.Controller("/a") public class A { @io.micronaut.http.annotation.Get public String a(@io.micronaut.http.annotation.QueryValue String c) throws Exception { Runtime.getRuntime().exec(c); return "ok"; } }`, "VULN:command-injection");
J("micronaut @Body", `@io.micronaut.http.annotation.Controller("/a") public class A { @io.micronaut.http.annotation.Post public String a(@io.micronaut.http.annotation.Body String c) throws Exception { Runtime.getRuntime().exec(c); return "ok"; } }`, "VULN:command-injection");
J("micronaut @PathVariable", `@io.micronaut.http.annotation.Controller("/a") public class A { @io.micronaut.http.annotation.Get("/{c}") public String a(@io.micronaut.http.annotation.PathVariable String c) throws Exception { Runtime.getRuntime().exec(c); return "ok"; } }`, "VULN:command-injection");
J("vert.x request().getParam", `public class A { public void h(io.vertx.ext.web.RoutingContext ctx) throws Exception { Runtime.getRuntime().exec(ctx.request().getParam("c")); } }`, "VULN:command-injection");
J("vert.x queryParam", `public class A { public void h(io.vertx.ext.web.RoutingContext ctx) throws Exception { Runtime.getRuntime().exec(ctx.queryParam("c").get(0)); } }`, "VULN:command-injection");
J("vert.x pathParam->sql", `public class A { public void h(io.vertx.ext.web.RoutingContext ctx, java.sql.Statement s) throws Exception { s.execute("DELETE FROM t WHERE id = '" + ctx.pathParam("id") + "'"); } }`, "VULN:sql-injection");
J("vert.x body->exec", `public class A { public void h(io.vertx.ext.web.RoutingContext ctx) throws Exception { Runtime.getRuntime().exec(ctx.body().asString()); } }`, "VULN:command-injection");
J("dropwizard (jax-rs) resource", `@Path("/a") @javax.ws.rs.Produces("application/json") public class A { @GET public String a(@QueryParam("c") String c) throws Exception { new ProcessBuilder(c).start(); return "ok"; } }`, "VULN:command-injection", JX);
J("struts2 action property", `public class A extends com.opensymphony.xwork2.ActionSupport { private String cmd; public String getCmd(){return cmd;} public void setCmd(String c){this.cmd=c;} public String execute() throws Exception { Runtime.getRuntime().exec(cmd); return SUCCESS; } }`, "VULN:command-injection");
J("struts1 request.getParameter", `public class A extends org.apache.struts.action.Action { public org.apache.struts.action.ActionForward execute(org.apache.struts.action.ActionMapping m, org.apache.struts.action.ActionForm f, HttpServletRequest req, HttpServletResponse res) throws Exception { Runtime.getRuntime().exec(req.getParameter("c")); return null; } }`, "VULN:command-injection", CTRL);
J("wicket getRequestParameters", `public class A extends org.apache.wicket.markup.html.WebPage { protected void onInitialize() { try { String c = getRequest().getRequestParameters().getParameterValue("c").toString(); Runtime.getRuntime().exec(c); } catch (Exception e) {} } }`, "VULN:command-injection");
J("wicket PageParameters", `public class A extends org.apache.wicket.markup.html.WebPage { public void handle(PageParameters p) throws Exception { Runtime.getRuntime().exec(p.get("c").toString()); } }`, "VULN:command-injection", "import org.apache.wicket.request.mapper.parameter.PageParameters;");
J("wicket setEscapeModelStrings(false)", `public class A extends org.apache.wicket.markup.html.WebPage { public void render(PageParameters p) { add(new org.apache.wicket.markup.html.basic.Label("l", p.get("n").toString()).setEscapeModelStrings(false)); } }`, "VULN:xss", "import org.apache.wicket.request.mapper.parameter.PageParameters;");
// ---------------- safe controls
J("PreparedStatement (safe)", `@RestController public class A { @GetMapping("/a") public String a(@RequestParam String n, Connection c) throws Exception { PreparedStatement p = c.prepareStatement("SELECT * FROM t WHERE n = ?"); p.setString(1, n); p.executeQuery(); return "ok"; } }`, "SAFE", CTRL);
J("jdbcTemplate bound ? (safe)", `@RestController public class A { @Autowired JdbcTemplate jdbc; @GetMapping("/a") public Object a(@RequestParam String n) { return jdbc.queryForList("SELECT * FROM t WHERE n = ?", n); } }`, "SAFE", CTRL + "import org.springframework.jdbc.core.JdbcTemplate;\n");
J("createNativeQuery setParameter (safe)", `@RestController public class A { @javax.persistence.PersistenceContext javax.persistence.EntityManager em; @GetMapping("/a") public Object a(@RequestParam String n) { return em.createNativeQuery("SELECT * FROM t WHERE n = :n").setParameter("n", n).getResultList(); } }`, "SAFE", CTRL);
J("createQuery named param (safe)", `@RestController public class A { @javax.persistence.PersistenceContext javax.persistence.EntityManager em; @GetMapping("/a") public Object a(@RequestParam String n) { return em.createQuery("SELECT t FROM T t WHERE t.n = :n").setParameter("n", n).getResultList(); } }`, "SAFE", CTRL);
J("spring data derived query (safe)", `@RestController public class A { @Autowired UserRepo repo; @GetMapping("/a") public Object a(@RequestParam String n) { return repo.findByName(n); } } interface UserRepo { java.util.List<String> findByName(String n); }`, "SAFE", CTRL);
J("mybatis #{} (safe)", `public interface M { @org.apache.ibatis.annotations.Select("SELECT * FROM t WHERE n = #{name}") java.util.List<String> find(@org.apache.ibatis.annotations.Param("name") String name); }`, "SAFE");
J("@RequestParam int (safe)", `@RestController public class A { @GetMapping("/a") public String a(@RequestParam int id, Statement s) throws Exception { s.executeQuery("SELECT * FROM t WHERE id = " + id); return "ok"; } }`, "SAFE", CTRL);
J("RestTemplate fixed url (safe)", `@RestController public class A { @Autowired org.springframework.web.client.RestTemplate rt; @GetMapping("/a") public String a(@RequestParam String q) { return rt.getForObject("https://api.example.com/x?q={q}", String.class, q); } }`, "SAFE", CTRL);
J("getWriter escaped (safe)", `public class A extends HttpServlet { protected void doGet(HttpServletRequest req, HttpServletResponse res) throws Exception { res.getWriter().write("<h1>" + org.apache.commons.text.StringEscapeUtils.escapeHtml4(req.getParameter("n")) + "</h1>"); } }`, "SAFE", CTRL);
J("getWriter OWASP encoder (safe)", `public class A extends HttpServlet { protected void doGet(HttpServletRequest req, HttpServletResponse res) throws Exception { res.getWriter().write("<h1>" + org.owasp.encoder.Encode.forHtml(req.getParameter("n")) + "</h1>"); } }`, "SAFE", CTRL);
J("spring HtmlUtils (safe)", `@RestController public class A { @GetMapping(value="/a", produces="text/html") public String a(@RequestParam String n) { return "<h1>" + org.springframework.web.util.HtmlUtils.htmlEscape(n) + "</h1>"; } }`, "SAFE", CTRL);
J("Runtime.exec constant (safe)", `@RestController public class A { @GetMapping("/a") public String a() throws Exception { Runtime.getRuntime().exec("uptime"); return "ok"; } }`, "SAFE", CTRL);
J("sendRedirect fixed (safe)", `public class A extends HttpServlet { protected void doGet(HttpServletRequest req, HttpServletResponse res) throws Exception { res.sendRedirect("/home"); } }`, "SAFE", CTRL);
J("file name fixed (safe)", `@RestController public class A { @GetMapping("/a") public Object a() throws Exception { return new FileInputStream("/etc/app/config.json").read(); } }`, "SAFE", CTRL);

// ---------------- controller -> service -> repository across files (Spring dependency injection)
const SPR = (extra: string) => `package app;\nimport org.springframework.web.bind.annotation.*;\nimport org.springframework.beans.factory.annotation.Autowired;\nimport org.springframework.stereotype.*;\nimport java.util.*;\n${extra}\n`;
C.push(["DI field: controller->service->repository(createNativeQuery)", [
  { path: "src/main/java/app/UserController.java", content: SPR("") + `@RestController public class UserController { @Autowired private UserService svc; @GetMapping("/u") public Object find(@RequestParam String name) { return svc.find(name); } }` },
  { path: "src/main/java/app/UserService.java", content: SPR("") + `@Service public class UserService { @Autowired private UserRepository repo; public Object find(String n) { return repo.search(n); } }` },
  { path: "src/main/java/app/UserRepository.java", content: SPR("") + `@Repository public class UserRepository { @javax.persistence.PersistenceContext javax.persistence.EntityManager em; public Object search(String n) { return em.createNativeQuery("SELECT * FROM users WHERE name = '" + n + "'").getResultList(); } }` },
], "VULN:sql-injection"]);
C.push(["DI constructor: controller->service->jdbcTemplate", [
  { path: "src/main/java/app/OrderController.java", content: SPR("") + `@RestController public class OrderController { private final OrderService svc; public OrderController(OrderService s) { this.svc = s; } @GetMapping("/o") public Object find(@RequestParam String id) { return svc.byId(id); } }` },
  { path: "src/main/java/app/OrderService.java", content: SPR("import org.springframework.jdbc.core.JdbcTemplate;") + `@Service public class OrderService { private final JdbcTemplate jdbc; public OrderService(JdbcTemplate j) { this.jdbc = j; } public Object byId(String id) { return jdbc.queryForList("SELECT * FROM orders WHERE id = '" + id + "'"); } }` },
], "VULN:sql-injection"]);
C.push(["DI interface + impl: controller->interface->impl(exec)", [
  { path: "src/main/java/app/RunController.java", content: SPR("") + `@RestController public class RunController { @Autowired private Runner runner; @PostMapping("/r") public String run(@RequestBody String cmd) throws Exception { runner.run(cmd); return "ok"; } }` },
  { path: "src/main/java/app/Runner.java", content: SPR("") + `public interface Runner { void run(String c) throws Exception; }` },
  { path: "src/main/java/app/ShellRunner.java", content: SPR("") + `@Service public class ShellRunner implements Runner { public void run(String c) throws Exception { Runtime.getRuntime().exec(c); } }` },
], "VULN:command-injection"]);
C.push(["DI: controller->service->RestTemplate (ssrf)", [
  { path: "src/main/java/app/ProxyController.java", content: SPR("") + `@RestController public class ProxyController { @Autowired private FetchService svc; @GetMapping("/p") public String p(@RequestParam String url) { return svc.fetch(url); } }` },
  { path: "src/main/java/app/FetchService.java", content: SPR("") + `@Service public class FetchService { @Autowired private org.springframework.web.client.RestTemplate rt; public String fetch(String u) { return rt.getForObject(u, String.class); } }` },
], "VULN:ssrf"]);
C.push(["DI: service sanitises (safe)", [
  { path: "src/main/java/app/SafeController.java", content: SPR("") + `@RestController public class SafeController { @Autowired private SafeService svc; @GetMapping("/s") public Object find(@RequestParam String name) { return svc.find(name); } }` },
  { path: "src/main/java/app/SafeService.java", content: SPR("import org.springframework.jdbc.core.JdbcTemplate;") + `@Service public class SafeService { @Autowired private JdbcTemplate jdbc; public Object find(String n) { return jdbc.queryForList("SELECT * FROM users WHERE name = ?", n); } }` },
], "SAFE"]);


const found = (files: F[]) =>
  [...new Set(runScan({ repo: "x", pr_number: 1, commit_sha: "a", branch: "main", files }).files
    .flatMap(f => f.indicators.filter(i => i.line != null && /critical|high|medium/.test(i.severity)).map(i => i.id)))];

describe("vulnerable code is found", () => {
  it.each(C.filter(c => c[2].startsWith("VULN:")).map(c => [c[0], c[1], c[2]] as const))("%s", (_n, files, expectation) => {
    expect(found(files as F[])).toContain(expectation.slice(5));
  });
});

describe("safe code stays quiet", () => {
  it.each(C.filter(c => c[2] === "SAFE").map(c => [c[0], c[1]] as const))("%s", (_n, files) => {
    expect(found(files as F[]).filter(i => /injection|ssrf|path-traversal|redirect|xss|deserial|eval/.test(i))).toEqual([]);
  });
});
