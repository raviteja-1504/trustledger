import { scanAstTaintJava, parseJavaSource } from "@/lib/astTaintJava";

// Recall + precision for the Java AST engine: entry-point sources, static/utility carriers, containers and
// class-field memory, lambdas and higher-order helpers, string-shape sinks, and the sinks/structural checks
// added with them. `strict` is the engine default (annotated/servlet sources only); `entry` adds the
// un-annotated entry-point tier the scanner uses.

const run = (code: string, entryPoints: boolean): string[] => {
  const cst = parseJavaSource(code);
  if (!cst) throw new Error("parse failed");
  return scanAstTaintJava(code, "A.java", cst, undefined, { entryPoints }).map(f => f.id);
};
const entry = (code: string, id: string) => run(code, true).includes(id);
const strict = (code: string, id: string) => run(code, false).includes(id);
const cls = (body: string, extra = "") => `
import java.util.*; import java.net.*; import java.nio.file.*; import java.sql.*; import java.io.*; import java.util.regex.*;
public class A {
  ${extra}
${body}
}`;

describe("sources", () => {
  it("un-annotated entry-point parameters are sources only in the entry-point tier", () => {
    const code = cls(`public static String q(Connection db, String id) throws Exception { return db.createStatement().executeQuery("SELECT * FROM t WHERE id=" + id).toString(); }`);
    expect(entry(code, "sql-injection")).toBe(true);
    expect(strict(code, "sql-injection")).toBe(false);
  });
  it("entry-point findings are flagged so their confidence can be lowered", () => {
    const code = cls(`public static void q(Statement st, String id) throws Exception { st.executeQuery("SELECT " + id); }`);
    const cst = parseJavaSource(code)!;
    expect(scanAstTaintJava(code, "A.java", cst, undefined, { entryPoints: true }).some(f => f.entryPointSeeded)).toBe(true);
    expect(scanAstTaintJava(code, "A.java", cst).some(f => f.entryPointSeeded)).toBe(false);
  });
  it("a method that something in the file calls is not an entry point; its caller's argument decides", () => {
    const code = cls(`
static void run(Statement st, String id) throws Exception { st.executeQuery("SELECT " + id); }
public static void main(String[] a) throws Exception { run(null, "constant"); }`);
    expect(entry(code, "sql-injection")).toBe(false);
  });
  it("private methods, getters and annotated parameters are never entry points", () => {
    expect(entry(cls(`private static void q(Statement st, String id) throws Exception { st.executeQuery("SELECT " + id); }`), "sql-injection")).toBe(false);
    expect(entry(cls(`public String getName(Statement st, String id) throws Exception { st.executeQuery("SELECT " + id); return ""; }`), "sql-injection")).toBe(false);
    expect(entry(cls(`public static void q(Statement st, @AuthenticationPrincipal String id) throws Exception { st.executeQuery("SELECT " + id); }`), "sql-injection")).toBe(false);
  });
  it("non-string parameters (Connection, int, boolean) are not sources", () => {
    expect(entry(cls(`public static void q(Statement st, int id, boolean b) throws Exception { st.executeQuery("SELECT " + id); }`), "sql-injection")).toBe(false);
  });
  it("a servlet request is recognised by TYPE, not only by the name `request`", () => {
    const code = cls(`public void doGet(HttpServletRequest r, HttpServletResponse resp) throws Exception { String q = r.getParameter("q"); Statement st = null; st.executeQuery("S " + q); }`);
    expect(strict(code, "sql-injection")).toBe(true);
  });
  it("JAX-RS annotations are sources", () => {
    expect(strict(cls(`public void f(@QueryParam("q") String q, Statement st) throws Exception { st.executeQuery("S " + q); }`), "sql-injection")).toBe(true);
  });
});

describe("propagation", () => {
  const sqlOf = (expr: string) => cls(`public static void q(Statement st, String x) throws Exception { st.executeQuery("S " + ${expr}); }`);
  it.each([
    ["URLDecoder.decode", `URLDecoder.decode(x, "UTF-8")`],
    ["String.join", `String.join(",", "a", x)`],
    ["String.valueOf", `String.valueOf(x)`],
    ["Path.of", `Path.of("/b", x).toString()`],
    ["String.replace with tainted replacement", `"abc".replace("b", x)`],
    ["Base64 decoder", `new String(Base64.getDecoder().decode(x))`],
    ["URI.create().resolve", `URI.create("http://h/").resolve(x).toString()`],
    ["new String(bytes)", `new String(x.getBytes())`],
  ])("%s keeps taint", (_l, expr) => {
    expect(entry(sqlOf(expr), "sql-injection")).toBe(true);
  });
  it("a numeric parse neutralizes", () => {
    expect(entry(sqlOf(`Integer.parseInt(x)`), "sql-injection")).toBe(false);
  });
  it("a decoder re-taints what an HTML escaper cleared", () => {
    const code = cls(`public static String q(String v) throws Exception { return "<b>" + URLDecoder.decode(escape(v), "UTF-8") + "</b>"; }
static String escape(String s) { return s.replace("<", "&lt;").replace(">", "&gt;"); }`);
    expect(entry(code, "xss")).toBe(true);
  });
  it("Map.put then get carries the value", () => {
    const code = cls(`public static void q(Statement st, String x) throws Exception { Map<String,String> m = new HashMap<>(); m.put("k", x); st.executeQuery("S " + m.get("k")); }`);
    expect(entry(code, "sql-injection")).toBe(true);
  });
  it("an array initializer carries its elements", () => {
    const code = cls(`public static void q(String cmd) throws Exception { Runtime.getRuntime().exec(new String[]{"sh", "-c", "echo " + cmd}); }`);
    expect(entry(code, "command-injection")).toBe(true);
  });
  it("class-field memory: written by one method, read by another (either order)", () => {
    const code = cls(`
static String render() { StringBuilder b = new StringBuilder(); for (String c : comments) b.append("<li>").append(c).append("</li>"); return b.toString(); }
public static void save(String x) { comments.add(x); }`, `static List<String> comments = new ArrayList<>();`);
    expect(entry(code, "xss")).toBe(true);
  });
  it("second-order SQL through a static Map", () => {
    const code = cls(`
public static void save(String u, String s) { saved.put(u, s); }
static String run(Statement st, String u) throws Exception { return st.executeQuery("S '" + saved.get(u) + "'").toString(); }`, `static Map<String,String> saved = new HashMap<>();`);
    expect(entry(code, "sql-injection")).toBe(true);
  });
  it("a local that shadows the field is not tainted by it", () => {
    const code = cls(`
public static void save(String x) { comments.add(x); }
static String render() { List<String> comments = List.of("a"); StringBuilder b = new StringBuilder(); for (String c : comments) b.append("<li>").append(c); return b.toString(); }`, `static List<String> comments = new ArrayList<>();`);
    expect(entry(code, "xss")).toBe(false);
  });
});

describe("lambdas and higher-order helpers", () => {
  it("f.apply(v) resolves to the lambda's body", () => {
    const code = cls(`public static String q(String v) { java.util.function.Function<String,String> f = x -> "<div>" + x + "</div>"; return f.apply(v); }`);
    expect(entry(code, "xss")).toBe(true);
  });
  it("a lambda that captured a tainted value carries it", () => {
    const code = cls(`public static String q(String v) { final String c = v; java.util.function.Function<String,String> f = x -> "<h1>" + c + "</h1>"; return f.apply(""); }`);
    expect(entry(code, "xss")).toBe(true);
  });
  it("a local higher-order helper propagates through its callback parameter", () => {
    const code = cls(`
static String map(String v, java.util.function.Function<String,String> f) { return f.apply(v); }
public static String q(String v) { return map(v, x -> "<span>" + x + "</span>"); }`);
    expect(entry(code, "xss")).toBe(true);
  });
  it("CompletableFuture.supplyAsync(...).get() carries the supplier's value", () => {
    const code = cls(`public static void q(Statement st, String id) throws Exception { String s = java.util.concurrent.CompletableFuture.supplyAsync(() -> "S " + id).get(); st.executeQuery(s); }`);
    expect(entry(code, "sql-injection")).toBe(true);
  });
});

describe("string-shape sinks", () => {
  it("SQL / LDAP / XPath / LDAP URL strings built around untrusted input", () => {
    expect(entry(cls(`public static String q(String id) { return "SELECT * FROM t WHERE id='" + id + "'"; }`), "sql-injection")).toBe(true);
    expect(entry(cls(`public static String q(String u) { return "(&(objectClass=person)(uid=" + u + "))"; }`), "ldap-injection")).toBe(true);
    expect(entry(cls(`public static String q(String u) { return "/users/user[name/text()='" + u + "']"; }`), "xpath-injection")).toBe(true);
    expect(entry(cls(`public static String q(String h) { return "ldap://" + h + "/dc=x"; }`), "ldap-injection")).toBe(true);
    expect(entry(cls(`public static String q(String id) { return String.format("SELECT * FROM t WHERE id='%s'", id); }`), "sql-injection")).toBe(true);
  });
  it("ordinary string building is not flagged", () => {
    expect(entry(cls(`public static String q(String n) { return "Hello " + n; }`), "sql-injection")).toBe(false);
    expect(entry(cls(`public static String q(String n) { return "a=" + n; }`), "ldap-injection")).toBe(false);
  });
  it("a returned HTML string built from untrusted input is XSS; a non-HTML string is not", () => {
    expect(entry(cls(`public static String q(String n) { return "<p>" + n + "</p>"; }`), "xss")).toBe(true);
    expect(entry(cls(`public static String q(String n) { return "value=" + n; }`), "xss")).toBe(false);
  });
  it("generics are not HTML markup", () => {
    expect(entry(cls(`public static Map<String,Object> q(String n) { Map<String,Object> m = new HashMap<>(); m.put("k", n); return m; }`), "xss")).toBe(false);
  });
});

describe("escaping", () => {
  const esc = `static String enc(String x) { return x.replace("<", "&lt;").replace(">", "&gt;"); }`;
  it("a local method that replaces < with an entity is an HTML escaper", () => {
    expect(entry(cls(`public static String q(String v) { return "<div>" + enc(v) + "</div>"; }`, esc), "xss")).toBe(false);
  });
  it("escape-then-append re-taints", () => {
    expect(entry(cls(`public static String q(String v, String s) { return "<div>" + enc(v) + s + "</div>"; }`, esc), "xss")).toBe(true);
  });
  it("an escaped value inside <script> is still XSS; in element text or a quoted attribute it is not", () => {
    expect(entry(cls(`public static String q(String v) { return "<script>let x='" + enc(v) + "';</script>"; }`, esc), "xss")).toBe(true);
    expect(entry(cls(`public static String q(String v) { return "<div data-v=\\"" + enc(v) + "\\"></div>"; }`, esc), "xss")).toBe(false);
  });
});

describe("new sinks", () => {
  it("header injection: setHeader and header-shaped map puts", () => {
    expect(entry(cls(`public static void q(HttpServletResponse r, String v) { r.setHeader("X-A", v); }`), "header-injection")).toBe(true);
    expect(entry(cls(`public static Map<String,String> q(String v) { Map<String,String> h = new HashMap<>(); h.put("Content-Disposition", "attachment; filename=" + v); return h; }`), "header-injection")).toBe(true);
    expect(entry(cls(`public static Map<String,String> q(String v) { Map<String,String> h = new HashMap<>(); h.put("name", v); return h; }`), "header-injection")).toBe(false);
  });
  it("path traversal through Path.of / Files", () => {
    expect(entry(cls(`public static String q(String n) throws Exception { return Files.readString(Path.of("/base", n)); }`), "path-traversal")).toBe(true);
    expect(entry(cls(`public static void q(String n, String c) throws Exception { Path p = Path.of("/base", n); Files.writeString(p, c); }`), "path-traversal")).toBe(true);
  });
  it("command execution through ProcessBuilder and Runtime.exec", () => {
    expect(entry(cls(`public static void q(String e, String a) throws Exception { new ProcessBuilder(e, a).start(); }`), "command-injection")).toBe(true);
    expect(entry(cls(`public static void q(String h) throws Exception { Runtime.getRuntime().exec("ping " + h); }`), "command-injection")).toBe(true);
  });
  it("SSRF through new URL(...) and raw sockets", () => {
    expect(entry(cls(`public static void q(String u) throws Exception { new URL(u).openStream(); }`), "ssrf")).toBe(true);
    expect(entry(cls(`public static void q(String h) throws Exception { new Socket(h, 80); }`), "ssrf")).toBe(true);
  });
  it("regex built from input", () => {
    expect(entry(cls(`public static boolean q(String p, String i) { return Pattern.compile(p).matcher(i).find(); }`), "redos")).toBe(true);
    expect(entry(cls(`public static boolean q(String i) { return Pattern.compile("^a+$").matcher(i).find(); }`), "redos")).toBe(false);
  });
  it("reflection and dynamic class loading", () => {
    expect(entry(cls(`public static Class<?> q(String n) throws Exception { return Class.forName(n); }`), "eval-exec")).toBe(true);
    expect(entry(cls(`public static Object q(Object o, String f, String v) throws Exception { o.getClass().getField(f).set(o, v); return o; }`), "mass-assignment")).toBe(true);
    expect(entry(cls(`public static Class<?> q() throws Exception { return Class.forName("java.lang.String"); }`), "eval-exec")).toBe(false);
  });
  it("script engines and SpEL", () => {
    expect(entry(cls(`public static Object q(javax.script.ScriptEngine e, String x) throws Exception { return e.eval(x); }`), "eval-exec")).toBe(true);
  });
  it("deserialization straight from untrusted bytes", () => {
    expect(entry(cls(`public static Object q(byte[] d) throws Exception { return new ObjectInputStream(new ByteArrayInputStream(d)).readObject(); }`), "insecure-deserialization")).toBe(true);
    expect(entry(cls(`public static Object q() throws Exception { return new ObjectInputStream(new FileInputStream("/etc/x")).readObject(); }`), "insecure-deserialization")).toBe(false);
  });
  it("template text controlled by the caller", () => {
    expect(entry(cls(`public static String q(String t, String u) { return t.replace("\${user}", u); }`), "ssti")).toBe(true);
    expect(entry(cls(`public static String q(String u) { return "Hi \${user}".replace("\${user}", u); }`), "ssti")).toBe(false);
  });
  it("copying every entry of an attacker map onto a target", () => {
    const code = cls(`static void merge(Map<String,Object> t, Map<String,Object> s) { for (var e : s.entrySet()) { t.put(e.getKey(), e.getValue()); } }`);
    expect(entry(code, "mass-assignment")).toBe(true);
    const counting = cls(`public static Map<String,Integer> q(List<String> ws) { Map<String,Integer> c = new HashMap<>(); for (String w : ws) c.put(w, 1); return c; }`);
    expect(entry(counting, "mass-assignment")).toBe(false);
  });
  it("secret compared with equals()", () => {
    expect(entry(cls(`public static boolean q(String supplied) { return supplied.equals(SECRET); }`, `static final String SECRET = "x";`), "timing-attack")).toBe(true);
    expect(entry(cls(`public static boolean q(String supplied) { return supplied.equals("admin"); }`), "timing-attack")).toBe(false);
  });
  it("weak digests", () => {
    expect(entry(cls(`public static Object q() throws Exception { return java.security.MessageDigest.getInstance("MD5"); }`), "weak-crypto")).toBe(true);
    expect(entry(cls(`public static Object q() throws Exception { return java.security.MessageDigest.getInstance("SHA-256"); }`), "weak-crypto")).toBe(false);
  });
  it("a hand-rolled JWT payload decode in a file with no verification", () => {
    const code = cls(`public static String q(String t) { String[] p = t.split("\\\\."); return new String(Base64.getUrlDecoder().decode(p[1])); }`);
    expect(strict(code, "jwt-none-alg")).toBe(true);
    expect(strict(`import io.jsonwebtoken.Jwts;\n${code}`, "jwt-none-alg")).toBe(false);
  });
});
