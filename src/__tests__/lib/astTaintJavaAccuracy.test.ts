/**
 * @jest-environment node
 *
 * Java AST taint engine accuracy: method identity (overloads, same-name methods in different classes), method-scoped
 * variable types, path construction vs filesystem access, XXE per parser instance, reflection lookup vs invocation,
 * expression parsing vs evaluation, lambdas / method references, cross-file resolution, finding quality.
 */
import { runScan } from "@/lib/scanner";
import type { ScanIndicator } from "@/lib/scanner";
import { scanAstTaintJava, parseJavaSource } from "@/lib/astTaintJava";

const HEAD = `package app;
import javax.servlet.http.*;
import java.io.*;
import java.nio.file.*;
import java.sql.*;
`;
const cls = (body: string, extra = "") => `${HEAD}${extra}
public class A extends HttpServlet {
${body}
}`;
const ids = (src: string, id: string): number[] => {
  const cst = parseJavaSource(src);
  if (!cst) throw new Error("parse failed");
  return scanAstTaintJava(src, "A.java", cst).filter(f => f.id === id).map(f => f.line);
};
const get = (body: string) => `  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
${body}
  }`;

type F = { path: string; content: string };
const scan = (files: F[]) => runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files });
const found = (files: F[], path: string, id: string): ScanIndicator[] =>
  scan(files).files.find(f => f.file_path === path)!.indicators.filter(i => i.confidence === 95 && i.sourceExpr !== undefined && i.id === id);

describe("method identity", () => {
  it("overloads do not overwrite each other: only the overload that reaches the sink is dangerous", () => {
    const src = (call: string) => cls(`
  private String run(String cmd) { return cmd; }
  private String run(String cmd, int n) { Runtime.getRuntime().exec(cmd); return "x"; }
${get(`    String c = request.getParameter("c");\n    ${call}`)}`);
    expect(ids(src(`run(c, 1);`), "command-injection").length).toBeGreaterThan(0);
    expect(ids(src(`run(c);`), "command-injection")).toEqual([]);
  });
  it("same-name methods in different classes stay separate", () => {
    const src = (receiver: string) => `${HEAD}
class Safe { String run(String c) { return c.length() + ""; } }
class Danger { String run(String c) { try { Runtime.getRuntime().exec(c); } catch (Exception e) {} return "x"; } }
public class A extends HttpServlet {
  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String c = request.getParameter("c");
    ${receiver}.run(c);
  }
}`;
    expect(ids(src(`new Safe()`), "command-injection")).toEqual([]);
    expect(ids(src(`new Danger()`), "command-injection").length).toBeGreaterThan(0);
  });
  it("a return summary belongs to one overload", () => {
    const src = (call: string) => cls(`
  private String pick(String a) { return "ls"; }
  private String pick(String a, String b) { return b; }
${get(`    String c = request.getParameter("c");\n    Runtime.getRuntime().exec(${call});`)}`);
    expect(ids(src(`pick("x", c)`), "command-injection").length).toBeGreaterThan(0);
    expect(ids(src(`pick(c)`), "command-injection")).toEqual([]);
  });
});

describe("method-scoped variable types", () => {
  it("the same variable name with different types in different methods", () => {
    const src = `${HEAD}
public class A extends HttpServlet {
  private void safeOne(String q) {
    StringBuilder name = new StringBuilder(q);
    log(name.toString());
  }
  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
    Statement name = null;
    String c = request.getParameter("c");
    name.execute("SELECT * FROM t WHERE x = '" + c + "'");
  }
}`;
    expect(ids(src, "sql-injection").length).toBeGreaterThan(0);
  });
  it("a parameter named like a Statement in one method does not make a String a Statement in another", () => {
    const src = `${HEAD}
public class A extends HttpServlet {
  private void a(Statement stmt, String t) throws Exception { stmt.executeQuery("SELECT 1"); }
  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String stmt = request.getParameter("c");
    response.getWriter().println(stmt.trim().length());
  }
}`;
    expect(ids(src, "sql-injection")).toEqual([]);
  });
  it("a local shadows a class field of another type", () => {
    const src = `${HEAD}
public class A extends HttpServlet {
  private Statement conn;
  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
    java.util.List<String> conn = new java.util.ArrayList<>();
    conn.add(request.getParameter("c"));
  }
}`;
    expect(ids(src, "sql-injection")).toEqual([]);
  });
});

describe("path construction vs filesystem access", () => {
  const p = (body: string) => cls(get(`    String f = request.getParameter("f");\n${body}`));
  it("Path.of, Paths.get and new File alone are not findings", () => {
    expect(ids(p(`    Path full = Paths.get("/srv", f);`), "path-traversal")).toEqual([]);
    expect(ids(p(`    Path full = Path.of("/srv", f);`), "path-traversal")).toEqual([]);
    expect(ids(p(`    File full = new File("/srv", f);`), "path-traversal")).toEqual([]);
    expect(ids(p(`    File full = new File("/srv/" + f);\n    response.getWriter().println(full.getName());`), "path-traversal")).toEqual([]);
  });
  it.each([
    ["Files.readString", `    Path full = Paths.get("/srv", f);\n    String s = Files.readString(full);`],
    ["Files.newInputStream", `    Path full = Path.of("/srv", f);\n    InputStream in = Files.newInputStream(full);`],
    ["FileInputStream", `    File full = new File("/srv", f);\n    InputStream in = new FileInputStream(full);`],
    ["File.delete", `    File full = new File("/srv", f);\n    full.delete();`],
    ["File.listFiles", `    File full = new File("/srv", f);\n    full.listFiles();`],
    ["File.exists", `    File full = new File("/srv/" + f);\n    boolean b = full.exists();`],
    ["FileReader on a string", `    Reader r = new FileReader("/srv/" + f);`],
    ["Files.walk", `    Files.walk(Paths.get("/srv", f));`],
  ])("a tainted path reaching %s is reported", (_n, body) => {
    expect(ids(p(body), "path-traversal").length).toBeGreaterThan(0);
  });
  it("an absolute path escapes the base: a '..' check proves nothing", () => {
    expect(ids(p(`    if (f.contains("..")) { return; }\n    InputStream in = new FileInputStream(new File("/srv", f));`), "path-traversal").length).toBeGreaterThan(0);
  });
  it("URL-decoded traversal is still the same value", () => {
    expect(ids(p(`    String d = java.net.URLDecoder.decode(f, "UTF-8");\n    InputStream in = new FileInputStream(new File("/srv", d));`), "path-traversal").length).toBeGreaterThan(0);
  });
  it("canonical containment makes the access safe", () => {
    expect(ids(p(`    File full = new File("/srv", f).getCanonicalFile();\n    if (!full.getPath().startsWith("/srv/")) { return; }\n    InputStream in = new FileInputStream(full);`), "path-traversal")).toEqual([]);
    expect(ids(p(`    Path full = Paths.get("/srv").resolve(f).normalize();\n    if (!full.startsWith(Paths.get("/srv"))) { return; }\n    String s = Files.readString(full);`), "path-traversal")).toEqual([]);
  });
  it("a containment test on a path that was not normalised proves nothing", () => {
    expect(ids(p(`    Path full = Paths.get("/srv").resolve(f);\n    if (!full.startsWith(Paths.get("/srv"))) { return; }\n    String s = Files.readString(full);`), "path-traversal").length).toBeGreaterThan(0);
  });
});

describe("XXE is judged per parser instance", () => {
  const x = (body: string) => cls(get(`    String xml = request.getParameter("x");\n${body}`), "import javax.xml.parsers.*;\nimport javax.xml.XMLConstants;\nimport org.xml.sax.InputSource;\nimport java.io.StringReader;\n");
  const HARD = `    DocumentBuilderFactory f1 = DocumentBuilderFactory.newInstance();\n    f1.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\n    DocumentBuilder b1 = f1.newDocumentBuilder();\n`;
  const SOFT = `    DocumentBuilderFactory f2 = DocumentBuilderFactory.newInstance();\n    DocumentBuilder b2 = f2.newDocumentBuilder();\n`;
  it("a hardened factory's builder is safe", () => {
    expect(ids(x(`${HARD}    b1.parse(new InputSource(new StringReader(xml)));`), "xxe")).toEqual([]);
  });
  it("an unhardened factory's builder is not", () => {
    expect(ids(x(`${SOFT}    b2.parse(new InputSource(new StringReader(xml)));`), "xxe").length).toBeGreaterThan(0);
  });
  it("hardening one factory does not harden another in the same file", () => {
    expect(ids(x(`${HARD}${SOFT}    b2.parse(new InputSource(new StringReader(xml)));`), "xxe").length).toBeGreaterThan(0);
    expect(ids(x(`${HARD}${SOFT}    b1.parse(new InputSource(new StringReader(xml)));`), "xxe")).toEqual([]);
  });
  it("hardening in another method does not harden this one", () => {
    const src = `${HEAD}import javax.xml.parsers.*;\nimport org.xml.sax.InputSource;\nimport java.io.StringReader;
public class A extends HttpServlet {
  private DocumentBuilder safe() throws Exception {
    DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
    f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    return f.newDocumentBuilder();
  }
  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String xml = request.getParameter("x");
    DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
    DocumentBuilder b = f.newDocumentBuilder();
    b.parse(new InputSource(new StringReader(xml)));
  }
}`;
    expect(ids(src, "xxe").length).toBeGreaterThan(0);
  });
  it("configuration order: hardening applied after the builder was created does not protect it", () => {
    const body = `    DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\n    DocumentBuilder b = f.newDocumentBuilder();\n    f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);\n    b.parse(new InputSource(new StringReader(xml)));`;
    expect(ids(x(body), "xxe").length).toBeGreaterThan(0);
  });
  it("secure processing alone or enabling the feature as false is not hardening it; the external-access properties are", () => {
    const off = `    DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\n    f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, false);\n    DocumentBuilder b = f.newDocumentBuilder();\n    b.parse(new InputSource(new StringReader(xml)));`;
    expect(ids(x(off), "xxe").length).toBeGreaterThan(0);
    const dtd = `    DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\n    f.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");\n    f.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");\n    DocumentBuilder b = f.newDocumentBuilder();\n    b.parse(new InputSource(new StringReader(xml)));`;
    expect(ids(x(dtd), "xxe")).toEqual([]);
  });
  it("external general and parameter entities disabled", () => {
    const body = `    DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();\n    f.setFeature("http://xml.org/sax/features/external-general-entities", false);\n    f.setFeature("http://xml.org/sax/features/external-parameter-entities", false);\n    DocumentBuilder b = f.newDocumentBuilder();\n    b.parse(new InputSource(new StringReader(xml)));`;
    expect(ids(x(body), "xxe")).toEqual([]);
  });
});

describe("reflection: lookup is not invocation", () => {
  const r = (body: string) => cls(get(`    String n = request.getParameter("n");\n${body}`), "import java.lang.reflect.*;\n");
  it("Class.forName / getMethod / getDeclaredMethod / loadClass alone are not code execution", () => {
    expect(ids(r(`    Class<?> c = Class.forName(n);`), "eval-exec")).toEqual([]);
    expect(ids(r(`    Method m = String.class.getMethod(n);`), "eval-exec")).toEqual([]);
    expect(ids(r(`    Method m = String.class.getDeclaredMethod(n);`), "eval-exec")).toEqual([]);
    expect(ids(r(`    Class<?> c = A.class.getClassLoader().loadClass(n);`), "eval-exec")).toEqual([]);
  });
  it("reaching invoke or newInstance is", () => {
    expect(ids(r(`    Method m = String.class.getMethod(n);\n    m.invoke("x");`), "eval-exec").length).toBeGreaterThan(0);
    expect(ids(r(`    Class<?> c = Class.forName(n);\n    Object o = c.getDeclaredConstructor().newInstance();`), "eval-exec").length).toBeGreaterThan(0);
  });
  it("invoking a method chosen by a constant is not", () => {
    expect(ids(r(`    Method m = String.class.getMethod("length");\n    m.invoke("x");`), "eval-exec")).toEqual([]);
  });
  it("getField alone is not mass assignment; writing through the attacker-chosen field is", () => {
    expect(ids(r(`    Field f = A.class.getField(n);`), "mass-assignment")).toEqual([]);
    expect(ids(r(`    Field f = A.class.getDeclaredField(n);\n    f.set(this, "v");`), "mass-assignment").length).toBeGreaterThan(0);
  });
});

describe("SpEL: parsing is not evaluating", () => {
  const s = (body: string) => cls(get(`    String e = request.getParameter("e");\n${body}`), "import org.springframework.expression.*;\nimport org.springframework.expression.spel.standard.SpelExpressionParser;\n");
  it("parseExpression alone is not a finding", () => {
    expect(ids(s(`    ExpressionParser p = new SpelExpressionParser();\n    Expression ex = p.parseExpression(e);`), "eval-exec")).toEqual([]);
  });
  it("evaluating the parsed expression is", () => {
    expect(ids(s(`    ExpressionParser p = new SpelExpressionParser();\n    Expression ex = p.parseExpression(e);\n    Object v = ex.getValue();`), "eval-exec").length).toBeGreaterThan(0);
    expect(ids(s(`    Object v = new SpelExpressionParser().parseExpression(e).getValue();`), "eval-exec").length).toBeGreaterThan(0);
  });
  it("evaluating a constant expression is not", () => {
    expect(ids(s(`    Object v = new SpelExpressionParser().parseExpression("1 + 1").getValue();`), "eval-exec")).toEqual([]);
  });
});

describe("SQL: prepared statements vs concatenation", () => {
  const q = (body: string) => cls(get(`    String id = request.getParameter("id");\n    Connection conn = null;\n${body}`));
  it("a bound parameter is safe", () => {
    expect(ids(q(`    PreparedStatement ps = conn.prepareStatement("SELECT * FROM t WHERE id = ?");\n    ps.setString(1, id);\n    ps.executeQuery();`), "sql-injection")).toEqual([]);
  });
  it("concatenation is not", () => {
    expect(ids(q(`    Statement st = conn.createStatement();\n    st.executeQuery("SELECT * FROM t WHERE id = '" + id + "'");`), "sql-injection").length).toBeGreaterThan(0);
    expect(ids(q(`    PreparedStatement ps = conn.prepareStatement("SELECT * FROM t WHERE id = '" + id + "'");`), "sql-injection").length).toBeGreaterThan(0);
  });
});

describe("lambdas and method references", () => {
  const l = (body: string) => cls(get(`    String c = request.getParameter("c");\n${body}`), "import java.util.*;\nimport java.util.function.*;\n");
  it("a lambda that returns its argument carries taint", () => {
    expect(ids(l(`    Function<String, String> f = s -> s + "x";\n    Runtime.getRuntime().exec(f.apply(c));`), "command-injection").length).toBeGreaterThan(0);
  });
  it("a lambda that ignores its argument does not", () => {
    expect(ids(l(`    Function<String, String> f = s -> "ls";\n    Runtime.getRuntime().exec(f.apply(c));`), "command-injection")).toEqual([]);
  });
  it("a lambda body that sinks its parameter, applied to tainted input", () => {
    expect(ids(l(`    Consumer<String> run = s -> { try { Runtime.getRuntime().exec(s); } catch (Exception e) {} };\n    run.accept(c);`), "command-injection").length).toBeGreaterThan(0);
    expect(ids(l(`    Consumer<String> run = s -> { try { Runtime.getRuntime().exec(s); } catch (Exception e) {} };\n    run.accept("ls");`), "command-injection")).toEqual([]);
  });
  it("a method reference to a local method", () => {
    const src = cls(`
  private void sink(String s) { try { Runtime.getRuntime().exec(s); } catch (Exception e) {} }
${get(`    String c = request.getParameter("c");\n    List<String> xs = Arrays.asList(c);\n    xs.forEach(this::sink);`)}`, "import java.util.*;\n");
    expect(ids(src, "command-injection").length).toBeGreaterThan(0);
  });
  it("a stream pipeline through map keeps taint", () => {
    expect(ids(l(`    List<String> out = Arrays.asList(c).stream().map(s -> s.trim()).collect(java.util.stream.Collectors.toList());\n    Runtime.getRuntime().exec(out.get(0));`), "command-injection").length).toBeGreaterThan(0);
  });
});

describe("cross-file resolution uses class identity", () => {
  const SERVICE = (pkg: string, body: string) => ({ path: `${pkg.replace(/\./g, "/")}/Svc.java`, content: `package ${pkg};\npublic class Svc {\n  public void run(String c) {\n    ${body}\n  }\n}\n` });
  const CALLER = (imp: string) => ({ path: "web/Ctl.java", content: `package web;\nimport javax.servlet.http.*;\n${imp}\npublic class Ctl extends HttpServlet {\n  private final Svc svc = new Svc();\n  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {\n    String c = request.getParameter("c");\n    svc.run(c);\n  }\n}\n` });
  it("two classes with the same simple name in different packages: the import picks one", () => {
    const files = (imp: string): F[] => [SERVICE("a.dangerous", "try { Runtime.getRuntime().exec(c); } catch (Exception e) {}"), SERVICE("b.safe", "System.out.println(c.length());"), CALLER(imp)];
    expect(found(files("import a.dangerous.Svc;"), "web/Ctl.java", "command-injection").length).toBeGreaterThan(0);
    expect(found(files("import b.safe.Svc;"), "web/Ctl.java", "command-injection")).toHaveLength(0);
  });
  it("an ambiguous simple name with no import is unknown, not a guess", () => {
    const files: F[] = [SERVICE("a.dangerous", "try { Runtime.getRuntime().exec(c); } catch (Exception e) {}"), SERVICE("b.safe", "System.out.println(c.length());"), CALLER("")];
    expect(found(files, "web/Ctl.java", "command-injection")).toHaveLength(0);
  });
  it("a trace through the callee names the callee file and sink line", () => {
    const f = found([SERVICE("a.dangerous", "try { Runtime.getRuntime().exec(c); } catch (Exception e) {}"), CALLER("import a.dangerous.Svc;")], "web/Ctl.java", "command-injection")[0];
    expect(f).toBeDefined();
    const last = f.trace![f.trace!.length - 1];
    expect(last.kind).toBe("sink");
    expect(last.file).toBe("a/dangerous/Svc.java");
  });
});

describe("BOLA: ownership checks", () => {
  const b = (params: string, body: string) => `${HEAD}import org.springframework.web.bind.annotation.*;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
@RestController
public class A {
  private java.util.Map<Long, Object> repo = new java.util.HashMap<>();
  @GetMapping("/orders/{id}")
  public Object get(${params}) {
${body}
  }
}`;
  const P = "@PathVariable Long id, @AuthenticationPrincipal Account user";
  it("an unchecked lookup by request id is reported", () => {
    expect(ids(b(P, `    return repo.get(id);`), "bola-missing-ownership-check").length).toBeGreaterThan(0);
  });
  it("comparing the request id with the authenticated principal before the lookup is safe", () => {
    expect(ids(b(P, `    if (!id.equals(user.getId())) { throw new RuntimeException(); }\n    return repo.get(id);`), "bola-missing-ownership-check")).toEqual([]);
  });
  it("a comparison that does not involve the principal is not an ownership check", () => {
    expect(ids(b(P, `    if (id.equals(0L)) { return null; }\n    return repo.get(id);`), "bola-missing-ownership-check").length).toBeGreaterThan(0);
  });
  it("a comparison against some other request value is not an ownership check either", () => {
    expect(ids(b(P + ", @RequestParam Long other", `    if (!id.equals(other)) { throw new RuntimeException(); }\n    return repo.get(id);`), "bola-missing-ownership-check").length).toBeGreaterThan(0);
  });
});

describe("type environments are per method (a name typed in one method is not typed that way in another)", () => {
  it("a Statement parameter in one method does not make a same-named local of another type a Statement", () => {
    const src = `${HEAD}
class Runner { void execute(String s) {} }
public class A extends HttpServlet {
  private void other(Statement conn) throws Exception { conn.close(); }
  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
    Runner conn = new Runner();
    conn.execute(request.getParameter("c"));
  }
}`;
    expect(ids(src, "sql-injection")).toEqual([]);
  });
  it("and when the local really is a Statement it is still reported", () => {
    const src = `${HEAD}
class Runner { void execute(String s) {} }
public class A extends HttpServlet {
  private void other(Runner conn) throws Exception { conn.execute("x"); }
  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
    Statement conn = null;
    conn.execute(request.getParameter("c"));
  }
}`;
    expect(ids(src, "sql-injection").length).toBeGreaterThan(0);
  });
  it("a field type applies only inside its own class", () => {
    const src = `${HEAD}
class Dao { private Statement conn; void a() throws Exception { conn.close(); } }
public class A extends HttpServlet {
  private Runner conn;
  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
    conn.execute(request.getParameter("c"));
  }
}
class Runner { void execute(String s) {} }`;
    expect(ids(src, "sql-injection")).toEqual([]);
  });
});

describe("finding quality: evidence and coverage", () => {
  it("a confirmed flow carries a source-to-sink trace", () => {
    const f = found([{ path: "A.java", content: cls(get(`    String c = request.getParameter("c");\n    Runtime.getRuntime().exec(c);`)) }], "A.java", "command-injection")[0];
    expect(f).toBeDefined();
    expect(f.trace!.map(t => t.kind)[0]).toBe("source");
    expect(f.trace![f.trace!.length - 1].kind).toBe("sink");
  });
});
