/**
 * Precision fixes from scanning OWASP SecurityShepherd, each with the real bug it must keep catching:
 *   - search() is an LDAP query only on a directory context / LDAP template (not FindXSS.search(term))
 *   - an environment-variable name used as a placeholder ("TLS_KEYSTORE_PASS") is not a password
 *   - new URL(x) only parses: SSRF needs the URL to be fetched
 *   - new File(...) of a classpath resource or a literal is a fixed path, whatever input sits nearby
 */
import { analyzeFile } from "@/lib/scanner";
import { scanAstTaintJava, parseJavaSource } from "@/lib/astTaintJava";
import { ensureTaintEngines } from "@/lib/engineWarmup";

jest.setTimeout(60_000);
beforeAll(async () => { await ensureTaintEngines(); });

const lines = (path: string, src: string, id: string) => analyzeFile(path, src).indicators.filter(i => i.id === id).map(i => i.line);
const servlet = (body: string, extra = "") => `import javax.servlet.http.*; import java.io.*; import java.net.*;
public class S extends HttpServlet {
${extra}
  public void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
    String term = request.getParameter("term");
${body}
  }
}
`;
// The body starts on line 6 of servlet().
const L = 6;

describe("LDAP: search() on something that can run one", () => {
  it("a static helper or a service of another type is not an LDAP query", () => {
    expect(lines("S.java", servlet(`    boolean hit = FindXSS.search(term);`), "ldap-injection")).toEqual([]);
    expect(lines("S.java", servlet(`    Object r = service.search(user, term);`, "  private final SearchService service = null;"), "ldap-injection")).toEqual([]);
  });

  it("a DirContext / LdapTemplate search with the input in the filter still is (the data-flow engine itself)", () => {
    const ast = (src: string) => scanAstTaintJava(src, "S.java", parseJavaSource(src)!).filter(f => f.id === "ldap-injection").map(f => f.line);
    // the whole filter from the request (no "(uid=" text, so only the search() sink can report it)
    expect(ast(servlet(`    Object r = ctx.search("ou=people", term, controls);`, "  private DirContext ctx;"))).toEqual([L]);
    expect(ast(servlet(`    Object r = ldapTemplate.search("ou=people", term, mapper);`, "  private LdapTemplate ldapTemplate;"))).toEqual([L]);
  });
});

describe("secrets: a placeholder variable name is not a password", () => {
  it("sed-replaced TLS_KEYSTORE_PASS is a name; a real literal still is a secret", () => {
    const docker = `FROM tomcat:9\nRUN sed -i -e 's/certificateKeystorePassword="TLS_KEYSTORE_PASS"/certificateKeystorePassword="'"$TLS_KEYSTORE_PASS"'"/' conf/server.xml\n`;
    expect(lines("Dockerfile", docker, "hardcoded-secret")).toEqual([]);
    expect(lines("src/Conf.java", `class Conf {\n  String keystorePassword = "Tq7vLm2Xr9Kp";\n}\n`, "hardcoded-secret")).toEqual([2]);
  });
});

describe("SSRF: the URL has to be fetched, not just parsed", () => {
  it("new URL(input).getHost() is a parse; openConnection / openStream / fetch on it is a request", () => {
    expect(lines("S.java", servlet(`    URL u = new URL(term);\n    String host = u.getHost();`), "ssrf")).toEqual([]);
    expect(lines("S.java", servlet(`    String host = new URL(term).getHost();`), "ssrf")).toEqual([]);
    expect(lines("S.java", servlet(`    URL u = new URL(term);\n    URLConnection c = u.openConnection();`), "ssrf").length).toBeGreaterThan(0);
    expect(lines("S.java", servlet(`    InputStream in = new URL(term).openStream();`), "ssrf").length).toBeGreaterThan(0);
  });

  it("the pattern rule on its own (a file the data-flow engine can't parse) sees the later fetch", () => {
    // A stray brace keeps the Java engine out, so only the line patterns decide.
    const broken = (use: string) => `class S {{ void f(HttpServletRequest request) {\n    String term = request.getParameter("u");\n    URL u = new URL(term);\n    ${use}\n`;
    expect(lines("S.java", broken(`log(u.getHost());`), "ssrf")).toEqual([]);
    // parsed inline, never stored or fetched
    const inline = `class S {{ void f(HttpServletRequest request) {\n    String term = request.getParameter("u");\n    log(new URL(term).getHost());\n`;
    expect(lines("S.java", inline, "ssrf")).toEqual([]);
    expect(lines("S.java", broken(`HttpURLConnection c = (HttpURLConnection) u.openConnection();`), "ssrf")).toContain(3);
  });

  it("the same rule in JavaScript: parsing is not fetching", () => {
    const js = (use: string) => `app.get("/p", (req, res) => {\n  const target = req.query.url;\n  const u = new URL(target);\n  ${use}\n});\n`;
    expect(lines("src/proxy.js", js(`res.send(u.hostname);`), "ssrf")).toEqual([]);
    expect(lines("src/proxy.js", js(`fetch(u).then(r => r.text()).then(t => res.send(t));`), "ssrf")).toEqual([4]);
  });
});

describe("path traversal: a fixed path is fixed whatever input sits nearby", () => {
  it("a classpath resource or a literal is not user-controlled; a path built from input still is", () => {
    const res = servlet(`    String props =\n        new File(Database.class.getResource("/challenges/x.properties").getFile()).getAbsolutePath();`);
    expect(lines("S.java", res, "path-traversal")).toEqual([]);
    expect(lines("S.java", servlet(`    File f = new File("/etc/app.conf");`), "path-traversal")).toEqual([]);
    expect(lines("S.java", servlet(`    String name = term;\n    File f = new File("/data/" + name);`), "path-traversal")).toContain(L + 1);
  });
});
