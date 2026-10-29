/**
 * @jest-environment node
 *
 * Coverage found scoring the NIST SARD Juliet suite (Java, C#): a Java method another file of the batch calls is not
 * an unexplained entry point (its callers say what it receives); `(new Helper()).sink(x)` resolves to Helper's
 * parameter facts; a parameter typed `HttpRequest` is the request (System.Web); and a SQL text built only from
 * constants -- literals, locals only ever assigned literals, `.Split()` / indexing of those -- vetoes the regex layer.
 */
import { runScan } from "@/lib/scanner";
import { warmCSharpTaintEngine } from "@/lib/astTaintCSharp";

beforeAll(async () => { await warmCSharpTaintEngine(); }, 120000);

const scan = (files: Array<[string, string]>) =>
  runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files: files.map(([path, content]) => ({ path, content })) });
const ldap = (r: ReturnType<typeof scan>, file: string) =>
  r.files.find(f => f.file_path === file)!.indicators.filter(i => i.id === "ldap-injection").map(i => i.line);

const sinkClass = `import javax.naming.directory.*;
public class Finder {
    public void badSink(String data) throws Exception {
        DirContext ctx = new InitialDirContext();
        String search = "(cn=" + data + ")";
        ctx.search("", search, null);
    }
    public void goodSink(String data) throws Exception {
        DirContext ctx = new InitialDirContext();
        String search = "(cn=" + data + ")";
        ctx.search("", search, null);
    }
}
`;
const caller = (call: string) => `import javax.servlet.http.*;
public class Handler {
    public void bad(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String data = request.getParameter("name");
        ${call.replace(/SINK/g, "badSink").replace(/ARG/g, "data")}
    }
    public void good(HttpServletRequest request, HttpServletResponse response) throws Exception {
        String data = "foo";
        ${call.replace(/SINK/g, "goodSink").replace(/ARG/g, "data")}
    }
}
`;

describe("methods called from another file of the batch", () => {
  it("(new C()).m(x) reports at the caller with tainted input, not inside C for both callers", () => {
    const r = scan([["Finder.java", sinkClass], ["Handler.java", caller("(new Finder()).SINK(ARG);")]]);
    expect(ldap(r, "Handler.java")).toEqual([5]);
    expect(ldap(r, "Finder.java")).toEqual([]);
  });
  it("a variable bound to new C()", () => {
    const r = scan([["Finder.java", sinkClass], ["Handler.java", caller("Finder f = new Finder(); f.SINK(ARG);")]]);
    expect(ldap(r, "Handler.java")).toEqual([5]);
    expect(ldap(r, "Finder.java")).toEqual([]);
  });
  it("with no caller in the batch, a public method's String parameters are still assumed untrusted", () => {
    const r = scan([["Finder.java", sinkClass]]);
    expect(ldap(r, "Finder.java").sort((a, b) => (a ?? 0) - (b ?? 0))).toEqual([6, 11]);
  });
});

const sqlIn = (r: ReturnType<typeof scan>, file: string) =>
  r.files.find(f => f.file_path === file)!.indicators.filter(i => i.id === "sql-injection").map(i => `${i.line}${i.sourceExpr ? "*" : ""}`);

describe("C# System.Web request parameters", () => {
  const cs = (decl: string, read: string) => `using System.Web;\nusing System.Diagnostics;\nclass C : AbstractTestCaseWeb\n{\n    public override void Bad(${decl}, HttpResponse resp)\n    {\n        string data = ${read};\n        Process.Start("/bin/ls " + data);\n    }\n}\n`;
  const cmd = (code: string) => scan([["C.cs", code]]).files[0].indicators.some(i => i.id === "command-injection" && !!i.sourceExpr);
  it("QueryString / Params / Form / Cookies on a parameter typed HttpRequest", () => {
    expect(cmd(cs("HttpRequest req", `req.QueryString["id"]`))).toBe(true);
    expect(cmd(cs("HttpRequestBase request", `request.Params["id"]`))).toBe(true);
    expect(cmd(cs("HttpRequest req", `req.Form["id"]`))).toBe(true);
    expect(cmd(cs("HttpRequest req", `req.Cookies["id"].Value`))).toBe(true);
  });
  it("not the same members on something that isn't a request", () => {
    expect(cmd(cs("Settings req", `req.QueryString["id"]`))).toBe(false);
    expect(cmd(cs("HttpRequest req", `other.QueryString["id"]`))).toBe(false);
  });
});

describe("SQL built only from constants vetoes the line rule", () => {
  it("C#: a literal local, its Split() and its elements", () => {
    const cs = (body: string) => `using System.Web;\nusing System.Data.SqlClient;\nclass C : AbstractTestCaseWeb\n{\n    private void GoodG2B(HttpRequest req, HttpResponse resp)\n    {\n        string data;\n${body}\n    }\n}\n`;
    const lines = (body: string) => sqlIn(scan([["C.cs", cs(body)]]), "C.cs");
    expect(lines(`        data = "foo";\n        SqlCommand cmd = null;\n        cmd.CommandText = "select * from u where n='" + data + "'";`)).toEqual([]);
    expect(lines(`        data = "foo";\n        string[] names = data.Split('-');\n        SqlCommand cmd = null;\n        cmd.CommandText += "update u set n=1 where n='" + names[0] + "';";`)).toEqual([]);
    // one non-constant assignment and it is not proven
    expect(lines(`        data = "foo";\n        data = System.Environment.GetEnvironmentVariable("X");\n        SqlCommand cmd = null;\n        cmd.CommandText = "select * from u where n='" + data + "'";`)).toEqual(["11"]);
  });
  it("Java: a local only ever assigned a literal; not a parameter", () => {
    const java = (sig: string, body: string) => `import java.sql.*;\npublic class Q {\n    private void goodG2B(${sig}) throws Exception {\n${body}\n        Statement s = IO.getDBConnection().createStatement();\n        s.executeQuery("select * from users where name='" + data + "'");\n    }\n}\n`;
    expect(sqlIn(scan([["Q.java", java("", `        String data;\n        data = "foo";`)]]), "Q.java")).toEqual([]);
    expect(sqlIn(scan([["Q.java", java("String data", "")]]), "Q.java").length).toBe(1);
  });
  it("Java: a dead null arm, split() and its elements, through addBatch", () => {
    const java = (assign: string) => `import java.sql.*;\npublic class Q {\n    private void goodG2B() throws Exception {\n        String data;\n        if (false) { data = null; } else { ${assign} }\n        String names[] = data.split("-");\n        Statement s = IO.getDBConnection().createStatement();\n        for (int i = 0; i < names.length; i++) {\n            s.addBatch("update users set hitcount=hitcount+1 where name='" + names[i] + "'");\n        }\n    }\n}\n`;
    expect(sqlIn(scan([["Q.java", java(`data = "foo";`)]]), "Q.java")).toEqual([]);
    expect(sqlIn(scan([["Q.java", java(`data = System.getenv("X");`)]]), "Q.java").length).toBe(1);
  });
  it("C#: a dead null arm", () => {
    const cs = `using System.Web;\nusing System.Data.SqlClient;\nclass C : AbstractTestCaseWeb\n{\n    private void GoodG2B(HttpRequest req, HttpResponse resp)\n    {\n        string data;\n        if (false) { data = null; } else { data = "foo"; }\n        SqlCommand cmd = null;\n        cmd.CommandText = "select * from u where n='" + data + "'";\n    }\n}\n`;
    expect(sqlIn(scan([["C.cs", cs]]), "C.cs")).toEqual([]);
  });
});

describe("C# log injection", () => {
  const cs = (stmt: string) => `using System.Web;\nclass C : AbstractTestCaseWeb\n{\n    public override void Bad(HttpRequest req, HttpResponse resp)\n    {\n        string data = req.Params.Get("name");\n        ${stmt}\n    }\n}\n`;
  const log = (stmt: string) => scan([["C.cs", cs(stmt)]]).files[0].indicators.some(i => i.id === "log-injection" && !!i.sourceExpr);
  it("request input written by NLog / Microsoft.Extensions.Logging / Serilog", () => {
    expect(log(`IO.Logger.Log(NLog.LogLevel.Warn, null, "Failed to parse value = " + data);`)).toBe(true);
    expect(log(`_logger.LogWarning("Login failed for " + data);`)).toBe(true);
    expect(log(`Log.Information("user {Name}", data);`)).toBe(true);
  });
  it("not a constant, not structured context, not a non-logger", () => {
    expect(log(`_logger.LogWarning("Login failed");`)).toBe(false);
    expect(log(`_logger.LogWarning("Login failed", new { data });`)).toBe(false);
    expect(log(`cache.Warn(data);`)).toBe(false);
    expect(log(`_logger.LogWarning("Failed: " + int.Parse(data));`)).toBe(false);
  });
});

describe("C# System.Web response sinks, code generation and reflection", () => {
  const cs = (body: string) => `using System.Web;\nclass C : AbstractTestCaseWeb\n{\n    public override void Bad(HttpRequest req, HttpResponse resp)\n    {\n        string data = req.Params.Get("name");\n${body}\n    }\n}\n`;
  const ids = (body: string) => scan([["C.cs", cs(body)]]).files[0].indicators.filter(i => !!i.sourceExpr).map(i => i.id);
  it("resp.Write / StatusDescription (XSS), AddHeader / new HttpCookie (header splitting)", () => {
    expect(ids(`        resp.Write("<br>data = " + data);`)).toContain("xss");
    expect(ids(`        resp.StatusDescription = "<br>value " + data;`)).toContain("xss");
    expect(ids(`        resp.AddHeader("Location", "/author.jsp?lang=" + data);`)).toContain("header-injection");
    expect(ids(`        HttpCookie c = new HttpCookie("lang", data);\n        resp.AppendCookie(c);`)).toContain("header-injection");
    expect(ids(`        resp.Write("<br>constant");`)).not.toContain("xss");
    expect(ids(`        other.Write(data);`)).not.toContain("xss");
  });
  it("CompileAssemblyFromSource and Activator.CreateInstance(assembly, typeName)", () => {
    expect(ids(`        var provider = CodeDomProvider.CreateProvider("CSharp");\n        var cr = provider.CompileAssemblyFromSource(new CompilerParameters(), "class X { int Y = " + data + "; }");`)).toContain("eval-exec");
    expect(ids(`        var container = Activator.CreateInstance(null, data);`)).toContain("eval-exec");
    expect(ids(`        var container = Activator.CreateInstance(null, "Testing.test");`)).not.toContain("eval-exec");
  });
});

describe("Java network input", () => {
  const java = (decl: string, read: string) => `import java.io.*;\nimport java.net.*;\npublic class N {\n    public void bad() throws Exception {\n        ${decl}\n        BufferedReader r = new BufferedReader(new InputStreamReader(${read}.getInputStream(), "UTF-8"));\n        String data = r.readLine();\n        Runtime.getRuntime().exec("ls " + data);\n    }\n}\n`;
  const cmd = (code: string) => scan([["N.java", code]]).files[0].indicators.some(i => i.id === "command-injection" && !!i.sourceExpr);
  it("Socket / URLConnection input streams are request-like input", () => {
    expect(cmd(java(`Socket socket = new Socket("host.example.org", 39544);`, "socket"))).toBe(true);
    expect(cmd(java(`URLConnection urlConnection = (new URL("http://www.example.org/")).openConnection();`, "urlConnection"))).toBe(true);
    expect(cmd(java(`Process proc = Runtime.getRuntime().exec("id");`, "proc"))).toBe(false);
  });
});

describe("cross-file facts of several kinds at one call", () => {
  it("a callee that both logs and renders its parameter reports both at the caller", () => {
    const svc = `import javax.servlet.http.*;\npublic class Svc {\n    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(Svc.class);\n    public void greet(String name, HttpServletResponse response) throws Exception {\n        log.info("greeting " + name);\n        response.getWriter().println("<p>" + name + "</p>");\n    }\n}\n`;
    const ctl = `import javax.servlet.http.*;\npublic class Ctl extends HttpServlet {\n    private Svc svc = new Svc();\n    public void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {\n        String n = request.getParameter("n");\n        svc.greet(n, response);\n    }\n}\n`;
    const r = scan([["Svc.java", svc], ["Ctl.java", ctl]]);
    const at = r.files.find(f => f.file_path === "Ctl.java")!.indicators.filter(i => i.line === 6 && !!i.sourceExpr).map(i => i.id).sort();
    expect(at).toEqual(["log-injection", "xss"]);
  });
});
