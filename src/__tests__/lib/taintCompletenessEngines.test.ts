import { scanAstTaintPython, warmPythonTaintEngine, parsePythonSourceSync } from "@/lib/astTaintPython";
import { parseJavaSource, scanAstTaintJava } from "@/lib/astTaintJava";
import { scanAstTaintGo, warmGoTaintEngine, parseGoSourceSync } from "@/lib/astTaintGo";
import { scanAstTaintCSharp, warmCSharpTaintEngine, parseCSharpSourceSync } from "@/lib/astTaintCSharp";

// Completeness gaps found by measuring recall against PyGoat, crAPI and WebGoat (known-vulnerable apps), plus
// the framework idioms those corpora don't cover for Go and C#. Each case is the real-world shape that was
// missed, misattributed, or wrongly flagged.

beforeAll(async () => {
  await warmPythonTaintEngine(); await warmGoTaintEngine(); await warmCSharpTaintEngine();
}, 60000);

const py = (src: string) => scanAstTaintPython(src, "v.py", parsePythonSourceSync(src, "v.py")!).map(f => `${f.id}@${f.line}`);
const java = (body: string) => {
  const src = `import org.springframework.web.bind.annotation.*;\n@RestController\npublic class C {\n${body}\n}\n`;
  return scanAstTaintJava(src, "C.java", parseJavaSource(src)!, undefined, { entryPoints: false });
};
const go = (body: string) => {
  const src = `package main\n${body}\n`;
  return scanAstTaintGo(src, "m.go", parseGoSourceSync(src, "m.go")!).map(f => `${f.id}@${f.line}`);
};
const CS_HEAD = `using System; using Microsoft.AspNetCore.Mvc; using Microsoft.EntityFrameworkCore;\n`;
const cs = (src: string) => scanAstTaintCSharp(src, "C.cs", parseCSharpSourceSync(src, "C.cs")!).map(f => `${f.id}@${f.line}`);
const ctl = (members: string) => `${CS_HEAD}[ApiController]\npublic class C : ControllerBase {\n${members}\n}\n`;

describe("Python (Django/Flask) framework modeling", () => {
  it("request.COOKIES and request.FILES are request input", () => {
    expect(py(`import pickle\ndef v(request):\n    admin = pickle.loads(request.COOKIES.get('token'))\n`)).toEqual(["insecure-deserialization@3"]);
    expect(py(`import yaml\ndef v(request):\n    f = request.FILES["file"]\n    data = yaml.load(f, yaml.Loader)\n`)).toEqual(["insecure-deserialization@4"]);
  });
  it("re.sub carries taint (it reshapes a string, it doesn't validate it)", () => {
    expect(py(`import re, subprocess\ndef v(request):\n    d = request.POST.get('domain')\n    d = re.sub(r'^x', '', d)\n    subprocess.Popen("dig {}".format(d), shell=True)\n`)).toEqual(["command-injection@5"]);
  });
  it("PIL ImageMath.eval evaluates its argument as code", () => {
    expect(py(`from PIL import ImageMath\ndef v(request):\n    out = ImageMath.eval(request.POST.get("function"), a=1)\n`)).toEqual(["eval-exec@3"]);
  });
});

describe("Java", () => {
  it("a finding names the tainted operand, not the leftmost token of the argument", () => {
    const f = java(`@PostMapping("/x") public void a(@RequestParam String u) {\n statement.executeQuery("SELECT * FROM t WHERE a = '" + u + "'");\n}`);
    expect(f.map(x => `${x.id}:${x.sourceExpr}`)).toEqual(["sql-injection:u"]);
  });
  it("source text keeps the spacing of the original code", () => {
    const f = java(`@PostMapping("/x") public void a(@RequestParam String t) throws Exception {\n var p = new JwkProviderBuilder(new URL(t)).build();\n}`);
    expect(f[0]?.sourceExpr).toBe("new URL(t)");
  });
  it("a reference cast keeps taint; a primitive cast clears it", () => {
    expect(java(`@PostMapping("/x") public void a(@RequestParam String q) {\n Object o = q;\n String s = (String) o;\n statement.executeQuery("SELECT * FROM t WHERE a = '" + s + "'");\n}`).map(x => x.id)).toEqual(["sql-injection"]);
    expect(java(`@PostMapping("/x") public void a(@RequestParam double q) {\n int n = (int) q;\n statement.executeQuery("SELECT * FROM t WHERE a = " + n);\n}`)).toEqual([]);
  });
  it("SSRF through a URL held in a variable, and through a JWKS provider fed from the token's jku header", () => {
    expect(java(`@PostMapping("/x") public void a(@RequestParam String u) throws Exception {\n URL url = new URL(u);\n url.openConnection();\n}`).map(x => `${x.id}@${x.line}`)).toEqual(["ssrf@6"]);
    expect(java(`@PostMapping("/x") public void a(@RequestParam String token) throws Exception {\n var jku = JWT.decode(token).getHeaderClaim("jku");\n new JwkProviderBuilder(new URL(jku.asString())).build();\n}`).map(x => x.id)).toEqual(["ssrf"]);
    expect(java(`@PostMapping("/x") public void a(@RequestParam String u) throws Exception {\n URL url = new URL("https://example.com");\n url.openConnection();\n}`)).toEqual([]);
  });
  it("jjwt key-resolver callbacks receive the UNVERIFIED token's header (the `kid` injection)", () => {
    expect(java(`@PostMapping("/x") public void a(@RequestParam String token) {\n Jwts.parser().setSigningKeyResolver(new SigningKeyResolverAdapter() {\n  @Override public byte[] resolveSigningKeyBytes(JwsHeader header, Claims claims) {\n   final String kid = (String) header.get("kid");\n   connection.createStatement().executeQuery("SELECT key FROM jwt_keys WHERE id = '" + kid + "'");\n   return null;\n  }\n }).parseClaimsJws(token);\n}`).map(x => `${x.id}@${x.line}`)).toEqual(["sql-injection@8"]);
    expect(java(`public void other(JwsHeader header) {\n statement.executeQuery("SELECT * FROM t WHERE a = '" + header.getKeyId() + "'");\n}`)).toEqual([]);
  });
});

describe("Go web-framework sinks on the handler context", () => {
  it("echo/gin File and FileAttachment serve a path; Redirect sends the user elsewhere", () => {
    expect(go(`func h(c echo.Context) error {\n p := c.Param("file")\n return c.File("/data/" + p)\n}`)).toEqual(["path-traversal@4"]);
    expect(go(`func h(c *gin.Context) {\n c.Redirect(http.StatusFound, c.Query("next"))\n}`)).toEqual(["open-redirect@3"]);
  });
  it("a literal path, or a File method on something other than the context, is not a sink", () => {
    expect(go(`func h(c *gin.Context) {\n c.File("/data/report.pdf")\n}`)).toEqual([]);
    expect(go(`func h(c *gin.Context) {\n archive.File(c.Query("f"))\n}`)).toEqual([]);
  });
});

describe("C# / ASP.NET Core", () => {
  it("EF Core's FormattableString APIs parameterize an interpolated string passed directly", () => {
    expect(cs(ctl(`[HttpPost] public IActionResult A([FromQuery] string q) { db.Database.ExecuteSqlInterpolated($"DELETE FROM t WHERE a = {q}"); return Ok(); }`))).toEqual([]);
    expect(cs(ctl(`[HttpGet] public IActionResult A([FromQuery] string q) { var r = db.Database.SqlQuery<int>($"SELECT id FROM t WHERE a = {q}").ToList(); return Ok(); }`))).toEqual([]);
  });
  it("...but the same string assigned to a variable and passed to a Raw API is concatenated SQL", () => {
    expect(cs(ctl(`[HttpGet] public IActionResult A([FromQuery] string q) { string sql = $"SELECT id FROM t WHERE a = '{q}'"; db.Database.ExecuteSqlRaw(sql); return Ok(); }`))).toEqual(["sql-injection@4"]);
  });
  it("minimal API handler parameters bound from the request are sources (top-level Program.cs)", () => {
    expect(cs(`${CS_HEAD}var app = WebApplication.Create();\napp.MapGet("/x", (string q, AppDb db) => db.Users.FromSqlRaw("SELECT * FROM u WHERE n = '" + q + "'").ToList());\n`)).toEqual(["sql-injection@3"]);
    expect(cs(`${CS_HEAD}var app = WebApplication.Create();\napp.MapPost("/x", ([FromBody] Dto d, AppDb db) => db.Database.ExecuteSqlRaw("DELETE FROM t WHERE a = '" + d.Name + "'"));\n`)).toEqual(["sql-injection@3"]);
  });
  it("a dependency-injected service parameter is not a source", () => {
    expect(cs(`${CS_HEAD}var app = WebApplication.Create();\napp.MapGet("/x", (AppDb db) => db.Users.FromSqlRaw("SELECT * FROM u WHERE n = '" + db.DefaultName + "'").ToList());\n`)).toEqual([]);
  });
});
