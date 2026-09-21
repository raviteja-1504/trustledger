import { warmCSharpTaintEngine, parseCSharpSourceSync, scanAstTaintCSharp } from "@/lib/astTaintCSharp";

// Recall + precision for the C# AST engine: expression-bodied helpers, delegates/closures, static passthroughs,
// container writes, class-field memory, and the sinks/structural checks added with them.

beforeAll(async () => { await warmCSharpTaintEngine(); }, 30000);

function ids(content: string): string[] {
  const root = parseCSharpSourceSync(content, "A.cs");
  if (!root) throw new Error("parse failed");
  return scanAstTaintCSharp(content, "A.cs", root).map(f => f.id);
}
const has = (code: string, id: string) => ids(code).includes(id);

const HEAD = `using System; using System.Linq; using System.Net; using System.Text; using System.IO; using System.Diagnostics; using System.Collections.Generic;
using Microsoft.AspNetCore.Mvc;
`;
const cls = (members: string, attrs = "[ApiController]") => `${HEAD}${attrs}\npublic class C : ControllerBase {\n${members}\n}\n`;
const get = (body: string, params = `[FromQuery] string q`) => `[HttpGet("x")] public IActionResult A(${params}) { ${body} }`;
const post = (body: string, params = `[FromForm] string q`) => `[HttpPost("x")] public IActionResult A(${params}) { ${body} }`;

describe("helpers and propagation", () => {
  it("an expression-bodied helper carries taint to its caller", () => {
    const code = cls(`static string Norm(string v) => "http://h/" + v;\n${get(`return Redirect(Norm(q));`)}`);
    expect(has(code, "open-redirect")).toBe(true);
  });
  it("params string[] arguments propagate", () => {
    const code = cls(`static string J(string p, params string[] v) { return p + string.Join(",", v); }\n${get(`return Content("<b>" + J("k", q, q) + "</b>", "text/html");`)}`);
    expect(has(code, "xss")).toBe(true);
  });
  it("a callback applied to the value carries taint through a higher-order helper", () => {
    const code = cls(`static string With(string v, Func<string, string> f) { return f(v); }\n${get(`return Content(With(q, x => "<i>" + x + "</i>"), "text/html");`)}`);
    expect(has(code, "xss")).toBe(true);
  });
  it("a closure built from the value and called later carries it", () => {
    const code = cls(`static Func<string> Later(string v) { return () => v; }\n${get(`var r = Later(q); return Content(r(), "text/html");`)}`);
    expect(has(code, "xss")).toBe(true);
  });
  it("await of a helper task keeps taint", () => {
    const code = cls(`static async System.Threading.Tasks.Task<string> Mk(string id) { return await System.Threading.Tasks.Task.FromResult("SELECT * FROM t WHERE i = '" + id + "'"); }
      string Run(string s) { return new System.Data.SqlClient.SqlCommand(s).ExecuteScalar()?.ToString(); }
      [HttpGet("x")] public async System.Threading.Tasks.Task<IActionResult> A([FromQuery] string id) { var s = await Mk(id); return Ok(Run(s)); }`);
    expect(has(code, "sql-injection")).toBe(true);
  });
  it("double URL-decoding re-taints", () => {
    const code = cls(`${get(`var f = WebUtility.UrlDecode(WebUtility.UrlDecode(q)); return Ok(System.IO.File.ReadAllText(Path.Combine("/srv", f)));`)}`);
    expect(has(code, "path-traversal")).toBe(true);
  });
  it("encode-then-decode brings HTML danger back", () => {
    const code = cls(get(`var d = Uri.UnescapeDataString(Uri.EscapeDataString(q)); return Content("<div>" + d + "</div>", "text/html");`));
    expect(has(code, "xss")).toBe(true);
  });
});

describe("containers, fields and second-order flows", () => {
  it("static dictionary written by one action and read by another (second-order SQLi)", () => {
    const code = cls(`static readonly Dictionary<string, string> Saved = new Dictionary<string, string>();
      string Run(string s) { return new System.Data.SqlClient.SqlCommand(s).ExecuteScalar()?.ToString(); }
      [HttpPost("s")] public IActionResult S([FromForm] string u, [FromForm] string v) { Saved[u] = v; return Ok(); }
      [HttpGet("r")] public IActionResult R([FromQuery] string u) { var t = Saved[u]; return Ok(Run("SELECT * FROM t WHERE n = '" + t + "'")); }`);
    expect(has(code, "sql-injection")).toBe(true);
  });
  it("stored XSS through a static list and a StringBuilder", () => {
    const code = cls(`static readonly List<string> Comments = new List<string>();
      [HttpPost("s")] public IActionResult S([FromForm] string c) { Comments.Add(c); return Ok(); }
      [HttpGet("r")] public IActionResult R() { var sb = new StringBuilder(); foreach (var c in Comments) sb.Append("<li>" + c + "</li>"); return Content(sb.ToString(), "text/html"); }`);
    expect(has(code, "xss")).toBe(true);
  });
  it("an object initializer's values are part of the object", () => {
    const code = cls(`class T { public string Bin; public string Arg; }
      static string Go(T t) { return Process.Start(t.Bin, t.Arg).StandardOutput.ReadToEnd(); }
      ${post(`return Ok(Go(new T { Bin = q, Arg = "x" }));`)}`);
    expect(has(code, "command-injection")).toBe(true);
  });
  it("a local with the same name as a tainted field does not inherit the field's taint", () => {
    const code = cls(`static readonly List<string> Items = new List<string>();
      [HttpPost("s")] public IActionResult S([FromForm] string c) { Items.Add(c); return Ok(); }
      [HttpGet("r")] public IActionResult R() { var Items = new List<string> { "a" }; return Content("<b>" + string.Join(",", Items) + "</b>", "text/html"); }`);
    expect(has(code, "xss")).toBe(false);
  });
});

describe("new sinks", () => {
  it.each([
    ["header via indexer", get(`Response.Headers["X-A"] = "v=" + q; return Ok();`), "header-injection"],
    ["header via Add", get(`Response.Headers.Add("X-A", q); return Ok();`), "header-injection"],
    ["ReDoS static", get(`return Ok(System.Text.RegularExpressions.Regex.IsMatch("abc", q));`), "redos"],
    ["ReDoS ctor", get(`return Ok(new System.Text.RegularExpressions.Regex(q).IsMatch("abc"));`), "redos"],
    ["assembly load", get(`return Ok(System.Reflection.Assembly.Load(q).GetTypes().Length);`), "eval-exec"],
    ["Type.GetType", get(`return Ok(Type.GetType(q));`), "eval-exec"],
    ["script eval", get(`return Ok(Microsoft.CodeAnalysis.CSharp.Scripting.CSharpScript.EvaluateAsync(q));`), "eval-exec"],
    ["reflection setter", get(`var o = new object(); typeof(C).GetProperty(q).SetValue(o, "x"); return Ok(o);`), "mass-assignment"],
    ["Mongo raw filter", get(`return Ok(coll.Find(q));`), "nosql-injection"],
    ["template parse", get(`return Content(Scriban.Template.Parse(q).Render(), "text/html");`), "ssti"],
    ["LDAP filter concat", get(`var f = "(&(objectClass=person)(uid=" + q + "))"; return Ok(f);`), "ldap-injection"],
    ["XPath concat", get(`var d = new System.Xml.XmlDocument(); return Ok(d.SelectNodes("/u/x[n='" + q + "']"));`), "xpath-injection"],
    ["SQL concat", get(`var s = "SELECT * FROM t WHERE a = '" + q + "'"; return Ok(s);`), "sql-injection"],
    ["SQL interpolation", get(`var s = $"SELECT * FROM t WHERE a = '{q}'"; return Ok(s);`), "sql-injection"],
    ["SQL string.Format", get(`var s = string.Format("SELECT * FROM t WHERE a = '{0}'", q); return Ok(s);`), "sql-injection"],
    ["CommandText property", get(`var c = new System.Data.SqlClient.SqlCommand(); c.CommandText = "SELECT " + q; return Ok(c);`), "sql-injection"],
    ["WebClient SSRF (chained ctor)", get(`return Ok(new WebClient().DownloadString(q));`), "ssrf"],
    ["TypeNameHandling", get(`return Ok(Newtonsoft.Json.JsonConvert.DeserializeObject(q, new Newtonsoft.Json.JsonSerializerSettings { TypeNameHandling = Newtonsoft.Json.TypeNameHandling.All }));`), "insecure-deserialization"],
    ["FileStream path", get(`return Ok(new FileStream(q, FileMode.Open));`), "path-traversal"],
  ])("%s", (_l, member, id) => {
    expect(has(cls(`dynamic coll = null;\n${member}`), id)).toBe(true);
  });
  it("HTML-encoding a value that lands inside a <script> block is still XSS", () => {
    expect(has(cls(get(`var v = System.Web.HttpUtility.HtmlEncode(q); return Content($"<script>var x = '{v}';</script>", "text/html");`)), "xss")).toBe(true);
  });
  it("an untrusted value compared to a stored secret with == is a timing leak", () => {
    expect(has(cls(`const string AppSecret = "s";\n${get(`if (q == AppSecret) return Ok(); return Unauthorized();`)}`), "timing-attack")).toBe(true);
  });
  it("copying every entry of a request-supplied map is mass assignment", () => {
    const code = cls(`static Dictionary<string, object> Merge(Dictionary<string, object> t, Dictionary<string, object> s) { foreach (var kv in s) { t[kv.Key] = kv.Value; } return t; }
      [HttpPost("m")] public IActionResult M([FromBody] Dictionary<string, object> input) { return Ok(Merge(new Dictionary<string, object>(), input)); }`);
    expect(has(code, "mass-assignment")).toBe(true);
  });
  it("binding a request body onto a model with privileged properties is mass assignment", () => {
    const code = cls(`public class Acct { public string Email { get; set; } public bool IsAdmin { get; set; } }
      [HttpPost("a")] public IActionResult A([FromBody] Acct a) { return Ok(a); }`);
    expect(has(code, "mass-assignment")).toBe(true);
  });
  it("hand-rolled JWT decoding without a signature check", () => {
    const code = cls(get(`var parts = q.Split('.'); var p = Encoding.UTF8.GetString(Convert.FromBase64String(parts[1])); return Ok(p);`));
    expect(has(code, "jwt-none-alg")).toBe(true);
  });
});

describe("precision", () => {
  it("a numeric parse neutralizes SQL injection", () => {
    expect(has(cls(get(`var s = "SELECT * FROM t WHERE id = " + int.Parse(q); return Ok(s);`)), "sql-injection")).toBe(false);
  });
  it("bound SqlParameters are not injection", () => {
    const code = cls(get(`var c = new System.Data.SqlClient.SqlCommand("SELECT * FROM t WHERE a = @a"); c.Parameters.Add(new System.Data.SqlClient.SqlParameter("@a", q)); return Ok(c.ExecuteScalar());`));
    expect(has(code, "sql-injection")).toBe(false);
  });
  it("a constant header value is fine", () => {
    expect(has(cls(get(`Response.Headers["X-A"] = "1"; return Ok(q.Length);`)), "header-injection")).toBe(false);
  });
  it("HTML-encoded value in an HTML body context is not XSS", () => {
    expect(has(cls(get(`return Content("<div>" + System.Web.HttpUtility.HtmlEncode(q) + "</div>", "text/html");`)), "xss")).toBe(false);
  });
  it("Regex.Escape on the pattern is not ReDoS", () => {
    expect(has(cls(get(`return Ok(System.Text.RegularExpressions.Regex.IsMatch("abc", System.Text.RegularExpressions.Regex.Escape(q)));`)), "redos")).toBe(false);
  });
  it("reading the request body as a stream is not a path traversal", () => {
    expect(has(cls(post(`var r = new StreamReader(Request.Body); return Ok(r.ReadToEnd().Length);`)), "path-traversal")).toBe(false);
  });
  it("comparing two request values is not a secret compare", () => {
    expect(has(cls(post(`if (q == password) return Ok(); return Forbid();`, `[FromForm] string q, [FromForm] string password`)), "timing-attack")).toBe(false);
  });
  it("a literal allowlist guard clears the value", () => {
    const code = cls(`static readonly string[] Ok2 = new[] { "a", "b" };\n${get(`if (!Ok2.Contains(q)) return BadRequest(); return Content("<b>" + q + "</b>", "text/html");`)}`);
    expect(has(code, "xss")).toBe(false);
  });
  it("a DTO without privileged properties is not mass assignment", () => {
    const code = cls(`public class Dto { public string Email { get; set; } public string Name { get; set; } }
      [HttpPost("a")] public IActionResult A([FromBody] Dto a) { return Ok(a); }`);
    expect(has(code, "mass-assignment")).toBe(false);
  });
  it("[BindNever] on the privileged property is respected", () => {
    const code = cls(`public class Acct { public string Email { get; set; } [BindNever] public bool IsAdmin { get; set; } }
      [HttpPost("a")] public IActionResult A([FromBody] Acct a) { return Ok(a); }`);
    expect(has(code, "mass-assignment")).toBe(false);
  });
  it("token validated with the JWT handler is not a manual decode", () => {
    const code = cls(get(`var parts = q.Split('.'); new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler().ValidateToken(q, null, out _); var p = Convert.FromBase64String(parts[1]); return Ok(p);`));
    expect(has(code, "jwt-none-alg")).toBe(false);
  });
  it("an opaque unknown call does not carry taint", () => {
    expect(has(cls(get(`var s = Mystery(q); return Content("<b>" + s + "</b>", "text/html");`)), "xss")).toBe(false);
  });
  it("a request-independent method has no findings", () => {
    expect(ids(cls(`[HttpGet("x")] public IActionResult A() { var s = "SELECT 1"; return Content("<b>" + s + "</b>", "text/html"); }`))).toEqual([]);
  });
});
