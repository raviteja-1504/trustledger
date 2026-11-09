/**
 * @jest-environment node
 *
 * C# AST taint engine accuracy: method identity (overloads, same-name methods in different classes, named / optional
 * arguments), scoped type environments, path construction vs filesystem access, reflection lookup vs invocation,
 * per-method JWT evidence, BOLA ownership, soundness of proof-based suppression, finding identity, cross-file
 * namespace identity.
 */
import { analyzeFile, runScan } from "@/lib/scanner";
import type { ScanIndicator } from "@/lib/scanner";
import { warmCSharpTaintEngine, parseCSharpSourceSync, scanAstTaintCSharp } from "@/lib/astTaintCSharp";

beforeAll(async () => { await warmCSharpTaintEngine(); }, 120000);

const USING = `using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Data.SqlClient;
using System.Diagnostics;
using System.Collections.Generic;
using Microsoft.AspNetCore.Mvc;
`;
/** Findings from the data-flow engine itself (it sets sourceExpr), not the line-pattern layer. */
const ast = (code: string, path = "Controllers/C.cs"): ScanIndicator[] => analyzeFile(path, code).indicators.filter(i => !!i.sourceExpr);
const has = (code: string, id: string) => ast(code).some(i => i.id === id);
/** every indicator (engine + line-pattern layer) -- for suppression tests, where the regex layer's veto is the point */
const anyHas = (code: string, id: string) => analyzeFile("Controllers/C.cs", code).indicators.some(i => i.id === id);

const controller = (members: string, extra = "") => `${USING}${extra}
[ApiController]
public class C : ControllerBase
{
${members}
}
`;
const action = (body: string, params = "string input", extra = "") => controller(`  [HttpGet("x")]\n  public IActionResult F(${params})\n  {\n${body}\n    return Ok();\n  }`, extra);

describe("method identity", () => {
  const ov = (call: string) => controller(`  private void Run(string cmd) { }\n  private void Run(string cmd, int n) { Process.Start(cmd); }\n  [HttpGet("x")]\n  public IActionResult F(string input)\n  {\n    ${call}\n    return Ok();\n  }`);
  it("overloads: only the overload that reaches the sink is dangerous", () => {
    expect(has(ov("Run(input, 1);"), "command-injection")).toBe(true);
    expect(has(ov("Run(input);"), "command-injection")).toBe(false);
  });
  it("same-named methods in different classes are separate", () => {
    const code = (recv: string) => `${USING}
public class Safe { public void Run(string c) { var n = c.Length; } }
public class Danger { public void Run(string c) { Process.Start(c); } }
[ApiController]
public class C : ControllerBase
{
  [HttpGet("x")]
  public IActionResult F(string input)
  {
    ${recv}.Run(input);
    return Ok();
  }
}
`;
    expect(has(code("new Safe()"), "command-injection")).toBe(false);
    expect(has(code("new Danger()"), "command-injection")).toBe(true);
    expect(has(code("Danger d = new Danger(); d"), "command-injection")).toBe(true);
  });
  it("named arguments bind by name, whatever their order", () => {
    const def = `  private void Run(string label, string cmd) { Process.Start(cmd); }\n`;
    const call = (c: string) => controller(`${def}  [HttpGet("x")]\n  public IActionResult F(string input)\n  {\n    ${c}\n    return Ok();\n  }`);
    expect(has(call(`Run(cmd: input, label: "x");`), "command-injection")).toBe(true);
    expect(has(call(`Run(label: input, cmd: "ls");`), "command-injection")).toBe(false);
  });
  it("an optional parameter the call leaves out is the callee's own constant", () => {
    const def = `  private void Run(string label, string cmd = "ls") { Process.Start(cmd); }\n`;
    const call = (c: string) => controller(`${def}  [HttpGet("x")]\n  public IActionResult F(string input)\n  {\n    ${c}\n    return Ok();\n  }`);
    expect(has(call(`Run(input);`), "command-injection")).toBe(false);
    expect(has(call(`Run("x", input);`), "command-injection")).toBe(true);
  });
  it("a return summary belongs to one overload", () => {
    const def = `  private string Pick(string a) { return "ls"; }\n  private string Pick(string a, string b) { return b; }\n`;
    const call = (c: string) => controller(`${def}  [HttpGet("x")]\n  public IActionResult F(string input)\n  {\n    Process.Start(${c});\n    return Ok();\n  }`);
    expect(has(call(`Pick("x", input)`), "command-injection")).toBe(true);
    expect(has(call(`Pick(input)`), "command-injection")).toBe(false);
  });
  it("a params array takes every trailing argument", () => {
    const def = `  private void Run(params string[] parts) { Process.Start(string.Join(" ", parts)); }\n`;
    expect(has(controller(`${def}  [HttpGet("x")]\n  public IActionResult F(string input)\n  {\n    Run("a", input);\n    return Ok();\n  }`), "command-injection")).toBe(true);
  });
});

describe("scoped type environments", () => {
  it("a field of the same name in another class does not lend its type", () => {
    const code = `${USING}
public class Cache { public void Execute(string k) { } }
public class Dao { private SqlConnection _db; public void Close() { _db.Close(); } }
[ApiController]
public class C : ControllerBase
{
  private Cache _db = new Cache();
  [HttpGet("x")]
  public IActionResult F(string input)
  {
    _db.Execute("k" + input);
    return Ok();
  }
}
`;
    expect(has(code, "sql-injection")).toBe(false);
  });
  it("a local of the same name in another method does not lend its type", () => {
    const code = `${USING}
public class Runner { public void ExecuteReader(string s) { } }
[ApiController]
public class C : ControllerBase
{
  private void Other() { var cmd = new SqlCommand("select 1"); cmd.ExecuteReader(); }
  [HttpGet("x")]
  public IActionResult F(string input)
  {
    var cmd = new Runner();
    cmd.ExecuteReader("x" + input);
    return Ok();
  }
}
`;
    expect(has(code, "sql-injection")).toBe(false);
  });
});

describe("path construction vs filesystem access", () => {
  it("Path.Combine / GetFullPath alone are not findings", () => {
    expect(has(action(`    var p = Path.Combine("/srv", input);`), "path-traversal")).toBe(false);
    expect(has(action(`    var p = Path.GetFullPath(Path.Combine("/srv", input));`), "path-traversal")).toBe(false);
  });
  it.each([
    ["File.ReadAllText", `File.ReadAllText(Path.Combine("/srv", input));`],
    ["File.OpenRead", `File.OpenRead(Path.Combine("/srv", input));`],
    ["File.Delete", `File.Delete(Path.Combine("/srv", input));`],
    ["Directory.GetFiles", `Directory.GetFiles(Path.Combine("/srv", input));`],
    ["new FileStream", `new FileStream(Path.Combine("/srv", input), FileMode.Open);`],
    ["File.WriteAllText", `File.WriteAllText(Path.Combine("/srv", input), "x");`],
  ])("a tainted path reaching %s is reported", (_n, call) => {
    expect(has(action(`    ${call}`), "path-traversal")).toBe(true);
  });
  it("a '..' check does not stop an absolute path", () => {
    expect(has(action(`    if (input.Contains("..")) return BadRequest();\n    File.ReadAllText(input);`), "path-traversal")).toBe(true);
  });
  it("GetFullPath followed by a directory-anchored StartsWith is containment; without the separator it is not", () => {
    const body = (prefix: string) => `    var full = Path.GetFullPath(Path.Combine("/srv/app/", input));\n    if (!full.StartsWith("${prefix}")) return BadRequest();\n    File.ReadAllText(full);`;
    expect(has(action(body("/srv/app/")), "path-traversal")).toBe(false);
    expect(has(action(body("/srv/app")), "path-traversal")).toBe(true);
  });
  it("a StartsWith check on a path that was not canonicalised proves nothing", () => {
    expect(has(action(`    var full = Path.Combine("/srv/app/", input);\n    if (!full.StartsWith("/srv/app/")) return BadRequest();\n    File.ReadAllText(full);`), "path-traversal")).toBe(true);
  });
});

describe("reflection: lookup is not execution or mutation", () => {
  const r = (body: string) => action(`    var t = typeof(C);\n${body}`);
  it("GetMethod / GetProperty / GetField / Type.GetType alone are not findings", () => {
    expect(has(r(`    var m = t.GetMethod(input);`), "eval-exec")).toBe(false);
    expect(has(r(`    var p = t.GetProperty(input);`), "mass-assignment")).toBe(false);
    expect(has(r(`    var f = t.GetField(input);`), "mass-assignment")).toBe(false);
    expect(has(r(`    var ty = Type.GetType(input);`), "eval-exec")).toBe(false);
  });
  it("invoking the looked-up method / instantiating the looked-up type is", () => {
    expect(has(r(`    var m = t.GetMethod(input);\n    m.Invoke(this, null);`), "eval-exec")).toBe(true);
    expect(has(r(`    t.GetMethod(input).Invoke(this, null);`), "eval-exec")).toBe(true);
    expect(has(r(`    var o = Activator.CreateInstance(Type.GetType(input));`), "eval-exec")).toBe(true);
  });
  it("invoking a method chosen by a constant is not", () => {
    expect(has(r(`    t.GetMethod("ToString").Invoke(this, null);`), "eval-exec")).toBe(false);
  });
  it("writing through an attacker-chosen property is mass assignment", () => {
    expect(has(r(`    var p = t.GetProperty(input);\n    p.SetValue(this, "x");`), "mass-assignment")).toBe(true);
    expect(has(r(`    t.GetProperty("Name").SetValue(this, "x");`), "mass-assignment")).toBe(false);
  });
});

describe("JWT evidence belongs to the method that holds it", () => {
  const code = (readBody: string) => `${USING}
using System.Text;
using System.IdentityModel.Tokens.Jwt;
[ApiController]
public class AuthController : ControllerBase
{
  [HttpGet("validate")]
  public IActionResult Validate(string token)
  {
    var h = new JwtSecurityTokenHandler();
    h.ValidateToken(token, new Microsoft.IdentityModel.Tokens.TokenValidationParameters(), out _);
    return Ok();
  }
  [HttpGet("claims")]
  public IActionResult Claims()
  {
${readBody}
    return Ok();
  }
}
`;
  const READ = `    var token = Request.Headers["Authorization"].ToString();
    var jwt = new JwtSecurityTokenHandler().ReadJwtToken(token);`;
  const DECODE = `    var token = Request.Headers["Authorization"].ToString();
    var parts = token.Split('.');
    var payload = Encoding.UTF8.GetString(Convert.FromBase64String(parts[1]));`;
  it("a validating method elsewhere in the file does not excuse reading an unvalidated token", () => {
    expect(has(code(READ), "jwt-none-alg")).toBe(true);
  });
  it("a validating method elsewhere in the file does not excuse a hand-rolled decode", () => {
    expect(has(code(DECODE), "jwt-none-alg")).toBe(true);
  });
  it("the method that validates is fine", () => {
    expect(has(code(`${READ}
    new JwtSecurityTokenHandler().ValidateToken(token, new Microsoft.IdentityModel.Tokens.TokenValidationParameters(), out _);`), "jwt-none-alg")).toBe(false);
  });
});

describe("BOLA: a role is not ownership", () => {
  const b = (params: string, body: string) => `${USING}
[ApiController]
[Authorize]
public class OrdersController : ControllerBase
{
  private readonly AppDb _db = null;
  [HttpGet("orders/{id}")]
  public IActionResult Get(${params})
  {
${body}
  }
}
`;
  const P = "[FromRoute] int id";
  const bola = (code: string) => has(code, "bola-missing-ownership-check");
  it("an unchecked lookup by route id is reported", () => {
    expect(bola(b(P, `    var o = _db.Orders.Find(id);\n    return Ok(o);`))).toBe(true);
  });
  it("comparing the owner with the authenticated user before use is safe", () => {
    expect(bola(b(P, `    var o = _db.Orders.Find(id);\n    if (o.OwnerId != User.Identity.Name) return Forbid();\n    return Ok(o);`))).toBe(false);
  });
  it("an IsInRole check is not ownership", () => {
    expect(bola(b(P, `    if (!User.IsInRole("Admin")) return Forbid();\n    var o = _db.Orders.Find(id);\n    return Ok(o);`))).toBe(true);
  });
  it("a check made after the data was returned protects nothing", () => {
    expect(bola(b(P, `    var o = _db.Orders.Find(id);\n    var r = Ok(o);\n    if (o.OwnerId != User.Identity.Name) return Forbid();\n    return r;`))).toBe(true);
  });
});

describe("proof-based suppression never treats unknown as safe", () => {
  // the line-pattern layer reports SQL built from a request value; the proof pass may veto it ONLY when the argument is
  // independent of input on every path
  const sql = (members: string, body: string) => `${USING}
public class Repo
{
${members}
  public void Run(string input, bool flag, SqlConnection conn)
  {
${body}
  }
}
`;
  const EXEC = `    new SqlCommand(q, conn).ExecuteReader();`;
  it("a constant on every path is proven safe", () => {
    expect(anyHas(sql("", `    string q = "SELECT 1";\n${EXEC}`), "sql-injection")).toBe(false);
  });
  it("a branch that assigns input on one path keeps the finding", () => {
    expect(anyHas(sql("", `    string q;\n    if (flag) q = "SELECT 1"; else q = "SELECT * FROM t WHERE n = '" + input + "'";\n${EXEC}`), "sql-injection")).toBe(true);
  });
  it("a loop that appends input keeps the finding", () => {
    expect(anyHas(sql("", `    var q = "SELECT * FROM t WHERE 1=1";\n    foreach (var part in input.Split(',')) { q += " AND n = '" + part + "'"; }\n${EXEC}`), "sql-injection")).toBe(true);
  });
  it("an exception path that reassigns from input keeps the finding", () => {
    expect(anyHas(sql("", `    string q = "SELECT 1";\n    try { int.Parse(input); } catch (Exception) { q = "SELECT * FROM t WHERE n = '" + input + "'"; }\n${EXEC}`), "sql-injection")).toBe(true);
  });
  it("a shadowing inner variable does not hide the outer tainted one", () => {
    expect(anyHas(sql("", `    var q = "SELECT * FROM t WHERE n = '" + input + "'";\n    { var other = "SELECT 1"; }\n${EXEC}`), "sql-injection")).toBe(true);
  });
  it("a constant reaching the sink through a field another method may write is not proven", () => {
    expect(anyHas(sql(`  private string _q = "SELECT 1";\n  public void Set(string v) { _q = "SELECT * FROM t WHERE n = '" + v + "'"; }`, `    new SqlCommand(_q, conn).ExecuteReader();`), "sql-injection")).toBe(true);
  });
  it("a public method that other code can call with anything is not proven by its own constant default", () => {
    expect(anyHas(sql("", `    var q = "SELECT * FROM t WHERE n = '" + input + "'";\n${EXEC}`), "sql-injection")).toBe(true);
  });
});

describe("finding identity", () => {
  it("two different flows on the same line are two findings", () => {
    const code = action(`    Process.Start(input); File.ReadAllText(input);`);
    const hits = ast(code);
    expect(hits.filter(i => i.id === "command-injection")).toHaveLength(1);
    expect(hits.filter(i => i.id === "path-traversal")).toHaveLength(1);
  });
  it("the same sink class fed by two different sources on one line is two flows in the engine and both are named in the record", () => {
    const code = action(`    Process.Start(input); Process.Start(Request.Query["b"]);`, "string input");
    const root = parseCSharpSourceSync(code, "Controllers/C.cs")!;
    expect(scanAstTaintCSharp(code, "Controllers/C.cs", root).filter(f => f.id === "command-injection").length).toBeGreaterThanOrEqual(2);
    const record = ast(code).find(i => i.id === "command-injection")!;
    expect(record.detail).toMatch(/same line, also/);
  });
  it("a finding names its source, sink and a trace", () => {
    const f = ast(action(`    Process.Start(input);`)).find(i => i.id === "command-injection")!;
    expect(f.sourceExpr).toBeTruthy();
    expect(f.sinkExpr).toBeTruthy();
    expect(f.trace![0].kind).toBe("source");
    expect(f.trace![f.trace!.length - 1].kind).toBe("sink");
  });
});

describe("cross-file resolution uses namespace identity", () => {
  type F = { path: string; content: string };
  const scan = (files: F[]) => runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files });
  const found = (files: F[], path: string, id: string) =>
    scan(files).files.find(f => f.file_path === path)!.indicators.filter(i => i.sourceExpr !== undefined && i.id === id);
  const svc = (ns: string, body: string): F => ({ path: `${ns.replace(/\./g, "/")}/Svc.cs`, content: `using System.Diagnostics;\nnamespace ${ns}\n{\n  public class Svc\n  {\n    public void Run(string c)\n    {\n      ${body}\n    }\n  }\n}\n` });
  const ctl = (usingNs: string): F => ({ path: "Web/Ctl.cs", content: `using Microsoft.AspNetCore.Mvc;\nusing ${usingNs};\nnamespace Web\n{\n  [ApiController]\n  public class Ctl : ControllerBase\n  {\n    private readonly Svc _svc = new Svc();\n    [HttpGet("x")]\n    public IActionResult F(string input)\n    {\n      _svc.Run(input);\n      return Ok();\n    }\n  }\n}\n` });
  it("two classes of the same name in different namespaces: the using picks one", () => {
    const files = (ns: string): F[] => [svc("A.Danger", "Process.Start(c);"), svc("B.Safe", "var n = c.Length;"), ctl(ns)];
    expect(found(files("A.Danger"), "Web/Ctl.cs", "command-injection").length).toBeGreaterThan(0);
    expect(found(files("B.Safe"), "Web/Ctl.cs", "command-injection")).toHaveLength(0);
  });
  it("an ambiguous simple name with no using is unknown, not a guess", () => {
    const files: F[] = [svc("A.Danger", "Process.Start(c);"), svc("B.Safe", "var n = c.Length;"), { ...ctl("System"), content: ctl("System").content }];
    expect(found(files, "Web/Ctl.cs", "command-injection")).toHaveLength(0);
  });
});

describe("parser coverage", () => {
  it("source that does not parse does not throw", () => {
    expect(() => analyzeFile("Controllers/Broken.cs", "public class Broken { void A( { }")).not.toThrow();
  });
});

describe("SQL: API resolution, bound parameters, helpers", () => {
  const ctl = (body: string) => action(body, "string input");
  it("string concatenation into SqlCommand text", () => {
    expect(has(ctl(`    var c = new SqlCommand("SELECT * FROM t WHERE n = '" + input + "'", new SqlConnection());\n    c.ExecuteReader();`), "sql-injection")).toBe(true);
  });
  it("a bound parameter is safe", () => {
    expect(has(ctl(`    var c = new SqlCommand("SELECT * FROM t WHERE n = @n", new SqlConnection());\n    c.Parameters.AddWithValue("@n", input);\n    c.ExecuteReader();`), "sql-injection")).toBe(false);
  });
  it("a parameter value in the SQL text AND bound is still injectable through the text", () => {
    expect(has(ctl(`    var c = new SqlCommand("SELECT * FROM " + input + " WHERE n = @n", new SqlConnection());\n    c.Parameters.AddWithValue("@n", "x");\n    c.ExecuteReader();`), "sql-injection")).toBe(true);
  });
  it("EF Core FromSqlRaw with concatenation, but not the interpolated (parameterised) form", () => {
    expect(has(ctl(`    var r = db.Users.FromSqlRaw("SELECT * FROM Users WHERE Name = '" + input + "'");`), "sql-injection")).toBe(true);
    expect(has(ctl(`    var r = db.Users.FromSqlInterpolated($"SELECT * FROM Users WHERE Name = {input}");`), "sql-injection")).toBe(false);
  });
  it("Dapper Query with concatenation versus a parameter object", () => {
    expect(has(ctl(`    var conn = new SqlConnection();\n    conn.Query("SELECT * FROM t WHERE n = '" + input + "'");`), "sql-injection")).toBe(true);
    expect(has(ctl(`    var conn = new SqlConnection();\n    conn.Query("SELECT * FROM t WHERE n = @n", new { n = input });`), "sql-injection")).toBe(false);
  });
  it("SQL built by a helper method and by StringBuilder", () => {
    const helper = `  private string Build(string n) { return "SELECT * FROM t WHERE n = '" + n + "'"; }\n`;
    expect(has(controller(`${helper}  [HttpGet("x")]\n  public IActionResult F(string input)\n  {\n    new SqlCommand(Build(input), new SqlConnection()).ExecuteReader();\n    return Ok();\n  }`), "sql-injection")).toBe(true);
    expect(has(ctl(`    var sb = new System.Text.StringBuilder("SELECT * FROM t WHERE n = '");\n    sb.Append(input);\n    new SqlCommand(sb.ToString(), new SqlConnection()).ExecuteReader();`), "sql-injection")).toBe(true);
  });
});

describe("propagation through C# constructs", () => {
  const flows = (body: string, extra = "") => has(action(body + `\n    Process.Start(v);`, "string input", extra), "command-injection");
  it.each([
    ["a List", `    var l = new List<string>(); l.Add(input); var v = l[0];`],
    ["a Dictionary", `    var d = new Dictionary<string, string>(); d["k"] = input; var v = d["k"];`],
    ["an object initializer", `    var o = new Holder { Value = input }; var v = o.Value;`],
    ["a property assignment", `    var o = new Holder(); o.Value = input; var v = o.Value;`],
    ["an object alias", `    var o = new Holder { Value = input }; var p = o; var v = p.Value;`],
    ["a local function", `    string Echo(string s) => s; var v = Echo(input);`],
    ["a lambda", `    Func<string, string> f = s => s + "x"; var v = f(input);`],
    ["a closure", `    var captured = input; Func<string> f = () => captured; var v = f();`],
    ["await of a Task result", `    var v = Task.FromResult(input).Result;`],
    ["a tuple", `    var t = (a: input, b: "x"); var v = t.a;`],
    ["string interpolation", `    var v = $"ls {input}";`],
    ["string.Format", `    var v = string.Format("ls {0}", input);`],
  ])("taint survives %s", (_n, body) => {
    expect(flows(body, `public class Holder { public string Value { get; set; } }`)).toBe(true);
  });
  it("a sanitizer is sink-class specific: HtmlEncode does not make a command safe", () => {
    expect(flows(`    var v = System.Net.WebUtility.HtmlEncode(input);`)).toBe(true);
  });
  it("a constant overwrites the tainted value", () => {
    expect(flows(`    var v = input; v = "ls";`)).toBe(false);
  });
});

describe("mass assignment: a role attribute is not proof", () => {
  it("binding a whole model with a privileged property is reported even under [Authorize(Roles=...)]", () => {
    const code = `${USING}
public class Account { public string Email { get; set; } public bool IsAdmin { get; set; } }
[ApiController]
public class AccountsController : ControllerBase
{
  [HttpPost("x")]
  [Authorize(Roles = "Admin")]
  public IActionResult Update([FromBody] Account model)
  {
    return Ok(model);
  }
}
`;
    expect(has(code, "mass-assignment")).toBe(true);
  });
  it("a model without privileged properties is not", () => {
    const code = `${USING}
public class Profile { public string Email { get; set; } public string Name { get; set; } }
[ApiController]
public class ProfilesController : ControllerBase
{
  [HttpPost("x")]
  public IActionResult Update([FromBody] Profile model) { return Ok(model); }
}
`;
    expect(has(code, "mass-assignment")).toBe(false);
  });
});

describe("more ways suppression could be wrong", () => {
  const sql = (body: string, members = "") => `${USING}
public class Repo
{
${members}
  public void Run(string input, SqlConnection conn)
  {
${body}
  }
}
`;
  const EXEC = `    new SqlCommand(q, conn).ExecuteReader();`;
  it("a lambda that assigns input to the query before it runs", () => {
    expect(anyHas(sql(`    string q = "SELECT 1";\n    Action set = () => { q = "SELECT * FROM t WHERE n = '" + input + "'"; };\n    set();\n${EXEC}`), "sql-injection")).toBe(true);
  });
  it("a helper that writes its out parameter from input", () => {
    expect(anyHas(sql(`    string q;\n    Fill(input, out q);\n${EXEC}`, `  private void Fill(string v, out string q) { q = "SELECT * FROM t WHERE n = '" + v + "'"; }`), "sql-injection")).toBe(true);
  });
  it("a switch whose default case uses input", () => {
    expect(anyHas(sql(`    string q;\n    switch (input.Length) { case 1: q = "SELECT 1"; break; default: q = "SELECT * FROM t WHERE n = '" + input + "'"; break; }\n${EXEC}`), "sql-injection")).toBe(true);
  });
  it("a try-finally that assigns after a possible exception", () => {
    expect(anyHas(sql(`    string q = "SELECT 1";\n    try { q = "SELECT * FROM t WHERE n = '" + input + "'"; } finally { }\n${EXEC}`), "sql-injection")).toBe(true);
  });
  it("a virtual method an override can replace is not proven constant", () => {
    const members = `  protected virtual string Table() { return "t"; }`;
    expect(anyHas(sql(`    var q = "SELECT * FROM " + Table();\n${EXEC}`, members), "sql-injection")).toBe(true);
    // ...while the same method, not overridable, is a constant and is proven
    expect(anyHas(sql(`    var q = "SELECT * FROM " + Table();\n${EXEC}`, `  private string Table() { return "t"; }`), "sql-injection")).toBe(false);
  });
});
