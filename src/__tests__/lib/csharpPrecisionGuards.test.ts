/**
 * @jest-environment node
 *
 * C# engine precision found on the vuln-csharp corpus's FalsePositives.cs traps: allowlists through `?.ToLower()`,
 * anchored Regex.IsMatch patterns (including pure literal alternatives), Path.GetFullPath + StartsWith confinement, a
 * bound Path.Combine judged where the path is used, typed System.Text.Json deserialization, and SQL command text built
 * only from constants.
 */
import { analyzeFile } from "@/lib/scanner";
import { warmCSharpTaintEngine } from "@/lib/astTaintCSharp";

beforeAll(async () => { await warmCSharpTaintEngine(); }, 120000);

const controller = (body: string, params = "string input") =>
  `using System.IO;\nusing System.Text.RegularExpressions;\n[ApiController]\npublic class C : ControllerBase {\n  [HttpGet("x")]\n  public IActionResult F(${params}) {\n${body}\n  }\n}\n`;
const ids = (code: string) => analyzeFile("Controllers/C.cs", code).indicators.map(i => i.id);
const has = (code: string, id: string) => ids(code).includes(id);
/** A finding from the data-flow engine itself (not the line-pattern layer). */
const flowHas = (code: string, id: string) =>
  analyzeFile("Controllers/C.cs", code).indicators.some(i => i.id === id && /real data-flow|is concatenated into/.test(i.detail ?? ""));

describe("guards", () => {
  it("a literal allowlist checked through ?.ToLower() / .Trim()", () => {
    const body = (arg: string) => `    var allowed = new HashSet<string> { "json", "xml" };\n    if (!allowed.Contains(${arg})) return BadRequest();\n    return Ok(System.IO.File.ReadAllText($"/var/app/static/export.{input}"));`;
    expect(has(controller(body("input?.ToLower()")), "path-traversal")).toBe(false);
    expect(has(controller(body("input.Trim()")), "path-traversal")).toBe(false);
    expect(has(controller(body("Lookup(input)")), "path-traversal")).toBe(true);
  });

  it("Regex.IsMatch with an anchored pattern -- an alphabet or literal alternatives", () => {
    const body = (pattern: string) => `    if (!Regex.IsMatch(input ?? "", @"${pattern}")) return BadRequest();\n    var psi = new System.Diagnostics.ProcessStartInfo("bash", $"-c \\"deploy --env {input}\\"");\n    return Ok(System.Diagnostics.Process.Start(psi));`;
    expect(has(controller(body("^(dev|staging|prod)$")), "command-injection")).toBe(false);
    expect(has(controller(body("^[a-z0-9]+$")), "command-injection")).toBe(false);
    expect(has(controller(body("[a-z]+")), "command-injection")).toBe(true);
    expect(has(controller(body("^[a-z;]+$")), "command-injection")).toBe(true);
  });

  it("an instance Regex built from a literal pattern", () => {
    const body = `    var re = new Regex(@"^[a-z0-9_]+$");\n    if (!re.IsMatch(input)) return BadRequest();\n    return Ok(System.IO.File.ReadAllText("/data/" + input));`;
    expect(has(controller(body), "path-traversal")).toBe(false);
  });

  it("Path.GetFullPath + StartsWith confines the path; StartsWith on the raw combination doesn't", () => {
    const body = (wrap: string) => `    const string baseDir = "/var/app/public/";\n    var fullPath = ${wrap};\n    if (!fullPath.StartsWith(baseDir)) return BadRequest();\n    return Ok(System.IO.File.ReadAllText(fullPath));`;
    expect(has(controller(body(`Path.GetFullPath(Path.Combine(baseDir, input ?? ""))`)), "path-traversal")).toBe(false);
    expect(has(controller(body(`baseDir + input`)), "path-traversal")).toBe(true);
  });

  it("a negated check keeps its narrower classes", () => {
    // StartsWith after GetFullPath clears traversal only: the same value is still SQL-injectable
    const body = `    var full = Path.GetFullPath(Path.Combine("/srv", input));\n    if (!full.StartsWith("/srv/")) return BadRequest();\n    using var cmd = new SqlCommand("SELECT * FROM f WHERE p = '" + full + "'", conn);\n    return Ok(cmd.ExecuteScalar());`;
    expect(flowHas(controller(body), "sql-injection")).toBe(true);
  });
});

describe("paths built but not opened", () => {
  it("the Combine-line veto needs the bound path itself to reach the file call", () => {
    expect(has(controller(`    var p = Path.Combine("/srv", input);\n    var other = System.IO.File.ReadAllText("/etc/app.conf");\n    return Ok(p + other);`), "path-traversal")).toBe(true);
  });

  it("a bound Path.Combine is judged at the file call; an unbound one is still a finding", () => {
    // (the confined case -- GetFullPath(Combine(...)) checked with StartsWith, then read -- is covered above)
    expect(has(controller(`    return Ok(Path.Combine("/srv", input));`), "path-traversal")).toBe(true);
    expect(has(controller(`    var p = Path.Combine("/srv", input);\n    return Ok(System.IO.File.ReadAllText(p));`), "path-traversal")).toBe(true);
  });
});

describe("deserialization", () => {
  it("typed System.Text.Json binds to the declared type; BinaryFormatter / TypeNameHandling still don't", () => {
    expect(has(controller(`    var o = System.Text.Json.JsonSerializer.Deserialize<SafeDto>(input);\n    return Ok(o);`), "insecure-deserialization")).toBe(false);
    expect(has(controller(`    var o = JsonSerializer.Deserialize<SafeDto>(input);\n    return Ok(o);`), "insecure-deserialization")).toBe(false);
    expect(has(controller(`    var f = new BinaryFormatter();\n    var o = f.Deserialize(new MemoryStream(Convert.FromBase64String(input)));\n    return Ok(o);`), "insecure-deserialization")).toBe(true);
  });
});

describe("SQL", () => {
  it("command text built only from constants is not injectable (ctor and Execute lines)", () => {
    const body = (second: string) => `    const string connStr = "Server=.;";\n    string userInput = "admin";\n    string rawQuery = "SELECT COUNT(*) FROM Users";\n    string dangerous = rawQuery + ${second};\n    using var conn = new SqlConnection(connStr);\n    using var cmd = new SqlCommand(dangerous, conn);\n    return Ok(cmd.ExecuteScalar());`;
    expect(has(controller(body(`" WHERE Role = 'admin'"`), ""), "sql-injection")).toBe(false);
    expect(has(controller(body(`" WHERE Role = '" + input + "'"`)), "sql-injection")).toBe(true);
  });

  it("inline new SqlCommand(constant).ExecuteScalar() is vetoed at its own line", () => {
    const code = controller(`    string userInput = "admin";\n    string q = "SELECT COUNT(*) FROM Users";\n    using var conn = new SqlConnection("Server=.;");\n    return Ok(new SqlCommand(q, conn).ExecuteScalar());`, "");
    expect(has(code, "sql-injection")).toBe(false);
  });

  it("a local bound to something other than constants is not a proven constant", () => {
    const code = controller(`    string userInput = "admin";\n    string q = LoadQuery();\n    using var conn = new SqlConnection("Server=.;");\n    using var cmd = new SqlCommand(q, conn);\n    return Ok(cmd.ExecuteScalar());`, "");
    expect(has(code, "sql-injection")).toBe(true);
  });
});
