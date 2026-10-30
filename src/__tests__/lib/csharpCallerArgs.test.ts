/**
 * @jest-environment node
 *
 * C# cross-file callers in the proof pass: a public helper that other files of the batch call receives what those
 * calls pass, so SQL it builds from a parameter only ever given a constant is proven safe (the line layer's
 * concatenation match there is vetoed). A helper any caller hands request data (reported at that caller), a helper
 * nothing in the batch calls, and an entry point (controller action) all keep a finding.
 */
import { runScan } from "@/lib/scanner";
import { warmCSharpTaintEngine } from "@/lib/astTaintCSharp";

beforeAll(async () => { await warmCSharpTaintEngine(); }, 120000);

const helper = (cls = "ReportSql", method = "Hits", extraClass = "") => `using System.Data.SqlClient;
public class ${cls}${extraClass}
{
    public static void ${method}(string data, SqlConnection conn)
    {
        SqlCommand cmd = new SqlCommand();
        cmd.Connection = conn;
        cmd.CommandText = "update users set hitcount=hitcount+1 where name='" + data + "'";
        cmd.ExecuteNonQuery();
    }
}
`;
const caller = (arg: string, call = "ReportSql.Hits(data, conn);") => `using System.Data.SqlClient;
using System.Web;
public class Jobs
{
    public void Run(HttpRequest req, SqlConnection conn)
    {
        string data = ${arg};
        ${call}
    }
}
`;
/** `path:line` of every SQL injection finding in the batch */
const sql = (files: { path: string; content: string }[]) =>
  runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files })
    .files.flatMap(f => f.indicators.filter(i => i.id === "sql-injection").map(i => `${f.file_path}:${i.line}`));

describe("cross-file callers in the C# proof pass", () => {
  it("a helper only ever given a constant is proven safe; given request data it is reported at the caller", () => {
    expect(sql([{ path: "ReportSql.cs", content: helper() }, { path: "Jobs.cs", content: caller(`"nightly"`) }])).toEqual([]);
    expect(sql([{ path: "ReportSql.cs", content: helper() }, { path: "Jobs.cs", content: caller(`req.QueryString["name"]`) }])).toEqual(["Jobs.cs:8"]);
  });

  it("a helper nothing in the batch calls keeps the finding (its callers are unknown)", () => {
    expect(sql([{ path: "ReportSql.cs", content: helper() }, { path: "Jobs.cs", content: caller(`"nightly"`, "") }])).toEqual(["ReportSql.cs:8"]);
  });

  it("one tainted call site anywhere keeps it, even when another passes a constant", () => {
    const second = caller(`req.Form["n"]`).replace("class Jobs", "class Imports");
    expect(sql([{ path: "ReportSql.cs", content: helper() }, { path: "Jobs.cs", content: caller(`"nightly"`) }, { path: "Imports.cs", content: second }])).toEqual(["Imports.cs:8"]);
  });

  it("a constant passed through a second helper still reaches the first as a constant", () => {
    const relay = `using System.Data.SqlClient;\npublic class Relay\n{\n    public static void Pass(string v, SqlConnection conn)\n    {\n        ReportSql.Hits(v, conn);\n    }\n}\n`;
    const files = (arg: string) => [{ path: "ReportSql.cs", content: helper() }, { path: "Relay.cs", content: relay }, { path: "Jobs.cs", content: caller(arg, "Relay.Pass(data, conn);") }];
    expect(sql(files(`"nightly"`))).toEqual([]);
    expect(sql(files(`req.QueryString["name"]`))).not.toEqual([]);
  });

  it("request data put into an object's field is still request data when the object is passed", () => {
    const boxHelper = helper().replace("string data, SqlConnection conn)\n    {", "Box box, SqlConnection conn)\n    {\n        string data = box.Value;");
    const box = `public class Box\n{\n    public string Value;\n}\n`;
    const call = (arg: string) => caller(arg, "Box b = new Box();\n        b.Value = data;\n        ReportSql.Hits(b, conn);");
    expect(sql([{ path: "Box.cs", content: box }, { path: "ReportSql.cs", content: boxHelper }, { path: "Jobs.cs", content: call(`req.QueryString["name"]`) }])).not.toEqual([]);
  });

  it("a named argument's VALUE is what is passed, not the local that happens to share its name", () => {
    // `data` the local is a constant; `data:` the argument is request input
    const call = caller(`"nightly"`, `ReportSql.Hits(conn: conn, data: req.QueryString["n"]);`);
    // reported at the caller, through the callee's sink, although the names put it out of position
    expect(sql([{ path: "ReportSql.cs", content: helper() }, { path: "Jobs.cs", content: call }])).toEqual(["Jobs.cs:8"]);
  });

  it("an entry point (a controller) keeps the finding whatever the batch passes", () => {
    const controller = helper("ReportController", "Hits", " : Controller");
    expect(sql([{ path: "ReportController.cs", content: controller }, { path: "Jobs.cs", content: caller(`"nightly"`, "ReportController.Hits(data, conn);") }])).toEqual(["ReportController.cs:8"]);
    // recognised by its base class too, whatever the class is called
    const byBase = helper("Reports", "Hits", " : ControllerBase");
    expect(sql([{ path: "Reports.cs", content: byBase }, { path: "Jobs.cs", content: caller(`"nightly"`, "Reports.Hits(data, conn);") }])).toEqual(["Reports.cs:8"]);
  });

  it("a named argument may bind any parameter, so it proves nothing about position", () => {
    // conn is clean here, so reading the arguments by position would wrongly hand `data` a clean value
    const named = caller(`req.QueryString["n"]`, "ReportSql.Hits(conn: null, data: data);");
    expect(sql([{ path: "ReportSql.cs", content: helper() }, { path: "Jobs.cs", content: named }])).not.toEqual([]);
  });

  it("a virtual call resolves to the class actually constructed, through the base type", () => {
    const base = `public abstract class SinkBase\n{\n    public abstract void Act(string data, System.Data.SqlClient.SqlConnection conn);\n}\n`;
    const impl = (cls: string) => helper(cls, "Act", " : SinkBase").replace("public static void Act", "public override void Act");
    const call = (cls: string, arg: string) => caller(arg, `SinkBase s = new ${cls}();\n        s.Act(data, conn);`).replace("class Jobs", `class Run${cls}`);
    const found = sql([
      { path: "SinkBase.cs", content: base }, { path: "GoodSink.cs", content: impl("GoodSink") }, { path: "BadSink.cs", content: impl("BadSink") },
      { path: "RunGood.cs", content: call("GoodSink", `"nightly"`) }, { path: "RunBad.cs", content: call("BadSink", `req.QueryString["n"]`) },
    ]);
    expect(found.filter(l => /^(?:GoodSink|RunGood)\.cs/.test(l))).toEqual([]);
    expect(found.filter(l => /^(?:BadSink|RunBad)\.cs/.test(l))).not.toEqual([]);
  });
});
