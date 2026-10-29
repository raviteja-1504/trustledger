/**
 * @jest-environment node
 *
 * C#: the proof pass (a sink whose argument stays clean with every parameter, field and unmodelled input assumed
 * tainted vetoes the regex layer's SQL line match -- Juliet's goodG2B copies of a constant), and network input
 * (TcpClient.GetStream, Socket.Receive, WebClient.OpenRead / DownloadString) as a source.
 */
import { analyzeFile } from "@/lib/scanner";
import { warmCSharpTaintEngine } from "@/lib/astTaintCSharp";

beforeAll(async () => { await warmCSharpTaintEngine(); }, 120000);

const cls = (body: string, members = "") => `using System;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Data.SqlClient;
using System.Web;

class C : AbstractTestCaseWeb
{
${members}
    private void GoodG2B(HttpRequest req, HttpResponse resp)
    {
${body}
    }
}
`;
const sqlLines = (code: string) => analyzeFile("src/C.cs", code).indicators.filter(i => i.id === "sql-injection").map(i => i.line);
const sqlAst = (code: string) => analyzeFile("src/C.cs", code).indicators.some(i => i.id === "sql-injection" && !!i.sourceExpr);
const sink = (v: string) => `        SqlCommand cmd = null;\n        using (SqlConnection db = IO.GetDBConnection())\n        {\n            cmd.Connection = db;\n            cmd.CommandText += "update users set hitcount=hitcount+1 where name='" + ${v} + "';";\n            cmd.ExecuteNonQuery();\n        }`;

describe("proof pass", () => {
  it("a constant copied through a block and re-declared (Juliet _31) is not SQL injection", () => {
    const body = `        string dataCopy;\n        {\n            string data;\n            data = "foo";\n            dataCopy = data;\n        }\n        {\n            string data = dataCopy;\n${sink("data")}\n        }`;
    expect(sqlLines(cls(body))).toEqual([]);
  });
  it("an unmodelled call fed a constant is proven; fed a parameter it is not", () => {
    expect(sqlLines(cls(`        string data = Helper.Normalize("foo");\n${sink("data")}`))).toEqual([]);
    expect(sqlLines(cls(`        string data = Helper.Normalize(req.QueryString["id"]);\n${sink("data")}`)).length).toBeGreaterThan(0);
  });
  it("fields, this.fields, inherited getters and static readers are never proven", () => {
    expect(sqlLines(cls(`        string data = saved;\n${sink("data")}`, "    private string saved;")).length).toBeGreaterThan(0);
    expect(sqlLines(cls(`        string data = this.Saved;\n${sink("data")}`, "    public string Saved { get; set; }")).length).toBeGreaterThan(0);
    expect(sqlLines(cls(`        string data = GetInput();\n${sink("data")}`)).length).toBeGreaterThan(0);
    expect(sqlLines(cls(`        string data = Console.ReadLine();\n${sink("data")}`)).length).toBeGreaterThan(0);
  });
  it("a local helper returning a field with no argument is not proven; one returning a constant is", () => {
    expect(sqlLines(cls(`        string data = Load();\n${sink("data")}`, "    private string saved;\n    private string Load() { return saved; }")).length).toBeGreaterThan(0);
    expect(sqlLines(cls(`        string data = Load();\n${sink("data")}`, "    private string Load() { return \"foo\"; }"))).toEqual([]);
  });
});

describe("proof pass through private helpers (Juliet _41)", () => {
  const helper = (vis: string) => `    ${vis} static void GoodG2BSink(string data)\n    {\n${sink("data")}\n    }\n`;
  it("a private helper called only with a constant is proven", () => {
    expect(sqlLines(cls(`        string data = "foo";\n        GoodG2BSink(data);`, helper("private")))).toEqual([]);
  });
  it("the same helper with one caller passing input, or public, is not", () => {
    const two = cls(`        GoodG2BSink("foo");`, helper("private") + `    public void Bad(HttpRequest req)\n    {\n        GoodG2BSink(req.QueryString["id"]);\n    }\n`);
    expect(sqlLines(two).length).toBeGreaterThan(0);
    expect(sqlLines(cls(`        GoodG2BSink("foo");`, helper("public"))).length).toBeGreaterThan(0);
  });
  it("a helper also passed as a delegate is not proven", () => {
    const code = cls(`        GoodG2BSink("foo");\n        Action<string> f = GoodG2BSink;`, helper("private"));
    expect(sqlLines(code).length).toBeGreaterThan(0);
  });
});

describe("proof pass soundness (Juliet _68 / _75)", () => {
  it("another class's static field is never proven", () => {
    expect(sqlLines(cls(`        string data = OtherClass.data;\n${sink("data")}`)).length).toBeGreaterThan(0);
  });
  it("a parameter written into a local stream and read back is never proven", () => {
    const body = `        string data;\n        var binForm = new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();\n        using (var memStream = new MemoryStream())\n        {\n            memStream.Write(dataSerialized, 0, dataSerialized.Length);\n            data = (string)binForm.Deserialize(memStream);\n        }\n${sink("data")}`;
    expect(sqlLines(cls(body).replace("GoodG2B(HttpRequest req, HttpResponse resp)", "BadSink(byte[] dataSerialized, HttpRequest req, HttpResponse resp)")).length).toBeGreaterThan(0);
  });
});

describe("int.Parse as validation", () => {
  const eval_ = (cond: string) => cls(`        string data = req.QueryString["n"];\n        int? parsedNum = null;\n        try\n        {\n            parsedNum = int.Parse(data);\n        }\n        catch (FormatException)\n        {\n        }\n        if (${cond})\n        {\n            var provider = System.CodeDom.Compiler.CodeDomProvider.CreateProvider("CSharp");\n            provider.CompileAssemblyFromSource(new System.CodeDom.Compiler.CompilerParameters(), "class C { int S() { return 10 + " + data + "; } }");\n        }`);
  const evalAst = (code: string) => analyzeFile("src/C.cs", code).indicators.some(i => i.id === "eval-exec" && !!i.sourceExpr);
  it("the value is only used where its int.Parse succeeded; unguarded it still reports", () => {
    expect(evalAst(eval_("parsedNum != null"))).toBe(false);
    expect(evalAst(eval_("data != null"))).toBe(true);
  });
});

describe("network input", () => {
  it("TcpClient.GetStream read through a StreamReader (Juliet Connect_tcp)", () => {
    const body = (src: string) => `        string data = "";\n        using (TcpClient tcpConn = new TcpClient("host.example.org", 39544))\n        {\n            using (StreamReader sr = new StreamReader(${src}))\n            {\n                data = sr.ReadLine();\n            }\n        }\n${sink("data")}`;
    expect(sqlAst(cls(body("tcpConn.GetStream()")))).toBe(true);
    expect(sqlAst(cls(body(`File.OpenRead("local.txt")`)))).toBe(false);
  });
  it("WebClient.OpenRead / DownloadString and an accepted socket (NetClient / Listen_tcp)", () => {
    expect(sqlAst(cls(`        WebClient client = new WebClient();\n        string data = client.DownloadString("http://www.example.org/");\n${sink("data")}`))).toBe(true);
    expect(sqlAst(cls(`        string data = "";\n        TcpListener listener = new TcpListener(IPAddress.Any, 39543);\n        using (TcpClient tcpConn = listener.AcceptTcpClient())\n        using (StreamReader sr = new StreamReader(tcpConn.GetStream()))\n        {\n            data = sr.ReadLine();\n        }\n${sink("data")}`))).toBe(true);
    // the same method names on something that is no network client
    expect(sqlAst(cls(`        Cache client = new Cache();\n        string data = client.DownloadString("k");\n${sink("data")}`))).toBe(false);
  });
});
