/**
 * @jest-environment node
 *
 * Request sources and sinks of the C# web stack: ASP.NET Core / MVC 5 / Web API / minimal APIs, Blazor, Nancy, ServiceStack, SignalR,
 * Umbraco, Orchard Core, and EF Core / Dapper / NHibernate / OrmLite / NPoco. Each vulnerable case ("rule") must be reported; each
 * "!rule" case is the safe counterpart (parameterised query, interpolated EF API, numeric id, fixed type) that must stay quiet.
 */
import { runScan } from "@/lib/scanner";
import { ensureTaintEngines } from "@/lib/engineWarmup";
jest.setTimeout(300_000);
beforeAll(async () => { await ensureTaintEngines(); }, 120_000);
const ids = (name: string, content: string) =>
  runScan({ repo: "x", pr_number: 1, commit_sha: "a", branch: "main", files: [{ path: `t/${name}`, content }] })
    .files[0].indicators.filter(i => i.line != null && i.id !== "ai-model-attribution").map(i => i.id);
const U = `using System;\nusing System.IO;\nusing System.Net.Http;\nusing System.Diagnostics;\nusing System.Data.SqlClient;\nusing Microsoft.AspNetCore.Mvc;\nusing Microsoft.EntityFrameworkCore;\nusing Newtonsoft.Json;\n`;
const C = (body: string, usings = "") => `${U}${usings}\nnamespace App { public class HomeController : Controller {\n${body}\n} }\n`;
const A = (body: string, usings = "") => `${U}${usings}\nnamespace App { [ApiController] public class ApiCtl : ControllerBase {\n${body}\n} }\n`;
const cases: Array<[string, string, string]> = [
 // ASP.NET Core / MVC / Web API sources
 ["core FromQuery sql", "sql-injection", C(`public IActionResult A([FromQuery] string n) { var c = new SqlCommand("SELECT * FROM t WHERE n='" + n + "'"); return Ok(); }`)],
 ["core FromBody ssrf", "ssrf", A(`public async Task<IActionResult> A([FromBody] Req r) { var h = new HttpClient(); await h.GetAsync(r.Url); return Ok(); }\npublic class Req { public string Url {get;set;} }`)],
 ["core FromBody string", "command-injection", A(`public IActionResult A([FromBody] string c) { Process.Start("sh", "-c " + c); return Ok(); }`)],
 ["core Request.Query", "ssrf", C(`public async Task<IActionResult> A() { var h = new HttpClient(); await h.GetAsync(Request.Query["u"]); return Ok(); }`)],
 ["core Request.Query ToString", "ssrf", C(`public async Task<IActionResult> A() { var h = new HttpClient(); var u = Request.Query["u"].ToString(); await h.GetStringAsync(u); return Ok(); }`)],
 ["core Request.Form", "command-injection", C(`public IActionResult A() { Process.Start(Request.Form["c"]); return Ok(); }`)],
 ["core Request.Headers", "ssrf", C(`public async Task<IActionResult> A() { var h = new HttpClient(); await h.GetAsync(Request.Headers["X-U"]); return Ok(); }`)],
 ["core Request.Headers TryGetValue", "ssrf", C(`public async Task<IActionResult> A() { Request.Headers.TryGetValue("X-U", out var v); var h = new HttpClient(); await h.GetAsync(v.ToString()); return Ok(); }`)],
 ["core Request.Body reader", "command-injection", C(`public async Task<IActionResult> A() { var s = await new StreamReader(Request.Body).ReadToEndAsync(); Process.Start(s); return Ok(); }`)],
 ["core HttpRequest param", "path-traversal", C(`public string A(HttpRequest req) { return File.ReadAllText(req.Query["f"]); }`)],
 ["core Request.Cookies", "path-traversal", C(`public string A() { return File.ReadAllText(Request.Cookies["f"]); }`)],
 ["core implicit param", "path-traversal", C(`public string A(string f) { return File.ReadAllText(f); }`)],
 ["core FromRoute", "path-traversal", C(`public string A([FromRoute] string f) { return File.ReadAllText(f); }`)],
 ["core FromHeader", "path-traversal", C(`public string A([FromHeader(Name="X")] string f) { return File.ReadAllText(f); }`)],
 ["core FromForm", "path-traversal", C(`public string A([FromForm] string f) { return File.ReadAllText(f); }`)],
 ["core model prop", "sql-injection", C(`public IActionResult A(Req r) { var c = new SqlCommand("SELECT * FROM t WHERE n='" + r.Name + "'"); return Ok(); }\npublic class Req { public string Name {get;set;} }`)],
 ["core HttpContext.Request.Query", "path-traversal", C(`public string A() { return File.ReadAllText(HttpContext.Request.Query["f"]); }`)],
 ["core QueryString.Value", "path-traversal", C(`public string A() { return File.ReadAllText(Request.QueryString.Value); }`)],
 ["core Request.Path", "path-traversal", C(`public string A() { return File.ReadAllText(Request.Path.Value); }`)],
 ["core ReadFormAsync", "command-injection", C(`public async Task<IActionResult> A() { var f = await Request.ReadFormAsync(); Process.Start(f["c"]); return Ok(); }`)],
 ["core Form.TryGetValue", "command-injection", C(`public IActionResult A() { Request.Form.TryGetValue("c", out var v); Process.Start(v); return Ok(); }`)],
 ["core ReadFromJsonAsync", "ssrf", A(`public async Task<IActionResult> A() { var r = await Request.ReadFromJsonAsync<Req>(); await new HttpClient().GetAsync(r.Url); return Ok(); }\npublic class Req { public string Url {get;set;} }`)],
 ["minimal api lambda", "ssrf", `${U}\nvar app = WebApplication.Create();\napp.MapGet("/a", async (string u) => { var h = new HttpClient(); return await h.GetStringAsync(u); });\n`],
 ["minimal api FromQuery", "ssrf", `${U}\nvar app = WebApplication.Create();\napp.MapGet("/a", async ([FromQuery] string u) => await new HttpClient().GetStringAsync(u));\n`],
 ["minimal api HttpRequest", "ssrf", `${U}\nvar app = WebApplication.Create();\napp.MapGet("/a", async (HttpRequest req) => await new HttpClient().GetStringAsync(req.Query["u"]));\n`],
 // sinks
 ["EF FromSqlRaw concat", "sql-injection", C(`public IActionResult A(string n) { var r = _db.Users.FromSqlRaw("SELECT * FROM U WHERE N='" + n + "'").ToList(); return Ok(r); }\nDbContext _db;`)],
 ["EF FromSqlRaw interp", "sql-injection", C(`public IActionResult A(string n) { var r = _db.Users.FromSqlRaw($"SELECT * FROM U WHERE N='{n}'").ToList(); return Ok(r); }\nDbContext _db;`)],
 ["EF ExecuteSqlRaw", "sql-injection", C(`public IActionResult A(string n) { _db.Database.ExecuteSqlRaw("DELETE FROM U WHERE N='" + n + "'"); return Ok(); }\nDbContext _db;`)],
 ["EF ExecuteSqlRawAsync", "sql-injection", C(`public async Task<IActionResult> A(string n) { await _db.Database.ExecuteSqlRawAsync($"DELETE FROM U WHERE N='{n}'"); return Ok(); }\nDbContext _db;`)],
 ["EF ExecuteSqlInterpolated safe", "!sql-injection", C(`public async Task<IActionResult> A(string n) { await _db.Database.ExecuteSqlInterpolatedAsync($"DELETE FROM U WHERE N={n}"); return Ok(); }\nDbContext _db;`)],
 ["EF FromSqlInterpolated safe", "!sql-injection", C(`public IActionResult A(string n) { var r = _db.Users.FromSqlInterpolated($"SELECT * FROM U WHERE N={n}").ToList(); return Ok(r); }\nDbContext _db;`)],
 ["EF FromSql interp (EF8 safe)", "!sql-injection", C(`public IActionResult A(string n) { var r = _db.Users.FromSql($"SELECT * FROM U WHERE N={n}").ToList(); return Ok(r); }\nDbContext _db;`)],
 ["EF FromSqlRaw param safe", "!sql-injection", C(`public IActionResult A(string n) { var r = _db.Users.FromSqlRaw("SELECT * FROM U WHERE N={0}", n).ToList(); return Ok(r); }\nDbContext _db;`)],
 ["EF SqlQueryRaw", "sql-injection", C(`public IActionResult A(string n) { var r = _db.Database.SqlQueryRaw<int>("SELECT 1 FROM U WHERE N='" + n + "'").ToList(); return Ok(r); }\nDbContext _db;`)],
 ["EF ExecuteSqlCommand", "sql-injection", C(`public IActionResult A(string n) { _db.Database.ExecuteSqlCommand("DELETE FROM U WHERE N='" + n + "'"); return Ok(); }\nDbContext _db;`)],
 ["EF FromSql legacy concat", "sql-injection", C(`public IActionResult A(string n) { var r = _db.Users.FromSql("SELECT * FROM U WHERE N='" + n + "'").ToList(); return Ok(r); }\nDbContext _db;`)],
 ["EF LINQ safe", "!sql-injection", C(`public IActionResult A(string n) { var r = _db.Users.Where(u => u.Name == n).ToList(); return Ok(r); }\nDbContext _db;`)],
 ["EF OrderBy dynamic linq", "sql-injection", C(`public IActionResult A(string o) { var r = _db.Users.OrderBy(o).ToList(); return Ok(r); }\nDbContext _db;`, `using System.Linq.Dynamic.Core;\n`)],
 ["EF Where dynamic linq", "sql-injection", C(`public IActionResult A(string o) { var r = _db.Users.Where(o).ToList(); return Ok(r); }\nDbContext _db;`, `using System.Linq.Dynamic.Core;\n`)],
 ["SqlCommand ctor", "sql-injection", C(`public IActionResult A(string n) { using var c = new SqlCommand("SELECT * FROM t WHERE n='" + n + "'", conn); c.ExecuteReader(); return Ok(); }\nSqlConnection conn;`)],
 ["SqlCommand CommandText", "sql-injection", C(`public IActionResult A(string n) { var c = conn.CreateCommand(); c.CommandText = "SELECT * FROM t WHERE n='" + n + "'"; c.ExecuteScalar(); return Ok(); }\nSqlConnection conn;`)],
 ["SqlCommand params safe", "!sql-injection", C(`public IActionResult A(string n) { var c = new SqlCommand("SELECT * FROM t WHERE n=@n", conn); c.Parameters.AddWithValue("@n", n); c.ExecuteReader(); return Ok(); }\nSqlConnection conn;`)],
 ["SqlDataAdapter", "sql-injection", C(`public IActionResult A(string n) { var d = new SqlDataAdapter("SELECT * FROM t WHERE n='" + n + "'", conn); return Ok(); }\nSqlConnection conn;`)],
 ["OleDb/Npgsql/MySql command", "sql-injection", C(`public IActionResult A(string n) { var c = new NpgsqlCommand($"SELECT * FROM t WHERE n='{n}'", conn); c.ExecuteReader(); return Ok(); }\nNpgsqlConnection conn;`)],
 ["Dapper Query", "sql-injection", C(`public IActionResult A(string n) { var r = conn.Query<int>("SELECT * FROM t WHERE n='" + n + "'"); return Ok(r); }\nSqlConnection conn;`, `using Dapper;\n`)],
 ["Dapper QueryAsync", "sql-injection", C(`public async Task<IActionResult> A(string n) { var r = await conn.QueryAsync<int>($"SELECT * FROM t WHERE n='{n}'"); return Ok(r); }\nSqlConnection conn;`, `using Dapper;\n`)],
 ["Dapper Execute", "sql-injection", C(`public IActionResult A(string n) { conn.Execute("DELETE FROM t WHERE n='" + n + "'"); return Ok(); }\nSqlConnection conn;`, `using Dapper;\n`)],
 ["Dapper QueryFirst", "sql-injection", C(`public IActionResult A(string n) { var r = conn.QueryFirstOrDefault<int>("SELECT * FROM t WHERE n='" + n + "'"); return Ok(r); }\nSqlConnection conn;`, `using Dapper;\n`)],
 ["Dapper ExecuteScalar", "sql-injection", C(`public IActionResult A(string n) { var r = conn.ExecuteScalar<int>("SELECT COUNT(*) FROM t WHERE n='" + n + "'"); return Ok(r); }\nSqlConnection conn;`, `using Dapper;\n`)],
 ["Dapper QueryMultiple", "sql-injection", C(`public IActionResult A(string n) { var r = conn.QueryMultiple("SELECT * FROM t WHERE n='" + n + "'"); return Ok(); }\nSqlConnection conn;`, `using Dapper;\n`)],
 ["Dapper params safe", "!sql-injection", C(`public IActionResult A(string n) { var r = conn.Query<int>("SELECT * FROM t WHERE n=@n", new { n }); return Ok(r); }\nSqlConnection conn;`, `using Dapper;\n`)],
 ["NHibernate CreateSQLQuery", "sql-injection", C(`public IActionResult A(string n) { var r = session.CreateSQLQuery("SELECT * FROM t WHERE n='" + n + "'").List(); return Ok(r); }\nNHibernate.ISession session;`, `using NHibernate;\n`)],
 ["NHibernate CreateQuery HQL", "sql-injection", C(`public IActionResult A(string n) { var r = session.CreateQuery("from User where name='" + n + "'").List(); return Ok(r); }\nNHibernate.ISession session;`, `using NHibernate;\n`)],
 ["NHibernate CreateQuery param safe", "!sql-injection", C(`public IActionResult A(string n) { var r = session.CreateQuery("from User where name=:n").SetParameter("n", n).List(); return Ok(r); }\nNHibernate.ISession session;`, `using NHibernate;\n`)],
 ["NHibernate Query Linq safe", "!sql-injection", C(`public IActionResult A(string n) { var r = session.Query<int>().Where(u => u == 1).ToList(); return Ok(r); }\nNHibernate.ISession session;`, `using NHibernate;\n`)],
 ["NHibernate Restrictions.Sql", "sql-injection", C(`public IActionResult A(string n) { var r = session.CreateCriteria<User>().Add(Restrictions.Sql("name='" + n + "'")).List(); return Ok(r); }\nNHibernate.ISession session;`, `using NHibernate;\nusing NHibernate.Criterion;\n`)],
 ["NHibernate GetNamedQuery safe", "!sql-injection", C(`public IActionResult A(string n) { var r = session.GetNamedQuery("q").SetParameter("n", n).List(); return Ok(r); }\nNHibernate.ISession session;`, `using NHibernate;\n`)],
 ["Process.Start file", "command-injection", C(`public IActionResult A(string c) { Process.Start(c); return Ok(); }`)],
 ["Process.Start psi args", "command-injection", C(`public IActionResult A(string c) { var p = new ProcessStartInfo("cmd.exe", "/c " + c); Process.Start(p); return Ok(); }`)],
 ["ProcessStartInfo FileName", "command-injection", C(`public IActionResult A(string c) { var p = new ProcessStartInfo { FileName = c }; Process.Start(p); return Ok(); }`)],
 ["ProcessStartInfo Arguments", "command-injection", C(`public IActionResult A(string c) { var p = new ProcessStartInfo { FileName = "bash", Arguments = "-c " + c }; Process.Start(p); return Ok(); }`)],
 ["Process.Start constant safe", "!command-injection", C(`public IActionResult A(string c) { Process.Start("ls"); return Ok(); }`)],
 ["File.ReadAllText", "path-traversal", C(`public string A(string f) { return File.ReadAllText(f); }`)],
 ["File.ReadAllBytes", "path-traversal", C(`public byte[] A(string f) { return File.ReadAllBytes(f); }`)],
 ["File.OpenRead", "path-traversal", C(`public IActionResult A(string f) { return File(File.OpenRead(f), "x"); }`)],
 ["File.WriteAllText", "path-traversal", C(`public IActionResult A(string f, string d) { System.IO.File.WriteAllText(f, d); return Ok(); }`)],
 ["File.Delete", "path-traversal", C(`public IActionResult A(string f) { System.IO.File.Delete(f); return Ok(); }`)],
 ["Path.Combine", "path-traversal", C(`public string A(string f) { return File.ReadAllText(Path.Combine("/data", f)); }`)],
 ["PhysicalFile", "path-traversal", C(`public IActionResult A(string f) { return PhysicalFile(f, "text/plain"); }`)],
 ["StreamReader path", "path-traversal", C(`public string A(string f) { using var r = new StreamReader(f); return r.ReadToEnd(); }`)],
 ["FileStream path", "path-traversal", C(`public IActionResult A(string f) { var s = new FileStream(f, FileMode.Open); return Ok(); }`)],
 ["Directory.GetFiles", "path-traversal", C(`public IActionResult A(string f) { return Ok(Directory.GetFiles(f)); }`)],
 ["GetFileName safe", "!path-traversal", C(`public string A(string f) { return File.ReadAllText(Path.Combine("/data", Path.GetFileName(f))); }`)],
 ["HttpClient.GetAsync", "ssrf", C(`public async Task<IActionResult> A(string u) { await new HttpClient().GetAsync(u); return Ok(); }`)],
 ["HttpClient.GetStringAsync", "ssrf", C(`public async Task<IActionResult> A(string u) { await new HttpClient().GetStringAsync(u); return Ok(); }`)],
 ["HttpClient.PostAsync", "ssrf", C(`public async Task<IActionResult> A(string u) { await new HttpClient().PostAsync(u, null); return Ok(); }`)],
 ["HttpClient.SendAsync msg", "ssrf", C(`public async Task<IActionResult> A(string u) { var m = new HttpRequestMessage(HttpMethod.Get, u); await new HttpClient().SendAsync(m); return Ok(); }`)],
 ["HttpClient.SendAsync uri", "ssrf", C(`public async Task<IActionResult> A(string u) { var m = new HttpRequestMessage { RequestUri = new Uri(u), Method = HttpMethod.Get }; await new HttpClient().SendAsync(m); return Ok(); }`)],
 ["HttpClient factory", "ssrf", C(`public async Task<IActionResult> A(string u) { var c = _f.CreateClient(); await c.GetAsync(u); return Ok(); }\nIHttpClientFactory _f;`)],
 ["HttpClient field", "ssrf", C(`public async Task<IActionResult> A(string u) { await _http.GetAsync(u); return Ok(); }\nHttpClient _http;`)],
 ["HttpClient BaseAddress", "ssrf", C(`public async Task<IActionResult> A(string u) { _http.BaseAddress = new Uri(u); await _http.GetAsync("/x"); return Ok(); }\nHttpClient _http;`)],
 ["WebClient.DownloadString", "ssrf", C(`public string A(string u) { return new System.Net.WebClient().DownloadString(u); }`)],
 ["HttpWebRequest.Create", "ssrf", C(`public IActionResult A(string u) { var r = System.Net.WebRequest.Create(u); r.GetResponse(); return Ok(); }`)],
 ["RestSharp", "ssrf", C(`public IActionResult A(string u) { var c = new RestClient(u); return Ok(); }`, `using RestSharp;\n`)],
 ["Flurl", "ssrf", C(`public async Task<IActionResult> A(string u) { await u.GetStringAsync(); return Ok(); }`, `using Flurl.Http;\n`)],
 ["HttpClient const safe", "!ssrf", C(`public async Task<IActionResult> A(string n) { await new HttpClient().GetAsync("https://api.example.com/x"); return Ok(); }`)],
 ["Html.Raw controller", "xss", C(`public IActionResult A(string n) { ViewBag.X = new Microsoft.AspNetCore.Html.HtmlString(n); return View(); }`)],
 ["HtmlString ctor", "xss", C(`public IActionResult A(string n) { return View(new HtmlString(n)); }`, `using Microsoft.AspNetCore.Html;\n`)],
 ["Content text/html", "xss", C(`public IActionResult A(string n) { return Content("<b>" + n + "</b>", "text/html"); }`)],
 ["Content interp html", "xss", C(`public IActionResult A(string n) { return Content($"<b>{n}</b>", "text/html"); }`)],
 ["Response.WriteAsync html", "xss", C(`public async Task A(string n) { Response.ContentType = "text/html"; await Response.WriteAsync("<b>" + n); }`)],
 ["Response.Write", "xss", C(`public void A(string n) { Response.Write("<b>" + n); }`)],
 ["Content plain safe", "!xss", C(`public IActionResult A(string n) { return Content(n, "text/plain"); }`)],
 ["Json safe", "!xss", C(`public IActionResult A(string n) { return Json(new { n }); }`)],
 ["HtmlEncode safe", "!xss", C(`public IActionResult A(string n) { return Content("<b>" + System.Net.WebUtility.HtmlEncode(n), "text/html"); }`)],
 ["Blazor MarkupString", "xss", `@page "/x"\n@code {\n [Parameter, SupplyParameterFromQuery] public string N { get; set; }\n}\n<div>@((MarkupString)N)</div>\n`],
 ["Blazor MarkupString cs", "xss", `using Microsoft.AspNetCore.Components;\nnamespace App { public partial class P : ComponentBase { [SupplyParameterFromQuery] public string N { get; set; }\n RenderFragment R() => b => b.AddMarkupContent(0, N);\n MarkupString M() => new MarkupString(N); } }\n`],
 ["Blazor AddMarkupContent", "xss", `using Microsoft.AspNetCore.Components;\nnamespace App { public partial class P : ComponentBase { [Parameter] public string N { get; set; }\n protected override void BuildRenderTree(Microsoft.AspNetCore.Components.Rendering.RenderTreeBuilder b) { b.AddMarkupContent(0, N); } } }\n`],
 ["Blazor text safe", "!xss", `@page "/x"\n@code {\n [Parameter] public string N { get; set; }\n}\n<div>@N</div>\n`],
 ["Blazor NavigateTo", "open-redirect", `using Microsoft.AspNetCore.Components;\nnamespace App { public partial class P : ComponentBase { [Inject] NavigationManager Nav { get; set; }\n [Parameter] public string Next { get; set; }\n void G() { Nav.NavigateTo(Next); } } }\n`],
 ["Blazor JS eval", "eval-exec", `using Microsoft.AspNetCore.Components;\nnamespace App { public partial class P : ComponentBase { [Inject] IJSRuntime JS { get; set; }\n [Parameter] public string C { get; set; }\n async Task G() { await JS.InvokeVoidAsync("eval", C); } } }\n`],
 ["Redirect", "open-redirect", C(`public IActionResult A(string u) { return Redirect(u); }`)],
 ["RedirectPermanent", "open-redirect", C(`public IActionResult A(string u) { return RedirectPermanent(u); }`)],
 ["LocalRedirect safe", "!open-redirect", C(`public IActionResult A(string u) { return LocalRedirect(u); }`)],
 ["IsLocalUrl safe", "!open-redirect", C(`public IActionResult A(string u) { if (Url.IsLocalUrl(u)) return Redirect(u); return Ok(); }`)],
 // deserialization
 ["JsonConvert TypeNameHandling", "insecure-deserialization", C(`public IActionResult A([FromBody] string b) { var o = JsonConvert.DeserializeObject(b, new JsonSerializerSettings { TypeNameHandling = TypeNameHandling.All }); return Ok(); }`)],
 ["JsonConvert plain safe", "!insecure-deserialization", C(`public IActionResult A([FromBody] string b) { var o = JsonConvert.DeserializeObject<Req>(b); return Ok(); }\npublic class Req {}`)],
 ["BinaryFormatter", "insecure-deserialization", C(`public IActionResult A() { var f = new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter(); var o = f.Deserialize(Request.Body); return Ok(); }`)],
 ["BinaryFormatter var", "insecure-deserialization", C(`public IActionResult A(string b) { var f = new BinaryFormatter(); var o = f.Deserialize(new MemoryStream(Convert.FromBase64String(b))); return Ok(); }`, `using System.Runtime.Serialization.Formatters.Binary;\n`)],
 ["NetDataContractSerializer", "insecure-deserialization", C(`public IActionResult A(string b) { var f = new System.Runtime.Serialization.NetDataContractSerializer(); var o = f.Deserialize(new MemoryStream(Convert.FromBase64String(b))); return Ok(); }`)],
 ["LosFormatter", "insecure-deserialization", C(`public IActionResult A(string b) { var f = new System.Web.UI.LosFormatter(); var o = f.Deserialize(b); return Ok(); }`)],
 ["ObjectStateFormatter", "insecure-deserialization", C(`public IActionResult A(string b) { var f = new System.Web.UI.ObjectStateFormatter(); var o = f.Deserialize(b); return Ok(); }`)],
 ["SoapFormatter", "insecure-deserialization", C(`public IActionResult A() { var f = new System.Runtime.Serialization.Formatters.Soap.SoapFormatter(); var o = f.Deserialize(Request.Body); return Ok(); }`)],
 ["XmlSerializer type", "insecure-deserialization", C(`public IActionResult A(string t) { var s = new System.Xml.Serialization.XmlSerializer(Type.GetType(t)); var o = s.Deserialize(Request.Body); return Ok(); }`)],
 ["XmlSerializer fixed safe", "!insecure-deserialization", C(`public IActionResult A() { var s = new System.Xml.Serialization.XmlSerializer(typeof(Req)); var o = s.Deserialize(Request.Body); return Ok(); }\npublic class Req {}`)],
 ["TypeNameHandling Auto JsonSerializer", "insecure-deserialization", C(`public IActionResult A([FromBody] string b) { var s = new JsonSerializer { TypeNameHandling = TypeNameHandling.Auto }; var o = s.Deserialize(new JsonTextReader(new StringReader(b))); return Ok(); }`)],
 ["JavaScriptSerializer SimpleTypeResolver", "insecure-deserialization", C(`public IActionResult A(string b) { var s = new System.Web.Script.Serialization.JavaScriptSerializer(new System.Web.Script.Serialization.SimpleTypeResolver()); var o = s.DeserializeObject(b); return Ok(); }`)],
 ["YamlDotNet", "insecure-deserialization", C(`public IActionResult A(string b) { var d = new YamlDotNet.Serialization.Deserializer(); var o = d.Deserialize<object>(b); return Ok(); }`)],
 ["Type.GetType activator", "eval-exec", C(`public IActionResult A(string t) { var o = Activator.CreateInstance(Type.GetType(t)); return Ok(); }`)],
 // other frameworks
 ["Nancy query", "path-traversal", `using Nancy;\nnamespace App { public class M : NancyModule { public M() { Get("/a", p => File.ReadAllText(Request.Query["f"])); } } }\n`],
 ["Nancy route param", "path-traversal", `using Nancy;\nnamespace App { public class M : NancyModule { public M() { Get("/a/{f}", p => File.ReadAllText(p.f)); } } }\n`],
 ["Nancy route param ssrf", "ssrf", `using Nancy;\nusing System.Net.Http;\nnamespace App { public class M : NancyModule { public M() { Get("/a/{u}", async p => await new HttpClient().GetStringAsync((string)p.u)); } } }\n`],
 ["Nancy Form sql", "sql-injection", `using Nancy;\nusing System.Data.SqlClient;\nnamespace App { public class M : NancyModule { public M() { Post("/a", p => { var c = new SqlCommand("SELECT * FROM t WHERE n='" + Request.Form["n"] + "'"); return 1; }); } } }\n`],
 ["Nancy Bind", "sql-injection", `using Nancy;\nusing Nancy.ModelBinding;\nusing System.Data.SqlClient;\nnamespace App { public class R { public string N {get;set;} } public class M : NancyModule { public M() { Post("/a", p => { var r = this.Bind<R>(); var c = new SqlCommand("SELECT * FROM t WHERE n='" + r.N + "'"); return 1; }); } } }\n`],
 ["Nancy Redirect", "open-redirect", `using Nancy;\nnamespace App { public class M : NancyModule { public M() { Get("/a", p => Response.AsRedirect(Request.Query["u"])); } } }\n`],
 ["ServiceStack request dto", "sql-injection", `using ServiceStack;\nusing System.Data.SqlClient;\nnamespace App { [Route("/a")] public class Req : IReturn<string> { public string N {get;set;} }\n public class Svc : Service { public object Get(Req r) { var c = new SqlCommand("SELECT * FROM t WHERE n='" + r.N + "'"); return 1; } } }\n`],
 ["ServiceStack Any ssrf", "ssrf", `using ServiceStack;\nusing System.Net.Http;\nnamespace App { public class Req : IReturn<string> { public string U {get;set;} }\n public class Svc : Service { public async Task<object> Any(Req r) { return await new HttpClient().GetStringAsync(r.U); } } }\n`],
 ["ServiceStack Request.QueryString", "path-traversal", `using ServiceStack;\nnamespace App { public class Svc : Service { public object Get(Req r) { return File.ReadAllText(Request.QueryString["f"]); } }\n public class Req {} }\n`],
 ["ServiceStack Db.SqlList", "sql-injection", `using ServiceStack;\nusing ServiceStack.OrmLite;\nnamespace App { public class Req { public string N {get;set;} }\n public class Svc : Service { public object Get(Req r) { return Db.SqlList<int>("SELECT * FROM t WHERE n='" + r.N + "'"); } } }\n`],
 ["ServiceStack Db.Select", "sql-injection", `using ServiceStack;\nusing ServiceStack.OrmLite;\nnamespace App { public class Req { public string N {get;set;} }\n public class Svc : Service { public object Get(Req r) { return Db.Select<int>("name = '" + r.N + "'"); } } }\n`],
 ["ServiceStack OrmLite params safe", "!sql-injection", `using ServiceStack;\nusing ServiceStack.OrmLite;\nnamespace App { public class Req { public string N {get;set;} }\n public class Svc : Service { public object Get(Req r) { return Db.SqlList<int>("SELECT * FROM t WHERE n=@n", new { n = r.N }); } } }\n`],
 ["ServiceStack redirect", "open-redirect", `using ServiceStack;\nnamespace App { public class Req { public string U {get;set;} }\n public class Svc : Service { public object Get(Req r) { return HttpResult.Redirect(r.U); } } }\n`],
 ["SignalR hub sql", "sql-injection", `using Microsoft.AspNetCore.SignalR;\nusing System.Data.SqlClient;\nnamespace App { public class ChatHub : Hub { public async Task Send(string n) { var c = new SqlCommand("SELECT * FROM t WHERE n='" + n + "'"); } } }\n`],
 ["SignalR hub ssrf", "ssrf", `using Microsoft.AspNetCore.SignalR;\nusing System.Net.Http;\nnamespace App { public class ChatHub : Hub { public async Task Send(string u) { await new HttpClient().GetAsync(u); } } }\n`],
 ["SignalR hub cmd", "command-injection", `using Microsoft.AspNetCore.SignalR;\nnamespace App { public class ChatHub : Hub { public void Run(string c) { System.Diagnostics.Process.Start(c); } } }\n`],
 ["SignalR hub private helper safe", "!sql-injection", `using Microsoft.AspNetCore.SignalR;\nusing System.Data.SqlClient;\nnamespace App { public class ChatHub : Hub { public async Task Send(int id) { var c = new SqlCommand("SELECT * FROM t WHERE id=" + id); } } }\n`],
 ["SignalR legacy hub", "sql-injection", `using Microsoft.AspNet.SignalR;\nusing System.Data.SqlClient;\nnamespace App { public class ChatHub : Hub { public void Send(string n) { var c = new SqlCommand("SELECT * FROM t WHERE n='" + n + "'"); } } }\n`],
 ["Umbraco SurfaceController", "sql-injection", `using Umbraco.Cms.Web.Website.Controllers;\nusing System.Data.SqlClient;\nnamespace App { public class S : SurfaceController { public IActionResult A(string n) { var c = new SqlCommand("SELECT * FROM t WHERE n='" + n + "'"); return null; } } }\n`],
 ["Umbraco UmbracoApiController", "ssrf", `using Umbraco.Cms.Web.Common.Controllers;\nusing System.Net.Http;\nnamespace App { public class S : UmbracoApiController { public async Task<string> A(string u) { return await new HttpClient().GetStringAsync(u); } } }\n`],
 ["Umbraco database Fetch", "sql-injection", `using Umbraco.Cms.Web.Common.Controllers;\nusing NPoco;\nnamespace App { public class S : UmbracoApiController { IScopeProvider sp; public object A(string n) { using var s = sp.CreateScope(); return s.Database.Fetch<int>("SELECT * FROM t WHERE n='" + n + "'"); } } }\n`],
 ["Umbraco Sql builder safe", "!sql-injection", `using Umbraco.Cms.Web.Common.Controllers;\nusing NPoco;\nnamespace App { public class S : UmbracoApiController { IScopeProvider sp; public object A(string n) { using var s = sp.CreateScope(); return s.Database.Fetch<int>("SELECT * FROM t WHERE n=@0", n); } } }\n`],
 ["Umbraco Request.Query", "path-traversal", `using Umbraco.Cms.Web.Common.Controllers;\nnamespace App { public class S : UmbracoApiController { public string A() { return File.ReadAllText(Request.Query["f"]); } } }\n`],
 ["Orchard Core controller", "sql-injection", `using Microsoft.AspNetCore.Mvc;\nusing OrchardCore.Admin;\nusing System.Data.SqlClient;\nnamespace App { [Admin] public class S : Controller { public IActionResult A(string n) { var c = new SqlCommand("SELECT * FROM t WHERE n='" + n + "'"); return null; } } }\n`],
 ["Orchard YesSql", "sql-injection", `using Microsoft.AspNetCore.Mvc;\nusing YesSql;\nnamespace App { public class S : Controller { ISession _s; public async Task<IActionResult> A(string n) { var r = await _s.QueryAsync<Foo>("select * from t where n='" + n + "'"); return null; } } }\n`],
 ["Orchard Liquid render", "ssti", `using Microsoft.AspNetCore.Mvc;\nusing OrchardCore.Liquid;\nnamespace App { public class S : Controller { ILiquidTemplateManager _l; public async Task<string> A(string t) { return await _l.RenderStringAsync(t, null); } } }\n`],
 ["MVC5 Request.Params", "path-traversal", `using System.Web.Mvc;\nnamespace App { public class H : Controller { public string A() { return System.IO.File.ReadAllText(Request.Params["f"]); } } }\n`],
 ["MVC5 Request.QueryString", "path-traversal", `using System.Web.Mvc;\nnamespace App { public class H : Controller { public string A() { return System.IO.File.ReadAllText(Request.QueryString["f"]); } } }\n`],
 ["MVC5 Request[..]", "path-traversal", `using System.Web.Mvc;\nnamespace App { public class H : Controller { public string A() { return System.IO.File.ReadAllText(Request["f"]); } } }\n`],
 ["MVC5 Server.MapPath", "path-traversal", `using System.Web.Mvc;\nnamespace App { public class H : Controller { public string A(string f) { return System.IO.File.ReadAllText(Server.MapPath("~/x/" + f)); } } }\n`],
 ["MVC5 Response.Redirect", "open-redirect", `using System.Web.Mvc;\nnamespace App { public class H : Controller { public void A(string u) { Response.Redirect(u); } } }\n`],
 ["MVC5 Response.Write", "xss", `using System.Web.Mvc;\nnamespace App { public class H : Controller { public void A() { Response.Write(Request.QueryString["n"]); } } }\n`],
 ["MVC5 MvcHtmlString.Create", "xss", `using System.Web.Mvc;\nnamespace App { public class H : Controller { public object A(string n) { return MvcHtmlString.Create(n); } } }\n`],
 ["WebApi ApiController", "sql-injection", `using System.Web.Http;\nusing System.Data.SqlClient;\nnamespace App { public class H : ApiController { public object A(string n) { var c = new SqlCommand("SELECT * FROM t WHERE n='" + n + "'"); return 1; } } }\n`],
 ["WebApi FromUri", "ssrf", `using System.Web.Http;\nusing System.Net.Http;\nnamespace App { public class H : ApiController { public async Task<string> A([FromUri] string u) { return await new HttpClient().GetStringAsync(u); } } }\n`],
 ["WebApi Request.RequestUri query", "path-traversal", `using System.Web.Http;\nnamespace App { public class H : ApiController { public string A() { var q = Request.GetQueryNameValuePairs(); return File.ReadAllText(q.First().Value); } } }\n`],
 ["WebApi Content.ReadAsStringAsync", "command-injection", `using System.Web.Http;\nnamespace App { public class H : ApiController { public async Task A() { var b = await Request.Content.ReadAsStringAsync(); System.Diagnostics.Process.Start(b); } } }\n`],
 ["WebApi HttpResponseMessage html", "xss", `using System.Web.Http;\nusing System.Net.Http;\nnamespace App { public class H : ApiController { public HttpResponseMessage A(string n) { var r = new HttpResponseMessage(); r.Content = new StringContent("<b>" + n, System.Text.Encoding.UTF8, "text/html"); return r; } } }\n`],
 ["Razor Html.Raw ViewBag", "xss", `@Html.Raw(ViewBag.Msg)\n`],
 ["Razor Html.Raw constant safe", "!xss", `@Html.Raw("<b>hi</b>")\n`],
 ["Razor Html.Encode safe", "!xss", `@Html.Raw(Html.Encode(Model.Bio))\n`],
 // XML / LDAP / misc
 ["LDAP DirectorySearcher", "ldap-injection", C(`public IActionResult A(string n) { var s = new System.DirectoryServices.DirectorySearcher(); s.Filter = "(cn=" + n + ")"; s.FindAll(); return Ok(); }`)],
 ["XPath SelectNodes", "xpath-injection", C(`public IActionResult A(string n) { var d = new System.Xml.XmlDocument(); d.SelectNodes("//u[@n='" + n + "']"); return Ok(); }`)],
 ["Regex ReDoS", "redos", C(`public IActionResult A(string n) { new System.Text.RegularExpressions.Regex(n).IsMatch("x"); return Ok(); }`)],
 ["Log injection", "log-injection", C(`public IActionResult A(string n) { _log.LogInformation("user " + n); return Ok(); }\nMicrosoft.Extensions.Logging.ILogger _log;`)],
 ["legacy FromSql via variable", "sql-injection", C(`public IActionResult A(string n) { var q = string.Format("SELECT * FROM U WHERE N='{0}'", n); var r = _db.Users.FromSql(q).ToList(); return Ok(r); }
DbContext _db;`)],
 ["NPoco via variable", "sql-injection", `using NPoco;
using Microsoft.AspNetCore.Mvc;
namespace App { public class S : Controller { Database db; public object A(string n) { var q = string.Format("SELECT * FROM t WHERE n='{0}'", n); return db.Fetch<int>(q); } } }
`],
 ["neg NPoco via constant", "!sql-injection", `using NPoco;
using Microsoft.AspNetCore.Mvc;
namespace App { public class S : Controller { Database db; public object A(string n) { var q = "SELECT * FROM t WHERE n=@0"; return db.Fetch<int>(q, n); } } }
`],
 ["MarkupString of trusted constant stays quiet in engine", "!xss", `using Microsoft.AspNetCore.Components;
namespace App { public partial class P : ComponentBase { MarkupString M() { var s = "<b>x</b>"; return new MarkupString(s); } } }
`],
 ["neg explicit numeric FromQuery", "!command-injection", C(`public IActionResult A([FromQuery] int id) { Process.Start("sh", "-c " + id); return Ok(); }`)],
 ["hub method DTO", "ssrf", `using Microsoft.AspNetCore.SignalR;
using System.Net.Http;
namespace App { public class Msg { public string Url {get;set;} } public class ChatHub : Hub { public async Task Send(Msg m) { await new HttpClient().GetAsync(m.Url); } } }
`],
 ["razor page handler", "ssrf", `using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Net.Http;
namespace App { public class P : PageModel { public async Task OnGet(string u) { await new HttpClient().GetAsync(u); } } }
`],
 ["razor page BindProperty", "ssrf", `using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Mvc;
using System.Net.Http;
namespace App { public class P : PageModel { [BindProperty] public string U { get; set; }
 public async Task OnPost() { await new HttpClient().GetAsync(U); } } }
`],
 ["ServiceStack Get DTO", "ssrf", `using ServiceStack;
using System.Net.Http;
namespace App { public class Req { public string U {get;set;} }
 public class Svc : Service { public async Task<object> Get(Req r) { return await new HttpClient().GetStringAsync(r.U); } } }
`],
 ["neg ServiceStack helper", "!ssrf", `using ServiceStack;
using System.Net.Http;
namespace App { public class Svc : Service { public async Task<string> Fetch(string u) { return await new HttpClient().GetStringAsync(u); } } }
`],
 ["EF8 FromSql concat legacy", "sql-injection", C(`public IActionResult A(string n) { var r = _db.Users.FromSql("SELECT * FROM U WHERE N='" + n + "'").ToList(); return Ok(r); }
DbContext _db;`)],
 ["NPoco concat", "sql-injection", `using NPoco;
using Microsoft.AspNetCore.Mvc;
namespace App { public class S : Controller { Database db; public object A(string n) { return db.Fetch<int>("SELECT * FROM t WHERE n='" + n + "'"); } } }
`],
 ["Blazor new MarkupString query param", "xss", `using Microsoft.AspNetCore.Components;
namespace App { public partial class P : ComponentBase { [SupplyParameterFromQuery] public string N { get; set; }
 MarkupString M() { var s = N; return new MarkupString(s); } } }
`],
 ["Blazor cast of query param", "xss", `using Microsoft.AspNetCore.Components;
namespace App { public partial class P : ComponentBase { [SupplyParameterFromQuery] public string N { get; set; }
 object M() { return (MarkupString)N; } } }
`],
 ["neg numeric id into command", "!command-injection", C(`public IActionResult A(int id) { Process.Start("tool", "--id " + id); return Ok(); }`)],
 ["neg numeric id into path", "!path-traversal", C(`public string A(long id) { return File.ReadAllText("/data/" + id); }`)],
 ["neg Guid into sql", "!sql-injection", C(`public IActionResult A(Guid id) { var c = new SqlCommand("SELECT * FROM t WHERE id='" + id + "'", conn); return Ok(); }\nSqlConnection conn;`)],
 ["neg Parameter on plain class", "!xss", `namespace App { public class Plain { [Parameter] public string N { get; set; } MarkupString M() => new MarkupString("<b>x</b>"); } }\n`],
 ["neg dynamic linq lambda", "!sql-injection", C(`public IActionResult A(string n) { var r = _db.Users.Where(u => u.Name == n).OrderBy(u => u.Id).ToList(); return Ok(r); }\nDbContext _db;`, `using System.Linq.Dynamic.Core;\n`)],
 ["neg ormlite lambda", "!sql-injection", `using ServiceStack;\nusing ServiceStack.OrmLite;\nnamespace App { public class Req { public string N {get;set;} }\n public class Svc : Service { public object Get(Req r) { return Db.Select<int>(x => x == 1); } } }\n`],
 ["neg flurl constant url", "!ssrf", C(`public async Task<IActionResult> A(string n) { await "https://api.example.com/x".GetStringAsync(); return Ok(); }`, `using Flurl.Http;\n`)],
 ["neg StringContent json", "!xss", C(`public async Task<IActionResult> A(string n) { var c = new StringContent(n, System.Text.Encoding.UTF8, "application/json"); return Ok(); }`)],
 ["neg JavaScriptSerializer plain", "!insecure-deserialization", C(`public IActionResult A(string b) { var s = new System.Web.Script.Serialization.JavaScriptSerializer(); var o = s.DeserializeObject(b); return Ok(); }`)],
 ["neg JS interop fixed fn", "!eval-exec", `using Microsoft.AspNetCore.Components;\nnamespace App { public partial class P : ComponentBase { [Inject] IJSRuntime JS { get; set; }\n [Parameter] public string C { get; set; }\n async Task G() { await JS.InvokeVoidAsync("console.log", C); } } }\n`],
 ["neg hub non-public helper", "!ssrf", `using Microsoft.AspNetCore.SignalR;\nusing System.Net.Http;\nnamespace App { public class ChatHub : Hub { async Task Helper(string u) { await new HttpClient().GetAsync(u); } } }\n`],
 ["neg non-controller class public method", "!ssrf", `using System.Net.Http;\nnamespace App { public class Util { public async Task Fetch(string u) { await new HttpClient().GetAsync(u); } } }\n`],
 ["Header injection", "header-injection", C(`public IActionResult A(string n) { Response.Headers.Add("X-N", n); return Ok(); }`)],
];
describe("C# framework request sources and sinks", () => {
  it.each(cases)("%s -> %s", (label, want, code) => {
    const file = code.startsWith("@") ? "v.cshtml" : /^@/m.test(code) && /@page|@code/.test(code) ? "p.razor" : "p.cs";
    const got = ids(file, code);
    if (want.startsWith("!")) expect(got).not.toContain(want.slice(1));
    else expect(got).toContain(want);
  });
});
