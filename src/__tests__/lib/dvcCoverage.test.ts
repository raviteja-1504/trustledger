/**
 * @jest-environment node
 *
 * Coverage found scanning The Damn Vulnerable Codebase (one small app per language): conventionally routed MVC
 * actions as request input and `process.StartInfo.*` as a command sink (C#), a Sinatra route block's string as
 * the HTML response (Ruby), `require("child_process").exec(...)` read straight off require() (JS), and literal
 * credentials in ADO.NET connection strings, JDBC getConnection() and PHP define().
 */
import { analyzeFile } from "@/lib/scanner";
import { warmCSharpTaintEngine } from "@/lib/astTaintCSharp";
import { warmRubyTaintEngine } from "@/lib/astTaintRuby";

beforeAll(async () => { await warmCSharpTaintEngine(); await warmRubyTaintEngine(); }, 120000);

const found = (path: string, code: string) => analyzeFile(path, code).indicators;
const astHas = (path: string, code: string, id: string) => found(path, code).some(i => i.id === id && !!i.sourceExpr);
const has = (path: string, code: string, id: string) => found(path, code).some(i => i.id === id);

describe("C# MVC actions", () => {
  const controller = (method: string, base = "Controller", cls = "HomeController") =>
    `namespace A {\n  public class ${cls} : ${base} {\n${method}\n  }\n}\n`;
  const exec = (mods = "public") => `    ${mods} IActionResult Exec(string command) {\n      System.Diagnostics.Process.Start("cmd.exe", "/C " + command);\n      return Content("x");\n    }`;
  it("a public action of a controller binds its simple parameters without a verb attribute", () => {
    expect(astHas("Controllers/HomeController.cs", controller(exec()), "command-injection")).toBe(true);
    expect(astHas("Controllers/HomeController.cs", controller(exec(), "ControllerBase", "ApiController"), "command-injection")).toBe(true);
  });
  it("not a private helper, a [NonAction], a static method, or a class that isn't a controller", () => {
    expect(astHas("Controllers/HomeController.cs", controller(exec("private")), "command-injection")).toBe(false);
    expect(astHas("Controllers/HomeController.cs", controller(exec("public static")), "command-injection")).toBe(false);
    expect(astHas("Controllers/HomeController.cs", controller(`    [NonAction]\n${exec()}`), "command-injection")).toBe(false);
    expect(astHas("Services/Runner.cs", controller(exec(), "BaseService", "Runner"), "command-injection")).toBe(false);
  });
  it("process.StartInfo.FileName / Arguments on a new Process", () => {
    const body = (rhs: string) => controller(`    public IActionResult Exec(string command) {\n      var process = new System.Diagnostics.Process();\n      process.StartInfo.FileName = "cmd.exe";\n      process.StartInfo.Arguments = ${rhs};\n      process.Start();\n      return Content("x");\n    }`);
    expect(astHas("Controllers/HomeController.cs", body(`$"/C {command}"`), "command-injection")).toBe(true);
    expect(astHas("Controllers/HomeController.cs", body(`"/C dir"`), "command-injection")).toBe(false);
  });
});

describe("Sinatra routes", () => {
  const app = (route: string, header = "require 'sinatra'\n") => `${header}\n${route}\n`;
  it("an interpolated string as the route's value is the HTML body", () => {
    expect(astHas("app.rb", app(`get '/greet' do\n  name = params['name']\n  "<h1>Hello, #{name}</h1>"\nend`), "xss")).toBe(true);
    expect(astHas("app.rb", app(`class App < Sinatra::Base\n  get '/greet' do\n    "<p>#{params[:q]}</p>"\n  end\nend`, ""), "xss")).toBe(true);
  });
  it("escaped, constant, a template render, or not a Sinatra app", () => {
    expect(astHas("app.rb", app(`get '/greet' do\n  "<h1>Hello, #{Rack::Utils.escape_html(params['name'])}</h1>"\nend`), "xss")).toBe(false);
    expect(astHas("app.rb", app(`get '/greet' do\n  n = 1\n  "<h1>#{n}</h1>"\nend`), "xss")).toBe(false);
    expect(astHas("app.rb", app(`get '/greet' do\n  @name = params['name']\n  erb :greet\nend`), "xss")).toBe(false);
    // Grape renders a route's value as JSON
    expect(astHas("api.rb", app(`class API < Grape::API\n  get '/greet' do\n    "<p>#{params[:q]}</p>"\n  end\nend`, "require 'grape'\n"), "xss")).toBe(false);
  });
});

describe("JS inline require", () => {
  it("require('child_process').exec(input)", () => {
    const code = `const app = require('express')();\napp.get('/exec', (req, res) => {\n  const command = req.query.cmd;\n  require('child_process').exec(command, (e, out) => res.send(out));\n});\n`;
    expect(astHas("app.js", code, "command-injection")).toBe(true);
    expect(astHas("app.js", code.replace("exec(command", `exec("ls"`), "command-injection")).toBe(false);
  });
});

describe("literal database credentials", () => {
  it("an ADO.NET connection string with a literal password; not a templated one", () => {
    const cs = (s: string) => `namespace A {\n  public class Db {\n    private string cs = "${s}";\n    public void Open() { }\n  }\n}\n`;
    expect(has("Db.cs", cs("Server=db01;Database=app;User Id=sa;Password=Xk92mQ7vLp;"), "hardcoded-secret")).toBe(true);
    expect(has("Db.cs", cs("Data Source=db01;Initial Catalog=app;Pwd=Xk92mQ7vLp"), "hardcoded-secret")).toBe(true);
    expect(has("Db.cs", cs("Server=db01;Database=app;User Id=sa;Password={0};"), "hardcoded-secret")).toBe(false);
    expect(has("Db.cs", cs("Server=db01;Database=app;User Id=sa;Password=changeme;"), "hardcoded-secret")).toBe(false);
    // the database being named "test" says nothing about the password
    expect(has("Db.cs", cs("Server=localhost;Database=test;User Id=sa;Password=supersecretpassword;"), "hardcoded-secret")).toBe(true);
    expect(has("Db.cs", cs("Server=db01;Database=app;Integrated Security=true;"), "hardcoded-secret")).toBe(false);
  });
  it("a literal password argument to DriverManager.getConnection", () => {
    const j = (args: string) => `public class Db {\n  public Connection c() throws Exception {\n    return DriverManager.getConnection(${args});\n  }\n}\n`;
    expect(has("Db.java", j(`"jdbc:mysql://db01:3306/app", "root", "Xk92mQ7vLp"`), "hardcoded-secret")).toBe(true);
    expect(has("Db.java", j(`url, user, System.getenv("DB_PASS")`), "hardcoded-secret")).toBe(false);
    expect(has("Db.java", j(`"jdbc:mysql://db01:3306/app", "root", ""`), "hardcoded-secret")).toBe(false);
  });
  it("PHP define() of a secret-named constant", () => {
    const p = (line: string) => `<?php\n${line}\n$a = 1;\n$b = 2;\n$c = 3;\n`;
    expect(has("config.php", p(`define('API_KEY', '12345-ABCDE');`), "hardcoded-secret")).toBe(true);
    expect(has("config.php", p(`define('API_KEY', getenv('API_KEY'));`), "hardcoded-secret")).toBe(false);
    expect(has("config.php", p(`define('SITE_NAME', 'Xk92mQ7vLp-shop');`), "hardcoded-secret")).toBe(false);
  });
});
