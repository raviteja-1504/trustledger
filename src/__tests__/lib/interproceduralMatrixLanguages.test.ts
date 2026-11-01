/**
 * @jest-environment node
 *
 * The interprocedural matrix in every other engine (Java, PHP, Ruby, C#, Kotlin, Rust, C/C++; Go, Python and
 * JavaScript are in interproceduralMatrix.test.ts): request input read directly, through a helper's return, through two
 * helpers, through an object field, through a method of an object, then a builder / executor / resolver / renderer /
 * fetcher / redirect helper between it and the sink. Each vulnerable case must be found by the data-flow engine itself
 * (full confidence) with a trace that starts at the real input read and ends at the sink -- a helper -> sink case also
 * passing through the helper's parameter; each safe twin (a helper returning a constant, a bound parameter) is silent.
 */
import { analyzeFile } from "@/lib/scanner";
import { warmPhpTaintEngine } from "@/lib/astTaintPHP";
import { warmRubyTaintEngine } from "@/lib/astTaintRuby";
import { warmCSharpTaintEngine } from "@/lib/astTaintCSharp";
import { warmKotlinTaintEngine } from "@/lib/astTaintKotlin";
import { warmRustTaintEngine } from "@/lib/astTaintRust";
import { warmCppTaintEngine } from "@/lib/astTaintCpp";

beforeAll(async () => {
  await warmPhpTaintEngine(); await warmRubyTaintEngine(); await warmCSharpTaintEngine();
  await warmKotlinTaintEngine(); await warmRustTaintEngine(); await warmCppTaintEngine();
}, 120000);

type C = { name: string; id: string; expect: boolean; code: string };
const cases = (mk: (decls: string, body: string) => string, k: Record<string, [string, string]>): C[] => {
  const ids: Record<string, [string, boolean]> = {
    "1 direct read -> SQL": ["sql-injection", true], "2 helper return -> SQL": ["sql-injection", true],
    "3 two helper returns -> SQL": ["sql-injection", true], "4 object field -> SQL": ["sql-injection", true],
    "5 method return -> SQL": ["sql-injection", true], "6 clean constant (safe)": ["sql-injection", false],
    "7 parameterized (safe)": ["sql-injection", false], "8 helper -> executor -> command": ["command-injection", true],
    "9 helper -> renderer -> XSS": ["xss", true], "10 helper -> resolver -> path": ["path-traversal", true],
    "11 helper -> fetcher -> SSRF": ["ssrf", true], "12 helper -> redirect": ["open-redirect", true],
  };
  return Object.entries(k).map(([name, [d, b]]) => ({ name, id: ids[name][0], expect: ids[name][1], code: mk(d, b) }));
};

const java = (d: string, b: string) => `import javax.servlet.http.*;
import java.sql.*;
import java.io.*;
import java.net.*;

public class UserServlet extends HttpServlet {
    private Connection conn;

${d}

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws Exception {
${b}
    }
}
`;
const JSRC = `    private String getInput(HttpServletRequest request) {\n        return request.getParameter("v");\n    }`;
const JQ = (e: string) => `        conn.createStatement().executeQuery("SELECT * FROM t WHERE c = '" + ${e} + "'");`;
const JAVA = cases(java, {
  "1 direct read -> SQL": ["", `        String v = request.getParameter("v");\n${JQ("v")}`],
  "2 helper return -> SQL": [JSRC, `        String v = getInput(request);\n${JQ("v")}`],
  "3 two helper returns -> SQL": [`${JSRC}\n    private String normalize(String s) {\n        return s.trim();\n    }`, `        String v = normalize(getInput(request));\n${JQ("v")}`],
  "4 object field -> SQL": [`    static class Filter {\n        String name;\n    }`, `        Filter f = new Filter();\n        f.name = request.getParameter("v");\n${JQ("f.name")}`],
  "5 method return -> SQL": [`    static class Params {\n        private final HttpServletRequest req;\n        Params(HttpServletRequest req) { this.req = req; }\n        String name() { return req.getParameter("v"); }\n    }`, `        Params p = new Params(request);\n${JQ("p.name()")}`],
  "6 clean constant (safe)": [`    private String getName() {\n        return "admin";\n    }`, `        String v = getName();\n${JQ("v")}`],
  "7 parameterized (safe)": [JSRC, `        String v = getInput(request);\n        PreparedStatement ps = conn.prepareStatement("SELECT * FROM t WHERE c = ?");\n        ps.setString(1, v);\n        ps.executeQuery();`],
  "8 helper -> executor -> command": [`${JSRC}\n    private void runCommand(String cmd) throws IOException {\n        Runtime.getRuntime().exec("ping -c 1 " + cmd);\n    }`, `        runCommand(getInput(request));`],
  "9 helper -> renderer -> XSS": [`${JSRC}\n    private String renderUser(String name) {\n        return "<h1>" + name + "</h1>";\n    }`, `        response.getWriter().println(renderUser(getInput(request)));`],
  "10 helper -> resolver -> path": [`${JSRC}\n    private String resolveFile(String name) {\n        return "/srv/files/" + name;\n    }`, `        FileInputStream in = new FileInputStream(resolveFile(getInput(request)));\n        in.close();`],
  "11 helper -> fetcher -> SSRF": [`${JSRC}\n    private InputStream fetchRemote(String url) throws IOException {\n        return new URL(url).openStream();\n    }`, `        fetchRemote(getInput(request)).close();`],
  "12 helper -> redirect": [`${JSRC}\n    private void performRedirect(HttpServletResponse response, String target) throws IOException {\n        response.sendRedirect(target);\n    }`, `        performRedirect(response, getInput(request));`],
});

const php = (d: string, b: string) => `<?php
$db = mysqli_connect("localhost", "app", getenv("DB_PASS"), "app");

${d}

${b}
`;
const PSRC = `function get_input() {\n    return $_GET['v'];\n}`;
const PQ = (e: string) => `mysqli_query($db, "SELECT * FROM t WHERE c = '" . ${e} . "'");`;
const PHP = cases(php, {
  "1 direct read -> SQL": ["", `$v = $_GET['v'];\n${PQ("$v")}`],
  "2 helper return -> SQL": [PSRC, `$v = get_input();\n${PQ("$v")}`],
  "3 two helper returns -> SQL": [`${PSRC}\nfunction normalize($s) {\n    return trim($s);\n}`, `$v = normalize(get_input());\n${PQ("$v")}`],
  "4 object field -> SQL": ["", `$f = new stdClass();\n$f->name = $_GET['v'];\n${PQ("$f->name")}`],
  "5 method return -> SQL": [`class Params {\n    public function name() {\n        return $_GET['v'];\n    }\n}`, `$p = new Params();\n${PQ("$p->name()")}`],
  "6 clean constant (safe)": [`function get_name() {\n    return 'admin';\n}`, `$v = get_name();\n${PQ("$v")}`],
  "7 parameterized (safe)": [PSRC, `$v = get_input();\n$stmt = mysqli_prepare($db, "SELECT * FROM t WHERE c = ?");\nmysqli_stmt_bind_param($stmt, "s", $v);\nmysqli_stmt_execute($stmt);`],
  "8 helper -> executor -> command": [`${PSRC}\nfunction run_command($cmd) {\n    return shell_exec("ping -c 1 " . $cmd);\n}`, `echo run_command(get_input());`],
  "9 helper -> renderer -> XSS": [`${PSRC}\nfunction render_user($name) {\n    return "<h1>" . $name . "</h1>";\n}`, `echo render_user(get_input());`],
  "10 helper -> resolver -> path": [`${PSRC}\nfunction resolve_file($name) {\n    return "/srv/files/" . $name;\n}`, `readfile(resolve_file(get_input()));`],
  "11 helper -> fetcher -> SSRF": [`${PSRC}\nfunction fetch_remote($url) {\n    $ch = curl_init($url);\n    return curl_exec($ch);\n}`, `echo fetch_remote(get_input());`],
  "12 helper -> redirect": [`${PSRC}\nfunction perform_redirect($target) {\n    header("Location: " . $target);\n    exit;\n}`, `perform_redirect(get_input());`],
});

const ruby = (d: string, b: string) => `class UsersController < ApplicationController
  def show
${b}
  end

  private

${d}
end
`;
const RSRC = `  def user_input\n    params[:v]\n  end`;
const RQ = (e: string) => `    ActiveRecord::Base.connection.execute("SELECT * FROM t WHERE c = '#{${e}}'")\n    head :ok`;
const RUBY = cases(ruby, {
  "1 direct read -> SQL": ["", `    v = params[:v]\n${RQ("v")}`],
  "2 helper return -> SQL": [RSRC, `    v = user_input\n${RQ("v")}`],
  "3 two helper returns -> SQL": [`${RSRC}\n\n  def normalize(s)\n    s.strip\n  end`, `    v = normalize(user_input)\n${RQ("v")}`],
  "4 object field -> SQL": ["", `    filter = { name: params[:v] }\n${RQ("filter[:name]")}`],
  "5 method return -> SQL": [`  def query_params\n    QueryParams.new(params)\n  end\n\n  class QueryParams\n    def initialize(p)\n      @p = p\n    end\n\n    def name\n      @p[:v]\n    end\n  end`, `    v = query_params.name\n${RQ("v")}`],
  "6 clean constant (safe)": [`  def default_name\n    "admin"\n  end`, `    v = default_name\n${RQ("v")}`],
  "7 parameterized (safe)": [RSRC, `    v = user_input\n    User.where("name = ?", v)\n    head :ok`],
  "8 helper -> executor -> command": [`${RSRC}\n\n  def run_command(cmd)\n    system("ping -c 1 #{cmd}")\n  end`, `    run_command(user_input)\n    head :ok`],
  "9 helper -> renderer -> XSS": [`${RSRC}\n\n  def render_user(name)\n    "<h1>#{name}</h1>"\n  end`, `    render html: render_user(user_input).html_safe`],
  "10 helper -> resolver -> path": [`${RSRC}\n\n  def resolve_file(name)\n    "/srv/files/#{name}"\n  end`, `    send_file resolve_file(user_input)`],
  "11 helper -> fetcher -> SSRF": [`${RSRC}\n\n  def fetch_remote(url)\n    Net::HTTP.get(URI(url))\n  end`, `    render plain: fetch_remote(user_input)`],
  "12 helper -> redirect": [`${RSRC}\n\n  def perform_redirect(target)\n    redirect_to target\n  end`, `    perform_redirect(user_input)`],
});

const cs = (d: string, b: string) => `using System.Data.SqlClient;
using System.Diagnostics;
using System.Net.Http;
using Microsoft.AspNetCore.Mvc;

public class UserController : Controller {
    private SqlConnection conn;

${d}

    [HttpGet("/x")]
    public IActionResult Show() {
${b}
    }
}
`;
const CSRC = `    private string GetInput() {\n        return Request.Query["v"];\n    }`;
const CQ = (e: string) => `        new SqlCommand("SELECT * FROM t WHERE c = '" + ${e} + "'", conn).ExecuteReader();\n        return Ok();`;
const CS = cases(cs, {
  "1 direct read -> SQL": ["", `        string v = Request.Query["v"];\n${CQ("v")}`],
  "2 helper return -> SQL": [CSRC, `        var v = GetInput();\n${CQ("v")}`],
  "3 two helper returns -> SQL": [`${CSRC}\n    private string Normalize(string s) {\n        return s.Trim();\n    }`, `        var v = Normalize(GetInput());\n${CQ("v")}`],
  "4 object field -> SQL": [`    class Filter {\n        public string Name;\n    }`, `        var f = new Filter { Name = Request.Query["v"] };\n${CQ("f.Name")}`],
  "5 method return -> SQL": [`    class Params {\n        private readonly Microsoft.AspNetCore.Http.HttpRequest req;\n        public Params(Microsoft.AspNetCore.Http.HttpRequest req) { this.req = req; }\n        public string Name() { return req.Query["v"]; }\n    }`, `        var p = new Params(Request);\n${CQ("p.Name()")}`],
  "6 clean constant (safe)": [`    private string GetName() {\n        return "admin";\n    }`, `        var v = GetName();\n${CQ("v")}`],
  "7 parameterized (safe)": [CSRC, `        var v = GetInput();\n        var cmd = new SqlCommand("SELECT * FROM t WHERE c = @c", conn);\n        cmd.Parameters.AddWithValue("@c", v);\n        cmd.ExecuteReader();\n        return Ok();`],
  "8 helper -> executor -> command": [`${CSRC}\n    private void RunCommand(string cmd) {\n        Process.Start("/bin/sh", "-c \\"ping -c 1 " + cmd + "\\"");\n    }`, `        RunCommand(GetInput());\n        return Ok();`],
  "9 helper -> renderer -> XSS": [`${CSRC}\n    private string RenderUser(string name) {\n        return "<h1>" + name + "</h1>";\n    }`, `        return Content(RenderUser(GetInput()), "text/html");`],
  "10 helper -> resolver -> path": [`${CSRC}\n    private string ResolveFile(string name) {\n        return "/srv/files/" + name;\n    }`, `        return Content(System.IO.File.ReadAllText(ResolveFile(GetInput())));`],
  "11 helper -> fetcher -> SSRF": [`${CSRC}\n    private string FetchRemote(string url) {\n        return new HttpClient().GetStringAsync(url).Result;\n    }`, `        return Content(FetchRemote(GetInput()));`],
  "12 helper -> redirect": [`${CSRC}\n    private IActionResult PerformRedirect(string target) {\n        return Redirect(target);\n    }`, `        return PerformRedirect(GetInput());`],
});

const kt = (d: string, b: string) => `import org.springframework.web.bind.annotation.*
import org.springframework.jdbc.core.JdbcTemplate
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

@RestController
class UserController(private val jdbc: JdbcTemplate) {
${d}

    @GetMapping("/x")
    fun handle(request: HttpServletRequest, response: HttpServletResponse): String {
${b}
        return "ok"
    }
}
`;
const KSRC = `    private fun getInput(request: HttpServletRequest): String {\n        return request.getParameter("v")\n    }`;
const KQ = (e: string) => `        jdbc.queryForList("SELECT * FROM t WHERE c = '" + ${e} + "'")`;
const KOTLIN = cases(kt, {
  "1 direct read -> SQL": ["", `        val v = request.getParameter("v")\n${KQ("v")}`],
  "2 helper return -> SQL": [KSRC, `        val v = getInput(request)\n${KQ("v")}`],
  "3 two helper returns -> SQL": [`${KSRC}\n    private fun normalize(s: String): String = s.trim()`, `        val v = normalize(getInput(request))\n${KQ("v")}`],
  "4 object field -> SQL": [`    data class Filter(val name: String)`, `        val f = Filter(request.getParameter("v"))\n${KQ("f.name")}`],
  "5 method return -> SQL": [`    class Params(private val req: HttpServletRequest) {\n        fun name(): String = req.getParameter("v")\n    }`, `        val p = Params(request)\n${KQ("p.name()")}`],
  "6 clean constant (safe)": [`    private fun getName(): String = "admin"`, `        val v = getName()\n${KQ("v")}`],
  "7 parameterized (safe)": [KSRC, `        val v = getInput(request)\n        jdbc.queryForList("SELECT * FROM t WHERE c = ?", v)`],
  "8 helper -> executor -> command": [`${KSRC}\n    private fun runCommand(cmd: String) {\n        Runtime.getRuntime().exec("ping -c 1 " + cmd)\n    }`, `        runCommand(getInput(request))`],
  "9 helper -> renderer -> XSS": [`${KSRC}\n    private fun renderUser(name: String): String {\n        return "<h1>" + name + "</h1>"\n    }`, `        response.writer.println(renderUser(getInput(request)))`],
  "10 helper -> resolver -> path": [`${KSRC}\n    private fun resolveFile(name: String): String {\n        return "/srv/files/" + name\n    }`, `        java.io.File(resolveFile(getInput(request))).readText()`],
  "11 helper -> fetcher -> SSRF": [`${KSRC}\n    private fun fetchRemote(url: String): String {\n        return java.net.URL(url).readText()\n    }`, `        fetchRemote(getInput(request))`],
  "12 helper -> redirect": [`${KSRC}\n    private fun performRedirect(response: HttpServletResponse, target: String) {\n        response.sendRedirect(target)\n    }`, `        performRedirect(response, getInput(request))`],
});

const rs = (d: string, b: string) => `use axum::{extract::{Query, State}, response::{Html, Redirect, IntoResponse}};
use sqlx::PgPool;
use std::collections::HashMap;

${d}

async fn handle(Query(q): Query<HashMap<String, String>>, State(pool): State<PgPool>) -> impl IntoResponse {
${b}
}
`;
const RSSRC = `fn get_input(q: &HashMap<String, String>) -> String {\n    q.get("v").cloned().unwrap_or_default()\n}`;
const RSQ = (e: string) => `    sqlx::query(&format!("SELECT * FROM t WHERE c = '{}'", ${e})).execute(&pool).await.unwrap();\n    Html("ok".to_string())`;
const RUST = cases(rs, {
  "1 direct read -> SQL": ["", `    let v = q.get("v").cloned().unwrap_or_default();\n${RSQ("v")}`],
  "2 helper return -> SQL": [RSSRC, `    let v = get_input(&q);\n${RSQ("v")}`],
  "3 two helper returns -> SQL": [`${RSSRC}\n\nfn normalize(s: String) -> String {\n    s.trim().to_string()\n}`, `    let v = normalize(get_input(&q));\n${RSQ("v")}`],
  "4 object field -> SQL": [`struct Filter {\n    name: String,\n}`, `    let f = Filter { name: q.get("v").cloned().unwrap_or_default() };\n${RSQ("f.name")}`],
  "5 method return -> SQL": [`struct Params(HashMap<String, String>);\n\nimpl Params {\n    fn name(&self) -> String {\n        self.0.get("v").cloned().unwrap_or_default()\n    }\n}`, `    let p = Params(q);\n${RSQ("p.name()")}`],
  "6 clean constant (safe)": [`fn get_name() -> String {\n    "admin".to_string()\n}`, `    let v = get_name();\n${RSQ("v")}`],
  "7 parameterized (safe)": [RSSRC, `    let v = get_input(&q);\n    sqlx::query("SELECT * FROM t WHERE c = $1").bind(v).execute(&pool).await.unwrap();\n    Html("ok".to_string())`],
  "8 helper -> executor -> command": [`${RSSRC}\n\nfn run_command(cmd: &str) {\n    std::process::Command::new("sh").arg("-c").arg(format!("ping -c 1 {}", cmd)).output().unwrap();\n}`, `    run_command(&get_input(&q));\n    Html("ok".to_string())`],
  "9 helper -> renderer -> XSS": [`${RSSRC}\n\nfn render_user(name: &str) -> String {\n    format!("<h1>{}</h1>", name)\n}`, `    Html(render_user(&get_input(&q)))`],
  "10 helper -> resolver -> path": [`${RSSRC}\n\nfn resolve_file(name: &str) -> String {\n    format!("/srv/files/{}", name)\n}`, `    let body = std::fs::read_to_string(resolve_file(&get_input(&q))).unwrap();\n    Html(body)`],
  "11 helper -> fetcher -> SSRF": [`${RSSRC}\n\nasync fn fetch_remote(url: &str) -> String {\n    reqwest::get(url).await.unwrap().text().await.unwrap()\n}`, `    Html(fetch_remote(&get_input(&q)).await)`],
  "12 helper -> redirect": [`${RSSRC}\n\nfn perform_redirect(target: &str) -> Redirect {\n    Redirect::to(target)\n}`, `    perform_redirect(&get_input(&q))`],
});

const cpp = (d: string, b: string) => `#include <cstdio>
#include <cstdlib>
#include <string>
#include <sqlite3.h>
#include <curl/curl.h>

sqlite3 *db;

${d}

int main() {
${b}
    return 0;
}
`;
const CPPSRC = `const char *get_input() {\n    return getenv("V");\n}`;
const CPQ = (e: string) => `    std::string sql = std::string("SELECT * FROM t WHERE c = '") + ${e} + "'";\n    sqlite3_exec(db, sql.c_str(), 0, 0, 0);`;
const CPP = cases(cpp, {
  "1 direct read -> SQL": ["", `    const char *v = getenv("V");\n${CPQ("v")}`],
  "2 helper return -> SQL": [CPPSRC, `    const char *v = get_input();\n${CPQ("v")}`],
  "3 two helper returns -> SQL": [`${CPPSRC}\nstd::string normalize(const char *s) {\n    return std::string(s);\n}`, `    std::string v = normalize(get_input());\n${CPQ("v")}`],
  "4 object field -> SQL": [`struct Filter {\n    const char *name;\n};`, `    Filter f;\n    f.name = getenv("V");\n${CPQ("f.name")}`],
  "5 method return -> SQL": [`struct Params {\n    const char *name() { return getenv("V"); }\n};`, `    Params p;\n${CPQ("p.name()")}`],
  "6 clean constant (safe)": [`const char *get_name() {\n    return "admin";\n}`, `    const char *v = get_name();\n${CPQ("v")}`],
  "7 parameterized (safe)": [CPPSRC, `    const char *v = get_input();\n    sqlite3_stmt *st;\n    sqlite3_prepare_v2(db, "SELECT * FROM t WHERE c = ?", -1, &st, 0);\n    sqlite3_bind_text(st, 1, v, -1, 0);\n    sqlite3_step(st);`],
  "8 helper -> executor -> command": [`${CPPSRC}\nvoid run_command(const char *cmd) {\n    std::string c = std::string("ping -c 1 ") + cmd;\n    system(c.c_str());\n}`, `    run_command(get_input());`],
  "10 helper -> resolver -> path": [`${CPPSRC}\nstd::string resolve_file(const char *name) {\n    return std::string("/srv/files/") + name;\n}`, `    FILE *fp = fopen(resolve_file(get_input()).c_str(), "r");\n    if (fp) fclose(fp);`],
  "11 helper -> fetcher -> SSRF": [`${CPPSRC}\nvoid fetch_remote(const char *url) {\n    CURL *c = curl_easy_init();\n    curl_easy_setopt(c, CURLOPT_URL, url);\n    curl_easy_perform(c);\n}`, `    fetch_remote(get_input());`],
});

// a call with arguments chained on a helper's result is a call of THAT method, not of the helper
JAVA.push({ name: "9b helper -> renderer -> substring -> XSS", id: "xss", expect: true, code: java(
  `${JSRC}\n    private String renderUser(String name) {\n        return "<h1>" + name + "</h1>";\n    }`,
  `        response.getWriter().println(renderUser(getInput(request)).substring(0));`) });
JAVA.push({ name: "10b helper -> resolver -> concat(local) -> path", id: "path-traversal", expect: true, code: java(
  `${JSRC}\n    private String resolveFile(String name) {\n        return "/srv/files/" + name;\n    }`,
  `        String ext = ".txt";\n        FileInputStream in = new FileInputStream(resolveFile(getInput(request)).concat(ext));\n        in.close();`) });
// the input in the chained call's argument, not in the helper it is chained on (which returns a constant)
JAVA.push({ name: "10c constant helper .concat(input helper) -> path", id: "path-traversal", expect: true, code: java(
  `${JSRC}\n    private String baseDir() {\n        return "/srv/files/";\n    }`,
  `        FileInputStream in = new FileInputStream(baseDir().concat(getInput(request)));\n        in.close();`) });

describe("Kotlin: the constant proof needs every write of a local to be a literal", () => {
  it("a local that may also hold a service's value keeps its SQL finding", () => {
    const code = kt(`    private val svc = UserService()`,
      `        var v = "admin"\n        if (request.isSecure) {\n            v = svc.lookupName()\n        }\n${KQ("v")}`);
    expect(analyzeFile("UserController.kt", code).indicators.filter(i => i.id === "sql-injection").length).toBeGreaterThan(0);
  });
  it("a local only ever assigned literals is proven constant", () => {
    const code = kt("", `        var v = "admin"\n        if (request.isSecure) {\n            v = "guest"\n        }\n${KQ("v")}`);
    expect(analyzeFile("UserController.kt", code).indicators.filter(i => i.id === "sql-injection")).toHaveLength(0);
  });
});

// The read each language's trace must start at (Rust: the `Query(q)` extractor, or what a method reads from it).
const MATRICES: Array<[string, string, C[], RegExp]> = [
  ["Java", "UserServlet.java", JAVA, /\b(?:request|req)\.getParameter\("v"\)/],
  ["PHP", "user.php", PHP, /\$_GET\['v'\]/],
  ["Ruby", "users_controller.rb", RUBY, /^params(?:\[:v\])?$/],
  ["C#", "UserController.cs", CS, /\b(?:Request|req)\.Query\["v"\]/],
  ["Kotlin", "UserController.kt", KOTLIN, /\b(?:request|req)\.getParameter\("v"\)/],
  ["Rust", "handler.rs", RUST, /^q$|^self\.0\.get\("v"\)/],
  ["C++", "main.cpp", CPP, /getenv\("V"\)/],
];

for (const [lang, file, matrix, read] of MATRICES) {
  describe(`${lang}: source -> helper -> transformation -> sink`, () => {
    for (const c of matrix) {
      it(c.name, () => {
        const found = analyzeFile(file, c.code).indicators.filter(i => i.id === c.id);
        if (!c.expect) { expect(found).toHaveLength(0); return; }
        // the data-flow engine's own finding with the longest trace (a builder in another function stays its own finding)
        const flow = found.filter(f => f.confidence === 95 && (f.trace?.length ?? 0) >= 2).sort((a, b) => (b.trace?.length ?? 0) - (a.trace?.length ?? 0))[0];
        expect(flow).toBeDefined();
        const trace = flow!.trace!;
        expect(trace[0].kind).toBe("source");
        expect(trace[0].label).toMatch(read);
        expect(trace[trace.length - 1].kind).toBe("sink");
        // a sink inside a helper: the trace goes through the helper's parameter back to the caller
        if (/^(?:8|9b?|10b?|11|12) /.test(c.name)) expect(trace.some(s => s.kind === "parameter")).toBe(true);
      });
    }
  });
}