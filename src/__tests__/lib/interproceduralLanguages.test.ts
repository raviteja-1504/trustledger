/**
 * @jest-environment node
 *
 * The same three-function flow in every tree-sitter / CST engine -- a helper that reads the request, a builder that
 * concatenates it into SQL, a helper that executes it -- must be found by the data-flow engine itself (full confidence)
 * with a trace that starts at the real request read and steps through each function boundary: the builder's
 * parameter, the executing helper's parameter, then the sink.
 */
import { analyzeFile } from "@/lib/scanner";
import { warmPythonTaintEngine } from "@/lib/astTaintPython";
import { warmPhpTaintEngine } from "@/lib/astTaintPHP";
import { warmRubyTaintEngine } from "@/lib/astTaintRuby";
import { warmCSharpTaintEngine } from "@/lib/astTaintCSharp";

beforeAll(async () => { await warmPythonTaintEngine(); await warmPhpTaintEngine(); await warmRubyTaintEngine(); await warmCSharpTaintEngine(); }, 120000);

const HELPER_APPS: Record<string, string> = {
  "app.py": `from flask import Flask, request
app = Flask(__name__)
def get_user_input():
    return request.args.get("username")
def build_query(name):
    return "SELECT id FROM users WHERE name = '" + name + "'"
def fetch_user(db, sql):
    db.execute(sql)
@app.route("/user")
def user():
    name = get_user_input()
    sql = build_query(name)
    fetch_user(db, sql)
    return "ok"
`,
  "UserController.java": `import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletRequest;
import java.sql.*;
@RestController
public class UserController {
    private String getUserInput(HttpServletRequest request) {
        return request.getParameter("username");
    }
    private String buildQuery(String name) {
        return "SELECT id FROM users WHERE name = '" + name + "'";
    }
    private void fetchUser(Connection conn, String sql) throws SQLException {
        conn.createStatement().executeQuery(sql);
    }
    @GetMapping("/user")
    public String user(HttpServletRequest request, Connection conn) throws SQLException {
        String name = getUserInput(request);
        String sql = buildQuery(name);
        fetchUser(conn, sql);
        return "ok";
    }
}
`,
  "user.php": `<?php
function get_user_input() {
    return $_GET['username'];
}
function build_query($name) {
    return "SELECT id FROM users WHERE name = '" . $name . "'";
}
function fetch_user($db, $sql) {
    return mysqli_query($db, $sql);
}
$name = get_user_input();
$sql = build_query($name);
fetch_user($db, $sql);
`,
  "users_controller.rb": `class UsersController < ApplicationController
  def show
    name = user_input
    sql = build_query(name)
    fetch_user(sql)
    render plain: "ok"
  end

  private

  def user_input
    params[:username]
  end

  def build_query(name)
    "SELECT id FROM users WHERE name = '#{name}'"
  end

  def fetch_user(sql)
    ActiveRecord::Base.connection.execute(sql)
  end
end
`,
  "UserController.cs": `using Microsoft.AspNetCore.Mvc;
using System.Data.SqlClient;
public class UserController : Controller {
    private string GetUserInput() {
        return Request.Query["username"];
    }
    private string BuildQuery(string name) {
        return "SELECT id FROM users WHERE name = '" + name + "'";
    }
    private void FetchUser(SqlConnection conn, string sql) {
        new SqlCommand(sql, conn).ExecuteReader();
    }
    [HttpGet("/user")]
    public IActionResult Show(SqlConnection conn) {
        var name = GetUserInput();
        var sql = BuildQuery(name);
        FetchUser(conn, sql);
        return Ok();
    }
}
`,
};
const REQUEST_READ: Record<string, RegExp> = {
  "app.py": /request\.args\.get/, "UserController.java": /request\.getParameter/, "user.php": /\$_GET/,
  "users_controller.rb": /params\[:username\]/, "UserController.cs": /Request\.Query/,
};

describe("source helper -> query builder -> executing helper, in every engine", () => {
  for (const [file, code] of Object.entries(HELPER_APPS)) {
    it(file, () => {
      // the flow with the longest trace (a builder in another function stays its own, shorter finding)
      const flow = analyzeFile(file, code).indicators.filter(i => i.id === "sql-injection" && i.confidence === 95).sort((a, b) => (b.trace?.length ?? 0) - (a.trace?.length ?? 0))[0];
      expect(flow).toBeDefined();
      const trace = flow!.trace!;
      expect(trace[0].kind).toBe("source");
      expect(trace[0].label).toMatch(REQUEST_READ[file]);
      // through both function boundaries: the builder's parameter and the executing helper's
      expect(trace.filter(s => s.kind === "parameter").length).toBeGreaterThanOrEqual(2);
      expect(trace[trace.length - 1].kind).toBe("sink");
    });
  }

  it("a helper that returns a constant is no source, in every engine", () => {
    const constant: Record<string, [string, string]> = {
      "app.py": ['request.args.get("username")', '"guest"'], "UserController.java": ['request.getParameter("username")', '"guest"'],
      "user.php": ["$_GET['username']", "'guest'"], "users_controller.rb": ["params[:username]", '"guest"'], "UserController.cs": ['Request.Query["username"]', '"guest"'],
    };
    for (const [file, code] of Object.entries(HELPER_APPS)) {
      const [from, to] = constant[file];
      const found = analyzeFile(file, code.replace(from, to)).indicators.filter(i => i.id === "sql-injection" && i.confidence === 95);
      expect({ file, found: found.length }).toEqual({ file, found: 0 });
    }
  });
});
