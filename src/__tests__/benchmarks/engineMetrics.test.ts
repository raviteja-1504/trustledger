/**
 * @jest-environment node
 *
 * Labelled mini-benchmark across the data-flow engines: vulnerable snippets (must be found) and their safe twins (must
 * not be), run through the real analyzeFile. Reports true/false positives and negatives, precision, recall and F1 per
 * language, and fails if either drops below the floors. This is a regression harness over a small hand-written corpus,
 * not a substitute for scoring against a large external benchmark: a perfect score here says nothing about code the
 * corpus does not resemble.
 */
import { analyzeFile } from "@/lib/scanner";
import { warmPythonTaintEngine } from "@/lib/astTaintPython";
import { warmGoTaintEngine } from "@/lib/astTaintGo";
import { warmCSharpTaintEngine } from "@/lib/astTaintCSharp";
import { warmPhpTaintEngine } from "@/lib/astTaintPHP";
import { warmRubyTaintEngine } from "@/lib/astTaintRuby";
import { warmKotlinTaintEngine } from "@/lib/astTaintKotlin";
import { warmRustTaintEngine } from "@/lib/astTaintRust";
import { warmCppTaintEngine } from "@/lib/astTaintCpp";

interface Case { lang: string; name: string; file: string; code: string; id: string; vulnerable: boolean }
const V = (lang: string, name: string, file: string, id: string, code: string): Case => ({ lang, name, file, code, id, vulnerable: true });
const S = (lang: string, name: string, file: string, id: string, code: string): Case => ({ lang, name, file, code, id, vulnerable: false });

const CASES: Case[] = [
  // ── JavaScript ──
  V("javascript", "exec concat", "src/a.js", "command-injection", `const { exec } = require("child_process");\napp.get("/a", (req, res) => { exec("ls " + req.query.d); res.send("ok"); });\n`),
  V("javascript", "sql concat", "src/a.js", "sql-injection", `app.get("/a", (req, res) => { db.query("SELECT * FROM u WHERE id = " + req.params.id, () => res.send("ok")); });\n`),
  V("javascript", "path read", "src/a.js", "path-traversal", `const fs = require("fs");\napp.get("/a", (req, res) => { fs.readFile(req.query.f, "utf8", (e, d) => res.send(d)); });\n`),
  S("javascript", "execFile fixed", "src/a.js", "command-injection", `const { execFile } = require("child_process");\napp.get("/a", (req, res) => { execFile("ls", ["-l"]); res.send("ok"); });\n`),
  S("javascript", "sql bound", "src/a.js", "sql-injection", `app.get("/a", (req, res) => { db.query("SELECT * FROM u WHERE id = ?", [req.params.id], () => res.send("ok")); });\n`),
  S("javascript", "path basename", "src/a.js", "path-traversal", `const fs = require("fs"); const path = require("path");\napp.get("/a", (req, res) => { fs.readFile(path.join("/data", path.basename(req.query.f)), "utf8", (e, d) => res.send(d)); });\n`),
  // ── Python ──
  V("python", "os.system", "app/a.py", "command-injection", `import os\nfrom flask import request\n\ndef run():\n    os.system("ls " + request.args.get("d"))\n`),
  V("python", "sql concat", "app/a.py", "sql-injection", `from flask import request\n\ndef run(cursor):\n    cursor.execute("SELECT * FROM u WHERE id=" + request.args["id"])\n`),
  V("python", "open", "app/a.py", "path-traversal", `from flask import request\n\ndef run():\n    return open(request.args["f"]).read()\n`),
  S("python", "argv list", "app/a.py", "command-injection", `import subprocess\nfrom flask import request\n\ndef run():\n    subprocess.run(["ls", "-l"])\n`),
  S("python", "sql bound", "app/a.py", "sql-injection", `from flask import request\n\ndef run(cursor):\n    cursor.execute("SELECT * FROM u WHERE id=%s", (request.args["id"],))\n`),
  S("python", "int cast", "app/a.py", "command-injection", `import os\nfrom flask import request\n\ndef run():\n    os.system("sleep " + str(int(request.args["n"])))\n`),
  // ── Java ──
  V("java", "exec concat", "src/A.java", "command-injection", `import javax.servlet.http.*;\npublic class A extends HttpServlet {\n  protected void doGet(HttpServletRequest req, HttpServletResponse res) throws Exception {\n    Runtime.getRuntime().exec("ls " + req.getParameter("d"));\n  }\n}\n`),
  V("java", "sql concat", "src/A.java", "sql-injection", `import javax.servlet.http.*;\nimport java.sql.*;\npublic class A extends HttpServlet {\n  protected void doGet(HttpServletRequest req, HttpServletResponse res) throws Exception {\n    Connection c = null;\n    c.createStatement().executeQuery("SELECT * FROM u WHERE id=" + req.getParameter("id"));\n  }\n}\n`),
  V("java", "file open", "src/A.java", "path-traversal", `import javax.servlet.http.*;\nimport java.io.*;\npublic class A extends HttpServlet {\n  protected void doGet(HttpServletRequest req, HttpServletResponse res) throws Exception {\n    new FileInputStream(new File(req.getParameter("f")));\n  }\n}\n`),
  S("java", "exec fixed", "src/A.java", "command-injection", `import javax.servlet.http.*;\npublic class A extends HttpServlet {\n  protected void doGet(HttpServletRequest req, HttpServletResponse res) throws Exception {\n    Runtime.getRuntime().exec(new String[]{"ls", "-l"});\n  }\n}\n`),
  S("java", "prepared", "src/A.java", "sql-injection", `import javax.servlet.http.*;\nimport java.sql.*;\npublic class A extends HttpServlet {\n  protected void doGet(HttpServletRequest req, HttpServletResponse res) throws Exception {\n    Connection c = null;\n    PreparedStatement ps = c.prepareStatement("SELECT * FROM u WHERE id=?");\n    ps.setString(1, req.getParameter("id"));\n    ps.executeQuery();\n  }\n}\n`),
  S("java", "int parse", "src/A.java", "command-injection", `import javax.servlet.http.*;\npublic class A extends HttpServlet {\n  protected void doGet(HttpServletRequest req, HttpServletResponse res) throws Exception {\n    int n = Integer.parseInt(req.getParameter("n"));\n    Runtime.getRuntime().exec("sleep " + n);\n  }\n}\n`),
  // ── Go ──
  V("golang", "exec sh -c", "main.go", "command-injection", `package main\nimport ("net/http"; "os/exec")\nfunc h(w http.ResponseWriter, r *http.Request) {\n\texec.Command("sh", "-c", "ls "+r.URL.Query().Get("d")).Run()\n}\n`),
  V("golang", "sql concat", "main.go", "sql-injection", `package main\nimport ("net/http"; "database/sql")\nfunc h(w http.ResponseWriter, r *http.Request, db *sql.DB) {\n\tdb.Query("SELECT * FROM u WHERE id = " + r.URL.Query().Get("id"))\n}\n`),
  V("golang", "os.Open", "main.go", "path-traversal", `package main\nimport ("net/http"; "os")\nfunc h(w http.ResponseWriter, r *http.Request) {\n\tos.Open(r.URL.Query().Get("f"))\n}\n`),
  S("golang", "exec fixed", "main.go", "command-injection", `package main\nimport ("net/http"; "os/exec")\nfunc h(w http.ResponseWriter, r *http.Request) {\n\texec.Command("ls", "-l").Run()\n}\n`),
  S("golang", "sql bound", "main.go", "sql-injection", `package main\nimport ("net/http"; "database/sql")\nfunc h(w http.ResponseWriter, r *http.Request, db *sql.DB) {\n\tdb.Query("SELECT * FROM u WHERE id = $1", r.URL.Query().Get("id"))\n}\n`),
  S("golang", "atoi", "main.go", "command-injection", `package main\nimport ("net/http"; "os/exec"; "strconv")\nfunc h(w http.ResponseWriter, r *http.Request) {\n\tn, _ := strconv.Atoi(r.URL.Query().Get("n"))\n\texec.Command("sleep", strconv.Itoa(n)).Run()\n}\n`),
  // ── C# ──
  V("csharp", "Process.Start", "Controllers/A.cs", "command-injection", `using System.Diagnostics; using Microsoft.AspNetCore.Mvc;\npublic class AController : Controller {\n  public IActionResult Run(string d) { Process.Start("cmd", "/c dir " + d); return Ok(); }\n}\n`),
  V("csharp", "SqlCommand concat", "Controllers/A.cs", "sql-injection", `using System.Data.SqlClient; using Microsoft.AspNetCore.Mvc;\npublic class AController : Controller {\n  public IActionResult Run(string id, SqlConnection c) { var cmd = new SqlCommand("SELECT * FROM u WHERE id=" + id, c); cmd.ExecuteReader(); return Ok(); }\n}\n`),
  V("csharp", "File.ReadAllText", "Controllers/A.cs", "path-traversal", `using System.IO; using Microsoft.AspNetCore.Mvc;\npublic class AController : Controller {\n  public IActionResult Run(string f) { return Content(File.ReadAllText(f)); }\n}\n`),
  S("csharp", "process fixed", "Controllers/A.cs", "command-injection", `using System.Diagnostics; using Microsoft.AspNetCore.Mvc;\npublic class AController : Controller {\n  public IActionResult Run(string d) { Process.Start("cmd", "/c dir"); return Ok(); }\n}\n`),
  S("csharp", "sql parameter", "Controllers/A.cs", "sql-injection", `using System.Data.SqlClient; using Microsoft.AspNetCore.Mvc;\npublic class AController : Controller {\n  public IActionResult Run(string id, SqlConnection c) { var cmd = new SqlCommand("SELECT * FROM u WHERE id=@id", c); cmd.Parameters.AddWithValue("@id", id); cmd.ExecuteReader(); return Ok(); }\n}\n`),
  S("csharp", "GetFileName", "Controllers/A.cs", "path-traversal", `using System.IO; using Microsoft.AspNetCore.Mvc;\npublic class AController : Controller {\n  public IActionResult Run(string f) { return Content(File.ReadAllText(Path.Combine("/data", Path.GetFileName(f)))); }\n}\n`),
  // ── PHP ──
  V("php", "system", "a.php", "command-injection", `<?php\nsystem("ls " . $_GET['d']);\n`),
  V("php", "mysqli concat", "a.php", "sql-injection", `<?php\n$c = mysqli_connect("h", "u", "p", "d");\nmysqli_query($c, "SELECT * FROM u WHERE id = " . $_GET['id']);\n`),
  V("php", "file_get_contents", "a.php", "path-traversal", `<?php\necho file_get_contents($_GET['f']);\n`),
  S("php", "escapeshellarg", "a.php", "command-injection", `<?php\nsystem("ls " . escapeshellarg($_GET['d']));\n`),
  S("php", "prepared", "a.php", "sql-injection", `<?php\n$pdo = new PDO("sqlite::memory:");\n$st = $pdo->prepare("SELECT * FROM u WHERE id = ?");\n$st->execute([$_GET['id']]);\n`),
  S("php", "basename", "a.php", "path-traversal", `<?php\necho file_get_contents("/data/" . basename($_GET['f']));\n`),
  // ── Ruby ──
  V("ruby", "system interp", "app/controllers/a_controller.rb", "command-injection", `class AController < ApplicationController\n  def run\n    system("ls #{params[:d]}")\n  end\nend\n`),
  V("ruby", "where interp", "app/controllers/a_controller.rb", "sql-injection", `class AController < ApplicationController\n  def run\n    User.where("id = #{params[:id]}")\n  end\nend\n`),
  V("ruby", "File.read", "app/controllers/a_controller.rb", "path-traversal", `class AController < ApplicationController\n  def run\n    render plain: File.read(params[:f])\n  end\nend\n`),
  S("ruby", "system argv", "app/controllers/a_controller.rb", "command-injection", `class AController < ApplicationController\n  def run\n    system("ls", "-l")\n  end\nend\n`),
  S("ruby", "where hash", "app/controllers/a_controller.rb", "sql-injection", `class AController < ApplicationController\n  def run\n    User.where(id: params[:id])\n  end\nend\n`),
  S("ruby", "basename", "app/controllers/a_controller.rb", "path-traversal", `class AController < ApplicationController\n  def run\n    render plain: File.read(File.join("/data", File.basename(params[:f])))\n  end\nend\n`),
  // ── Kotlin ──
  V("kotlin", "exec", "src/A.kt", "command-injection", `@RestController\nclass A {\n  @GetMapping("/a")\n  fun run(@RequestParam d: String): String { Runtime.getRuntime().exec("ls " + d); return "ok" }\n}\n`),
  V("kotlin", "jdbc concat", "src/A.kt", "sql-injection", `@RestController\nclass A(private val jdbc: JdbcTemplate) {\n  @GetMapping("/a")\n  fun run(@RequestParam id: String): Any = jdbc.queryForList("SELECT * FROM u WHERE id = '" + id + "'")\n}\n`),
  V("kotlin", "File", "src/A.kt", "path-traversal", `@RestController\nclass A {\n  @GetMapping("/a")\n  fun run(@RequestParam f: String): String = java.io.File(f).readText()\n}\n`),
  S("kotlin", "exec array", "src/A.kt", "command-injection", `@RestController\nclass A {\n  @GetMapping("/a")\n  fun run(@RequestParam d: String): String { Runtime.getRuntime().exec(arrayOf("ls", "-l")); return "ok" }\n}\n`),
  S("kotlin", "jdbc bound", "src/A.kt", "sql-injection", `@RestController\nclass A(private val jdbc: JdbcTemplate) {\n  @GetMapping("/a")\n  fun run(@RequestParam id: String): Any = jdbc.queryForList("SELECT * FROM u WHERE id = ?", id)\n}\n`),
  S("kotlin", "toInt", "src/A.kt", "command-injection", `@RestController\nclass A {\n  @GetMapping("/a")\n  fun run(@RequestParam n: String): String { Runtime.getRuntime().exec("sleep " + n.toInt()); return "ok" }\n}\n`),
  // ── Rust ──
  V("rust", "Command", "src/a.rs", "command-injection", `use std::process::Command;\nuse axum::extract::Query;\n#[derive(serde::Deserialize)]\npub struct P { pub d: String }\npub async fn run(Query(p): Query<P>) -> String {\n    let _ = Command::new("sh").arg("-c").arg(format!("ls {}", p.d)).spawn();\n    "ok".to_string()\n}\n`),
  V("rust", "sqlx format", "src/a.rs", "sql-injection", `use axum::extract::Query;\n#[derive(serde::Deserialize)]\npub struct P { pub id: String }\npub async fn run(Query(p): Query<P>, pool: sqlx::PgPool) -> String {\n    let _ = sqlx::query(&format!("SELECT * FROM u WHERE id = '{}'", p.id)).fetch_all(&pool).await;\n    "ok".to_string()\n}\n`),
  V("rust", "fs read", "src/a.rs", "path-traversal", `use axum::extract::Query;\n#[derive(serde::Deserialize)]\npub struct P { pub f: String }\npub async fn run(Query(p): Query<P>) -> String {\n    std::fs::read_to_string(&p.f).unwrap_or_default()\n}\n`),
  S("rust", "Command fixed", "src/a.rs", "command-injection", `use std::process::Command;\nuse axum::extract::Query;\n#[derive(serde::Deserialize)]\npub struct P { pub d: String }\npub async fn run(Query(p): Query<P>) -> String {\n    let _ = Command::new("ls").arg("-l").spawn();\n    let _ = &p;\n    "ok".to_string()\n}\n`),
  S("rust", "sqlx bind", "src/a.rs", "sql-injection", `use axum::extract::Query;\n#[derive(serde::Deserialize)]\npub struct P { pub id: String }\npub async fn run(Query(p): Query<P>, pool: sqlx::PgPool) -> String {\n    let _ = sqlx::query("SELECT * FROM u WHERE id = $1").bind(&p.id).fetch_all(&pool).await;\n    "ok".to_string()\n}\n`),
  S("rust", "closure never run", "src/a.rs", "command-injection", `use std::process::Command;\nuse axum::extract::Query;\n#[derive(serde::Deserialize)]\npub struct P { pub d: String }\npub async fn run(Query(p): Query<P>) -> String {\n    let _task = || { Command::new(&p.d).spawn() };\n    "ok".to_string()\n}\n`),
  // ── C/C++ ──
  V("cpp", "system argv", "src/a.cpp", "command-injection", `#include <cstdlib>\nint main(int argc, char** argv) { system(argv[1]); return 0; }\n`),
  V("cpp", "use after free", "src/a.cpp", "use-after-free", `#include <cstdlib>\nint main() { char* p = (char*)malloc(8); if (!p) return 1; free(p); p[0] = 'a'; return 0; }\n`),
  V("cpp", "fopen argv", "src/a.cpp", "path-traversal", `#include <cstdio>\nint main(int argc, char** argv) { FILE* f = fopen(argv[1], "r"); if (f) fclose(f); return 0; }\n`),
  S("cpp", "system fixed", "src/a.cpp", "command-injection", `#include <cstdlib>\nint main(int argc, char** argv) { system("ls"); return 0; }\n`),
  S("cpp", "freed then reassigned", "src/a.cpp", "use-after-free", `#include <cstdlib>\nint main() { char* p = (char*)malloc(8); if (!p) return 1; free(p); p = (char*)malloc(8); if (!p) return 1; p[0] = 'a'; free(p); return 0; }\n`),
  S("cpp", "ifdef safe arm only", "src/a.cpp", "command-injection", `#include <cstdlib>\nint main(int argc, char** argv) {\n  const char* c;\n#ifdef A\n  c = "ls";\n#else\n  c = "dir";\n#endif\n  system(c);\n  return 0;\n}\n`),
];

beforeAll(async () => {
  await Promise.all([warmPythonTaintEngine(), warmGoTaintEngine(), warmCSharpTaintEngine(), warmPhpTaintEngine(), warmRubyTaintEngine(), warmKotlinTaintEngine(), warmRustTaintEngine(), warmCppTaintEngine()]);
}, 120000);

interface Tally { tp: number; fp: number; fn: number; tn: number; misses: string[] }
const tallies = new Map<string, Tally>();

describe("labelled engine benchmark", () => {
  for (const c of CASES) {
    it(`${c.lang}: ${c.name} (${c.vulnerable ? "vulnerable" : "safe"})`, () => {
      const found = analyzeFile(c.file, c.code).indicators.some(i => i.id === c.id);
      const t = tallies.get(c.lang) ?? { tp: 0, fp: 0, fn: 0, tn: 0, misses: [] };
      if (c.vulnerable) { if (found) t.tp++; else { t.fn++; t.misses.push(`FN ${c.name}`); } }
      else if (found) { t.fp++; t.misses.push(`FP ${c.name}`); } else t.tn++;
      tallies.set(c.lang, t);
    });
  }

  it("reports per-language and overall precision / recall, and holds the floors", () => {
    const rows: string[] = ["language      TP FP FN TN  precision recall  F1"];
    const all: Tally = { tp: 0, fp: 0, fn: 0, tn: 0, misses: [] };
    const ratio = (a: number, b: number) => (b === 0 ? 1 : a / b);
    for (const [lang, t] of tallies) {
      const p = ratio(t.tp, t.tp + t.fp), r = ratio(t.tp, t.tp + t.fn), f1 = p + r === 0 ? 0 : (2 * p * r) / (p + r);
      rows.push(`${lang.padEnd(13)} ${String(t.tp).padStart(2)} ${String(t.fp).padStart(2)} ${String(t.fn).padStart(2)} ${String(t.tn).padStart(2)}  ${p.toFixed(2).padStart(9)} ${r.toFixed(2).padStart(6)} ${f1.toFixed(2).padStart(5)}${t.misses.length ? "   " + t.misses.join("; ") : ""}`);
      all.tp += t.tp; all.fp += t.fp; all.fn += t.fn; all.tn += t.tn;
    }
    const P = ratio(all.tp, all.tp + all.fp), R = ratio(all.tp, all.tp + all.fn);
    rows.push(`${"ALL".padEnd(13)} ${String(all.tp).padStart(2)} ${String(all.fp).padStart(2)} ${String(all.fn).padStart(2)} ${String(all.tn).padStart(2)}  ${P.toFixed(2).padStart(9)} ${R.toFixed(2).padStart(6)}`);
    console.log("\n" + rows.join("\n"));
    expect(tallies.size).toBe(new Set(CASES.map(c => c.lang)).size);
    expect(P).toBeGreaterThanOrEqual(0.9);
    expect(R).toBeGreaterThanOrEqual(0.8);
  });
});
