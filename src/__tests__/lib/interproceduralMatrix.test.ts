/**
 * @jest-environment node
 *
 * Interprocedural taint, end to end: request input read in a helper, passed through a builder / transformation in
 * another function, reaching a sink in a third -- for SQL, command, path, XSS, SSRF and redirect sinks, in Go,
 * Python and JavaScript. Each vulnerable case must be found by the data-flow engine (full confidence), with a trace that starts at
 * the real request read; each safe twin (parameterised, escaped, allow-listed, fixed host, constant) stays silent.
 */
import { analyzeFile } from "@/lib/scanner";
import { warmGoTaintEngine } from "@/lib/astTaintGo";
import { warmPythonTaintEngine } from "@/lib/astTaintPython";

beforeAll(async () => { await warmGoTaintEngine(); await warmPythonTaintEngine(); }, 120000);

const goFile = (imports: string[], decls: string, handler: string) => `package main

import (
${["net/http", ...imports].map(i => `\t"${i}"`).join("\n")}
)

${decls}

func handle(w http.ResponseWriter, r *http.Request) {
${handler}
}
`;
const SRC = `func getInput(r *http.Request) string {\n\treturn r.URL.Query().Get("v")\n}`;
const SRC2 = `${SRC}\n\nfunc normalize(s string) string {\n\treturn strings.TrimSpace(s)\n}`;
const GO_MATRIX: Array<{ name: string; id: string; expect: boolean; code: string }> = [
  { name: "1 direct read -> SQL", id: "sql-injection", expect: true, code: goFile(["database/sql", "fmt"], `var db *sql.DB`,
    `\tv := r.URL.Query().Get("v")\n\tdb.Query(fmt.Sprintf("SELECT * FROM t WHERE c = '%s'", v))`) },
  { name: "2 helper return -> SQL", id: "sql-injection", expect: true, code: goFile(["database/sql", "fmt"], `var db *sql.DB\n\n${SRC}`,
    `\tv := getInput(r)\n\tdb.Query(fmt.Sprintf("SELECT * FROM t WHERE c = '%s'", v))`) },
  { name: "3 two helper returns -> SQL", id: "sql-injection", expect: true, code: goFile(["database/sql", "fmt", "strings"], `var db *sql.DB\n\n${SRC2}`,
    `\tv := normalize(getInput(r))\n\tdb.Query(fmt.Sprintf("SELECT * FROM t WHERE c = '%s'", v))`) },
  { name: "4 struct field -> SQL", id: "sql-injection", expect: true, code: goFile(["database/sql", "fmt"], `var db *sql.DB\n\ntype Filter struct {\n\tName string\n}`,
    `\tf := Filter{Name: r.URL.Query().Get("v")}\n\tdb.Query("SELECT * FROM t WHERE c = '" + f.Name + "'")`) },
  { name: "5 method return -> SQL", id: "sql-injection", expect: true, code: goFile(["database/sql"], `var db *sql.DB\n\ntype Req struct {\n\tr *http.Request\n}\n\nfunc (q Req) Name() string {\n\treturn q.r.URL.Query().Get("v")\n}`,
    `\tq := Req{r: r}\n\tdb.Query("SELECT * FROM t WHERE c = '" + q.Name() + "'")`) },
  { name: "6 clean constant -> SQL (safe)", id: "sql-injection", expect: false, code: goFile(["database/sql", "fmt"], `var db *sql.DB\n\nfunc getName() string {\n\treturn "admin"\n}`,
    `\tv := getName()\n\tdb.Query(fmt.Sprintf("SELECT * FROM t WHERE c = '%s'", v))`) },
  { name: "7 parameterized query (safe)", id: "sql-injection", expect: false, code: goFile(["database/sql"], `var db *sql.DB\n\n${SRC}`,
    `\tv := getInput(r)\n\tdb.Query("SELECT * FROM t WHERE c = $1", v)`) },
  { name: "8 helper return -> command", id: "command-injection", expect: true, code: goFile(["os/exec"], SRC,
    `\tv := getInput(r)\n\texec.Command("sh", "-c", "ping -c 1 "+v).Run()`) },
  { name: "9 helper return -> XSS", id: "xss", expect: true, code: goFile(["fmt"], SRC,
    `\tv := getInput(r)\n\thtml := "<h1>" + v + "</h1>"\n\tfmt.Fprint(w, html)`) },
  { name: "10 helper return -> path", id: "path-traversal", expect: true, code: goFile(["os"], SRC,
    `\tv := getInput(r)\n\tp := "/srv/files/" + v\n\tdata, _ := os.ReadFile(p)\n\tw.Write(data)`) },
  { name: "11 helper return -> SSRF", id: "ssrf", expect: true, code: goFile([], SRC,
    `\tv := getInput(r)\n\tresp, _ := http.Get(v)\n\tdefer resp.Body.Close()`) },
  { name: "12 helper return -> redirect", id: "open-redirect", expect: true, code: goFile([], SRC,
    `\tv := getInput(r)\n\thttp.Redirect(w, r, v, http.StatusFound)`) },
];

const pyApp = (helpers: string, route: string) => `import sqlite3
import subprocess
import requests
from flask import Flask, request, send_file, redirect, make_response

app = Flask(__name__)
conn = sqlite3.connect("app.db")

${helpers}

@app.route("/x")
def handler():
${route}
`;
const PY_MATRIX: Array<{ name: string; id: string; expect: boolean; code: string }> = [
  { name: "04 SQL helper -> builder -> execute", id: "sql-injection", expect: true, code: pyApp(
    `def get_username():\n    return request.args.get("username")\n\ndef build_user_query(username):\n    return "SELECT * FROM users WHERE name = '" + username + "'"`,
    `    username = get_username()\n    query = build_user_query(username)\n    cursor = conn.cursor()\n    cursor.execute(query)\n    return "ok"`) },
  { name: "05 SQL sink inside a helper", id: "sql-injection", expect: true, code: pyApp(
    `def get_username():\n    return request.args.get("username")\n\ndef build_user_query(username):\n    return f"SELECT * FROM users WHERE name = '{username}'"\n\ndef run_query(sql):\n    cursor = conn.cursor()\n    cursor.execute(sql)\n    return cursor.fetchall()`,
    `    rows = run_query(build_user_query(get_username()))\n    return str(rows)`) },
  { name: "06 SQL parameterised (safe)", id: "sql-injection", expect: false, code: pyApp(
    `def get_username():\n    return request.args.get("username")`,
    `    username = get_username()\n    cursor = conn.cursor()\n    cursor.execute("SELECT * FROM users WHERE name = ?", (username,))\n    return "ok"`) },
  { name: "07 command helper -> executor -> subprocess", id: "command-injection", expect: true, code: pyApp(
    `def get_command():\n    return request.args.get("cmd")\n\ndef execute_user_command(cmd):\n    return subprocess.run("echo " + cmd, shell=True, capture_output=True)`,
    `    result = execute_user_command(get_command())\n    return result.stdout`) },
  { name: "08 command argv list, no shell (safe)", id: "command-injection", expect: false, code: pyApp(
    `def get_command():\n    return request.args.get("cmd")\n\ndef execute_user_command(cmd):\n    return subprocess.run(["echo", "--", cmd], capture_output=True)`,
    `    result = execute_user_command(get_command())\n    return result.stdout`) },
  { name: "10 path helper -> resolver -> send_file", id: "path-traversal", expect: true, code: pyApp(
    `def get_requested_file():\n    return request.args.get("file")\n\ndef resolve_file(name):\n    return "/srv/files/" + name`,
    `    path = resolve_file(get_requested_file())\n    return send_file(path)`) },
  { name: "11 path basename (safe)", id: "path-traversal", expect: false, code: pyApp(
    `import os\n\ndef get_requested_file():\n    return request.args.get("file")\n\ndef resolve_file(name):\n    return os.path.join("/srv/files", os.path.basename(name))`,
    `    path = resolve_file(get_requested_file())\n    return send_file(path)`) },
  { name: "13 XSS helper -> renderer -> response", id: "xss", expect: true, code: pyApp(
    `def get_display_name():\n    return request.args.get("name")\n\ndef render_user(name):\n    return "<h1>Hello " + name + "</h1>"`,
    `    return make_response(render_user(get_display_name()))`) },
  { name: "14 XSS escaped (safe)", id: "xss", expect: false, code: pyApp(
    `from markupsafe import escape\n\ndef get_display_name():\n    return request.args.get("name")\n\ndef render_user(name):\n    return "<h1>Hello " + str(escape(name)) + "</h1>"`,
    `    return make_response(render_user(get_display_name()))`) },
  { name: "16 SSRF helper -> fetcher -> requests.get", id: "ssrf", expect: true, code: pyApp(
    `def get_remote_url():\n    return request.args.get("url")\n\ndef fetch_remote_resource(url):\n    return requests.get(url, timeout=5).text`,
    `    return fetch_remote_resource(get_remote_url())`) },
  { name: "17 SSRF fixed host (safe)", id: "ssrf", expect: false, code: pyApp(
    `def get_remote_url():\n    return request.args.get("path")\n\ndef fetch_remote_resource(path):\n    return requests.get("https://api.example.com/" + path, timeout=5).text`,
    `    return fetch_remote_resource(get_remote_url())`) },
  { name: "18 redirect helper -> performer -> redirect", id: "open-redirect", expect: true, code: pyApp(
    `def get_redirect_target():\n    return request.args.get("next")\n\ndef perform_redirect(target):\n    return redirect(target)`,
    `    return perform_redirect(get_redirect_target())`) },
  { name: "19 redirect allow-listed (safe)", id: "open-redirect", expect: false, code: pyApp(
    `ALLOWED_TARGETS = {"/home", "/profile", "/settings"}\n\ndef get_redirect_target():\n    return request.args.get("next")\n\ndef perform_redirect(target):\n    if target not in ALLOWED_TARGETS:\n        return redirect("/")\n    return redirect(target)`,
    `    return perform_redirect(get_redirect_target())`) },
  { name: "19b relative-only check is bypassable with /\\\\evil.com (still reported)", id: "open-redirect", expect: true, code: pyApp(
    `from urllib.parse import urlparse\n\ndef get_redirect_target():\n    return request.args.get("next")\n\ndef perform_redirect(target):\n    if urlparse(target).netloc or not target.startswith("/") or target.startswith("//"):\n        return redirect("/")\n    return redirect(target)`,
    `    return perform_redirect(get_redirect_target())`) },
];

const jsApp = (helpers: string, route: string) => `const express = require("express");
const { exec } = require("child_process");
const axios = require("axios");
const app = express();
const db = require("./db");

${helpers}

app.get("/x", (req, res) => {
${route}
});
`;
const JS_SRC = `function getInput(req) {\n  return req.query.v;\n}`;
const JS_MATRIX: Array<{ name: string; id: string; expect: boolean; code: string }> = [
  { name: "1 direct read -> SQL", id: "sql-injection", expect: true, code: jsApp("",
    `  const v = req.query.v;\n  db.query("SELECT * FROM t WHERE c = '" + v + "'");\n  res.send("ok");`) },
  { name: "2 helper return -> SQL", id: "sql-injection", expect: true, code: jsApp(JS_SRC,
    `  const v = getInput(req);\n  db.query("SELECT * FROM t WHERE c = '" + v + "'");\n  res.send("ok");`) },
  { name: "3 two helper returns -> SQL", id: "sql-injection", expect: true, code: jsApp(`${JS_SRC}\nfunction normalize(s) {\n  return s.trim();\n}`,
    `  const v = normalize(getInput(req));\n  db.query(\`SELECT * FROM t WHERE c = '\${v}'\`);\n  res.send("ok");`) },
  { name: "4 object field -> SQL", id: "sql-injection", expect: true, code: jsApp("",
    `  const filter = { name: req.query.v };\n  db.query("SELECT * FROM t WHERE c = '" + filter.name + "'");\n  res.send("ok");`) },
  { name: "5 method return (request kept on this) -> SQL", id: "sql-injection", expect: true, code: jsApp(
    `class Params {\n  constructor(req) { this.req = req; }\n  name() { return this.req.query.v; }\n}`,
    `  const p = new Params(req);\n  db.query("SELECT * FROM t WHERE c = '" + p.name() + "'");\n  res.send("ok");`) },
  { name: "6 clean constant -> SQL (safe)", id: "sql-injection", expect: false, code: jsApp(`function getName() {\n  return "admin";\n}`,
    `  const v = getName();\n  db.query("SELECT * FROM t WHERE c = '" + v + "'");\n  res.send("ok");`) },
  { name: "7 parameterized query (safe)", id: "sql-injection", expect: false, code: jsApp(JS_SRC,
    `  const v = getInput(req);\n  db.query("SELECT * FROM t WHERE c = ?", [v]);\n  res.send("ok");`) },
  { name: "8 helper -> builder -> SQL helper", id: "sql-injection", expect: true, code: jsApp(
    `${JS_SRC}\nfunction buildQuery(v) {\n  return "SELECT * FROM t WHERE c = '" + v + "'";\n}\nfunction runQuery(sql) {\n  return db.query(sql);\n}`,
    `  runQuery(buildQuery(getInput(req)));\n  res.send("ok");`) },
  { name: "9 helper -> executor -> exec", id: "command-injection", expect: true, code: jsApp(
    `${JS_SRC}\nfunction runCommand(cmd) {\n  return exec("ping -c 1 " + cmd);\n}`,
    `  runCommand(getInput(req));\n  res.send("ok");`) },
  { name: "10 helper -> resolver -> sendFile", id: "path-traversal", expect: true, code: jsApp(
    `${JS_SRC}\nfunction resolveFile(name) {\n  return "/srv/files/" + name;\n}`,
    `  res.sendFile(resolveFile(getInput(req)));`) },
  { name: "11 helper -> renderer -> response", id: "xss", expect: true, code: jsApp(
    `${JS_SRC}\nfunction renderUser(name) {\n  return "<h1>" + name + "</h1>";\n}`,
    `  res.send(renderUser(getInput(req)));`) },
  { name: "12 helper -> fetcher -> axios", id: "ssrf", expect: true, code: jsApp(
    `${JS_SRC}\nfunction fetchRemote(url) {\n  return axios.get(url);\n}`,
    `  fetchRemote(getInput(req));\n  res.send("ok");`) },
  { name: "13 helper -> redirect", id: "open-redirect", expect: true, code: jsApp(
    `${JS_SRC}\nfunction performRedirect(res, target) {\n  return res.redirect(target);\n}`,
    `  performRedirect(res, getInput(req));`) },
];

describe("JavaScript: the constant proof is for const locals only", () => {
  it("a let appended to later (a streamed body) keeps its SQL finding", () => {
    const code = jsApp("", `  let body = "";\n  req.on("data", c => body += c);\n  req.on("end", () => db.query("SELECT * FROM t WHERE c = '" + body + "'"));`);
    expect(analyzeFile("app.js", code).indicators.filter(i => i.id === "sql-injection").length).toBeGreaterThan(0);
  });
});

const REQUEST_READ =/r\.URL\.Query\(\)\.Get|request\.args\.get|req\.query\.v/;

for (const [lang, file, matrix] of [["Go", "main.go", GO_MATRIX], ["Python", "app.py", PY_MATRIX], ["JavaScript", "app.js", JS_MATRIX]] as const) {
  describe(`${lang}: source -> helper -> transformation -> sink`, () => {
    for (const c of matrix) {
      it(c.name, () => {
        const found = analyzeFile(file, c.code).indicators.filter(i => i.id === c.id);
        if (!c.expect) { expect(found).toHaveLength(0); return; }
        // the data-flow engine's own finding, not a line-pattern match, with a trace from the request read to the sink
        const flow = found.filter(f => f.confidence === 95 && (f.trace?.length ?? 0) >= 2).sort((a, b) => (b.trace?.length ?? 0) - (a.trace?.length ?? 0))[0];
        expect(flow).toBeDefined();
        expect(flow!.trace![0].kind).toBe("source");
        expect(flow!.trace![0].label).toMatch(REQUEST_READ);
        expect(flow!.trace![flow!.trace!.length - 1].kind).toBe("sink");
      });
    }
  });
}
