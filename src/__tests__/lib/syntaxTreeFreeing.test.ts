/**
 * @jest-environment node
 *
 * tree-sitter trees live in WebAssembly memory that garbage collection never reclaims: a process that parsed ~50k files
 * without freeing them aborted inside tree-sitter, and every later parse failed (the Juliet C/C++ benchmark silently
 * lost 3751 files of its last category). analyzeFile frees the trees it parsed; runScan frees the ones its cross-file
 * pass parsed, after every file is analysed; nothing frees a tree twice or reads one after it is freed.
 */
import * as runtime from "@/lib/treeSitterRuntime";
import { analyzeFile, runScan } from "@/lib/scanner";
import { warmGoTaintEngine } from "@/lib/astTaintGo";
import { warmPythonTaintEngine } from "@/lib/astTaintPython";
import { warmCppTaintEngine } from "@/lib/astTaintCpp";
import { warmCSharpTaintEngine } from "@/lib/astTaintCSharp";

beforeAll(async () => { await warmGoTaintEngine(); await warmPythonTaintEngine(); await warmCppTaintEngine(); await warmCSharpTaintEngine(); }, 120000);
afterEach(() => jest.restoreAllMocks());

const GO = `package main\n\nimport (\n\t"database/sql"\n\t"net/http"\n)\n\nvar db *sql.DB\n\nfunc handle(w http.ResponseWriter, r *http.Request) {\n\tdb.Query("SELECT * FROM u WHERE id = " + r.URL.Query().Get("id"))\n}\n`;
const C = `#include <stdlib.h>\n#include <stdio.h>\nint main(void) {\n    char cmd[256];\n    snprintf(cmd, sizeof cmd, "ls %s", getenv("DIR"));\n    system(cmd);\n    return 0;\n}\n`;
const PY = `from flask import Flask, request\nimport os\napp = Flask(__name__)\n\n@app.route("/a")\ndef a():\n    os.system("ping " + request.args["h"])\n    return "ok"\n`;
const CS = `using Microsoft.AspNetCore.Mvc;\nusing System.Data.SqlClient;\npublic class A : Controller {\n    private SqlConnection conn;\n    [HttpGet("/a")]\n    public IActionResult B() {\n        new SqlCommand("SELECT * FROM u WHERE id = " + Request.Query["id"], conn).ExecuteReader();\n        return Ok();\n    }\n}\n`;

describe("freeSyntaxTree", () => {
  it("deletes a tree once, however often it is asked", () => {
    const tree = { delete: jest.fn() };
    runtime.freeSyntaxTree({ tree });
    runtime.freeSyntaxTree({ tree });
    expect(tree.delete).toHaveBeenCalledTimes(1);
  });
  it("ignores a missing root", () => {
    expect(() => { runtime.freeSyntaxTree(null); runtime.freeSyntaxTree(undefined); runtime.freeSyntaxTree({}); }).not.toThrow();
  });
});

describe("ownership", () => {
  it("analyzeFile frees the tree it parsed itself", () => {
    const spy = jest.spyOn(runtime, "freeSyntaxTree");
    analyzeFile("main.go", GO);
    expect(spy).toHaveBeenCalledTimes(1);
  });

  it("runScan frees each cross-file tree exactly once, after the files are analysed (analyzeFile leaves them alone)", () => {
    const spy = jest.spyOn(runtime, "freeSyntaxTree");
    const out = runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files: [
      { path: "main.go", content: GO }, { path: "main.c", content: C }, { path: "app.py", content: PY }, { path: "A.cs", content: CS },
    ] });
    const roots = spy.mock.calls.map(c => c[0]).filter(Boolean);
    // one tree per tree-sitter file, none freed twice
    expect(roots.length).toBe(4);
    expect(new Set(roots).size).toBe(4);
    // and the findings are all there: nothing read a freed tree
    const ids = out.files.flatMap(f => f.indicators.map(i => `${f.file_path}:${i.id}`));
    expect(ids).toEqual(expect.arrayContaining(["main.go:sql-injection", "main.c:command-injection", "app.py:command-injection", "A.cs:sql-injection"]));
  });

  it("scanning the same batch twice gives the same findings", () => {
    const batch = { repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files: [
      { path: "main.go", content: GO }, { path: "main.c", content: C }, { path: "app.py", content: PY }, { path: "A.cs", content: CS },
    ] };
    const ids = () => runScan(batch).files.flatMap(f => f.indicators.map(i => `${f.file_path}:${i.id}:${i.line}`)).sort();
    expect(ids()).toEqual(ids());
  });
});
