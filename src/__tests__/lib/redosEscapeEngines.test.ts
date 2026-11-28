import { runScan } from "@/lib/scanner";
import { warmPythonTaintEngine } from "@/lib/astTaintPython";
import { warmGoTaintEngine } from "@/lib/astTaintGo";
import { warmCSharpTaintEngine } from "@/lib/astTaintCSharp";
import { warmPhpTaintEngine } from "@/lib/astTaintPHP";
import { warmRubyTaintEngine } from "@/lib/astTaintRuby";

beforeAll(async () => { await Promise.all([warmPythonTaintEngine(), warmGoTaintEngine(), warmCSharpTaintEngine(), warmPhpTaintEngine(), warmRubyTaintEngine()]); }, 180000);

const redos = (path: string, content: string) =>
  runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files: [{ path, content }] }).files[0].indicators.filter(i => i.id === "redos");

const CASES: Array<[string, string, string, string]> = [
  ["py escaped", "app.py", `from flask import request\nimport re\n\n@app.route("/s")\ndef s():\n    q = request.args.get("q")\n    return str(re.search(re.escape(q), "abc"))\n`, "0"],
  ["py raw", "app.py", `from flask import request\nimport re\n\n@app.route("/s")\ndef s():\n    q = request.args.get("q")\n    return str(re.search(q, "abc"))\n`, "1"],
  ["go escaped", "main.go", `package main\n\nimport (\n\t"net/http"\n\t"regexp"\n)\n\nfunc h(w http.ResponseWriter, r *http.Request) {\n\tq := r.URL.Query().Get("q")\n\tre := regexp.MustCompile(regexp.QuoteMeta(q))\n\t_ = re\n}\n`, "0"],
  ["go raw", "main.go", `package main\n\nimport (\n\t"net/http"\n\t"regexp"\n)\n\nfunc h(w http.ResponseWriter, r *http.Request) {\n\tq := r.URL.Query().Get("q")\n\tre := regexp.MustCompile(q)\n\t_ = re\n}\n`, "1"],
  ["java escaped", "A.java", `import javax.servlet.http.*;\nimport java.util.regex.*;\npublic class A extends HttpServlet {\n  protected void doGet(HttpServletRequest req, HttpServletResponse res) {\n    String q = req.getParameter("q");\n    Pattern p = Pattern.compile(Pattern.quote(q));\n  }\n}\n`, "0"],
  ["java raw", "A.java", `import javax.servlet.http.*;\nimport java.util.regex.*;\npublic class A extends HttpServlet {\n  protected void doGet(HttpServletRequest req, HttpServletResponse res) {\n    String q = req.getParameter("q");\n    Pattern p = Pattern.compile(q);\n  }\n}\n`, "1"],
  ["cs escaped", "A.cs", `using System.Text.RegularExpressions;\nusing Microsoft.AspNetCore.Mvc;\npublic class C : Controller {\n  public IActionResult Get(string q) {\n    var r = new Regex(Regex.Escape(q));\n    return Ok();\n  }\n}\n`, "0"],
  ["cs raw", "A.cs", `using System.Text.RegularExpressions;\nusing Microsoft.AspNetCore.Mvc;\npublic class C : Controller {\n  public IActionResult Get(string q) {\n    var r = new Regex(q);\n    return Ok();\n  }\n}\n`, "1"],
  ["php escaped", "a.php", `<?php\n$q = $_GET['q'];\npreg_match('/' . preg_quote($q, '/') . '/', 'abc');\n`, "0"],
  ["php raw", "a.php", `<?php\n$q = $_GET['q'];\npreg_match('/' . $q . '/', 'abc');\n`, "1"],
  ["ruby escaped", "a.rb", `class C < ApplicationController\n  def s\n    r = Regexp.new(Regexp.escape(params[:q]))\n  end\nend\n`, "0"],
  ["ruby raw", "a.rb", `class C < ApplicationController\n  def s\n    r = Regexp.new(params[:q])\n  end\nend\n`, "1"],
];

describe("regex-escaped input across the language engines (raw input still flagged, escaped input not)", () => {
  for (const [name, path, code, want] of CASES) {
    it(name, () => {
      const n = redos(path, code).length;
      expect(n > 0 ? "1" : "0").toBe(want);
    });
  }
});
