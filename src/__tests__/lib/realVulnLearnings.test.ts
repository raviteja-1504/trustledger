/**
 * @jest-environment node
 *
 * What the RealVuln benchmark (kolega-ai/Real-Vuln-Benchmark, 140 Python + TS/JS repos) taught us, as regressions:
 *  - a vendored copy of a library is third-party code, not the customer's: its own `.innerHTML = value` is not their XSS
 *  - a response object built with JsonResponse/jsonify and returned later is JSON, not an HTML body
 *  - res.send(<database record>) is JSON, not reflected XSS
 */
import { runScan, looksVendored } from "@/lib/scanner";
import { warmPythonTaintEngine } from "@/lib/astTaintPython";

beforeAll(async () => { await warmPythonTaintEngine(); }, 120000);

const scan = (files: Array<[string, string]>) =>
  runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files: files.map(([path, content]) => ({ path, content })) });
const indicators = (files: Array<[string, string]>, file: string) => scan(files).files.find(f => f.file_path === file)!.indicators;

describe("vendored libraries are third-party code", () => {
  it("recognises them by directory, by the library's own banner, and by an unmistakable file name", () => {
    for (const p of [
      "node_modules/lodash/lodash.js", "vendor/github.com/x/y/z.go", "src/third_party/zlib/inflate.c", "app/Vendors/lib.php",
      "public/plugins/datatables/jquery.dataTables.js", "static/vendor/foo.js", "assets/js/libs/thing.js",
      "static/jquery/jquery.slim.js", "static/js/html5.js", "public/js/jquery-3.6.0.min.js", "web/js/bootstrap.bundle.js", "js/sweetalert2.js",
    ]) expect(looksVendored(p, "var x = 1;")).toBe(true);
    expect(looksVendored("public/js/a.js", "/*! jQuery v3.6.0 | (c) OpenJS Foundation */\nfoo()")).toBe(true);
    expect(looksVendored("js/b.js", "/*!\n * Select2 4.0.13\n * https://select2.github.io\n */")).toBe(true);
  });

  it("does not take the customer's own code for a library", () => {
    for (const p of [
      "src/app/page.tsx", "server/routes/users.js", "static/js/app.js", "public/js/checkout.js", "src/lib/jquery-helpers.ts",
      "assets/js/main.js", "src/components/Chart.tsx", "app/vendor_portal/views.py", "src/vendored.ts",
    ]) expect(looksVendored(p, "export const x = 1;")).toBe(false);
    // a comment that merely mentions a library is not its banner, and only the top of the file counts
    expect(looksVendored("static/js/app.js", "// we use jQuery 3.6 for the carousel\nfoo()")).toBe(false);
    expect(looksVendored("static/js/app.js", `${"x\n".repeat(400)}/*! jQuery v3.6.0 */`)).toBe(false);
  });

  it("a vendored library's innerHTML is kept as third_party evidence, while the same code in the app is the customer's", () => {
    const code = "function render(el, value) {\n  el.innerHTML = value;\n}\n";
    const vendored = indicators([["public/plugins/sweetalert2/sweetalert2.js", code]], "public/plugins/sweetalert2/sweetalert2.js");
    const xssIn = (list: typeof vendored) => list.filter(i => i.id === "xss");
    expect(xssIn(vendored).length).toBeGreaterThan(0);
    expect(xssIn(vendored).every(i => i.codeCategory === "third_party")).toBe(true);
    const own = indicators([["src/render.js", code]], "src/render.js");
    expect(xssIn(own).length).toBeGreaterThan(0);
    expect(xssIn(own).every(i => i.codeCategory !== "third_party")).toBe(true);
  });

  it("a real secret in a vendored file is still the customer's problem", () => {
    const key = `const k = "AKIA${"IOSFODNN7EXAMPLE"}";\n`;
    const found = indicators([["vendor/lib/config.js", key]], "vendor/lib/config.js");
    for (const i of found.filter(x => x.id === "hardcoded-secret" || x.id === "high-entropy-secret")) expect(i.codeCategory).toBe("application");
  });
});

describe("a JSON response object returned later is not an HTML body (Python)", () => {
  const view = (body: string) => `from django.http import JsonResponse

def handler(request):
${body}
`;
  const xss = (src: string) => indicators([["views.py", src]], "views.py").filter(i => i.id === "xss");

  it("JsonResponse held in a variable, headers set on it, then returned: not XSS", () => {
    expect(xss(view(`    origin = request.headers.get("origin", "*")
    response = JsonResponse({"origin": origin})
    response["Access-Control-Allow-Origin"] = origin
    return response`))).toHaveLength(0);
  });

  it("an HTML body built from the same input still is XSS", () => {
    const src = `from flask import request

@app.route("/hi")
def hi():
    name = request.args.get("name")
    return "<h1>" + name + "</h1>"
`;
    expect(xss(src).length).toBeGreaterThan(0);
  });
});

describe("sending a stored record is not reflected XSS (Express)", () => {
  const route = (body: string) => `const express = require("express");
const router = express.Router();
router.get("/u/:id", async (req, res) => {
${body}
});
`;
  const xss = (src: string) => indicators([["routes/u.js", src]], "routes/u.js").filter(i => i.id === "xss");

  it("res.send(record) where the request only supplied the lookup key: not XSS", () => {
    expect(xss(route(`  const user = await User.findById(req.params.id);
  res.send(user);`))).toHaveLength(0);
    expect(xss(route(`  const items = await db.query("SELECT * FROM n WHERE owner = ?", [req.query.o]);
  res.send(items);`))).toHaveLength(0);
  });

  it("res.send of a string built from the request is still XSS", () => {
    expect(xss(route(`  const html = "<p>" + req.query.name + "</p>";
  res.send(html);`)).length).toBeGreaterThan(0);
  });
});

describe("a command or code that is a constant is not an injection (DataFlowBench negative cases)", () => {
  const evalExec = (path: string, src: string) => indicators([[path, src]], path).filter(i => i.id === "eval-exec" || i.id === "command-injection");

  it("a plain string constant passed to os.system / eval / execSync / exec: not reported", () => {
    expect(evalExec("run.py", `import os\n\ndef run():\n    os.system("clean")\n    os.system('ls -la')\n`)).toHaveLength(0);
    expect(evalExec("run.js", `function run() {\n  eval("clean");\n  eval(\`1 + 1\`);\n}\n`)).toHaveLength(0);
    expect(evalExec("build.js", `const { execSync } = require("child_process");\nexecSync("npm run build", { stdio: "inherit" });\n`)).toHaveLength(0);
    expect(evalExec("s.py", `import subprocess\nsubprocess.call("make all", shell=True)\n`)).toHaveLength(0);
  });

  it("anything built into the command is still reported: concatenation, formatting, f-strings, template interpolation, a variable", () => {
    expect(evalExec("a.py", `import os\ndef f(x):\n    os.system("ls " + x)\n`).length).toBeGreaterThan(0);
    expect(evalExec("b.py", `import os\ndef f(x):\n    os.system("ls %s" % x)\n`).length).toBeGreaterThan(0);
    expect(evalExec("c.py", `import os\ndef f(x):\n    os.system(f"ls {x}")\n`).length).toBeGreaterThan(0);
    expect(evalExec("d.py", `import os\ndef f(x):\n    os.system("ls {}".format(x))\n`).length).toBeGreaterThan(0);
    expect(evalExec("e.js", "function f(x) {\n  eval(`1 + ${x}`);\n}\n").length).toBeGreaterThan(0);
    expect(evalExec("f.js", `function f(x) {\n  eval("1 + " + x);\n}\n`).length).toBeGreaterThan(0);
    expect(evalExec("g.js", `function f(cmd) {\n  eval(cmd);\n}\n`).length).toBeGreaterThan(0);
    expect(evalExec("h.py", `import subprocess\ndef f(c):\n    subprocess.call(c, shell=True)\n`).length).toBeGreaterThan(0);
  });
});

describe("a variable last set to a string literal is a constant command", () => {
  const evalExec = (path: string, src: string) => indicators([[path, src]], path).filter(i => i.id === "eval-exec" || i.id === "command-injection");

  it("overwritten with a literal before the call: not reported (DataFlowBench local-overwrite)", () => {
    expect(evalExec("a.py", `import os\nfrom flask import request\n\ndef run():\n    value = request.args.get("x")\n    value = "clean"\n    os.system(value)\n`)).toHaveLength(0);
    expect(evalExec("a.js", `function run(req) {\n  let value = req.query.x;\n  value = "clean";\n  eval(value);\n}\n`)).toHaveLength(0);
  });

  it("the same in a file with Windows (CRLF) line endings", () => {
    const crlf = (src: string) => src.replace(/\n/g, "\r\n");
    expect(evalExec("w.js", crlf(`const cp = require("child_process");\nfunction run() {\n  const value = "printf constant";\n  cp.execSync(value);\n}\n`))).toHaveLength(0);
    expect(evalExec("w.py", crlf(`import os\n\ndef run():\n    value = "clean"\n    os.system(value)\n`))).toHaveLength(0);
    expect(evalExec("w2.js", crlf(`function run(req) {\n  let value = "clean";\n  value = req.query.x;\n  eval(value);\n}\n`)).length).toBeGreaterThan(0);
  });

  it("still reported when the last assignment is computed, conditional, augmented, or the variable is a parameter", () => {
    expect(evalExec("b.py", `import os\nfrom flask import request\n\ndef run():\n    value = "clean"\n    value = request.args.get("x")\n    os.system(value)\n`).length).toBeGreaterThan(0);
    expect(evalExec("c.py", `import os\nfrom flask import request\n\ndef run(flag):\n    value = request.args.get("x")\n    if flag:\n        value = "clean"\n    os.system(value)\n`).length).toBeGreaterThan(0);
    expect(evalExec("d.py", `import os\nfrom flask import request\n\ndef run():\n    value = "ls "\n    value += request.args.get("x")\n    os.system(value)\n`).length).toBeGreaterThan(0);
    expect(evalExec("e.py", `import os\n\ndef run(value):\n    os.system(value)\n`).length).toBeGreaterThan(0);
    expect(evalExec("f.js", `function run(req) {\n  let value = "clean";\n  value = req.query.x;\n  eval(value);\n}\n`).length).toBeGreaterThan(0);
  });
});

describe("a command made of literals and shell-quoted values is not an injection", () => {
  const evalExec = (path: string, src: string) => indicators([[path, src]], path).filter(i => i.id === "eval-exec" || i.id === "command-injection");

  it("every non-literal piece wrapped in shlex.quote / pipes.quote: not reported", () => {
    expect(evalExec("q.py", `import os, shlex\n\ndef run(a):\n    os.system("echo " + shlex.quote(a))\n`)).toHaveLength(0);
    expect(evalExec("q2.py", `import os, pipes\n\ndef run(a, b):\n    os.system("cp " + pipes.quote(a) + " " + pipes.quote(b))\n`)).toHaveLength(0);
  });

  it("any unquoted piece, or a quote around only part of it, is still reported", () => {
    expect(evalExec("r.py", `import os, shlex\n\ndef run(a, b):\n    os.system("echo " + shlex.quote(a) + b)\n`).length).toBeGreaterThan(0);
    expect(evalExec("r2.py", `import os, shlex\n\ndef run(a):\n    os.system("echo " + a)\n`).length).toBeGreaterThan(0);
    expect(evalExec("r3.py", `import os, shlex\n\ndef run(a):\n    os.system(shlex.quote(a) + " x" + a.upper())\n`).length).toBeGreaterThan(0);
  });
});
