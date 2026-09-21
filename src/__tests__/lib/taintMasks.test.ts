import { scanAstTaint } from "@/lib/astTaint";
import { scanAstTaintPython, parsePythonSourceSync, warmPythonTaintEngine } from "@/lib/astTaintPython";
import { sanitizerClears } from "@/lib/taint/sanitizers";
import { SinkClass } from "@/lib/taint/taintCore";

beforeAll(async () => { await warmPythonTaintEngine(); }, 30000);

const js = (code: string) => scanAstTaint(code, "a.ts").map(f => f.id);

describe("sanitizer table", () => {
  it("HTML escapers clear XSS only", () => {
    expect(sanitizerClears("js", "escapeHtml")).toBe(SinkClass.XSS);
    expect(sanitizerClears("php", "htmlspecialchars")).toBe(SinkClass.XSS);
  });
  it("filter_var clears nothing without a sanitizing/validating constant", () => {
    expect(sanitizerClears("php", "filter_var", ["$x", "FILTER_DEFAULT"])).toBe(0);
    expect(sanitizerClears("php", "filter_var", ["$x"])).toBe(0);
    expect(sanitizerClears("php", "filter_var", ["$x", "FILTER_VALIDATE_INT"])).toBe(sanitizerClears("php", "intval"));
    expect((sanitizerClears("php", "intval") ?? 0) & SinkClass.CONTROL).toBe(0);
  });
  it("does not treat inherited Object.prototype names as sanitizers", () => {
    expect(sanitizerClears("js", "toString")).toBeNull();
    expect(sanitizerClears("cs", "constructor")).toBeNull();
  });
  it("C# Encode is receiver-aware", () => {
    expect(sanitizerClears("cs", "HtmlEncoder.Default.Encode")).toBe(SinkClass.XSS);
    expect(sanitizerClears("cs", "Convert.Encode")).toBe(0);
  });
  it("only numeric parsers clear all classes in C#", () => {
    expect(sanitizerClears("cs", "int.Parse")).toBe(sanitizerClears("php", "intval"));
    expect(sanitizerClears("cs", "JObject.Parse")).toBe(0);
  });
});

describe("JS/TS: sanitizers are sink-class aware", () => {
  it("HTML escaper clears XSS", () => {
    expect(js(`
import { escapeHtml } from "x";
app.get("/a", (req, res) => { const c = escapeHtml(req.query.q); res.send(c); });
`)).not.toContain("xss");
  });

  it("HTML escaper does NOT clear command injection (wrong-class sanitizer still reported)", () => {
    expect(js(`
import { exec } from "child_process";
import { escapeHtml } from "x";
app.get("/a", (req, res) => { const c = escapeHtml(req.query.q); exec("ls " + c); });
`)).toContain("command-injection");
  });

  it("HTML escaper does NOT clear SQL injection", () => {
    expect(js(`
import { escapeHtml } from "x";
app.get("/a", (req, res) => { const c = escapeHtml(req.query.q); db.query("SELECT " + c); });
`)).toContain("sql-injection");
  });

  it("numeric coercion clears every injection class", () => {
    const ids = js(`
app.get("/a", (req, res) => { const n = parseInt(req.query.q); db.query("SELECT " + n); res.send(n); });
`);
    expect(ids).not.toContain("sql-injection");
    expect(ids).not.toContain("xss");
  });

  it("a wrapper around an HTML escaper still propagates non-XSS taint", () => {
    const ids = js(`
import { escapeHtml } from "x";
function clean(v) { return escapeHtml(v); }
app.get("/a", (req, res) => { const c = clean(req.query.q); db.query("SELECT " + c); res.send(c); });
`);
    expect(ids).toContain("sql-injection");
    expect(ids).not.toContain("xss");
  });

  it("reports a positively-sanitized sink through the suppression out-param", () => {
    const suppressed: { id: string; line: number }[] = [];
    scanAstTaint(`
import { escapeHtml } from "x";
app.get("/a", (req, res) => { const c = escapeHtml(req.query.q); res.send(c); });
`, "a.ts", undefined, undefined, suppressed);
    expect(suppressed.some(s => s.id === "xss")).toBe(true);
  });

  it("does not report a suppression for a flow that was never tainted", () => {
    const suppressed: { id: string; line: number }[] = [];
    scanAstTaint(`
app.get("/a", (req, res) => { const c = "literal"; res.send(c); });
`, "a.ts", undefined, undefined, suppressed);
    expect(suppressed.length).toBe(0);
  });
});

describe("Python: sanitizers are sink-class aware", () => {
  const py = (code: string) => {
    const root = parsePythonSourceSync(code, "a.py");
    if (!root) throw new Error("parse failed");
    return scanAstTaintPython(code, "a.py", root).map(f => f.id);
  };

  it("shlex.quote clears command injection", () => {
    expect(py(`
import os, shlex
from flask import request
def h():
    q = shlex.quote(request.args.get("q"))
    os.system("ls " + q)
`)).not.toContain("command-injection");
  });

  it("html.escape does NOT clear command injection", () => {
    expect(py(`
import os, html
from flask import request
def h():
    q = html.escape(request.args.get("q"))
    os.system("ls " + q)
`)).toContain("command-injection");
  });
});

describe("PHP: sanitizers are sink-class aware", () => {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const php = require("@/lib/astTaintPHP") as typeof import("@/lib/astTaintPHP");
  beforeAll(async () => { await php.warmPhpTaintEngine(); }, 30000);
  const scanPhp = (code: string) => {
    const root = php.parsePhpSourceSync(code, "a.php");
    if (!root) throw new Error("parse failed");
    return php.scanAstTaintPHP(code, "a.php", root).map(f => f.id);
  };

  it("htmlspecialchars clears XSS", () => {
    expect(scanPhp(`<?php
$n = htmlspecialchars($_GET['n']);
echo "<h1>" . $n . "</h1>";`)).not.toContain("xss");
  });

  it("htmlspecialchars does NOT clear SQL injection", () => {
    expect(scanPhp(`<?php
$n = htmlspecialchars($_GET['n']);
mysqli_query($conn, "SELECT * FROM t WHERE n = '" . $n . "'");`)).toContain("sql-injection");
  });

  it("escapeshellarg clears command injection but not XSS", () => {
    const ids = scanPhp(`<?php
$h = escapeshellarg($_GET['h']);
shell_exec("ping " . $h);
echo $h;`);
    expect(ids).not.toContain("command-injection");
    expect(ids).toContain("xss");
  });

  it("filter_var with FILTER_DEFAULT does not sanitize", () => {
    expect(scanPhp(`<?php
$v = filter_var($_GET['v'], FILTER_DEFAULT);
mysqli_query($conn, "SELECT " . $v);`)).toContain("sql-injection");
  });

  it("filter_var with FILTER_VALIDATE_INT sanitizes injection classes", () => {
    expect(scanPhp(`<?php
$v = filter_var($_GET['v'], FILTER_VALIDATE_INT);
mysqli_query($conn, "SELECT " . $v);`)).not.toContain("sql-injection");
  });

  it("a (int) cast clears injection classes (was silently taint-preserving)", () => {
    expect(scanPhp(`<?php
$id = (int)$_GET['id'];
mysqli_query($conn, "SELECT * FROM t WHERE id = " . $id);`)).not.toContain("sql-injection");
  });

  it("a method named htmlspecialchars on an object is NOT recorded as the PHP sanitizer", () => {
    // An unknown method call is opaque (untainted) either way, so the
    // observable difference is whether it counts as a POSITIVE sanitization
    // (which would let the regex-layer veto drop a real regex finding).
    const scanWithSuppressed = (code: string) => {
      const root = php.parsePhpSourceSync(code, "a.php");
      if (!root) throw new Error("parse failed");
      const suppressed: { id: string; line: number }[] = [];
      php.scanAstTaintPHP(code, "a.php", root, suppressed);
      return suppressed;
    };
    expect(scanWithSuppressed(`<?php
$n = $helper->htmlspecialchars($_GET['n']);
echo "<h1>" . $n . "</h1>";`)).toEqual([]);
    expect(scanWithSuppressed(`<?php
$n = htmlspecialchars($_GET['n']);
echo "<h1>" . $n . "</h1>";`).some(s => s.id === "xss")).toBe(true);
  });
});

describe("C#: sanitizers are sink-class aware", () => {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const cs = require("@/lib/astTaintCSharp") as typeof import("@/lib/astTaintCSharp");
  beforeAll(async () => { await cs.warmCSharpTaintEngine(); }, 30000);
  const scanCs = (code: string) => {
    const root = cs.parseCSharpSourceSync(code, "A.cs");
    if (!root) throw new Error("parse failed");
    return cs.scanAstTaintCSharp(code, "A.cs", root).map(f => f.id);
  };

  it("HtmlEncode clears XSS", () => {
    expect(scanCs(`
public class A {
  [HttpGet("a")]
  public IActionResult M([FromQuery] string n) {
    var c = WebUtility.HtmlEncode(n);
    return Content("<b>" + c + "</b>", "text/html");
  }
}`)).not.toContain("xss");
  });

  it("HtmlEncode does NOT clear command injection", () => {
    expect(scanCs(`
public class A {
  [HttpGet("a")]
  public void M([FromQuery] string n) {
    var c = WebUtility.HtmlEncode(n);
    Process.Start("ping", c);
  }
}`)).toContain("command-injection");
  });

  it("an (int) cast clears SQL injection taint", () => {
    expect(scanCs(`
public class A {
  [HttpGet("a")]
  public void M([FromQuery] string n) {
    var id = (int)n;
    db.Users.FromSqlRaw("SELECT * FROM U WHERE Id = " + id);
  }
}`)).not.toContain("sql-injection");
  });
});

describe("regex-layer veto (end to end through analyzeFile)", () => {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { analyzeFile } = require("@/lib/scanner") as typeof import("@/lib/scanner");

  const sanitized = `
import express from "express";
import { escapeHtml } from "./esc";
const app = express();
app.get("/hello", (req, res) => {
  const name = escapeHtml(req.query.name);
  res.send("<h1>Hello " + name + "</h1>");
});
`;
  const unsanitized = sanitized.replace("escapeHtml(req.query.name)", "req.query.name");

  it("does not report XSS for a flow the AST engine proved sanitized (regex duplicate dropped)", () => {
    expect(analyzeFile("routes/hello.ts", sanitized).indicators.some(i => i.id === "xss")).toBe(false);
  });

  it("still reports XSS for the identical unsanitized flow (veto is not a blanket suppression)", () => {
    expect(analyzeFile("routes/hello.ts", unsanitized).indicators.some(i => i.id === "xss")).toBe(true);
  });
});
