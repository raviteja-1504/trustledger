// Source -> sink trace generation (taint/taintCore.ts's buildBackwardTraceGeneric) and the
// unquoted-HTML-attribute context check, ported from JS/TS to Go, Java, C#, PHP and Python.

import { scanAstTaintGo, parseGoSourceSync, warmGoTaintEngine } from "@/lib/astTaintGo";
import { scanAstTaintJava, parseJavaSource } from "@/lib/astTaintJava";
import { scanAstTaintCSharp, parseCSharpSourceSync, warmCSharpTaintEngine } from "@/lib/astTaintCSharp";
import { scanAstTaintPHP, parsePhpSourceSync, warmPhpTaintEngine } from "@/lib/astTaintPHP";
import { scanAstTaintPython, parsePythonSourceSync, warmPythonTaintEngine } from "@/lib/astTaintPython";

jest.setTimeout(60000);
beforeAll(async () => {
  await Promise.all([warmGoTaintEngine(), warmCSharpTaintEngine(), warmPhpTaintEngine(), warmPythonTaintEngine()]);
});

describe("Go", () => {
  const src = `package main
import "net/http"
func h(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	q := "SELECT * FROM t WHERE id=" + id
	db.Query(q)
}
`;
  const findings = () => scanAstTaintGo(src, "x.go", parseGoSourceSync(src, "x.go")!);

  it("has a source-first trace resolving id back to its declaration", () => {
    const f = findings().find(x => x.id === "sql-injection")!;
    expect(f).toBeDefined();
    expect(f.trace).toBeDefined();
    expect(f.trace![0].kind).toBe("source");
    expect(f.trace![0].label).toContain("URL.Query");
    expect(f.trace![f.trace!.length - 1].kind).toBe("sink");
  });
});

describe("Java", () => {
  const src = `import org.springframework.web.bind.annotation.*;
@RestController
public class C {
  @GetMapping("/x")
  public String a(@RequestParam String id) {
    String q = "SELECT * FROM t WHERE id='" + id + "'";
    return db.execute(q);
  }
}`;
  const findings = () => scanAstTaintJava(src, "x.java", parseJavaSource(src)!);

  it("has a trace ending at the sink", () => {
    const f = findings().find(x => x.id === "sql-injection")!;
    expect(f).toBeDefined();
    expect(f.trace).toBeDefined();
    expect(f.trace![f.trace!.length - 1].kind).toBe("sink");
  });
});

describe("C#", () => {
  const src = `using Microsoft.AspNetCore.Mvc;
public class C : ControllerBase {
  [HttpGet("x")] public IActionResult A([FromQuery] string id) {
    var s = "SELECT * FROM t WHERE id='" + id + "'";
    return Ok(s);
  }
}`;
  const findings = () => scanAstTaintCSharp(src, "x.cs", parseCSharpSourceSync(src, "x.cs")!);

  it("has a source-first trace with a parameter as the terminal source", () => {
    const f = findings().find(x => x.id === "sql-injection")!;
    expect(f).toBeDefined();
    expect(f.trace![0].kind).toBe("source");
    expect(f.trace![0].label).toBe("id");
  });

  it("flags an HTML-encoded value dropped into an unquoted attribute", () => {
    const attrSrc = `using Microsoft.AspNetCore.Mvc;
public class C : ControllerBase {
  [HttpGet("x")] public IActionResult A([FromQuery] string v) {
    var enc = System.Web.HttpUtility.HtmlEncode(v);
    return Content("<div title=" + enc + ">", "text/html");
  }
}`;
    const f = scanAstTaintCSharp(attrSrc, "x.cs", parseCSharpSourceSync(attrSrc, "x.cs")!);
    expect(f.some(x => x.id === "xss" && /unquoted/i.test(x.detail))).toBe(true);
  });
});

describe("PHP", () => {
  const src = `<?php function f(){global $db; $id = $_GET['id']; $q = "SELECT * FROM t WHERE id='".$id."'"; $db->query($q);}`;
  const findings = () => {
    const root = parsePhpSourceSync(src, "x.php")!;
    return scanAstTaintPHP(src, "x.php", root);
  };

  it("has a trace ending at the sink", () => {
    const f = findings().find(x => x.id === "sql-injection")!;
    expect(f).toBeDefined();
    expect(f.trace![f.trace!.length - 1].kind).toBe("sink");
  });

  it("flags an HTML-escaped value dropped into an unquoted attribute", () => {
    const attrSrc = `<?php function f(){$v = htmlspecialchars($_GET['value']); echo "<div title=".$v.">";}`;
    const root = parsePhpSourceSync(attrSrc, "x.php")!;
    const f = scanAstTaintPHP(attrSrc, "x.php", root);
    expect(f.some(x => x.id === "xss")).toBe(true);
  });
});

describe("Python", () => {
  const src = `def handler(request):
    id = request.GET.get("id")
    q = "SELECT * FROM t WHERE id='" + id + "'"
    db.execute(q)
`;
  const findings = () => scanAstTaintPython(src, "x.py", parsePythonSourceSync(src, "x.py")!);

  it("has a trace ending at the sink", () => {
    const f = findings().find(x => x.id === "sql-injection")!;
    expect(f).toBeDefined();
    expect(f.trace![f.trace!.length - 1].kind).toBe("sink");
    expect(f.trace![f.trace!.length - 1].line).toBe(4);
  });

  it("flags an f-string-escaped value dropped into an unquoted attribute", () => {
    const attrSrc = `import html
def handler(request):
    v = html.escape(request.GET.get("value"))
    return HttpResponse(f"<div title={v}>")
`;
    const f = scanAstTaintPython(attrSrc, "x.py", parsePythonSourceSync(attrSrc, "x.py")!);
    expect(f.some(x => x.id === "xss")).toBe(true);
  });
});
