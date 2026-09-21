import { scanAstTaint } from "@/lib/astTaint";

// Path sensitivity for the JS/TS engine (the reference implementation the
// other engines mirror). `sink(x)` below is `db.query("SELECT " + x)`, a SQL
// sink; `x` is request-derived unless a test says otherwise.

const scan = (code: string) => scanAstTaint(code, "a.ts").map(f => f.id);
const handler = (body: string, prelude = "") => `
${prelude}
app.get("/a", (req, res) => {
${body}
});
`;
const sql = (v: string) => `db.query("SELECT " + ${v});`;
const hasSql = (code: string) => scan(code).includes("sql-injection");

describe("JS/TS path sensitivity: branches", () => {
  it("if/else that overwrites on ONE branch and keeps taint on the other still reports (was a miss: last writer won)", () => {
    expect(hasSql(handler(`
let x = "ok";
if (req.query.a) { x = req.query.q; } else { x = "ok"; }
${sql("x")}`))).toBe(true);
  });

  it("reversed branch order reports too", () => {
    expect(hasSql(handler(`
let x = "ok";
if (req.query.a) { x = "ok"; } else { x = req.query.q; }
${sql("x")}`))).toBe(true);
  });

  it("a reassignment INSIDE a branch is not undone by the entry env (was a false positive)", () => {
    expect(hasSql(handler(`
let x = req.query.q;
if (req.query.a) { x = "safe"; ${sql("x")} }`))).toBe(false);
  });

  it("an arm that returns does not contribute its taint after the if", () => {
    expect(hasSql(handler(`
let x = "k";
if (req.query.a) { x = req.query.q; return; }
${sql("x")}`))).toBe(false);
  });

  it("taint from a non-terminating arm survives the join", () => {
    expect(hasSql(handler(`
let x = "k";
if (req.query.a) { x = req.query.q; }
${sql("x")}`))).toBe(true);
  });

  it("dead code after return/throw is not walked", () => {
    expect(hasSql(handler(`
const x = req.query.q;
return;
${sql("x")}`))).toBe(false);
  });

  it("switch: a literal case arm makes the subject that literal; default still reports", () => {
    const code = (arm: string) => handler(`
const x = req.query.q;
switch (x) {
  case "a": ${arm === "case" ? sql("x") : ""} break;
  default: ${arm === "default" ? sql("x") : ""} break;
}`);
    expect(hasSql(code("case"))).toBe(false);
    expect(hasSql(code("default"))).toBe(true);
  });
});

describe("JS/TS path sensitivity: expressions", () => {
  it("ternary: taint in either arm reports (was a miss)", () => {
    expect(hasSql(handler(`const x = req.query.a ? req.query.q : "k"; ${sql("x")}`))).toBe(true);
  });

  it("ternary: a tainted CONDITION with constant arms does not report", () => {
    expect(hasSql(handler(`const x = req.query.q ? "a" : "b"; ${sql("x")}`))).toBe(false);
  });

  it("?? and || propagate taint from either operand", () => {
    expect(hasSql(handler(`const x = req.query.q ?? "d"; ${sql("x")}`))).toBe(true);
    expect(hasSql(handler(`const x = req.query.q || "d"; ${sql("x")}`))).toBe(true);
  });

  it("compound assignment keeps existing taint and adds new", () => {
    expect(hasSql(handler(`let q = req.query.q; q += "z"; ${sql("q")}`))).toBe(true);
    expect(hasSql(handler(`let q = "a"; q += req.query.b; ${sql("q")}`))).toBe(true);
    expect(hasSql(handler(`let q = "a"; q += "b"; ${sql("q")}`))).toBe(false);
  });
});

describe("JS/TS path sensitivity: loops and try", () => {
  it("loop-carried flow: assigned late in iteration N, used early in N+1", () => {
    expect(hasSql(handler(`
let x = "k";
for (const i of [1, 2]) { ${sql("x")} x = req.query.q; }`))).toBe(true);
  });

  it("a loop variable iterating a tainted collection is tainted", () => {
    expect(hasSql(handler(`for (const item of req.body.items) { ${sql("item")} }`))).toBe(true);
  });

  it("try/catch: taint assigned in the try body survives past the statement", () => {
    expect(hasSql(handler(`
let x = "k";
try { x = req.query.q; } catch (e) { }
${sql("x")}`))).toBe(true);
  });

  it("the catch variable does not inherit an outer variable of the same name", () => {
    expect(hasSql(handler(`
const e = req.query.q;
try { foo(); } catch (e) { ${sql("e")} }`))).toBe(false);
  });
});

describe("JS/TS path sensitivity: scoping", () => {
  it("a function parameter shadows a same-named tainted outer variable", () => {
    expect(hasSql(`
const q = "x";
app.get("/a", (req, res) => { const q2 = req.query.q; });
function f(q) { ${sql("q")} }
`)).toBe(false);
  });

  it("taint in one handler does not leak into a sibling handler's same-named variable", () => {
    expect(hasSql(`
app.get("/a", (req, res) => { const id = req.query.id; });
app.get("/b", (req, res) => { const id = "42"; ${sql("id")} });
`)).toBe(false);
  });
});

describe("JS/TS path sensitivity: narrow guards", () => {
  const withX = (body: string, prelude = "") => handler(`const x = req.query.q;\n${body}`, prelude);

  it("allowlist membership against a literal array: guarded arm is clean", () => {
    expect(hasSql(withX(`if (["a", "b"].includes(x)) { ${sql("x")} }`))).toBe(false);
  });

  it("allowlist via a top-level const collection, early-return form", () => {
    expect(hasSql(withX(`if (!ALLOWED.includes(x)) return;\n${sql("x")}`, `const ALLOWED = ["a", "b"];`))).toBe(false);
  });

  it("the unguarded arm of an allowlist check is still reported", () => {
    expect(hasSql(withX(`if (!["a", "b"].includes(x)) { ${sql("x")} }`))).toBe(true);
  });

  it("Set.has against a literal Set", () => {
    expect(hasSql(withX(`if (ALLOWED.has(x)) { ${sql("x")} }`, `const ALLOWED = new Set(["a", "b"]);`))).toBe(false);
  });

  it("indexOf(...) !== -1 against a literal collection", () => {
    expect(hasSql(withX(`if (["a", "b"].indexOf(x) !== -1) { ${sql("x")} }`))).toBe(false);
  });

  it("Number.isInteger early return", () => {
    expect(hasSql(withX(`if (!Number.isInteger(x)) return;\n${sql("x")}`))).toBe(false);
  });

  it("typeof x === 'number'", () => {
    expect(hasSql(withX(`if (typeof x === "number") { ${sql("x")} }`))).toBe(false);
  });

  it("equality with a literal: then-arm is that literal", () => {
    expect(hasSql(withX(`if (x === "admin") { ${sql("x")} }`))).toBe(false);
    expect(hasSql(withX(`if (x !== "admin") return;\n${sql("x")}`))).toBe(false);
  });

  it("&& combines guards; || only guards the all-false side", () => {
    expect(hasSql(withX(`if (Number.isInteger(x) && req.query.b) { ${sql("x")} }`))).toBe(false);
    expect(hasSql(withX(`if (Number.isInteger(x) || req.query.b) { ${sql("x")} }`))).toBe(true);
  });

  // --- things that look like validation but are deliberately NOT recognized ---
  it("does NOT recognize a custom validator function", () => {
    expect(hasSql(withX(`if (isValid(x)) { ${sql("x")} }`))).toBe(true);
    expect(hasSql(withX(`if (!isValid(x)) return;\n${sql("x")}`))).toBe(true);
  });

  it("does NOT recognize a regex test", () => {
    expect(hasSql(withX(`if (/^\\d+$/.test(x)) { ${sql("x")} }`))).toBe(true);
  });

  it("does NOT recognize a prefix check", () => {
    expect(hasSql(withX(`if (x.startsWith("a")) { ${sql("x")} }`))).toBe(true);
  });

  it("does NOT trust a collection that contains a non-literal", () => {
    expect(hasSql(withX(`if ([req.query.a, "b"].includes(x)) { ${sql("x")} }`))).toBe(true);
  });

  it("a guard applies only to the guarded variable", () => {
    expect(hasSql(handler(`
const x = req.query.q;
const y = req.query.r;
if (Number.isInteger(x)) { ${sql("y")} }`))).toBe(true);
  });

  it("guard-cleared sinks are recorded for the regex-layer veto", () => {
    const suppressed: { id: string; line: number }[] = [];
    scanAstTaint(withX(`if (!Number.isInteger(x)) return;\n${sql("x")}`), "a.ts", undefined, undefined, suppressed);
    expect(suppressed.some(s => s.id === "sql-injection")).toBe(true);
  });
});

describe("JS/TS path sensitivity: interprocedural summaries", () => {
  it("a function that sanitizes on one path and returns raw on another still propagates", () => {
    expect(hasSql(`
function pick(v, c) { if (c) { return Number(v); } return v; }
app.get("/a", (req, res) => { const x = pick(req.query.q, req.query.c); ${sql("x")} });
`)).toBe(true);
  });

  it("a function whose every return path is guarded/coerced does not propagate", () => {
    expect(hasSql(`
function safe(v) { if (!Number.isInteger(v)) { return 0; } return v; }
app.get("/a", (req, res) => { const x = safe(req.query.q); ${sql("x")} });
`)).toBe(false);
  });

  it("returns inside a nested callback do not count as the outer function's return", () => {
    expect(hasSql(`
function wrap(v) { [1].forEach(() => { return v; }); return "k"; }
app.get("/a", (req, res) => { const x = wrap(req.query.q); ${sql("x")} });
`)).toBe(false);
  });
});

// ── Python ──────────────────────────────────────────────────────────────────
import { scanAstTaintPython, parsePythonSourceSync, warmPythonTaintEngine } from "@/lib/astTaintPython";

describe("Python path sensitivity", () => {
  beforeAll(async () => { await warmPythonTaintEngine(); }, 30000);

  const scanPy = (code: string, suppressed?: { id: string; line: number }[]) => {
    const root = parsePythonSourceSync(code, "a.py");
    if (!root) throw new Error("parse failed");
    return scanAstTaintPython(code, "a.py", root, suppressed).map(f => f.id);
  };
  const ind = (body: string) => body.split("\n").map(l => `    ${l}`).join("\n");
  const fn = (body: string, prelude = "") => `
from flask import request
${prelude}
def h(c=None, d=None):
    x = request.args.get("q")
${ind(body)}
`;
  const SINK = `cursor.execute("SELECT " + x)`;
  const hasSql = (code: string) => scanPy(code).includes("sql-injection");

  it("if/else overwriting on one branch and keeping taint on the other still reports", () => {
    expect(hasSql(fn(`
if c:
    x = request.args.get("q")
else:
    x = "ok"
${SINK}`))).toBe(true);
  });

  it("elif chain: taint from a middle arm survives the join", () => {
    expect(hasSql(fn(`
y = "k"
if c:
    y = "a"
elif d:
    y = request.args.get("q")
else:
    y = "b"
cursor.execute("SELECT " + y)`))).toBe(true);
  });

  it("an arm that returns does not contribute its taint", () => {
    expect(hasSql(fn(`
y = "k"
if c:
    y = request.args.get("q")
    return
cursor.execute("SELECT " + y)`))).toBe(false);
  });

  it("dead code after return/raise is not walked", () => {
    expect(hasSql(fn(`
return
${SINK}`))).toBe(false);
    expect(hasSql(fn(`
raise ValueError()
${SINK}`))).toBe(false);
  });

  it("ternary and boolean operators propagate taint from either operand", () => {
    expect(hasSql(fn(`y = x if c else "k"\ncursor.execute("SELECT " + y)`))).toBe(true);
    expect(hasSql(fn(`y = c or x\ncursor.execute("SELECT " + y)`))).toBe(true);
    expect(hasSql(fn(`y = "a" if x else "b"\ncursor.execute("SELECT " + y)`))).toBe(false);
  });

  it("augmented assignment keeps existing taint", () => {
    expect(hasSql(fn(`x += "z"\n${SINK}`))).toBe(true);
    expect(hasSql(fn(`y = "a"\ny += x\ncursor.execute("SELECT " + y)`))).toBe(true);
    expect(hasSql(fn(`y = "a"\ny += "b"\ncursor.execute("SELECT " + y)`))).toBe(false);
  });

  it("a loop variable over a tainted collection is tainted; loop-carried flow reports", () => {
    expect(hasSql(fn(`for item in request.args.getlist("q"):\n    cursor.execute("SELECT " + item)`))).toBe(true);
    expect(hasSql(fn(`
y = "k"
for i in range(3):
    cursor.execute("SELECT " + y)
    y = request.args.get("q")`))).toBe(true);
  });

  it("try/except: taint assigned in try survives; the except alias shadows an outer name", () => {
    expect(hasSql(fn(`
y = "k"
try:
    y = request.args.get("q")
except Exception:
    pass
cursor.execute("SELECT " + y)`))).toBe(true);
    expect(hasSql(fn(`
e = request.args.get("q")
try:
    pass
except Exception as e:
    cursor.execute("SELECT " + e)`))).toBe(false);
  });

  it("match/case: a literal case arm makes the subject that literal; the wildcard still reports", () => {
    const code = (arm: "lit" | "wild") => fn(`
match x:
    case "a":
        ${arm === "lit" ? SINK : "pass"}
    case _:
        ${arm === "wild" ? SINK : "pass"}`);
    expect(hasSql(code("lit"))).toBe(false);
    expect(hasSql(code("wild"))).toBe(true);
  });

  it("sibling functions do not share taint through a same-named variable", () => {
    expect(hasSql(`
from flask import request
def a():
    q = request.args.get("q")
def b():
    q = "42"
    cursor.execute("SELECT " + q)
`)).toBe(false);
  });

  describe("narrow guards", () => {
    it("literal-collection membership, early-return and guarded-arm forms", () => {
      expect(hasSql(fn(`if x in ("a", "b"):\n    ${SINK}`))).toBe(false);
      expect(hasSql(fn(`if x not in ALLOWED:\n    return\n${SINK}`, `ALLOWED = {"a", "b"}`))).toBe(false);
      expect(hasSql(fn(`if x not in ("a", "b"):\n    ${SINK}`))).toBe(true);
    });

    it("strict numeric/type checks", () => {
      expect(hasSql(fn(`if not x.isdigit():\n    return\n${SINK}`))).toBe(false);
      expect(hasSql(fn(`if isinstance(x, int):\n    ${SINK}`))).toBe(false);
    });

    it("equality with a literal", () => {
      expect(hasSql(fn(`if x == "admin":\n    ${SINK}`))).toBe(false);
      expect(hasSql(fn(`if x != "admin":\n    return\n${SINK}`))).toBe(false);
    });

    it("does NOT recognize startswith, regex matches, or custom validators", () => {
      expect(hasSql(fn(`if x.startswith("a"):\n    ${SINK}`))).toBe(true);
      expect(hasSql(fn(`if re.match(r"^\d+$", x):\n    ${SINK}`))).toBe(true);
      expect(hasSql(fn(`if is_valid(x):\n    ${SINK}`))).toBe(true);
      expect(hasSql(fn(`if not is_valid(x):\n    return\n${SINK}`))).toBe(true);
    });

    it("does NOT trust a collection containing a non-literal", () => {
      expect(hasSql(fn(`if x in ("a", request.args.get("b")):\n    ${SINK}`))).toBe(true);
    });

    it("guard-cleared sinks are recorded for the regex-layer veto", () => {
      const suppressed: { id: string; line: number }[] = [];
      scanPy(fn(`if not x.isdigit():\n    return\n${SINK}`), suppressed);
      expect(suppressed.some(s => s.id === "sql-injection")).toBe(true);
    });
  });

  describe("interprocedural summaries", () => {
    it("a helper that builds a query in a local and returns it now propagates (the old flat summary never did)", () => {
      expect(hasSql(`
from flask import request
def build(v):
    q = "SELECT * FROM t WHERE a = " + v
    return q
def h():
    cursor.execute(build(request.args.get("q")))
`)).toBe(true);
    });

    it("a helper guarded/coerced on every return path does not propagate", () => {
      expect(hasSql(`
from flask import request
def safe(v):
    if not v.isdigit():
        return "0"
    return v
def h():
    cursor.execute("SELECT " + safe(request.args.get("q")))
`)).toBe(false);
    });

    it("a helper that sanitizes on one path and returns raw on another still propagates", () => {
      expect(hasSql(`
from flask import request
def pick(v, c):
    if c:
        return int(v)
    return v
def h():
    cursor.execute("SELECT " + pick(request.args.get("q"), 1))
`)).toBe(true);
    });
  });
});

import { scanAstTaintGo, warmGoTaintEngine } from "@/lib/astTaintGo";

describe("Go path sensitivity", () => {
  beforeAll(async () => { await warmGoTaintEngine(); }, 30000);

  const goWrap = (body: string, extra = "") => `package main

import (
	"database/sql"
	"net/http"
	"os/exec"
	"strconv"
)

${extra}
func handler(w http.ResponseWriter, r *http.Request) {
${body}
}
`;
  const SRC = `r.URL.Query().Get("q")`;
  const goSql = (v: string) => `db.Query("SELECT * FROM t WHERE a = " + ${v})`;
  const hasSqlGo = (code: string) => scanAstTaintGo(code, "x.go").some(f => f.id === "sql-injection");

  describe("branches", () => {
    it("tainted on one arm, safe on the other, still reports", () => {
      expect(hasSqlGo(goWrap(`
	x := "ok"
	if a {
		x = ${SRC}
	} else {
		x = "ok"
	}
	${goSql("x")}`))).toBe(true);
    });

    it("overwritten on every arm does not report", () => {
      expect(hasSqlGo(goWrap(`
	x := ${SRC}
	if a {
		x = "one"
	} else {
		x = "two"
	}
	${goSql("x")}`))).toBe(false);
    });

    it("else-if chain merges every arm", () => {
      expect(hasSqlGo(goWrap(`
	x := "ok"
	if a {
		x = "one"
	} else if b {
		x = ${SRC}
	} else {
		x = "two"
	}
	${goSql("x")}`))).toBe(true);
    });

    it("an arm that returns drops out of the join", () => {
      expect(hasSqlGo(goWrap(`
	x := "ok"
	if a {
		x = ${SRC}
		return
	}
	${goSql("x")}`))).toBe(false);
    });

    it("a panic-terminated arm drops out too", () => {
      expect(hasSqlGo(goWrap(`
	x := "ok"
	if a {
		x = ${SRC}
		panic("no")
	}
	${goSql("x")}`))).toBe(false);
    });

    it("code after return is not walked", () => {
      expect(hasSqlGo(goWrap(`
	x := ${SRC}
	return
	${goSql("x")}`))).toBe(false);
    });

    it("compound += keeps existing taint (was cleared by a literal RHS)", () => {
      expect(hasSqlGo(goWrap(`
	q := ${SRC}
	q += " LIMIT 1"
	db.Query(q)`))).toBe(true);
    });

    it("var declaration with a tainted initializer is tracked", () => {
      expect(hasSqlGo(goWrap(`
	var q = "SELECT * FROM t WHERE a = " + ${SRC}
	db.Query(q)`))).toBe(true);
    });

    it("if-statement initializer is walked before its condition", () => {
      expect(hasSqlGo(goWrap(`
	if v := ${SRC}; v != "" {
		${goSql("v")}
	}`))).toBe(true);
    });
  });

  describe("loops, switch, select", () => {
    it("range over a tainted collection taints the element", () => {
      expect(hasSqlGo(goWrap(`
	for _, v := range r.Header["X-Name"] {
		${goSql("v")}
	}`))).toBe(true);
    });

    it("loop-carried flow reaches a sink earlier in the body", () => {
      expect(hasSqlGo(goWrap(`
	prev := "ok"
	for i := 0; i < 3; i++ {
		${goSql("prev")}
		prev = ${SRC}
	}`))).toBe(true);
    });

    it("switch clause taint joins after the switch", () => {
      expect(hasSqlGo(goWrap(`
	x := "ok"
	switch a {
	case 1:
		x = ${SRC}
	default:
		x = "ok"
	}
	${goSql("x")}`))).toBe(true);
    });

    it("switch that overwrites in every clause (with default) does not report", () => {
      expect(hasSqlGo(goWrap(`
	x := ${SRC}
	switch a {
	case 1:
		x = "one"
	default:
		x = "two"
	}
	${goSql("x")}`))).toBe(false);
    });

    it("select clauses are walked", () => {
      expect(hasSqlGo(goWrap(`
	x := "ok"
	select {
	case <-done:
		x = ${SRC}
	default:
	}
	${goSql("x")}`))).toBe(true);
    });
  });

  describe("scoping", () => {
    it("a function literal's own parameter shadows a tainted outer name", () => {
      expect(hasSqlGo(goWrap(`
	x := ${SRC}
	f := func(x string) {
		${goSql("x")}
	}
	f("ok")`))).toBe(false);
    });

    it("a function literal still sees a captured tainted variable", () => {
      expect(hasSqlGo(goWrap(`
	x := ${SRC}
	f := func() {
		${goSql("x")}
	}
	f()`))).toBe(true);
    });

    it("taint does not leak from one function into the next", () => {
      expect(hasSqlGo(`package main
import "net/http"
func a(w http.ResponseWriter, r *http.Request) {
	x := ${SRC}
	_ = x
}
func b(w http.ResponseWriter, r *http.Request) {
	db.Query("SELECT " + x)
}
`)).toBe(false);
    });

    it("both names in a shared-type parameter declaration are parameters (seeded call sites reach the second)", () => {
      expect(hasSqlGo(`package main
import "net/http"
func run(a, b string) {
	db.Query("SELECT " + b)
}
func handler(w http.ResponseWriter, r *http.Request) {
	run("k", ${SRC})
}
`)).toBe(true);
    });
  });

  describe("narrow guards", () => {
    it("membership in a literal slice via slices.Contains", () => {
      expect(hasSqlGo(goWrap(`
	x := ${SRC}
	if slices.Contains([]string{"a", "b"}, x) {
		${goSql("x")}
	}`))).toBe(false);
    });

    it("the _, ok := allowed[x] map idiom guards the ok arm", () => {
      expect(hasSqlGo(goWrap(`
	x := ${SRC}
	if _, ok := allowed[x]; ok {
		${goSql("x")}
	}`, `var allowed = map[string]bool{"a": true, "b": true}`))).toBe(false);
    });

    it("the map idiom with early return guards what follows", () => {
      expect(hasSqlGo(goWrap(`
	x := ${SRC}
	_, ok := allowed[x]
	if !ok {
		return
	}
	${goSql("x")}`, `var allowed = map[string]bool{"a": true}`))).toBe(false);
    });

    it("a map that is ever rebound to something non-literal is not trusted", () => {
      expect(hasSqlGo(goWrap(`
	x := ${SRC}
	allowed = loadAllowed()
	if _, ok := allowed[x]; ok {
		${goSql("x")}
	}`, `var allowed = map[string]bool{"a": true}`))).toBe(true);
    });

    it("equality with a literal guards the then-arm", () => {
      expect(hasSqlGo(goWrap(`
	x := ${SRC}
	if x == "admin" {
		${goSql("x")}
	}`))).toBe(false);
    });

    it("x != literal with early return guards what follows", () => {
      expect(hasSqlGo(goWrap(`
	x := ${SRC}
	if x != "admin" {
		return
	}
	${goSql("x")}`))).toBe(false);
    });

    it("strict numeric parse: err != nil early return guards the raw string", () => {
      expect(hasSqlGo(goWrap(`
	x := ${SRC}
	if _, err := strconv.Atoi(x); err != nil {
		return
	}
	${goSql("x")}`))).toBe(false);
    });

    it("a switch on the subject with literal cases guards the clause", () => {
      expect(hasSqlGo(goWrap(`
	x := ${SRC}
	switch x {
	case "a", "b":
		${goSql("x")}
	}`))).toBe(false);
    });

    it("a type switch numeric case guards the alias", () => {
      expect(hasSqlGo(goWrap(`
	var x interface{} = ${SRC}
	switch v := x.(type) {
	case int:
		${goSql("v")}
	}`))).toBe(false);
    });

    it("a custom validator is NOT a guard", () => {
      expect(hasSqlGo(goWrap(`
	x := ${SRC}
	if isValid(x) {
		${goSql("x")}
	}`))).toBe(true);
    });

    it("a prefix check is NOT a guard", () => {
      expect(hasSqlGo(goWrap(`
	x := ${SRC}
	if strings.HasPrefix(x, "a") {
		${goSql("x")}
	}`))).toBe(true);
    });

    it("a guard on one variable does not clear another", () => {
      expect(hasSqlGo(goWrap(`
	x := ${SRC}
	y := ${SRC}
	if x == "ok" {
		${goSql("y")}
	}`))).toBe(true);
    });
  });

  describe("interprocedural summaries", () => {
    it("a helper that builds a query in a local and returns it now propagates", () => {
      expect(hasSqlGo(`package main
import "net/http"
func build(v string) string {
	q := "SELECT * FROM t WHERE a = " + v
	return q
}
func handler(w http.ResponseWriter, r *http.Request) {
	db.Query(build(${SRC}))
}
`)).toBe(true);
    });

    it("a helper that coerces on every path does not propagate", () => {
      expect(hasSqlGo(`package main
import ("net/http"; "strconv")
func clean(v string) string {
	n, err := strconv.Atoi(v)
	if err != nil {
		return "0"
	}
	return strconv.Itoa(n)
}
func handler(w http.ResponseWriter, r *http.Request) {
	db.Query("SELECT " + clean(${SRC}))
}
`)).toBe(false);
    });
  });

  describe("BOLA dominance", () => {
    const ids = (code: string) => scanAstTaintGo(code, "x.go").filter(f => f.id === "idor").length;
    const LOOKUP = `db.QueryRow("SELECT * FROM docs WHERE id = ?", id)`;

    it("no ownership check reports", () => {
      expect(ids(goWrap(`
	id := r.URL.Query().Get("id")
	${LOOKUP}`))).toBe(1);
    });

    it("early-return on mismatch dominates the lookup", () => {
      expect(ids(goWrap(`
	id := r.URL.Query().Get("id")
	if id != c.MustGet("userID") {
		return
	}
	${LOOKUP}`))).toBe(0);
    });

    it("lookup inside the equal arm is protected", () => {
      expect(ids(goWrap(`
	id := r.URL.Query().Get("id")
	if id == c.MustGet("userID") {
		${LOOKUP}
	}`))).toBe(0);
    });

    it("a comparison AFTER the lookup no longer suppresses", () => {
      expect(ids(goWrap(`
	id := r.URL.Query().Get("id")
	${LOOKUP}
	if id != c.MustGet("userID") {
		return
	}`))).toBe(1);
    });

    it("a comparison whose result is unused no longer suppresses", () => {
      expect(ids(goWrap(`
	id := r.URL.Query().Get("id")
	_ = id == c.MustGet("userID")
	${LOOKUP}`))).toBe(1);
    });

    it("a mismatch arm that does NOT terminate does not protect what follows", () => {
      expect(ids(goWrap(`
	id := r.URL.Query().Get("id")
	if id != c.MustGet("userID") {
		log.Println("mismatch")
	}
	${LOOKUP}`))).toBe(1);
    });

    it("the comparison held in a variable resolves one hop", () => {
      expect(ids(goWrap(`
	id := r.URL.Query().Get("id")
	isOwner := id == c.MustGet("userID")
	if !isOwner {
		return
	}
	${LOOKUP}`))).toBe(0);
    });
  });
});

import { warmCSharpTaintEngine, parseCSharpSourceSync, scanAstTaintCSharp } from "@/lib/astTaintCSharp";

describe("C# path sensitivity", () => {
  beforeAll(async () => { await warmCSharpTaintEngine(); }, 30000);

  const csScan = (content: string) => {
    const root = parseCSharpSourceSync(content, "A.cs");
    if (!root) throw new Error("parse failed");
    return scanAstTaintCSharp(content, "A.cs", root);
  };
  // `x` is request-derived; `t` is a request-derived string too (second source)
  const method = (body: string, extra = "") => `
public class C {
  ${extra}
  [HttpGet("a")]
  public IActionResult A([FromQuery] string x, [FromQuery] string t) {
${body}
    return Ok();
  }
}`;
  const csSql = (v: string) => `db.Users.FromSqlRaw("SELECT * FROM t WHERE a = '" + ${v} + "'");`;
  const hasSqlCs = (code: string) => csScan(code).some(f => f.id === "sql-injection");

  describe("branches", () => {
    it("tainted on one arm, safe on the other, still reports", () => {
      expect(hasSqlCs(method(`
    var y = "ok";
    if (t == null) { y = x; } else { y = "ok"; }
    ${csSql("y")}`))).toBe(true);
    });

    it("overwritten on every arm does not report", () => {
      expect(hasSqlCs(method(`
    var y = x;
    if (t == null) { y = "one"; } else { y = "two"; }
    ${csSql("y")}`))).toBe(false);
    });

    it("else-if chain merges every arm", () => {
      expect(hasSqlCs(method(`
    var y = "ok";
    if (t == null) { y = "one"; } else if (t == "z") { y = x; } else { y = "two"; }
    ${csSql("y")}`))).toBe(true);
    });

    it("an arm that returns drops out of the join", () => {
      expect(hasSqlCs(method(`
    var y = "ok";
    if (t == null) { y = x; return Ok(); }
    ${csSql("y")}`))).toBe(false);
    });

    it("a throwing arm drops out too", () => {
      expect(hasSqlCs(method(`
    var y = "ok";
    if (t == null) { y = x; throw new Exception("no"); }
    ${csSql("y")}`))).toBe(false);
    });

    it("code after return is not walked", () => {
      expect(hasSqlCs(method(`
    var y = x;
    return Ok();
    ${csSql("y")}`))).toBe(false);
    });

    it("braceless if arms are walked", () => {
      expect(hasSqlCs(method(`
    var y = "ok";
    if (t == null) y = x;
    ${csSql("y")}`))).toBe(true);
    });
  });

  describe("expressions", () => {
    it("ternary is the union of its arms only (condition excluded)", () => {
      expect(hasSqlCs(method(`
    var y = x != null ? "a" : "b";
    ${csSql("y")}`))).toBe(false);
      expect(hasSqlCs(method(`
    var y = t == null ? x : "b";
    ${csSql("y")}`))).toBe(true);
    });

    it("?? carries either operand", () => {
      expect(hasSqlCs(method(`
    var y = x ?? "d";
    ${csSql("y")}`))).toBe(true);
    });

    it("compound += keeps existing taint", () => {
      expect(hasSqlCs(method(`
    var y = x;
    y += " LIMIT 1";
    ${csSql("y")}`))).toBe(true);
    });

    it("??= keeps existing taint", () => {
      expect(hasSqlCs(method(`
    var y = x;
    y ??= "d";
    ${csSql("y")}`))).toBe(true);
    });

    it("switch expression: value is the union of arm results, not the subject", () => {
      expect(hasSqlCs(method(`
    var y = x switch { "a" => "one", _ => "two" };
    ${csSql("y")}`))).toBe(false);
      expect(hasSqlCs(method(`
    var y = t switch { "a" => x, _ => "two" };
    ${csSql("y")}`))).toBe(true);
    });
  });

  describe("loops, try, switch", () => {
    it("foreach over a tainted collection taints the element", () => {
      expect(hasSqlCs(method(`
    foreach (var v in Request.Query["q"]) {
      ${csSql("v")}
    }`))).toBe(true);
    });

    it("loop-carried flow reaches a sink earlier in the body", () => {
      expect(hasSqlCs(method(`
    var prev = "ok";
    for (int i = 0; i < 3; i++) {
      ${csSql("prev")}
      prev = x;
    }`))).toBe(true);
    });

    it("while loop body is walked", () => {
      expect(hasSqlCs(method(`
    var prev = "ok";
    while (t == null) {
      ${csSql("prev")}
      prev = x;
    }`))).toBe(true);
    });

    it("try-body taint reaches a catch handler and the code after", () => {
      expect(hasSqlCs(method(`
    var y = "ok";
    try { y = x; Work(); } catch (Exception e) { ${csSql("y")} }`))).toBe(true);
      expect(hasSqlCs(method(`
    var y = "ok";
    try { Work(); y = x; } catch (Exception e) { } finally { }
    ${csSql("y")}`))).toBe(true);
    });

    it("the catch variable is not tainted by an outer name", () => {
      expect(hasSqlCs(method(`
    var e = x;
    try { Work(); } catch (Exception e) { ${csSql("e")} }`))).toBe(false);
    });

    it("switch clause taint joins after the switch", () => {
      expect(hasSqlCs(method(`
    var y = "ok";
    switch (t) {
      case "1": y = x; break;
      default: y = "ok"; break;
    }
    ${csSql("y")}`))).toBe(true);
    });

    it("a switch that overwrites in every section (with default) does not report", () => {
      expect(hasSqlCs(method(`
    var y = x;
    switch (t) {
      case "1": y = "one"; break;
      default: y = "two"; break;
    }
    ${csSql("y")}`))).toBe(false);
    });
  });

  describe("scoping", () => {
    it("a lambda parameter shadows a tainted outer name", () => {
      expect(hasSqlCs(method(`
    var y = x;
    Func<string, string> f = y2 => "k";
    Action<string> g = y => { ${csSql("y")} };`))).toBe(false);
    });

    it("a lambda still sees a captured tainted variable", () => {
      expect(hasSqlCs(method(`
    var y = x;
    Action g = () => { ${csSql("y")} };`))).toBe(true);
    });
  });

  describe("narrow guards", () => {
    it("membership in a literal array", () => {
      expect(hasSqlCs(method(`
    if (new[] { "a", "b" }.Contains(x)) {
      ${csSql("x")}
    }`))).toBe(false);
    });

    it("membership in a literal collection field", () => {
      expect(hasSqlCs(method(`
    if (Allowed.Contains(x)) {
      ${csSql("x")}
    }`, `static readonly string[] Allowed = new[] { "a", "b" };`))).toBe(false);
    });

    it("a collection field that is ever rebound is not trusted", () => {
      expect(hasSqlCs(method(`
    Allowed = Load();
    if (Allowed.Contains(x)) {
      ${csSql("x")}
    }`, `static string[] Allowed = new[] { "a", "b" };`))).toBe(true);
    });

    it("equality with a literal guards the then-arm", () => {
      expect(hasSqlCs(method(`
    if (x == "admin") {
      ${csSql("x")}
    }`))).toBe(false);
    });

    it("x != literal with early return guards what follows", () => {
      expect(hasSqlCs(method(`
    if (x != "admin") { return BadRequest(); }
    ${csSql("x")}`))).toBe(false);
    });

    it("int.TryParse early return guards the raw string", () => {
      expect(hasSqlCs(method(`
    if (!int.TryParse(x, out var n)) { return BadRequest(); }
    ${csSql("x")}`))).toBe(false);
    });

    it("int.TryParse true-arm guards the raw string", () => {
      expect(hasSqlCs(method(`
    if (int.TryParse(x, out int n)) {
      ${csSql("x")}
    }`))).toBe(false);
    });

    it("a literal `is` pattern guards the then-arm", () => {
      expect(hasSqlCs(method(`
    if (x is "a" or "b") {
      ${csSql("x")}
    }`))).toBe(false);
    });

    it("a switch section with literal case labels guards the subject", () => {
      expect(hasSqlCs(method(`
    switch (x) {
      case "a":
      case "b":
        ${csSql("x")}
        break;
    }`))).toBe(false);
    });

    it("string.Equals with a literal guards", () => {
      expect(hasSqlCs(method(`
    if (string.Equals(x, "admin")) {
      ${csSql("x")}
    }`))).toBe(false);
    });

    it("a custom validator is NOT a guard", () => {
      expect(hasSqlCs(method(`
    if (IsValid(x)) {
      ${csSql("x")}
    }`))).toBe(true);
    });

    it("StartsWith is NOT a guard", () => {
      expect(hasSqlCs(method(`
    if (x.StartsWith("a")) {
      ${csSql("x")}
    }`))).toBe(true);
    });

    it("a guard on one variable does not clear another", () => {
      expect(hasSqlCs(method(`
    if (x == "ok") {
      ${csSql("t")}
    }`))).toBe(true);
    });
  });

  describe("interprocedural summaries", () => {
    it("a helper that builds a query in a local and returns it now propagates", () => {
      expect(hasSqlCs(`
public class C {
  static string Build(string v) {
    var q = "SELECT * FROM t WHERE a = '" + v + "'";
    return q;
  }
  [HttpGet("a")]
  public IActionResult A([FromQuery] string x) {
    db.Users.FromSqlRaw(Build(x));
    return Ok();
  }
}`)).toBe(true);
    });

    it("a helper that coerces on every path does not propagate", () => {
      expect(hasSqlCs(`
public class C {
  static string Clean(string v) {
    if (!int.TryParse(v, out var n)) { return "0"; }
    return n.ToString();
  }
  [HttpGet("a")]
  public IActionResult A([FromQuery] string x) {
    db.Users.FromSqlRaw("SELECT " + Clean(x));
    return Ok();
  }
}`)).toBe(false);
    });

    it("a return inside a lambda is not the method's return", () => {
      expect(hasSqlCs(`
public class C {
  static string Pick(string v) {
    Func<string> f = () => { return v; };
    return "k";
  }
  [HttpGet("a")]
  public IActionResult A([FromQuery] string x) {
    db.Users.FromSqlRaw("SELECT " + Pick(x));
    return Ok();
  }
}`)).toBe(false);
    });
  });

  describe("BOLA dominance", () => {
    const bola = (body: string) => `
public class C {
  [HttpGet("doc/{id}")]
  public IActionResult Get([FromRoute] int id) {
${body}
    return Ok();
  }
}`;
    const count = (code: string) => csScan(code).filter(f => f.id === "bola-missing-ownership-check").length;
    const LOOKUP = `var d = _db.Docs.Find(id);`;

    it("no ownership check reports", () => {
      expect(count(bola(LOOKUP))).toBe(1);
    });

    it("early-return on mismatch dominates the lookup", () => {
      expect(count(bola(`
    if (id != User.GetId()) { return Forbid(); }
    ${LOOKUP}`))).toBe(0);
    });

    it("lookup inside the equal arm is protected", () => {
      expect(count(bola(`
    if (id == User.GetId()) {
      ${LOOKUP}
    }`))).toBe(0);
    });

    it("a comparison AFTER the lookup no longer suppresses", () => {
      expect(count(bola(`
    ${LOOKUP}
    if (id != User.GetId()) { return Forbid(); }`))).toBe(1);
    });

    it("a comparison whose result is unused no longer suppresses", () => {
      expect(count(bola(`
    var same = id == User.GetId();
    ${LOOKUP}`))).toBe(1);
    });

    it("a mismatch arm that does NOT terminate does not protect what follows", () => {
      expect(count(bola(`
    if (id != User.GetId()) { Log("mismatch"); }
    ${LOOKUP}`))).toBe(1);
    });

    it("throwing on mismatch protects what follows", () => {
      expect(count(bola(`
    if (id != User.GetId()) { throw new UnauthorizedAccessException(); }
    ${LOOKUP}`))).toBe(0);
    });

    it("the comparison held in a variable resolves one hop", () => {
      expect(count(bola(`
    var isOwner = id == User.GetId();
    if (!isOwner) { return Forbid(); }
    ${LOOKUP}`))).toBe(0);
    });

    it(".Equals guard with early return", () => {
      expect(count(bola(`
    if (!id.Equals(User.GetId())) { return Forbid(); }
    ${LOOKUP}`))).toBe(0);
    });
  });
});

import { warmPhpTaintEngine, parsePhpSourceSync, scanAstTaintPHP } from "@/lib/astTaintPHP";

describe("PHP path sensitivity", () => {
  beforeAll(async () => { await warmPhpTaintEngine(); }, 30000);

  const phpScan = (content: string) => {
    const root = parsePhpSourceSync(content, "a.php");
    if (!root) throw new Error("parse failed");
    return scanAstTaintPHP(content, "a.php", root);
  };
  const fn = (body: string, extra = "") => `<?php
${extra}
function h($conn, $flag) {
${body}
}
`;
  const SRC = `$_GET['q']`;
  const phpSql = (v: string) => `mysqli_query($conn, "SELECT * FROM t WHERE a = '" . ${v} . "'");`;
  const hasSqlPhp = (code: string) => phpScan(code).some(f => f.id === "sql-injection");

  describe("branches", () => {
    it("tainted on one arm, safe on the other, still reports", () => {
      expect(hasSqlPhp(fn(`
  $y = "ok";
  if ($flag) { $y = ${SRC}; } else { $y = "ok"; }
  ${phpSql("$y")}`))).toBe(true);
    });

    it("overwritten on every arm does not report", () => {
      expect(hasSqlPhp(fn(`
  $y = ${SRC};
  if ($flag) { $y = "one"; } else { $y = "two"; }
  ${phpSql("$y")}`))).toBe(false);
    });

    it("elseif chain merges every arm", () => {
      expect(hasSqlPhp(fn(`
  $y = "ok";
  if ($flag == 1) { $y = "one"; } elseif ($flag == 2) { $y = ${SRC}; } else { $y = "two"; }
  ${phpSql("$y")}`))).toBe(true);
    });

    it("alternative colon syntax is walked", () => {
      expect(hasSqlPhp(fn(`
  $y = "ok";
  if ($flag): $y = ${SRC}; else: $y = "ok"; endif;
  ${phpSql("$y")}`))).toBe(true);
    });

    it("an arm that returns drops out of the join", () => {
      expect(hasSqlPhp(fn(`
  $y = "ok";
  if ($flag) { $y = ${SRC}; return; }
  ${phpSql("$y")}`))).toBe(false);
    });

    it("an arm that exits drops out too", () => {
      expect(hasSqlPhp(fn(`
  $y = "ok";
  if ($flag) { $y = ${SRC}; exit; }
  ${phpSql("$y")}`))).toBe(false);
      expect(hasSqlPhp(fn(`
  $y = "ok";
  if ($flag) { $y = ${SRC}; die("no"); }
  ${phpSql("$y")}`))).toBe(false);
    });

    it("code after return is not walked", () => {
      expect(hasSqlPhp(fn(`
  $y = ${SRC};
  return;
  ${phpSql("$y")}`))).toBe(false);
    });

    it("braceless if arms are walked", () => {
      expect(hasSqlPhp(fn(`
  $y = "ok";
  if ($flag) $y = ${SRC};
  ${phpSql("$y")}`))).toBe(true);
    });
  });

  describe("expressions", () => {
    it("ternary is the union of its arms only (condition excluded)", () => {
      expect(hasSqlPhp(fn(`
  $y = ${SRC} ? "a" : "b";
  ${phpSql("$y")}`))).toBe(false);
      expect(hasSqlPhp(fn(`
  $y = $flag ? ${SRC} : "b";
  ${phpSql("$y")}`))).toBe(true);
    });

    it("short ternary and ?? carry the operand", () => {
      expect(hasSqlPhp(fn(`
  $y = ${SRC} ?: "d";
  ${phpSql("$y")}`))).toBe(true);
      expect(hasSqlPhp(fn(`
  $y = ${SRC} ?? "d";
  ${phpSql("$y")}`))).toBe(true);
    });

    it(".= keeps existing taint (was a miss: never handled)", () => {
      expect(hasSqlPhp(fn(`
  $y = ${SRC};
  $y .= " LIMIT 1";
  ${phpSql("$y")}`))).toBe(true);
    });

    it(".= builds a tainted query from a clean prefix", () => {
      expect(hasSqlPhp(fn(`
  $y = "SELECT * FROM t WHERE a = ";
  $y .= ${SRC};
  mysqli_query($conn, $y);`))).toBe(true);
    });

    it("array element write taints the array read back", () => {
      expect(hasSqlPhp(fn(`
  $p = [];
  $p['k'] = ${SRC};
  ${phpSql("$p['k']")}`))).toBe(true);
    });

    it("list destructuring binds every target", () => {
      expect(hasSqlPhp(fn(`
  [$a, $b] = [${SRC}, "x"];
  ${phpSql("$a")}`))).toBe(true);
    });

    it("match: value is the union of arm results, not the subject", () => {
      expect(hasSqlPhp(fn(`
  $y = match(${SRC}) { "a" => "one", default => "two" };
  ${phpSql("$y")}`))).toBe(false);
      expect(hasSqlPhp(fn(`
  $y = match($flag) { 1 => ${SRC}, default => "two" };
  ${phpSql("$y")}`))).toBe(true);
    });
  });

  describe("loops, try, switch, closures", () => {
    it("foreach over a tainted array taints the element", () => {
      expect(hasSqlPhp(fn(`
  foreach ($_GET as $k => $v) {
    ${phpSql("$v")}
  }`))).toBe(true);
    });

    it("loop-carried flow reaches a sink earlier in the body", () => {
      expect(hasSqlPhp(fn(`
  $prev = "ok";
  for ($i = 0; $i < 3; $i++) {
    ${phpSql("$prev")}
    $prev = ${SRC};
  }`))).toBe(true);
    });

    it("while loop body is walked", () => {
      expect(hasSqlPhp(fn(`
  $prev = "ok";
  while ($flag) {
    ${phpSql("$prev")}
    $prev = ${SRC};
  }`))).toBe(true);
    });

    it("try-body taint reaches a catch handler and the code after", () => {
      expect(hasSqlPhp(fn(`
  $y = "ok";
  try { $y = ${SRC}; work(); } catch (Exception $e) { ${phpSql("$y")} }`))).toBe(true);
      expect(hasSqlPhp(fn(`
  $y = "ok";
  try { work(); $y = ${SRC}; } catch (Exception $e) { } finally { }
  ${phpSql("$y")}`))).toBe(true);
    });

    it("switch clause taint joins after the switch", () => {
      expect(hasSqlPhp(fn(`
  $y = "ok";
  switch ($flag) {
    case 1: $y = ${SRC}; break;
    default: $y = "ok"; break;
  }
  ${phpSql("$y")}`))).toBe(true);
    });

    it("a switch that overwrites in every clause (with default) does not report", () => {
      expect(hasSqlPhp(fn(`
  $y = ${SRC};
  switch ($flag) {
    case 1: $y = "one"; break;
    default: $y = "two"; break;
  }
  ${phpSql("$y")}`))).toBe(false);
    });

    it("a closure sees only its use() variables", () => {
      expect(hasSqlPhp(fn(`
  $y = ${SRC};
  $f = function () { ${phpSql("$y")} };`))).toBe(false);
      expect(hasSqlPhp(fn(`
  $y = ${SRC};
  $f = function () use ($y) { ${phpSql("$y")} };`))).toBe(true);
    });

    it("an arrow function captures the enclosing scope", () => {
      expect(hasSqlPhp(fn(`
  $y = ${SRC};
  $f = fn() => mysqli_query($conn, "SELECT " . $y);`))).toBe(true);
    });

    it("a closure parameter shadows a tainted outer name", () => {
      expect(hasSqlPhp(fn(`
  $y = ${SRC};
  $f = function ($y) { ${phpSql("$y")} };`))).toBe(false);
    });
  });

  describe("narrow guards", () => {
    it("in_array with a strict literal list", () => {
      expect(hasSqlPhp(fn(`
  $y = ${SRC};
  if (in_array($y, ["a", "b"], true)) { ${phpSql("$y")} }`))).toBe(false);
    });

    it("loose in_array is trusted only for string-only literal lists", () => {
      expect(hasSqlPhp(fn(`
  $y = ${SRC};
  if (in_array($y, ["a", "b"])) { ${phpSql("$y")} }`))).toBe(false);
      expect(hasSqlPhp(fn(`
  $y = ${SRC};
  if (in_array($y, [0, 1])) { ${phpSql("$y")} }`))).toBe(true);
    });

    it("in_array against a variable bound only to a literal array", () => {
      expect(hasSqlPhp(fn(`
  $y = ${SRC};
  if (in_array($y, $allowed, true)) { ${phpSql("$y")} }`, `$allowed = ["a", "b"];`))).toBe(false);
    });

    it("an array that is ever appended to is not trusted", () => {
      expect(hasSqlPhp(fn(`
  $y = ${SRC};
  $allowed[] = $flag;
  if (in_array($y, $allowed, true)) { ${phpSql("$y")} }`, `$allowed = ["a", "b"];`))).toBe(true);
    });

    it("isset on a literal-keyed map guards the index", () => {
      expect(hasSqlPhp(fn(`
  $y = ${SRC};
  if (isset($map[$y])) { ${phpSql("$y")} }`, `$map = ["a" => 1, "b" => 2];`))).toBe(false);
    });

    it("is_numeric early exit guards what follows", () => {
      expect(hasSqlPhp(fn(`
  $y = ${SRC};
  if (!is_numeric($y)) { exit; }
  ${phpSql("$y")}`))).toBe(false);
    });

    it("ctype_digit guards the then-arm", () => {
      expect(hasSqlPhp(fn(`
  $y = ${SRC};
  if (ctype_digit($y)) { ${phpSql("$y")} }`))).toBe(false);
    });

    it("strict equality with a literal guards the then-arm", () => {
      expect(hasSqlPhp(fn(`
  $y = ${SRC};
  if ($y === "admin") { ${phpSql("$y")} }`))).toBe(false);
    });

    it("loose equality with a NUMERIC literal is not a guard (PHP < 8 juggling)", () => {
      expect(hasSqlPhp(fn(`
  $y = ${SRC};
  if ($y == 0) { ${phpSql("$y")} }`))).toBe(true);
    });

    it("a switch case on a string literal guards the clause", () => {
      expect(hasSqlPhp(fn(`
  $y = ${SRC};
  switch ($y) { case "a": ${phpSql("$y")} break; }`))).toBe(false);
    });

    it("preg_match is NOT a guard", () => {
      expect(hasSqlPhp(fn(`
  $y = ${SRC};
  if (preg_match('/^a/', $y)) { ${phpSql("$y")} }`))).toBe(true);
    });

    it("a custom validator is NOT a guard", () => {
      expect(hasSqlPhp(fn(`
  $y = ${SRC};
  if (is_valid($y)) { ${phpSql("$y")} }`))).toBe(true);
    });

    it("a guard on one variable does not clear another", () => {
      expect(hasSqlPhp(fn(`
  $y = ${SRC};
  $z = ${SRC};
  if ($y === "ok") { ${phpSql("$z")} }`))).toBe(true);
    });
  });

  describe("top-level scripts", () => {
    it("code after a bare top-level exit is still analyzed (concatenated-snippet scripts must not lose findings)", () => {
      expect(hasSqlPhp(`<?php
header("Location: /x");
exit;
$q = $_GET['q'];
mysqli_query($conn, "SELECT " . $q);
`)).toBe(true);
    });
  });

  describe("interprocedural summaries", () => {
    it("a helper that builds a query in a local and returns it now propagates", () => {
      expect(hasSqlPhp(`<?php
function build($v) {
  $q = "SELECT * FROM t WHERE a = '" . $v . "'";
  return $q;
}
function h($conn) {
  mysqli_query($conn, build(${SRC}));
}
`)).toBe(true);
    });

    it("a helper that coerces on every path does not propagate", () => {
      expect(hasSqlPhp(`<?php
function clean($v) {
  if (!is_numeric($v)) { return "0"; }
  return $v;
}
function h($conn) {
  mysqli_query($conn, "SELECT " . clean(${SRC}));
}
`)).toBe(false);
    });

    it("a return inside a closure is not the function's return", () => {
      expect(hasSqlPhp(`<?php
function pick($v) {
  $f = function () use ($v) { return $v; };
  return "k";
}
function h($conn) {
  mysqli_query($conn, "SELECT " . pick(${SRC}));
}
`)).toBe(false);
    });
  });

  describe("BOLA dominance", () => {
    const bola = (body: string) => `<?php
function getDoc($conn, $id) {
${body}
}
`;
    const count = (code: string) => phpScan(code).filter(f => f.id === "bola-missing-ownership-check").length;
    const LOOKUP = `$d = Doc::find($id);`;

    it("no ownership check reports", () => {
      expect(count(bola(LOOKUP))).toBe(1);
    });

    it("early exit on mismatch dominates the lookup", () => {
      expect(count(bola(`
  if ($id != $_SESSION['user_id']) { http_response_code(403); exit; }
  ${LOOKUP}`))).toBe(0);
    });

    it("lookup inside the equal arm is protected", () => {
      expect(count(bola(`
  if ($id == $_SESSION['user_id']) {
    ${LOOKUP}
  }`))).toBe(0);
    });

    it("a comparison AFTER the lookup no longer suppresses", () => {
      expect(count(bola(`
  ${LOOKUP}
  if ($id != $_SESSION['user_id']) { exit; }`))).toBe(1);
    });

    it("a comparison whose result is unused no longer suppresses", () => {
      expect(count(bola(`
  $same = $id == $_SESSION['user_id'];
  ${LOOKUP}`))).toBe(1);
    });

    it("a mismatch arm that does NOT terminate does not protect what follows", () => {
      expect(count(bola(`
  if ($id != $_SESSION['user_id']) { error_log("mismatch"); }
  ${LOOKUP}`))).toBe(1);
    });

    it("the comparison held in a variable resolves one hop", () => {
      expect(count(bola(`
  $isOwner = $id === $_SESSION['user_id'];
  if (!$isOwner) { return null; }
  ${LOOKUP}`))).toBe(0);
    });

    it("abort_if on a mismatch dominates the lookup", () => {
      expect(count(bola(`
  abort_if($id != $_SESSION['user_id'], 403);
  ${LOOKUP}`))).toBe(0);
    });

    it("abort_unless on a match dominates the lookup", () => {
      expect(count(bola(`
  abort_unless($id == $_SESSION['user_id'], 403);
  ${LOOKUP}`))).toBe(0);
    });
  });
});

import { scanAstTaintJava, parseJavaSource } from "@/lib/astTaintJava";

describe("Java path sensitivity", () => {
  const javaScan = (content: string) => {
    const cst = parseJavaSource(content);
    if (!cst) throw new Error("parse failed");
    return scanAstTaintJava(content, "A.java", cst);
  };
  // `x` and `t` are request-derived (Spring @RequestParam)
  const method = (body: string, fields = "") => `
public class A {
  ${fields}
  @GetMapping("/a")
  public String a(@RequestParam String x, @RequestParam String t) throws Exception {
${body}
    return "ok";
  }
}`;
  const jSql = (v: string) => `stmt.executeQuery("SELECT * FROM t WHERE a = '" + ${v} + "'");`;
  const hasSqlJ = (code: string) => javaScan(code).some(f => f.id === "sql-injection");

  describe("branches", () => {
    it("tainted on one arm, safe on the other, still reports", () => {
      expect(hasSqlJ(method(`
    String y = "ok";
    if (t == null) { y = x; } else { y = "ok"; }
    ${jSql("y")}`))).toBe(true);
    });

    it("overwritten on every arm does not report", () => {
      expect(hasSqlJ(method(`
    String y = x;
    if (t == null) { y = "one"; } else { y = "two"; }
    ${jSql("y")}`))).toBe(false);
    });

    it("else-if chain merges every arm", () => {
      expect(hasSqlJ(method(`
    String y = "ok";
    if (t == null) { y = "one"; } else if (t.isEmpty()) { y = x; } else { y = "two"; }
    ${jSql("y")}`))).toBe(true);
    });

    it("an arm that returns drops out of the join", () => {
      expect(hasSqlJ(method(`
    String y = "ok";
    if (t == null) { y = x; return "no"; }
    ${jSql("y")}`))).toBe(false);
    });

    it("a throwing arm drops out too", () => {
      expect(hasSqlJ(method(`
    String y = "ok";
    if (t == null) { y = x; throw new IllegalStateException("no"); }
    ${jSql("y")}`))).toBe(false);
    });

    it("code after return is not walked", () => {
      expect(hasSqlJ(`
public class A {
  @GetMapping("/a")
  public String a(@RequestParam String x) throws Exception {
    String y = x;
    return "done";
    ${jSql("y")}
  }
}`)).toBe(false);
    });

    it("braceless if arms are walked", () => {
      expect(hasSqlJ(method(`
    String y = "ok";
    if (t == null) y = x;
    ${jSql("y")}`))).toBe(true);
    });
  });

  describe("expressions", () => {
    it("ternary is the union of its arms only (condition excluded)", () => {
      expect(hasSqlJ(method(`
    String y = x != null ? "a" : "b";
    ${jSql("y")}`))).toBe(false);
      expect(hasSqlJ(method(`
    String y = t == null ? x : "b";
    ${jSql("y")}`))).toBe(true);
    });

    it("nested ternary carries every arm", () => {
      expect(hasSqlJ(method(`
    String y = t == null ? "a" : t.isEmpty() ? x : "b";
    ${jSql("y")}`))).toBe(true);
    });

    it("compound += keeps existing taint", () => {
      expect(hasSqlJ(method(`
    String y = x;
    y += " LIMIT 1";
    ${jSql("y")}`))).toBe(true);
    });

    it("compound += builds a tainted query from a clean prefix", () => {
      expect(hasSqlJ(method(`
    String y = "SELECT * FROM t WHERE a = ";
    y += x;
    stmt.executeQuery(y);`))).toBe(true);
    });

    it("switch expression: value is the union of arm results, not the subject", () => {
      expect(hasSqlJ(method(`
    String y = switch (x) { case "a" -> "one"; default -> "two"; };
    ${jSql("y")}`))).toBe(false);
      expect(hasSqlJ(method(`
    String y = switch (t) { case "a" -> x; default -> "two"; };
    ${jSql("y")}`))).toBe(true);
    });
  });

  describe("loops, try, switch, lambdas", () => {
    it("enhanced for over a tainted collection taints the element", () => {
      expect(hasSqlJ(`
public class A {
  @PostMapping("/a")
  public String a(@RequestBody List<String> items) throws Exception {
    for (String v : items) {
      ${jSql("v")}
    }
    return "ok";
  }
}`)).toBe(true);
    });

    it("loop-carried flow reaches a sink earlier in the body", () => {
      expect(hasSqlJ(method(`
    String prev = "ok";
    for (int i = 0; i < 3; i++) {
      ${jSql("prev")}
      prev = x;
    }`))).toBe(true);
    });

    it("while loop body is walked", () => {
      expect(hasSqlJ(method(`
    String prev = "ok";
    while (t == null) {
      ${jSql("prev")}
      prev = x;
    }`))).toBe(true);
    });

    it("try-body taint reaches a catch handler and the code after", () => {
      expect(hasSqlJ(method(`
    String y = "ok";
    try { y = x; work(); } catch (Exception e) { ${jSql("y")} }`))).toBe(true);
      expect(hasSqlJ(method(`
    String y = "ok";
    try { work(); y = x; } catch (Exception e) { } finally { }
    ${jSql("y")}`))).toBe(true);
    });

    it("the catch variable is not tainted by an outer name", () => {
      expect(hasSqlJ(method(`
    String e = x;
    try { work(); } catch (Exception e) { ${jSql("e")} }`))).toBe(false);
    });

    it("old-style switch clause taint joins after the switch", () => {
      expect(hasSqlJ(method(`
    String y = "ok";
    switch (t) {
      case "1": y = x; break;
      default: y = "ok";
    }
    ${jSql("y")}`))).toBe(true);
    });

    it("a switch that overwrites in every clause (with default) does not report", () => {
      expect(hasSqlJ(method(`
    String y = x;
    switch (t) {
      case "1": y = "one"; break;
      default: y = "two";
    }
    ${jSql("y")}`))).toBe(false);
    });

    it("a lambda parameter shadows a tainted outer name", () => {
      expect(hasSqlJ(method(`
    String y = x;
    java.util.function.Consumer<String> g = y -> { ${jSql("y")} };`))).toBe(false);
    });

    it("a lambda still sees a captured tainted variable", () => {
      expect(hasSqlJ(method(`
    String y = x;
    Runnable g = () -> { ${jSql("y")} };`))).toBe(true);
    });
  });

  describe("narrow guards", () => {
    it("membership in a literal Set.of", () => {
      expect(hasSqlJ(method(`
    if (Set.of("a", "b").contains(x)) {
      ${jSql("x")}
    }`))).toBe(false);
    });

    it("membership in a literal collection field", () => {
      expect(hasSqlJ(method(`
    if (ALLOWED.contains(x)) {
      ${jSql("x")}
    }`, `private static final List<String> ALLOWED = List.of("a", "b");`))).toBe(false);
    });

    it("a collection field that is ever mutated is not trusted", () => {
      expect(hasSqlJ(method(`
    ALLOWED.add(t);
    if (ALLOWED.contains(x)) {
      ${jSql("x")}
    }`, `private static final List<String> ALLOWED = new ArrayList<>(List.of("a", "b"));`))).toBe(true);
    });

    it("\"lit\".equals(x) guards the then-arm", () => {
      expect(hasSqlJ(method(`
    if ("admin".equals(x)) {
      ${jSql("x")}
    }`))).toBe(false);
    });

    it("x.equals(\"lit\") guards the then-arm", () => {
      expect(hasSqlJ(method(`
    if (x.equals("admin")) {
      ${jSql("x")}
    }`))).toBe(false);
    });

    it("!equals with early return guards what follows", () => {
      expect(hasSqlJ(method(`
    if (!"admin".equals(x)) { return "no"; }
    ${jSql("x")}`))).toBe(false);
    });

    it("x instanceof Integer guards the then-arm", () => {
      expect(hasSqlJ(method(`
    Object o = x;
    if (o instanceof Integer) {
      ${jSql("o")}
    }`))).toBe(false);
    });

    it("StringUtils.isNumeric early return guards what follows", () => {
      expect(hasSqlJ(method(`
    if (!StringUtils.isNumeric(x)) { return "no"; }
    ${jSql("x")}`))).toBe(false);
    });

    it("a switch section with literal case labels guards the subject", () => {
      expect(hasSqlJ(method(`
    switch (x) {
      case "a":
      case "b":
        ${jSql("x")}
        break;
    }`))).toBe(false);
    });

    it("&& composes: both conjuncts hold in the then-arm", () => {
      expect(hasSqlJ(method(`
    if (t != null && "admin".equals(x)) {
      ${jSql("x")}
    }`))).toBe(false);
    });

    it("a custom validator is NOT a guard", () => {
      expect(hasSqlJ(method(`
    if (isValid(x)) {
      ${jSql("x")}
    }`))).toBe(true);
    });

    it("startsWith is NOT a guard", () => {
      expect(hasSqlJ(method(`
    if (x.startsWith("a")) {
      ${jSql("x")}
    }`))).toBe(true);
    });

    it("matches() is NOT a guard", () => {
      expect(hasSqlJ(method(`
    if (x.matches("[a-z]+")) {
      ${jSql("x")}
    }`))).toBe(true);
    });

    it("a guard on one variable does not clear another", () => {
      expect(hasSqlJ(method(`
    if ("ok".equals(x)) {
      ${jSql("t")}
    }`))).toBe(true);
    });
  });

  describe("interprocedural summaries", () => {
    it("a helper that builds a query in a local and returns it now propagates", () => {
      expect(hasSqlJ(`
public class A {
  private String build(String v) {
    String q = "SELECT * FROM t WHERE a = '" + v + "'";
    return q;
  }
  @GetMapping("/a")
  public String a(@RequestParam String x) throws Exception {
    stmt.executeQuery(build(x));
    return "ok";
  }
}`)).toBe(true);
    });

    it("a helper that coerces on every path does not propagate", () => {
      expect(hasSqlJ(`
public class A {
  private String clean(String v) {
    if (!StringUtils.isNumeric(v)) { return "0"; }
    return v;
  }
  @GetMapping("/a")
  public String a(@RequestParam String x) throws Exception {
    stmt.executeQuery("SELECT " + clean(x));
    return "ok";
  }
}`)).toBe(false);
    });

    it("a return inside a lambda is not the method's return", () => {
      expect(hasSqlJ(`
public class A {
  private String pick(String v) {
    Supplier<String> f = () -> { return v; };
    return "k";
  }
  @GetMapping("/a")
  public String a(@RequestParam String x) throws Exception {
    stmt.executeQuery("SELECT " + pick(x));
    return "ok";
  }
}`)).toBe(false);
    });
  });

  describe("BOLA dominance", () => {
    const bola = (body: string) => `
public class A {
  @GetMapping("/doc/{id}")
  public Object get(@PathVariable String id, Authentication authentication) {
${body}
    return null;
  }
}`;
    const count = (code: string) => javaScan(code).filter(f => f.id === "bola-missing-ownership-check").length;
    const LOOKUP = `Object d = repo.findById(id);`;

    it("no ownership check reports", () => {
      expect(count(bola(LOOKUP))).toBe(1);
    });

    it("early return on mismatch dominates the lookup", () => {
      expect(count(bola(`
    if (!id.equals(authentication.getName())) { return null; }
    ${LOOKUP}`))).toBe(0);
    });

    it("throw on mismatch dominates the lookup", () => {
      expect(count(bola(`
    if (!id.equals(authentication.getName())) { throw new RuntimeException("no"); }
    ${LOOKUP}`))).toBe(0);
    });

    it("lookup inside the equal arm is protected", () => {
      expect(count(bola(`
    if (id.equals(authentication.getName())) {
      ${LOOKUP}
    }`))).toBe(0);
    });

    it("a comparison AFTER the lookup no longer suppresses", () => {
      expect(count(bola(`
    ${LOOKUP}
    if (!id.equals(authentication.getName())) { return null; }`))).toBe(1);
    });

    it("a comparison whose result is unused no longer suppresses", () => {
      expect(count(bola(`
    boolean same = id.equals(authentication.getName());
    ${LOOKUP}`))).toBe(1);
    });

    it("a mismatch arm that does NOT terminate does not protect what follows", () => {
      expect(count(bola(`
    if (!id.equals(authentication.getName())) { log.warn("mismatch"); }
    ${LOOKUP}`))).toBe(1);
    });

    it("the comparison held in a variable resolves one hop", () => {
      expect(count(bola(`
    boolean isOwner = id.equals(authentication.getName());
    if (!isOwner) { return null; }
    ${LOOKUP}`))).toBe(0);
    });

    it("== comparison with early return", () => {
      expect(count(bola(`
    if (id != authentication.getName()) { return null; }
    ${LOOKUP}`))).toBe(0);
    });

    it("Objects.equals dominates", () => {
      expect(count(bola(`
    if (!Objects.equals(id, authentication.getName())) { return null; }
    ${LOOKUP}`))).toBe(0);
    });
  });
});
