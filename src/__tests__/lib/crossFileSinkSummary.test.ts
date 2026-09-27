import { runScan } from "@/lib/scanner";
import type { ScanIndicator } from "@/lib/scanner";
import { resolveCrossFile } from "@/lib/taint/crossFile";
import type { FileGraph } from "@/lib/taint/crossFile";
import { mergeSinkFacts, MAX_SINK_FACTS_PER_FN, SinkClass } from "@/lib/taint/taintCore";
import type { ParamSinkFact } from "@/lib/taint/taintCore";

// Cross-file PARAMETER -> SINK summaries. Before this, a cross-file summary said only which parameters reach
// a function's RETURN value, so `runQuery(req.query.id)` was invisible when runQuery's body sinks its
// parameter and returns nothing -- the same-file "seed the callee's params and re-walk its body" pass can't
// reach a body in another file. These pin the new behaviour and its boundaries.

type F = { path: string; content: string };
const scan = (files: F[]) => runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files });
const ast = (r: ReturnType<typeof scan>, path: string, id?: string): ScanIndicator[] =>
  r.files.find(f => f.file_path === path)!.indicators
    .filter(i => i.confidence === 95 && i.sourceExpr !== undefined && (id === undefined || i.id === id));

const SQL_WRAPPER = `export function runQuery(sql) {
  db.execute(sql);
}`;
const ROUTE_CALLING = (call: string, imp = `import { runQuery } from "./db";`) => `${imp}
app.get("/x", (req, res) => {
  const id = req.query.id;
  ${call};
});`;

describe("core: a wrapper that sinks its parameter and returns nothing", () => {
  it("reports at the CALL SITE in the calling file, id and confidence like an in-file finding", () => {
    const r = scan([{ path: "src/db.ts", content: SQL_WRAPPER }, { path: "src/route.ts", content: ROUTE_CALLING("runQuery(id)") }]);
    const found = ast(r, "src/route.ts", "sql-injection");
    expect(found).toHaveLength(1);
    expect(found[0].line).toBe(4);                              // the runQuery(id) call line in the route
    expect(found[0].severity).toBe("critical");
    expect(found[0].sinkExpr).toContain("runQuery");
    expect(found[0].sinkExpr).toContain("db.execute");
  });

  it("does NOT report anything in the callee file for it (the callee alone has no untrusted input)", () => {
    const r = scan([{ path: "src/db.ts", content: SQL_WRAPPER }, { path: "src/route.ts", content: ROUTE_CALLING("runQuery(id)") }]);
    expect(ast(r, "src/db.ts")).toHaveLength(0);
  });

  it("the trace ends with a cross-file step and the callee's REAL sink location (file + line)", () => {
    const r = scan([{ path: "src/db.ts", content: SQL_WRAPPER }, { path: "src/route.ts", content: ROUTE_CALLING("runQuery(id)") }]);
    const trace = ast(r, "src/route.ts", "sql-injection")[0].trace!;
    const kinds = trace.map(s => s.kind);
    expect(kinds[0]).toBe("source");
    expect(kinds.slice(-2)).toEqual(["cross-file", "sink"]);
    const sink = trace[trace.length - 1];
    expect(sink.file).toBe("src/db.ts");
    expect(sink.line).toBe(2);                                  // `db.execute(sql);` is line 2 of the callee
    expect(sink.label).toBe("db.execute");
    expect(trace[trace.length - 2].file).toBe("src/route.ts");
  });

  it("the detail names the sink's file:line and the module it crossed into", () => {
    const r = scan([{ path: "src/db.ts", content: SQL_WRAPPER }, { path: "src/route.ts", content: ROUTE_CALLING("runQuery(id)") }]);
    const d = ast(r, "src/route.ts", "sql-injection")[0].detail!;
    expect(d).toContain("src/db.ts:2");
    expect(d).toContain(`imported from ./db`);
  });

  it("an untainted argument is not reported", () => {
    const r = scan([{ path: "src/db.ts", content: SQL_WRAPPER }, { path: "src/route.ts", content: ROUTE_CALLING(`runQuery("SELECT 1")`) }]);
    expect(ast(r, "src/route.ts")).toHaveLength(0);
  });
});

describe("binding is per PARAMETER, not per call", () => {
  const helper = `export function run(label, sql) {
  console.log(label);
  db.execute(sql);
}`;
  const imp = `import { run } from "./db";`;
  it("taint on the parameter that reaches the sink is reported", () => {
    const r = scan([{ path: "src/db.ts", content: helper }, { path: "src/route.ts", content: ROUTE_CALLING(`run("q", id)`, imp) }]);
    expect(ast(r, "src/route.ts", "sql-injection")).toHaveLength(1);
  });
  it("taint on a parameter that never reaches the sink is NOT reported", () => {
    const r = scan([{ path: "src/db.ts", content: helper }, { path: "src/route.ts", content: ROUTE_CALLING(`run(id, "SELECT 1")`, imp) }]);
    expect(ast(r, "src/route.ts")).toHaveLength(0);
  });
  it("a rest parameter binds every argument from its index", () => {
    const rest = `export function runAll(...parts) {
  db.execute(parts[0]);
}`;
    const r = scan([{ path: "src/db.ts", content: rest }, { path: "src/route.ts", content: ROUTE_CALLING(`runAll("a", id)`, `import { runAll } from "./db";`) }]);
    expect(ast(r, "src/route.ts", "sql-injection")).toHaveLength(1);
  });
});

describe("sanitization is honoured per sink class, on both sides of the call", () => {
  it("a callee that coerces its parameter to an integer before the sink is not a sink for that parameter", () => {
    const safe = `export function runQuery(sql) {
  db.execute(parseInt(sql, 10));
}`;
    const r = scan([{ path: "src/db.ts", content: safe }, { path: "src/route.ts", content: ROUTE_CALLING("runQuery(id)") }]);
    expect(ast(r, "src/route.ts")).toHaveLength(0);
  });

  it("a caller that coerces the argument to an integer before crossing is not reported", () => {
    const r = scan([{ path: "src/db.ts", content: SQL_WRAPPER }, { path: "src/route.ts", content: ROUTE_CALLING("runQuery(parseInt(id, 10))") }]);
    expect(ast(r, "src/route.ts")).toHaveLength(0);
  });

  it("clearing the WRONG class in the caller does not hide the flow (path.basename clears path, not SQL)", () => {
    const r = scan([{ path: "src/db.ts", content: SQL_WRAPPER }, { path: "src/route.ts", content: ROUTE_CALLING("runQuery(path.basename(id))") }]);
    expect(ast(r, "src/route.ts", "sql-injection")).toHaveLength(1);
  });

  it("clearing the RIGHT class in the caller does (path.basename before a path-traversal wrapper)", () => {
    const pathWrapper = `export function readIt(p) {
  fs.readFile(p);
}`;
    const imp = `import { readIt } from "./io";`;
    const flagged = scan([{ path: "src/io.ts", content: pathWrapper }, { path: "src/route.ts", content: ROUTE_CALLING("readIt(id)", imp) }]);
    expect(ast(flagged, "src/route.ts", "path-traversal")).toHaveLength(1);
    const cleared = scan([{ path: "src/io.ts", content: pathWrapper }, { path: "src/route.ts", content: ROUTE_CALLING("readIt(path.basename(id))", imp) }]);
    expect(ast(cleared, "src/route.ts", "path-traversal")).toHaveLength(0);
  });
});

describe("multi-hop: the summary composes through calls, within and across files", () => {
  it("through a same-file helper inside the callee (exported run -> local helper -> sink)", () => {
    const callee = `export function run(x) {
  helper(x);
}
function helper(y) {
  db.execute(y);
}`;
    const r = scan([{ path: "src/db.ts", content: callee }, { path: "src/route.ts", content: ROUTE_CALLING("run(id)", `import { run } from "./db";`) }]);
    const f = ast(r, "src/route.ts", "sql-injection");
    expect(f).toHaveLength(1);
    expect(f[0].detail).toContain("run -> helper");             // attribution of the path taken
    expect(f[0].trace![f[0].trace!.length - 1].line).toBe(5);   // the ORIGINAL sink line, not the helper's call line
  });

  it("through another FILE (route -> b.forward -> c.runQuery -> sink), one fixed-point round per hop", () => {
    const c = SQL_WRAPPER;
    const b = `import { runQuery } from "./c";
export function forward(x) {
  runQuery(x);
}`;
    const r = scan([
      { path: "src/c.ts", content: c }, { path: "src/b.ts", content: b },
      { path: "src/route.ts", content: ROUTE_CALLING("forward(id)", `import { forward } from "./b";`) },
    ]);
    const f = ast(r, "src/route.ts", "sql-injection");
    expect(f).toHaveLength(1);
    expect(f[0].detail).toContain("src/c.ts:2");                // the sink's own file, not the intermediate hop's
    expect(f[0].detail).toContain("forward -> runQuery");
    // ...and the middle hop, which has no untrusted input of its own, reports nothing.
    expect(ast(r, "src/b.ts")).toHaveLength(0);
  });

  it("a wrapper that pipes an imported helper's RETURN value into a sink (shapes and sinks work together)", () => {
    const build = `export function buildQuery(input) {
  return \`SELECT * FROM t WHERE id=\${input}\`;
}`;
    const exec = `import { buildQuery } from "./build";
export function runById(id) {
  db.execute(buildQuery(id));
}`;
    const r = scan([
      { path: "src/build.ts", content: build }, { path: "src/exec.ts", content: exec },
      { path: "src/route.ts", content: ROUTE_CALLING("runById(id)", `import { runById } from "./exec";`) },
    ]);
    expect(ast(r, "src/route.ts", "sql-injection")).toHaveLength(1);
  });

  describe("a middle hop that sanitizes before forwarding", () => {
    const io = `export function readIt(p) {\n  fs.readFile(p);\n}`;
    const routeVia = (fn: string) => ROUTE_CALLING(`${fn}(id)`, `import { ${fn} } from "./mid";`);
    it("clearing the SINK'S class in the middle hop removes the fact (basename before a path sink)", () => {
      const mid = `import { readIt } from "./io";\nexport function safeRead(p) {\n  readIt(path.basename(p));\n}`;
      const r = scan([{ path: "src/io.ts", content: io }, { path: "src/mid.ts", content: mid }, { path: "src/route.ts", content: routeVia("safeRead") }]);
      expect(ast(r, "src/route.ts")).toHaveLength(0);
    });
    it("clearing a DIFFERENT class in the middle hop does not (basename clears path, this sink is SQL)", () => {
      const mid = `import { runQuery } from "./io";\nexport function viaBase(p) {\n  runQuery(path.basename(p));\n}`;
      const r = scan([{ path: "src/io.ts", content: SQL_WRAPPER }, { path: "src/mid.ts", content: mid }, { path: "src/route.ts", content: routeVia("viaBase") }]);
      expect(ast(r, "src/route.ts", "sql-injection")).toHaveLength(1);
    });
    it("the same middle hop WITHOUT the sanitizer does forward the fact (control)", () => {
      const mid = `import { readIt } from "./io";\nexport function rawRead(p) {\n  readIt(p);\n}`;
      const r = scan([{ path: "src/io.ts", content: io }, { path: "src/mid.ts", content: mid }, { path: "src/route.ts", content: routeVia("rawRead") }]);
      expect(ast(r, "src/route.ts", "path-traversal")).toHaveLength(1);
    });
  });

  it("terminates on (mutually) recursive forwarders and reports the sink once", () => {
    const rec = `export function loop(x) {
  loop(x);
  db.execute(x);
}`;
    const r = scan([{ path: "src/db.ts", content: rec }, { path: "src/route.ts", content: ROUTE_CALLING("loop(id)", `import { loop } from "./db";`) }]);
    expect(ast(r, "src/route.ts", "sql-injection")).toHaveLength(1);
  });
});

describe("import / export forms", () => {
  it("default export", () => {
    const d = `export default function runQuery(sql) {
  db.execute(sql);
}`;
    const r = scan([{ path: "src/db.ts", content: d }, { path: "src/route.ts", content: ROUTE_CALLING("runQuery(id)", `import runQuery from "./db";`) }]);
    expect(ast(r, "src/route.ts", "sql-injection")).toHaveLength(1);
  });

  it("renamed named import (`import { runQuery as rq }`)", () => {
    const r = scan([{ path: "src/db.ts", content: SQL_WRAPPER }, { path: "src/route.ts", content: ROUTE_CALLING("rq(id)", `import { runQuery as rq } from "./db";`) }]);
    expect(ast(r, "src/route.ts", "sql-injection")).toHaveLength(1);
  });

  it("namespace import (`import * as d` then `d.runQuery(id)`)", () => {
    const r = scan([{ path: "src/db.ts", content: SQL_WRAPPER }, { path: "src/route.ts", content: ROUTE_CALLING("d.runQuery(id)", `import * as d from "./db";`) }]);
    expect(ast(r, "src/route.ts", "sql-injection")).toHaveLength(1);
  });

  it("`export { x } from` re-export barrel", () => {
    const r = scan([
      { path: "src/db.ts", content: SQL_WRAPPER },
      { path: "src/barrel.ts", content: `export { runQuery } from "./db";` },
      { path: "src/route.ts", content: ROUTE_CALLING("runQuery(id)", `import { runQuery } from "./barrel";`) },
    ]);
    expect(ast(r, "src/route.ts", "sql-injection")).toHaveLength(1);
  });

  it("`export *` re-export barrel", () => {
    const r = scan([
      { path: "src/db.ts", content: SQL_WRAPPER },
      { path: "src/barrel.ts", content: `export * from "./db";` },
      { path: "src/route.ts", content: ROUTE_CALLING("runQuery(id)", `import { runQuery } from "./barrel";`) },
    ]);
    expect(ast(r, "src/route.ts", "sql-injection")).toHaveLength(1);
  });

  it("CommonJS (`exports.x = function`, `const { x } = require`)", () => {
    const cjs = `exports.runQuery = function (sql) {
  db.execute(sql);
};`;
    const r = scan([{ path: "src/db.js", content: cjs }, { path: "src/route.js", content: ROUTE_CALLING("runQuery(id)", `const { runQuery } = require("./db");`) }]);
    expect(ast(r, "src/route.js", "sql-injection")).toHaveLength(1);
  });

  it("an unresolvable/external import never throws and reports nothing", () => {
    const route = ROUTE_CALLING("runQuery(id)", `import { runQuery } from "some-external-package";`);
    expect(() => scan([{ path: "src/route.ts", content: route }])).not.toThrow();
    expect(ast(scan([{ path: "src/route.ts", content: route }]), "src/route.ts")).toHaveLength(0);
  });
});

describe("precision: a call resolves only when the target is unambiguous", () => {
  const sendWrapper = `export function send(html) {
  res.send(html);
}`;
  it("an imported wrapper called by name is flagged", () => {
    const r = scan([{ path: "src/out.ts", content: sendWrapper }, { path: "src/route.ts", content: ROUTE_CALLING("send(id)", `import { send } from "./out";`) }]);
    expect(ast(r, "src/route.ts", "xss")).toHaveLength(1);
  });
  it("`emitter.send(x)` on an unrelated object is NOT mistaken for the imported `send`", () => {
    const r = scan([{ path: "src/out.ts", content: sendWrapper }, { path: "src/route.ts", content: ROUTE_CALLING("emitter.send(id)", `import { send } from "./out";`) }]);
    expect(ast(r, "src/route.ts", "xss")).toHaveLength(0);
  });
});

// ── parity: the summary walk's sink decision must agree with the main scan's, sink shape by shape ─────
describe("parity with the same-file scan for every sink shape", () => {
  const cases: Array<{ name: string; id: string; body: string }> = [
    { name: "sql",       id: "sql-injection",     body: "db.execute(p);" },
    { name: "command",   id: "command-injection", body: "exec(p);" },
    { name: "path",      id: "path-traversal",    body: "fs.readFile(p);" },
    { name: "ssrf",      id: "ssrf",              body: "fetch(p);" },
    { name: "xss",       id: "xss",               body: "res.send(p);" },
    { name: "innerHTML", id: "xss",               body: "el.innerHTML = p;" },
    { name: "redirect",  id: "open-redirect",     body: "res.redirect(p);" },
    { name: "header",    id: "header-injection",  body: `res.setHeader("X-A", p);` },
    { name: "nosql",     id: "nosql-injection",   body: "users.find(p);" },
    { name: "eval",      id: "eval-exec",         body: "eval(p);" },
  ];
  for (const c of cases) {
    it(`${c.name}: same finding id whether the wrapper is in the same file or another`, () => {
      const def = `export function wrap(p) {\n  ${c.body}\n}`;
      const call = `app.get("/x", (req, res) => {\n  wrap(req.query.v);\n});`;
      const sameFile = scan([{ path: "src/one.ts", content: `${def}\n${call}` }]);
      expect(ast(sameFile, "src/one.ts", c.id).length).toBeGreaterThan(0);          // the main scan flags this shape...
      const cross = scan([{ path: "src/lib.ts", content: def }, { path: "src/route.ts", content: `import { wrap } from "./lib";\n${call}` }]);
      expect(ast(cross, "src/route.ts", c.id)).toHaveLength(1);                     // ...and so must the cross-file summary
    });
  }
});

// ── orchestrator + merge units ──────────────────────────────────────────────────────────────────────
const fact = (over: Partial<ParamSinkFact> = {}): ParamSinkFact => ({
  index: 0, isRest: false, id: "sql-injection", sinkClass: SinkClass.SQL, sinkExpr: "db.execute", file: "c.ts", line: 3, via: ["f"], ...over,
});

describe("mergeSinkFacts", () => {
  it("is a set-union: the same sink reached by two routes is one fact, and the first route's via wins", () => {
    const into: ParamSinkFact[] = [fact({ via: ["a"] })];
    expect(mergeSinkFacts(into, [fact({ via: ["a", "b", "c"] })])).toBe(false);
    expect(into).toHaveLength(1);
    expect(into[0].via).toEqual(["a"]);
  });
  it("distinguishes by parameter index, sink location and expression", () => {
    const into: ParamSinkFact[] = [];
    mergeSinkFacts(into, [fact(), fact({ index: 1 }), fact({ line: 9 }), fact({ sinkExpr: "db.query" })]);
    expect(into).toHaveLength(4);
  });
  it("is capped deterministically and a fact the cap drops does not count as growth", () => {
    const into: ParamSinkFact[] = [];
    mergeSinkFacts(into, Array.from({ length: MAX_SINK_FACTS_PER_FN + 5 }, (_, i) => fact({ line: i + 1 })));
    expect(into).toHaveLength(MAX_SINK_FACTS_PER_FN);
    const before = into.map(f => f.line);
    // sorts after everything kept (key ends "...:c.ts:99") so it is evicted immediately
    expect(mergeSinkFacts(into, [fact({ line: 99999 })])).toBe(false);
    expect(into.map(f => f.line)).toEqual(before);
  });
});

describe("resolveCrossFile carries sink facts through the same graph as shapes", () => {
  const noShapes = () => new Map();
  const graph = (path: string, imports: FileGraph["imports"], reexports: FileGraph["reexports"], sinks?: FileGraph["computeSinks"]): FileGraph => ({
    path, imports, reexports, computeSummary: noShapes, computeSinks: sinks,
  });
  const resolve = (_from: string, spec: string) => `${spec.replace("./", "")}.ts`;

  it("named import, namespace import, and re-export chain", () => {
    const f = fact();
    const files: FileGraph[] = [
      graph("c.ts", [], [], () => new Map([["run", [f]]])),
      graph("barrel.ts", [], [{ publicName: null, importedName: null, moduleSpecifier: "./c" }]),
      graph("named.ts", [{ localName: "run", importedName: "run", moduleSpecifier: "./c" }], []),
      graph("ns.ts", [{ localName: "lib", importedName: "*", moduleSpecifier: "./barrel", namespace: true }], []),
    ];
    const bridge = resolveCrossFile(files, resolve);
    expect(bridge.propagatingByFile.get("named.ts")!.get("run")!.sinks).toEqual([f]);
    expect(bridge.propagatingByFile.get("ns.ts")!.get("run")!.sinks).toEqual([f]);          // via the export * barrel
    expect(bridge.propagatingByFile.get("ns.ts")!.get("run")!.resolvedPath).toBe("barrel.ts");
  });

  it("an engine without computeSinks is unaffected (optional)", () => {
    const bridge = resolveCrossFile([graph("a.ts", [], [])], resolve);
    expect(bridge.sinkSummaries.get("a.ts")!.size).toBe(0);
    expect(bridge.propagatingByFile.size).toBe(0);
  });

  it("a facts-only entry (no return shapes) still appears in the bridge", () => {
    const f = fact();
    const bridge = resolveCrossFile([
      graph("c.ts", [], [], () => new Map([["run", [f]]])),
      graph("route.ts", [{ localName: "run", importedName: "run", moduleSpecifier: "./c" }], []),
    ], resolve);
    const e = bridge.propagatingByFile.get("route.ts")!.get("run")!;
    expect(e.shapes).toEqual([]);
    expect(e.sinks).toEqual([f]);
  });
});
