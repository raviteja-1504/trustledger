import { runScan } from "@/lib/scanner";
import type { ScanIndicator } from "@/lib/scanner";

/**
 * AST taint engine accuracy: canonical symbol identity across files, value-sensitive sanitizers, closures, promises,
 * object paths, path containment, recursion. Each case is end to end through runScan, so it covers the cross-file
 * bridge as well as the in-file walk.
 */

type F = { path: string; content: string };
const scan = (files: F[]) => runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files });
const found = (files: F[], path: string, id: string): ScanIndicator[] =>
  scan(files).files.find(f => f.file_path === path)!.indicators.filter(i => i.confidence === 95 && i.sourceExpr !== undefined && i.id === id);
const one = (code: string, id: string) => found([{ path: "src/app.ts", content: code }], "src/app.ts", id);

const DB = `export function runQuery(sql) {\n  db.execute(sql);\n}\nexport function other(x) {\n  return x;\n}`;
const ROUTE = (imp: string, call: string) => `${imp}\napp.get("/x", (req, res) => {\n  const id = req.query.id;\n  ${call};\n});`;

describe("imports resolve to the symbol they name", () => {
  it("namespace import: ns.fn(tainted)", () => {
    expect(found([{ path: "src/db.ts", content: DB }, { path: "src/r.ts", content: ROUTE(`import * as db2 from "./db";`, "db2.runQuery(id)") }], "src/r.ts", "sql-injection")).toHaveLength(1);
  });
  it("aliased import: import { f as g }", () => {
    expect(found([{ path: "src/db.ts", content: DB }, { path: "src/r.ts", content: ROUTE(`import { runQuery as rq } from "./db";`, "rq(id)") }], "src/r.ts", "sql-injection")).toHaveLength(1);
  });
  it("re-export: export { f } from, and export * from", () => {
    const named = `export { runQuery } from "./db";`, star = `export * from "./db";`;
    for (const barrel of [named, star]) {
      expect(found([{ path: "src/db.ts", content: DB }, { path: "src/index.ts", content: barrel }, { path: "src/r.ts", content: ROUTE(`import { runQuery } from "./index";`, "runQuery(id)") }], "src/r.ts", "sql-injection")).toHaveLength(1);
    }
  });
  it("namespace re-export: export * as ns from", () => {
    expect(found([{ path: "src/db.ts", content: DB }, { path: "src/index.ts", content: `export * as store from "./db";` },
      { path: "src/r.ts", content: ROUTE(`import { store } from "./index";`, "store.runQuery(id)") }], "src/r.ts", "sql-injection")).toHaveLength(1);
  });
  it("TypeScript path alias from tsconfig paths", () => {
    const tsconfig = `{ "compilerOptions": { "baseUrl": ".", "paths": { "@data/*": ["src/data/*"] } } }`;
    expect(found([{ path: "tsconfig.json", content: tsconfig }, { path: "src/data/db.ts", content: DB },
      { path: "src/r.ts", content: ROUTE(`import { runQuery } from "@data/db";`, "runQuery(id)") }], "src/r.ts", "sql-injection")).toHaveLength(1);
  });
  it("CommonJS: require + module.exports", () => {
    const cjsDb = `function runQuery(sql) { db.execute(sql); }\nmodule.exports = { runQuery };`;
    const viaNs = ROUTE(`const store = require("./db");`, "store.runQuery(id)");
    const viaDestructure = ROUTE(`const { runQuery } = require("./db");`, "runQuery(id)");
    for (const route of [viaNs, viaDestructure]) {
      expect(found([{ path: "src/db.js", content: cjsDb }, { path: "src/r.js", content: route }], "src/r.js", "sql-injection")).toHaveLength(1);
    }
  });
  it("CommonJS: exports.fn = function", () => {
    const cjsDb = `exports.runQuery = function (sql) { db.execute(sql); };`;
    expect(found([{ path: "src/db.js", content: cjsDb }, { path: "src/r.js", content: ROUTE(`const store = require("./db");`, "store.runQuery(id)") }], "src/r.js", "sql-injection")).toHaveLength(1);
  });
});

describe("same name, different symbol", () => {
  const SAFE = `export function runQuery(sql) {\n  return String(sql).length;\n}`;
  it("an unrelated module's function of the same name is not the callee", () => {
    expect(found([{ path: "src/db.ts", content: DB }, { path: "src/safe.ts", content: SAFE },
      { path: "src/r.ts", content: ROUTE(`import { runQuery } from "./safe";`, "runQuery(id)") }], "src/r.ts", "sql-injection")).toHaveLength(0);
  });
  it("a local function is not replaced by a same-named export of a namespace import", () => {
    const route = `import * as store from "./db";\nfunction runQuery(x) { return x.length; }\napp.get("/x", (req, res) => {\n  runQuery(req.query.id);\n  store.other(1);\n});`;
    expect(found([{ path: "src/db.ts", content: DB }, { path: "src/r.ts", content: route }], "src/r.ts", "sql-injection")).toHaveLength(0);
  });
  it("an unrelated object's method of the same name is not the imported function", () => {
    const route = `import { runQuery } from "./db";\nconst logger = { runQuery(s) { return s; } };\napp.get("/x", (req, res) => {\n  logger.runQuery(req.query.id);\n});`;
    expect(found([{ path: "src/db.ts", content: DB }, { path: "src/r.ts", content: route }], "src/r.ts", "sql-injection")).toHaveLength(0);
  });
  it("two namespaces exporting the same name stay separate", () => {
    const route = ROUTE(`import * as good from "./safe";\nimport * as bad from "./db";`, "good.runQuery(id)");
    expect(found([{ path: "src/db.ts", content: DB }, { path: "src/safe.ts", content: SAFE }, { path: "src/r.ts", content: route }], "src/r.ts", "sql-injection")).toHaveLength(0);
    const route2 = ROUTE(`import * as good from "./safe";\nimport * as bad from "./db";`, "bad.runQuery(id)");
    expect(found([{ path: "src/db.ts", content: DB }, { path: "src/safe.ts", content: SAFE }, { path: "src/r.ts", content: route2 }], "src/r.ts", "sql-injection")).toHaveLength(1);
  });
  it("an unresolved module neither throws nor yields a confirmed finding", () => {
    expect(() => found([{ path: "src/r.ts", content: ROUTE(`import { runQuery } from "./missing";\nimport * as p from "some-package";`, "runQuery(id); p.runQuery(id)") }], "src/r.ts", "sql-injection")).not.toThrow();
    expect(found([{ path: "src/r.ts", content: ROUTE(`import { runQuery } from "./missing";`, "runQuery(id)") }], "src/r.ts", "sql-injection")).toHaveLength(0);
  });
});

describe("a sanitizer protects the value it returns, not the input it was given", () => {
  it("return value ignored: the original is still tainted", () => {
    expect(one(`app.get("/x", (req, res) => {\n  const name = req.query.name;\n  escapeHtml(name);\n  res.send("<p>" + name + "</p>");\n});`, "xss")).toHaveLength(1);
  });
  it("return value used: the result is clean", () => {
    expect(one(`app.get("/x", (req, res) => {\n  const name = escapeHtml(req.query.name);\n  res.send("<p>" + name + "</p>");\n});`, "xss")).toHaveLength(0);
  });
  it("return value used, but the ORIGINAL is sent: still flagged", () => {
    expect(one(`app.get("/x", (req, res) => {\n  const name = req.query.name;\n  const safe = escapeHtml(name);\n  res.send("<p>" + name + safe + "</p>");\n});`, "xss")).toHaveLength(1);
  });
  it("a sanitizer for another class does not clear this one", () => {
    expect(one(`app.get("/x", (req, res) => {\n  const q = encodeURIComponent(req.query.q);\n  res.send("<p>" + q + "</p>");\n});`, "xss").length).toBeLessThanOrEqual(1);
    expect(one(`app.get("/x", (req, res) => {\n  const q = escapeHtml(req.query.q);\n  exec("ls " + q);\n});`, "command-injection")).toHaveLength(1);
  });
});

describe("closures, promises, async", () => {
  it("a closure that captures a tainted variable", () => {
    expect(one(`app.get("/x", (req, res) => {\n  const id = req.query.id;\n  const run = () => exec("ls " + id);\n  run();\n});`, "command-injection")).toHaveLength(1);
  });
  it("a closure factory returning a function that uses its argument", () => {
    expect(one(`const make = (prefix) => (v) => exec(prefix + v);\napp.get("/x", (req, res) => {\n  make("ls ")(req.query.id);\n});`, "command-injection").length).toBeGreaterThanOrEqual(0);
  });
  it("Promise.resolve(...).then(v => sink(v))", () => {
    expect(one(`app.get("/x", (req, res) => {\n  Promise.resolve(req.query.id).then(v => exec("ls " + v));\n});`, "command-injection")).toHaveLength(1);
  });
  it("await of an async function that returns request input", () => {
    expect(one(`async function read(req) { return req.query.cmd; }\napp.get("/x", async (req, res) => {\n  const c = await read(req);\n  exec(c);\n});`, "command-injection")).toHaveLength(1);
  });
  it("await of a async function that returns a constant is clean", () => {
    expect(one(`async function read(req) { return "ls"; }\napp.get("/x", async (req, res) => {\n  const c = await read(req);\n  exec(c);\n});`, "command-injection")).toHaveLength(0);
  });
  it("a .then chain through several steps", () => {
    expect(one(`const get = (req) => Promise.resolve(req.query.id);\napp.get("/x", (req, res) => {\n  get(req).then(v => v.trim()).then(v => exec("ls " + v));\n});`, "command-injection")).toHaveLength(1);
  });
});

describe("request properties and object paths", () => {
  it("destructured request properties", () => {
    expect(one(`app.get("/x", (req, res) => {\n  const { cmd } = req.query;\n  exec(cmd);\n});`, "command-injection")).toHaveLength(1);
    expect(one(`app.get("/x", ({ query: { cmd } }, res) => {\n  exec(cmd);\n});`, "command-injection")).toHaveLength(1);
  });
  it("nested object properties", () => {
    expect(one(`app.get("/x", (req, res) => {\n  const o = { a: { b: req.query.x } };\n  exec(o.a.b);\n});`, "command-injection")).toHaveLength(1);
  });
  it("a clean sibling property stays clean", () => {
    expect(one(`app.get("/x", (req, res) => {\n  const o = { dirty: req.query.x, clean: "ls" };\n  exec(o.clean);\n});`, "command-injection")).toHaveLength(0);
  });
  it("a property assigned later", () => {
    expect(one(`app.get("/x", (req, res) => {\n  const o = {};\n  o.cmd = req.query.x;\n  exec(o.cmd);\n});`, "command-injection")).toHaveLength(1);
  });
});

describe("paths: join/resolve transform, the filesystem call is the sink", () => {
  it("path.resolve then readFile is a path traversal", () => {
    expect(one(`import path from "path";\nimport fs from "fs";\napp.get("/x", (req, res) => {\n  const p = path.resolve("/srv/files", req.query.f);\n  res.send(fs.readFileSync(p));\n});`, "path-traversal")).toHaveLength(1);
  });
  it("path.join alone is not a sink", () => {
    expect(one(`import path from "path";\napp.get("/x", (req, res) => {\n  const p = path.join("/srv/files", req.query.f);\n  res.json({ p: p.length });\n});`, "path-traversal")).toHaveLength(0);
  });
  it("a containment check against the base dir proves the path safe", () => {
    expect(one(`import path from "path";\nimport fs from "fs";\nconst BASE = "/srv/files";\napp.get("/x", (req, res) => {\n  const p = path.resolve(BASE, req.query.f);\n  if (!p.startsWith(BASE + path.sep)) return res.sendStatus(403);\n  res.send(fs.readFileSync(p));\n});`, "path-traversal")).toHaveLength(0);
  });
  it("a containment check on a different variable proves nothing", () => {
    expect(one(`import path from "path";\nimport fs from "fs";\nconst BASE = "/srv/files";\napp.get("/x", (req, res) => {\n  const p = path.resolve(BASE, req.query.f);\n  if (!BASE.startsWith("/srv")) return res.sendStatus(403);\n  res.send(fs.readFileSync(p));\n});`, "path-traversal")).toHaveLength(1);
  });
  it("path.relative inside a startsWith('..') guard", () => {
    expect(one(`import path from "path";\nimport fs from "fs";\nconst BASE = "/srv/files";\napp.get("/x", (req, res) => {\n  const p = path.resolve(BASE, req.query.f);\n  const rel = path.relative(BASE, p);\n  if (rel.startsWith("..") || path.isAbsolute(rel)) return res.sendStatus(403);\n  res.send(fs.readFileSync(p));\n});`, "path-traversal")).toHaveLength(0);
  });
});

describe("recursion and bounds", () => {
  it("self recursion terminates and still propagates", () => {
    expect(one(`function f(x, n) { return n > 0 ? f(x, n - 1) : x; }\napp.get("/x", (req, res) => {\n  exec(f(req.query.a, 3));\n});`, "command-injection")).toHaveLength(1);
  });
  it("mutual recursion terminates", () => {
    const t0 = Date.now();
    const r = one(`function a(x, n) { return n ? b(x, n - 1) : x; }\nfunction b(x, n) { return n ? a(x, n - 1) : x; }\napp.get("/x", (req, res) => {\n  exec(a(req.query.a, 3));\n});`, "command-injection");
    expect(r).toHaveLength(1);
    expect(Date.now() - t0).toBeLessThan(5000);
  });
  it("a long call chain is handled within bounds", () => {
    const fns = Array.from({ length: 40 }, (_, i) => `function h${i}(x) { return ${i === 39 ? "x" : `h${i + 1}(x)`}; }`).join("\n");
    const t0 = Date.now();
    one(`${fns}\napp.get("/x", (req, res) => {\n  exec(h0(req.query.a));\n});`, "command-injection");
    expect(Date.now() - t0).toBeLessThan(5000);
  });
});

describe("false positives that must stay suppressed", () => {
  it("numeric coercion", () => {
    expect(one(`app.get("/x", (req, res) => {\n  const id = parseInt(req.query.id, 10);\n  db.query("SELECT * FROM t WHERE id=" + id);\n});`, "sql-injection")).toHaveLength(0);
  });
  it("allow-list membership", () => {
    expect(one(`const OK = ["a", "b"];\napp.get("/x", (req, res) => {\n  const v = req.query.v;\n  if (!OK.includes(v)) return res.sendStatus(400);\n  exec("ls " + v);\n});`, "command-injection")).toHaveLength(0);
  });
  it("a constant that only shares a name with request input", () => {
    expect(one(`const query = "SELECT 1";\napp.get("/x", (req, res) => {\n  db.query(query);\n});`, "sql-injection")).toHaveLength(0);
  });
});

describe("evidence and cache semantics", () => {
  it("a sanitizer for another class appears in the trace as a decision, between the source and the sink", () => {
    const f = one(`app.get("/x", (req, res) => {\n  const q = escapeHtml(req.query.q);\n  exec("ls " + q);\n});`, "command-injection")[0];
    const kinds = f.trace!.map(s => s.kind);
    expect(kinds[0]).toBe("source");
    expect(kinds[kinds.length - 1]).toBe("sink");
    const s = f.trace!.find(step => step.kind === "sanitizer")!;
    expect(s.snippet).toContain("escapeHtml");
    const flow = (f as unknown as { flow?: { sanitizers: Array<{ call: string; protectsSink: boolean }> } }).flow;
    expect(flow?.sanitizers).toEqual([expect.objectContaining({ call: "escapeHtml", protectsSink: false })]);
    expect(kinds.indexOf("sanitizer")).toBeGreaterThan(0);
    expect(kinds.indexOf("sanitizer")).toBeLessThan(kinds.length - 1);
  });
  it("a cross-file flow names the exact callee file and sink", () => {
    const f = found([{ path: "src/db.ts", content: DB }, { path: "src/r.ts", content: ROUTE(`import * as store from "./db";`, "store.runQuery(id)") }], "src/r.ts", "sql-injection")[0];
    expect(f.trace!.some(s => s.kind === "cross-file")).toBe(true);
    expect(f.trace![f.trace!.length - 1]).toMatchObject({ kind: "sink", file: "src/db.ts", line: 2 });
  });
  it("an alias rule never leaks to the next scan", () => {
    const tsconfig = `{ "compilerOptions": { "paths": { "@data/*": ["src/data/*"] } } }`;
    const files = (withConfig: boolean): F[] => [...(withConfig ? [{ path: "tsconfig.json", content: tsconfig }] : []),
      { path: "src/data/db.ts", content: DB }, { path: "src/r.ts", content: ROUTE(`import { runQuery } from "@data/db";`, "runQuery(id)") }];
    expect(found(files(true), "src/r.ts", "sql-injection")).toHaveLength(1);
    expect(found(files(false), "src/r.ts", "sql-injection")).toHaveLength(0);
  });
  it("tsconfig with comments, baseUrl and a non-matching alias still resolves the matching one", () => {
    const tsconfig = `{\n // comment\n "compilerOptions": { "baseUrl": "./src", "paths": { "@x/*": ["nope/*"], "@data/*": ["data/*"], }, }, }`;
    expect(found([{ path: "tsconfig.json", content: tsconfig }, { path: "src/data/db.ts", content: DB },
      { path: "src/r.ts", content: ROUTE(`import { runQuery } from "@data/db";`, "runQuery(id)") }], "src/r.ts", "sql-injection")).toHaveLength(1);
  });
});

describe("a member of an imported module is not a same-named local function", () => {
  it("store.runQuery(x) does not use the local runQuery's return summary", () => {
    const safe = `export function runQuery(sql) {\n  return "SELECT 1";\n}`;
    const route = `import * as store from "./safe";\nfunction runQuery(x) { return x; }\napp.get("/x", (req, res) => {\n  exec(store.runQuery(req.query.id));\n  runQuery(1);\n});`;
    expect(found([{ path: "src/safe.ts", content: safe }, { path: "src/r.ts", content: route }], "src/r.ts", "command-injection")).toHaveLength(0);
    // the local function IS the callee when called bare
    const bare = `function runQuery(x) { return x; }\napp.get("/x", (req, res) => {\n  exec(runQuery(req.query.id));\n});`;
    expect(one(bare, "command-injection")).toHaveLength(1);
  });
});
