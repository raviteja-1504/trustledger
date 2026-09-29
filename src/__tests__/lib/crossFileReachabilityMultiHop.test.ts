import { runScan } from "@/lib/scanner";
import { computeCrossFileReachable } from "@/lib/crossFileReachability";
import type { ReachFile } from "@/lib/crossFileReachability";

// Multi-hop cross-file reachability. The old bridge was one pass: "is the CALLER reachable from ITS OWN
// file's entry points?". It missed (1) any chain longer than one hop through a function the regex call graph
// doesn't see as an entry point, (2) re-export chains, and (3) the local helpers a cross-file-reached function
// calls (where the sink usually is). See crossFileReachability.ts for the algorithm.

const file = (path: string, over: Partial<ReachFile> = {}): ReachFile =>
  ({ path, edges: [], reachable: new Set(), imports: [], reexports: [], ...over });
const names = (m: Map<string, Set<string>>, path: string) => [...(m.get(path) ?? [])].sort();

describe("computeCrossFileReachable (pure graph algorithm)", () => {
  it("one hop: a reachable caller marks the imported name in the callee file", () => {
    const r = computeCrossFileReachable([
      file("route.ts", { reachable: new Set(["handler"]), edges: [{ caller: "handler", callee: "runQuery" }],
        imports: [{ localName: "runQuery", importedName: "runQuery", resolvedPath: "db.ts" }] }),
      file("db.ts"),
    ]);
    expect(names(r, "db.ts")).toEqual(["runQuery"]);
  });

  it("MANY hops: route -> a.foo -> b.bar -> c.baz, where none of foo/bar is an entry point of its own file", () => {
    const r = computeCrossFileReachable([
      file("route.ts", { reachable: new Set(["handler"]), edges: [{ caller: "handler", callee: "foo" }],
        imports: [{ localName: "foo", importedName: "foo", resolvedPath: "a.ts" }] }),
      file("a.ts", { edges: [{ caller: "foo", callee: "bar" }], imports: [{ localName: "bar", importedName: "bar", resolvedPath: "b.ts" }] }),
      file("b.ts", { edges: [{ caller: "bar", callee: "baz" }], imports: [{ localName: "baz", importedName: "baz", resolvedPath: "c.ts" }] }),
      file("c.ts"),
    ]);
    expect(names(r, "a.ts")).toEqual(["foo"]);
    expect(names(r, "b.ts")).toEqual(["bar"]);
    expect(names(r, "c.ts")).toEqual(["baz"]);      // the old one-pass bridge stopped at b.ts
  });

  it("a reached function makes its own LOCAL callees reachable (the helper that holds the sink)", () => {
    const r = computeCrossFileReachable([
      file("route.ts", { reachable: new Set(["handler"]), edges: [{ caller: "handler", callee: "runQuery" }],
        imports: [{ localName: "runQuery", importedName: "runQuery", resolvedPath: "db.ts" }] }),
      file("db.ts", { edges: [{ caller: "runQuery", callee: "helper" }, { caller: "helper", callee: "deepHelper" }] }),
    ]);
    expect(names(r, "db.ts")).toEqual(["deepHelper", "helper", "runQuery"]);
  });

  it("follows `export { x } from` (renamed) to the real declaration", () => {
    const r = computeCrossFileReachable([
      file("route.ts", { reachable: new Set(["handler"]), edges: [{ caller: "handler", callee: "exec" }],
        imports: [{ localName: "exec", importedName: "exec", resolvedPath: "barrel.ts" }] }),
      file("barrel.ts", { reexports: [{ publicName: "exec", importedName: "runQuery", resolvedPath: "db.ts" }] }),
      file("db.ts"),
    ]);
    expect(names(r, "db.ts")).toEqual(["runQuery"]);   // the name in the DECLARING file, not the barrel's public alias
  });

  it("follows `export *` and chains of barrels", () => {
    const r = computeCrossFileReachable([
      file("route.ts", { reachable: new Set(["handler"]), edges: [{ caller: "handler", callee: "runQuery" }],
        imports: [{ localName: "runQuery", importedName: "runQuery", resolvedPath: "outer.ts" }] }),
      file("outer.ts", { reexports: [{ publicName: null, importedName: null, resolvedPath: "inner.ts" }] }),
      file("inner.ts", { reexports: [{ publicName: "runQuery", importedName: "runQuery", resolvedPath: "db.ts" }] }),
      file("db.ts"),
    ]);
    expect(names(r, "db.ts")).toEqual(["runQuery"]);
  });

  it("namespace import: `ns.f()` is recorded by its tail name, so every export of the namespace's module is a candidate", () => {
    const r = computeCrossFileReachable([
      file("route.ts", { reachable: new Set(["handler"]), edges: [{ caller: "handler", callee: "runQuery" }],
        imports: [{ localName: "ns", importedName: "*", namespace: true, resolvedPath: "db.ts" }] }),
      file("db.ts"),
    ]);
    expect(names(r, "db.ts")).toEqual(["runQuery"]);
  });

  it("terminates on cycles (a.foo <-> b.bar) and marks both", () => {
    const r = computeCrossFileReachable([
      file("route.ts", { reachable: new Set(["handler"]), edges: [{ caller: "handler", callee: "foo" }],
        imports: [{ localName: "foo", importedName: "foo", resolvedPath: "a.ts" }] }),
      file("a.ts", { edges: [{ caller: "foo", callee: "bar" }], imports: [{ localName: "bar", importedName: "bar", resolvedPath: "b.ts" }] }),
      file("b.ts", { edges: [{ caller: "bar", callee: "foo" }], imports: [{ localName: "foo", importedName: "foo", resolvedPath: "a.ts" }] }),
    ]);
    expect(names(r, "a.ts")).toEqual(["foo"]);
    expect(names(r, "b.ts")).toEqual(["bar"]);
  });

  it("a name already reachable from the file's OWN entry points is not repeated, but its outgoing hops are still followed", () => {
    const r = computeCrossFileReachable([
      file("a.ts", { reachable: new Set(["foo"]), edges: [{ caller: "foo", callee: "bar" }], imports: [{ localName: "bar", importedName: "bar", resolvedPath: "b.ts" }] }),
      file("b.ts"),
    ]);
    expect(r.has("a.ts")).toBe(false);
    expect(names(r, "b.ts")).toEqual(["bar"]);
  });

  it("an UNREACHABLE caller seeds nothing", () => {
    const r = computeCrossFileReachable([
      file("dead.ts", { edges: [{ caller: "deadFn", callee: "runQuery" }], imports: [{ localName: "runQuery", importedName: "runQuery", resolvedPath: "db.ts" }] }),
      file("db.ts"),
    ]);
    expect(r.size).toBe(0);
  });

  it("external / unresolvable specifiers are ignored and never throw", () => {
    expect(() => computeCrossFileReachable([
      file("route.ts", { reachable: new Set(["handler"]), edges: [{ caller: "handler", callee: "x" }],
        imports: [{ localName: "x", importedName: "x", resolvedPath: null }], reexports: [{ publicName: null, importedName: null, resolvedPath: null }] }),
    ])).not.toThrow();
  });

  it("only files with something to report appear in the result", () => {
    const r = computeCrossFileReachable([file("lonely.ts"), file("other.ts")]);
    expect(r.size).toBe(0);
  });
});

// ── end to end through runScan: the `reachability` of a real finding ────────────────────────────────
// Every db-side file exports via a SEPARATE `export { ... }` list, which callGraph.ts's regex does NOT treat as
// an entry point -- so anything reachable there is reachable only THANKS TO the cross-file bridge.
// The handlers pass `req.user.id` (set by auth middleware, not request input): with request input the sink would
// be part of a proven cross-file flow, and its finding folded into the handler's (findingCorrelation.ts) --
// these tests are about the CALL-GRAPH reachability of a sink no flow is proven to.
const SQL_FN = (name: string) => `function ${name}(id) {
  const sql = "SELECT * FROM t WHERE id = " + id;
  return db.query(sql);
}`;
const scan = (files: Array<{ path: string; content: string }>) =>
  runScan({ repo: "acme/app", pr_number: 1, commit_sha: "abc123", files });
const reach = (r: ReturnType<typeof scan>, path: string) =>
  r.files.find(f => f.file_path === path)!.indicators.find(i => i.id === "sql-injection")?.reachability;

describe("multi-hop reachability in a real scan", () => {
  it("route -> b.forward -> c.runQuery: the sink two files away is reachable, not 'unreachable'", () => {
    const r = scan([
      { path: "src/c.ts", content: `${SQL_FN("runQuery")}\nexport { runQuery };\n` },
      { path: "src/b.ts", content: `import { runQuery } from "./c";\nfunction forward(id) {\n  return runQuery(id);\n}\nexport { forward };\n` },
      { path: "src/a.ts", content: `import { forward } from "./b";\nexport function handler(req) {\n  return forward(req.user.id);\n}\n` },
    ]);
    expect(reach(r, "src/c.ts")).toBe("reachable");
  });

  it("through a re-export barrel", () => {
    const r = scan([
      { path: "src/db.ts", content: `${SQL_FN("runQuery")}\nexport { runQuery };\n` },
      { path: "src/barrel.ts", content: `export { runQuery } from "./db";\n` },
      { path: "src/api.ts", content: `import { runQuery } from "./barrel";\nexport function handler(req) {\n  return runQuery(req.user.id);\n}\n` },
    ]);
    expect(reach(r, "src/db.ts")).toBe("reachable");
  });

  it("the sink sits in a LOCAL helper of the cross-file-reached function (helper itself is never imported)", () => {
    const r = scan([
      { path: "src/db.ts", content: `${SQL_FN("helper")}\nfunction runQuery(id) {\n  return helper(id);\n}\nexport { runQuery };\n` },
      { path: "src/api.ts", content: `import { runQuery } from "./db";\nexport function handler(req) {\n  return runQuery(req.user.id);\n}\n` },
    ]);
    expect(reach(r, "src/db.ts")).toBe("reachable");
  });

  it("control: a file nothing reachable calls stays unreachable", () => {
    const r = scan([
      { path: "src/dead.ts", content: `${SQL_FN("deadHelper")}\nexport { deadHelper };\n` },
      { path: "src/api.ts", content: `export function handler(req) {\n  return 1;\n}\n` },
    ]);
    expect(reach(r, "src/dead.ts")).toBe("unreachable");
  });

  it("control: a caller that is itself unreachable does not make its callee reachable, at any depth", () => {
    const r = scan([
      { path: "src/c.ts", content: `${SQL_FN("runQuery")}\nexport { runQuery };\n` },
      { path: "src/b.ts", content: `import { runQuery } from "./c";\nfunction neverCalled(id) {\n  return runQuery(id);\n}\nexport { neverCalled };\n` },
      { path: "src/a.ts", content: `export function handler(req) {\n  return 1;\n}\n` },
    ]);
    expect(reach(r, "src/c.ts")).toBe("unreachable");
  });

  it("stays 'reachable', never promoted to 'entry-point', for a multi-hop function (it is not a network-facing handler)", () => {
    const r = scan([
      { path: "src/c.ts", content: `${SQL_FN("runQuery")}\nexport { runQuery };\n` },
      { path: "src/b.ts", content: `import { runQuery } from "./c";\nfunction forward(id) {\n  return runQuery(id);\n}\nexport { forward };\n` },
      { path: "src/a.ts", content: `import { forward } from "./b";\nexport function handler(req) {\n  return forward(req.user.id);\n}\n` },
    ]);
    expect(reach(r, "src/c.ts")).not.toBe("entry-point");
  });
});
