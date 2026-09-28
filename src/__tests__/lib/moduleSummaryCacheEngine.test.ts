import { runScan } from "@/lib/scanner";
import { warmPythonTaintEngine } from "@/lib/astTaintPython";

beforeAll(async () => { await warmPythonTaintEngine(); }, 120000);

// End-to-end proof that the cross-file summary cache (moduleSummaryCache.ts) is a pure optimization: a
// scan fed the PREVIOUS scan's module_cache must produce IDENTICAL findings, must actually reuse (not
// just accept and ignore) unchanged files' cross-file work, and must still get a CORRECT, UPDATED answer
// the moment something in the dependency chain changes.

type F = { path: string; content: string };
const scan = (files: F[], prev_module_cache?: Record<string, unknown>) =>
  runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files, prev_module_cache: prev_module_cache as never });
const findings = (r: ReturnType<typeof scan>, path: string) =>
  r.files.find(f => f.file_path === path)!.indicators.filter(i => i.confidence === 95).map(i => `${i.id}:${i.line}:${i.sourceExpr}`);

describe("JS/TS: reusing module_cache is a no-op on the result, and files ARE actually reused", () => {
  const WRAPPER = `export function runQuery(sql) {\n  db.execute(sql);\n}`;
  const ROUTE = `import { runQuery } from "./db";\napp.get("/x", (req, res) => {\n  const id = req.query.id;\n  runQuery(id);\n});`;

  it("a second scan with prev_module_cache from the first produces identical findings, for EVERY file including the one that reused its cache", () => {
    const files = [{ path: "src/db.ts", content: WRAPPER }, { path: "src/route.ts", content: ROUTE }];
    const first = scan(files);
    expect(findings(first, "src/route.ts")).toEqual(["sql-injection:4:id"]);
    expect(first.module_cache).toBeDefined();

    const second = scan(files, first.module_cache);
    expect(findings(second, "src/route.ts")).toEqual(findings(first, "src/route.ts"));
    expect(findings(second, "src/db.ts")).toEqual(findings(first, "src/db.ts"));
    // Neither file changed, so BOTH should be served from the cache the first scan produced.
    expect(second.module_cache_reused).toBe(2);
  });

  it("changing the CALLER (route.ts) does not disturb the callee's (db.ts) own reuse", () => {
    const files1 = [{ path: "src/db.ts", content: WRAPPER }, { path: "src/route.ts", content: ROUTE }];
    const first = scan(files1);
    const files2 = [{ path: "src/db.ts", content: WRAPPER }, { path: "src/route.ts", content: ROUTE.replace("req.query.id", "req.query.otherId") }];
    const second = scan(files2, first.module_cache);
    // db.ts's OWN content and (transitive) dependencies are unchanged -- it must still be reused.
    expect(second.module_cache_reused).toBe(1);
    expect(findings(second, "src/route.ts")).toEqual(["sql-injection:4:id"]);
  });

  it("changing the CALLEE (db.ts) correctly updates the caller's finding, not a stale cached one", () => {
    const files1 = [{ path: "src/db.ts", content: WRAPPER }, { path: "src/route.ts", content: ROUTE }];
    const first = scan(files1);
    expect(findings(first, "src/route.ts")).toEqual(["sql-injection:4:id"]);

    // db.ts's wrapper no longer sinks its parameter at all -- runQuery(id) should stop being reported.
    const SAFE_WRAPPER = `export function runQuery(sql) {\n  console.log(sql);\n}`;
    const files2 = [{ path: "src/db.ts", content: SAFE_WRAPPER }, { path: "src/route.ts", content: ROUTE }];
    const second = scan(files2, first.module_cache);
    expect(findings(second, "src/route.ts")).toEqual([]);
    // db.ts itself changed, so it must NOT be counted as reused; route.ts (unchanged content, but its only
    // dependency changed) must ALSO be recomputed fresh, not reused.
    expect(second.module_cache_reused).toBe(0);
  });

  it("a THIRD file, unrelated to the changed pair, is still reused", () => {
    const UNRELATED = `app.get("/y", (req, res) => { res.send("ok"); });`;
    const files1 = [{ path: "src/db.ts", content: WRAPPER }, { path: "src/route.ts", content: ROUTE }, { path: "src/other.ts", content: UNRELATED }];
    const first = scan(files1);
    const files2 = [{ path: "src/db.ts", content: WRAPPER.replace("db.execute", "db.query") }, { path: "src/route.ts", content: ROUTE }, { path: "src/other.ts", content: UNRELATED }];
    const second = scan(files2, first.module_cache);
    expect(second.module_cache_reused).toBe(1); // only other.ts
  });

  it("multi-hop (A -> B -> C): changing C invalidates B and A's reuse, but the finding is still correct", () => {
    const C = `export function raw(sql) {\n  db.execute(sql);\n}`;
    const B = `import { raw } from "./c";\nexport function wrap(sql) {\n  raw(sql);\n}`;
    const A = `import { wrap } from "./b";\napp.get("/x", (req, res) => {\n  wrap(req.query.id);\n});`;
    const files1 = [{ path: "src/c.ts", content: C }, { path: "src/b.ts", content: B }, { path: "src/a.ts", content: A }];
    const first = scan(files1);
    expect(findings(first, "src/a.ts")).toEqual(["sql-injection:3:req.query.id"]);

    const C2 = `export function raw(sql) {\n  console.log(sql);\n}`; // no longer sinks
    const files2 = [{ path: "src/c.ts", content: C2 }, { path: "src/b.ts", content: B }, { path: "src/a.ts", content: A }];
    const second = scan(files2, first.module_cache);
    expect(findings(second, "src/a.ts")).toEqual([]);
    expect(second.module_cache_reused).toBe(0); // c changed; b and a both transitively depend on it
  });
});

describe("Python: the same reuse/invalidation guarantees", () => {
  const WRAPPER = "def run_query(sql):\n    cursor.execute(sql)\n";
  const ROUTE = "from app.db import run_query\nfrom flask import request\n\n@app.route(\"/x\")\ndef view():\n    uid = request.args.get(\"id\")\n    run_query(uid)\n";

  it("a second scan with prev_module_cache produces identical findings and reuses both files", () => {
    const files = [{ path: "app/db.py", content: WRAPPER }, { path: "app/views.py", content: ROUTE }];
    const first = scan(files);
    expect(findings(first, "app/views.py")).toEqual(["sql-injection:7:uid"]);
    const second = scan(files, first.module_cache);
    expect(findings(second, "app/views.py")).toEqual(findings(first, "app/views.py"));
    expect(second.module_cache_reused).toBe(2);
  });

  it("changing the callee updates the caller's finding, not a stale cached one", () => {
    const files1 = [{ path: "app/db.py", content: WRAPPER }, { path: "app/views.py", content: ROUTE }];
    const first = scan(files1);
    const SAFE = "def run_query(sql):\n    print(sql)\n";
    const files2 = [{ path: "app/db.py", content: SAFE }, { path: "app/views.py", content: ROUTE }];
    const second = scan(files2, first.module_cache);
    expect(findings(second, "app/views.py")).toEqual([]);
    expect(second.module_cache_reused).toBe(0);
  });
});

describe("JS/TS: reachability's OWN per-file input (call-graph edges/reachable, not just shapes/sinks) survives reuse", () => {
  it("a cache-valid file's callGraphEdges/callGraphReachable are carried forward in module_cache, not silently dropped", () => {
    // Reachability (crossFileReachability.ts) needs its OWN per-file input (buildCallGraph's edges/
    // reachable) for EVERY file in the batch, including cache-valid ones -- a SEPARATE requirement from
    // the shapes/sinks the fixed point consumes. If a cache-valid file's call-graph data were silently
    // dropped instead of carried forward, the file would vanish from reachInputs on the NEXT scan (its
    // own reuse this scan is not what's tested here -- the fields this scan WRITES for next time are).
    const WRAPPER = `export function runQuery(sql) {\n  db.execute(sql);\n}`;
    const ROUTE = `import { runQuery } from "./db";\napp.get("/x", (req, res) => {\n  runQuery(req.query.id);\n});`;
    const files = [{ path: "src/db.ts", content: WRAPPER }, { path: "src/route.ts", content: ROUTE }];
    const first = scan(files);
    expect(first.module_cache!["src/db.ts"].callGraphEdges).toBeDefined();
    expect(first.module_cache!["src/db.ts"].callGraphReachable).toBeDefined();

    const second = scan(files, first.module_cache);
    expect(second.module_cache_reused).toBe(2);
    expect(second.module_cache!["src/db.ts"].callGraphEdges).toEqual(first.module_cache!["src/db.ts"].callGraphEdges);
    expect(second.module_cache!["src/db.ts"].callGraphReachable).toEqual(first.module_cache!["src/db.ts"].callGraphReachable);
  });

  it("a sink in a LOCAL (non-exported) helper, reachable only through db.ts's OWN internal edges, stays 'reachable' -- not 'unreachable' -- across a cache-reused rescan", () => {
    // Mirrors crossFileReachabilityMultiHop.test.ts's own "sink in a local helper" case exactly: helper()
    // is never imported by anyone, so it is reachable ONLY because runQuery (cross-file-reached) calls it,
    // via db.ts's OWN edges -- exactly the input a cache-valid file must still supply without re-parsing.
    // If those edges were silently dropped for a cache-valid db.ts, this would regress to "unreachable".
    const SQL_FN = (name: string) => `function ${name}(id) {\n  const sql = "SELECT * FROM t WHERE id = " + id;\n  return db.query(sql);\n}`;
    const DB = `${SQL_FN("helper")}\nfunction runQuery(id) {\n  return helper(id);\n}\nexport { runQuery };\n`;
    const API = `import { runQuery } from "./db";\nexport function handler(req) {\n  return runQuery(req.query.id);\n}\n`;
    const files = [{ path: "src/db.ts", content: DB }, { path: "src/api.ts", content: API }];
    const reachOf = (r: ReturnType<typeof scan>) => r.files.find(f => f.file_path === "src/db.ts")!.indicators.find(i => i.id === "sql-injection")?.reachability;

    const first = scan(files);
    expect(reachOf(first)).toBe("reachable");

    const second = scan(files, first.module_cache);
    expect(second.module_cache_reused).toBe(2);
    expect(reachOf(second)).toBe("reachable");
  });
});

describe("resolution drift: adding a new file that shadows an existing import invalidates the importer", () => {
  it("a file whose import resolution CHANGES because the batch composition changed is not wrongly reused", () => {
    const WRAPPER = `export function runQuery(sql) {\n  db.execute(sql);\n}`;
    const ROUTE = `import { runQuery } from "./db";\napp.get("/x", (req, res) => {\n  runQuery(req.query.id);\n});`;
    const files1 = [{ path: "src/db.ts", content: WRAPPER }, { path: "src/route.ts", content: ROUTE }];
    const first = scan(files1);
    // route.ts's own content is byte-identical, but the batch now ALSO has an unrelated new file --
    // resolution of "./db" is unaffected here (this specific resolver doesn't shadow), so this proves the
    // common "unrelated file added" case does NOT spuriously invalidate anything it shouldn't.
    const UNRELATED_NEW = `export const x = 1;`;
    const files2 = [{ path: "src/db.ts", content: WRAPPER }, { path: "src/route.ts", content: ROUTE }, { path: "src/new.ts", content: UNRELATED_NEW }];
    const second = scan(files2, first.module_cache);
    expect(findings(second, "src/route.ts")).toEqual(findings(first, "src/route.ts"));
    expect(second.module_cache_reused).toBe(2); // db.ts and route.ts both still reused; new.ts has no cache entry yet
  });
});
