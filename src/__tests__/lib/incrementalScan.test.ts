import { runScan } from "@/lib/scanner";
import type { ScanInput } from "@/lib/scanner";
import { computeFileCacheKey } from "@/lib/incrementalCache";
import type { CachedFileResult } from "@/lib/incrementalCache";

// Incremental scan reuse. The old `prev_hashes` DROPPED unchanged files from the scan; the new
// `prev_results`/`file_cache` REUSES their analysis, keeps them in every aggregate and in the cross-file
// graph, and only trusts a cached result when everything analyzeFile() reads is unchanged -- not just the
// file's own bytes (see incrementalCache.ts). These tests pin each of those properties.

const DB_TAINTED = `export function buildQuery(input) {
  return \`SELECT * FROM t WHERE id=\${input}\`;
}`;
// Same export, but the parameter is coerced to an integer first -- taint no longer survives to the return.
const DB_SANITIZED = `export function buildQuery(input) {
  return "SELECT * FROM t WHERE id=" + parseInt(input, 10);
}`;
const ROUTE = `import { buildQuery } from "./db";
app.get("/x", (req, res) => {
  const id = req.query.id;
  db.execute(buildQuery(id));
});`;
const UTIL = `export function clamp(value: number, lo: number, hi: number): number {
  return Math.min(hi, Math.max(lo, value));
}`;

type F = { path: string; content: string };
const baseFiles = (db = DB_TAINTED, util = UTIL): F[] => [
  { path: "src/db.ts", content: db },
  { path: "src/route.ts", content: ROUTE },
  { path: "src/util.ts", content: util },
];

function scan(files: F[], extra: Partial<ScanInput> = {}) {
  return runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files, ...extra });
}
// A cached entry with a sentinel planted in a field no post-pass touches: if the sentinel shows up in the
// next scan's output, that file was REUSED from the cache rather than re-derived by analyzeFile().
const SENTINEL = 0.424242;
function withSentinels(cache: Record<string, CachedFileResult>): Record<string, CachedFileResult> {
  const out: Record<string, CachedFileResult> = JSON.parse(JSON.stringify(cache));
  for (const k of Object.keys(out)) out[k].analysis.provenance.drift_score = SENTINEL;
  return out;
}
const reused = (r: ReturnType<typeof scan>, path: string) =>
  r.files.find(f => f.file_path === path)!.provenance.drift_score === SENTINEL;
const astSql = (r: ReturnType<typeof scan>, path: string) =>
  r.files.find(f => f.file_path === path)!.indicators.filter(i => i.id === "sql-injection" && i.confidence === 95);

describe("file_cache output", () => {
  it("every scanned file gets a cache entry keyed and stamped with its own path", () => {
    const r = scan(baseFiles());
    expect(Object.keys(r.file_cache!).sort()).toEqual(["src/db.ts", "src/route.ts", "src/util.ts"]);
    for (const [path, e] of Object.entries(r.file_cache!)) {
      expect(e.analysis.file_path).toBe(path);
      expect(e.cache_key).toMatch(/^[0-9a-f]{64}$/);
    }
  });
});

describe("reuse when nothing changed", () => {
  it("skips analysis for every file yet returns a result identical to a fresh scan", () => {
    const first = scan(baseFiles());
    const second = scan(baseFiles(), { prev_results: first.file_cache });
    expect(second.skipped_unchanged).toBe(3);
    expect(second.files).toEqual(first.files);
    expect(second.overall_risk).toBe(first.overall_risk);
    expect(second.scan_summary).toEqual(first.scan_summary);
  });

  it("really serves the cached analysis instead of silently re-deriving it (sentinel)", () => {
    const first = scan(baseFiles());
    const second = scan(baseFiles(), { prev_results: withSentinels(first.file_cache!) });
    for (const p of ["src/db.ts", "src/route.ts", "src/util.ts"]) expect(reused(second, p)).toBe(true);
  });

  it("does not let a reused result alias the cache entry (mutating output must not corrupt the cache)", () => {
    const first = scan(baseFiles());
    const cache = first.file_cache!;
    const second = scan(baseFiles(), { prev_results: cache });
    second.files[0].indicators.push({ id: "poison", label: "x", severity: "low" });
    expect(cache[second.files[0].file_path].analysis.indicators.some(i => i.id === "poison")).toBe(false);
  });
});

describe("partial change", () => {
  it("re-analyzes only the edited file, and unchanged files stay in the whole-PR result", () => {
    const first = scan(baseFiles());
    const edited = baseFiles(DB_TAINTED, UTIL + "\nexport const EXTRA = 1; // touched");
    const second = scan(edited, { prev_results: withSentinels(first.file_cache!) });
    expect(second.skipped_unchanged).toBe(2);
    expect(second.files).toHaveLength(3);                       // NOT just the changed subset
    expect(reused(second, "src/util.ts")).toBe(false);          // edited -> re-analyzed
    expect(reused(second, "src/db.ts")).toBe(true);
    expect(reused(second, "src/route.ts")).toBe(true);
  });

  it("aggregates are computed over the full set, not only the re-analyzed files", () => {
    const first = scan(baseFiles());
    const second = scan(baseFiles(DB_TAINTED, UTIL + "\n// edit"), { prev_results: first.file_cache });
    // The vulnerable route.ts was reused, so the PR-level counts must still see its finding.
    expect(second.scan_summary.total_security_findings).toBe(first.scan_summary.total_security_findings);
    expect(second.overall_risk).toBe(first.overall_risk);
  });
});

describe("dependency-aware invalidation (hash equality alone is NOT sufficient)", () => {
  it("baseline: the cross-file flow through buildQuery is reported at the route", () => {
    expect(astSql(scan(baseFiles()), "src/route.ts").length).toBeGreaterThan(0);
  });

  it("an UNCHANGED caller is re-analyzed when its callee changes, and the stale finding disappears", () => {
    const first = scan(baseFiles(DB_TAINTED));
    expect(astSql(first, "src/route.ts").length).toBeGreaterThan(0);

    // route.ts is byte-for-byte identical; only db.ts changed (now sanitizes).
    const second = scan(baseFiles(DB_SANITIZED), { prev_results: withSentinels(first.file_cache!) });
    expect(reused(second, "src/route.ts")).toBe(false);         // caller NOT served from cache
    expect(reused(second, "src/util.ts")).toBe(true);           // unrelated file still reused
    expect(astSql(second, "src/route.ts")).toHaveLength(0);     // a hash-only skip would keep reporting it

    // ...and the outcome equals a from-scratch scan of the same inputs.
    const fresh = scan(baseFiles(DB_SANITIZED));
    expect(second.files.find(f => f.file_path === "src/route.ts")!.indicators)
      .toEqual(fresh.files.find(f => f.file_path === "src/route.ts")!.indicators);
  });

  it("the reverse direction: a callee that BECOMES tainted makes an unchanged caller start reporting", () => {
    const first = scan(baseFiles(DB_SANITIZED));
    expect(astSql(first, "src/route.ts")).toHaveLength(0);
    const second = scan(baseFiles(DB_TAINTED), { prev_results: first.file_cache });
    expect(astSql(second, "src/route.ts").length).toBeGreaterThan(0);
  });
});

describe("cross-file sink facts are part of the cache key", () => {
  // route -> b.forward -> c.runQuery -> sink. route's DIRECT callee (b) is byte-identical across the two
  // scans; only c changes -- the sink moves from line 2 to line 3. The finding's detail names that line, so a
  // cached route.ts would be stale. Only the sink facts in the key can catch this (route's other key inputs --
  // its own content, b's content, b's return shapes -- are all unchanged).
  const C = `export function runQuery(sql) {\n  db.execute(sql);\n}`;
  const C_MOVED = `// a header comment pushes the sink down one line\n${C}`;
  const B = `import { runQuery } from "./c";\nexport function forward(x) {\n  runQuery(x);\n}`;
  const R = `import { forward } from "./b";\napp.get("/x", (req, res) => {\n  const id = req.query.id;\n  forward(id);\n});`;
  const set = (c: string): F[] => [{ path: "src/c.ts", content: c }, { path: "src/b.ts", content: B }, { path: "src/route.ts", content: R }];
  const detail = (r: ReturnType<typeof scan>) =>
    r.files.find(f => f.file_path === "src/route.ts")!.indicators.find(i => i.id === "sql-injection" && i.confidence === 95)?.detail;

  it("a sink that moved two hops away invalidates the caller even though its direct callee is unchanged", () => {
    const first = scan(set(C));
    expect(detail(first)).toContain("src/c.ts:2");
    const second = scan(set(C_MOVED), { prev_results: withSentinels(first.file_cache!) });
    expect(reused(second, "src/route.ts")).toBe(false);
    expect(detail(second)).toContain("src/c.ts:3");             // not the stale ":2" a cached result would carry
    expect(detail(second)).toBe(detail(scan(set(C_MOVED))));    // identical to a from-scratch scan
  });

  it("with nothing changed the caller IS reused (the sink facts don't make the key unstable)", () => {
    const first = scan(set(C));
    const second = scan(set(C), { prev_results: withSentinels(first.file_cache!) });
    for (const p of ["src/c.ts", "src/b.ts", "src/route.ts"]) expect(reused(second, p)).toBe(true);
  });
});

describe("cache_namespace", () => {
  it("a different namespace never reuses the previous release's results", () => {
    const first = scan(baseFiles(), { cache_namespace: "release-1" });
    expect(scan(baseFiles(), { prev_results: first.file_cache, cache_namespace: "release-2" }).skipped_unchanged).toBe(0);
    expect(scan(baseFiles(), { prev_results: first.file_cache, cache_namespace: "release-1" }).skipped_unchanged).toBe(3);
  });
});

describe("PR-level post-passes re-run over the full set without duplicating indicators", () => {
  const helper = `
export function lookupUser(db, req) {
  const id = req.params.id;
  const result = db.query(\`SELECT * FROM users WHERE id=\${id}\`);
  return result;
}
`.trim();
  const consumer = `
import { lookupUser } from "./helper";

export async function handler(db, req) {
  const user = lookupUser(db, req);
  return user;
}
`.trim();
  const files: F[] = [{ path: "src/helper.ts", content: helper }, { path: "src/consumer.ts", content: consumer }];
  const count = (r: ReturnType<typeof scan>) =>
    r.files.find(f => f.file_path === "src/consumer.ts")!.indicators.filter(i => i.id === "cross-file-taint-exposure").length;

  it("the cached snapshot is taken BEFORE post-pass indicators are injected", () => {
    const first = scan(files);
    expect(count(first)).toBeGreaterThan(0);                                    // post-pass ran on the live result
    expect(first.file_cache!["src/consumer.ts"].analysis.indicators.some(i => i.id === "cross-file-taint-exposure")).toBe(false);
  });

  it("a reused file gets the post-pass indicator exactly once, not once per scan", () => {
    const first = scan(files);
    const second = scan(files, { prev_results: first.file_cache });
    const third  = scan(files, { prev_results: second.file_cache });
    expect(second.skipped_unchanged).toBe(2);
    expect(count(second)).toBe(count(first));
    expect(count(third)).toBe(count(first));
  });
});

describe("computeFileCacheKey", () => {
  const base = { namespace: "", path: "a.ts", contentHash: "h", prPriorBias: 0, contentHashOf: (_: string) => "c" };
  const shapes = [{ index: 0, isRest: false, mask: 3, name: "x" }, { index: 1, isRest: false, name: "y" }];

  it("is independent of Map/Set insertion order", () => {
    const a = new Map([["f", { shapes, fromModule: "./m", resolvedPath: "m.ts" }], ["g", { shapes, fromModule: "./n", resolvedPath: "n.ts" }]]);
    const b = new Map([["g", { shapes, fromModule: "./n", resolvedPath: "n.ts" }], ["f", { shapes, fromModule: "./m", resolvedPath: "m.ts" }]]);
    expect(computeFileCacheKey({ ...base, jsCrossFile: a, crossFileReachable: new Set(["p", "q"]) }))
      .toBe(computeFileCacheKey({ ...base, jsCrossFile: b, crossFileReachable: new Set(["q", "p"]) }));
  });

  it("changes when the callee's content changes, even though shapes are identical", () => {
    const m = new Map([["f", { shapes, fromModule: "./m", resolvedPath: "m.ts" }]]);
    const k1 = computeFileCacheKey({ ...base, jsCrossFile: m, contentHashOf: () => "callee-v1" });
    const k2 = computeFileCacheKey({ ...base, jsCrossFile: m, contentHashOf: () => "callee-v2" });
    expect(k1).not.toBe(k2);
  });

  it("changes with a shape's surviving-class mask, reachable set, path, bias and content", () => {
    const k = (o: object) => computeFileCacheKey({ ...base, ...o });
    const m1 = new Map([["f", { shapes: [{ index: 0, mask: 1 }], fromModule: "./m" }]]);
    const m2 = new Map([["f", { shapes: [{ index: 0, mask: 2 }], fromModule: "./m" }]]);
    expect(k({ jsCrossFile: m1 })).not.toBe(k({ jsCrossFile: m2 }));
    expect(k({})).not.toBe(k({ crossFileReachable: new Set(["h"]) }));
    expect(k({})).not.toBe(k({ path: "b.ts" }));
    expect(k({})).not.toBe(k({ contentHash: "h2" }));
    expect(k({})).not.toBe(k({ prPriorBias: 0.05 }));
  });

  it("ignores float noise in the PR prior bias", () => {
    expect(computeFileCacheKey({ ...base, prPriorBias: 0.08 })).toBe(computeFileCacheKey({ ...base, prPriorBias: 0.08 + 1e-12 }));
  });
});
