import { computeCacheValidity, computeModuleCacheContentHash } from "@/lib/moduleSummaryCache";
import type { CachedModuleSummary } from "@/lib/moduleSummaryCache";

// computeCacheValidity is a pure graph-invalidation fixed point over CACHED metadata alone (never file
// content beyond the hash comparison) -- these pin its soundness in isolation, before scanner.ts wires it
// into a real batch. A file is "valid" (safe to reuse its cached summary/sinks/call-graph with zero
// re-parsing) only if it AND everything it transitively imports/re-exports from is unchanged.

const cached = (over: Partial<CachedModuleSummary> = {}): CachedModuleSummary => ({
  contentHash: "h", imports: [], reexports: [], summary: [], sinks: [], ...over,
});
const imp = (spec: string, resolvedPath: string | null) =>
  ({ localName: "x", importedName: "x", moduleSpecifier: spec, resolvedPath });

describe("computeCacheValidity: no dependencies", () => {
  it("all unchanged files with no imports are valid", () => {
    const files = [{ path: "a.ts", contentHash: "h" }, { path: "b.ts", contentHash: "h" }];
    const prev = { "a.ts": cached(), "b.ts": cached() };
    expect(computeCacheValidity(files, prev, () => null)).toEqual(new Set(["a.ts", "b.ts"]));
  });
  it("a changed file's own hash mismatch makes it invalid", () => {
    const files = [{ path: "a.ts", contentHash: "NEW" }];
    const prev = { "a.ts": cached({ contentHash: "OLD" }) };
    expect(computeCacheValidity(files, prev, () => null)).toEqual(new Set());
  });
  it("a brand new file (not in the previous cache at all) is never valid", () => {
    const files = [{ path: "a.ts", contentHash: "h" }];
    expect(computeCacheValidity(files, {}, () => null)).toEqual(new Set());
  });
});

describe("computeCacheValidity: transitive invalidation through imports", () => {
  it("a file that imports a CHANGED file is also invalidated, even though its own content is unchanged", () => {
    const files = [{ path: "a.ts", contentHash: "h" }, { path: "b.ts", contentHash: "NEW" }];
    const prev = {
      "a.ts": cached({ imports: [imp("./b", "b.ts")] }),
      "b.ts": cached({ contentHash: "OLD" }),
    };
    const resolve = (_from: string, spec: string) => (spec === "./b" ? "b.ts" : null);
    expect(computeCacheValidity(files, prev, resolve)).toEqual(new Set());
  });
  it("a file with NO dependency on the changed file stays valid", () => {
    const files = [{ path: "a.ts", contentHash: "h" }, { path: "b.ts", contentHash: "NEW" }, { path: "c.ts", contentHash: "h" }];
    const prev = { "a.ts": cached(), "b.ts": cached({ contentHash: "OLD" }), "c.ts": cached() };
    expect(computeCacheValidity(files, prev, () => null)).toEqual(new Set(["a.ts", "c.ts"]));
  });
  it("multi-hop: A -> B -> C, C changes, both A and B are invalidated", () => {
    const files = [{ path: "a.ts", contentHash: "h" }, { path: "b.ts", contentHash: "h" }, { path: "c.ts", contentHash: "NEW" }];
    const prev = {
      "a.ts": cached({ imports: [imp("./b", "b.ts")] }),
      "b.ts": cached({ imports: [imp("./c", "c.ts")] }),
      "c.ts": cached({ contentHash: "OLD" }),
    };
    const resolve = (from: string, spec: string) => {
      if (from === "a.ts" && spec === "./b") return "b.ts";
      if (from === "b.ts" && spec === "./c") return "c.ts";
      return null;
    };
    expect(computeCacheValidity(files, prev, resolve)).toEqual(new Set());
  });
  it("re-export edges invalidate transitively the same way import edges do", () => {
    const files = [{ path: "a.ts", contentHash: "h" }, { path: "b.ts", contentHash: "NEW" }];
    const prev = {
      "a.ts": cached({ reexports: [{ publicName: "x", importedName: "x", moduleSpecifier: "./b", resolvedPath: "b.ts" }] }),
      "b.ts": cached({ contentHash: "OLD" }),
    };
    const resolve = (_from: string, spec: string) => (spec === "./b" ? "b.ts" : null);
    expect(computeCacheValidity(files, prev, resolve)).toEqual(new Set());
  });
});

describe("computeCacheValidity: resolution drift (batch composition changed, content didn't)", () => {
  it("invalidates a file whose import now resolves to a DIFFERENT path than cached (e.g. a new file added elsewhere took precedence)", () => {
    const files = [{ path: "a.ts", contentHash: "h" }, { path: "b.ts", contentHash: "h" }, { path: "b2.ts", contentHash: "h" }];
    const prev = {
      "a.ts": cached({ imports: [imp("./b", "b.ts")] }),
      "b.ts": cached(), "b2.ts": cached(),
    };
    // last scan "./b" resolved to b.ts; this scan (batch changed) it resolves to b2.ts instead
    const resolve = (_from: string, spec: string) => (spec === "./b" ? "b2.ts" : null);
    expect(computeCacheValidity(files, prev, resolve)).toEqual(new Set(["b.ts", "b2.ts"]));
  });
  it("invalidates a file whose import target was removed from the batch (now resolves to null)", () => {
    const files = [{ path: "a.ts", contentHash: "h" }];
    const prev = { "a.ts": cached({ imports: [imp("./gone", "gone.ts")] }) };
    expect(computeCacheValidity(files, prev, () => null)).toEqual(new Set());
  });
});

describe("computeCacheValidity: cycles don't spuriously invalidate", () => {
  it("A and B import each other, both unchanged -> both stay valid", () => {
    const files = [{ path: "a.ts", contentHash: "h" }, { path: "b.ts", contentHash: "h" }];
    const prev = {
      "a.ts": cached({ imports: [imp("./b", "b.ts")] }),
      "b.ts": cached({ imports: [imp("./a", "a.ts")] }),
    };
    const resolve = (from: string, spec: string) => {
      if (from === "a.ts" && spec === "./b") return "b.ts";
      if (from === "b.ts" && spec === "./a") return "a.ts";
      return null;
    };
    expect(computeCacheValidity(files, prev, resolve)).toEqual(new Set(["a.ts", "b.ts"]));
  });
  it("a self-referential cycle where ONE member changes still invalidates the rest of the cycle", () => {
    const files = [{ path: "a.ts", contentHash: "h" }, { path: "b.ts", contentHash: "NEW" }];
    const prev = {
      "a.ts": cached({ imports: [imp("./b", "b.ts")] }),
      "b.ts": cached({ contentHash: "OLD", imports: [imp("./a", "a.ts")] }),
    };
    const resolve = (from: string, spec: string) => {
      if (from === "a.ts" && spec === "./b") return "b.ts";
      if (from === "b.ts" && spec === "./a") return "a.ts";
      return null;
    };
    expect(computeCacheValidity(files, prev, resolve)).toEqual(new Set());
  });
});

describe("computeCacheValidity: external/unresolvable specifiers never invalidate on their own", () => {
  it("an import of an external package (always resolves to null) does not prevent validity", () => {
    const files = [{ path: "a.ts", contentHash: "h" }];
    const prev = { "a.ts": cached({ imports: [imp("lodash", null)] }) };
    expect(computeCacheValidity(files, prev, () => null)).toEqual(new Set(["a.ts"]));
  });
});

describe("computeModuleCacheContentHash: version/namespace fold (a stale cache must never look valid)", () => {
  it("the same raw hash under the same version+namespace is identical", () => {
    expect(computeModuleCacheContentHash("ns1", "rawhash")).toBe(computeModuleCacheContentHash("ns1", "rawhash"));
  });
  it("a different namespace (a deploy boundary) changes the composite hash", () => {
    expect(computeModuleCacheContentHash("ns1", "rawhash")).not.toBe(computeModuleCacheContentHash("ns2", "rawhash"));
  });
  it("a different raw content hash changes the composite hash", () => {
    expect(computeModuleCacheContentHash("ns1", "rawhash1")).not.toBe(computeModuleCacheContentHash("ns1", "rawhash2"));
  });
});

describe("computeCacheValidity + computeModuleCacheContentHash together: a namespace change invalidates everything, even though the file's raw content is unchanged", () => {
  it("a cache entry keyed to a DIFFERENT namespace's composite hash is never valid, despite an unchanged file", () => {
    const rawHash = "same-raw-content-hash";
    const files = [{ path: "a.ts", contentHash: computeModuleCacheContentHash("deploy-2", rawHash) }];
    const prev = { "a.ts": cached({ contentHash: computeModuleCacheContentHash("deploy-1", rawHash) }) };
    expect(computeCacheValidity(files, prev, () => null)).toEqual(new Set());
  });
  it("the SAME namespace with the SAME raw content is valid", () => {
    const rawHash = "same-raw-content-hash";
    const files = [{ path: "a.ts", contentHash: computeModuleCacheContentHash("deploy-1", rawHash) }];
    const prev = { "a.ts": cached({ contentHash: computeModuleCacheContentHash("deploy-1", rawHash) }) };
    expect(computeCacheValidity(files, prev, () => null)).toEqual(new Set(["a.ts"]));
  });
});
