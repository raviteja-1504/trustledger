import { runScan, analyzeFile } from "@/lib/scanner";

// Decision 1: cross-file reachability, JS/TS only, one hop. Before this
// phase, a helper function's OWN local call graph (callGraph.ts's
// buildCallGraph, per-file only) had no way to know it was actually called
// from a reachable function in a DIFFERENT file that imports it -- every
// finding inside such a helper silently scored "unreachable" regardless of
// real reachability, exactly the same visible symptom the Java/Python
// resolver bugs had, for yet another root cause (no cross-file bridge at
// all, not a broken resolver).
//
// db.ts's runQuery is deliberately exported via a SEPARATE `export { ... }`
// statement, not an inline `export function` -- callGraph.ts's regex-based
// tryMatchFunc only sets is_exported from the declaration line itself, so
// this shape is NOT already classified "entry-point" by the pre-existing
// is_exported shortcut. That isolates the test to what THIS phase's new
// cross-file bridge specifically contributes, rather than something the
// existing is_exported check would already have caught on its own.

const DB_FILE = `
function runQuery(id) {
  const sql = "SELECT * FROM t WHERE id = " + id;
  return db.query(sql);
}
export { runQuery };
`;

const API_FILE = `
import { runQuery } from "./db";
export function handler(req) {
  return runQuery(req.query.id);
}
`;

describe("cross-file reachability bridge (Decision 1)", () => {
  it("analyzeFile() alone (no cross-file context) scores db.ts's finding unreachable -- the baseline this phase fixes", () => {
    const result = analyzeFile("db.ts", DB_FILE);
    const finding = result.indicators.find(i => i.id === "sql-injection");
    expect(finding).toBeDefined();
    expect(finding?.reachability).toBe("unreachable");
  });

  it("runScan() with both files resolves db.ts's finding to something other than unreachable, via api.ts's handler calling it", () => {
    const result = runScan({
      repo: "acme/app", pr_number: 1, commit_sha: "abc123",
      files: [
        { path: "src/db.ts", content: DB_FILE },
        { path: "src/api.ts", content: API_FILE },
      ],
    });
    const dbFile = result.files.find(f => f.file_path === "src/db.ts")!;
    const finding = dbFile.indicators?.find(i => i.id === "sql-injection");
    expect(finding).toBeDefined();
    expect(finding?.reachability).not.toBe("unreachable");
  });

  it("does not mark the cross-file-reached function as an entry-point tier (only reachable) -- it isn't itself a network-facing handler", () => {
    const result = runScan({
      repo: "acme/app", pr_number: 1, commit_sha: "abc123",
      files: [
        { path: "src/db.ts", content: DB_FILE },
        { path: "src/api.ts", content: API_FILE },
      ],
    });
    const dbFile = result.files.find(f => f.file_path === "src/db.ts")!;
    const finding = dbFile.indicators?.find(i => i.id === "sql-injection");
    expect(finding?.reachability).toBe("reachable");
  });

  it("does not affect a file with no cross-file callers at all (a genuinely unreachable helper stays unreachable)", () => {
    const deadFile = `
function deadHelper(id) {
  const sql = "SELECT * FROM logs WHERE id = " + id;
  return db.query(sql);
}
export { deadHelper };
`;
    const result = runScan({
      repo: "acme/app", pr_number: 1, commit_sha: "abc123",
      files: [
        { path: "src/dead.ts", content: deadFile },
        { path: "src/api.ts", content: API_FILE }, // does NOT import from dead.ts
      ],
    });
    const deadResult = result.files.find(f => f.file_path === "src/dead.ts")!;
    const finding = deadResult.indicators?.find(i => i.id === "sql-injection");
    expect(finding?.reachability).toBe("unreachable");
  });
});
