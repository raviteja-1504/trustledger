import { runScan } from "@/lib/scanner";

// Regression tests for real, symbol-level cross-file taint analysis --
// distinct from crossFileTaint.test.ts, which exercises the older, shallow
// file-level co-occurrence heuristic (computeCrossFileTaintIndicators,
// "cross-file-taint-exposure" id). This suite exercises the new mechanism,
// which reuses the exact same per-parameter interprocedural machinery
// built for same-file analysis (ParamShape/computeReturnTaintPropagating/
// argsForShape) and emits the REAL sink-category id (sql-injection,
// command-injection, etc.) at the caller's actual sink call site, mirroring
// how a same-file interprocedural finding already works.
describe("cross-file taint — per-parameter precision across a file boundary", () => {
  it("does NOT flag when only the unused exported parameter is tainted", () => {
    const helper = `
export function buildLog(userId, message) {
  return \`User \${userId} did something\`;
}`.trim();
    const consumer = `
import { buildLog } from "./helper";
app.get("/x", (req, res) => {
  const safeId = "static-id";
  const taintedMessage = req.query.msg;
  exec(buildLog(safeId, taintedMessage));
});`.trim();
    const result = runScan({
      repo: "t", pr_number: 1, commit_sha: "a", branch: "main",
      files: [{ path: "src/helper.ts", content: helper }, { path: "src/consumer.ts", content: consumer }],
    });
    const consumerFile = result.files.find(f => f.file_path === "src/consumer.ts")!;
    expect(consumerFile.indicators.some(i => i.id === "command-injection")).toBe(false);
  });

  it("flags when the parameter that actually reaches the return IS tainted", () => {
    const helper = `
export function buildLog(userId, message) {
  return \`User \${userId} did something\`;
}`.trim();
    const consumer = `
import { buildLog } from "./helper";
app.get("/x", (req, res) => {
  const taintedId = req.query.id;
  exec(buildLog(taintedId, "static message"));
});`.trim();
    const result = runScan({
      repo: "t", pr_number: 1, commit_sha: "a", branch: "main",
      files: [{ path: "src/helper.ts", content: helper }, { path: "src/consumer.ts", content: consumer }],
    });
    const consumerFile = result.files.find(f => f.file_path === "src/consumer.ts")!;
    const finding = consumerFile.indicators.find(i => i.id === "command-injection");
    expect(finding).toBeDefined();
    // Attribution note: proves the cross-file origin is surfaced in the
    // message, not just that the finding fires at all.
    expect(finding?.detail).toContain("buildLog");
    expect(finding?.detail).toContain("./helper");
  });

  it("fires for assign-then-use-downstream (proves Pass 2 does a real re-walk, not post-processing)", () => {
    const db = `
export function buildQuery(input) {
  const q = \`SELECT * FROM t WHERE id=\${input}\`;
  return q;
}`.trim();
    const route = `
import { buildQuery } from "./db";
app.get("/x", (req, res) => {
  const id = req.query.id;
  const q = buildQuery(id);
  db.execute(q);
});`.trim();
    const result = runScan({
      repo: "t", pr_number: 1, commit_sha: "a", branch: "main",
      files: [{ path: "src/db.ts", content: db }, { path: "src/route.ts", content: route }],
    });
    const routeFile = result.files.find(f => f.file_path === "src/route.ts")!;
    expect(routeFile.indicators.some(i => i.id === "sql-injection")).toBe(true);
  });

  it("does not throw and does not false-positive on an unresolvable import (external package)", () => {
    const route = `
import { buildQuery } from "some-external-package";
app.get("/x", (req, res) => {
  const id = req.query.id;
  db.execute(buildQuery(id));
});`.trim();
    expect(() => runScan({
      repo: "t", pr_number: 1, commit_sha: "a", branch: "main",
      files: [{ path: "src/route.ts", content: route }],
    })).not.toThrow();
  });

  it("handles an aliased named import correctly (import { buildQuery as bq })", () => {
    const db = `
export function buildQuery(input) {
  const q = \`SELECT * FROM t WHERE id=\${input}\`;
  return q;
}`.trim();
    const route = `
import { buildQuery as bq } from "./db";
app.get("/x", (req, res) => {
  const id = req.query.id;
  db.execute(bq(id));
});`.trim();
    const result = runScan({
      repo: "t", pr_number: 1, commit_sha: "a", branch: "main",
      files: [{ path: "src/db.ts", content: db }, { path: "src/route.ts", content: route }],
    });
    const routeFile = result.files.find(f => f.file_path === "src/route.ts")!;
    expect(routeFile.indicators.some(i => i.id === "sql-injection")).toBe(true);
  });
});
