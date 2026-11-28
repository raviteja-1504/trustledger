import { confidenceReason } from "@/lib/confidence";
import { runScan } from "@/lib/scanner";

describe("confidenceReason", () => {
  it("a traced flow names the source kind, the sink and the number of steps", () => {
    const r = confidenceReason({ confidence: 95, sourceExpr: "req.query.q", sinkExpr: "db.query", flow: { hops: 2, source: { inputKind: "URL query parameter" } } })!;
    expect(r).toContain("`req.query.q` (a url query parameter)");
    expect(r).toContain("`db.query`");
    expect(r).toContain("through 2 steps");
  });
  it("an assumed source says nothing was seen reading the request", () => {
    expect(confidenceReason({ confidence: 80, sourceExpr: "id", flow: { source: { assumed: true } } })).toMatch(/treated as untrusted; no request read/);
  });
  it("a pattern-only finding says no value was traced", () => {
    expect(confidenceReason({ confidence: 60 })).toMatch(/matching a code pattern; no value was traced/);
  });
  it("names a sanitizer that runs but does not protect the sink, and what lowers it", () => {
    const r = confidenceReason({ confidence: 95, sourceExpr: "x", flow: { sanitizers: [{ call: "String", protectsSink: false }] }, reachability: "unreachable", codeCategory: "test_code" })!;
    expect(r).toMatch(/`String` runs on the way but does not protect/);
    expect(r).toMatch(/no path to this code from an entry point/);
    expect(r).toMatch(/test code/);
  });
  it("is null when the finding carries no confidence at all", () => {
    expect(confidenceReason({})).toBeNull();
  });
  it("is attached to real scan output without claiming a trace the scan did not make", () => {
    const code = "import express from \"express\";\nconst app = express();\napp.get(\"/x\", (req, res) => {\n  db.query(\"SELECT * FROM t WHERE id=\" + req.query.id);\n  res.send(\"ok\");\n});\n";
    const ind = runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files: [{ path: "src/a.ts", content: code }] }).files[0].indicators.find(i => i.id === "sql-injection")!;
    const r = confidenceReason(ind)!;
    expect(r).toMatch(/was traced to/);
    expect(r).toContain("req.query");
  });
});
