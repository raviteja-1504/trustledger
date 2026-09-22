import { runScan } from "@/lib/scanner";

// Source -> sink trace generation and stable finding fingerprints (see taintCore.ts's TraceStep
// docblock, astTaint.ts's buildTrace, and scanner.ts's computeFingerprint).

function scanOne(path: string, content: string) {
  return runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files: [{ path, content }] });
}

const ROUTE = `app.get("/x", (req, res) => {
  const id = req.query.id;
  db.execute(id);
});`;

describe("source -> sink trace", () => {
  it("a same-file finding gets a source-first trace ending at the sink, with real line numbers", () => {
    const result = scanOne("src/route.ts", ROUTE);
    const finding = result.files[0].indicators.find(i => i.id === "sql-injection")!;
    expect(finding).toBeDefined();
    expect(finding.sourceExpr).toBe("id");
    expect(finding.sinkExpr).toBe("db.execute");
    expect(finding.trace).toBeDefined();
    const trace = finding.trace!;
    expect(trace[0].kind).toBe("source");
    expect(trace[0].label).toContain("req.query.id");
    expect(trace[0].line).toBe(2);
    expect(trace[trace.length - 1].kind).toBe("sink");
    expect(trace[trace.length - 1].line).toBe(3);
    expect(trace.every(s => s.file === "src/route.ts")).toBe(true);
  });

  it("a cross-file finding's trace crosses into the callee file with a real file + line there", () => {
    const db = `export function buildQuery(input) {
  const q = \`SELECT * FROM t WHERE id=\${input}\`;
  return q;
}`;
    const route = `import { buildQuery } from "./db";
app.get("/x", (req, res) => {
  const id = req.query.id;
  const q = buildQuery(id);
  db.execute(q);
});`;
    const result = runScan({
      repo: "t", pr_number: 1, commit_sha: "a", branch: "main",
      files: [{ path: "src/db.ts", content: db }, { path: "src/route.ts", content: route }],
    });
    const routeFile = result.files.find(f => f.file_path === "src/route.ts")!;
    const finding = routeFile.indicators.find(i => i.id === "sql-injection")!;
    expect(finding.trace).toBeDefined();
    const trace = finding.trace!;
    // At least one step actually lands inside db.ts (not just a text note about it).
    const calleeStep = trace.find(s => s.file === "src/db.ts");
    expect(calleeStep).toBeDefined();
    expect(calleeStep!.line).toBe(3);
    const crossStep = trace.find(s => s.kind === "cross-file");
    expect(crossStep).toBeDefined();
    expect(crossStep!.label).toContain("./db");
    expect(trace[trace.length - 1].kind).toBe("sink");
  });

  it("does not throw when there is no import to resolve (no cross-file map at all)", () => {
    expect(() => scanOne("src/solo.ts", ROUTE)).not.toThrow();
  });
});

describe("stable fingerprints", () => {
  it("is stable across unrelated lines added above the finding", () => {
    const a = scanOne("src/route.ts", ROUTE);
    const shifted = `// a comment\n// another comment\nfunction unrelated() { return 1; }\n\n${ROUTE}`;
    const b = scanOne("src/route.ts", shifted);
    const fpA = a.files[0].indicators.find(i => i.id === "sql-injection")!.fingerprint;
    const fpB = b.files[0].indicators.find(i => i.id === "sql-injection")!.fingerprint;
    expect(fpA).toBeDefined();
    expect(fpA).toBe(fpB);
  });

  it("changes when the sink expression itself changes", () => {
    const a = scanOne("src/route.ts", ROUTE);
    const changed = ROUTE.replace("db.execute(id)", "db.query(id)");
    const b = scanOne("src/route.ts", changed);
    const fpA = a.files[0].indicators.find(i => i.id === "sql-injection")!.fingerprint;
    const fpB = b.files[0].indicators.find(i => i.id === "sql-injection")!.fingerprint;
    expect(fpA).not.toBe(fpB);
  });

  it("differs between two distinct findings in the same file", () => {
    const twoFindings = `app.get("/x", (req, res) => {
  const id = req.query.id;
  db.execute(id);
  document.write(req.query.html);
});`;
    const result = scanOne("src/route.ts", twoFindings);
    const fps = result.files[0].indicators.filter(i => i.id === "sql-injection" || i.id === "xss").map(i => i.fingerprint);
    expect(fps.length).toBeGreaterThanOrEqual(2);
    expect(new Set(fps).size).toBe(fps.length);
  });

  it("every security indicator on a scanned file has a fingerprint", () => {
    const result = scanOne("src/route.ts", ROUTE);
    for (const i of result.files[0].indicators) {
      if (i.id.startsWith("ai-") || i.id === "style-drift") continue; // aggregate signals, not per-flow findings
      expect(i.fingerprint).toBeDefined();
      expect(i.fingerprint!.length).toBeGreaterThan(0);
    }
  });
});

describe("AST findings win the same-line dedup over a regex duplicate", () => {
  it("a sql-injection finding at a line both layers catch keeps the AST engine's richer data (confidence 95, sourceExpr present)", () => {
    const result = scanOne("src/route.ts", ROUTE);
    const finding = result.files[0].indicators.find(i => i.id === "sql-injection")!;
    expect(finding.confidence).toBe(95);
    expect(finding.sourceExpr).toBeDefined();
  });
});
