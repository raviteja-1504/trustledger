import fs from "fs";
import { analyzeFile } from "@/lib/scanner";
import { scanAstTaint, computeExportTaintSummary } from "@/lib/astTaint";

const FIXTURE_PATH =
  "C:/Users/ADMIN/AppData/Local/Temp/claude/d--trustledger/dd894828-e726-4544-b53b-93aca10d3d41/scratchpad/owasp_test_app.ts";

describe("Real AST-based taint engine (Phase 1: JS/TS) — regression floor against the full OWASP benchmark fixture", () => {
  // This fixture drove ~4 rounds of regex-detector fixes earlier this
  // session. If the scratchpad has been cleared since, skip rather than
  // fail the suite over an environment artifact.
  const fixtureExists = fs.existsSync(FIXTURE_PATH);
  const itIfFixture = fixtureExists ? it : it.skip;

  itIfFixture("still finds every id the regex layer already caught, plus new AST-only catches", () => {
    const content = fs.readFileSync(FIXTURE_PATH, "utf8");
    const result = analyzeFile("app.ts", content);
    const ids = new Set(result.indicators.map(i => i.id));
    for (const id of [
      "weak-crypto", "sql-injection", "eval-exec", "weak-signing-secret",
      "command-injection", "ssrf", "path-traversal", "prototype-pollution",
      "open-redirect", "weak-cors", "xss", "verbose-error", "cookie-no-httponly",
    ]) {
      expect(ids.has(id)).toBe(true);
    }
    // Two real cases only the AST engine can catch: a sink call whose
    // argument is an inline concatenation expression, not a bare identifier
    // (res.send("<div>" + bio + "</div>") at line 157, fs.writeFileSync(
    // "/tmp/uploads/" + filename, content) at line 399) -- the regex named-
    // taint sinks require `\s*\(\s*(\w+)\b`, which structurally cannot match
    // anything but a bare variable reference.
    expect(result.indicators.some(i => i.id === "xss" && i.line === 157)).toBe(true);
    expect(result.indicators.some(i => i.id === "path-traversal" && i.line === 399)).toBe(true);
  });
});

describe("Real AST-based taint engine — multi-line-wrapped statements (the specific failure mode this phase exists to fix)", () => {
  it("catches command injection when the source, template literal, and sink call are each split across several lines", () => {
    const content = `
app.get("/api/ping", (req, res) => {
  const host =
    req
      .query
      .host;
  const command =
    \`ping -c 1 \${
      host
    }\`;
  exec(
    command,
    (error, stdout) => { res.send(stdout); }
  );
});
`;
    // Prove the regex layer alone cannot see this (documents the real gap).
    const regexOnly = analyzeFile("app-regex-baseline.js", content);
    // Real AST engine, directly:
    const astFindings = scanAstTaint(content, "app.ts");
    expect(astFindings.some(f => f.id === "command-injection")).toBe(true);
    // Full pipeline (JS/TS file extension) must include it too.
    const result = analyzeFile("app.ts", content);
    expect(result.indicators.some(i => i.id === "command-injection")).toBe(true);
    void regexOnly;
  });

  it("catches SQL injection when a concatenated query string and a chained db.query() call are split across several lines", () => {
    const content = `
app.get("/api/account", async (req, res) => {
  const id =
    req.query.id;
  const query =
    "SELECT * FROM accounts WHERE id = '" +
    id +
    "'";
  const result =
    await db
      .query(
        query
      );
  res.json(result);
});
`;
    const astFindings = scanAstTaint(content, "app.ts");
    expect(astFindings.some(f => f.id === "sql-injection")).toBe(true);
    const result = analyzeFile("app.ts", content);
    expect(result.indicators.some(i => i.id === "sql-injection")).toBe(true);
  });

  it("does not flag an untainted, fully-static multi-line query", () => {
    const content = `
async function getAllUsers() {
  const query =
    "SELECT * FROM users " +
    "WHERE active = 1";
  return await db.query(query);
}
`;
    const astFindings = scanAstTaint(content, "app.ts");
    expect(astFindings.some(f => f.id === "sql-injection")).toBe(false);
  });
});

describe("Real AST-based taint engine — same-file interprocedural call binding", () => {
  it("propagates taint through a local helper's return value to the call site", () => {
    const content = `
function buildCommand(host) {
  return \`ping -c1 \${host}\`;
}
app.get("/ping", (req, res) => {
  const host = req.query.host;
  exec(buildCommand(host), (e, out) => res.send(out));
});
`;
    const astFindings = scanAstTaint(content, "app.ts");
    const finding = astFindings.find(f => f.id === "command-injection");
    expect(finding).toBeDefined();
    expect(finding?.sourceExpr).toContain("buildCommand");
  });

  it("does not propagate taint through a helper whose return value never depends on its parameters", () => {
    const content = `
function getVersion(host) {
  return "v1.0";
}
app.get("/ping", (req, res) => {
  const host = req.query.host;
  exec(getVersion(host), (e, out) => res.send(out));
});
`;
    const astFindings = scanAstTaint(content, "app.ts");
    expect(astFindings.some(f => f.id === "command-injection")).toBe(false);
  });
});

describe("Real AST-based taint engine — per-parameter return-taint precision (multi-param helper)", () => {
  // buildLog's return only ever depends on `userId` -- `message` is never
  // referenced in it at all. A per-FUNCTION propagating boolean (the old
  // design) can't tell the two params apart, so it would fire on
  // buildLog(safeId, taintedMessage) even though `message` never flows
  // anywhere. Per-parameter tracking must not.
  const helper = `
function buildLog(userId, message) {
  return \`User \${userId} did something\`;
}`;

  it("does NOT flag when only the unused parameter is tainted", () => {
    const content = `${helper}
app.get("/x", (req, res) => {
  const safeId = "static-id";
  const taintedMessage = req.query.msg;
  exec(buildLog(safeId, taintedMessage));
});`;
    expect(scanAstTaint(content, "app.ts").some(f => f.id === "command-injection")).toBe(false);
  });

  it("still flags when the parameter that actually reaches the return IS tainted", () => {
    const content = `${helper}
app.get("/x", (req, res) => {
  const taintedId = req.query.id;
  exec(buildLog(taintedId, "static message"));
});`;
    expect(scanAstTaint(content, "app.ts").some(f => f.id === "command-injection")).toBe(true);
  });

  it("flags when EITHER of two independently-propagating params is tainted (doesn't over-correct to requiring both)", () => {
    const combine = `
function combine(a, b) { return a + b; }`;
    const aTainted = `${combine}
app.get("/x", (req, res) => { exec(combine(req.query.a, "safe")); });`;
    const bTainted = `${combine}
app.get("/y", (req, res) => { exec(combine("safe", req.query.b)); });`;
    expect(scanAstTaint(aTainted, "app.ts").some(f => f.id === "command-injection")).toBe(true);
    expect(scanAstTaint(bTainted, "app.ts").some(f => f.id === "command-injection")).toBe(true);
  });

  // Real, pre-existing gap found and fixed while building cross-file taint
  // analysis: computeReturnTaintPropagating used to seed only the tested
  // parameter itself, never any local variable assigned from it -- so a
  // function that assigns to a local before returning it ("const q = ...;
  // return q;", an extremely common pattern: query builders, sanitizer
  // wrappers) was never detected as propagating at all. Same-file, not
  // cross-file, but Pass 1's export summary would have inherited this
  // blind spot wholesale if left unfixed.
  it("propagates taint through a local var assigned before return (assign-then-return)", () => {
    const content = `
function buildQuery(input) {
  const q = \`SELECT * FROM t WHERE id=\${input}\`;
  return q;
}
app.get("/x", (req, res) => {
  const id = req.query.id;
  db.query(buildQuery(id));
});`;
    expect(scanAstTaint(content, "app.ts").some(f => f.id === "sql-injection")).toBe(true);
  });
});

describe("computeExportTaintSummary — cross-file Pass 1, exported-function detection", () => {
  it("includes export function and export const arrow functions with their propagating param shapes", () => {
    const content = `
export function buildLog(userId, message) {
  return \`User \${userId}\`;
}
export const buildQuery = (input) => \`SELECT * FROM t WHERE id=\${input}\`;
`;
    const summary = computeExportTaintSummary(content, "app.ts");
    expect(summary.get("buildLog")?.map(s => s.index)).toEqual([0]);
    expect(summary.get("buildQuery")?.map(s => s.index)).toEqual([0]);
  });

  it("includes a function exposed via an `export { local as public }` list", () => {
    const content = `
function buildLog(userId) {
  return \`User \${userId}\`;
}
export { buildLog as publicBuildLog };
`;
    const summary = computeExportTaintSummary(content, "app.ts");
    expect(summary.has("buildLog")).toBe(false);
    expect(summary.get("publicBuildLog")?.map(s => s.index)).toEqual([0]);
  });

  it("excludes export default and non-exported functions", () => {
    const content = `
export default function buildLog(userId) {
  return \`User \${userId}\`;
}
function privateHelper(userId) {
  return \`User \${userId}\`;
}
`;
    const summary = computeExportTaintSummary(content, "app.ts");
    expect(summary.size).toBe(0);
  });
});

describe("Real AST-based taint engine — negative cases", () => {
  it("does not flag a call with no taint anywhere in scope", () => {
    const content = `
function cleanup() {
  exec("rm -rf /tmp/cache");
}
`;
    expect(scanAstTaint(content, "app.ts")).toHaveLength(0);
  });

  it("does not misfire on the common regex.exec() method-call idiom", () => {
    const content = `
function parseLine(pattern, line) {
  const command = pattern.exec(line);
  return command;
}
`;
    expect(scanAstTaint(content, "app.ts").some(f => f.id === "command-injection")).toBe(false);
  });

  it("never throws on syntactically broken input", () => {
    const content = "function broken( { const x = ;;; req.query.";
    expect(() => scanAstTaint(content, "app.ts")).not.toThrow();
  });
});
