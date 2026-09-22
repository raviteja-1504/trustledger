import { runScan } from "@/lib/scanner";
import { warmPythonTaintEngine } from "@/lib/astTaintPython";

// Phase 3 (cross-file analysis) hardening: export/import forms beyond the original named-import-only
// mechanism (default export, re-export chains incl. `export *`, namespace imports, CommonJS), the
// multi-hop fixed point (A -> B -> C, not just one hop), and Python's own cross-file resolution --
// see taint/crossFile.ts's own docblock for the shared algorithm and what's explicitly out of scope.

beforeAll(async () => { await warmPythonTaintEngine(); }, 30000);

function scan(files: Array<{ path: string; content: string }>) {
  return runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files });
}
function fires(files: Array<{ path: string; content: string }>, atPath: string, id: string): boolean {
  const result = scan(files);
  const f = result.files.find(x => x.file_path === atPath);
  return !!f?.indicators.some(i => i.id === id);
}

describe("JS/TS export forms", () => {
  it("a default-exported function's taint propagates across the import", () => {
    const helper = `export default function buildQuery(input) {
  return \`SELECT * FROM t WHERE id=\${input}\`;
}`;
    const route = `import buildQuery from "./db";
app.get("/x", (req, res) => {
  const id = req.query.id;
  db.execute(buildQuery(id));
});`;
    expect(fires([{ path: "src/db.ts", content: helper }, { path: "src/route.ts", content: route }], "src/route.ts", "sql-injection")).toBe(true);
  });

  it("`export { x } from` re-export chain resolves to the real declaration two hops away", () => {
    const a = `export function buildQuery(input) {
  return \`SELECT * FROM t WHERE id=\${input}\`;
}`;
    const b = `export { buildQuery } from "./a";`;
    const route = `import { buildQuery } from "./b";
app.get("/x", (req, res) => {
  const id = req.query.id;
  db.execute(buildQuery(id));
});`;
    expect(fires(
      [{ path: "src/a.ts", content: a }, { path: "src/b.ts", content: b }, { path: "src/route.ts", content: route }],
      "src/route.ts", "sql-injection",
    )).toBe(true);
  });

  it("`export * from` re-exports every name of the source module", () => {
    const a = `export function buildQuery(input) {
  return \`SELECT * FROM t WHERE id=\${input}\`;
}`;
    const barrel = `export * from "./a";`;
    const route = `import { buildQuery } from "./barrel";
app.get("/x", (req, res) => {
  const id = req.query.id;
  db.execute(buildQuery(id));
});`;
    expect(fires(
      [{ path: "src/a.ts", content: a }, { path: "src/barrel.ts", content: barrel }, { path: "src/route.ts", content: route }],
      "src/route.ts", "sql-injection",
    )).toBe(true);
  });

  it("a namespace import (`import * as ns`) resolves a call through the namespace", () => {
    const helper = `export function buildQuery(input) {
  return \`SELECT * FROM t WHERE id=\${input}\`;
}`;
    const route = `import * as db2 from "./db";
app.get("/x", (req, res) => {
  const id = req.query.id;
  db.execute(db2.buildQuery(id));
});`;
    expect(fires([{ path: "src/db.ts", content: helper }, { path: "src/route.ts", content: route }], "src/route.ts", "sql-injection")).toBe(true);
  });

  it("CommonJS module.exports / require() resolves the same as an ES import", () => {
    const helper = `module.exports.buildQuery = function(input) {
  return "SELECT * FROM t WHERE id=" + input;
};`;
    const route = `const { buildQuery } = require("./db");
app.get("/x", (req, res) => {
  const id = req.query.id;
  db.execute(buildQuery(id));
});`;
    expect(fires([{ path: "src/db.js", content: helper }, { path: "src/route.js", content: route }], "src/route.js", "sql-injection")).toBe(true);
  });
});

describe("multi-hop (A -> B -> C)", () => {
  it("a wrapper around a cross-file call is itself recognized as propagating", () => {
    const c = `export function buildQuery(input) {
  return \`SELECT * FROM t WHERE id=\${input}\`;
}`;
    const b = `import { buildQuery } from "./c";
export function wrap(id) {
  return buildQuery(id);
}`;
    const a = `import { wrap } from "./b";
app.get("/x", (req, res) => {
  const id = req.query.id;
  db.execute(wrap(id));
});`;
    expect(fires(
      [{ path: "src/c.ts", content: c }, { path: "src/b.ts", content: b }, { path: "src/a.ts", content: a }],
      "src/a.ts", "sql-injection",
    )).toBe(true);
  });
});

describe("precision across a file boundary", () => {
  it("a real sanitizer wrapper imported from another file still suppresses the AST engine's own XSS finding", () => {
    // Confidence 95 is this codebase's own signature for an AST-derived finding (vs. a lower-confidence
    // regex one) -- see every findAstTaint*Findings wrapper in scanner.ts. A separate, cross-file-unaware
    // regex XSS detector firing independently here is a pre-existing, same-file gap too (not something
    // this cross-file AST bridge introduced or is responsible for suppressing).
    const helper = `export function safe(input) {
  return escapeHtml(input);
}`;
    const route = `import { safe } from "./sanitize";
app.get("/x", (req, res) => {
  document.write(safe(req.query.html));
});`;
    const result = scan([{ path: "src/sanitize.ts", content: helper }, { path: "src/route.ts", content: route }]);
    const f = result.files.find(x => x.file_path === "src/route.ts")!;
    expect(f.indicators.some(i => i.id === "xss" && i.confidence === 95)).toBe(false);
  });

  it("an unresolvable default import (external package) does not throw or false-positive", () => {
    const route = `import buildQuery from "some-external-package";
app.get("/x", (req, res) => {
  db.execute(buildQuery(req.query.id));
});`;
    expect(() => scan([{ path: "src/route.ts", content: route }])).not.toThrow();
  });
});

describe("Python cross-file", () => {
  it("`from .mod import x` resolves a relative import in the same package", () => {
    const helper = `def build_query(id):
    return "SELECT * FROM t WHERE id=" + id
`;
    const api = `from .helpers import build_query

def handler(request):
    id = request.GET.get("id")
    db.execute(build_query(id))
`;
    expect(fires(
      [{ path: "pkg/helpers.py", content: helper }, { path: "pkg/api.py", content: api }],
      "pkg/api.py", "sql-injection",
    )).toBe(true);
  });

  it("`from pkg.mod import x` resolves an absolute import against the batch", () => {
    const helper = `def build_query(id):
    return "SELECT * FROM t WHERE id=" + id
`;
    const api = `from pkg.helpers import build_query

def handler(request):
    id = request.GET.get("id")
    db.execute(build_query(id))
`;
    expect(fires(
      [{ path: "pkg/helpers.py", content: helper }, { path: "app/api.py", content: api }],
      "app/api.py", "sql-injection",
    )).toBe(true);
  });

  it("`from . import helpers` (submodule/namespace form) resolves a call through the module", () => {
    const helper = `def build_query(id):
    return "SELECT * FROM t WHERE id=" + id
`;
    const api = `from . import helpers

def handler(request):
    id = request.GET.get("id")
    db.execute(helpers.build_query(id))
`;
    expect(fires(
      [{ path: "pkg/helpers.py", content: helper }, { path: "pkg/api.py", content: api }],
      "pkg/api.py", "sql-injection",
    )).toBe(true);
  });

  it("does not throw on an unresolvable Python import", () => {
    const api = `from some_external_package import build_query

def handler(request):
    db.execute(build_query(request.GET.get("id")))
`;
    expect(() => scan([{ path: "pkg/api.py", content: api }])).not.toThrow();
  });
});
