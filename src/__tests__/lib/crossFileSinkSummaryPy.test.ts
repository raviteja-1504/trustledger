import { runScan } from "@/lib/scanner";
import type { ScanIndicator } from "@/lib/scanner";
import { warmPythonTaintEngine } from "@/lib/astTaintPython";

// Python mirror of crossFileSinkSummary.test.ts: cross-file PARAMETER -> SINK summaries. A wrapper that sinks
// its parameter and returns nothing (`def run_query(sql): cursor.execute(sql)`) used to be invisible when
// called from another module; the finding now lands at the call site with the callee's real sink location.

beforeAll(async () => { await warmPythonTaintEngine(); }, 120000);

type F = { path: string; content: string };
const scan = (files: F[]) => runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files });
const ast = (r: ReturnType<typeof scan>, path: string, id?: string): ScanIndicator[] =>
  r.files.find(f => f.file_path === path)!.indicators
    .filter(i => i.confidence === 95 && i.sourceExpr !== undefined && (id === undefined || i.id === id));

const SQL_WRAPPER = `def run_query(sql):
    cursor.execute(sql)
`;
// A Django-style view: `request.GET.get(...)` is a taint source; the call is on line 5.
const VIEW = (call: string, imp = "from .db import run_query") => `${imp}

def handler(request):
    value = request.GET.get("v")
    ${call}
`;

describe("core: a wrapper that sinks its parameter and returns nothing", () => {
  it("reports at the CALL SITE in the calling module, like an in-file finding", () => {
    const r = scan([{ path: "pkg/db.py", content: SQL_WRAPPER }, { path: "pkg/views.py", content: VIEW("run_query(value)") }]);
    const found = ast(r, "pkg/views.py", "sql-injection");
    expect(found).toHaveLength(1);
    expect(found[0].line).toBe(5);
    expect(found[0].severity).toBe("critical");
    expect(found[0].sinkExpr).toContain("run_query");
    expect(found[0].sinkExpr).toContain("cursor.execute");
  });

  it("does not report anything in the callee module (no untrusted input of its own)", () => {
    const r = scan([{ path: "pkg/db.py", content: SQL_WRAPPER }, { path: "pkg/views.py", content: VIEW("run_query(value)") }]);
    expect(ast(r, "pkg/db.py")).toHaveLength(0);
  });

  it("the trace ends with a cross-file step and the callee's REAL sink location", () => {
    const r = scan([{ path: "pkg/db.py", content: SQL_WRAPPER }, { path: "pkg/views.py", content: VIEW("run_query(value)") }]);
    const trace = ast(r, "pkg/views.py", "sql-injection")[0].trace!;
    const kinds = trace.map(s => s.kind);
    const crossing = kinds.indexOf("cross-file");
    expect(trace[crossing].file).toBe("pkg/views.py");
    expect(trace[crossing + 1]).toMatchObject({ kind: "parameter", file: "pkg/db.py" });
    expect(kinds[kinds.length - 1]).toBe("sink");
    const sink = trace[trace.length - 1];
    expect(sink.file).toBe("pkg/db.py");
    expect(sink.line).toBe(2);
    expect(sink.label).toBe("cursor.execute");
  });

  it("the detail names the sink's file:line and the module it crossed into", () => {
    const r = scan([{ path: "pkg/db.py", content: SQL_WRAPPER }, { path: "pkg/views.py", content: VIEW("run_query(value)") }]);
    const d = ast(r, "pkg/views.py", "sql-injection")[0].detail!;
    expect(d).toContain("pkg/db.py:2");
    expect(d).toContain("imported from .db");
  });

  it("an untainted argument is not reported", () => {
    const r = scan([{ path: "pkg/db.py", content: SQL_WRAPPER }, { path: "pkg/views.py", content: VIEW(`run_query("SELECT 1")`) }]);
    expect(ast(r, "pkg/views.py")).toHaveLength(0);
  });
});

describe("binding is per PARAMETER", () => {
  const helper = `def run(label, sql):
    print(label)
    cursor.execute(sql)
`;
  const imp = "from .db import run";
  it("taint on the parameter that reaches the sink is reported", () => {
    const r = scan([{ path: "pkg/db.py", content: helper }, { path: "pkg/views.py", content: VIEW(`run("q", value)`, imp) }]);
    expect(ast(r, "pkg/views.py", "sql-injection")).toHaveLength(1);
  });
  it("taint on a parameter that never reaches the sink is NOT reported", () => {
    const r = scan([{ path: "pkg/db.py", content: helper }, { path: "pkg/views.py", content: VIEW(`run(value, "SELECT 1")`, imp) }]);
    expect(ast(r, "pkg/views.py")).toHaveLength(0);
  });
  it("a *args parameter binds every argument from its index", () => {
    const rest = `def run_all(*parts):
    cursor.execute(parts[0])
`;
    const r = scan([{ path: "pkg/db.py", content: rest }, { path: "pkg/views.py", content: VIEW(`run_all("a", value)`, "from .db import run_all") }]);
    expect(ast(r, "pkg/views.py", "sql-injection")).toHaveLength(1);
  });
});

describe("sanitization is honoured per sink class, on both sides of the call", () => {
  it("a callee that coerces its parameter to int before the sink is not a sink for it", () => {
    const safe = `def run_query(sql):
    cursor.execute(int(sql))
`;
    const r = scan([{ path: "pkg/db.py", content: safe }, { path: "pkg/views.py", content: VIEW("run_query(value)") }]);
    expect(ast(r, "pkg/views.py")).toHaveLength(0);
  });
  it("a caller that coerces the argument before crossing is not reported", () => {
    const r = scan([{ path: "pkg/db.py", content: SQL_WRAPPER }, { path: "pkg/views.py", content: VIEW("run_query(int(value))") }]);
    expect(ast(r, "pkg/views.py")).toHaveLength(0);
  });
  it("clearing the WRONG class in the caller does not hide the flow (basename clears path, not SQL)", () => {
    const r = scan([{ path: "pkg/db.py", content: SQL_WRAPPER }, { path: "pkg/views.py", content: VIEW("run_query(os.path.basename(value))") }]);
    expect(ast(r, "pkg/views.py", "sql-injection")).toHaveLength(1);
  });
  it("a middle hop that clears the SINK'S class removes the fact; one that clears another class does not", () => {
    const io = `def read_it(p):
    open(p)
`;
    const midSafe = `from .io import read_it

def safe_read(p):
    read_it(os.path.basename(p))
`;
    const midRaw = `from .io import read_it

def raw_read(p):
    read_it(p)
`;
    const mk = (mid: string, fn: string) => scan([
      { path: "pkg/io.py", content: io }, { path: "pkg/mid.py", content: mid },
      { path: "pkg/views.py", content: VIEW(`${fn}(value)`, `from .mid import ${fn}`) },
    ]);
    expect(ast(mk(midSafe, "safe_read"), "pkg/views.py", "path-traversal")).toHaveLength(0);
    expect(ast(mk(midRaw, "raw_read"), "pkg/views.py", "path-traversal")).toHaveLength(1);   // control
    const sqlVia = `from .db import run_query

def via_base(p):
    run_query(os.path.basename(p))
`;
    const r = scan([
      { path: "pkg/db.py", content: SQL_WRAPPER }, { path: "pkg/mid.py", content: sqlVia },
      { path: "pkg/views.py", content: VIEW("via_base(value)", "from .mid import via_base") },
    ]);
    expect(ast(r, "pkg/views.py", "sql-injection")).toHaveLength(1);
  });
});

describe("multi-hop", () => {
  it("through a same-file helper inside the callee (public function -> private helper -> sink)", () => {
    const callee = `def run(x):
    _helper(x)

def _helper(y):
    cursor.execute(y)
`;
    const r = scan([{ path: "pkg/db.py", content: callee }, { path: "pkg/views.py", content: VIEW("run(value)", "from .db import run") }]);
    const f = ast(r, "pkg/views.py", "sql-injection");
    expect(f).toHaveLength(1);
    expect(f[0].detail).toContain("run -> _helper");
    expect(f[0].trace![f[0].trace!.length - 1].line).toBe(5);     // the ORIGINAL sink line, not the helper's call line
  });

  it("through another MODULE (views -> mid.forward -> db.run_query -> sink)", () => {
    const mid = `from .db import run_query

def forward(x):
    run_query(x)
`;
    const r = scan([
      { path: "pkg/db.py", content: SQL_WRAPPER }, { path: "pkg/mid.py", content: mid },
      { path: "pkg/views.py", content: VIEW("forward(value)", "from .mid import forward") },
    ]);
    const f = ast(r, "pkg/views.py", "sql-injection");
    expect(f).toHaveLength(1);
    expect(f[0].detail).toContain("pkg/db.py:2");
    expect(f[0].detail).toContain("forward -> run_query");
    expect(ast(r, "pkg/mid.py")).toHaveLength(0);
  });

  it("a wrapper that pipes an imported helper's RETURN value into a sink (shapes and sinks together)", () => {
    const build = `def build_query(id):
    return "SELECT * FROM t WHERE id=" + id
`;
    const exec = `from .build import build_query

def run_by_id(id):
    cursor.execute(build_query(id))
`;
    const r = scan([
      { path: "pkg/build.py", content: build }, { path: "pkg/exec.py", content: exec },
      { path: "pkg/views.py", content: VIEW("run_by_id(value)", "from .exec import run_by_id") },
    ]);
    expect(ast(r, "pkg/views.py", "sql-injection")).toHaveLength(1);
  });

  it("terminates on a recursive function and reports the sink once", () => {
    const rec = `def loop(x):
    loop(x)
    cursor.execute(x)
`;
    const r = scan([{ path: "pkg/db.py", content: rec }, { path: "pkg/views.py", content: VIEW("loop(value)", "from .db import loop") }]);
    expect(ast(r, "pkg/views.py", "sql-injection")).toHaveLength(1);
  });
});

describe("import forms", () => {
  it("absolute `from pkg.db import run_query`", () => {
    const r = scan([{ path: "pkg/db.py", content: SQL_WRAPPER }, { path: "app/views.py", content: VIEW("run_query(value)", "from pkg.db import run_query") }]);
    expect(ast(r, "app/views.py", "sql-injection")).toHaveLength(1);
  });
  it("`from . import db` then `db.run_query(value)` (namespace form)", () => {
    const r = scan([{ path: "pkg/db.py", content: SQL_WRAPPER }, { path: "pkg/views.py", content: VIEW("db.run_query(value)", "from . import db") }]);
    expect(ast(r, "pkg/views.py", "sql-injection")).toHaveLength(1);
  });
  it("renamed import (`from .db import run_query as rq`)", () => {
    const r = scan([{ path: "pkg/db.py", content: SQL_WRAPPER }, { path: "pkg/views.py", content: VIEW("rq(value)", "from .db import run_query as rq") }]);
    expect(ast(r, "pkg/views.py", "sql-injection")).toHaveLength(1);
  });
  it("an unresolvable import never throws and reports nothing", () => {
    const view = VIEW("run_query(value)", "from some_external_package import run_query");
    expect(() => scan([{ path: "pkg/views.py", content: view }])).not.toThrow();
    expect(ast(scan([{ path: "pkg/views.py", content: view }]), "pkg/views.py")).toHaveLength(0);
  });
});

describe("precision: a call resolves only when the target is unambiguous", () => {
  const sender = `def make(html):
    return make_response(html)
`;
  it("an imported wrapper called by name is flagged", () => {
    const r = scan([{ path: "pkg/out.py", content: sender }, { path: "pkg/views.py", content: VIEW("make(value)", "from .out import make") }]);
    expect(ast(r, "pkg/views.py", "xss")).toHaveLength(1);
  });
  it("`factory.make(x)` on an unrelated object is NOT mistaken for the imported `make`", () => {
    const r = scan([{ path: "pkg/out.py", content: sender }, { path: "pkg/views.py", content: VIEW("factory.make(value)", "from .out import make") }]);
    expect(ast(r, "pkg/views.py", "xss")).toHaveLength(0);
  });
  it("`self.make(x)` in a class is not resolved to the imported function either", () => {
    const view = `from .out import make

class View:
    def handler(self, request):
        value = request.GET.get("v")
        self.make(value)
`;
    const r = scan([{ path: "pkg/out.py", content: sender }, { path: "pkg/views.py", content: view }]);
    expect(ast(r, "pkg/views.py", "xss")).toHaveLength(0);
  });
});

// ── parity: the summary walk's sink decision must agree with the main scan's, sink shape by shape ─────
describe("parity with the same-file scan for every sink shape", () => {
  const cases: Array<{ name: string; id: string; body: string }> = [
    { name: "sql",        id: "sql-injection",         body: "cursor.execute(p)" },
    { name: "command",    id: "command-injection",     body: "os.system(p)" },
    { name: "path",       id: "path-traversal",        body: "open(p)" },
    { name: "ssrf",       id: "ssrf",                  body: "requests.get(p)" },
    { name: "redirect",   id: "open-redirect",         body: "redirect(p)" },
    { name: "xss",        id: "xss",                   body: "make_response(p)" },
    { name: "ssti",       id: "ssti",                  body: "render_template_string(p)" },
    { name: "header",     id: "header-injection",      body: `resp.headers.add("X-A", p)` },
    { name: "header-set", id: "header-injection",      body: `response.headers["X-A"] = p` },
    { name: "pickle",     id: "insecure-deserialization", body: "pickle.loads(p)" },
    { name: "eval",       id: "eval-exec",             body: "eval(p)" },
  ];
  for (const c of cases) {
    it(`${c.name}: same finding id whether the wrapper is in the same module or another`, () => {
      const def = `def wrap(p):\n    ${c.body}\n`;
      const view = `\ndef handler(request):\n    value = request.GET.get("v")\n    wrap(value)\n`;
      const sameFile = scan([{ path: "pkg/one.py", content: `${def}${view}` }]);
      expect(ast(sameFile, "pkg/one.py", c.id).length).toBeGreaterThan(0);          // the main scan flags this shape...
      const cross = scan([{ path: "pkg/lib.py", content: def }, { path: "pkg/views.py", content: `from .lib import wrap\n${view}` }]);
      expect(ast(cross, "pkg/views.py", c.id)).toHaveLength(1);                     // ...and so must the cross-module summary
    });
  }
});

describe("incremental reuse covers Python sink facts", () => {
  const C = `def run_query(sql):\n    cursor.execute(sql)\n`;
  const C_MOVED = `# a header comment pushes the sink down one line\n${C}`;
  const B = `from .c import run_query\n\ndef forward(x):\n    run_query(x)\n`;
  const set = (c: string): F[] => [
    { path: "pkg/c.py", content: c }, { path: "pkg/b.py", content: B },
    { path: "pkg/views.py", content: VIEW("forward(value)", "from .b import forward") },
  ];
  const detail = (r: ReturnType<typeof scan>) => ast(r, "pkg/views.py", "sql-injection")[0]?.detail;
  const SENTINEL = 0.424242;

  it("a sink that moved two modules away invalidates the caller although its direct callee is unchanged", () => {
    const first = scan(set(C));
    expect(detail(first)).toContain("pkg/c.py:2");
    const cache = JSON.parse(JSON.stringify(first.file_cache!));
    for (const k of Object.keys(cache)) cache[k].analysis.provenance.drift_score = SENTINEL;
    const second = runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files: set(C_MOVED), prev_results: cache });
    expect(second.files.find(f => f.file_path === "pkg/views.py")!.provenance.drift_score).not.toBe(SENTINEL);
    expect(detail(second)).toContain("pkg/c.py:3");
  });
});
