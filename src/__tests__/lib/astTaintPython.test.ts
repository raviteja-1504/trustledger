import fs from "fs";
import { analyzeFile } from "@/lib/scanner";
import { scanAstTaintPython, warmPythonTaintEngine } from "@/lib/astTaintPython";

const SCRATCHPAD = "C:/Users/ADMIN/AppData/Local/Temp/claude/d--trustledger/dd894828-e726-4544-b53b-93aca10d3d41/scratchpad";
const FLASK_FIXTURE   = `${SCRATCHPAD}/owasp_test_app.py`;
const FASTAPI_FIXTURE = `${SCRATCHPAD}/owasp_test_app_fastapi.py`;
const DJANGO_FIXTURE  = `${SCRATCHPAD}/owasp_test_app_django.py`;
const VAMPI_FIXTURE   = `${SCRATCHPAD}/vampi/api_views/users.py`;

// Jest doesn't run src/instrumentation.ts (that's a Next.js server-startup
// hook, production only), so the WASM parser's async warm-up has to be
// awaited explicitly here before any test relies on it being ready.
beforeAll(async () => {
  await warmPythonTaintEngine();
}, 30000);

function itIfExists(path: string) {
  return fs.existsSync(path) ? it : it.skip;
}

describe("Real AST-based taint engine (Phase 2: Python) — regression floor against the real Flask OWASP benchmark fixture", () => {
  itIfExists(FLASK_FIXTURE)("still finds every id the regex layer already caught, plus a real AST-only sink match", () => {
    const content = fs.readFileSync(FLASK_FIXTURE, "utf8");
    const result = analyzeFile("owasp_test_app.py", content);
    const ids = new Set(result.indicators.map(i => i.id));
    for (const id of [
      "command-injection", "ssti", "path-traversal", "ssrf", "sql-injection", "insecure-deserialization",
    ]) {
      expect(ids.has(id)).toBe(true);
    }
    // AST-engine-specific: command injection built from `"ping -c 1 " + host`
    // (request.args-sourced) flowing into subprocess.check_output(..., shell=True)
    // -- a real structural taint match, not just a regex line hit.
    const astFindings = scanAstTaintPython(content, "owasp_test_app.py");
    expect(astFindings.some(f => f.id === "command-injection" && f.line === 149)).toBe(true);
    expect(astFindings.some(f => f.id === "sql-injection" && f.line === 141)).toBe(true);
    expect(astFindings.some(f => f.id === "ssti" && f.line === 157)).toBe(true);
    expect(astFindings.some(f => f.id === "ssrf" && f.line === 180)).toBe(true);
  });

  itIfExists(VAMPI_FIXTURE)("never throws scanning a real, larger VAmPI source file", () => {
    const content = fs.readFileSync(VAMPI_FIXTURE, "utf8");
    expect(() => scanAstTaintPython(content, "users.py")).not.toThrow();
    expect(() => analyzeFile("users.py", content)).not.toThrow();
  });
});

describe("Real AST-based taint engine — .format()/%-formatting and f-string taint (the specific gap this phase exists to close)", () => {
  it("catches SQL injection through .format() string formatting", () => {
    const content = `
def handler():
    user_id = request.args.get("id")
    cursor.execute("SELECT * FROM users WHERE id = {}".format(user_id))
`;
    const findings = scanAstTaintPython(content, "app.py");
    expect(findings.some(f => f.id === "sql-injection")).toBe(true);
  });

  it("catches command injection through %-style string formatting", () => {
    const content = `
def handler():
    host = request.args.get("host")
    os.system("ping -c 1 %s" % host)
`;
    const findings = scanAstTaintPython(content, "app.py");
    expect(findings.some(f => f.id === "command-injection")).toBe(true);
  });

  it("catches SQL injection through an f-string interpolation", () => {
    const content = `
def handler():
    user_id = request.args.get("id")
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
`;
    const findings = scanAstTaintPython(content, "app.py");
    expect(findings.some(f => f.id === "sql-injection")).toBe(true);
  });

  it("does not flag a fully-static .format() call with no tainted argument", () => {
    const content = `
def handler():
    cursor.execute("SELECT * FROM users WHERE active = {}".format(1))
`;
    expect(scanAstTaintPython(content, "app.py")).toHaveLength(0);
  });
});

describe("Real AST-based taint engine — same-file interprocedural call binding", () => {
  it("propagates taint through a local helper's return value to the call site", () => {
    const content = `
def build_query(uid):
    return f"SELECT * FROM users WHERE id = {uid}"

def handler():
    uid = request.args.get("id")
    cursor.execute(build_query(uid))
`;
    const findings = scanAstTaintPython(content, "app.py");
    expect(findings.some(f => f.id === "sql-injection")).toBe(true);
  });

  it("does not propagate taint through a helper whose return value never depends on its parameters", () => {
    const content = `
def get_table_name(uid):
    return "users"

def handler():
    uid = request.args.get("id")
    cursor.execute(get_table_name(uid))
`;
    expect(scanAstTaintPython(content, "app.py")).toHaveLength(0);
  });
});

describe("Real AST-based taint engine — per-parameter return-taint precision (multi-param helper)", () => {
  // build_log's return only ever depends on user_id -- message is never
  // referenced in it at all. A per-FUNCTION propagating boolean (the old
  // design) can't tell the two params apart, so it would fire on
  // build_log(safe_id, tainted_message) even though message never flows
  // anywhere. Per-parameter tracking must not.
  const helper = `
def build_log(user_id, message):
    return f"User {user_id} did something"
`;

  it("does NOT flag when only the unused parameter is tainted", () => {
    const content = `${helper}
def handler():
    safe_id = "static-id"
    tainted_message = request.args.get("msg")
    os.system(build_log(safe_id, tainted_message))
`;
    expect(scanAstTaintPython(content, "app.py").some(f => f.id === "command-injection")).toBe(false);
  });

  it("still flags when the parameter that actually reaches the return IS tainted", () => {
    const content = `${helper}
def handler():
    tainted_id = request.args.get("id")
    os.system(build_log(tainted_id, "static message"))
`;
    expect(scanAstTaintPython(content, "app.py").some(f => f.id === "command-injection")).toBe(true);
  });

  it("flags when EITHER of two independently-propagating params is tainted", () => {
    const combine = `
def combine(a, b):
    return a + b
`;
    const aTainted = `${combine}
def handler():
    os.system(combine(request.args.get("a"), "safe"))
`;
    const bTainted = `${combine}
def handler():
    os.system(combine("safe", request.args.get("b")))
`;
    expect(scanAstTaintPython(aTainted, "app.py").some(f => f.id === "command-injection")).toBe(true);
    expect(scanAstTaintPython(bTainted, "app.py").some(f => f.id === "command-injection")).toBe(true);
  });
});

describe("Real AST-based taint engine — FastAPI parameter-injection source style", () => {
  itIfExists(FASTAPI_FIXTURE)("finds the real AST-only catches in the hand-written FastAPI fixture", () => {
    const content = fs.readFileSync(FASTAPI_FIXTURE, "utf8");
    const findings = scanAstTaintPython(content, "owasp_test_app_fastapi.py");
    expect(findings.some(f => f.id === "sql-injection")).toBe(true);   // f-string, .format(), and interprocedural cases
    expect(findings.some(f => f.id === "command-injection")).toBe(true); // %-formatting and shell=True cases
    expect(findings.some(f => f.id === "ssrf")).toBe(true);
    // Negative: Depends()-injected db session must not cause /health or
    // /version (fully static queries) to false-positive.
    expect(findings.some(f => f.detail.includes("SELECT 1") || f.detail.includes("app_meta"))).toBe(false);
  });

  it("treats every parameter of a route-decorated handler as tainted at entry, with no request.* prefix", () => {
    const content = `
@app.get("/users/{user_id}")
def get_user(user_id: int):
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
`;
    const findings = scanAstTaintPython(content, "app.py");
    expect(findings.some(f => f.id === "sql-injection")).toBe(true);
  });

  it("does not taint a plain (non-decorated) function's parameters", () => {
    const content = `
def get_user(user_id: int):
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
`;
    expect(scanAstTaintPython(content, "app.py")).toHaveLength(0);
  });
});

describe("Real AST-based taint engine — Django request.GET/.POST dict-access source style", () => {
  itIfExists(DJANGO_FIXTURE)("finds the real AST-only catches in the hand-written Django fixture, including the class-based view", () => {
    const content = fs.readFileSync(DJANGO_FIXTURE, "utf8");
    const findings = scanAstTaintPython(content, "owasp_test_app_django.py");
    expect(findings.some(f => f.id === "sql-injection")).toBe(true);
    expect(findings.some(f => f.id === "command-injection")).toBe(true);
    expect(findings.some(f => f.id === "open-redirect")).toBe(true);
    // Negative: an aliased `requests` HTTP client (imported as `request`)
    // must not be treated as Django's request object.
    expect(findings.some(f => f.sourceExpr.includes("example.com"))).toBe(false);
  });

  it("scopes request.GET/.POST to a function whose own parameter is literally named `request`", () => {
    const positive = `
def view(request):
    user_id = request.GET['id']
    cursor.execute("SELECT * FROM users WHERE id = {}".format(user_id))
`;
    expect(scanAstTaintPython(positive, "views.py").some(f => f.id === "sql-injection")).toBe(true);

    // Same request.GET[...] shape, but the enclosing function has no
    // `request` parameter -- must not be scoped in as a Django view.
    const negative = `
def view():
    user_id = request.GET['id']
    cursor.execute("SELECT * FROM users WHERE id = {}".format(user_id))
`;
    expect(scanAstTaintPython(negative, "views.py")).toHaveLength(0);
  });
});

describe("Real AST-based taint engine — negative cases and malformed-input guards", () => {
  it("does not flag a call with no taint anywhere in scope", () => {
    const content = `
def cleanup():
    os.system("rm -rf /tmp/cache")
`;
    expect(scanAstTaintPython(content, "app.py")).toHaveLength(0);
  });

  it("does not flag subprocess.run() with a list argument (the safe shell=False idiom)", () => {
    const content = `
def handler():
    cmd = request.args.get("cmd")
    subprocess.run(["ping", "-c", "1", cmd])
`;
    expect(scanAstTaintPython(content, "app.py").some(f => f.id === "command-injection")).toBe(false);
  });

  it("returns [] rather than throwing on an empty file", () => {
    expect(() => scanAstTaintPython("", "app.py")).not.toThrow();
    expect(scanAstTaintPython("", "app.py")).toEqual([]);
  });

  it("never throws on syntactically broken input", () => {
    const content = "def broken(:\n    x = ;;; request.args.";
    expect(() => scanAstTaintPython(content, "app.py")).not.toThrow();
  });
});
