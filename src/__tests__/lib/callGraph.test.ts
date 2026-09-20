import { extractFunctions, detectEntryPoints, buildCallGraph } from "@/lib/callGraph";

describe("callGraph.extractFunctions — brace mode (JS/TS/Go/Java, unchanged behavior)", () => {
  it("extracts a JS function declaration with a real body", () => {
    const content = "function foo(a, b) {\n  return a + b;\n}\n";
    const funcs = extractFunctions(content);
    expect(funcs.some(f => f.name === "foo" && f.start_line === 1 && f.end_line === 3)).toBe(true);
  });

  it("excludes a true single-line function (existing, unchanged limitation)", () => {
    const content = "function foo() {}\nfunction bar() { return 1; }\n";
    const funcs = extractFunctions(content);
    expect(funcs).toHaveLength(0);
  });

  it("extracts a Go function", () => {
    const content = "func handler(w http.ResponseWriter, r *http.Request) {\n\tfmt.Println(\"hi\")\n}\n";
    const funcs = extractFunctions(content);
    expect(funcs.some(f => f.name === "handler")).toBe(true);
  });

  it("extracts a Java method with a public modifier and generic return type (Decision 2)", () => {
    const content = [
      "public class A {",
      "  public ResponseEntity<User> getUser(String id) {",
      "    return ResponseEntity.ok(repo.findById(id));",
      "  }",
      "}",
    ].join("\n");
    const funcs = extractFunctions(content);
    const fn = funcs.find(f => f.name === "getUser");
    expect(fn).toBeDefined();
    expect(fn!.is_exported).toBe(true);
  });

  it("extracts a private Java method with a void return type", () => {
    const content = [
      "public class A {",
      "  private void logAndRun(String cmd) {",
      "    Runtime.getRuntime().exec(cmd);",
      "  }",
      "}",
    ].join("\n");
    const funcs = extractFunctions(content);
    const fn = funcs.find(f => f.name === "logAndRun");
    expect(fn).toBeDefined();
    expect(fn!.is_exported).toBe(false);
  });

  it("does not match a Java if/for/while control-flow statement as its own method", () => {
    const content = "public class A {\n  public void m() {\n    if (x) {\n      y();\n    }\n  }\n}\n";
    const funcs = extractFunctions(content);
    expect(funcs.some(f => f.name === "m")).toBe(true);
    expect(funcs.some(f => f.name === "if")).toBe(false);
  });
});

describe("callGraph.extractFunctions — Python indent mode (Decision 1, bug fix)", () => {
  it("extracts a simple Python function (previously always dropped)", () => {
    const content = "def foo(a, b):\n    return a + b\n";
    const funcs = extractFunctions(content);
    expect(funcs.some(f => f.name === "foo" && f.start_line === 1 && f.end_line === 2)).toBe(true);
  });

  it("extracts two sibling top-level functions with correct, non-overlapping ranges", () => {
    const content = [
      "def foo(a, b):",
      "    x = 1",
      "    if x:",
      "        y = 2",
      "    return x",
      "",
      "def bar():",
      "    pass",
    ].join("\n");
    const funcs = extractFunctions(content);
    const foo = funcs.find(f => f.name === "foo");
    const bar = funcs.find(f => f.name === "bar");
    expect(foo).toBeDefined();
    expect(bar).toBeDefined();
    expect(foo!.start_line).toBe(1);
    expect(bar!.start_line).toBe(7);
    expect(bar!.end_line).toBe(8);
    // Non-overlapping: bar starts strictly after foo ends.
    expect(bar!.start_line).toBeGreaterThan(foo!.end_line);
  });

  it("extracts a function that is the last thing in the file (EOF flush)", () => {
    const content = "def only():\n    return 1\n";
    const funcs = extractFunctions(content);
    expect(funcs.some(f => f.name === "only" && f.end_line === 2)).toBe(true);
  });

  it("extracts a nested method inside a class at a deeper base indent", () => {
    const content = [
      "class Widget:",
      "    def render(self):",
      "        return \"<div></div>\"",
      "",
      "    def other(self):",
      "        pass",
    ].join("\n");
    const funcs = extractFunctions(content);
    expect(funcs.some(f => f.name === "render")).toBe(true);
    expect(funcs.some(f => f.name === "other")).toBe(true);
  });

  it("handles an async def", () => {
    const content = "async def fetch(url):\n    return await get(url)\n";
    const funcs = extractFunctions(content);
    expect(funcs.some(f => f.name === "fetch")).toBe(true);
  });

  it("does not merge a dedented sibling function's body into the previous one", () => {
    const content = [
      "def a():",
      "    return 1",
      "def b():",
      "    return 2",
    ].join("\n");
    const funcs = extractFunctions(content);
    const a = funcs.find(f => f.name === "a")!;
    expect(a.body).not.toContain("def b");
  });
});

describe("callGraph.buildCallGraph — Python reachability now works end to end (Decision 1)", () => {
  it("a Flask-style handler function is extracted and its own function name is reachable via BFS from itself as an entry point once exported/entry-detected", () => {
    // Not yet decorator-aware (Decision 3) -- this only proves extraction
    // itself now works, i.e. graph.functions is non-empty for Python,
    // closing the root cause of "always unreachable".
    const content = "def handler(request):\n    return do_work(request)\n\ndef do_work(request):\n    return request.body\n";
    const graph = buildCallGraph(content);
    expect(graph.functions.length).toBeGreaterThanOrEqual(2);
    expect(graph.functions.some(f => f.name === "handler")).toBe(true);
    expect(graph.functions.some(f => f.name === "do_work")).toBe(true);
  });
});

describe("callGraph.detectEntryPoints — existing JS/Express patterns (unchanged)", () => {
  it("flags an exported function as an entry point", () => {
    const content = "export function handler(req, res) {\n  res.send('ok');\n}\n";
    const funcs = extractFunctions(content);
    const entries = detectEntryPoints(funcs, content);
    expect(entries).toContain("handler");
  });
});

describe("callGraph.detectEntryPoints — multi-language entry points (Decision 3, new capability)", () => {
  it("flags a Java method annotated with @GetMapping, decorator on the line above the signature", () => {
    const content = [
      "public class A {",
      "  @GetMapping(\"/users/{id}\")",
      "  private Object getUser(String id) {",
      "    return Database.find(id);",
      "  }",
      "}",
    ].join("\n");
    const funcs = extractFunctions(content);
    const entries = detectEntryPoints(funcs, content);
    expect(entries).toContain("getUser");
  });

  it("does not flag a private Java method with no mapping annotation", () => {
    const content = [
      "public class A {",
      "  private Object helper(String id) {",
      "    return Database.find(id);",
      "  }",
      "}",
    ].join("\n");
    const funcs = extractFunctions(content);
    const entries = detectEntryPoints(funcs, content);
    expect(entries).not.toContain("helper");
  });

  it("flags a Flask route decorated with @app.route", () => {
    const content = [
      "@app.route(\"/users/<id>\")",
      "def get_user(id):",
      "    return db.find(id)",
    ].join("\n");
    const funcs = extractFunctions(content);
    const entries = detectEntryPoints(funcs, content);
    expect(entries).toContain("get_user");
  });

  it("flags a FastAPI route decorated with @router.get", () => {
    const content = [
      "@router.get(\"/users/{id}\")",
      "def get_user(id: str):",
      "    return db.find(id)",
    ].join("\n");
    const funcs = extractFunctions(content);
    const entries = detectEntryPoints(funcs, content);
    expect(entries).toContain("get_user");
  });

  it("does not flag an undecorated Python function", () => {
    const content = "def helper(id):\n    return db.find(id)\n";
    const funcs = extractFunctions(content);
    const entries = detectEntryPoints(funcs, content);
    expect(entries).not.toContain("helper");
  });

  it("flags a Go function registered as a Gin route handler by name", () => {
    const content = [
      "func getUser(c *gin.Context) {",
      "\tid := c.Param(\"id\")",
      "\tc.JSON(200, db.Find(id))",
      "}",
      "",
      "func setup(router *gin.Engine) {",
      "\trouter.GET(\"/users/:id\", getUser)",
      "}",
    ].join("\n");
    const funcs = extractFunctions(content);
    const entries = detectEntryPoints(funcs, content);
    expect(entries).toContain("getUser");
  });

  it("does not flag a Go function that is never registered as a route handler", () => {
    const content = "func helper(id string) string {\n\treturn db.Find(id)\n}\n";
    const funcs = extractFunctions(content);
    const entries = detectEntryPoints(funcs, content);
    expect(entries).not.toContain("helper");
  });
});
