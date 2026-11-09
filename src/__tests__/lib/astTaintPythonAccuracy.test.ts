import { runScan } from "@/lib/scanner";
import type { ScanIndicator } from "@/lib/scanner";
import { warmPythonTaintEngine } from "@/lib/astTaintPython";

/**
 * Python AST taint engine: canonical function identity, Python argument binding, path sinks vs transformations,
 * context-sensitive validation, FastAPI parameter sources, exact cross-file resolution, response typing.
 * End to end through runScan so the cross-file bridge is covered too.
 */

beforeAll(async () => { await warmPythonTaintEngine(); }, 120000);

type F = { path: string; content: string };
const scan = (files: F[]) => runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files });
const found = (files: F[], path: string, id: string): ScanIndicator[] =>
  scan(files).files.find(f => f.file_path === path)!.indicators.filter(i => i.confidence === 95 && i.sourceExpr !== undefined && i.id === id);
const one = (code: string, id: string, path = "app.py") => found([{ path, content: code }], path, id);
const FLASK = `import os\nimport subprocess\nfrom flask import Flask, request, abort, jsonify\napp = Flask(__name__)\n`;
const route = (body: string) => `${FLASK}\n${body}`;

describe("canonical function identity", () => {
  const classes = `
class Safe:
    def run(self, cmd):
        return len(cmd)

class Danger:
    def run(self, cmd):
        os.system(cmd)
`;
  it("same method name on two classes: only the class that sinks is reported", () => {
    expect(one(route(`${classes}
@app.route("/a")
def a():
    s = Safe()
    s.run(request.args.get("c"))
    return "ok"
`), "command-injection")).toHaveLength(0);
    expect(one(route(`${classes}
@app.route("/a")
def a():
    d = Danger()
    d.run(request.args.get("c"))
    return "ok"
`), "command-injection")).toHaveLength(1);
  });
  it("self.method resolves to the method of the enclosing class", () => {
    expect(one(route(`${classes}
class View:
    def run(self, cmd):
        return cmd

    def handle(self):
        self.run(request.args.get("c"))
        return "ok"
`), "command-injection")).toHaveLength(0);
  });
  it("a module function and a method of the same name are different symbols", () => {
    expect(one(route(`
def run(cmd):
    return len(cmd)

class Runner:
    def run(self, cmd):
        os.system(cmd)

@app.route("/a")
def a():
    run(request.args.get("c"))
    return "ok"
`), "command-injection")).toHaveLength(0);
  });
  it("return summaries are per symbol: a same-named method that returns its argument does not taint the function", () => {
    expect(one(route(`
def build(x):
    return "ls"

class B:
    def build(self, x):
        return x

@app.route("/a")
def a():
    os.system(build(request.args.get("c")))
    return "ok"
`), "command-injection")).toHaveLength(0);
    expect(one(route(`
def build(x):
    return "ls"

class B:
    def build(self, x):
        return x

@app.route("/a")
def a():
    os.system(B().build(request.args.get("c")))
    return "ok"
`), "command-injection")).toHaveLength(1);
  });
});

describe("argument binding", () => {
  const call = (def: string, invocation: string) => route(`
${def}

@app.route("/a")
def a():
    c = request.args.get("c")
    ${invocation}
    return "ok"
`);
  it("keyword arguments bind by name, whatever their order", () => {
    const def = `def f(a, b):\n    os.system(b)`;
    expect(one(call(def, `f(b=c, a="x")`), "command-injection")).toHaveLength(1);
    expect(one(call(def, `f(a=c, b="ls")`), "command-injection")).toHaveLength(0);
    expect(one(call(def, `f(c, b="ls")`), "command-injection")).toHaveLength(0);
    expect(one(call(def, `f("x", b=c)`), "command-injection")).toHaveLength(1);
  });
  it("keyword-only and positional-only parameters", () => {
    expect(one(call(`def f(a, *, cmd):\n    os.system(cmd)`, `f("x", cmd=c)`), "command-injection")).toHaveLength(1);
    expect(one(call(`def f(a, *, cmd):\n    os.system(cmd)`, `f(c, cmd="ls")`), "command-injection")).toHaveLength(0);
    expect(one(call(`def f(cmd, /, a):\n    os.system(cmd)`, `f(c, a="x")`), "command-injection")).toHaveLength(1);
    expect(one(call(`def f(cmd, /, a):\n    os.system(cmd)`, `f("ls", a=c)`), "command-injection")).toHaveLength(0);
  });
  it("*args and **kwargs", () => {
    expect(one(call(`def f(*args):\n    os.system(args[0])`, `f(c)`), "command-injection")).toHaveLength(1);
    expect(one(call(`def f(**kw):\n    os.system(kw["cmd"])`, `f(cmd=c)`), "command-injection")).toHaveLength(1);
    expect(one(call(`def f(a, **kw):\n    os.system(a)`, `f("ls", cmd=c)`), "command-injection")).toHaveLength(0);
  });
  it("a default value is not caller-controlled", () => {
    expect(one(call(`def f(a, b="ls"):\n    os.system(b)`, `f(c)`), "command-injection")).toHaveLength(0);
    expect(one(call(`def f(a, b="ls"):\n    os.system(b)`, `f(c, c)`), "command-injection")).toHaveLength(1);
  });
  it("keyword binding drives return summaries", () => {
    const def = `def pick(a, b):\n    return b`;
    expect(one(call(def, `os.system(pick("x", b=c))`), "command-injection")).toHaveLength(1);
    expect(one(call(def, `os.system(pick(c, b="ls"))`), "command-injection")).toHaveLength(0);
    expect(one(call(def, `os.system(pick(b=c, a="x"))`), "command-injection")).toHaveLength(1);
  });
  it("bound instance, class and static methods", () => {
    const cls = (decorated: string, invocation: string) => route(`
class R:
${decorated}

@app.route("/a")
def a():
    c = request.args.get("c")
    ${invocation}
    return "ok"
`);
    expect(one(cls(`    def run(self, cmd):\n        os.system(cmd)`, `R().run(c)`), "command-injection")).toHaveLength(1);
    expect(one(cls(`    def run(self, cmd):\n        os.system(cmd)`, `R().run(cmd=c)`), "command-injection")).toHaveLength(1);
    expect(one(cls(`    @classmethod\n    def run(cls, cmd):\n        os.system(cmd)`, `R.run(c)`), "command-injection")).toHaveLength(1);
    expect(one(cls(`    @staticmethod\n    def run(cmd):\n        os.system(cmd)`, `R.run(c)`), "command-injection")).toHaveLength(1);
    expect(one(cls(`    @staticmethod\n    def run(prefix, cmd):\n        os.system(cmd)`, `R.run(c, "ls")`), "command-injection")).toHaveLength(0);
  });
  it("cross-file: keywords bind by name through the sink summary", () => {
    const db = `def run(sql, *, table):\n    cursor.execute(sql)\n`;
    const views = (call: string) => `from .db import run\n\ndef handler(request):\n    v = request.GET.get("v")\n    ${call}\n`;
    expect(found([{ path: "pkg/db.py", content: db }, { path: "pkg/views.py", content: views(`run(table="t", sql=v)`) }], "pkg/views.py", "sql-injection")).toHaveLength(1);
    expect(found([{ path: "pkg/db.py", content: db }, { path: "pkg/views.py", content: views(`run("select 1", table=v)`) }], "pkg/views.py", "sql-injection")).toHaveLength(0);
  });
});

describe("paths: building a path is a transformation, the filesystem call is the sink", () => {
  const p = (body: string) => route(`
import shutil
import zipfile
import tarfile
from pathlib import Path
BASE = "/srv/files"

@app.route("/a")
def a():
    f = request.args.get("f")
${body.split("\n").map(l => "    " + l).join("\n")}
    return "ok"
`);
  it("os.path.join, Path() and Path / value alone are not findings", () => {
    expect(one(p(`full = os.path.join(BASE, f)`), "path-traversal")).toHaveLength(0);
    expect(one(p(`full = Path(f)`), "path-traversal")).toHaveLength(0);
    expect(one(p(`full = Path(BASE) / f`), "path-traversal")).toHaveLength(0);
    expect(one(p(`full = os.path.normpath(os.path.join(BASE, f))`), "path-traversal")).toHaveLength(0);
  });
  it.each([
    ["open", `open(os.path.join(BASE, f))`],
    ["os.listdir", `os.listdir(os.path.join(BASE, f))`],
    ["os.scandir", `os.scandir(os.path.join(BASE, f))`],
    ["os.open", `os.open(os.path.join(BASE, f), os.O_RDONLY)`],
    ["pathlib read_text", `(Path(BASE) / f).read_text()`],
    ["pathlib via variable", `target = Path(BASE) / f\ntarget.unlink()`],
    ["shutil.copy", `shutil.copy(os.path.join(BASE, f), "/tmp/out")`],
    ["shutil.rmtree", `shutil.rmtree(os.path.join(BASE, f))`],
    ["zip extractall", `zipfile.ZipFile("a.zip").extractall(os.path.join(BASE, f))`],
    ["tar extractall", `tarfile.open("a.tar").extractall(path=os.path.join(BASE, f))`],
  ])("a tainted path reaching %s is reported", (_name, body) => {
    expect(one(p(body), "path-traversal").length).toBeGreaterThanOrEqual(1);
  });
  it("no '..' in the value does not prove it safe: an absolute path escapes the base directory", () => {
    expect(one(p(`if ".." in f:\n    abort(400)\nopen(os.path.join(BASE, f))`), "path-traversal")).toHaveLength(1);
  });
  it("canonical containment does", () => {
    expect(one(p(`full = os.path.realpath(os.path.join(BASE, f))\nif not full.startswith(BASE + os.sep):\n    abort(403)\nopen(full)`), "path-traversal")).toHaveLength(0);
    expect(one(p(`full = os.path.realpath(os.path.join(BASE, f))\nif os.path.commonpath([BASE, full]) != BASE:\n    abort(403)\nopen(full)`), "path-traversal")).toHaveLength(0);
    expect(one(p(`full = (Path(BASE) / f).resolve()\nif not full.is_relative_to(BASE):\n    abort(403)\nfull.read_text()`), "path-traversal")).toHaveLength(0);
  });
  it("a prefix test on a path that was not canonicalised proves nothing", () => {
    expect(one(p(`full = os.path.join(BASE, f)\nif not full.startswith(BASE):\n    abort(403)\nopen(full)`), "path-traversal")).toHaveLength(1);
  });
});

describe("validation proves only what it proves", () => {
  const q = (body: string) => route(`
@app.route("/a")
def a():
    name = request.args.get("n")
${body.split("\n").map(l => "    " + l).join("\n")}
`);
  it("no quote character does not make a numeric SQL position safe", () => {
    expect(one(q(`if "'" in name:\n    abort(400)\ncursor.execute("SELECT * FROM t WHERE id = " + name)\nreturn "ok"`), "sql-injection")).toHaveLength(1);
  });
  it("no '<' does not make an attribute or script context safe", () => {
    expect(one(q(`if "<" in name:\n    abort(400)\nreturn '<a href="/x" title="' + name + '">'`), "xss")).toHaveLength(1);
    expect(one(q(`if "<" in name:\n    abort(400)\nreturn "<script>var n = " + name + ";</script>"`), "xss")).toHaveLength(1);
  });
  it("no quote does not protect an identifier position in SQL", () => {
    expect(one(q(`if "'" in name or '"' in name:\n    abort(400)\ncursor.execute("SELECT * FROM " + name)\nreturn "ok"`), "sql-injection")).toHaveLength(1);
  });
  it("an allow-list still clears every class", () => {
    expect(one(q(`if name not in ["a", "b"]:\n    abort(400)\ncursor.execute("SELECT * FROM " + name)\nreturn "ok"`), "sql-injection")).toHaveLength(0);
  });
  it("an integer check still clears SQL", () => {
    expect(one(q(`if not name.isdigit():\n    abort(400)\ncursor.execute("SELECT * FROM t WHERE id = " + name)\nreturn "ok"`), "sql-injection")).toHaveLength(0);
  });
});

describe("FastAPI parameters", () => {
  const fa = (sig: string, body: string, extra = "") => `import os\nfrom typing import Annotated\nfrom fastapi import FastAPI, Depends, Query, Path, Body, Header, Cookie, Request\n${extra}\napp = FastAPI()\n\n@app.get("/x/{item}")\ndef h(${sig}):\n    ${body}\n    return {}\n`;
  it("a plain, Query, Path, Body, Header or Cookie parameter is attacker input", () => {
    for (const sig of ["cmd: str", "cmd: str = Query(...)", "cmd: str = Path(...)", "cmd: str = Body(...)", "cmd: str = Header(...)", "cmd: str = Cookie(None)", "cmd"]) {
      expect(one(fa(sig, "os.system(cmd)"), "command-injection")).toHaveLength(1);
    }
  });
  it("a Depends-injected dependency is not", () => {
    expect(one(fa("user=Depends(get_user)", "os.system(user)", "def get_user():\n    return 'u'"), "command-injection")).toHaveLength(0);
    expect(one(fa("db: Session = Depends(get_db)", "os.system(db)", "def get_db():\n    return 'x'"), "command-injection")).toHaveLength(0);
    expect(one(fa("user: Annotated[str, Depends(get_user)]", "os.system(user)", "def get_user():\n    return 'u'"), "command-injection")).toHaveLength(0);
  });
  it("a Depends parameter does not hide the request parameters beside it", () => {
    expect(one(fa("cmd: str, user=Depends(get_user)", "os.system(cmd)", "def get_user():\n    return 'u'"), "command-injection")).toHaveLength(1);
  });
  it("a value type the framework validates cannot carry an injection payload", () => {
    expect(one(fa("item_id: int", 'cursor.execute("SELECT * FROM t WHERE id = " + str(item_id))'), "sql-injection")).toHaveLength(0);
    expect(one(fa("item_id: str", 'cursor.execute("SELECT * FROM t WHERE id = " + item_id)'), "sql-injection")).toHaveLength(1);
  });
  it("the Request object's own query parameters are still sources", () => {
    expect(one(fa("request: Request", 'os.system(request.query_params["c"])'), "command-injection")).toHaveLength(1);
  });
});

describe("cross-file symbol resolution is exact", () => {
  const SQL = `def run_query(sql):\n    cursor.execute(sql)\n`;
  const SAFE = `def run_query(sql):\n    return len(sql)\n`;
  const view = (imp: string) => `${imp}\n\ndef handler(request):\n    v = request.GET.get("v")\n    run_query(v)\n`;
  it("two modules with the same function name: the import names the one it resolves to", () => {
    const files = (imp: string): F[] => [{ path: "pkg/a/db.py", content: SQL }, { path: "pkg/b/db.py", content: SAFE }, { path: "pkg/views.py", content: view(imp) }];
    expect(found(files("from .a.db import run_query"), "pkg/views.py", "sql-injection")).toHaveLength(1);
    expect(found(files("from .b.db import run_query"), "pkg/views.py", "sql-injection")).toHaveLength(0);
  });
  it("an absolute import matching two modules by suffix is unknown, not a guess", () => {
    const files: F[] = [{ path: "x/db.py", content: SQL }, { path: "y/db.py", content: SAFE }, { path: "views.py", content: view("from db import run_query") }];
    expect(found(files, "views.py", "sql-injection")).toHaveLength(0);
  });
  it("an unresolved import neither throws nor reports", () => {
    expect(() => found([{ path: "views.py", content: view("from nowhere import run_query") }], "views.py", "sql-injection")).not.toThrow();
    expect(found([{ path: "views.py", content: view("from nowhere import run_query") }], "views.py", "sql-injection")).toHaveLength(0);
  });
  it("the trace keeps the callee file and the real sink line", () => {
    const f = found([{ path: "pkg/db.py", content: SQL }, { path: "pkg/views.py", content: view("from .db import run_query") }], "pkg/views.py", "sql-injection")[0];
    expect(f.trace![f.trace!.length - 1]).toMatchObject({ kind: "sink", file: "pkg/db.py", line: 2 });
  });
});

describe("response typing", () => {
  it("a dict, jsonify or JSON return is not an HTML body", () => {
    expect(one(route(`@app.route("/a")\ndef a():\n    return {"q": request.args.get("q")}`), "xss")).toHaveLength(0);
    expect(one(route(`@app.route("/a")\ndef a():\n    return jsonify(q=request.args.get("q"))`), "xss")).toHaveLength(0);
    expect(one(route(`@app.route("/a")\ndef a():\n    return jsonify({"q": request.args.get("q")}), 200`), "xss")).toHaveLength(0);
    expect(one(route(`import json\n@app.route("/a")\ndef a():\n    return json.dumps({"q": request.args.get("q")})`), "xss")).toHaveLength(0);
  });
  it("a string returned from a handler is an HTML body", () => {
    expect(one(route(`@app.route("/a")\ndef a():\n    return "<p>" + request.args.get("q") + "</p>"`), "xss")).toHaveLength(1);
  });
  it("an explicit non-HTML mimetype is not HTML", () => {
    expect(one(route(`from flask import Response\n@app.route("/a")\ndef a():\n    return Response(request.args.get("q"), mimetype="application/json")`), "xss")).toHaveLength(0);
  });
});

describe("JWT verification", () => {
  it("a custom verifier is not assumed absent because no JWT library is imported", () => {
    const code = `import hmac, hashlib, base64, json\nfrom flask import request\n\ndef verify(token):\n    head, body, sig = token.split(".")\n    good = hmac.new(KEY, (head + "." + body).encode(), hashlib.sha256).digest()\n    return hmac.compare_digest(base64.urlsafe_b64decode(sig + "=="), good)\n\ndef handler():\n    token = request.headers.get("Authorization")\n    if not verify(token):\n        return "no", 401\n    claims = json.loads(base64.urlsafe_b64decode(token.split(".")[1] + "=="))\n    return claims\n`;
    expect(one(code, "jwt-none-alg")).toHaveLength(0);
  });
  it("base64 + JSON parsing of unrelated data is not a JWT bypass", () => {
    const code = `import base64, json\nfrom flask import request\n\n@app.route("/a")\ndef a():\n    blob = request.args.get("b")\n    data = json.loads(base64.b64decode(blob))\n    return {"n": data.get("n")}\n`;
    expect(one(code, "jwt-none-alg")).toHaveLength(0);
  });
});

describe("JWT: manual decode without any verification is still reported", () => {
  it("splits a token, decodes a part and parses it, with no signature check anywhere", () => {
    const code = `import base64, json\nfrom flask import request\n\ndef claims():\n    token = request.headers.get("Authorization")\n    payload = token.split(".")[1]\n    return json.loads(base64.urlsafe_b64decode(payload + "=="))\n`;
    expect(one(code, "jwt-none-alg")).toHaveLength(1);
  });
});

describe("a path built in a helper is reported where the filesystem is used", () => {
  it("helper returns os.path.join(BASE, decoded); the caller opens it", () => {
    const code = `import os\nBASE = "/srv"\n\ndef resolve_upload(name):\n    return os.path.join(BASE, name)\n\ndef case(request_obj):\n    target = resolve_upload(request_obj.args.get("name"))\n    with open(target, "r") as handle:\n        return handle.read()\n`;
    const f = one(code, "path-traversal");
    expect(f.map(x => x.line)).toEqual([9]);                 // the open(), not the join
  });
  it("abspath(join(..., f'{name}.json')) opened later", () => {
    const code = `import os\n\ndef read_config(name):\n    candidate = os.path.abspath(\n        os.path.join("/etc/myapp", f"{name}.json")\n    )\n    with open(candidate) as h:\n        return h.read()\n\ndef case(request_obj):\n    return read_config(request_obj.args.get("name"))\n`;
    const f = one(code, "path-traversal");
    expect(f.map(x => x.line)).toEqual([7]);                  // reported at the open() the tainted name reaches
  });
});

describe("a bare name is never a method", () => {
  it("run(x) calls whatever `run` is in scope, not the only method called run", () => {
    const code = route(`from runner import run

class Job:
    def run(self, cmd):
        os.system(cmd)

@app.route("/a")
def a():
    run(request.args.get("c"))
    return "ok"
`);
    expect(one(code, "command-injection")).toHaveLength(0);
  });
  it("a bare call is not a method's return summary either", () => {
    const code = route(`from helpers import echo

class Box:
    def echo(self, x):
        return x

@app.route("/a")
def a():
    os.system(echo(request.args.get("c")))
    return "ok"
`);
    expect(one(code, "command-injection")).toHaveLength(0);
  });
});
