import { scanAstTaintPython, parsePythonSourceSync, warmPythonTaintEngine } from "@/lib/astTaintPython";

// Recall + precision for the Python AST engine: request-object naming, builtin/stdlib
// passthroughs, subscripts/await/lambdas/comprehensions, callbacks and closures, object
// methods, module-scope container memory, and the sinks/structural checks added with them.

beforeAll(async () => { await warmPythonTaintEngine(); }, 30000);

const ids = (code: string): string[] => {
  const root = parsePythonSourceSync(code, "a.py");
  if (!root) throw new Error("parse failed");
  return scanAstTaintPython(code, "a.py", root).map(f => f.id);
};
const has = (code: string, id: string) => ids(code).includes(id);

const HEAD = `import os, re, json, base64, subprocess, importlib, pickle, yaml
import urllib.parse
import urllib.request
from flask import Response, redirect, render_template_string
`;
const view = (body: string, top = "", param = "request_obj") =>
  `${HEAD}\n${top}\ndef view(${param}):\n    x = ${param}.args.get("q")\n${body.split("\n").map(l => "    " + l).join("\n")}\n`;
const sql = (expr: string) => view(`cursor.execute("SELECT " + ${expr})`);

describe("request objects are recognised by shape, not only the Flask global", () => {
  it.each(["request", "req", "request_obj", "http_request", "flask_request"])("%s", (name) => {
    expect(has(view(`cursor.execute("S " + x)`, "", name), "sql-injection")).toBe(true);
  });
  it("a parameter that is not request-shaped is not a source", () => {
    expect(has(view(`cursor.execute("S " + x)`, "", "config"), "sql-injection")).toBe(false);
  });
  it("request-shaped names still need a request attribute", () => {
    expect(has(`${HEAD}\ndef v(request_id):\n    cursor.execute("S " + request_id)\n`, "sql-injection")).toBe(false);
  });
});

describe("propagation through builtins and stdlib", () => {
  it.each([
    ["str(x)", "str(x)"],
    ["urllib.parse.unquote", "urllib.parse.unquote(x)"],
    ["json round trip", "json.loads(json.dumps({'v': x}))['v']"],
    ["base64.b64decode().decode()", "base64.b64decode(x).decode()"],
    ["sep.join([...])", "','.join(['a', x])"],
    ["os.path.join", "os.path.join('/b', x)"],
    ["str.format arg", "'{}'.format(x)"],
    ["dict subscript", "{'k': x}['k']"],
    ["x.split()[0]", "x.split(',')[0]"],
    ["d.get(k, tainted default)", "{}.get('k', x)"],
  ])("%s keeps taint", (_l, expr) => {
    expect(has(sql(expr), "sql-injection")).toBe(true);
  });
  it("int(x) neutralizes and an opaque call stays untainted", () => {
    expect(has(sql("int(x)"), "sql-injection")).toBe(false);
    expect(has(sql("some_unknown(x)"), "sql-injection")).toBe(false);
  });
  it("d.get(tainted_key) does not taint an untainted value", () => {
    expect(has(sql("{'a': 'b'}.get(x)"), "sql-injection")).toBe(false);
  });
  it("str() defeats NoSQL operator injection but not SQL", () => {
    expect(has(view(`users.find_one({"u": str(x)})`), "nosql-injection")).toBe(false);
    expect(has(view(`users.find_one({"u": x})`), "nosql-injection")).toBe(true);
  });
});

describe("await, lambdas, comprehensions, callbacks, methods", () => {
  it("await unwraps an async helper", () => {
    const code = `${HEAD}
async def make_sql(v):
    return "S " + v
async def view(request_obj):
    q = await make_sql(request_obj.args.get("id"))
    cursor.execute(q)
`;
    expect(has(code, "sql-injection")).toBe(true);
  });
  it("a returned lambda carries what it captured", () => {
    const code = `${HEAD}
def delayed(v):
    return lambda: v
def view(request_obj):
    r = delayed(request_obj.args.get("q"))
    cursor.execute("S " + r())
`;
    expect(has(code, "sql-injection")).toBe(true);
  });
  it("a generator expression passed to join binds its loop variable", () => {
    expect(has(view(`cursor.execute("".join(f"<{c}>" for c in [x]))`), "sql-injection")).toBe(true);
    expect(has(view(`cursor.execute("".join(f"<{c}>" for c in ["a", "b"]))`), "sql-injection")).toBe(false);
  });
  it("a list comprehension carries the iterable's taint", () => {
    expect(has(view(`cursor.execute(",".join([c.strip() for c in x.split(",")]))`), "sql-injection")).toBe(true);
  });
  it("a higher-order helper propagates through its callback parameter", () => {
    const code = `${HEAD}
def with_value(v, callback):
    return callback(v)
def view(request_obj):
    cursor.execute(with_value(request_obj.args.get("q"), lambda s: s))
`;
    expect(has(code, "sql-injection")).toBe(true);
  });
  it("a local class method resolves by name", () => {
    const code = `${HEAD}
class Repo:
    def find_by_id(self, uid):
        return cursor.execute("S " + uid)
repo = Repo()
def view(request_obj):
    return repo.find_by_id(request_obj.args.get("id"))
`;
    expect(has(code, "sql-injection")).toBe(true);
  });
  it("*args from a list splat reaches the helper", () => {
    const code = `${HEAD}
def build(parts):
    return " ".join(parts)
def view(request_obj):
    hosts = request_obj.form.getlist("h")
    os.system(build(["ping", *hosts]))
`;
    expect(has(code, "command-injection")).toBe(true);
  });
});

describe("containers and module-scope memory", () => {
  it("append into a local list taints the list", () => {
    expect(has(view(`items = []\nitems.append(x)\ncursor.execute(",".join(items))`), "sql-injection")).toBe(true);
  });
  it("assigning into a dict by key taints the dict", () => {
    expect(has(view(`d = {}\nd["k"] = x\ncursor.execute("S " + d["k"])`), "sql-injection")).toBe(true);
  });
  it("stored XSS: a module-level list written by one function and read by another", () => {
    const code = `${HEAD}
comments = []
def render():
    body = "".join(f"<li>{c}</li>" for c in comments)
    return Response(body, mimetype="text/html")
def store(request_obj):
    comments.append(request_obj.form.get("comment"))
`;
    expect(has(code, "xss")).toBe(true);
  });
  it("second-order SQL through a module-level dict", () => {
    const code = `${HEAD}
saved = {}
def save(request_obj):
    saved[request_obj.form.get("u")] = request_obj.form.get("q")
def run(u):
    cursor.execute("S " + saved.get(u, ""))
`;
    expect(has(code, "sql-injection")).toBe(true);
  });
  it("a local that shadows the module-level container is not tainted by it", () => {
    const code = `${HEAD}
comments = []
def store(request_obj):
    comments.append(request_obj.form.get("c"))
def render():
    comments = ["a", "b"]
    return Response("".join(comments), mimetype="text/html")
`;
    expect(has(code, "xss")).toBe(false);
  });
});

describe("new sinks", () => {
  it("Response / make_response are HTML sinks unless the mimetype is not HTML", () => {
    expect(has(view(`return Response(x, mimetype="text/html")`), "xss")).toBe(true);
    expect(has(view(`return Response(x)`), "xss")).toBe(true);
    expect(has(view(`return Response(x, mimetype="application/json")`), "xss")).toBe(false);
    expect(has(view(`return Response("ok")`), "xss")).toBe(false);
  });
  it("response.headers[...] = tainted, and .headers.add()", () => {
    expect(has(view(`r = Response("ok")\nr.headers["X-A"] = x`), "header-injection")).toBe(true);
    expect(has(view(`r = Response("ok")\nr.headers.add("X-A", x)`), "header-injection")).toBe(true);
    expect(has(view(`r = Response("ok")\nr.headers["X-A"] = "const"`), "header-injection")).toBe(false);
  });
  it("a Response object with a tainted header is not itself returned as an HTML string", () => {
    expect(has(view(`r = Response("ok")\nr.headers["X-A"] = x\nreturn r`), "xss")).toBe(false);
  });
  it("pymongo-style find/update with a request-derived filter", () => {
    expect(has(view(`mongo.users.find({"u": x})`), "nosql-injection")).toBe(true);
    expect(has(view(`collection.update_one({"id": x}, {"$set": {}})`), "nosql-injection")).toBe(true);
  });
  it("LDAP and XPath", () => {
    expect(has(view(`conn.search_s("dc=x", 2, "(uid=" + x + ")")`), "ldap-injection")).toBe(true);
    expect(has(view(`tree.xpath("//u[@n='" + x + "']")`), "xpath-injection")).toBe(true);
    expect(has(view(`tree.xpath("//u")`), "xpath-injection")).toBe(false);
  });
  it("a user-controlled regular expression", () => {
    expect(has(view(`re.search(x, "text")`), "redos")).toBe(true);
    expect(has(view(`re.compile(x)`), "redos")).toBe(true);
    expect(has(view(`re.search("^a+$", x)`), "redos")).toBe(false);
    expect(has(view(`re.search(re.escape(x), "text")`), "redos")).toBe(false);
  });
  it("eval / exec / aliases / dynamic import / globals dispatch", () => {
    expect(has(view(`eval(x)`), "eval-exec")).toBe(true);
    expect(has(`${HEAD}\nrun = eval\ndef v(request_obj):\n    run(request_obj.form.get("e"))\n`, "eval-exec")).toBe(true);
    expect(has(view(`importlib.import_module(x)`), "eval-exec")).toBe(true);
    expect(has(view(`fn = globals().get(x)\nfn(1)`), "eval-exec")).toBe(true);
    expect(has(view(`fn = globals().get("known")\nfn(1)`), "eval-exec")).toBe(false);
  });
  it("pickle / yaml deserialization, but not safe_load or a Safe loader", () => {
    expect(has(view(`pickle.loads(base64.b64decode(x))`), "insecure-deserialization")).toBe(true);
    expect(has(view(`yaml.load(x, Loader=yaml.Loader)`), "insecure-deserialization")).toBe(true);
    expect(has(view(`yaml.load(x, Loader=yaml.SafeLoader)`), "insecure-deserialization")).toBe(false);
    expect(has(view(`yaml.safe_load(x)`), "insecure-deserialization")).toBe(false);
  });
  it("setattr with an attacker-chosen name, and an attacker-controlled format string", () => {
    expect(has(view(`setattr(obj, x, 1)`), "mass-assignment")).toBe(true);
    expect(has(view(`setattr(obj, "role", x)`), "mass-assignment")).toBe(false);
    expect(has(view(`return x.format(user=u)`), "ssti")).toBe(true);
    expect(has(view(`return "{}".format(x)`), "ssti")).toBe(false);
  });
  it("subprocess: shell=True or a tainted EXECUTABLE flags, tainted arguments alone do not", () => {
    expect(has(view(`subprocess.run(["ls", x])`), "command-injection")).toBe(false);
    expect(has(view(`subprocess.run([x, "-l"])`), "command-injection")).toBe(true);
    expect(has(view(`subprocess.run("ls " + x, shell=True)`), "command-injection")).toBe(true);
  });
  it("send_file / os.remove / shutil are path sinks", () => {
    expect(has(`${HEAD}\nfrom flask import send_file\ndef v(request_obj):\n    return send_file(request_obj.args.get("f"))\n`, "path-traversal")).toBe(true);
    expect(has(view(`os.remove(x)`), "path-traversal")).toBe(true);
  });
});

describe("returned strings from request handlers", () => {
  it("a handler returning a tainted string is reflected XSS", () => {
    expect(has(view(`return "<p>" + x + "</p>"`), "xss")).toBe(true);
    expect(has(view(`return f"<p>{x}</p>"`), "xss")).toBe(true);
  });
  it("dict / list / jsonify returns are not HTML", () => {
    expect(has(view(`return {"q": x}`), "xss")).toBe(false);
    expect(has(view(`return [x]`), "xss")).toBe(false);
    expect(has(view(`return jsonify({"q": x})`), "xss")).toBe(false);
  });
  it("a helper returning a dict is not treated as an HTML string", () => {
    const code = `${HEAD}
def merge(t, s):
    for k, v in s.items():
        t[k] = v
    return t
def view(request_obj):
    return merge({}, request_obj.get_json())
`;
    expect(has(code, "xss")).toBe(false);
  });
  it("a non-handler function returning a tainted value is not an XSS sink", () => {
    expect(has(`${HEAD}\ndef helper(value):\n    return "<p>" + value\n`, "xss")).toBe(false);
  });
  it("a FastAPI handler's return is JSON, not HTML", () => {
    const code = `${HEAD}
from fastapi import FastAPI
app = FastAPI()
@app.get("/x")
def h(request):
    return "<p>" + request.args.get("q")
`;
    expect(has(code, "xss")).toBe(false);
  });
});

describe("escaping context", () => {
  it("an escaped value inside <script> is still XSS; in a quoted attribute or element text it is not", () => {
    const esc = "def escape_html(v):\n    return v.replace('<', '&lt;')\n";
    expect(has(view(`v = escape_html(x)\nh = f"<script>const a = '{v}';</script>"\nreturn Response(h, mimetype="text/html")`, esc), "xss")).toBe(true);
    expect(has(view(`v = escape_html(x)\nh = f"<div>{v}</div>"\nreturn Response(h, mimetype="text/html")`, esc), "xss")).toBe(false);
    expect(has(view(`v = escape_html(x)\nh = f'<div data-v="{v}"></div>'\nreturn Response(h, mimetype="text/html")`, esc), "xss")).toBe(false);
  });
  it("escape-then-append re-taints", () => {
    const esc = "def escape_html(v):\n    return v.replace('<', '&lt;')\n";
    expect(has(view(`o = escape_html(x) + request_obj.args.get("s")\nreturn Response(o, mimetype="text/html")`, esc), "xss")).toBe(true);
  });
});

describe("timing, JWT, dict merge", () => {
  it("secret compared to request input with ==", () => {
    const top = `SECRET = os.getenv("S")`;
    expect(has(view(`if x == SECRET:\n    pass`, top), "timing-attack")).toBe(true);
    expect(has(view(`if x == "literal":\n    pass`, top), "timing-attack")).toBe(false);
    expect(has(view(`if SECRET == "literal":\n    pass`, top), "timing-attack")).toBe(false);
  });
  it("hand-rolled JWT payload decode in a file with no verification", () => {
    const code = `import base64, json
def decode(t):
    p = t.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(p + "=="))
`;
    expect(has(code, "jwt-none-alg")).toBe(true);
    expect(has(`import jwt\n${code}`, "jwt-none-alg")).toBe(false);
  });
  it("copying a request dict key-by-key onto an object", () => {
    const code = `${HEAD}
def apply(obj, fields):
    for k, v in fields.items():
        obj[k] = v
    return obj
def view(request_obj):
    return apply({}, request_obj.get_json())
`;
    expect(has(code, "mass-assignment")).toBe(true);
  });
  it("a word-count loop is not mass assignment", () => {
    const code = `${HEAD}
def count(request_obj):
    counts = {}
    for w in request_obj.args.get("t").split():
        counts[w] = counts.get(w, 0) + 1
    return counts
`;
    expect(has(code, "mass-assignment")).toBe(false);
  });
});
