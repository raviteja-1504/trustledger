import { scanAstTaint } from "@/lib/astTaint";

// Recall + precision for the JS/TS AST engine: builtin passthroughs, await,
// element access, callbacks/closures, object methods, module-scope container
// memory, the fluent `res.*` sink shapes, and the sinks/structural checks added
// with them. `x` is request-derived unless a test says otherwise.

const HELPERS = `
import * as path from "node:path";
import * as fs from "node:fs";
import * as cp from "node:child_process";
function identity<T>(x: T): T { return x; }
function wrap<T>(x: T): { value: T } { return { value: x }; }
function unwrap<T>(x: { value: T }): T { return x.value; }
function delayed<T>(x: T): () => T { return () => x; }
function escapeHtml(v: string) { return v.replaceAll("<", "&lt;"); }
`;
const handler = (body: string, top = "") => `${HELPERS}\n${top}\napp.get("/a", async (req: any, res: any) => {\n  const x = req.query.q;\n${body}\n});\n`;
const ids = (code: string) => scanAstTaint(code, "a.ts").map(f => f.id);
const has = (code: string, id: string) => ids(code).includes(id);
const sql = (expr: string) => handler(`db.query("S " + ${expr});`);

describe("propagation through builtins", () => {
  it.each([
    ["String(x)", "String(x)"],
    ["decodeURIComponent(x)", "decodeURIComponent(x)"],
    ["JSON.parse(JSON.stringify())", "JSON.parse(JSON.stringify({ v: x })).v"],
    ["Buffer.from().toString()", 'Buffer.from(x, "base64").toString("utf8")'],
    ["new URL(x).toString()", "new URL(x).toString()"],
    ["path.resolve", 'path.resolve("/b", x)'],
    ["Object.assign({}, x)", "Object.assign({}, x)"],
    ["x.split()[0]", 'x.split(",")[0]'],
    ["closure held in a variable", "delayed(x)()"],
    ["replace with tainted replacement", '"abc".replace("b", x)'],
  ])("%s keeps taint", (_l, expr) => {
    expect(has(sql(expr), "sql-injection")).toBe(true);
  });

  it("Number(x) and parseInt still neutralize", () => {
    expect(has(sql("Number(x)"), "sql-injection")).toBe(false);
    expect(has(sql("parseInt(x, 10)"), "sql-injection")).toBe(false);
  });

  it("a decoder re-taints what an earlier URL-encoder cleared", () => {
    expect(has(handler(`res.redirect(decodeURIComponent(encodeURIComponent(x)));`), "open-redirect")).toBe(true);
    expect(has(handler(`res.redirect(encodeURIComponent(x));`), "open-redirect")).toBe(false);
  });

  it("String() defeats operator-object (NoSQL) injection but not SQL", () => {
    expect(has(handler(`mongo.find({ u: String(x) });`), "nosql-injection")).toBe(false);
    expect(has(handler(`mongo.find({ u: x });`), "nosql-injection")).toBe(true);
  });

  it("an opaque unknown call is still untainted", () => {
    expect(has(sql("someUnknownThing(x)"), "sql-injection")).toBe(false);
  });
});

describe("await, promises, callbacks, closures", () => {
  it("await unwraps", () => {
    expect(has(handler(`const v = await Promise.resolve(x); db.query("S " + v);`), "sql-injection")).toBe(true);
  });
  it("await of a local async helper propagates", () => {
    expect(has(handler(`const v = await abuild(x); db.query(v);`, `async function abuild(v: string) { return "Q " + v; }`), "sql-injection")).toBe(true);
  });
  it(".then(cb) carries what the callback makes of the value", () => {
    expect(has(handler(`const v = await Promise.resolve(x).then(y => y.trim()).then(y => \`<i>\${y}</i>\`); res.send(v);`), "xss")).toBe(true);
    expect(has(handler(`const v = await Promise.resolve(x).then(y => escapeHtml(y)); res.send(v);`), "xss")).toBe(false);
  });
  it("a higher-order helper propagates through its callback parameter", () => {
    expect(has(handler(`res.send(withValue(x, y => y));`, `function withValue<T>(v: T, cb: (a: T) => T): T { return cb(v); }`), "xss")).toBe(true);
  });
  it("a returned closure carries what it captured", () => {
    expect(has(handler(`res.send(mk(x)());`, `function mk(v: string) { const c = v; return () => "<h1>" + c + "</h1>"; }`), "xss")).toBe(true);
  });
  it("a local class method resolves by name", () => {
    expect(has(handler(`await repo.findById(x);`, `class R { async findById(id: string) { return db.query("S " + id); } } const repo = new R();`), "sql-injection")).toBe(true);
  });
  it("a property written onto an object taints the whole object", () => {
    expect(has(handler(`const u: any = {}; u.host = x; http.get(u.toString());`), "ssrf")).toBe(true);
  });
});

describe("containers and module-scope memory", () => {
  it("a value pushed into a local array taints the array", () => {
    expect(has(handler(`const a: string[] = []; a.push(x); res.send(a.join(","));`), "xss")).toBe(true);
  });
  it("a value written into a container by key taints the container", () => {
    expect(has(handler(`const o: any = {}; o[x] = x; res.send(JSON.stringify(o));`), "xss")).toBe(true);
  });
  it("stored XSS: taint written by one handler is read by another (either order)", () => {
    const code = `${HELPERS}
const comments: string[] = [];
app.get("/read", (_req: any, res: any) => { res.type("html").send("<ul>" + comments.map(c => "<li>" + c + "</li>").join("") + "</ul>"); });
app.post("/write", (req: any, res: any) => { comments.push(String(req.body.c)); res.json({}); });`;
    expect(has(code, "xss")).toBe(true);
  });
  it("second-order SQL through a module-level Map", () => {
    const code = `${HELPERS}
const saved = new Map<string, string>();
app.post("/s", (req: any, res: any) => { saved.set(String(req.body.u), String(req.body.q)); });
async function run(u: string) { return db.query("S " + (saved.get(u) ?? "")); }`;
    expect(has(code, "sql-injection")).toBe(true);
  });
  it("a LOCAL variable that shadows the module-level container is not tainted by it", () => {
    const code = `${HELPERS}
const comments: string[] = [];
app.post("/w", (req: any, res: any) => { comments.push(String(req.body.c)); });
app.get("/r", (_req: any, res: any) => { const comments = ["a", "b"]; res.send(comments.join(",")); });`;
    expect(has(code, "xss")).toBe(false);
  });
});

describe("response sinks", () => {
  it.each([
    ["res.send(x)", `res.send(x);`],
    ["res.type('html').send(x)", `res.type("html").send(x);`],
    ["res.status(200).send(x)", `res.status(200).send(x);`],
    ["res.status(200).type('html').send(x)", `res.status(200).type("html").send(x);`],
  ])("%s is an XSS sink", (_l, body) => {
    expect(has(handler(body), "xss")).toBe(true);
  });
  it("a constant through the chain is not flagged", () => {
    expect(has(handler(`res.status(200).send("ok");`), "xss")).toBe(false);
  });
  it("res.json is not an XSS sink", () => {
    expect(has(handler(`res.json({ v: x });`), "xss")).toBe(false);
  });
  it("setHeader / set / header are header-injection sinks", () => {
    expect(has(handler(`res.setHeader("X-A", x);`), "header-injection")).toBe(true);
    expect(has(handler(`res.status(200).set("X-A", x);`), "header-injection")).toBe(true);
    expect(has(handler(`res.setHeader("X-A", "const");`), "header-injection")).toBe(false);
  });
  it("sendFile / download are path-traversal sinks, but sendFile with { root } is confined", () => {
    expect(has(handler(`res.sendFile(x);`), "path-traversal")).toBe(true);
    expect(has(handler(`res.download(x);`), "path-traversal")).toBe(true);
    expect(has(handler(`res.sendFile(x, { root: "/srv/public" });`), "path-traversal")).toBe(false);
  });
  it("execFile / execFileSync / fork are command sinks", () => {
    expect(has(handler(`cp.execFileSync(x, ["a"]);`), "command-injection")).toBe(true);
    expect(has(handler(`cp.execFile("ls", [x]);`), "command-injection")).toBe(true);
  });
});

describe("NoSQL, RegExp, dynamic code", () => {
  it("mongo-style find/update with a request-derived filter", () => {
    expect(has(handler(`await mongo.find({ u: x });`), "nosql-injection")).toBe(true);
    expect(has(handler(`await users.updateOne({ id: x }, { $set: {} });`), "nosql-injection")).toBe(true);
  });
  it("Array.find with a callback is not NoSQL", () => {
    expect(has(handler(`const found = users.find(u => u.id === x);`), "nosql-injection")).toBe(false);
  });
  it("filter merged from the request through a helper", () => {
    const code = handler(`await mongo.find(makeFilter(req.body.filter));`, `
function deepMerge(target: any, source: any) { for (const k of Object.keys(source)) { const v = source[k]; target[k] = v; } return target; }
function makeFilter(f: any) { return deepMerge({ active: true }, f); }`);
    expect(has(code, "nosql-injection")).toBe(true);
  });
  it("new RegExp(userInput) / RegExp(userInput)", () => {
    expect(has(handler(`new RegExp(x);`), "redos")).toBe(true);
    expect(has(handler(`RegExp(x);`), "redos")).toBe(true);
    expect(has(handler(`new RegExp("^a+$");`), "redos")).toBe(false);
  });
  it("dynamic import of a request-derived module", () => {
    expect(has(handler(`await import(x);`), "eval-exec")).toBe(true);
    expect(has(handler(`await import("./known");`), "eval-exec")).toBe(false);
  });
  it("an alias of eval is still eval", () => {
    expect(has(handler(`const run = eval; run(x);`), "eval-exec")).toBe(true);
  });
  it("a function selected from globalThis by an attacker-chosen key", () => {
    expect(has(handler(`const fn = (globalThis as any)[String(x)]; fn(1);`), "eval-exec")).toBe(true);
    expect(has(handler(`(globalThis as any)[x](1);`), "eval-exec")).toBe(true);
    expect(has(handler(`const fn = (globalThis as any)["parseInt"]; fn("1");`), "eval-exec")).toBe(false);
  });
});

describe("escaping context", () => {
  it("an HTML-escaped value inside <script> is still an XSS", () => {
    expect(has(handler(`res.send(\`<script>const a = '\${escapeHtml(x)}';</script>\`);`), "xss")).toBe(true);
  });
  it("an HTML-escaped value in element text or a quoted attribute stays clean", () => {
    expect(has(handler(`res.send(\`<div>\${escapeHtml(x)}</div>\`);`), "xss")).toBe(false);
    expect(has(handler(`res.send(\`<div data-v="\${escapeHtml(x)}"></div>\`);`), "xss")).toBe(false);
  });
  it("escape-then-append re-taints", () => {
    expect(has(handler(`res.send(escapeHtml(x) + String(req.query.s));`), "xss")).toBe(true);
  });
});

describe("mass assignment, timing, JWT, prototype pollution", () => {
  it("Object.assign(new Entity(), req.body)", () => {
    expect(has(handler(`res.json(Object.assign(new Account(), req.body));`), "mass-assignment")).toBe(true);
    expect(has(handler(`res.json(Object.assign({}, req.body));`), "mass-assignment")).toBe(false);
    expect(has(handler(`res.json(Object.assign(new Account(), { a: 1 }));`), "mass-assignment")).toBe(false);
  });
  it("secret compared to request input with ===", () => {
    const top = `const SECRET = process.env.APP_SECRET;`;
    expect(has(handler(`if (String(req.query.token) === SECRET) res.send("ok");`, top), "timing-attack")).toBe(true);
    expect(has(handler(`if (x === "literal") res.send("ok");`, top), "timing-attack")).toBe(false);
    expect(has(handler(`if (SECRET === "literal") res.send("ok");`, top), "timing-attack")).toBe(false);
  });
  it("hand-rolled JWT payload decode with no verification in the file", () => {
    const code = `function dec(t: string) { const [, p] = t.split("."); return JSON.parse(Buffer.from(p, "base64url").toString("utf8")); }`;
    expect(has(code, "jwt-none-alg")).toBe(true);
    expect(has(`import jwt from "jsonwebtoken"; ${code} jwt.verify("a", "b");`, "jwt-none-alg")).toBe(false);
  });
  it("dotted-path setter without a prototype guard", () => {
    const bad = `function setPath(o: any, p: string, v: unknown) { const parts = p.split("."); let c = o; for (let i = 0; i < parts.length - 1; i++) { c[parts[i]] ??= {}; c = c[parts[i]]; } c[parts[parts.length - 1]] = v; }`;
    expect(has(bad, "prototype-pollution")).toBe(true);
    const guarded = bad.replace("const parts", `if (p.includes("__proto__") || p.includes("constructor")) return; const parts`);
    expect(has(guarded, "prototype-pollution")).toBe(false);
  });
});
