import { runScan } from "@/lib/scanner";
import { warmPythonTaintEngine } from "@/lib/astTaintPython";

beforeAll(async () => { await warmPythonTaintEngine(); }, 30000);

// SSRF position awareness, end to end through the JS/TS engine: where the untrusted part lands in the URL decides.

const scan = (path: string, content: string) =>
  runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files: [{ path, content }] });
const ssrf = (content: string) =>
  scan("src/route.ts", content).files[0].indicators.filter(i => i.id === "ssrf");
const route = (body: string) => `app.get("/x", async (req, res) => {\n  const id = req.query.id;\n  ${body}\n});`;

describe("JS/TS SSRF: literal host, tainted path segment", () => {
  it("template literal with a pinned host is NOT flagged (the ordinary REST-client call)", () => {
    expect(ssrf(route("await fetch(`https://api.example.com/users/${id}`);"))).toHaveLength(0);
  });
  it("concatenation with a pinned host is NOT flagged", () => {
    expect(ssrf(route(`await fetch("https://api.example.com/users/" + id);`))).toHaveLength(0);
  });
  it("...also through axios and a query string", () => {
    expect(ssrf(route("await axios.get(`https://api.example.com/search?q=${id}`);"))).toHaveLength(0);
  });
});

describe("JS/TS SSRF: attacker picks the host", () => {
  it("the whole URL is tainted", () => {
    expect(ssrf(route("await fetch(id);"))).toHaveLength(1);
  });
  it("host position in a template literal, and the culprit is named", () => {
    const f = ssrf(route("await fetch(`https://${id}/users`);"));
    expect(f).toHaveLength(1);
    expect(f[0].sourceExpr).toContain("id");
  });
  it("host position in a concatenation", () => {
    expect(ssrf(route(`await fetch("https://" + id);`))).toHaveLength(1);
  });
  it("an unterminated host (`.evil.com` / `@evil.com` can be appended)", () => {
    expect(ssrf(route("await fetch(`https://api.example.com${id}`);"))).toHaveLength(1);
  });
});

describe("JS/TS SSRF: URL-encoding is position dependent", () => {
  it("encoding in host position does NOT clear it (was a false negative)", () => {
    const f = ssrf(route("await fetch(`https://${encodeURIComponent(id)}/x`);"));
    expect(f).toHaveLength(1);
    expect(f[0].detail ?? "").toMatch(/host position/);
  });
  it("encoding in a path or query IS a defence", () => {
    expect(ssrf(route("await fetch(`https://api.example.com/u/${encodeURIComponent(id)}`);"))).toHaveLength(0);
  });
  it("an encoded value alone is not a host", () => {
    expect(ssrf(route("await fetch(encodeURIComponent(id));"))).toHaveLength(0);
  });
  it("coercion clears it everywhere, even in host position", () => {
    expect(ssrf(route("await fetch(`https://${parseInt(id)}/x`);"))).toHaveLength(0);
  });
});

describe("JS/TS: value kind does not leak into other sink classes", () => {
  it("encodeURIComponent still does not neutralize SQL", () => {
    const r = scan("src/q.ts", route("db.query(`SELECT * FROM t WHERE a = '${encodeURIComponent(id)}'`);"));
    expect(r.files[0].indicators.filter(i => i.id === "sql-injection")).toHaveLength(1);
  });
});

// ── Python: same rule, same verdicts (the position model is shared, the decomposition is per-engine) ──
const pyScan = (content: string) =>
  scan("app/views.py", content).files[0].indicators.filter(i => i.id === "ssrf");
const pyRoute = (body: string) =>
  `import requests\nfrom flask import request\n\n@app.route("/x")\ndef view():\n    uid = request.args.get("id")\n    ${body}\n`;

describe("Python SSRF: position awareness", () => {
  it("f-string with a pinned host is NOT flagged", () => {
    expect(pyScan(pyRoute('requests.get(f"https://api.example.com/users/{uid}")'))).toHaveLength(0);
  });
  it("concatenation with a pinned host is NOT flagged", () => {
    expect(pyScan(pyRoute('requests.get("https://api.example.com/users/" + uid)'))).toHaveLength(0);
  });
  it("whole URL tainted", () => {
    expect(pyScan(pyRoute("requests.get(uid)"))).toHaveLength(1);
  });
  it("host position in an f-string, culprit named", () => {
    const f = pyScan(pyRoute('requests.get(f"https://{uid}/users")'));
    expect(f).toHaveLength(1);
    expect(f[0].sourceExpr).toContain("uid");
  });
  it("host position in a concatenation", () => {
    expect(pyScan(pyRoute('requests.get("https://" + uid)'))).toHaveLength(1);
  });
  it("unterminated host", () => {
    expect(pyScan(pyRoute('requests.get(f"https://api.example.com{uid}")'))).toHaveLength(1);
  });
  it("quote() in host position does NOT clear it", () => {
    const f = pyScan(pyRoute('requests.get(f"https://{urllib.parse.quote(uid)}/x")').replace("import requests", "import requests\nimport urllib.parse"));
    expect(f).toHaveLength(1);
    expect(f[0].detail ?? "").toMatch(/host position/);
  });
  it("quote() in a path IS a defence", () => {
    expect(pyScan(pyRoute('requests.get(f"https://api.example.com/u/{urllib.parse.quote(uid)}")').replace("import requests", "import requests\nimport urllib.parse"))).toHaveLength(0);
  });
  it("int() coercion clears it even in host position", () => {
    expect(pyScan(pyRoute('requests.get(f"https://{int(uid)}/x")'))).toHaveLength(0);
  });
  it("another tainted argument is still checked when the URL itself is pinned", () => {
    // multi-line so only the AST engine (not the line-based regex layer) can see the tainted keyword argument
    const call = ["requests.get(", '        f"https://api.example.com/x/{uid}",', "        proxies=uid,", "    )"].join("\n");
    expect(pyScan(pyRoute(call))).toHaveLength(1);
  });
});

// ── parity: a wrapper in another file must get the SAME verdict as the same code in one file ──
type Multi = { path: string; content: string }[];
const scanMulti = (files: Multi) => runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files });
const countSsrf = (r: ReturnType<typeof scanMulti>, path: string) =>
  r.files.find(f => f.file_path === path)!.indicators.filter(i => i.id === "ssrf").length;

const JS_SHAPES: Array<[string, string, number]> = [
  ["pinned host, path operand",       "fetch(`https://api.example.com/u/${p}`);", 0],
  ["pinned host, concatenation",      `fetch("https://api.example.com/u/" + p);`, 0],
  ["operand is the whole URL",        "fetch(p);", 1],
  ["operand is the host",             "fetch(`https://${p}/x`);", 1],
  ["unterminated host",               "fetch(`https://api.example.com${p}`);", 1],
  ["encoded operand in host",         "fetch(`https://${encodeURIComponent(p)}/x`);", 1],
  ["encoded operand in path",         "fetch(`https://api.example.com/u/${encodeURIComponent(p)}`);", 0],
  ["coerced operand in host",         "fetch(`https://${parseInt(p)}/x`);", 0],
];
describe("parity JS/TS: summary walk agrees with the main scan on SSRF shape", () => {
  it.each(JS_SHAPES)("%s", (_name, body, expected) => {
    const def = `export function wrap(p) {\n  ${body}\n}`;
    const call = `app.get("/x", (req, res) => {\n  wrap(req.query.v);\n});`;
    const same = scanMulti([{ path: "src/one.ts", content: `${def}\n${call}` }]);
    const cross = scanMulti([{ path: "src/lib.ts", content: def }, { path: "src/route.ts", content: `import { wrap } from "./lib";\n${call}` }]);
    // same-file: the finding lands at the sink inside `wrap` (seeded call) -- count it wherever it is
    expect(countSsrf(same, "src/one.ts")).toBe(expected);
    expect(countSsrf(cross, "src/route.ts")).toBe(expected);
  });
});

const PY_SHAPES: Array<[string, string, number]> = [
  ["pinned host, f-string",           'requests.get(f"https://api.example.com/u/{p}")', 0],
  ["pinned host, concatenation",      'requests.get("https://api.example.com/u/" + p)', 0],
  ["operand is the whole URL",        "requests.get(p)", 1],
  ["operand is the host",             'requests.get(f"https://{p}/x")', 1],
  ["unterminated host",               'requests.get(f"https://api.example.com{p}")', 1],
  ["encoded operand in host",         'requests.get(f"https://{urllib.parse.quote(p)}/x")', 1],
  ["encoded operand in path",         'requests.get(f"https://api.example.com/u/{urllib.parse.quote(p)}")', 0],
  ["coerced operand in host",         'requests.get(f"https://{int(p)}/x")', 0],
];
describe("parity Python: summary walk agrees with the main scan on SSRF shape", () => {
  it.each(PY_SHAPES)("%s", (_name, body, expected) => {
    const def = `import requests\nimport urllib.parse\n\ndef wrap(p):\n    ${body}\n`;
    const call = `@app.route("/x")\ndef view():\n    wrap(request.args.get("v"))\n`;
    const same = scanMulti([{ path: "app/one.py", content: `${def}\nfrom flask import request\n${call}` }]);
    const cross = scanMulti([{ path: "app/lib.py", content: def }, { path: "app/views.py", content: `from flask import request\nfrom app.lib import wrap\n\n${call}` }]);
    expect(countSsrf(same, "app/one.py")).toBe(expected);
    expect(countSsrf(cross, "app/views.py")).toBe(expected);
  });
});
