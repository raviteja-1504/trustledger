import { runScan } from "@/lib/scanner";
import { warmPythonTaintEngine } from "@/lib/astTaintPython";

beforeAll(async () => { await warmPythonTaintEngine(); }, 120000);

// SQL position awareness, end to end through both engines: escaping is a real defence inside a quoted string
// literal and none at all outside one (an unquoted numeric position, or an identifier).

const scan = (path: string, content: string) =>
  runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files: [{ path, content }] });
const astSql = (content: string) =>
  scan("src/route.ts", content).files[0].indicators.filter(i => i.id === "sql-injection" && i.sourceExpr !== undefined);
const route = (body: string) => `app.get("/x", async (req, res) => {\n  const id = req.query.id;\n  ${body}\n});`;

describe("JS/TS SQL: escaping is a defence only inside a quoted literal", () => {
  it("escaped value inside quotes is NOT flagged (the common escape+quote pattern)", () => {
    expect(astSql(route(`db.query("SELECT * FROM t WHERE name = '" + mysql.escape(id) + "'");`))).toHaveLength(0);
  });
  it("escaped value in an unquoted numeric position IS flagged (escaping doesn't help)", () => {
    const f = astSql(route(`db.query("SELECT * FROM t WHERE id = " + mysql.escape(id));`));
    expect(f).toHaveLength(1);
    expect(f[0].detail ?? "").toMatch(/quoted string literal/);
  });
  it("escaped value in an identifier position (ORDER BY) IS flagged", () => {
    expect(astSql(route(`db.query("SELECT * FROM t ORDER BY " + mysql.escape(id));`))).toHaveLength(1);
  });
  it("escaped value standing alone IS flagged", () => {
    expect(astSql(route(`db.query(mysql.escape(id));`))).toHaveLength(1);
  });
  it("connection.escape / SqlString.escape are recognized the same way", () => {
    expect(astSql(route(`db.query("SELECT * FROM t WHERE name = '" + connection.escape(id) + "'");`))).toHaveLength(0);
    expect(astSql(route(`db.query("SELECT * FROM t WHERE id = " + connection.escape(id));`))).toHaveLength(1);
  });
});

describe("JS/TS SQL: a plainly tainted value is flagged in every position", () => {
  it("unescaped inside quotes", () => {
    expect(astSql(route(`db.query("SELECT * FROM t WHERE name = '" + id + "'");`))).toHaveLength(1);
  });
  it("unescaped unquoted", () => {
    expect(astSql(route(`db.query("SELECT * FROM t WHERE id = " + id);`))).toHaveLength(1);
  });
});

describe("JS/TS SQL: coercion is safe everywhere, including unquoted", () => {
  it("parseInt clears it in a numeric position", () => {
    expect(astSql(route(`db.query("SELECT * FROM t WHERE id = " + parseInt(id));`))).toHaveLength(0);
  });
});

describe("JS/TS: SQL-escaping does not neutralize a DIFFERENT class on the same value", () => {
  it("mysql.escape does not clear command injection", () => {
    const r = scan("src/route.ts", route(`exec("ls " + mysql.escape(id));`));
    expect(r.files[0].indicators.filter(i => i.id === "command-injection")).toHaveLength(1);
  });
});

// ── Python: same rule, same verdicts ──
const pyScan = (content: string) =>
  scan("app/views.py", content).files[0].indicators.filter(i => i.id === "sql-injection" && i.sourceExpr !== undefined);
const pyRoute = (body: string) =>
  `import pymysql\nfrom flask import request\n\n@app.route("/x")\ndef view():\n    uid = request.args.get("id")\n    ${body}\n`;

describe("Python SQL: escaping is a defence only inside a quoted literal", () => {
  it("escaped value inside quotes is NOT flagged", () => {
    expect(pyScan(pyRoute('cursor.execute("SELECT * FROM t WHERE name = \'" + pymysql.escape_string(uid) + "\'")'))).toHaveLength(0);
  });
  it("escaped value in an unquoted numeric position IS flagged", () => {
    const f = pyScan(pyRoute('cursor.execute("SELECT * FROM t WHERE id = " + pymysql.escape_string(uid))'));
    expect(f).toHaveLength(1);
    expect(f[0].detail ?? "").toMatch(/quoted string literal/);
  });
  it("escaped value in an identifier position IS flagged", () => {
    expect(pyScan(pyRoute('cursor.execute("SELECT * FROM t ORDER BY " + pymysql.escape_string(uid))'))).toHaveLength(1);
  });
  it("int() coercion is safe even unquoted", () => {
    expect(pyScan(pyRoute('cursor.execute("SELECT * FROM t WHERE id = " + str(int(uid)))'))).toHaveLength(0);
  });
});

describe("Python SQL: a plainly tainted value is flagged in every position", () => {
  it("unescaped inside quotes (f-string)", () => {
    expect(pyScan(pyRoute('cursor.execute(f"SELECT * FROM t WHERE name = \'{uid}\'")'))).toHaveLength(1);
  });
  it("unescaped unquoted (f-string)", () => {
    expect(pyScan(pyRoute('cursor.execute(f"SELECT * FROM t WHERE id = {uid}")'))).toHaveLength(1);
  });
});

// ── parity: the summary/cross-file walk must agree with the main scan on SQL shape ──
type Multi = { path: string; content: string }[];
const scanMulti = (files: Multi) => runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files });
const countSql = (r: ReturnType<typeof scanMulti>, path: string) =>
  r.files.find(f => f.file_path === path)!.indicators.filter(i => i.id === "sql-injection" && i.confidence === 95).length;

const JS_SQL_SHAPES: Array<[string, string, number]> = [
  ["escaped, inside quotes",        `db.query("SELECT * FROM t WHERE name = '" + mysql.escape(p) + "'");`, 0],
  ["escaped, unquoted",             `db.query("SELECT * FROM t WHERE id = " + mysql.escape(p));`, 1],
  ["whole query tainted",           "db.query(p);", 1],
  ["coerced, unquoted",             `db.query("SELECT * FROM t WHERE id = " + parseInt(p));`, 0],
];
describe("parity JS/TS: summary walk agrees with the main scan on SQL shape", () => {
  it.each(JS_SQL_SHAPES)("%s", (_name, body, expected) => {
    const def = `export function wrap(p) {\n  ${body}\n}`;
    const call = `app.get("/x", (req, res) => {\n  wrap(req.query.v);\n});`;
    const same = scanMulti([{ path: "src/one.ts", content: `${def}\n${call}` }]);
    const cross = scanMulti([{ path: "src/lib.ts", content: def }, { path: "src/route.ts", content: `import { wrap } from "./lib";\n${call}` }]);
    expect(countSql(same, "src/one.ts")).toBe(expected);
    expect(countSql(cross, "src/route.ts")).toBe(expected);
  });
});

const PY_SQL_SHAPES: Array<[string, string, number]> = [
  ["escaped, inside quotes",        "cursor.execute(\"SELECT * FROM t WHERE name = '\" + pymysql.escape_string(p) + \"'\")", 0],
  ["escaped, unquoted",             'cursor.execute("SELECT * FROM t WHERE id = " + pymysql.escape_string(p))', 1],
  ["whole query tainted",           "cursor.execute(p)", 1],
  ["coerced, unquoted",             'cursor.execute("SELECT * FROM t WHERE id = " + str(int(p)))', 0],
];
describe("parity Python: summary walk agrees with the main scan on SQL shape", () => {
  it.each(PY_SQL_SHAPES)("%s", (_name, body, expected) => {
    const def = `import pymysql\n\ndef wrap(p):\n    ${body}\n`;
    const call = `@app.route("/x")\ndef view():\n    wrap(request.args.get("v"))\n`;
    const same = scanMulti([{ path: "app/one.py", content: `${def}\nfrom flask import request\n${call}` }]);
    const cross = scanMulti([{ path: "app/lib.py", content: def }, { path: "app/views.py", content: `from flask import request\nfrom app.lib import wrap\n\n${call}` }]);
    expect(countSql(same, "app/one.py")).toBe(expected);
    expect(countSql(cross, "app/views.py")).toBe(expected);
  });
});
