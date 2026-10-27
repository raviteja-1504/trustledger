/**
 * @jest-environment node
 *
 * Python coverage found scanning DVPWA (Damn Vulnerable Python Web Application, aiohttp): aiohttp's request
 * surface as input (`await request.post()`, `request.query`, `request.match_info`), `web.Response` as an HTML sink
 * only when its content type says so, and `md5(...)` imported bare from hashlib.
 */
import { runScan } from "@/lib/scanner";
import { warmPythonTaintEngine } from "@/lib/astTaintPython";

beforeAll(async () => { await warmPythonTaintEngine(); }, 120000);

const scan = (files: Array<[string, string]>) =>
  runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files: files.map(([path, content]) => ({ path, content })) });
const ids = (files: Array<[string, string]>, file: string, ast = true) =>
  scan(files).files.find(f => f.file_path === file)!.indicators.filter(i => !ast || !!i.sourceExpr).map(i => i.id);

const view = (body: string) => `from aiohttp import web\n\nasync def handler(request):\n${body}\n`;

describe("aiohttp request input", () => {
  it("form, query and path segments reach SQL", () => {
    const sql = (read: string) => view(`    v = ${read}\n    async with request.app['db'].acquire() as conn:\n        async with conn.cursor() as cur:\n            await cur.execute("SELECT * FROM s WHERE n = '%s'" % v)\n    return web.json_response({})`);
    expect(ids([["views.py", sql(`(await request.post())['name']`)]], "views.py")).toContain("sql-injection");
    expect(ids([["views.py", sql(`request.query.get('q')`)]], "views.py")).toContain("sql-injection");
    expect(ids([["views.py", sql(`request.match_info['id']`)]], "views.py")).toContain("sql-injection");
    expect(ids([["views.py", sql(`int(request.match_info['id'])`)]], "views.py")).not.toContain("sql-injection");
  });
  it("through a DAO's static method in another file", () => {
    const dao = `class Student:\n    @staticmethod\n    async def create(conn, name: str):\n        q = ("INSERT INTO students (name) VALUES ('%(name)s')" % {'name': name})\n        async with conn.cursor() as cur:\n            await cur.execute(q)\n`;
    const v = `from aiohttp.web import Request\nfrom app.dao.student import Student\n\nasync def students(request: Request):\n    data = await request.post()\n    async with request.app['db'].acquire() as conn:\n        await Student.create(conn, data['name'])\n    return {}\n`;
    expect(ids([["app/dao/student.py", dao], ["app/views.py", v]], "app/views.py")).toContain("sql-injection");
  });
});

describe("aiohttp web.Response", () => {
  it("is HTML only with an HTML content type", () => {
    const resp = (args: string) => view(`    q = request.query.get('q')\n    return web.Response(${args})`);
    expect(ids([["views.py", resp(`text="<p>" + q + "</p>", content_type="text/html")`)]], "views.py")).toContain("xss");
    expect(ids([["views.py", resp(`text="<p>" + q + "</p>"`)]], "views.py")).not.toContain("xss");
    expect(ids([["views.py", resp(`text="<p>" + q + "</p>", content_type="application/json")`)]], "views.py")).not.toContain("xss");
  });
});

describe("weak hash imported bare", () => {
  it("from hashlib import md5 / sha1 (aliased too); not an unrelated md5()", () => {
    const f = (imp: string, call: string) => `${imp}\n\ndef check(pw, stored):\n    return stored == ${call}(pw.encode()).hexdigest()\n`;
    expect(ids([["user.py", f("from hashlib import md5", "md5")]], "user.py", false)).toContain("weak-crypto");
    expect(ids([["user.py", f("from hashlib import sha1 as digest", "digest")]], "user.py", false)).toContain("weak-crypto");
    expect(ids([["user.py", f("from hashlib import sha256", "sha256")]], "user.py", false)).not.toContain("weak-crypto");
    expect(ids([["user.py", f("from mylib import md5", "md5")]], "user.py", false)).not.toContain("weak-crypto");
  });
});
