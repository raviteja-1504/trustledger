/** @jest-environment node */
/**
 * webargs / flask-apispec `@use_kwargs` / `@use_args`: the decorator parses the request and hands the values to the view
 * as its keyword arguments, so those parameters are request input (and a `**kwargs` receives them all).
 */
import { runScan } from "@/lib/scanner";
import { ensureTaintEngines } from "@/lib/engineWarmup";

beforeAll(async () => { await ensureTaintEngines(); }, 120_000);

type Step = { file: string; line: number; kind: string };
type Hit = { file: string; id: string; line: number; trace: Step[] };
const scan = (files: Array<{ path: string; content: string }>): Hit[] =>
  runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files }).files.flatMap(f => f.indicators
    .filter(i => i.sourceExpr && i.line != null)
    .map(i => ({ file: f.file_path, id: i.id, line: i.line!, trace: (i as { trace?: Step[] }).trace ?? [] })));
const of = (hits: Hit[], id: string) => hits.filter(h => h.id === id);

const view = (decorator: string, signature: string, body: string) => ({
  path: "app/views.py",
  content: `from flask import Blueprint\nfrom flask_apispec import use_kwargs\nfrom webargs import fields\nfrom . import helpers\nbp = Blueprint('a', __name__)\n\n@bp.route('/x')\n${decorator}\n${signature}\n${body}\n`,
});

describe("webargs-bound parameters", () => {
  it("a dict-schema field reaching eval is code injection, traced from the decorated parameter", () => {
    const hits = of(scan([view(`@use_kwargs({'expression': fields.Str(required=True)})`, `def f(expression):`, `    return eval(expression, {}, {})`)]), "eval-exec");
    expect(hits).toHaveLength(1);
    expect(hits[0].trace.some(t => t.kind === "source" && t.line === 9)).toBe(true);   // the `def` line: where the parameter is declared
  });

  it("flows on through an imported helper (SQL text built there)", () => {
    const helper = { path: "app/helpers.py", content: `from app.db import db\n\n\ndef run_search(term):\n    query = "SELECT * FROM t WHERE x LIKE '%{0}%'".format(term)\n    return db.session.execute(query).fetchall()\n` };
    const hits = of(scan([view(`@use_kwargs({'q': fields.Str()})`, `def f(q):`, `    return helpers.run_search(q)`), helper]), "sql-injection");
    expect(hits).toHaveLength(1);
    expect(hits[0].trace.some(t => t.file === "app/helpers.py")).toBe(true);
  });

  it("a `**kwargs` view under a schema object receives them all (SSRF through a helper)", () => {
    const helper = { path: "app/helpers.py", content: `import requests\n\n\ndef reachable(url):\n    return requests.get(url, timeout=5).ok\n` };
    const hits = of(scan([view(`@use_kwargs(user_schema)`, `def f(**kwargs):`, `    return helpers.reachable(kwargs['image'])`), helper]), "ssrf");
    expect(hits).toHaveLength(1);
  });

  it("a `**kwargs` view under a dict schema of text fields receives them; of only typed fields it does not", () => {
    expect(of(scan([view(`@use_kwargs({'q': fields.Str()})`, `def f(**kwargs):`, `    return eval(kwargs['q'])`)]), "eval-exec")).toHaveLength(1);
    expect(of(scan([view(`@use_kwargs({'n': fields.Int()})`, `def f(**kwargs):`, `    return eval(kwargs['n'])`)]), "eval-exec")).toHaveLength(0);
  });

  it("a field the schema types as a number is not request text: no finding", () => {
    expect(scan([view(`@use_kwargs({'n': fields.Int()})`, `def f(n):`, `    return str(n)`)])).toHaveLength(0);
  });

  it("a parameter the schema does not name stays untainted", () => {
    expect(of(scan([view(`@use_kwargs({'q': fields.Str()})`, `def f(slug, q=None):`, `    return eval(slug)`)]), "eval-exec")).toHaveLength(0);
  });

  it("no webargs decorator: a plain parameter is not a source", () => {
    expect(of(scan([view(``, `def f(expression):`, `    return eval(expression)`)]), "eval-exec")).toHaveLength(0);
  });
});
