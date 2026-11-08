/** @jest-environment node */
/** SQLAlchemy `session.execute(text(f"..."))`: text() only wraps the SQL string, so the string is the injectable part. */
import { runScan } from "@/lib/scanner";
import { ensureTaintEngines } from "@/lib/engineWarmup";

beforeAll(async () => { await ensureTaintEngines(); }, 120_000);

type Step = { file: string; line: number; kind: string };
const sqli = (files: Array<{ path: string; content: string }>) => runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files })
  .files.flatMap(f => f.indicators.filter(i => i.id === "sql-injection" && i.sourceExpr).map(i => ({ file: f.file_path, line: i.line!, trace: ((i as { trace?: Step[] }).trace ?? []) })));

const handler = (stmt: string) => ({ path: "app/x.py", content: `from fastapi import FastAPI, Query\nfrom typing import Annotated\nfrom sqlalchemy import text\napp = FastAPI()\n\n@app.get("/x")\nasync def f(q: Annotated[str, Query()], session):\n${stmt}\n    return result.all()\n` });

describe("text() wrapped SQL", () => {
  it("an f-string inside text() is flagged, traced from the parameter", () => {
    const [h] = sqli([handler(`    result = await session.execute(text(f"SELECT 1 WHERE t LIKE '%{q}%'"))`)]);
    expect(h).toBeDefined();
    expect(h.line).toBe(8);
    expect(h.trace.some(t => t.kind === "source" && t.line === 7)).toBe(true);
  });

  it("with a second positional argument (`text(sql, bind)`), the SQL is the first", () => {
    expect(sqli([handler(`    result = await session.execute(text(f"SELECT 1 WHERE t LIKE '%{q}%'", engine))`)])).toHaveLength(1);
  });

  it("bound parameters beside a constant text() are not", () => {
    expect(sqli([handler(`    result = await session.execute(text("SELECT 1 WHERE t LIKE :q"), {"q": f"%{q}%"})`)])).toHaveLength(0);
  });

  it("flows through an awaited cross-file service call", () => {
    const svc = { path: "app/services/reports.py", content: `from sqlalchemy import text\n\n\nasync def search_reports(session, query):\n    result = await session.execute(text(f"SELECT id FROM reports WHERE title LIKE '%{query}%'"))\n    return result.all()\n` };
    const caller = { path: "app/www.py", content: `from fastapi import FastAPI, Query\nfrom typing import Annotated\nfrom .services.reports import search_reports\napp = FastAPI()\n\n@app.get("/r")\nasync def r(\n    query: Annotated[str, Query()],\n    session,\n):\n    reports = await search_reports(session, query)\n    return reports\n` };
    const hits = sqli([caller, svc]);
    expect(hits).toHaveLength(1);
    expect(hits[0].trace.map(t => `${t.file}:${t.line}`)).toEqual(expect.arrayContaining(["app/www.py:8", "app/services/reports.py:5"]));
  });
});
