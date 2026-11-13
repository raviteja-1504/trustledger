/**
 * @jest-environment node
 *
 * What dynast-bench's FastAPI app taught the Python engine:
 *  - `await request.body()` / `.form()` / `.stream()` read what the client sent (json() already did)
 *  - `RedirectResponse(x)` is a redirect sink, like Flask's redirect()
 *  - a same-site path check (`startswith("/")` and not `startswith("//")`) clears the redirect, in either spelling
 *  - the facets must survive `not` (they were dropped by the inversion helper)
 */
import { runScan } from "@/lib/scanner";
import { ensureTaintEngines } from "@/lib/engineWarmup";

beforeAll(async () => { await ensureTaintEngines(); }, 180000);

const ids = (content: string) =>
  runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files: [{ path: "app/main.py", content }] })
    .files.flatMap(f => f.indicators.filter(i => i.line != null).map(i => i.id));

const HEAD = `import yaml\nfrom fastapi import FastAPI, Request\nfrom fastapi.responses import RedirectResponse\napp = FastAPI()\n`;

describe("Starlette request readers are sources", () => {
  it("await request.body() reaches yaml.load with an unsafe loader", () => {
    expect(ids(HEAD + `@app.post("/y")\nasync def y(request: Request):\n    body = await request.body()\n    return {"v": str(yaml.load(body, Loader=yaml.Loader))}\n`)).toContain("insecure-deserialization");
  });
  it("yaml.safe_load of the same body is not reported", () => {
    expect(ids(HEAD + `@app.post("/y")\nasync def y(request: Request):\n    body = await request.body()\n    return {"v": str(yaml.safe_load(body))}\n`)).not.toContain("insecure-deserialization");
  });
});

describe("RedirectResponse", () => {
  it("is an open redirect for a request value", () => {
    expect(ids(HEAD + `@app.get("/goto")\nasync def goto(next: str = "/"):\n    return RedirectResponse(next)\n`)).toContain("open-redirect");
  });
  it("a same-site path check clears it (negated form with 'or')", () => {
    expect(ids(HEAD + `@app.get("/goto")\nasync def goto(next: str = "/"):\n    if not next.startswith("/") or next.startswith("//"):\n        next = "/"\n    return RedirectResponse(next)\n`)).not.toContain("open-redirect");
  });
  it("a same-site path check clears it (positive form with 'and')", () => {
    expect(ids(HEAD + `@app.get("/goto")\nasync def goto(next: str = "/"):\n    target = next if next.startswith("/") and not next.startswith("//") else "/"\n    return RedirectResponse(target)\n`)).not.toContain("open-redirect");
  });
  it("a '/' prefix check alone is not enough ('//evil.example' passes it)", () => {
    expect(ids(HEAD + `@app.get("/goto")\nasync def goto(next: str = "/"):\n    if not next.startswith("/"):\n        next = "/"\n    return RedirectResponse(next)\n`)).toContain("open-redirect");
  });
});
