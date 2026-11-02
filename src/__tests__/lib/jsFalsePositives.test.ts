/**
 * @jest-environment node
 *
 * JS/TS false positives found by scanning TrustLedger's own source (src/lib/fpBenchmarkBaseline.ts), fixed in the
 * engine rather than accepted:
 *   - `new URL(req.url)` -- a route handler parsing its own query string -- is not a server-side request forgery;
 *     a parsed URL that is then fetched still is.
 *   - "eval()" inside a string, a template's text or JSX text is not a call; eval in code (including inside a
 *     template's `${…}`) still is.
 */
import { analyzeFile } from "@/lib/scanner";

const ids = (path: string, src: string, id: string) => analyzeFile(path, src).indicators.filter(i => i.id === id).map(i => i.line);

describe("ssrf: new URL(...) only parses", () => {
  it("reading a route's own query string is not SSRF", () => {
    const src = [
      "export async function GET(req: Request) {",
      "  const url = new URL(req.url);",
      "  const q = url.searchParams.get('q');",
      "  return Response.json({ q });",
      "}",
    ].join("\n");
    expect(ids("src/app/api/search/route.ts", src, "ssrf")).toEqual([]);
  });

  it("a URL built from request input and then fetched is SSRF", () => {
    const src = [
      "app.get('/proxy', async (req, res) => {",
      "  const target = new URL(req.query.target);",
      "  const r = await fetch(target);",
      "  res.send(await r.text());",
      "});",
    ].join("\n");
    // reported where the request is made (the fetch), and/or where the URL is built
    expect(ids("src/proxy.js", src, "ssrf").some(l => l === 2 || l === 3)).toBe(true);
  });

  it("fetching it inline is SSRF too", () => {
    expect(ids("src/proxy.js", "app.post('/p', async (req, res) => { const r = await fetch(new URL(req.body.url)); res.send(r.status); });", "ssrf").length).toBeGreaterThan(0);
  });
});

describe("eval-exec: calls, not text", () => {
  it("'eval()' in a string, a template's text or JSX text is not a call", () => {
    const src = [
      "export const RULES = [{ detail: \"eval() or new Function() enables arbitrary code injection\" }];",
      "export const title = (n: number, r: string) => `eval()/exec() RCE pattern in ${n} files in ${r}`;",
      "export const Help = () => <p>Never call eval() on user input</p>;",
    ].join("\n");
    expect(ids("src/lib/catalog.tsx", src, "eval-exec")).toEqual([]);
  });

  it("eval in code is still found -- also inside a template substitution", () => {
    const src = [
      "export function run(req: any) {",
      "  const out = eval(req.body.code);",
      "  return `${eval(req.query.expr)}`;",
      "}",
    ].join("\n");
    expect(ids("src/lib/run.ts", src, "eval-exec")).toEqual(expect.arrayContaining([2, 3]));
  });

  it("new Function(...) built from a string is still found", () => {
    expect(ids("src/lib/run.ts", "export const f = (body: string) => new Function('a', body);", "eval-exec")).toEqual([1]);
  });
});
