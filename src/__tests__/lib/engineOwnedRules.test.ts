/**
 * @jest-environment node
 *
 * Rules the data-flow engines own (UTM step 4): on a file an engine analysed, the regex layer's findings for those
 * rules are dropped -- the engine's sink models decide. A file no engine parses keeps the regex as its only check.
 */
import { analyzeFile, ENGINE_OWNED_RULES } from "@/lib/scanner";
import { ensureTaintEngines } from "@/lib/engineWarmup";

beforeAll(async () => { await ensureTaintEngines(); }, 120_000);
const ssrfLines = (path: string, src: string) => analyzeFile(path, src).indicators.filter(i => i.id === "ssrf").map(i => i.line);

// The shape of Juice Shop's test/api/data-export.test.ts: request input read near a supertest `request(app)` call --
// the regex layer's proximity guess fires; the JS engine knows `request` here isn't an HTTP client (not imported)
const SUPERTEST = [
  "async function t(app, req) {",
  "  const note = req.body.note",
  "  await request(app).post('/rest/basket/4/checkout').send({ note })",
  "}",
].join("\n");

it("SSRF is engine-owned", () => expect([...ENGINE_OWNED_RULES]).toEqual(["ssrf"]));

it("the regex layer does guess SSRF there (so the next test means something)", () =>
  expect(ssrfLines("DataExport.scala", SUPERTEST)).toEqual([3]));

it("a regex-only SSRF guess on a file the JS engine analysed is dropped", () => expect(ssrfLines("data-export.test.js", SUPERTEST)).toEqual([]));

it("the engine's own SSRF findings stay", () =>
  expect(ssrfLines("a.js", ["app.get('/p', async (req, res) => {", "  await fetch(req.query.u);", "});"].join("\n"))).toEqual([2]));

it("a language with no engine keeps the regex layer", () =>
  expect(ssrfLines("Fetch.scala", ['def f(request: Request) = {', '  val u = request.getParameter("u")', "  new URL(request.getParameter(\"u\")).openStream()", "}"].join("\n")).length).toBeGreaterThan(0));
