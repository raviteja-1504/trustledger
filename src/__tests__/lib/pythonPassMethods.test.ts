/**
 * @jest-environment node
 *
 * Python cross-file pass-through methods: `thing = helpers.ThingFactory.createThing(); thing.doSomething(param)` --
 * the factory picks a class at run time, so the argument counts only when EVERY batch definition of the method
 * returns it (OWASP Benchmark Python's shape).
 */
import { runScan, collectPassMethodsPy } from "@/lib/scanner";
import { computePassMethodsPy } from "@/lib/astTaintPython";
import { ensureTaintEngines } from "@/lib/engineWarmup";
import { parsePythonSourceSync } from "@/lib/astTaintPython";

beforeAll(async () => { await ensureTaintEngines(); }, 120_000);

const FACTORY = (thing2Body: string) => [
  "def createThing():",
  "    return Thing1()",
  "",
  "class Thing1:",
  "    def doSomething(self, x: str):",
  "        ret = x",
  "        return ret",
  "",
  "class Thing2:",
  "    def doSomething(self, x: str):",
  thing2Body,
].join("\n");
const PASSES = "        return '' + x";
const DROPS = "        return 'constant'";

const VIEW = [
  "from flask import request",
  "import helpers.ThingFactory",
  "def view():",
  "    param = request.args.get('f')",
  "    thing = helpers.ThingFactory.createThing()",
  "    bar = thing.doSomething(param)",
  "    return open(f'/srv/files/{bar}').read()",
].join("\n");

const pathFindings = (thing2Body: string) => runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files: [
  { path: "helpers/ThingFactory.py", content: FACTORY(thing2Body) }, { path: "app/views.py", content: VIEW },
] }).files.find(f => f.file_path === "app/views.py")!.indicators.filter(i => i.id === "path-traversal" && i.sourceExpr).map(i => i.line);

describe("per-method summaries", () => {
  it("argument indexes after self, with what survives", () => {
    const out = computePassMethodsPy(FACTORY(PASSES), "f.py");
    expect(out.map(([n, e]) => [n, e.map(([i]) => i)])).toEqual([["doSomething", [0]], ["doSomething", [0]]]);
  });
  it("a definition passing nothing through is still listed (it vetoes the name)", () =>
    expect(computePassMethodsPy(FACTORY(DROPS), "f.py")[1]).toEqual(["doSomething", []]));
  it("builtin method names are never summarised", () =>
    expect(computePassMethodsPy("class C:\n    def get(self, k):\n        return k\n", "c.py")).toEqual([]));
});

describe("batch combination", () => {
  const combine = (body: string) => collectPassMethodsPy(new Map([["f.py", parsePythonSourceSync(FACTORY(body), "f.py")!]]), new Map([["f.py", FACTORY(body)]]));
  it("every definition passes argument 0: kept", () => expect([...(combine(PASSES).get("doSomething") ?? new Map()).keys()]).toEqual([0]));
  it("one definition doesn't: the name is dropped", () => expect(combine(DROPS).has("doSomething")).toBe(false));
});

describe("end to end", () => {
  it("a factory-made object's pass-through method carries the request value to the file read", () => expect(pathFindings(PASSES)).toEqual([7]));
  it("not when one implementation returns a constant", () => expect(pathFindings(DROPS)).toEqual([]));
});
