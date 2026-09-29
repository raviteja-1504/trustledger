import { runScan } from "@/lib/scanner";
import { scanAstTaint } from "@/lib/astTaint";
import { scanAstTaintPython, warmPythonTaintEngine } from "@/lib/astTaintPython";

beforeAll(async () => { await warmPythonTaintEngine(); }, 120000);

type F = { path: string; content: string };
const sqlLines = (files: F[], path = "src/r.ts") => {
  const r = runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files });
  return (r.files.find(f => f.file_path === path)?.indicators ?? []).filter(i => i.id === "sql-injection" && i.sourceExpr).map(i => i.line);
};
const route = (body: string, top = "") => ({ path: "src/r.ts", content: `${top}\napp.get("/u", async (req, res) => {\n${body}\n});\n` });
const Q = `db.query("SELECT * FROM u WHERE id = " + id)`;

describe("JS: taint that comes back from a helper, a promise or a callback", () => {
  const helpers = { path: "src/h.ts", content: `export async function getId(req) { return req.query.id; }\nexport function getIdSync(req) { return req.query.id; }\nexport function withId(req, cb) { cb(req.query.id); }\nexport function fetchId(req) { return Promise.resolve(req.query.id); }\nexport function withOne(cb) { cb("1"); }\n` };

  it("a helper that returns request input it reads itself: sync, awaited, or through a promise, in this file or another", () => {
    expect(sqlLines([route(`  const id = await getId(req);\n  ${Q};`, `async function getId(req) { return req.query.id; }`)])).toEqual([4]);
    expect(sqlLines([helpers, route(`  const id = getIdSync(req);\n  ${Q};`, `import { getIdSync } from "./h";`)])).toEqual([4]);
    expect(sqlLines([helpers, route(`  const id = await getId(req);\n  ${Q};`, `import { getId } from "./h";`)])).toEqual([4]);
    expect(sqlLines([helpers, route(`  const id = await fetchId(req);\n  ${Q};`, `import { fetchId } from "./h";`)])).toEqual([4]);
  });

  it("a .then / array callback receives the receiver's value", () => {
    expect(sqlLines([route(`  Promise.resolve(req.query.id).then(id => ${Q});`)])).toEqual([3]);
    expect(sqlLines([helpers, route(`  getId(req).then(id => ${Q});`, `import { getId } from "./h";`)])).toEqual([3]);
    expect(sqlLines([route(`  [req.query.a, req.query.b].forEach(id => ${Q});`)])).toEqual([3]);
    expect(sqlLines([route(`  Promise.resolve("1").then(id => ${Q});`)])).toEqual([]);
  });

  it("a callback handed to a helper that calls it with request input, in this file or another", () => {
    expect(sqlLines([route(`  withId(req, id => ${Q});`, `function withId(req, cb) { cb(req.query.id); }`)])).toEqual([3]);
    expect(sqlLines([helpers, route(`  withId(req, id => ${Q});`, `import { withId } from "./h";`)])).toEqual([3]);
    expect(sqlLines([helpers, route(`  withOne(id => ${Q});`, `import { withOne } from "./h";`)])).toEqual([]);
  });
});

describe("JS: code evaluated inside a node:vm sandbox", () => {
  const ids = (b: string) => scanAstTaint(`import vm from "vm";\nimport { eval as safeEval } from "notevil";\napp.post("/x", (req, res) => {\n${b}\n});\n`, "x.ts").map(f => f.id);

  it("a constant code string that runs a sandbox evaluator on request data (Juice Shop's b2bOrder)", () => {
    expect(ids(`const orderLinesData = req.body.orderLinesData || "";\nconst sandbox = { safeEval, orderLinesData };\nvm.createContext(sandbox);\nvm.runInContext("safeEval(orderLinesData)", sandbox, { timeout: 2000 });`)).toEqual(["eval-exec"]);
    expect(ids(`const data = req.body.x;\nvm.runInNewContext("eval(data)", { data });`)).toEqual(["eval-exec"]);
  });

  it("request data as the code string itself", () => {
    expect(ids(`vm.runInNewContext(req.body.code, {});`)).toEqual(["eval-exec"]);
  });

  it("not when the sandbox value is constant, or the code doesn't evaluate it", () => {
    expect(ids(`const data = "1+1";\nvm.runInContext("safeEval(data)", { safeEval, data });`)).toEqual([]);
    expect(ids(`const data = req.body.x;\nvm.runInContext("JSON.stringify(data)", { data });`)).toEqual([]);
    expect(ids(`const data = req.body.x;\nconst format = (s) => s.trim();\nvm.runInContext("format(data)", { format, data });`)).toEqual([]);
  });

  it("new Function is a data-flow finding only with a tainted argument", () => {
    expect(ids(`const f = new Function("specifier", "return import(specifier)");`)).toEqual([]);
    expect(ids(`const f = new Function("ctx", req.body.code);`)).toEqual(["eval-exec"]);
  });

  it("...and an all-constant new Function isn't reported by the pattern layer either (Juice Shop's lib/xml.ts)", () => {
    const src = `const dynamicImport = new Function('specifier', 'return import(specifier)');\nexport async function load() { return dynamicImport('libxml2-wasm'); }\n`;
    const r = runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files: [{ path: "lib/xml.ts", content: src }] });
    expect(r.files[0].indicators.filter(i => i.id === "eval-exec")).toEqual([]);
  });
});

describe("Python: XML parsed with external entities explicitly enabled (XXE)", () => {
  const ids = (b: string) => scanAstTaintPython(`from xml.dom.pulldom import parseString\nfrom xml.sax import make_parser\nfrom xml.sax.handler import feature_external_ges\nfrom lxml import etree\ndef v(request):\n${b.split("\n").map(l => "    " + l).join("\n")}\n`, "v.py").map(f => f.id);

  it("SAX/pulldom with feature_external_ges on (PyGoat), and lxml with resolve_entities=True", () => {
    expect(ids(`parser = make_parser()\nparser.setFeature(feature_external_ges, True)\ndoc = parseString(request.body.decode("utf-8"), parser=parser)`)).toEqual(["xxe"]);
    expect(ids(`p = etree.XMLParser(resolve_entities=True)\netree.fromstring(request.body, p)`)).toEqual(["xxe"]);
  });

  it("not with the feature off, the default parser, a safe lxml parser, or a constant document", () => {
    expect(ids(`p = make_parser()\np.setFeature(feature_external_ges, False)\nparseString(request.body.decode(), parser=p)`)).toEqual([]);
    expect(ids(`parseString(request.body.decode())`)).toEqual([]);
    expect(ids(`p = etree.XMLParser(resolve_entities=False)\netree.fromstring(request.body, p)`)).toEqual([]);
    expect(ids(`p = make_parser()\np.setFeature(feature_external_ges, True)\nparseString("<a/>", parser=p)`)).toEqual([]);
  });
});
