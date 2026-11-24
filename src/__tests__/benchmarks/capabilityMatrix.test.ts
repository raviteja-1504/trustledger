/**
 * @jest-environment node
 *
 * Capability matrix for the taint engines: one vulnerable case and one safe twin per analysis capability and language,
 * each isolating ONE property (field sensitivity, calling context, path sensitivity, interprocedural flow, cross-file
 * flow, aliasing, return values, sanitizers, framework sources, heap objects ...). Every case runs through the real
 * production pipeline (runScan). The report gives TP/FP/FN/TN, precision, recall and time per capability and per
 * language, and is written to capabilityMatrix.report.json in a deterministic order (no timestamps, no timings in the
 * JSON) so two runs on the same code are byte-identical.
 *
 * A small hand-written corpus: it shows which capabilities work and which do not, it is not a recall estimate for real
 * code. Cases are designed from the capability, never from the engine's own names, so a miss is a real gap.
 */
import fs from "fs";
import path from "path";
import { runScan } from "@/lib/scanner";
import { warmPythonTaintEngine } from "@/lib/astTaintPython";
import { warmCppTaintEngine } from "@/lib/astTaintCpp";

type Cap =
  | "field-sensitive" | "context-sensitive" | "path-sensitive" | "interprocedural" | "cross-file" | "pointer-alias"
  | "pointer-to-pointer" | "return-value" | "side-effect-summary" | "heap-object" | "sanitizer" | "framework";

interface Case { cap: Cap; lang: string; name: string; files: Record<string, string>; id: string; vulnerable: boolean }

const L = (...lines: string[]) => lines.join("\n") + "\n";
const cases: Case[] = [];
const pair = (cap: Cap, lang: string, name: string, id: string, vuln: Record<string, string>, safe: Record<string, string>) => {
  cases.push({ cap, lang, name, id, files: vuln, vulnerable: true });
  cases.push({ cap, lang, name, id, files: safe, vulnerable: false });
};

// ───────────────────────────── JavaScript (Express) ─────────────────────────────
const JS = "src/handler.js";
const jsHead = L(`const { exec } = require("child_process");`, `const express = require("express");`, `const app = express();`);
const jsRoute = (...body: string[]) => jsHead + L(`app.get("/a", (req, res) => {`, ...body.map(b => "  " + b), `  res.send("ok");`, `});`);
pair("field-sensitive", "javascript", "tainted vs clean property", "command-injection",
  { [JS]: jsRoute(`const o = {};`, `o.cmd = req.query.d;`, `o.safe = "ls";`, `exec(o.cmd);`) },
  { [JS]: jsRoute(`const o = {};`, `o.cmd = req.query.d;`, `o.safe = "ls";`, `exec(o.safe);`) });
pair("context-sensitive", "javascript", "same helper, tainted vs clean call", "command-injection",
  { [JS]: jsHead + L(`function id(x) { return x; }`, `app.get("/a", (req, res) => {`, `  const a = id("ls");`, `  const b = id(req.query.d);`, `  exec(b);`, `  res.send(a);`, `});`) },
  { [JS]: jsHead + L(`function id(x) { return x; }`, `app.get("/a", (req, res) => {`, `  const a = id("ls");`, `  const b = id(req.query.d);`, `  exec(a);`, `  res.send(b);`, `});`) });
pair("path-sensitive", "javascript", "overwritten on every branch", "command-injection",
  { [JS]: jsRoute(`let c = req.query.d;`, `if (req.query.f) { c = "ls"; }`, `exec(c);`) },
  { [JS]: jsRoute(`let c = req.query.d;`, `if (req.query.f) { c = "ls"; } else { c = "pwd"; }`, `exec(c);`) });
pair("interprocedural", "javascript", "two helper hops", "command-injection",
  { [JS]: jsHead + L(`function l2(x) { return "ls " + x; }`, `function l1(x) { return l2(x); }`, `app.get("/a", (req, res) => { exec(l1(req.query.d)); res.send("ok"); });`) },
  { [JS]: jsHead + L(`function l2(x) { return "ls"; }`, `function l1(x) { return l2(x); }`, `app.get("/a", (req, res) => { exec(l1(req.query.d)); res.send("ok"); });`) });
pair("cross-file", "javascript", "helper in another module", "command-injection",
  { "src/util.js": L(`exports.build = function build(x) { return "ls " + x; };`), [JS]: jsHead + L(`const { build } = require("./util");`, `app.get("/a", (req, res) => { exec(build(req.query.d)); res.send("ok"); });`) },
  { "src/util.js": L(`exports.build = function build(x) { return "ls"; };`), [JS]: jsHead + L(`const { build } = require("./util");`, `app.get("/a", (req, res) => { exec(build(req.query.d)); res.send("ok"); });`) });
pair("pointer-alias", "javascript", "object alias", "command-injection",
  { [JS]: jsRoute(`const a = {};`, `const b = a;`, `b.cmd = req.query.d;`, `exec(a.cmd);`) },
  { [JS]: jsRoute(`const a = {};`, `const b = {};`, `b.cmd = req.query.d;`, `a.cmd = "ls";`, `exec(a.cmd);`) });
pair("return-value", "javascript", "taint returned vs dropped", "command-injection",
  { [JS]: jsHead + L(`function get(r) { return r.query.d; }`, `app.get("/a", (req, res) => { exec("ls " + get(req)); res.send("ok"); });`) },
  { [JS]: jsHead + L(`function get(r) { const v = r.query.d; return "fixed"; }`, `app.get("/a", (req, res) => { exec("ls " + get(req)); res.send("ok"); });`) });
pair("sanitizer", "javascript", "trim is not a sanitizer, parseInt is", "command-injection",
  { [JS]: jsRoute(`exec("ls " + req.query.d.trim());`) },
  { [JS]: jsRoute(`const n = parseInt(req.query.n, 10);`, `exec("sleep " + n);`) });
pair("framework", "javascript", "Koa ctx.query source", "command-injection",
  { [JS]: L(`const { exec } = require("child_process");`, `const Router = require("koa-router");`, `const router = new Router();`, `router.get("/a", async (ctx) => { exec("ls " + ctx.query.d); ctx.body = "ok"; });`) },
  { [JS]: L(`const { exec } = require("child_process");`, `const Router = require("koa-router");`, `const router = new Router();`, `router.get("/a", async (ctx) => { exec("ls"); ctx.body = ctx.query.d; });`) });

// ───────────────────────────── Python (Flask / Django) ─────────────────────────────
const PY = "app/handler.py";
const pyHead = L(`import os`, `import shlex`, `from flask import Flask, request`, `app = Flask(__name__)`, ``);
const pyRoute = (...body: string[]) => pyHead + L(`@app.route("/a")`, `def a():`, ...body.map(b => "    " + b), `    return "ok"`);
pair("field-sensitive", "python", "tainted vs clean attribute", "command-injection",
  { [PY]: pyHead + L(`class O:`, `    pass`, ``, `@app.route("/a")`, `def a():`, `    o = O()`, `    o.cmd = request.args["d"]`, `    o.safe = "ls"`, `    os.system(o.cmd)`, `    return "ok"`) },
  { [PY]: pyHead + L(`class O:`, `    pass`, ``, `@app.route("/a")`, `def a():`, `    o = O()`, `    o.cmd = request.args["d"]`, `    o.safe = "ls"`, `    os.system(o.safe)`, `    return "ok"`) });
pair("field-sensitive", "python", "tainted vs clean dict key", "command-injection",
  { [PY]: pyRoute(`d = {}`, `d["cmd"] = request.args["d"]`, `d["safe"] = "ls"`, `os.system(d["cmd"])`) },
  { [PY]: pyRoute(`d = {}`, `d["cmd"] = request.args["d"]`, `d["safe"] = "ls"`, `os.system(d["safe"])`) });
pair("context-sensitive", "python", "same helper, tainted vs clean call", "command-injection",
  { [PY]: pyHead + L(`def ident(x):`, `    return x`, ``, `@app.route("/a")`, `def a():`, `    a1 = ident("ls")`, `    b1 = ident(request.args["d"])`, `    os.system(b1)`, `    return a1`) },
  { [PY]: pyHead + L(`def ident(x):`, `    return x`, ``, `@app.route("/a")`, `def a():`, `    a1 = ident("ls")`, `    b1 = ident(request.args["d"])`, `    os.system(a1)`, `    return b1`) });
pair("path-sensitive", "python", "overwritten on every branch", "command-injection",
  { [PY]: pyRoute(`c = request.args["d"]`, `if request.args.get("f"):`, `    c = "ls"`, `os.system(c)`) },
  { [PY]: pyRoute(`c = request.args["d"]`, `if request.args.get("f"):`, `    c = "ls"`, `else:`, `    c = "pwd"`, `os.system(c)`) });
pair("interprocedural", "python", "two helper hops", "command-injection",
  { [PY]: pyHead + L(`def l2(x):`, `    return "ls " + x`, ``, `def l1(x):`, `    return l2(x)`, ``, `@app.route("/a")`, `def a():`, `    os.system(l1(request.args["d"]))`, `    return "ok"`) },
  { [PY]: pyHead + L(`def l2(x):`, `    return "ls"`, ``, `def l1(x):`, `    return l2(x)`, ``, `@app.route("/a")`, `def a():`, `    os.system(l1(request.args["d"]))`, `    return "ok"`) });
pair("cross-file", "python", "helper in another module", "command-injection",
  { "app/util.py": L(`def build(x):`, `    return "ls " + x`), [PY]: pyHead + L(`from util import build`, ``, `@app.route("/a")`, `def a():`, `    os.system(build(request.args["d"]))`, `    return "ok"`) },
  { "app/util.py": L(`def build(x):`, `    return "ls"`), [PY]: pyHead + L(`from util import build`, ``, `@app.route("/a")`, `def a():`, `    os.system(build(request.args["d"]))`, `    return "ok"`) });
pair("pointer-alias", "python", "dict alias", "command-injection",
  { [PY]: pyRoute(`a = {}`, `b = a`, `b["cmd"] = request.args["d"]`, `os.system(a["cmd"])`) },
  { [PY]: pyRoute(`a = {}`, `b = {}`, `b["cmd"] = request.args["d"]`, `a["cmd"] = "ls"`, `os.system(a["cmd"])`) });
pair("return-value", "python", "taint returned vs dropped", "command-injection",
  { [PY]: pyHead + L(`def get():`, `    return request.args["d"]`, ``, `@app.route("/a")`, `def a():`, `    os.system("ls " + get())`, `    return "ok"`) },
  { [PY]: pyHead + L(`def get():`, `    v = request.args["d"]`, `    return "fixed"`, ``, `@app.route("/a")`, `def a():`, `    os.system("ls " + get())`, `    return "ok"`) });
pair("sanitizer", "python", "strip is not a sanitizer, shlex.quote is", "command-injection",
  { [PY]: pyRoute(`os.system("ls " + request.args["d"].strip())`) },
  { [PY]: pyRoute(`os.system("ls " + shlex.quote(request.args["d"]))`) });
pair("framework", "python", "Django ORM raw vs filter", "sql-injection",
  { "app/views.py": L(`from django.http import HttpResponse`, `from app.models import User`, ``, `def view(request):`, `    rows = User.objects.raw("SELECT * FROM u WHERE id=" + request.GET["id"])`, `    return HttpResponse(str(list(rows)))`) },
  { "app/views.py": L(`from django.http import HttpResponse`, `from app.models import User`, ``, `def view(request):`, `    rows = User.objects.filter(id=request.GET["id"])`, `    return HttpResponse(str(list(rows)))`) });

// ───────────────────────────── C / C++ ─────────────────────────────
const CPP = "src/main.cpp";
const cHead = L(`#include <cstdlib>`, `#include <cstring>`, `#include <cstdio>`, `#include <string>`);
const cMain = (...body: string[]) => cHead + L(`int main(int argc, char** argv) {`, ...body.map(b => "  " + b), `  return 0;`, `}`);
pair("field-sensitive", "cpp", "struct member: tainted vs clean field", "command-injection",
  { [CPP]: cHead + L(`struct S { char* cmd; char* safe; };`, `int main(int argc, char** argv) {`, `  S s;`, `  s.cmd = argv[1];`, `  s.safe = (char*)"ls";`, `  system(s.cmd);`, `  return 0;`, `}`) },
  { [CPP]: cHead + L(`struct S { char* cmd; char* safe; };`, `int main(int argc, char** argv) {`, `  S s;`, `  s.cmd = argv[1];`, `  s.safe = (char*)"ls";`, `  system(s.safe);`, `  return 0;`, `}`) });
pair("field-sensitive", "cpp", "member through a pointer", "command-injection",
  { [CPP]: cHead + L(`struct S { char* cmd; char* safe; };`, `int main(int argc, char** argv) {`, `  S s;`, `  S* p = &s;`, `  p->cmd = argv[1];`, `  p->safe = (char*)"ls";`, `  system(p->cmd);`, `  return 0;`, `}`) },
  { [CPP]: cHead + L(`struct S { char* cmd; char* safe; };`, `int main(int argc, char** argv) {`, `  S s;`, `  S* p = &s;`, `  p->cmd = argv[1];`, `  p->safe = (char*)"ls";`, `  system(p->safe);`, `  return 0;`, `}`) });
pair("context-sensitive", "cpp", "same helper, tainted vs clean call", "command-injection",
  { [CPP]: cHead + L(`static const char* ident(const char* x) { return x; }`, `int main(int argc, char** argv) {`, `  const char* a = ident("ls");`, `  const char* b = ident(argv[1]);`, `  system(b);`, `  (void)a;`, `  return 0;`, `}`) },
  { [CPP]: cHead + L(`static const char* ident(const char* x) { return x; }`, `int main(int argc, char** argv) {`, `  const char* a = ident("ls");`, `  const char* b = ident(argv[1]);`, `  system(a);`, `  (void)b;`, `  return 0;`, `}`) });
pair("path-sensitive", "cpp", "overwritten on every branch", "command-injection",
  { [CPP]: cMain(`const char* c = argv[1];`, `if (argc > 2) { c = "ls"; }`, `system(c);`) },
  { [CPP]: cMain(`const char* c = argv[1];`, `if (argc > 2) { c = "ls"; } else { c = "pwd"; }`, `system(c);`) });
pair("interprocedural", "cpp", "two helper hops", "command-injection",
  { [CPP]: cHead + L(`static const char* l2(const char* x) { return x; }`, `static const char* l1(const char* x) { return l2(x); }`, `int main(int argc, char** argv) { system(l1(argv[1])); return 0; }`) },
  { [CPP]: cHead + L(`static const char* l2(const char* x) { (void)x; return "ls"; }`, `static const char* l1(const char* x) { return l2(x); }`, `int main(int argc, char** argv) { system(l1(argv[1])); return 0; }`) });
pair("cross-file", "cpp", "helper in another translation unit", "command-injection",
  { "src/util.cpp": L(`const char* pick(const char* x) { return x; }`), [CPP]: cHead + L(`const char* pick(const char* x);`, `int main(int argc, char** argv) { system(pick(argv[1])); return 0; }`) },
  { "src/util.cpp": L(`const char* pick(const char* x) { (void)x; return "ls"; }`), [CPP]: cHead + L(`const char* pick(const char* x);`, `int main(int argc, char** argv) { system(pick(argv[1])); return 0; }`) });
pair("pointer-alias", "cpp", "pointer copy", "command-injection",
  { [CPP]: cMain(`char* p = argv[1];`, `char* q = p;`, `system(q);`) },
  { [CPP]: cMain(`char* p = argv[1];`, `char* q = p;`, `q = (char*)"ls";`, `system(q);`, `(void)p;`) });
pair("pointer-to-pointer", "cpp", "taint through **pp", "command-injection",
  { [CPP]: cMain(`char* p = argv[1];`, `char** pp = &p;`, `system(*pp);`) },
  { [CPP]: cMain(`char* p = argv[1];`, `char* c = (char*)"ls";`, `char** pp = &c;`, `system(*pp);`, `(void)p;`) });
pair("return-value", "cpp", "taint returned vs dropped", "command-injection",
  { [CPP]: cHead + L(`static char* get(char** a) { return a[1]; }`, `int main(int argc, char** argv) { system(get(argv)); return 0; }`) },
  { [CPP]: cHead + L(`static char* get(char** a) { (void)a; return (char*)"ls"; }`, `int main(int argc, char** argv) { system(get(argv)); return 0; }`) });
pair("side-effect-summary", "cpp", "out-parameter written by callee", "command-injection",
  { [CPP]: cHead + L(`static void fill(char** out, char** a) { *out = a[1]; }`, `int main(int argc, char** argv) {`, `  char* c = nullptr;`, `  fill(&c, argv);`, `  system(c);`, `  return 0;`, `}`) },
  { [CPP]: cHead + L(`static void fill(char** out, char** a) { (void)a; *out = (char*)"ls"; }`, `int main(int argc, char** argv) {`, `  char* c = nullptr;`, `  fill(&c, argv);`, `  system(c);`, `  return 0;`, `}`) });
pair("heap-object", "cpp", "taint copied into a heap buffer", "command-injection",
  { [CPP]: cMain(`char* b = (char*)malloc(256);`, `if (!b) return 1;`, `strncpy(b, argv[1], 255);`, `b[255] = 0;`, `system(b);`, `free(b);`) },
  { [CPP]: cMain(`char* b = (char*)malloc(256);`, `if (!b) return 1;`, `strncpy(b, "ls", 255);`, `b[255] = 0;`, `system(b);`, `free(b);`, `(void)argv;`) });
pair("sanitizer", "cpp", "std::string copy is not a sanitizer, atoi + %d is", "command-injection",
  { [CPP]: cMain(`std::string s(argv[1]);`, `system(s.c_str());`) },
  { [CPP]: cMain(`int n = atoi(argv[1]);`, `char cmd[64];`, `snprintf(cmd, sizeof cmd, "sleep %d", n);`, `system(cmd);`) });

// ───────────────────────────── runner ─────────────────────────────
// Two tiers are scored separately. "any" = every detector in the product. "dataflow" = only findings the AST taint engines
// produce (confidence exactly 95, which every engine wrapper sets for a proven data-flow match). The weaker tier (a
// non-constant shell argument, confidence 85) can hide missed data flows (recall) and adds noise (precision) if the two
// are merged, so a capability counts as working only if the dataflow tier gets it right.
const isDataflow = (i: { sourceExpr?: string }) => typeof i.sourceExpr === "string" && i.sourceExpr.length > 0;

beforeAll(async () => { await Promise.all([warmPythonTaintEngine(), warmCppTaintEngine()]); }, 120000);

interface Tier { tp: number; fp: number; fn: number; tn: number }
interface Tally { any: Tier; dataflow: Tier; ms: number }
const tier = (): Tier => ({ tp: 0, fp: 0, fn: 0, tn: 0 });
const empty = (): Tally => ({ any: tier(), dataflow: tier(), ms: 0 });
const byCap = new Map<string, Tally>(), byLang = new Map<string, Tally>();
const outcomes: Array<{ key: string; vulnerable: boolean; any: boolean; dataflow: boolean }> = [];

const score = (t: Tier, vulnerable: boolean, found: boolean) => {
  if (vulnerable) { if (found) t.tp++; else t.fn++; } else if (found) t.fp++; else t.tn++;
};
const add = (m: Map<string, Tally>, k: string, c: Case, any: boolean, dataflow: boolean, ms: number) => {
  const t = m.get(k) ?? empty();
  score(t.any, c.vulnerable, any); score(t.dataflow, c.vulnerable, dataflow);
  t.ms += ms; m.set(k, t);
};

describe("capability matrix", () => {
  for (const c of cases) {
    const key = `${c.lang} | ${c.cap} | ${c.name} | ${c.vulnerable ? "vulnerable" : "safe"}`;
    it(key, () => {
      const t0 = Date.now();
      const res = runScan({
        repo: "benchmark/capability", pr_number: 1, commit_sha: "0000000", branch: "main",
        files: Object.entries(c.files).map(([p, content]) => ({ path: p, content })),
      });
      const ms = Date.now() - t0;
      const hits = res.files.flatMap(f => f.indicators.filter(i => i.id === c.id).map(i => ({ file: f.file_path, i })));
      const any = hits.length > 0;
      const dataflow = hits.some(h => isDataflow(h.i as { sourceExpr?: string }));
      // CAP_PROBE=<substring of the case key> prints what fired, with confidence, to tell the AST engine from a regex rule.
      if (process.env.CAP_PROBE && key.includes(process.env.CAP_PROBE)) {
        for (const h of hits) console.log(`PROBE ${key}\n  ${h.file}:${h.i.line} conf=${h.i.confidence} ${String(h.i.detail ?? h.i.label).slice(0, 160)}`);
      }
      add(byCap, c.cap, c, any, dataflow, ms); add(byLang, c.lang, c, any, dataflow, ms);
      outcomes.push({ key, vulnerable: c.vulnerable, any, dataflow });
    }, 60000);
  }

  it("prints the matrix and writes the reproducible report", () => {
    const ratio = (a: number, b: number) => (b === 0 ? null : a / b);
    const f = (v: number | null) => (v === null ? "  n/a" : v.toFixed(2).padStart(5));
    const cell = (t: Tier) => `${String(t.tp).padStart(2)} ${String(t.fp).padStart(2)} ${String(t.fn).padStart(2)} ${String(t.tn).padStart(2)}  ${f(ratio(t.tp, t.tp + t.fp))} ${f(ratio(t.tp, t.tp + t.fn))}`;
    const table = (title: string, m: Map<string, Tally>) => {
      const rows = [`${title.padEnd(21)} | ANY DETECTOR              | DATA-FLOW ONLY (AST engine)`, `${"".padEnd(21)} | TP FP FN TN  prec  rec   | TP FP FN TN  prec  rec    ms`];
      for (const k of [...m.keys()].sort()) { const t = m.get(k)!; rows.push(`${k.padEnd(21)} | ${cell(t.any)}  | ${cell(t.dataflow)} ${String(t.ms).padStart(5)}`); }
      return rows.join("\n");
    };
    const wrongIn = (tierName: "any" | "dataflow") => outcomes.filter(o => o[tierName] === o.vulnerable ? false : true).map(o => `${o.vulnerable ? "FN" : "FP"}  ${o.key.replace(/ \| (vulnerable|safe)$/, "")}`).sort();
    const wrongAny = wrongIn("any"), wrongFlow = wrongIn("dataflow");
    console.log("\n" + table("capability", byCap) + "\n\n" + table("language", byLang)
      + `\n\nwrong, any detector (${wrongAny.length}):\n` + wrongAny.join("\n") + `\n\nwrong, data-flow only (${wrongFlow.length}):\n` + wrongFlow.join("\n"));

    const strip = (m: Map<string, Tally>) => Object.fromEntries([...m.keys()].sort().map(k => { const t = m.get(k)!; return [k, { any: t.any, dataflow: t.dataflow }]; }));
    const report = {
      note: "Hand-written capability corpus, deterministic (no timings). 'dataflow' counts only AST data-flow findings (those carrying a sourceExpr); 'any' adds the weaker rule-based detectors. A wrong outcome is a real gap or a labelling error to review.",
      totals: { cases: outcomes.length, wrongAny: wrongAny.length, wrongDataflow: wrongFlow.length },
      byCapability: strip(byCap), byLanguage: strip(byLang),
      wrongAnyDetector: wrongAny, wrongDataflowOnly: wrongFlow,
    };
    fs.writeFileSync(path.join(__dirname, "capabilityMatrix.report.json"), JSON.stringify(report, null, 2) + "\n");
    expect(outcomes.length).toBe(cases.length);
  });
});

// ───────────────────────────── what is known to be wrong today ─────────────────────────────
// The matrix is a regression guard AND a gap list. A case outside these lists that goes wrong is a regression and fails;
// a case inside them that starts passing is an improvement and also fails, so the entry is removed here on purpose.
// Gaps are listed, not hidden: each has a note on what is missing.
const KNOWN_WRONG_DATAFLOW: string[] = [];
// command-injection is now ENGINE_OWNED_RULES (scanner.ts): regex findings on engine-analysed files are dropped,
// removing all 12 FPs the weaker "non-constant shell argument" / "named tainted variable" rules produced.
const KNOWN_WRONG_ANY: string[] = [];

describe("capability matrix: no silent change", () => {
  const wrong = (tierName: "any" | "dataflow") => outcomes.filter(o => (o[tierName] !== o.vulnerable)).map(o => `${o.vulnerable ? "FN" : "FP"}  ${o.key.replace(/ \| (vulnerable|safe)$/, "")}`).sort();
  it("the AST data-flow tier is wrong on exactly the known cases", () => { expect(wrong("dataflow")).toEqual([...KNOWN_WRONG_DATAFLOW].sort()); });
  it("the any-detector tier is wrong on exactly the known cases", () => { expect(wrong("any")).toEqual([...KNOWN_WRONG_ANY].sort()); });
});
