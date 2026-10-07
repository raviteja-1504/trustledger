/**
 * Repository content is untrusted. A hostile file must not be able to crash a scan or run it past the scan
 * worker's time budget:
 *   - deeply nested code overflowed the AST engines' recursive visitors (Python, PHP) and failed the WHOLE scan;
 *   - one long run of spaces / word characters made regex rules quadratic (400 KB of spaces: ~6 minutes);
 *   - `var a = var a = ...` on one long line made the inline-source rule's unbounded `.*` quadratic.
 */
import { runScan } from "@/lib/scanner";
import { ensureTaintEngines } from "@/lib/engineWarmup";
import { tameLongRuns, MAX_RUN } from "@/lib/scanInputLimits";
import { treeTooDeep, MAX_AST_DEPTH } from "@/lib/treeSitterRuntime";
import { parsePythonSourceSync } from "@/lib/astTaintPython";
import { parsePhpSourceSync } from "@/lib/astTaintPHP";

const KB = 1024;
const scan = (path: string, content: string) =>
  runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files: [{ path, content }] });
const ids = (path: string, content: string) => (scan(path, content).files[0]?.indicators ?? []).map(i => `${i.id}@${i.line}`);
const nest = (open: string, close: string, n: number, mid = "x") => open.repeat(n) + mid + close.repeat(n);
const timed = <T>(fn: () => T): [T, number] => { const t = Date.now(); const r = fn(); return [r, Date.now() - t]; };

beforeAll(async () => { await ensureTaintEngines(); }, 120000);

describe("tameLongRuns", () => {
  it("cuts runs of word chars or spaces/tabs longer than MAX_RUN, keeps everything else exactly", () => {
    expect(tameLongRuns("a".repeat(MAX_RUN))).toBe("a".repeat(MAX_RUN));
    expect(tameLongRuns("a".repeat(MAX_RUN + 1))).toBe("a".repeat(MAX_RUN));
    expect(tameLongRuns(`x="${" ".repeat(5000)}";\ny = 1`)).toBe(`x="${" ".repeat(MAX_RUN)}";\ny = 1`);
    expect(tameLongRuns("\t".repeat(300) + "z")).toBe("\t".repeat(MAX_RUN) + "z");
    // classes don't merge: a long word run next to a long space run is cut separately
    expect(tameLongRuns("b".repeat(400) + " ".repeat(400) + "c")).toBe("b".repeat(MAX_RUN) + " ".repeat(MAX_RUN) + "c");
    // newlines are never runs: line count is preserved
    const blank = "\n".repeat(5000);
    expect(tameLongRuns(blank)).toBe(blank);
    const code = "const a_1 = req.query.id;\n  if (a_1) { run(a_1); }\n";
    expect(tameLongRuns(code)).toBe(code);
    expect(tameLongRuns("")).toBe("");
  });

  it("is linear: 2 MB in well under a second", () => {
    const [, ms] = timed(() => tameLongRuns(("ab ".repeat(100) + "x".repeat(3000) + " ".repeat(3000)).repeat(300)));
    expect(ms).toBeLessThan(1000);
  });
});

describe("deeply nested code", () => {
  it("treeTooDeep measures the real tree depth", () => {
    const shallow = parsePythonSourceSync("x = " + nest("f(", ")", 50) + "\n", "s.py")!;
    expect(treeTooDeep(shallow, MAX_AST_DEPTH)).toBe(false);
    expect(treeTooDeep(shallow, 50)).toBe(true);
    expect(treeTooDeep(parsePythonSourceSync("x = 1\n", "t.py")!, 10)).toBe(false);
  });

  it("a too-deep file gets no AST tree (so no engine walks it), a normal one still does", () => {
    expect(parsePythonSourceSync("x = " + nest("f(", ")", 5000) + "\n", "d.py")).toBeNull();
    expect(parsePhpSourceSync("<?php $x = " + nest("(", ")", 20000) + ";", "d.php")).toBeNull();
    expect(parsePythonSourceSync("x = f(g(1))\n", "ok.py")).not.toBeNull();
  });

  const DEEP: [string, string][] = [
    ["d.py", "import os\nx = " + nest("f(", ")", 20000) + "\n"],
    ["d.php", "<?php $x = " + nest("(", ")", 20000) + ";"],
    ["d.js", "const v = " + nest("(", ")", 20000) + ";"],
    ["d.ts", "const v = " + nest("[", "]", 20000) + ";"],
    ["d.go", "package main\nfunc f() { x := " + nest("(", ")", 20000) + " }\n"],
    ["d.java", "class A { void f() { int x = " + nest("(", ")", 20000) + "; } }"],
    ["d.cs", "class A { void F() { var x = " + nest("(", ")", 20000) + "; } }"],
    ["d.rb", "x = " + nest("(", ")", 20000) + "\n"],
    ["d.kt", "fun f() { val x = " + nest("(", ")", 20000) + " }"],
    ["d.rs", "fn f() { let x = " + nest("(", ")", 20000) + "; }"],
    ["chain.py", "x = " + Array.from({ length: 20000 }, () => "a").join(" + ") + "\n"],
    ["chain.rb", "x = " + Array.from({ length: 20000 }, () => "a").join(" + ") + "\n"],
    ["blocks.rb", "if a\n".repeat(20000) + "x\n" + "end\n".repeat(20000)],
  ];
  it.each(DEEP)("%s: the scan completes instead of crashing", (path, content) => {
    expect(() => scan(path, content)).not.toThrow();
  });

  it("the regex rules still scan a file that is too deep for the AST engines", () => {
    const py = "import os\nos.system(request.args.get('c'))\nx = " + nest("f(", ")", 20000) + "\n";
    expect(ids("d.py", py)).toContain("eval-exec@2");
  });
});

describe("regex time on long runs and long lines", () => {
  // Each took minutes before (and grew quadratically); now each is seconds.
  const CASES: [string, string][] = [
    ["spaces.js", "const x = \"" + " ".repeat(300 * KB) + "\";"],
    ["a.js", "a".repeat(300 * KB)],
    ["var.js", "var a = ".repeat(Math.floor(200 * KB / 8))],
    ["stmts.js", "const x = 1; ".repeat(Math.floor(200 * KB / 13)) + "const y = req.query.a;"],
    ["a.py", "a".repeat(300 * KB)],
    ["ldap.ts", "filter = `" + "(a=".repeat(Math.floor(200 * KB / 3))],
    ["arrow.js", "a = (".repeat(Math.floor(200 * KB / 5))],
    ["Dockerfile", "FROM x\n" + "RUN a \\\n".repeat(Math.floor(450 * KB / 8))],
  ];
  it.each(CASES)("%s is scanned in seconds", (path, content) => {
    const [, ms] = timed(() => scan(path, content));
    expect(ms).toBeLessThan(15000);
  }, 120000);

  it("a finding after a long run keeps its exact line number", () => {
    const js = "const a = req.query.a;\nconst pad = \"" + " ".repeat(50 * KB) + "\";\neval(a);\n";
    expect(ids("p.js", js)).toContain("eval-exec@3");
  });
});
