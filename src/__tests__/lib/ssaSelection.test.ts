import { runScan } from "@/lib/scanner";
import { selectSsaFunctions, SSA_MAX_FUNCTIONS } from "@/lib/ssaSelection";
import type { FunctionInfo } from "@/lib/ast";

// SSA taint analysis is bounded to a subset of a file's functions. It used to be "the 3 most complex", which
// has nothing to do with where the findings are: a short handler holding a real vulnerability was routinely
// skipped in favour of complex utility code. Selection is now ranked by security exposure, then complexity.

const fn = (name: string, line: number, endLine: number, complexity = 1): FunctionInfo => ({
  name, line, endLine, paramCount: 1, isAsync: false, isExported: false, isArrow: false, isMethod: false, complexity, nestDepth: 1,
});
const names = (fs: FunctionInfo[]) => fs.map(f => f.name);

describe("selectSsaFunctions (unit)", () => {
  it("a simple function holding a finding outranks more complex functions without one", () => {
    const fns = [fn("parser", 1, 40, 30), fn("formatter", 42, 80, 25), fn("machine", 82, 120, 20), fn("handler", 122, 130, 1)];
    const chosen = selectSsaFunctions(fns, [{ line: 125, severity: "high" }], { maxFunctions: 1 });
    expect(names(chosen)).toEqual(["handler"]);
  });

  it("falls back to complexity (then source order) when nothing has a finding", () => {
    const fns = [fn("a", 1, 10, 5), fn("b", 12, 20, 9), fn("c", 22, 30, 9)];
    expect(names(selectSsaFunctions(fns, [], { maxFunctions: 2 }))).toEqual(["b", "c"]);
  });

  it("weights by severity: one critical outranks several lows", () => {
    const fns = [fn("lows", 1, 20), fn("crit", 22, 40)];
    const findings = [
      { line: 3, severity: "low" as const }, { line: 5, severity: "low" as const }, { line: 7, severity: "low" as const },
      { line: 25, severity: "critical" as const },
    ];
    expect(names(selectSsaFunctions(fns, findings, { maxFunctions: 1 }))).toEqual(["crit"]);
  });

  it("attributes a finding to the INNERMOST enclosing function only", () => {
    const outer = fn("outer", 1, 100, 10);
    const inner = fn("inner", 40, 50, 1);
    const other = fn("other", 102, 120, 10);
    const chosen = selectSsaFunctions([outer, inner, other], [{ line: 45, severity: "critical" }], { maxFunctions: 1 });
    expect(names(chosen)).toEqual(["inner"]);                 // not `outer`, which merely contains it
  });

  it("ignores findings with no line and 'info' findings (they select nothing)", () => {
    const fns = [fn("a", 1, 10, 1), fn("b", 12, 20, 9)];
    expect(names(selectSsaFunctions(fns, [{ severity: "critical" }, { line: 3, severity: "info" }], { maxFunctions: 1 }))).toEqual(["b"]);
  });

  it("is bounded by a LINE budget, not just a count: a huge function is skipped and a smaller one still fits", () => {
    const fns = [fn("huge", 1, 700, 50), fn("small", 702, 720, 1)];
    const chosen = selectSsaFunctions(fns, [{ line: 10, severity: "critical" }], { lineBudget: 100, maxFunctions: 5 });
    expect(names(chosen)).toEqual(["small"]);
  });

  it("never analyzes a function above the per-function line ceiling", () => {
    const fns = [fn("monster", 1, 5000, 99), fn("ok", 5002, 5010, 1)];
    expect(names(selectSsaFunctions(fns, [{ line: 10, severity: "critical" }]))).toEqual(["ok"]);
  });

  it("caps the number of functions", () => {
    const fns = Array.from({ length: 30 }, (_, i) => fn(`f${i}`, i * 10 + 1, i * 10 + 8, 3));
    expect(selectSsaFunctions(fns, [])).toHaveLength(SSA_MAX_FUNCTIONS);
  });

  it("is deterministic regardless of the order functions are supplied in", () => {
    const fns = [fn("a", 1, 10, 4), fn("b", 12, 20, 4), fn("c", 22, 30, 4), fn("d", 32, 40, 4)];
    const findings = [{ line: 35, severity: "medium" as const }];
    const forward = names(selectSsaFunctions(fns, findings, { maxFunctions: 3 }));
    const reversed = names(selectSsaFunctions([...fns].reverse(), findings, { maxFunctions: 3 }));
    expect(reversed).toEqual(forward);
  });

  it("handles no functions and no findings", () => {
    expect(selectSsaFunctions([], [])).toEqual([]);
  });
});

// ── through the real scanner ────────────────────────────────────────────────────────────────────────
// Four complex utility functions come FIRST and a tiny vulnerable one last. The old top-3-by-complexity choice
// analyzed three of the complex ones and never the handler, so `ssa_taint_paths` had nothing for it.
const COMPLEX = (name: string) => `function ${name}(input) {
  let out = 0;
  for (let i = 0; i < input.length; i++) {
    if (input[i] > 10) { out += 1; } else if (input[i] > 5) { out += 2; } else if (input[i] > 2) { out += 3; } else { out += 4; }
    for (let j = 0; j < i; j++) {
      if (input[j] === input[i] && j % 2 === 0 || input[j] < 0) { out -= 1; }
      while (out > 100) { out -= 7; if (out % 3 === 0) { break; } }
    }
  }
  return out;
}`;
// (ssa.ts's sink model is line-regex based: it recognizes a template literal with `${...}` on the sink line, so
// the fixture uses that shape. Its recall is a separate matter from WHICH functions get analyzed, which is what
// these tests pin.)
const VULNERABLE = `function lookup(req) {
  const id = req.query.id;
  return db.query(\`SELECT * FROM users WHERE id = \${id}\`);
}`;

describe("selection through the real scanner", () => {
  const src = [COMPLEX("parseA"), COMPLEX("parseB"), COMPLEX("parseC"), COMPLEX("parseD"), VULNERABLE].join("\n\n");
  const result = runScan({ repo: "t", pr_number: 1, commit_sha: "a", branch: "main", files: [{ path: "src/big.ts", content: src }] });
  const file = result.files[0];
  const vulnLine = src.split("\n").findIndex(l => l.includes("return db.query(")) + 1;

  it("the file has a real finding in the short function (precondition for the assertions below)", () => {
    expect(file.indicators.some(i => i.id === "sql-injection" && i.line !== undefined && Math.abs(i.line - vulnLine) <= 2)).toBe(true);
  });

  it("the vulnerable function's data-flow path is present -- it used to be crowded out by complex utility code", () => {
    expect(file.ssa_taint_paths.some(p => Math.abs(p.sinkLine - vulnLine) <= 2)).toBe(true);
  });
});
