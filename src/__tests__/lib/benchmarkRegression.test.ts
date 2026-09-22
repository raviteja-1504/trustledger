/**
 * P0 "benchmark + regression framework": runs all six languages' hard-benchmark fixtures
 * (src/__tests__/benchmarks/fixtures/) through the real production scanner and asserts the result
 * hasn't gotten WORSE than the committed baseline (src/__tests__/benchmarks/baseline.json) -- the
 * single place this whole multi-phase recall effort can be proven not to have regressed, instead of
 * re-deriving "did we actually improve things" from scratch each time via the scratchpad.
 *
 * On a genuine improvement (a case that now fires, or an id a case now also detects), this test
 * passes as-is -- the baseline only needs bumping (re-run the failing/changed assertions and copy
 * the new astOnlyByCase over) when a change is INTENTIONAL. On a genuine regression, it fails with
 * the exact case(s) and id(s) that stopped firing, not just a changed aggregate count.
 */
import { runBenchmark, summarize, type BenchmarkSummary } from "../benchmarks/runBenchmark";
import baseline from "../benchmarks/baseline.json";
import { warmGoTaintEngine } from "@/lib/astTaintGo";
import { warmCSharpTaintEngine } from "@/lib/astTaintCSharp";
import { warmPhpTaintEngine } from "@/lib/astTaintPHP";
import { warmPythonTaintEngine } from "@/lib/astTaintPython";

jest.setTimeout(120000);
beforeAll(async () => {
  await Promise.all([warmGoTaintEngine(), warmCSharpTaintEngine(), warmPhpTaintEngine(), warmPythonTaintEngine()]);
});

type Baseline = Record<string, BenchmarkSummary>;
const BASELINE = baseline as unknown as Baseline;

const SPECS: Array<{ language: string; fixture: string; syntheticPath: string; astConfidenceValues?: number[] }> = [
  { language: "typescript", fixture: "hard.ts.fixture", syntheticPath: "bench.ts" },
  { language: "python", fixture: "hard.py.fixture", syntheticPath: "bench.py" },
  { language: "java", fixture: "HardJavaBenchmark.java.fixture", syntheticPath: "HardJavaBenchmark.java", astConfidenceValues: [95, 70] },
  { language: "go", fixture: "hard.go.fixture", syntheticPath: "bench.go" },
  { language: "csharp", fixture: "HardCSharpBenchmark.cs.fixture", syntheticPath: "HardCSharpBenchmark.cs" },
  { language: "php", fixture: "hard.php.fixture", syntheticPath: "bench.php" },
];

describe("benchmark regression (recall must not drop below the committed baseline)", () => {
  for (const spec of SPECS) {
    it(`${spec.language}: no case that used to fire has silently stopped`, () => {
      const base = BASELINE[spec.language];
      expect(base).toBeDefined();
      const summary = summarize(runBenchmark(spec.language, spec.fixture, spec.syntheticPath, spec.astConfidenceValues));

      // Per-case diff first -- the actionable signal. A case losing an id it used to AST-detect is a
      // real regression even if some OTHER case improved enough to keep the aggregate counts flat.
      const regressed: string[] = [];
      for (const [label, ids] of Object.entries(base.astOnlyByCase)) {
        const nowIds = new Set(summary.astOnlyByCase[label] ?? []);
        const missing = ids.filter(id => !nowIds.has(id));
        if (missing.length > 0) regressed.push(`case ${label}: lost ${missing.join(", ")} (had [${ids.join(", ")}], now [${[...nowIds].join(", ") || "none"}])`);
      }
      expect(regressed).toEqual([]);

      // Aggregate counts as a second, coarser gate (catches anything the per-case diff wouldn't,
      // e.g. totalCases itself shrinking because the fixture changed).
      expect(summary.totalCases).toBeGreaterThanOrEqual(base.totalCases);
      expect(summary.casesWithFinding).toBeGreaterThanOrEqual(base.casesWithFinding);
      expect(summary.astOnlyFindingCount).toBeGreaterThanOrEqual(base.astOnlyFindingCount);
    });
  }
});
