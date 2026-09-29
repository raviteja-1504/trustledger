/**
 * Cross-file benchmark regression: every multi-file case in benchmarks/crossFile/cases.ts through the real
 * scanner, compared case by case with the committed scorecard (benchmarks/crossFile/crossFileBaseline.json).
 * A flow that used to be found and no longer is, a look-alike that starts being reported, or a flow now
 * reported more than once fails with the case named. Improvements pass; after an intentional change,
 * regenerate the baseline with UPDATE_CROSS_FILE_BASELINE=1.
 */
import fs from "fs";
import path from "path";
import { runCrossFileBenchmark, type CaseScore, type LanguageScore } from "../benchmarks/crossFile/runCrossFileBenchmark";
import { warmGoTaintEngine } from "@/lib/astTaintGo";
import { warmCSharpTaintEngine } from "@/lib/astTaintCSharp";
import { warmPhpTaintEngine } from "@/lib/astTaintPHP";
import { warmPythonTaintEngine } from "@/lib/astTaintPython";

jest.setTimeout(120000);

const BASELINE_PATH = path.join(__dirname, "../benchmarks/crossFile/crossFileBaseline.json");
interface Baseline { byLanguage: Record<string, LanguageScore>; cases: Record<string, { outcome: CaseScore["outcome"]; duplicates: number }> }
const key = (s: { language: string; name: string }) => `${s.language}: ${s.name}`;

describe("cross-file benchmark (no regression against the committed scorecard)", () => {
  let result: ReturnType<typeof runCrossFileBenchmark>;
  let baseline: Baseline;
  // The scan must run AFTER the tree-sitter engines are warm: run at collection time, every non-TS case
  // silently scores as missed.
  beforeAll(async () => {
    await Promise.all([warmGoTaintEngine(), warmCSharpTaintEngine(), warmPhpTaintEngine(), warmPythonTaintEngine()]);
    result = runCrossFileBenchmark();
    if (process.env.UPDATE_CROSS_FILE_BASELINE) {
      const cases: Baseline["cases"] = {};
      for (const s of result.cases) cases[key(s)] = { outcome: s.outcome, duplicates: s.duplicates };
      fs.writeFileSync(BASELINE_PATH, JSON.stringify({ byLanguage: result.byLanguage, cases }, null, 2) + "\n");
    }
    baseline = JSON.parse(fs.readFileSync(BASELINE_PATH, "utf-8")) as Baseline;
  });

  it("the engines were warm: every language found at least one flow", () => {
    for (const [lang, s] of Object.entries(result.byLanguage)) expect({ lang, found: s.tp > 0 }).toEqual({ lang, found: true });
  });

  it("every baselined case still exists", () => {
    const now = new Set(result.cases.map(key));
    expect(Object.keys(baseline.cases).filter(k => !now.has(k))).toEqual([]);
  });

  it("no found flow is lost, no negative starts firing, no flow is reported twice", () => {
    const regressions: string[] = [];
    for (const s of result.cases) {
      const was = baseline.cases[key(s)];
      if (!was) continue;
      if (was.outcome === "tp" && s.outcome === "fn") regressions.push(`${key(s)}: no longer found`);
      if (was.outcome === "tn" && s.outcome === "fp") regressions.push(`${key(s)}: now reported (false positive)`);
      if (s.duplicates > was.duplicates) regressions.push(`${key(s)}: reported ${s.duplicates + 1} times`);
    }
    expect(regressions).toEqual([]);
  });

  it("per-language precision and recall do not drop", () => {
    for (const [lang, was] of Object.entries(baseline.byLanguage)) {
      const now = result.byLanguage[lang];
      expect({ lang, precision: now.precision >= was.precision, recall: now.recall >= was.recall })
        .toEqual({ lang, precision: true, recall: true });
    }
  });
});
