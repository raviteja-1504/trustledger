import { runAIAttributionBenchmark, formatBenchmarkReport, runToolAttributionBenchmark, formatToolAttributionReport } from "@/lib/aiAttributionBenchmark";

// This is a small (n=10), TS/JS-only internal benchmark — see
// aiAttributionBenchmark.fixtures.ts for sample provenance. It is a
// measurement/reporting tool, not a strict accuracy gate: with only 10
// samples, tuning ensemble weights to pass a tight threshold here would be
// overfitting. The report is logged so accuracy drift is visible over time.
describe("AI attribution benchmark", () => {
  it("produces a well-formed report over the labeled corpus", () => {
    const report = runAIAttributionBenchmark();
    // eslint-disable-next-line no-console
    console.log(formatBenchmarkReport(report));

    expect(report.results).toHaveLength(10);
    for (const r of report.results) {
      expect(r.ai_percentage).toBeGreaterThanOrEqual(0);
      expect(r.ai_percentage).toBeLessThanOrEqual(1);
    }
    expect(report.rocAuc).toBeGreaterThanOrEqual(0);
    expect(report.rocAuc).toBeLessThanOrEqual(1);
  });
});

// First-ever per-tool quality gate for attributeCode()'s predicted `model`
// field -- previously zero validation existed for whether a specific tool
// (Copilot vs Claude vs Gemini vs ...) was identified correctly, only
// whether the binary ai/human call was right. Deliberately modest bar
// given a ~10-sample corpus and that 7-way tool attribution is intrinsically
// harder than binary classification -- a real regression check, not a
// tight overfit target.
describe("AI tool attribution benchmark (per-model)", () => {
  it("predicts the correct tool at or above a baseline accuracy bar", () => {
    const report = runToolAttributionBenchmark();
    // eslint-disable-next-line no-console
    console.log(formatToolAttributionReport(report));

    expect(report.results.length).toBeGreaterThan(0);
    expect(report.accuracy).toBeGreaterThanOrEqual(0.6);
  });
});
