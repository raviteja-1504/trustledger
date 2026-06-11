import { runAIAttributionBenchmark, formatBenchmarkReport } from "@/lib/aiAttributionBenchmark";

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
