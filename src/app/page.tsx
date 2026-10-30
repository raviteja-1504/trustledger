/**
 * The landing page. Server-rendered wrapper: the figures it shows -- benchmark results, rule and CWE counts -- are
 * computed here from the published report and the engines' registries (lib/benchmarkReport.ts,
 * lib/publicCoverage.ts), so the interactive client component never hard-codes a number.
 */
import LandingClient, { type LandingEvidence } from "./LandingClient";
import { BENCHMARK_REPORT as R, rates, categoryAverage } from "@/lib/benchmarkReport";
import { dataFlowRules, dataFlowCwes } from "@/lib/publicCoverage";

export default function LandingPage() {
  const pooled = rates(R.corpora.flatMap(c => c.categories));
  const evidence: LandingEvidence = {
    engineCommit: R.engineCommit,
    measuredAt: R.generatedAt.slice(0, 10),
    pooledTpr: pooled.tpr,
    pooledFpr: pooled.fpr,
    labelledCases: pooled.cases,
    corpora: R.corpora.map(c => ({ name: c.name, languages: c.languages, score: categoryAverage(c.categories) })),
    juiceDetected: R.juice.challenges.filter(c => c.detected).length,
    juiceTotal: R.juice.challenges.length,
    ruleCount: dataFlowRules().length,
    cweCount: dataFlowCwes().length,
  };
  return <LandingClient evidence={evidence} />;
}
