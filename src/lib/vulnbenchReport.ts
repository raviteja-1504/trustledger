/**
 * TrustLedger on Snyk's VulnBench 2.0 (src/data/vulnbench.json, also served at /benchmarks/vulnbench.json): every one of the 108
 * reference vulnerabilities with the finding that matched it, or the fact that nothing did. Produced by
 * benchmarks/scorers/score_vulnbench.py from a run of the production scanner; nothing is typed in by hand except the published
 * comparison rows, which are copied from vulnbench.com with their source.
 */
import data from "@/data/vulnbench.json";

export interface VulnBenchRow {
  id: string; app: string; type: string; severity: string | null;
  /** Matched under the benchmark's published endpoint rule (the headline). */
  headline: boolean;
  /** Matched by a finding of the right type within 2 lines of ANY reference location (a sensitivity check only). */
  lenient: boolean;
  reference: { file: string; line: number; role: string | null }[];
  description: string;
  foundBy: { rule: string; file: string; line: number; detail: string } | null;
}
export interface VulnBenchReport {
  benchmark: { name: string; maintainer: string; version: string; url: string; repo: string; repoCommit: string };
  measuredAt: string; engineCommit: string; apps: number; languages: string[]; reference: number;
  /** `recall` is matched / 108; `macroRecall` averages the 20 applications equally, which is the metric the benchmark ranks by. */
  headline: { matched: number; recall: number; macroRecall: number };
  lenient: { matched: number; recall: number; macroRecall: number };
  perApp: { app: string; total: number; headline: number; lenient: number }[];
  reportedFindings: number; precisionLowerBound: number;
  byType: { type: string; total: number; headline: number; lenient: number }[];
  published: { source: string; copiedOn: string; note: string; rows: { name: string; matched: number; recall: number; precisionLowerBound: number }[] };
  rows: VulnBenchRow[];
}
export const VULNBENCH = data as VulnBenchReport;
