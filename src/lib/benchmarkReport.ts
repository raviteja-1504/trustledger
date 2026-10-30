/**
 * The published benchmark report (src/data/benchmarks.json, also served at /benchmarks/report.json): one measured
 * run of every public corpus against one engine commit, produced by benchmarks/build-report.mjs from the scorers'
 * own output. Nothing here is typed in by hand except the curated false-positive / false-negative examples and the
 * known limitations, which cite the corpus test case they come from.
 *
 * Scores follow the OWASP Benchmark convention: TPR (share of real vulnerabilities flagged) minus FPR (share of safe
 * cases flagged), in percentage points -- 0 is a coin flip, 100 is perfect.
 */
import report from "@/data/benchmarks.json";

export interface CategoryResult { name: string; tp: number; fn: number; fp: number; tn: number }
export interface CorpusResult {
  id: string;
  name: string;
  url: string;
  version: string;
  languages: string[];
  /** What a "case" is in this corpus and how a finding is matched to it. */
  scoring: string;
  runAt: string;
  files: number | null;
  wallMs: number | null;
  categories: CategoryResult[];
}
export interface JuiceResult {
  name: string; url: string; version: string; runAt: string; files: number | null; wallMs: number | null;
  challenges: { id: string; detected: boolean; via: string | null; location: string }[];
}
export interface AiAttributionResult {
  samples: number; threshold: number; precision: number; recall: number; f1: number; accuracy: number; rocAuc: number;
  toolSamples: number; toolAccuracy: number;
}
export interface Example { corpus: string; caseId: string; rule: string; title: string; explanation: string }
export interface HistoryPoint { commit: string; date: string; corpus: string; score: number; note?: string }
export interface BenchmarkReport {
  generatedAt: string;
  engineCommit: string;
  environment: string;
  corpora: CorpusResult[];
  juice: JuiceResult;
  aiAttribution: AiAttributionResult;
  falsePositives: Example[];
  falseNegatives: Example[];
  limitations: string[];
  comparison: { status: "not-run" | "published"; note: string };
  history: HistoryPoint[];
}

export const BENCHMARK_REPORT = report as BenchmarkReport;

export interface Rates { tp: number; fn: number; fp: number; tn: number; tpr: number; fpr: number; score: number; cases: number }

export function rates(cats: readonly CategoryResult[]): Rates {
  const tp = cats.reduce((s, c) => s + c.tp, 0), fn = cats.reduce((s, c) => s + c.fn, 0);
  const fp = cats.reduce((s, c) => s + c.fp, 0), tn = cats.reduce((s, c) => s + c.tn, 0);
  const tpr = tp + fn ? tp / (tp + fn) : 0, fpr = fp + tn ? fp / (fp + tn) : 0;
  return { tp, fn, fp, tn, tpr, fpr, score: Math.round((tpr - fpr) * 1000) / 10, cases: tp + fn + fp + tn };
}

/** The OWASP-style category average: each category's (TPR - FPR), averaged with equal weight. */
export function categoryAverage(cats: readonly CategoryResult[]): number {
  const scores = cats.map(c => rates([c])).filter(r => r.cases > 0).map(r => r.tpr - r.fpr);
  return scores.length ? Math.round((scores.reduce((s, x) => s + x, 0) / scores.length) * 1000) / 10 : 0;
}

/** Files per second over the corpus run, when its timing was captured. */
export function throughput(c: { files: number | null; wallMs: number | null }): number | null {
  return c.files && c.wallMs ? Math.round((c.files / (c.wallMs / 1000)) * 10) / 10 : null;
}

export const pct = (x: number) => `${(x * 100).toFixed(1)}%`;
