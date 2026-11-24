/**
 * AI-attribution accuracy benchmark.
 *
 * Runs the scanner's `ai_percentage` score against a small labeled corpus
 * (see `aiAttributionBenchmark.fixtures.ts`) and computes standard binary
 * classification metrics (precision, recall, F1, accuracy) at a chosen
 * decision threshold, plus threshold-independent ROC-AUC.
 *
 * This is intentionally a small (n=10), TS/JS-only internal benchmark — it
 * gives concrete, reproducible numbers for the AI-attribution engine instead
 * of none, but is not a substitute for a large external labeled corpus.
 */

import { runScan } from "./scanner";
import { BENCHMARK_SAMPLES, type BenchmarkSample, type BenchmarkLabel } from "./aiAttributionBenchmark.fixtures";
import { attributeCode, type AIModel } from "./aiAttribution";
import { TOOL_BENCHMARK_SAMPLES, type ToolBenchmarkSample } from "./aiAttributionBenchmark.fixtures.tools";

export interface SampleResult {
  id:          string;
  label:       BenchmarkLabel;
  ai_percentage: number;
  predicted:   BenchmarkLabel; // at the given threshold
  correct:     boolean;
}

export interface BenchmarkReport {
  threshold:  number;
  results:    SampleResult[];
  confusion: { tp: number; fp: number; tn: number; fn: number };
  precision:  number;
  recall:     number;
  f1:         number;
  accuracy:   number;
  rocAuc:     number;
  prAuc:      number;  // area under precision-recall curve (better for imbalanced sets)
  brierScore: number;  // mean squared error of probability estimates (lower = better)
  ece:        number;  // expected calibration error (lower = better)
}

/**
 * Runs the scanner against every sample in the benchmark corpus and returns
 * each sample's computed `ai_percentage`.
 */
export function scoreBenchmarkSamples(samples: BenchmarkSample[] = BENCHMARK_SAMPLES): Array<{ id: string; label: BenchmarkLabel; ai_percentage: number }> {
  return samples.map(sample => {
    const result = runScan({
      repo: "benchmark/ai-attribution", pr_number: 1, commit_sha: "0000000", branch: "main",
      files: [{ path: `bench/${sample.id}.${sample.language === "javascript" ? "js" : "ts"}`, content: sample.content }],
    });
    return { id: sample.id, label: sample.label, ai_percentage: result.files[0].ai_percentage };
  });
}

/** Computes ROC-AUC via the Mann-Whitney U statistic (rank-sum method). */
function computeRocAuc(scores: Array<{ score: number; label: BenchmarkLabel }>): number {
  const positives = scores.filter(s => s.label === "ai");
  const negatives = scores.filter(s => s.label === "human");
  if (positives.length === 0 || negatives.length === 0) return 0.5;

  let wins = 0, ties = 0;
  for (const p of positives) {
    for (const n of negatives) {
      if (p.score > n.score) wins++;
      else if (p.score === n.score) ties++;
    }
  }
  return (wins + 0.5 * ties) / (positives.length * negatives.length);
}

/**
 * Computes PR-AUC via trapezoidal integration over the precision-recall curve.
 * Thresholds are derived from the unique score values in descending order.
 */
function computePrAuc(scores: Array<{ score: number; label: BenchmarkLabel }>): number {
  const nPos = scores.filter(s => s.label === "ai").length;
  if (nPos === 0) return 0;

  // Sort thresholds descending (from highest score to lowest)
  const thresholds = [...new Set(scores.map(s => s.score))].sort((a, b) => b - a);
  const points: Array<{ p: number; r: number }> = [];

  for (const t of thresholds) {
    const tp = scores.filter(s => s.label === "ai" && s.score >= t).length;
    const fp = scores.filter(s => s.label === "human" && s.score >= t).length;
    const p = tp + fp > 0 ? tp / (tp + fp) : 1;
    const r = tp / nPos;
    points.push({ p, r });
  }
  // Add (recall=0, precision=1) baseline
  points.unshift({ p: 1, r: 0 });

  // Trapezoidal integration
  let auc = 0;
  for (let i = 1; i < points.length; i++) {
    const dr = points[i].r - points[i - 1].r;
    const avgP = (points[i].p + points[i - 1].p) / 2;
    auc += dr * avgP;
  }
  return Math.max(0, auc);
}

/** Brier score: mean squared error of probability estimates (treating "ai" = 1, "human" = 0). */
function computeBrierScore(scores: Array<{ score: number; label: BenchmarkLabel }>): number {
  if (scores.length === 0) return 1;
  const sum = scores.reduce((acc, s) => {
    const y = s.label === "ai" ? 1 : 0;
    return acc + (s.score - y) ** 2;
  }, 0);
  return sum / scores.length;
}

/**
 * Expected Calibration Error: bins predictions into 10 equal-width buckets,
 * computes |avg_confidence - fraction_positive| per bucket, weighted by count.
 */
function computeEce(scores: Array<{ score: number; label: BenchmarkLabel }>, nBins = 10): number {
  if (scores.length === 0) return 0;
  const bins: Array<{ sumConf: number; nPos: number; count: number }> =
    Array.from({ length: nBins }, () => ({ sumConf: 0, nPos: 0, count: 0 }));

  for (const s of scores) {
    const b = Math.min(nBins - 1, Math.floor(s.score * nBins));
    bins[b].sumConf += s.score;
    bins[b].nPos    += s.label === "ai" ? 1 : 0;
    bins[b].count   += 1;
  }

  let ece = 0;
  for (const bin of bins) {
    if (bin.count === 0) continue;
    const avgConf = bin.sumConf / bin.count;
    const fracPos = bin.nPos / bin.count;
    ece += (bin.count / scores.length) * Math.abs(avgConf - fracPos);
  }
  return ece;
}

/**
 * Runs the full benchmark: scores every sample, classifies it against
 * `threshold`, and computes precision/recall/F1/accuracy/ROC-AUC.
 *
 * @param threshold  ai_percentage >= threshold ⇒ predicted "ai" (default 0.5)
 */
export function runAIAttributionBenchmark(
  samples: BenchmarkSample[] = BENCHMARK_SAMPLES,
  threshold = 0.5,
): BenchmarkReport {
  const scored = scoreBenchmarkSamples(samples);

  const results: SampleResult[] = scored.map(s => {
    const predicted: BenchmarkLabel = s.ai_percentage >= threshold ? "ai" : "human";
    return { ...s, predicted, correct: predicted === s.label };
  });

  let tp = 0, fp = 0, tn = 0, fn = 0;
  for (const r of results) {
    if (r.label === "ai" && r.predicted === "ai") tp++;
    else if (r.label === "human" && r.predicted === "ai") fp++;
    else if (r.label === "human" && r.predicted === "human") tn++;
    else if (r.label === "ai" && r.predicted === "human") fn++;
  }

  const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
  const recall    = tp + fn > 0 ? tp / (tp + fn) : 0;
  const f1        = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 0;
  const accuracy  = results.length > 0 ? (tp + tn) / results.length : 0;
  const scorePairs = scored.map(s => ({ score: s.ai_percentage, label: s.label }));
  const rocAuc    = computeRocAuc(scorePairs);
  const prAuc     = computePrAuc(scorePairs);
  const brierScore = computeBrierScore(scorePairs);
  const ece       = computeEce(scorePairs);

  return { threshold, results, confusion: { tp, fp, tn, fn }, precision, recall, f1, accuracy, rocAuc, prAuc, brierScore, ece };
}

/** Formats a BenchmarkReport as a human-readable string (for logs/CLI). */
export function formatBenchmarkReport(report: BenchmarkReport): string {
  const lines: string[] = [
    `AI Attribution Benchmark (n=${report.results.length}, threshold=${report.threshold})`,
    `  Precision:   ${(report.precision * 100).toFixed(1)}%`,
    `  Recall:      ${(report.recall * 100).toFixed(1)}%`,
    `  F1:          ${(report.f1 * 100).toFixed(1)}%`,
    `  Accuracy:    ${(report.accuracy * 100).toFixed(1)}%`,
    `  ROC-AUC:     ${report.rocAuc.toFixed(3)}`,
    `  PR-AUC:      ${report.prAuc.toFixed(3)}`,
    `  Brier score: ${report.brierScore.toFixed(3)} (lower = better)`,
    `  ECE:         ${report.ece.toFixed(3)} (lower = better)`,
    `  Confusion: TP=${report.confusion.tp} FP=${report.confusion.fp} TN=${report.confusion.tn} FN=${report.confusion.fn}`,
    `  Per-sample:`,
  ];
  for (const r of report.results) {
    const mark = r.correct ? "✓" : "✗";
    lines.push(`    ${mark} ${r.id.padEnd(20)} label=${r.label.padEnd(5)} ai_pct=${(r.ai_percentage * 100).toFixed(1).padStart(5)}% predicted=${r.predicted}`);
  }
  return lines.join("\n");
}

// ── Per-tool attribution benchmark ──────────────────────────────────────────
// Checks whether attributeCode() predicts the correct TOOL (not just
// ai-vs-human) against a small labeled per-tool fixture set -- see
// aiAttributionBenchmark.fixtures.tools.ts for corpus notes/limitations.
// This is the first per-tool quality gate this engine has ever had.

export interface ToolAttributionResult {
  id:         string;
  expected:   AIModel;
  predicted:  AIModel;
  confidence: number;
  correct:    boolean;
}

export interface ToolAttributionReport {
  results:  ToolAttributionResult[];
  accuracy: number;
  perModel: Record<string, { correct: number; total: number }>;
}

export function runToolAttributionBenchmark(
  samples: ToolBenchmarkSample[] = TOOL_BENCHMARK_SAMPLES,
): ToolAttributionReport {
  const results: ToolAttributionResult[] = samples.map(s => {
    const r = attributeCode(s.content, s.language);
    return { id: s.id, expected: s.expectedModel, predicted: r.model, confidence: r.confidence, correct: r.model === s.expectedModel };
  });

  const perModel: Record<string, { correct: number; total: number }> = {};
  for (const r of results) {
    perModel[r.expected] ??= { correct: 0, total: 0 };
    perModel[r.expected].total += 1;
    if (r.correct) perModel[r.expected].correct += 1;
  }

  const accuracy = results.length > 0 ? results.filter(r => r.correct).length / results.length : 0;
  return { results, accuracy, perModel };
}

/** Formats a ToolAttributionReport as a human-readable string (for logs/CLI). */
export function formatToolAttributionReport(report: ToolAttributionReport): string {
  const lines: string[] = [
    `AI Tool Attribution Benchmark (n=${report.results.length})`,
    `  Accuracy: ${(report.accuracy * 100).toFixed(1)}%`,
    `  Per-sample:`,
  ];
  for (const r of report.results) {
    const mark = r.correct ? "✓" : "✗";
    lines.push(`    ${mark} ${r.id.padEnd(28)} expected=${r.expected.padEnd(15)} predicted=${r.predicted.padEnd(15)} confidence=${(r.confidence * 100).toFixed(0)}%`);
  }
  return lines.join("\n");
}
