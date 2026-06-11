/**
 * TrustLedger Precision / Recall Evaluation Framework
 *
 * Provides a structured ground-truth format and evaluation harness for
 * measuring the accuracy of scanner signals and the overall detector.
 *
 * Metrics computed:
 *   - Per-signal precision / recall / F1 / AUC-ROC (approximate)
 *   - Overall detector precision / recall / F1
 *   - Confusion matrix
 *   - False positive / false negative analysis
 *   - Signal calibration: expected vs actual fire rate
 */

import type { FileAnalysis } from "./scanner";

// ── Types ─────────────────────────────────────────────────────────────────────

export type GroundTruthLabel = "ai" | "human" | "mixed";

export interface GroundTruthFile {
  file_path:     string;
  label:         GroundTruthLabel;
  ai_fraction?:  number;   // for "mixed": 0–1 fraction of AI-generated lines
  source?:       string;   // e.g. "ChatGPT-4", "GitHub Copilot", "human-expert"
  notes?:        string;
}

export interface SignalEval {
  signal_id:    string;
  tp:           number;  // true positives (AI file, signal fired)
  fp:           number;  // false positives (human file, signal fired)
  tn:           number;  // true negatives (human file, signal silent)
  fn:           number;  // false negatives (AI file, signal silent)
  precision:    number;  // TP / (TP + FP)
  recall:       number;  // TP / (TP + FN)
  f1:           number;
  fire_rate_ai:    number;  // fraction of AI files where this fired
  fire_rate_human: number;  // fraction of human files where this fired
  likelihood_ratio: number; // P(fire|AI) / P(fire|human)
}

export interface OverallEval {
  threshold:    number;   // ai_percentage threshold used (e.g. 0.50)
  tp:           number;
  fp:           number;
  tn:           number;
  fn:           number;
  precision:    number;
  recall:       number;
  f1:           number;
  accuracy:     number;
  fpr:          number;   // false positive rate
  fnr:          number;   // false negative rate
  auc_approx:   number;   // AUC-ROC approximated via trapezoidal rule across thresholds
}

export interface ConfusionMatrix {
  ai_as_ai:     number;  // TP
  ai_as_human:  number;  // FN
  human_as_ai:  number;  // FP
  human_as_human: number; // TN
}

export interface BenchmarkReport {
  dataset_size:    number;
  ai_count:        number;
  human_count:     number;
  mixed_count:     number;
  signal_evals:    SignalEval[];
  overall:         OverallEval;
  confusion:       ConfusionMatrix;
  calibration:     CalibrationResult;
  false_positives: Array<{ file_path: string; ai_percentage: number; top_signals: string[] }>;
  false_negatives: Array<{ file_path: string; ai_percentage: number; source?: string }>;
  recommendations: string[];
}

export interface CalibrationResult {
  mean_score_ai:    number;  // mean ai_percentage for labelled-AI files
  mean_score_human: number;  // mean ai_percentage for labelled-human files
  separation:       number;  // mean_ai - mean_human (higher = better)
  overconfident:    number;  // fraction of human files with score > 0.65
  underconfident:   number;  // fraction of AI files with score < 0.35
  brier_score:      number;  // mean((score - label)^2) — lower is better
}

// ── Evaluation engine ─────────────────────────────────────────────────────────

export function evaluateBenchmark(
  groundTruth: GroundTruthFile[],
  analyses:    FileAnalysis[],
  threshold    = 0.50,
): BenchmarkReport {
  const analysisMap = new Map(analyses.map(a => [a.file_path, a]));

  const aiFiles    = groundTruth.filter(g => g.label === "ai");
  const humanFiles = groundTruth.filter(g => g.label === "human");
  const mixedFiles = groundTruth.filter(g => g.label === "mixed");

  // ── Per-signal evaluation ──────────────────────────────────────────────────

  const allSignalIds = new Set<string>();
  for (const a of analyses) a.explained_signals.forEach(s => allSignalIds.add(s.id));
  for (const a of analyses) a.indicators.forEach(i => allSignalIds.add(i.id));

  const signalEvals: SignalEval[] = [];
  for (const sigId of Array.from(allSignalIds)) {
    let tp = 0, fp = 0, tn = 0, fn = 0;
    for (const gt of groundTruth) {
      const a = analysisMap.get(gt.file_path);
      if (!a) continue;
      const fired = a.explained_signals.some(s => s.id === sigId && s.value > 0.15) ||
                    a.indicators.some(i => i.id === sigId);
      const isAI  = gt.label === "ai" || (gt.label === "mixed" && (gt.ai_fraction ?? 0.5) > 0.5);
      if (isAI  &&  fired) tp++;
      if (!isAI &&  fired) fp++;
      if (!isAI && !fired) tn++;
      if (isAI  && !fired) fn++;
    }
    const precision = tp + fp === 0 ? 1 : tp / (tp + fp);
    const recall    = tp + fn === 0 ? 0 : tp / (tp + fn);
    const f1        = precision + recall === 0 ? 0 : 2 * precision * recall / (precision + recall);
    const aiTotal   = aiFiles.length + mixedFiles.length || 1;
    const humTotal  = humanFiles.length || 1;
    signalEvals.push({
      signal_id: sigId, tp, fp, tn, fn, precision, recall, f1,
      fire_rate_ai:    (tp + fn === 0) ? 0 : tp / aiTotal,
      fire_rate_human: (fp + tn === 0) ? 0 : fp / humTotal,
      likelihood_ratio: fp === 0 ? (tp > 0 ? 99 : 1) : (tp / Math.max(1, aiTotal)) / (fp / Math.max(1, humTotal)),
    });
  }
  signalEvals.sort((a, b) => b.likelihood_ratio - a.likelihood_ratio);

  // ── Overall evaluation ─────────────────────────────────────────────────────

  let oTp = 0, oFp = 0, oTn = 0, oFn = 0;
  const fpFiles: BenchmarkReport["false_positives"] = [];
  const fnFiles: BenchmarkReport["false_negatives"] = [];

  for (const gt of groundTruth) {
    const a = analysisMap.get(gt.file_path);
    if (!a) continue;
    const predicted = a.ai_percentage >= threshold;
    const isAI = gt.label === "ai" || (gt.label === "mixed" && (gt.ai_fraction ?? 0.5) > 0.5);
    if (isAI && predicted)  oTp++;
    if (!isAI && predicted) { oFp++; fpFiles.push({ file_path: gt.file_path, ai_percentage: a.ai_percentage, top_signals: a.explained_signals.slice(0, 3).map(s => s.id) }); }
    if (!isAI && !predicted) oTn++;
    if (isAI && !predicted)  { oFn++; fnFiles.push({ file_path: gt.file_path, ai_percentage: a.ai_percentage, source: gt.source }); }
  }

  const precision  = oTp + oFp === 0 ? 1 : oTp / (oTp + oFp);
  const recall     = oTp + oFn === 0 ? 0 : oTp / (oTp + oFn);
  const f1         = precision + recall === 0 ? 0 : 2 * precision * recall / (precision + recall);
  const accuracy   = groundTruth.length === 0 ? 1 : (oTp + oTn) / groundTruth.length;
  const fpr        = oFp + oTn === 0 ? 0 : oFp / (oFp + oTn);
  const fnr        = oFn + oTp === 0 ? 0 : oFn / (oFn + oTp);

  // AUC-ROC approximation via trapezoidal rule across 11 thresholds
  const thresholds = [0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0];
  const rocPoints = thresholds.map(t => {
    let tp_ = 0, fp_ = 0, tn_ = 0, fn_ = 0;
    for (const gt of groundTruth) {
      const a = analysisMap.get(gt.file_path);
      if (!a) continue;
      const predicted = a.ai_percentage >= t;
      const isAI = gt.label === "ai" || (gt.label === "mixed" && (gt.ai_fraction ?? 0.5) > 0.5);
      if (isAI && predicted) tp_++; if (!isAI && predicted) fp_++;
      if (!isAI && !predicted) tn_++; if (isAI && !predicted) fn_++;
    }
    return { tpr: tp_ + fn_ === 0 ? 0 : tp_ / (tp_ + fn_), fpr: fp_ + tn_ === 0 ? 0 : fp_ / (fp_ + tn_) };
  });
  let auc = 0;
  for (let i = 1; i < rocPoints.length; i++) {
    auc += Math.abs(rocPoints[i].fpr - rocPoints[i-1].fpr) * (rocPoints[i].tpr + rocPoints[i-1].tpr) / 2;
  }

  // ── Calibration ────────────────────────────────────────────────────────────

  const aiScores    = groundTruth.filter(g => g.label === "ai").map(g => analysisMap.get(g.file_path)?.ai_percentage ?? 0);
  const humanScores = groundTruth.filter(g => g.label === "human").map(g => analysisMap.get(g.file_path)?.ai_percentage ?? 0);
  const mean = (xs: number[]) => xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : 0;
  const meanAI    = mean(aiScores);
  const meanHuman = mean(humanScores);
  const brierScore = mean(groundTruth.map(g => {
    const score = analysisMap.get(g.file_path)?.ai_percentage ?? 0;
    const label = g.label === "ai" ? 1 : g.label === "human" ? 0 : (g.ai_fraction ?? 0.5);
    return (score - label) ** 2;
  }));

  const calibration: CalibrationResult = {
    mean_score_ai: meanAI, mean_score_human: meanHuman,
    separation:   meanAI - meanHuman,
    overconfident: humanScores.filter(s => s > 0.65).length / Math.max(1, humanScores.length),
    underconfident: aiScores.filter(s => s < 0.35).length / Math.max(1, aiScores.length),
    brier_score: brierScore,
  };

  // ── Recommendations ────────────────────────────────────────────────────────

  const recommendations: string[] = [];
  if (calibration.overconfident > 0.10)
    recommendations.push(`High FP rate (${Math.round(calibration.overconfident * 100)}% of human files > 0.65) — raise sigmoid inflection or reduce SECONDARY signal weights`);
  if (calibration.underconfident > 0.15)
    recommendations.push(`High FN rate (${Math.round(calibration.underconfident * 100)}% of AI files < 0.35) — lower detection threshold or add discriminating signals`);
  if (calibration.separation < 0.30)
    recommendations.push(`Low AI/human score separation (${calibration.separation.toFixed(2)}) — detector may not be reliably discriminating`);
  signalEvals.filter(s => s.precision < 0.50 && s.fp > 3)
    .forEach(s => recommendations.push(`Signal '${s.signal_id}' has low precision (${Math.round(s.precision * 100)}%) — consider raising its threshold or moving to STYLE tier`));
  signalEvals.filter(s => s.likelihood_ratio > 5)
    .forEach(s => recommendations.push(`Signal '${s.signal_id}' is highly discriminating (LR=${s.likelihood_ratio.toFixed(1)}) — consider promoting to CORE tier`));
  if (auc < 0.80)
    recommendations.push(`AUC-ROC ${auc.toFixed(2)} is below acceptable range — overall detector needs improvement`);

  return {
    dataset_size:  groundTruth.length,
    ai_count:      aiFiles.length,
    human_count:   humanFiles.length,
    mixed_count:   mixedFiles.length,
    signal_evals:  signalEvals,
    overall: { threshold, tp: oTp, fp: oFp, tn: oTn, fn: oFn,
               precision, recall, f1, accuracy, fpr, fnr, auc_approx: auc },
    confusion: { ai_as_ai: oTp, ai_as_human: oFn, human_as_ai: oFp, human_as_human: oTn },
    calibration,
    false_positives: fpFiles,
    false_negatives: fnFiles,
    recommendations,
  };
}

// ── Threshold sweep (find optimal threshold) ──────────────────────────────────

export function findOptimalThreshold(
  groundTruth: GroundTruthFile[],
  analyses:    FileAnalysis[],
  metric:      "f1" | "precision" | "recall" = "f1",
): { threshold: number; score: number } {
  const thresholds = Array.from({ length: 19 }, (_, i) => (i + 1) * 0.05);
  let best = { threshold: 0.50, score: 0 };
  for (const t of thresholds) {
    const { overall } = evaluateBenchmark(groundTruth, analyses, t);
    const s = overall[metric];
    if (s > best.score) best = { threshold: t, score: s };
  }
  return best;
}

// ── Dataset builder helpers ───────────────────────────────────────────────────

export function buildGroundTruth(
  files: Array<{ path: string; label: GroundTruthLabel; source?: string; ai_fraction?: number }>,
): GroundTruthFile[] {
  return files.map(f => ({ file_path: f.path, label: f.label, source: f.source, ai_fraction: f.ai_fraction }));
}

export function summariseBenchmark(report: BenchmarkReport): string {
  const o = report.overall;
  return [
    `Dataset: ${report.dataset_size} files (${report.ai_count} AI, ${report.human_count} human, ${report.mixed_count} mixed)`,
    `Overall — Precision: ${(o.precision*100).toFixed(1)}%  Recall: ${(o.recall*100).toFixed(1)}%  F1: ${(o.f1*100).toFixed(1)}%  AUC: ${o.auc_approx.toFixed(3)}`,
    `Confusion: TP=${o.tp} FP=${o.fp} TN=${o.tn} FN=${o.fn}`,
    `Calibration — Mean(AI)=${(report.calibration.mean_score_ai*100).toFixed(1)}%  Mean(human)=${(report.calibration.mean_score_human*100).toFixed(1)}%  Separation=${(report.calibration.separation*100).toFixed(1)}pp`,
    `Brier score: ${report.calibration.brier_score.toFixed(3)}  (lower = better calibrated)`,
    `Top signals by LR: ${report.signal_evals.slice(0, 5).map(s => `${s.signal_id}(${s.likelihood_ratio.toFixed(1)}x)`).join(", ")}`,
    report.recommendations.length > 0 ? `\nRecommendations:\n${report.recommendations.map(r => `  • ${r}`).join("\n")}` : "  No recommendations — detector is well calibrated",
  ].join("\n");
}
