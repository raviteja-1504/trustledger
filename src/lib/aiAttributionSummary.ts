/**
 * What share of the code in a scan looks AI-written, by code volume, with what could not be judged said out loud.
 *
 * The scan's headline `total_ai_percentage` is a blend (code signals, PR behaviour, git history, tooling) and cannot
 * say "of how much code". This is the plain version: each analysed file contributes its lines times its AI score, over
 * the lines analysed. Code that cannot be judged is reported as such instead of being counted as human:
 *   excluded -- config, data, lockfiles and generated files: not source anyone authors, left out of the percentage
 *   unknown  -- source files too short for the signals to say anything (<= MIN_ANALYSABLE_LINES lines)
 *
 * The per-file scores are the scanner's heuristic scores, not measured probabilities (they have not been calibrated
 * against labelled code), so this is an estimate of the share, and `analysis_coverage` says how much of the eligible
 * code it rests on. Pure.
 */

/** Files at or below this many lines are too short for the style signals to mean anything (same cut-off as the scan's own aggregates). */
export const MIN_ANALYSABLE_LINES = 20;
/** A file is "AI-leaning" at or above this score and "human-leaning" below the lower one; between is mixed / unclear. */
export const AI_LEANING_AT = 0.7;
export const HUMAN_LEANING_BELOW = 0.3;
/** Signal-coverage bands of scan_quality (how many signals could apply to the file). */
export const HIGH_CONFIDENCE_AT = 0.7;
export const MEDIUM_CONFIDENCE_AT = 0.4;

/** scan_quality is optional: scans read back from the database do not store it, so their confidence split is left at 0. */
export interface AttributionFile { file_path: string; line_count: number; ai_percentage: number; scan_quality?: number }

export interface AIAttributionSummary {
  /** Estimated AI-written lines / analysed lines, 0-1. 0 when nothing was analysed (see analyzed_loc). */
  estimated_ai_percentage: number;
  estimated_ai_loc: number;
  /** Source lines in files that could be judged. */
  analyzed_loc: number;
  /** Source lines overall: analysed + unknown. The denominator of analysis_coverage. */
  eligible_loc: number;
  /** Source lines too short to judge. Neither human nor AI. */
  unknown_loc: number;
  /** Lines in config, data and generated files, left out of everything above. */
  excluded_loc: number;
  /** analyzed_loc / eligible_loc, 0-1 (0 when there is no eligible code). */
  analysis_coverage: number;
  /** Analysed lines by file score: >= 0.7, 0.3-0.7, below 0.3. */
  ai_leaning_loc: number;
  mixed_loc: number;
  human_leaning_loc: number;
  /** Analysed lines by how many signals applied to the file (scan_quality). */
  high_confidence_loc: number;
  medium_confidence_loc: number;
  low_confidence_loc: number;
}

const clamp01 = (n: number) => (Number.isFinite(n) ? Math.min(1, Math.max(0, n)) : 0);

export function summarizeAIAttribution(files: readonly AttributionFile[], isExcluded: (filePath: string) => boolean): AIAttributionSummary {
  const out: AIAttributionSummary = {
    estimated_ai_percentage: 0, estimated_ai_loc: 0, analyzed_loc: 0, eligible_loc: 0, unknown_loc: 0, excluded_loc: 0,
    analysis_coverage: 0, ai_leaning_loc: 0, mixed_loc: 0, human_leaning_loc: 0,
    high_confidence_loc: 0, medium_confidence_loc: 0, low_confidence_loc: 0,
  };
  for (const f of files) {
    const loc = Math.max(0, Math.floor(f.line_count) || 0);
    if (isExcluded(f.file_path)) { out.excluded_loc += loc; continue; }
    out.eligible_loc += loc;
    if (loc <= MIN_ANALYSABLE_LINES) { out.unknown_loc += loc; continue; }
    const p = clamp01(f.ai_percentage), q = f.scan_quality == null ? null : clamp01(f.scan_quality);
    out.analyzed_loc += loc;
    out.estimated_ai_loc += loc * p;
    if (p >= AI_LEANING_AT) out.ai_leaning_loc += loc; else if (p < HUMAN_LEANING_BELOW) out.human_leaning_loc += loc; else out.mixed_loc += loc;
    if (q != null) { if (q >= HIGH_CONFIDENCE_AT) out.high_confidence_loc += loc; else if (q >= MEDIUM_CONFIDENCE_AT) out.medium_confidence_loc += loc; else out.low_confidence_loc += loc; }
  }
  out.estimated_ai_percentage = out.analyzed_loc > 0 ? clamp01(out.estimated_ai_loc / out.analyzed_loc) : 0;   // from the exact sum, not the rounded line count
  out.estimated_ai_loc = Math.round(out.estimated_ai_loc);
  out.analysis_coverage = out.eligible_loc > 0 ? out.analyzed_loc / out.eligible_loc : 0;
  return out;
}

const n = (v: number) => v.toLocaleString("en-US");

/**
 * One sentence for a scan page: the share by volume, and what it rests on. Says what was left out instead of letting
 * the percentage read as covering the whole repository. null when no source could be judged.
 */
export function attributionSentence(a: AIAttributionSummary | null | undefined): string | null {
  if (!a || a.analyzed_loc <= 0) return null;
  const parts = [`${Math.round(a.estimated_ai_percentage * 100)}% of the ${n(a.analyzed_loc)} source lines analysed look AI-written`];
  if (a.unknown_loc > 0) parts.push(`${n(a.unknown_loc)} line${a.unknown_loc === 1 ? "" : "s"} too short to judge`);
  if (a.excluded_loc > 0) parts.push(`${n(a.excluded_loc)} line${a.excluded_loc === 1 ? "" : "s"} of config or generated files left out`);
  return parts.join(" · ");
}
