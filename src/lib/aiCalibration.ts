// ── AI evidence score vs. calibrated AI probability ──────────────────────────
//
// TrustLedger's AI number (`ai_percentage`, `total_ai_percentage`, the "AI %" in the UI) is an EVIDENCE SCORE: a
// hand-weighted noisy-OR over dozens of stylistic/structural signals, pushed through a sigmoid. It is monotone
// (more evidence -> higher) and useful for ranking and thresholding, but it is NOT a probability. "78%" does not
// mean "78 of every 100 files that score like this were written by an AI", and nothing in the pipeline ever
// checked that it does. Showing it as a percentage invites exactly that reading.
//
// A PROBABILITY is a different, stronger claim: P(AI-generated | this score), which can only be established
// empirically -- take a labelled corpus, score every file, and measure how often files at each score really were
// AI. That mapping is a "calibration". This module is that mechanism, kept deliberately separate from the score:
//
//   evidence score  : what the detector computed. Always available. Not a probability.
//   ai_probability  : a calibrated P(AI | score) with a confidence interval -- OR an explicit refusal.
//
// The refusal is the important design decision. A calibration fitted on too little (or unrepresentative) data is
// worse than none: it turns an honest "unknown" into a confident-looking number. So a map is only honoured when
// it clears a per-class sample floor; otherwise the result is `status: "uncalibrated"` with `value: null` and a
// reason -- never a guess. The repository ships no fitted map: the only labelled data it holds (~a dozen
// attribution samples) is far below the floor, and a probability derived from it would be fiction.
//
// Method: isotonic regression (pool-adjacent-violators). It assumes only that a higher score never means a LOWER
// chance of being AI -- true of any sensible detector -- and otherwise lets the data decide the shape, unlike a
// parametric (Platt/logistic) fit that presumes one.

export interface CalibrationBin {
  /** Inclusive lower score bound; the first bin's is always 0. A score belongs to the bin with the largest `lo` <= score. */
  lo: number;
  /** AI-labelled and total samples pooled into this bin -- kept so the interval is computable and auditable. */
  k: number;
  n: number;
  /** P(AI | score in this bin): the pooled rate k/n (monotone by construction), kept strictly inside (0,1). */
  p: number;
}

export interface CalibrationMap {
  /** Identifies this exact fit (bins + provenance). Recorded on every result so a probability can be traced back to it. */
  version: string;
  fitted_at: string;
  /** Where the labelled data came from -- a human-readable provenance, not machine-interpreted. */
  source: string;
  n_ai: number;
  n_human: number;
  bins: CalibrationBin[];
}

export interface AiProbability {
  status: "calibrated" | "uncalibrated";
  /** P(AI-generated | evidence score); null whenever status is "uncalibrated". Never a guess. */
  value: number | null;
  /** 95% Wilson interval for the bin's rate; null when uncalibrated. */
  interval: [number, number] | null;
  calibration_version: string | null;
  /** Why it is uncalibrated (absent when calibrated). */
  reason?: string;
}

/** Below this many samples PER CLASS a calibration is refused: a rate estimated from a handful of files is noise. */
export const MIN_CALIBRATION_SAMPLES_PER_CLASS = 100;
/**
 * Minimum samples in one bin. Plain isotonic regression happily produces bins of a single file (k/n = 0/1 or
 * 1/1), which as probabilities are absurd. Undersized bins are pooled into the neighbour with the nearest rate --
 * pooling adjacent blocks keeps the fit monotone, so this costs resolution only where the data cannot support it.
 */
export const MIN_BIN_SAMPLES = 25;

const clamp01 = (x: number): number => Math.min(1, Math.max(0, x));

/** 95% Wilson score interval for k successes in n trials (well-behaved at k=0, k=n and small n, unlike the normal approx). */
export function wilsonInterval(k: number, n: number, z = 1.96): [number, number] {
  if (n <= 0) return [0, 1];
  const phat = k / n;
  const z2 = z * z;
  const denom = 1 + z2 / n;
  const centre = (phat + z2 / (2 * n)) / denom;
  const half = (z * Math.sqrt((phat * (1 - phat)) / n + z2 / (4 * n * n))) / denom;
  return [clamp01(centre - half), clamp01(centre + half)];
}

/**
 * Fit a calibration map by isotonic regression. `samples`: the detector's evidence score for a file and whether the
 * file really was AI-generated (ground truth, from a labelled corpus). Non-finite scores are dropped.
 */
export function fitCalibration(
  samples: ReadonlyArray<{ score: number; ai: boolean }>,
  meta: { source: string; fitted_at: string },
  opts: { minBinSamples?: number } = {},
): CalibrationMap {
  const minBin = opts.minBinSamples ?? MIN_BIN_SAMPLES;
  // Collapse equal scores first: two files with the same score must land in the same bin, so a tie can never
  // straddle a boundary and make the lookup ambiguous.
  const byScore = new Map<number, { k: number; n: number }>();
  let nAi = 0, nHuman = 0;
  for (const s of samples) {
    if (!Number.isFinite(s.score)) continue;
    const key = clamp01(s.score);
    const cell = byScore.get(key) ?? { k: 0, n: 0 };
    cell.n += 1;
    if (s.ai) { cell.k += 1; nAi += 1; } else nHuman += 1;
    byScore.set(key, cell);
  }
  const points = [...byScore.entries()].sort((a, b) => a[0] - b[0]);

  // Pool adjacent violators: whenever a block's rate exceeds its successor's, merge them.
  const blocks: Array<{ lo: number; k: number; n: number }> = [];
  for (const [score, cell] of points) {
    blocks.push({ lo: score, k: cell.k, n: cell.n });
    while (blocks.length >= 2) {
      const b = blocks[blocks.length - 1], a = blocks[blocks.length - 2];
      if (a.k / a.n <= b.k / b.n) break;
      a.k += b.k; a.n += b.n;
      blocks.pop();                                   // the merged block keeps `a`'s (smaller) lower bound
    }
  }
  // Enforce minimum support: repeatedly pool the smallest undersized block into the neighbour with the nearest
  // rate. Pooled rates lie between the two originals, so monotonicity is preserved (see MIN_BIN_SAMPLES).
  for (;;) {
    let idx = -1;
    for (let i = 0; i < blocks.length; i++) if (blocks[i].n < minBin && (idx < 0 || blocks[i].n < blocks[idx].n)) idx = i;
    if (idx < 0 || blocks.length < 2) break;
    const left = idx > 0 ? blocks[idx - 1] : null;
    const right = idx < blocks.length - 1 ? blocks[idx + 1] : null;
    const rate = (b: { k: number; n: number }) => b.k / b.n;
    const useLeft = !right || (left !== null && Math.abs(rate(left) - rate(blocks[idx])) <= Math.abs(rate(right) - rate(blocks[idx])));
    const into = useLeft ? left! : blocks[idx];
    const from = useLeft ? blocks[idx] : right!;
    into.k += from.k; into.n += from.n;                // the pooled block keeps the LEFT block's lower bound
    blocks.splice(blocks.indexOf(from), 1);
  }
  if (blocks.length > 0) blocks[0].lo = 0;             // cover the whole score range from 0

  // The pooled rate is the estimate, kept off the exact 0/1 that a finite sample can never justify.
  const eps = 1 / (nAi + nHuman + 2);
  const bins: CalibrationBin[] = blocks.map(b => ({ lo: b.lo, k: b.k, n: b.n, p: Math.min(1 - eps, Math.max(eps, b.k / b.n)) }));

  const payload = JSON.stringify([bins, meta.source, nAi, nHuman]);
  let h = 2166136261;                                  // FNV-1a: a short, stable version tag (not a security hash)
  for (let i = 0; i < payload.length; i++) { h ^= payload.charCodeAt(i); h = Math.imul(h, 16777619); }
  return { version: `iso-${(h >>> 0).toString(16).padStart(8, "0")}`, fitted_at: meta.fitted_at, source: meta.source, n_ai: nAi, n_human: nHuman, bins };
}

/** Structural problems that make a map unsafe to apply. Empty array = usable. */
export function validateCalibrationMap(map: CalibrationMap): string[] {
  const errors: string[] = [];
  if (!map.bins.length) return ["no bins"];
  if (map.bins[0].lo !== 0) errors.push("first bin must start at score 0");
  for (let i = 0; i < map.bins.length; i++) {
    const b = map.bins[i];
    if (!(b.p >= 0 && b.p <= 1)) errors.push(`bin ${i}: p out of [0,1]`);
    if (!(b.n > 0 && b.k >= 0 && b.k <= b.n)) errors.push(`bin ${i}: inconsistent k/n`);
    if (i > 0 && !(b.lo > map.bins[i - 1].lo)) errors.push(`bin ${i}: lower bounds must strictly increase`);
    if (i > 0 && b.p < map.bins[i - 1].p) errors.push(`bin ${i}: probability decreases (not monotone)`);
  }
  if (map.n_ai < MIN_CALIBRATION_SAMPLES_PER_CLASS || map.n_human < MIN_CALIBRATION_SAMPLES_PER_CLASS) {
    errors.push(`fitted on ${map.n_ai} AI / ${map.n_human} human samples; at least ${MIN_CALIBRATION_SAMPLES_PER_CLASS} per class are required`);
  }
  return errors;
}

const uncalibrated = (reason: string): AiProbability =>
  ({ status: "uncalibrated", value: null, interval: null, calibration_version: null, reason });

/** The calibrated probability for an evidence score, or an explicit, reasoned refusal. Never throws, never guesses. */
export function toAiProbability(score: number, map: CalibrationMap | null | undefined): AiProbability {
  if (!Number.isFinite(score)) return uncalibrated("evidence score is not a finite number");
  if (!map) return uncalibrated("no calibration map is loaded; the evidence score is not a probability");
  const errors = validateCalibrationMap(map);
  if (errors.length > 0) return uncalibrated(`calibration map ${map.version} rejected: ${errors[0]}`);
  const s = clamp01(score);
  let bin = map.bins[0];
  for (const b of map.bins) { if (b.lo <= s) bin = b; else break; }
  return { status: "calibrated", value: bin.p, interval: wilsonInterval(bin.k, bin.n), calibration_version: map.version };
}

// ── Evaluation: how well does a score/probability match what actually happened ─────────────────────────

/** Mean squared error between predicted probability and the 0/1 outcome. Lower is better; 0.25 = always guessing 0.5. */
export function brierScore(pairs: ReadonlyArray<{ p: number; ai: boolean }>): number {
  if (pairs.length === 0) return NaN;
  return pairs.reduce((s, x) => s + (x.p - (x.ai ? 1 : 0)) ** 2, 0) / pairs.length;
}

/**
 * Expected calibration error: bucket predictions, and average |mean predicted - observed AI rate| weighted by bucket
 * size. 0 means a stated 70% really happens 70% of the time. This is the number that distinguishes a probability
 * from a mere score, so it is what a calibration must be judged on, on data the fit never saw.
 */
export function expectedCalibrationError(pairs: ReadonlyArray<{ p: number; ai: boolean }>, buckets = 10): number {
  if (pairs.length === 0) return NaN;
  const agg = Array.from({ length: buckets }, () => ({ n: 0, sumP: 0, k: 0 }));
  for (const x of pairs) {
    const i = Math.min(buckets - 1, Math.floor(clamp01(x.p) * buckets));
    agg[i].n += 1; agg[i].sumP += x.p; if (x.ai) agg[i].k += 1;
  }
  return agg.reduce((s, a) => (a.n === 0 ? s : s + (a.n / pairs.length) * Math.abs(a.sumP / a.n - a.k / a.n)), 0);
}
