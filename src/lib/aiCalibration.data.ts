import type { CalibrationMap } from "./aiCalibration";

/**
 * The calibration map applied by default. `null` = none: every scan reports its AI number as an uncalibrated
 * EVIDENCE SCORE with `ai_probability.status === "uncalibrated"` -- see aiCalibration.ts for why.
 *
 * Do NOT populate this from the labelled samples that ship in the repo (aiAttributionBenchmark.fixtures.ts holds
 * about a dozen): validateCalibrationMap refuses any map fitted on fewer than MIN_CALIBRATION_SAMPLES_PER_CLASS per
 * class, and that refusal is correct. To enable calibrated probabilities:
 *   1. assemble a labelled corpus representative of the code TrustLedger scans (>= 100 AI and >= 100 human files,
 *      ideally many times that, spanning languages and the AI tools in use);
 *   2. score each file with analyzeFile and record `ai_percentage`;
 *   3. fitCalibration(samples, { source, fitted_at }) on a TRAINING split;
 *   4. check expectedCalibrationError / brierScore on a HELD-OUT split -- the fit must beat the raw score there;
 *   5. commit the resulting map here (or pass it per scan via ScanInput.calibration).
 */
export const DEFAULT_AI_CALIBRATION: CalibrationMap | null = null;
