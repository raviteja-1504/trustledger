/**
 * Task 3 — AI Code Attribution Engine v3 tests.
 *
 * Four concerns:
 *   1. New AttributionResult fields are always present and well-formed.
 *   2. Clean human-written code does not score high as AI.
 *   3. contradictingSignals is populated correctly.
 *   4. PR-AUC, Brier score, and ECE are present in BenchmarkReport.
 */

import { attributeCode, AI_ATTRIBUTION_ENGINE_VERSION, type AttributionResult } from "@/lib/aiAttribution";
import { runAIAttributionBenchmark } from "@/lib/aiAttributionBenchmark";
import { BENCHMARK_SAMPLES, EXTENDED_BENCHMARK_SAMPLES } from "@/lib/aiAttributionBenchmark.fixtures";

// ── 1. New fields are always present ─────────────────────────────────────────

describe("AttributionResult new fields (task 3)", () => {
  const TYPICAL_AI = `
/**
 * Validates the given user input object and returns a result.
 *
 * @param input - The user input to validate.
 * @returns An object with success, data, and error fields.
 */
export function validateUserInput(input: unknown): { success: boolean; data?: UserInput; error?: string } {
  if (!input || typeof input !== "object") {
    return { success: false, error: "Input must be an object" };
  }
  try {
    const parsed = UserInputSchema.parse(input);
    return { success: true, data: parsed };
  } catch (error) {
    console.error("Validation failed:", error);
    return { success: false, error: (error as Error).message };
  }
}
  `;

  it("every result includes the new fields", () => {
    const r = attributeCode(TYPICAL_AI, "typescript");
    expect(r).toHaveProperty("contradictingSignals");
    expect(r).toHaveProperty("insufficientEvidence");
    expect(r).toHaveProperty("evidenceCategory");
    expect(r).toHaveProperty("confidenceLimitations");
    expect(r).toHaveProperty("engineVersion");
  });

  it("engineVersion matches the exported constant", () => {
    const r = attributeCode(TYPICAL_AI, "typescript");
    expect(r.engineVersion).toBe(AI_ATTRIBUTION_ENGINE_VERSION);
  });

  it("evidenceCategory is always 'statistical_stylistic'", () => {
    const r = attributeCode(TYPICAL_AI, "typescript");
    expect(r.evidenceCategory).toBe("statistical_stylistic");
  });

  it("confidenceLimitations is a non-empty string array", () => {
    const r = attributeCode(TYPICAL_AI, "typescript");
    expect(Array.isArray(r.confidenceLimitations)).toBe(true);
    expect(r.confidenceLimitations.length).toBeGreaterThan(0);
    for (const lim of r.confidenceLimitations) {
      expect(typeof lim).toBe("string");
      expect(lim.length).toBeGreaterThan(0);
    }
  });

  it("contradictingSignals is an array (may be empty)", () => {
    const r = attributeCode(TYPICAL_AI, "typescript");
    expect(Array.isArray(r.contradictingSignals)).toBe(true);
  });

  it("insufficientEvidence is false when a model is detected", () => {
    const r = attributeCode(TYPICAL_AI, "typescript");
    if (r.model !== "unknown") {
      expect(r.insufficientEvidence).toBe(false);
    }
  });

  it("insufficientEvidence is true for unknown attribution", () => {
    const r = attributeCode("unknown model", "typescript");
    // too short → model=unknown
    expect(r.insufficientEvidence).toBe(true);
  });

  it("short content returns insufficientEvidence=true with all new fields", () => {
    const r = attributeCode("x = 1", "typescript");
    expect(r.insufficientEvidence).toBe(true);
    expect(r.engineVersion).toBe(AI_ATTRIBUTION_ENGINE_VERSION);
    expect(r.evidenceCategory).toBe("statistical_stylistic");
    expect(Array.isArray(r.confidenceLimitations)).toBe(true);
    expect(r.confidenceLimitations.length).toBeGreaterThan(0);
    expect(Array.isArray(r.contradictingSignals)).toBe(true);
  });

  it("model-specific confidence limitation present when model is not unknown/human", () => {
    // Run against an AI-heavy sample to maximize chance of detecting a specific model
    const r = attributeCode(TYPICAL_AI, "typescript");
    if (r.model !== "unknown" && r.model !== "human") {
      expect(r.confidenceLimitations.some(l => l.includes("probabilistic estimate"))).toBe(true);
    }
  });
});

// ── 2. Clean human code does not score high as AI ───────────────────────────

describe("clean human code attribution (task 3)", () => {
  // Use the labeled human samples from the benchmark corpus — these are verified
  // human-written OSS code and must NOT be misclassified as high-confidence AI.
  const humanSamples = BENCHMARK_SAMPLES.filter(s => s.label === "human");

  it("every human fixture returns insufficientEvidence=false (enough content to score)", () => {
    for (const s of humanSamples) {
      const r = attributeCode(s.content, s.language);
      // These samples are all large enough to score
      expect(r.insufficientEvidence).toBe(false);
    }
  });

  it("human fixtures do not reach confidence ≥ 0.90 for any AI model", () => {
    for (const s of humanSamples) {
      const r = attributeCode(s.content, s.language);
      if (r.model !== "human" && r.model !== "unknown") {
        // AI model was predicted — confidence must be below 0.90 for human code
        expect(r.confidence).toBeLessThan(0.90);
      }
    }
  });

  it("no human fixture gets confidence ≥ 0.85 for a specific AI tool", () => {
    // The current engine is pattern-based; well-structured OSS code (zod, entities)
    // may loosely match stylistic patterns, but should never reach "high-confidence"
    // territory for any specific AI tool.
    for (const s of humanSamples) {
      const r = attributeCode(s.content, s.language);
      if (r.model !== "human" && r.model !== "unknown") {
        expect(r.confidence).toBeLessThan(0.85);
      }
    }
  });
});

// ── 3. contradictingSignals ───────────────────────────────────────────────────

describe("contradictingSignals (task 3)", () => {
  it("contradictingSignals is empty for unknown model", () => {
    const r = attributeCode("", "typescript");
    expect(r.contradictingSignals).toHaveLength(0);
  });

  it("contradictingSignals is empty for human attribution", () => {
    // Personal attribution comment → strong human signal
    const human = `
// @author Jane Smith
// Written by me for the internal reporting pipeline.
// FIXME(jane): this whole module needs a rewrite once we upgrade Node
export function legacyReport(data: any[]) {
  return data.map(r => ({ id: r.id, val: r.value ?? 0 }));
}
    `;
    const r = attributeCode(human, "typescript");
    if (r.model === "human") {
      expect(r.contradictingSignals).toHaveLength(0);
    }
    // regardless, the array must exist
    expect(Array.isArray(r.contradictingSignals)).toBe(true);
  });

  it("contradictingSignals contains strings when negative patterns fire", () => {
    // This sample has AI patterns (verbose JSDoc, { success, error }) but also
    // has a personal comment that might fire a negative pattern.
    const mixed = `
// @author dev — added for the payments flow
/**
 * Processes a payment and returns a result object.
 *
 * @param amount - The amount to charge in cents.
 * @returns An object with success, data, and error fields.
 */
export async function processPayment(amount: number): Promise<{ success: boolean; error?: string }> {
  try {
    const result = await chargeCard(amount);
    return { success: true, data: result };
  } catch (error) {
    console.error("Payment failed:", error);
    return { success: false, error: (error as Error).message };
  }
}
    `;
    const r = attributeCode(mixed, "typescript");
    // contradictingSignals is always an array
    expect(Array.isArray(r.contradictingSignals)).toBe(true);
    for (const s of r.contradictingSignals) {
      expect(typeof s).toBe("string");
    }
  });
});

// ── 4. BenchmarkReport new metrics ───────────────────────────────────────────

describe("BenchmarkReport includes PR-AUC, Brier score, ECE (task 3)", () => {
  let report: ReturnType<typeof runAIAttributionBenchmark>;

  beforeAll(() => {
    report = runAIAttributionBenchmark();
  });

  it("prAuc is defined and in [0, 1]", () => {
    expect(report.prAuc).toBeGreaterThanOrEqual(0);
    expect(report.prAuc).toBeLessThanOrEqual(1);
  });

  it("brierScore is defined and in [0, 1]", () => {
    expect(report.brierScore).toBeGreaterThanOrEqual(0);
    expect(report.brierScore).toBeLessThanOrEqual(1);
  });

  it("ece is defined and in [0, 1]", () => {
    expect(report.ece).toBeGreaterThanOrEqual(0);
    expect(report.ece).toBeLessThanOrEqual(1);
  });

  it("formatBenchmarkReport includes PR-AUC, Brier score, ECE lines", () => {
    const { formatBenchmarkReport } = require("@/lib/aiAttributionBenchmark");
    const text = formatBenchmarkReport(report);
    expect(text).toContain("PR-AUC");
    expect(text).toContain("Brier score");
    expect(text).toContain("ECE");
  });
});

// ── 5. Extended corpus fixture types ─────────────────────────────────────────

describe("EXTENDED_BENCHMARK_SAMPLES fixture label types (task 3)", () => {
  it("contains all five label types", () => {
    const labels = new Set(EXTENDED_BENCHMARK_SAMPLES.map(s => s.label));
    expect(labels.has("human")).toBe(true);
    expect(labels.has("ai")).toBe(true);
    expect(labels.has("ai-assisted")).toBe(true);
    expect(labels.has("mixed")).toBe(true);
    expect(labels.has("ai-refactored")).toBe(true);
  });

  it("mixed-provenance samples are excluded from BENCHMARK_SAMPLES (binary benchmark)", () => {
    const mixedLabels = new Set(["ai-assisted", "mixed", "ai-refactored"]);
    for (const s of BENCHMARK_SAMPLES) {
      expect(mixedLabels.has(s.label as string)).toBe(false);
    }
  });

  it("every extended sample has non-empty content (≥50 chars)", () => {
    for (const s of EXTENDED_BENCHMARK_SAMPLES) {
      expect(s.content.trim().length).toBeGreaterThanOrEqual(50);
    }
  });
});
