import { analyzeFile } from "@/lib/scanner";

describe("function-level AI scoring", () => {
  it("scores functions independently rather than duplicating the file-level score", () => {
    const content = `
// ── Type definitions ──────────────────────────────────────────────────
interface ProcessResult {
  success: boolean;
  message: string;
}

/**
 * Validates the input payload against the expected schema.
 * @param payload - The payload to validate
 * @returns The validation result
 */
async function validatePayload(payload: unknown): Promise<ProcessResult> {
  // First, we check that the payload is not null or undefined
  if (!payload) {
    return { success: false, message: "Payload is required" };
  }
  // Then, we ensure the payload has the correct shape
  if (typeof payload !== "object") {
    return { success: false, message: "Payload must be an object" };
  }
  // Finally, we return a successful result
  return { success: true, message: "Payload is valid" };
}

function doStuff(x, y) {
  // dont ask why this works, spent 3 hrs on this lol
  var z = x + y
  if (z > 10) {
    console.log("big!!", z) // TODO fix this later
  }
  return z
}
`.repeat(1);

    const result = analyzeFile("src/example.ts", content);

    expect(result.function_scores.length).toBeGreaterThanOrEqual(2);
    const names = result.function_scores.map(f => f.name);
    expect(names).toContain("validatePayload");
    expect(names).toContain("doStuff");

    const validateScore = result.function_scores.find(f => f.name === "validatePayload")!;
    const doStuffScore   = result.function_scores.find(f => f.name === "doStuff")!;

    // Scores must be independently computed per function, not both equal to
    // the file-level score (which would indicate the slicing did nothing),
    // and the direction should match: the verbose-docstring/step-comment
    // function should score higher than the typo-ridden/informal one.
    expect(validateScore.ai_percentage).not.toBe(doStuffScore.ai_percentage);
    expect(validateScore.ai_percentage).toBeGreaterThan(doStuffScore.ai_percentage);
  });

  it("excludes trivial functions below the minimum line threshold", () => {
    const content = `
function bigEnoughFunction() {
  const a = 1;
  const b = 2;
  const c = 3;
  const d = 4;
  return a + b + c + d;
}

function tiny() { return 1; }
`.repeat(1);

    const result = analyzeFile("src/tiny.ts", content);
    const names = result.function_scores.map(f => f.name);
    expect(names).not.toContain("tiny");
  });

  it("returns an empty array for files where AI scoring is skipped (e.g. config/generated files)", () => {
    const result = analyzeFile("package-lock.json", "{}".repeat(100));
    expect(result.function_scores).toEqual([]);
  });

  it("caps the number of scored functions for pathological files", () => {
    const manyFunctions = Array.from({ length: 60 }, (_, i) => `
function fn${i}() {
  const a = 1;
  const b = 2;
  const c = 3;
  return a + b + c;
}`).join("\n");

    const result = analyzeFile("src/generated.ts", manyFunctions);
    expect(result.function_scores.length).toBeLessThanOrEqual(40);
  });
});
