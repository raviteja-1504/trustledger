import { runScan } from "@/lib/scanner";
import type { ScanIndicator } from "@/lib/scanner";

const ID = "ai-blast-radius";

// Verbose, heavily-commented, defensively-typed style -- the same shape
// that reliably scores well above the AI% ensemble's thresholds elsewhere
// in this test suite (see aiAttributionBenchmark.fixtures.ts's AI-labeled
// samples, which score 50-80%+ with this style).
function aiStyleContent(exportName: string): string {
  return `import { z } from "zod";

/**
 * Result of a validation operation.
 */
export interface ValidationResult<T> {
  success: boolean;
  data?: T;
  error?: string;
}

/**
 * Schema for validating an incoming request payload.
 */
const requestSchema = z.object({
  id: z.string().min(1),
  amount: z.number().positive(),
  currency: z.string().length(3),
});

export type RequestInput = z.infer<typeof requestSchema>;

/**
 * Validates a request payload against the schema.
 *
 * @param input - The raw input to validate.
 * @returns A ValidationResult containing the parsed data or an error message.
 */
export function ${exportName}(input: unknown): ValidationResult<RequestInput> {
  try {
    const data = requestSchema.parse(input);
    return { success: true, data };
  } catch (error) {
    if (error instanceof z.ZodError) {
      return { success: false, error: error.errors.map((e) => e.message).join(", ") };
    }
    console.error("Unexpected error during validation:", error);
    return { success: false, error: "An unexpected error occurred during validation." };
  }
}

/**
 * Helper function to check whether the given amount is within acceptable
 * bounds for processing.
 *
 * @param amount - The amount to check.
 * @returns True if the amount is acceptable, false otherwise.
 */
export function isAcceptableAmount(amount: number): boolean {
  if (!amount || amount <= 0) {
    return false;
  }
  return amount < 1000000;
}
`;
}

const SIMPLE_HUMAN_CONTENT = `export function add(x: number, y: number): number {
  return x + y;
}

export function subtract(x: number, y: number): number {
  return x - y;
}
`;

function findings(files: { file_path: string; indicators: ScanIndicator[] }[], path: string) {
  const f = files.find(x => x.file_path === path)!;
  return f.indicators.filter(i => i.id === ID);
}

describe("AI blast radius -- real graph reach", () => {
  it("flags an AI-heavy file imported by another file in the same PR", () => {
    const source = aiStyleContent("validateRequest");
    const importer = `
import { validateRequest } from "./userService";

export function handleRequest(req) {
  return validateRequest(req.body);
}
`.trim();

    const result = runScan({
      repo: "test/blast-radius", pr_number: 1, commit_sha: "abc1234", branch: "main",
      files: [
        { path: "src/userService.ts", content: source },
        { path: "src/handler.ts", content: importer },
      ],
    });

    const hits = findings(result.files, "src/userService.ts");
    expect(hits.length).toBeGreaterThan(0);
    expect(hits[0].detail).toContain("src/handler.ts");
    expect(hits[0].severity).toBe("medium");

    const sourceFile = result.files.find(f => f.file_path === "src/userService.ts")!;
    expect(sourceFile.risk_score).not.toBe("LOW");
  });
});

describe("AI blast radius -- path-based criticality proxy", () => {
  it("flags an AI-heavy file at a sensitive path with no importers in this PR", () => {
    const source = aiStyleContent("validatePayment");

    const result = runScan({
      repo: "test/blast-radius-path", pr_number: 1, commit_sha: "abc1234", branch: "main",
      files: [{ path: "src/payment/processor.ts", content: source }],
    });

    const hits = findings(result.files, "src/payment/processor.ts");
    expect(hits.length).toBeGreaterThan(0);
    expect(hits[0].detail).toContain("sensitive area");
    expect(hits[0].detail).toContain("payment");
  });
});

describe("AI blast radius -- true negatives", () => {
  it("does not flag an AI-heavy file at a boring path with no importers", () => {
    const source = aiStyleContent("validateFormat");

    const result = runScan({
      repo: "test/blast-radius-negative", pr_number: 1, commit_sha: "abc1234", branch: "main",
      files: [{ path: "src/utils/format.ts", content: source }],
    });

    expect(findings(result.files, "src/utils/format.ts")).toHaveLength(0);
  });

  it("does not flag a low-AI file even when imported by another file", () => {
    const importer = `
import { add } from "./simple";

export function total(a, b) {
  return add(a, b);
}
`.trim();

    const result = runScan({
      repo: "test/blast-radius-lowai", pr_number: 1, commit_sha: "abc1234", branch: "main",
      files: [
        { path: "src/simple.ts", content: SIMPLE_HUMAN_CONTENT },
        { path: "src/total.ts", content: importer },
      ],
    });

    expect(findings(result.files, "src/simple.ts")).toHaveLength(0);
  });
});
