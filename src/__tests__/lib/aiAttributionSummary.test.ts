import { summarizeAIAttribution, MIN_ANALYSABLE_LINES } from "@/lib/aiAttributionSummary";
import { runScan } from "@/lib/scanner";

const f = (file_path: string, line_count: number, ai_percentage: number, scan_quality = 0.8) => ({ file_path, line_count, ai_percentage, scan_quality });
const none = () => false;

describe("summarizeAIAttribution", () => {
  it("weights each file by its lines (500 lines at 90%, 300 at 60%, 200 at 15% is 66%)", () => {
    // (450 + 180 + 30) / 1000 lines
    const s = summarizeAIAttribution([f("auth.ts", 500, 0.9), f("payment.ts", 300, 0.6), f("logger.ts", 200, 0.15)], none);
    expect(s.analyzed_loc).toBe(1000);
    expect(s.estimated_ai_loc).toBe(660);
    expect(s.estimated_ai_percentage).toBeCloseTo(0.66, 5);
  });

  it("a big file counts for more than a small one (not a plain average of file scores)", () => {
    const s = summarizeAIAttribution([f("big.ts", 900, 0.1), f("small.ts", 100, 0.9)], none);
    expect(s.estimated_ai_percentage).toBeCloseTo(0.18, 5);          // not (0.1+0.9)/2
  });

  it("code too short to judge is UNKNOWN: reported, not counted as human, and it lowers coverage", () => {
    const s = summarizeAIAttribution([f("a.ts", 100, 0.5), f("tiny.ts", MIN_ANALYSABLE_LINES, 0.0)], none);
    expect(s).toMatchObject({ unknown_loc: MIN_ANALYSABLE_LINES, analyzed_loc: 100, eligible_loc: 100 + MIN_ANALYSABLE_LINES });
    expect(s.estimated_ai_percentage).toBeCloseTo(0.5, 5);           // the tiny file did not drag it down
    expect(s.analysis_coverage).toBeCloseTo(100 / 120, 5);
  });

  it("config, data and generated files are excluded entirely", () => {
    const s = summarizeAIAttribution([f("a.ts", 100, 1), f("package-lock.json", 5000, 0), f("gen.ts", 800, 0)], p => p !== "a.ts");
    expect(s).toMatchObject({ excluded_loc: 5800, eligible_loc: 100, analyzed_loc: 100 });
    expect(s.estimated_ai_percentage).toBe(1);
    expect(s.analysis_coverage).toBe(1);
  });

  it("splits analysed lines into AI-leaning, mixed and human-leaning", () => {
    const s = summarizeAIAttribution([f("a.ts", 100, 0.7), f("b.ts", 200, 0.5), f("c.ts", 300, 0.29), f("d.ts", 400, 0.3)], none);
    expect(s).toMatchObject({ ai_leaning_loc: 100, mixed_loc: 600, human_leaning_loc: 300 });
  });

  it("splits analysed lines by how many signals applied (scan_quality)", () => {
    const s = summarizeAIAttribution([f("a.ts", 100, 0.5, 0.7), f("b.ts", 200, 0.5, 0.4), f("c.ts", 300, 0.5, 0.39)], none);
    expect(s).toMatchObject({ high_confidence_loc: 100, medium_confidence_loc: 200, low_confidence_loc: 300 });
  });

  it("nothing analysed is 0% with 0 coverage, never NaN", () => {
    for (const s of [summarizeAIAttribution([], none), summarizeAIAttribution([f("t.ts", 5, 1)], none), summarizeAIAttribution([f("x.json", 500, 1)], () => true)]) {
      expect(s.estimated_ai_percentage).toBe(0);
      expect(Number.isNaN(s.analysis_coverage)).toBe(false);
    }
    expect(summarizeAIAttribution([], none).analysis_coverage).toBe(0);
  });

  it("clamps out-of-range scores and ignores bad line counts", () => {
    const s = summarizeAIAttribution([f("a.ts", 100, 7), f("b.ts", 100, -3), f("c.ts", NaN, 0.5)], none);
    expect(s.estimated_ai_percentage).toBeCloseTo(0.5, 5);           // 100 @ 1 + 100 @ 0
    expect(s.analyzed_loc).toBe(200);
  });
});

describe("the scan reports it", () => {
  const long = (n: number) => Array.from({ length: n }, (_, i) => `export const value${i} = ${i};`).join("\n");
  it("runScan returns ai_attribution: source analysed, config excluded, tiny files unknown", () => {
    const r = runScan({
      repo: "o/r", pr_number: 1, commit_sha: "abc1234", branch: "main",
      files: [
        { path: "src/big.ts", content: long(60) },
        { path: "src/tiny.ts", content: "export const x = 1;" },
        { path: "package-lock.json", content: long(300) },
      ],
    });
    const a = r.ai_attribution!;
    expect(a.analyzed_loc).toBeGreaterThanOrEqual(60);
    expect(a.unknown_loc).toBeGreaterThan(0);
    expect(a.excluded_loc).toBeGreaterThanOrEqual(300);
    expect(a.eligible_loc).toBe(a.analyzed_loc + a.unknown_loc);
    expect(a.estimated_ai_percentage).toBeGreaterThanOrEqual(0);
    expect(a.estimated_ai_percentage).toBeLessThanOrEqual(1);
  });
  it("is deterministic: the same input gives the same attribution", () => {
    const input = { repo: "o/r", pr_number: 1, commit_sha: "abc1234", branch: "main", files: [{ path: "src/big.ts", content: long(80) }] };
    expect(runScan(input).ai_attribution).toEqual(runScan(input).ai_attribution);
  });
});

import { attributionSentence } from "@/lib/aiAttributionSummary";
describe("attributionSentence", () => {
  const sum = (files: Parameters<typeof summarizeAIAttribution>[0], excluded: (p: string) => boolean = () => false) => summarizeAIAttribution(files, excluded);
  it("says the share, what it rests on, and what was left out", () => {
    const a = sum([f("a.ts", 1000, 0.41), f("t.ts", 10, 0), f("lock.json", 5000, 0)], p => p === "lock.json");
    expect(attributionSentence(a)).toBe("41% of the 1,000 source lines analysed look AI-written · 10 lines too short to judge · 5,000 lines of config or generated files left out");
  });
  it("leaves out the clauses that do not apply, and uses the singular", () => {
    expect(attributionSentence(sum([f("a.ts", 100, 0.5)]))).toBe("50% of the 100 source lines analysed look AI-written");
    expect(attributionSentence(sum([f("a.ts", 100, 0.5), f("t.ts", 1, 0)]))).toContain("1 line too short to judge");
  });
  it("is null when nothing could be judged (or there is no summary), so callers fall back", () => {
    expect(attributionSentence(sum([f("t.ts", 5, 1)]))).toBeNull();
    expect(attributionSentence(null)).toBeNull();
    expect(attributionSentence(undefined)).toBeNull();
  });
});
