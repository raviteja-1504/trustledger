/**
 * @jest-environment node
 *
 * An engine that throws returns no findings; that must surface as a coverage gap (degraded scan), not as a clean file.
 */
import { recordEngineFailure, engineFailureSince } from "@/lib/taint/engineFailures";
import { summarizeHealth, describeHealth } from "@/lib/scanHealth";
import { warmRustTaintEngine, parseRustSourceSync, scanAstTaintRust } from "@/lib/astTaintRust";
import { warmCppTaintEngine, parseCppSourceSync, scanAstTaintCpp } from "@/lib/astTaintCpp";
import { warmKotlinTaintEngine, parseKotlinSourceSync, scanAstTaintKotlin } from "@/lib/astTaintKotlin";
import { warmRubyTaintEngine, parseRubySourceSync, scanAstTaintRuby } from "@/lib/astTaintRuby";

beforeAll(async () => { await Promise.all([warmRustTaintEngine(), warmCppTaintEngine(), warmKotlinTaintEngine(), warmRubyTaintEngine()]); }, 120000);

const boom = (real: unknown) => ({ get type(): string { throw new Error("boom"); }, real }) as never;

describe("failure registry", () => {
  it("returns a failure only at or after the given time, and analysis-failed wins over parse-failed", () => {
    const t0 = Date.now();
    recordEngineFailure("a.rs", "parse-failed");
    expect(engineFailureSince("a.rs", t0)).toBe("parse-failed");
    expect(engineFailureSince("a.rs", Date.now() + 1000)).toBeNull();
    recordEngineFailure("a.rs", "analysis-failed");
    recordEngineFailure("a.rs", "parse-failed");
    expect(engineFailureSince("a.rs", t0)).toBe("analysis-failed");
    expect(engineFailureSince("never-failed.rs", 0)).toBeNull();
  });
});

describe("engines record a thrown analysis", () => {
  const cases: Array<[string, string, () => void]> = [
    ["rust", "src/r.rs", () => scanAstTaintRust("fn main() {}", "src/r.rs", boom(parseRustSourceSync("fn main() {}", "src/r.rs")), [], {})],
    ["cpp", "src/c.cpp", () => scanAstTaintCpp("int main() {}", "src/c.cpp", boom(parseCppSourceSync("int main() {}", "src/c.cpp")))],
    ["kotlin", "A.kt", () => scanAstTaintKotlin("fun main() {}", "A.kt", boom(parseKotlinSourceSync("fun main() {}", "A.kt")), [], {})],
    ["ruby", "a.rb", () => scanAstTaintRuby("x = 1", "a.rb", boom(parseRubySourceSync("x = 1", "a.rb")), [])],
  ];
  it.each(cases)("%s", (_n, file, run) => {
    const t0 = Date.now();
    expect(engineFailureSince(file, t0)).toBeNull();
    run();
    expect(engineFailureSince(file, t0)).toBe("analysis-failed");
  });
});

describe("scan health", () => {
  it("a parse or analysis failure degrades the scan and is described", () => {
    const h = summarizeHealth([{ file: "a.rs", language: "rust", reason: "analysis-failed" }, { file: "b.rs", language: "rust", reason: "parse-failed" }], "v");
    expect(h.status).toBe("degraded");
    expect(h.gap_counts).toEqual({ "analysis-failed": 1, "parse-failed": 1 });
    const text = describeHealth(h);
    expect(text).toMatch(/could not be parsed/);
    expect(text).toMatch(/analysis failed on 1 file/);
  });
  it("by-design limits alone stay partial, and no gaps is complete", () => {
    expect(summarizeHealth([{ file: "x.js", language: "javascript", reason: "too-large" }], "v").status).toBe("partial");
    expect(summarizeHealth([], "v").status).toBe("complete");
  });
});
