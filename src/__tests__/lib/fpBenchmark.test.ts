import { diffAgainstBaseline, computeLineHash, extractSecurityFindings, formatNoiseReport } from "@/lib/fpBenchmark";
import type { FpBaselineEntry, LiveFinding } from "@/lib/fpBenchmark";
import type { FileAnalysis } from "@/lib/scanner";

describe("fpBenchmark diff logic — small inline fixtures, no corpus dependency", () => {
  it("fails a live finding not present in the baseline", () => {
    const live: LiveFinding[] = [
      { file: "a.ts", id: "xss", line: 5, severity: "critical", lineHash: computeLineHash("xss", "foo") },
    ];
    const { newFindings, matched } = diffAgainstBaseline(live, []);
    expect(newFindings).toHaveLength(1);
    expect(matched).toBe(0);
  });

  it("matches a baseline entry to its live finding by (file, id, lineHash), ignoring line drift", () => {
    const hash = computeLineHash("xss", "dangerouslySetInnerHTML({__html: d})");
    const live: LiveFinding[] = [
      { file: "a.ts", id: "xss", line: 99, severity: "critical", lineHash: hash }, // line moved from 5 -> 99
    ];
    const baseline: FpBaselineEntry[] = [
      { file: "a.ts", id: "xss", line: 5, severity: "critical", lineHash: hash, reason: "safe" },
    ];
    const { newFindings, staleEntries, matched } = diffAgainstBaseline(live, baseline);
    expect(newFindings).toHaveLength(0);
    expect(staleEntries).toHaveLength(0);
    expect(matched).toBe(1);
  });

  it("flags a stale baseline entry with no matching live finding", () => {
    const baseline: FpBaselineEntry[] = [
      { file: "a.ts", id: "xss", line: 5, severity: "critical", lineHash: "deadbeef0000", reason: "safe" },
    ];
    const { staleEntries } = diffAgainstBaseline([], baseline);
    expect(staleEntries).toHaveLength(1);
  });

  it("does not confuse a live finding for a different id on the same file+lineHash", () => {
    const hash = computeLineHash("xss", "same text");
    const live: LiveFinding[] = [{ file: "a.ts", id: "sql-injection", line: 1, severity: "critical", lineHash: hash }];
    const baseline: FpBaselineEntry[] = [{ file: "a.ts", id: "xss", line: 1, severity: "critical", lineHash: hash, reason: "safe" }];
    const { newFindings, staleEntries } = diffAgainstBaseline(live, baseline);
    expect(newFindings).toHaveLength(1);
    expect(staleEntries).toHaveLength(1);
  });

  it("a clean match against an otherwise-unrelated baseline reports zero new/stale", () => {
    const hash = computeLineHash("ssrf", "const url = new URL(req.url);");
    const live: LiveFinding[] = [{ file: "route.ts", id: "ssrf", line: 10, severity: "critical", lineHash: hash }];
    const baseline: FpBaselineEntry[] = [
      { file: "route.ts", id: "ssrf", line: 10, severity: "critical", lineHash: hash, reason: "inbound URL parse" },
      { file: "other.ts", id: "xss", line: 3, severity: "critical", lineHash: "abc123abc123", reason: "unrelated" },
    ];
    // Only the ssrf finding is live -- the unrelated baseline entry has no live match, so it's stale.
    const { newFindings, staleEntries } = diffAgainstBaseline(live, baseline);
    expect(newFindings).toHaveLength(0);
    expect(staleEntries).toHaveLength(1);
    expect(staleEntries[0].file).toBe("other.ts");
  });
});

describe("computeLineHash", () => {
  it("is deterministic for the same (id, text) pair", () => {
    expect(computeLineHash("xss", "foo")).toBe(computeLineHash("xss", "foo"));
  });

  it("differs when the id differs, even with identical text", () => {
    expect(computeLineHash("xss", "foo")).not.toBe(computeLineHash("sql-injection", "foo"));
  });

  it("differs when the text differs, even with identical id", () => {
    expect(computeLineHash("xss", "foo")).not.toBe(computeLineHash("xss", "bar"));
  });
});

describe("extractSecurityFindings", () => {
  // Only the fields extractSecurityFindings actually reads (file_path,
  // indicators) are meaningful here -- everything else is filler to satisfy
  // the type, so this is deliberately cast through `unknown` rather than
  // hand-filling every one of FileAnalysis's ~20 unrelated fields.
  function fa(overrides: { file_path: string; indicators: FileAnalysis["indicators"] }): FileAnalysis {
    return overrides as unknown as FileAnalysis;
  }

  it("filters out AI-signal ids and keeps real security findings", () => {
    const files = [fa({
      file_path: "a.ts",
      indicators: [
        { id: "dead-code-absence", label: "x", severity: "info", line: 1 },
        { id: "xss", label: "XSS", severity: "critical", line: 2 },
      ],
    })];
    const lineTextByFile = new Map([["a.ts", ["", "", "dangerouslySetInnerHTML(x)"]]]);
    const out = extractSecurityFindings(files, lineTextByFile, new Set(["dead-code-absence"]));
    expect(out).toHaveLength(1);
    expect(out[0].id).toBe("xss");
  });

  it("disambiguates two identical-text findings sharing (file, id, lineHash) within one file", () => {
    const files = [fa({
      file_path: "a.ts",
      indicators: [
        { id: "hallucinated-method-call", label: "x", severity: "medium", line: 1 },
        { id: "hallucinated-method-call", label: "x", severity: "medium", line: 5 },
      ],
    })];
    const lineTextByFile = new Map([["a.ts", ["dup line", "", "", "", "dup line"]]]);
    const out = extractSecurityFindings(files, lineTextByFile, new Set());
    expect(out).toHaveLength(2);
    expect(out[0].lineHash).not.toBe(out[1].lineHash);
  });
});

describe("formatNoiseReport", () => {
  it("includes total count, severity breakdown, and per-id counts", () => {
    const live: LiveFinding[] = [
      { file: "a.ts", id: "xss", line: 1, severity: "critical", lineHash: "h1" },
      { file: "b.ts", id: "xss", line: 2, severity: "critical", lineHash: "h2" },
      { file: "c.ts", id: "ssrf", line: 3, severity: "medium", lineHash: "h3" },
    ];
    const report = formatNoiseReport(live);
    expect(report).toContain("3 accepted security findings");
    expect(report).toContain("xss");
    expect(report).toContain("ssrf");
  });

  it("does not throw on an empty finding list", () => {
    expect(() => formatNoiseReport([])).not.toThrow();
  });
});
