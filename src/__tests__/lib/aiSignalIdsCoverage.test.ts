import { AI_SIGNAL_IDS } from "@/lib/scanner";

// Regression for a real bug found while building the false-positive
// benchmark: jsdoc-completeness/zero-debug-artifacts/import-exhaustiveness
// were moved from CORE into SECONDARY AI-attribution signals (scanner.ts,
// see the comment above SECONDARY_SIGNALS) without also being added to
// AI_SIGNAL_IDS -- the set that strips AI-attribution explainability
// signals out of ScanSummary.total_security_findings/critical_count and the
// exploitability/reachability scorers. Before the fix, up to hundreds of
// AI-signal hits on a real corpus were silently counted as if they were
// vulnerabilities. ai-blast-radius (injected post-analyzeFile at the batch
// level, never a CWE finding) had the same gap.
describe("AI_SIGNAL_IDS — every AI-attribution signal id must be excludable from security-finding counts", () => {
  it.each([
    "jsdoc-completeness",
    "zero-debug-artifacts",
    "import-exhaustiveness",
    "ai-blast-radius",
  ])("includes %s", (id) => {
    expect(AI_SIGNAL_IDS.has(id)).toBe(true);
  });
});
