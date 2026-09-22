/**
 * Shared benchmark runner (P0 "benchmark + regression framework"): scans one hard-benchmark fixture
 * through the REAL production pipeline (runScan) and groups its indicators by benchmark CASE, using
 * the same "nearest preceding `// NN` / `# NN` / `bonusNN` comment" convention every language's
 * fixture already follows (mirrors the scratchpad `lang_table.js` grouping script this was built
 * from, now a committed, versioned part of the repo instead of an ephemeral one-off).
 *
 * Each fixture is 60 numbered cases (`// 01` .. `// 60`, or `# 01` for Python) plus up to 7
 * language-specific bonus cases (`bonus01` .. `bonus07`), one real vulnerability pattern per case --
 * see any fixture's own header comment for the full convention. A case "has a finding" when at least
 * one indicator (from any detector, AST or regex) lands on a line whose nearest preceding case marker
 * is that case.
 */
import { runScan } from "@/lib/scanner";
import fs from "fs";
import path from "path";

export interface CaseResult {
  /** Every finding id that fired anywhere within this case, from ANY detector. */
  ids: Set<string>;
  /** The subset of `ids` that came from an AST data-flow match (confidence 95) rather than a
   * regex/keyword detector -- the more precise, higher-value signal this whole multi-phase effort
   * was built to grow. */
  astOnlyIds: Set<string>;
}

export interface BenchmarkReport {
  language: string;
  /** case label ("01".."60", "bonus01".."bonus07") -> what fired in it. */
  cases: Map<string, CaseResult>;
  /** Every case label the fixture defines, in file order -- lets a caller distinguish "no finding"
   * from "case doesn't exist". */
  caseOrder: string[];
  /** Ids that fired OUTSIDE any numbered case (shared helper functions near the top of the fixture,
   * before the first case marker) -- reported separately since they can't be attributed to one case. */
  outsideCaseIds: Set<string>;
}

// `// 01` / `# 01` (Python) / `/* 01 ...` (a block-comment opener, the JS/TS fixture's own
// convention) / a continuation `* 01` line inside one.
const CASE_MARKER_RE = /^\s*(?:\/\/|#|\/?\*)\s*(\d{2})\b/;
const BONUS_MARKER_RE = /\bbonus(\d{2})\b/i;

/** The case label a 1-based source line belongs to: the nearest `// NN`/`# NN`/`bonusNN` comment at
 * or before that line, scanning backward -- identical convention to every fixture's own header. */
function caseLabelForLine(sourceLines: string[], line1: number): string | null {
  for (let i = line1 - 1; i >= 0; i--) {
    const l = sourceLines[i];
    const bonus = l.match(BONUS_MARKER_RE);
    if (bonus) return `bonus${bonus[1]}`;
    const m = l.match(CASE_MARKER_RE);
    if (m) return m[1];
  }
  return null;
}

/** Every case label the fixture defines, in file order (used to report "no finding" cases too, not
 * just ones that fired). */
function collectCaseOrder(sourceLines: string[]): string[] {
  const labels: string[] = [];
  for (const l of sourceLines) {
    const bonus = l.match(BONUS_MARKER_RE);
    if (bonus) { labels.push(`bonus${bonus[1]}`); continue; }
    const m = l.match(CASE_MARKER_RE);
    if (m) labels.push(m[1]);
  }
  return labels;
}

export function runBenchmark(
  language: string, fixtureFile: string, syntheticPath: string,
  // Every AST wrapper across every engine sets EXACTLY 95 for a true AST data-flow match (see any
  // findAstTaint*Findings in scanner.ts) -- with one documented exception: Java's entry-point tier
  // (an un-annotated public method param with no in-file caller, still a real AST match, just less
  // certain the param is genuinely untrusted) reports 70. A regex/keyword detector's OWN confidence
  // formula (baseConfidence) can independently land anywhere up to 98, so this can't just be "any
  // finding with high confidence" -- it has to match one of the wrapper's own known literal values.
  astConfidenceValues: readonly number[] = [95],
): BenchmarkReport {
  const content = fs.readFileSync(path.join(__dirname, "fixtures", fixtureFile), "utf-8");
  const sourceLines = content.split("\n");
  const result = runScan({
    repo: "benchmark/fixtures", pr_number: 1, commit_sha: "0000000", branch: "main",
    files: [{ path: syntheticPath, content }],
  });
  const file = result.files.find(f => f.file_path === syntheticPath);
  const cases = new Map<string, CaseResult>();
  const outsideCaseIds = new Set<string>();
  const ensure = (label: string): CaseResult => {
    let c = cases.get(label);
    if (!c) { c = { ids: new Set(), astOnlyIds: new Set() }; cases.set(label, c); }
    return c;
  };
  for (const ind of file?.indicators ?? []) {
    if (!ind.line || ind.id.startsWith("ai-") || ind.id === "style-drift") continue;
    const label = caseLabelForLine(sourceLines, ind.line);
    if (!label) { outsideCaseIds.add(ind.id); continue; }
    const c = ensure(label);
    c.ids.add(ind.id);
    if (ind.confidence !== undefined && astConfidenceValues.includes(ind.confidence)) c.astOnlyIds.add(ind.id);
  }
  return { language, cases, caseOrder: collectCaseOrder(sourceLines), outsideCaseIds };
}

/** Summary numbers a regression test compares against the committed baseline. */
export interface BenchmarkSummary {
  totalCases: number;
  casesWithFinding: number;
  astOnlyFindingCount: number;
  /** case label -> sorted finding ids, AST-derived (confidence 95) only -- the precise part of the
   * report a regression test diffs case-by-case, not just the aggregate counts. */
  astOnlyByCase: Record<string, string[]>;
}

export function summarize(report: BenchmarkReport): BenchmarkSummary {
  const astOnlyByCase: Record<string, string[]> = {};
  let astOnlyFindingCount = 0;
  let casesWithFinding = 0;
  for (const label of report.caseOrder) {
    const c = report.cases.get(label);
    if (c && c.ids.size > 0) casesWithFinding++;
    if (c && c.astOnlyIds.size > 0) {
      astOnlyByCase[label] = [...c.astOnlyIds].sort();
      astOnlyFindingCount += c.astOnlyIds.size;
    }
  }
  return { totalCases: report.caseOrder.length, casesWithFinding, astOnlyFindingCount, astOnlyByCase };
}
