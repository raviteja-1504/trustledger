/**
 * False-positive benchmark — diff/report logic shared by the corpus-scanning
 * regression test (fpBenchmarkCorpus.benchmark.test.ts) and its own fast
 * unit tests (fpBenchmark.test.ts). Not a detector itself -- this is the
 * mechanism that decides "is this finding already known and accepted, or is
 * it new noise that needs a human to look at it," mirroring the standard
 * SAST baseline/allowlist pattern (Semgrep --baseline, Bandit baseline,
 * CodeQL suppression all work this way).
 */

import crypto from "crypto";
import type { FileAnalysis } from "./scanner";

export interface FpBaselineEntry {
  file:     string; // repo-relative, forward-slash
  id:       string; // ScanIndicator.id
  lineHash: string; // computeLineHash(id, trimmedLineText) -- the real matching key
  line:     number; // last-known line number -- display/debugging ONLY, never matched on
  severity: string; // last-known severity -- informational
  reason:   string; // REQUIRED: why this is accepted, human-reviewable
}

export interface LiveFinding {
  file:     string;
  id:       string;
  line?:    number;
  severity: string;
  detail?:  string;
  lineHash: string;
}

export interface FpDiffResult {
  newFindings:  LiveFinding[]; // in live, not in baseline -> hard fail
  staleEntries: FpBaselineEntry[]; // in baseline, not in live -> hard fail
  matched:      number; // sanity/reporting count
}

/**
 * A short, stable hash of (id, matched-line-text) -- deliberately NOT keyed
 * on the line NUMBER, which drifts on every unrelated edit to a file. This
 * is the real identity of a baseline entry; `line` is kept only for
 * human-readable display.
 */
export function computeLineHash(id: string, trimmedLineText: string): string {
  return crypto.createHash("sha256").update(`${id}::${trimmedLineText}`).digest("hex").slice(0, 12);
}

/**
 * Extracts every non-AI-signal finding from a batch of FileAnalysis results
 * into the flat LiveFinding shape the diff logic operates on. `lineTextByFile`
 * supplies each file's source lines (ScanIndicator only carries a line
 * NUMBER, not the matched text) -- callers already have file content in
 * memory from building ScanInput.files, so this is a cheap lookup, not a
 * re-read.
 *
 * Two findings sharing the same (file, id, lineHash) -- e.g. an identical
 * pattern repeated verbatim on two different lines of the same id -- would
 * otherwise collapse to one baseline key and silently under-count; an
 * occurrence index is appended to the hash for the 2nd+ occurrence within a
 * file so each still needs its own baseline entry.
 */
export function extractSecurityFindings(
  files: FileAnalysis[],
  lineTextByFile: Map<string, string[]>,
  aiSignalIds: Set<string>,
): LiveFinding[] {
  const out: LiveFinding[] = [];
  const occurrenceCount = new Map<string, number>(); // file::id::hash -> count seen so far

  for (const fa of files) {
    const lines = lineTextByFile.get(fa.file_path) ?? [];
    for (const ind of fa.indicators) {
      if (aiSignalIds.has(ind.id)) continue;
      const trimmedLineText = ind.line ? (lines[ind.line - 1] ?? "").trim() : "";
      let hash = computeLineHash(ind.id, trimmedLineText);
      const baseKey = `${fa.file_path}::${ind.id}::${hash}`;
      const seenBefore = occurrenceCount.get(baseKey) ?? 0;
      if (seenBefore > 0) hash = `${hash}-${seenBefore}`;
      occurrenceCount.set(baseKey, seenBefore + 1);

      out.push({
        file: fa.file_path, id: ind.id, line: ind.line, severity: ind.severity,
        detail: ind.detail, lineHash: hash,
      });
    }
  }
  return out;
}

function key(e: { file: string; id: string; lineHash: string }): string {
  return `${e.file}::${e.id}::${e.lineHash}`;
}

/**
 * New findings (live, not in baseline) and stale entries (baseline, no
 * longer produced live) both hard-fail in the corpus test -- mirroring
 * bigRepoScan.test.ts's existing unconditional-throw regression-floor
 * precedent, the only one this codebase has for this class of check. A
 * warn-only staleness policy is exactly how baselines rot into meaningless
 * allowlists over time.
 */
export function diffAgainstBaseline(live: LiveFinding[], baseline: FpBaselineEntry[]): FpDiffResult {
  const baseByKey = new Map(baseline.map(e => [key(e), e]));
  const liveByKey = new Map(live.map(f => [key(f), f]));

  const newFindings = live.filter(f => !baseByKey.has(key(f)));
  const staleEntries = baseline.filter(e => !liveByKey.has(key(e)));
  return { newFindings, staleEntries, matched: live.length - newFindings.length };
}

/** Aggregate, trackable "noise floor" -- printed unconditionally (even on a
 * clean pass) so the current count is always visible in CI logs, separate
 * from the pass/fail gate itself. */
export function formatNoiseReport(live: LiveFinding[]): string {
  const bySeverity: Record<string, number> = {};
  const byId: Record<string, number> = {};
  for (const f of live) {
    bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
    byId[f.id] = (byId[f.id] ?? 0) + 1;
  }
  const idRows = Object.entries(byId)
    .sort((a, b) => b[1] - a[1])
    .map(([id, n]) => `    ${id.padEnd(28)} ${n}`)
    .join("\n");
  return [
    `FP benchmark noise floor — ${live.length} accepted security findings in the src/ corpus`,
    `  By severity: ${JSON.stringify(bySeverity)}`,
    `  By id:`,
    idRows,
  ].join("\n");
}
