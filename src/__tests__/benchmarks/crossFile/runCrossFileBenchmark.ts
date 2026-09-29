/**
 * Cross-file benchmark runner: scans every case in cases.ts through the real production pipeline (runScan,
 * all files of a case in one scan) and scores it.
 *
 *  - Positive case: detected when the expected file carries a data-flow finding with the expected id whose
 *    canonical evidence (DataFlowEvidence) crosses files and ends at a sink in the expected file. Any further
 *    data-flow finding with that id in the case is counted as a DUPLICATE -- the same issue reported twice.
 *  - Negative case: a false positive when a data-flow finding with that id appears where it must not.
 *
 * A "data-flow finding" is one with a traced source (sourceExpr), as opposed to a regex/keyword hit.
 */
import { runScan } from "@/lib/scanner";
import { CROSS_FILE_CASES, type CrossFileCase } from "./cases";

export type CaseOutcome = "tp" | "fn" | "tn" | "fp";

export interface CaseScore { name: string; language: string; outcome: CaseOutcome; duplicates: number }

export interface LanguageScore { tp: number; fn: number; tn: number; fp: number; duplicates: number; precision: number; recall: number }

export function scoreCase(c: CrossFileCase): CaseScore {
  const r = runScan({ repo: "benchmark/cross-file", pr_number: 1, commit_sha: "0000000", branch: "main", files: c.files });
  const flows = r.files.flatMap(f => f.indicators
    .filter(i => i.id === c.expect.id && i.sourceExpr)
    .map(i => ({ file: f.file_path, ind: i })));
  if (c.expect.kind === "tp") {
    const { file, sinkFile } = c.expect;
    const hit = flows.find(x => x.file === file && x.ind.flow?.crossesFiles && x.ind.flow.sink.file === sinkFile);
    return { name: c.name, language: c.language, outcome: hit ? "tp" : "fn", duplicates: hit ? flows.length - 1 : 0 };
  }
  const where = c.expect.file;
  const bad = flows.some(x => !where || x.file === where);
  return { name: c.name, language: c.language, outcome: bad ? "fp" : "tn", duplicates: 0 };
}

export function runCrossFileBenchmark(): { cases: CaseScore[]; byLanguage: Record<string, LanguageScore> } {
  const cases = CROSS_FILE_CASES.map(scoreCase);
  const byLanguage: Record<string, LanguageScore> = {};
  for (const s of cases) {
    const l = byLanguage[s.language] ??= { tp: 0, fn: 0, tn: 0, fp: 0, duplicates: 0, precision: 0, recall: 0 };
    l[s.outcome]++;
    l.duplicates += s.duplicates;
  }
  for (const l of Object.values(byLanguage)) {
    l.precision = l.tp + l.fp === 0 ? 1 : +(l.tp / (l.tp + l.fp)).toFixed(3);
    l.recall = l.tp + l.fn === 0 ? 1 : +(l.tp / (l.tp + l.fn)).toFixed(3);
  }
  return { cases, byLanguage };
}
