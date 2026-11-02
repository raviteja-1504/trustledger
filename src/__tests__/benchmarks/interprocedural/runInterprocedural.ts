/**
 * Scores the advanced interprocedural suite (cases.ts) through the production pipeline (runScan, one file per
 * case), by the suite's own rule:
 *
 *   PASS     a data-flow finding with an expected id at the sink line, whose trace starts at the source line and
 *            passes through every expected step line;
 *   PARTIAL  a finding with an expected id at the sink line, but the trace is missing (a pattern rule) or misses
 *            the source or a step;
 *   MISS     nothing at the sink line.
 *
 * The safe twin (the source replaced by a constant) must carry no data-flow finding with an expected id.
 */
import fs from "fs";
import path from "path";
import { runScan, type ScanIndicator } from "@/lib/scanner";
import { INTERPROCEDURAL_CASES, type InterproceduralCase } from "./cases";

export type Outcome = "pass" | "partial" | "miss";
export interface CaseResult { id: string; outcome: Outcome; twin: "clean" | "fp"; missing: string[]; detail: string }

const FIXTURES = path.join(__dirname, "fixtures");

export function fixtureSource(c: InterproceduralCase): string {
  const file = fs.readdirSync(FIXTURES).find(f => f.startsWith(`${c.id}.`))!;
  return fs.readFileSync(path.join(FIXTURES, file), "utf8").replace(/\r\n/g, "\n");
}

/** 1-based line of the first line containing `snippet`. */
export function lineOf(code: string, snippet: string): number {
  const i = code.split("\n").findIndex(l => l.includes(snippet));
  if (i < 0) throw new Error(`snippet not found: ${snippet}`);
  return i + 1;
}

function findings(c: InterproceduralCase, code: string): ScanIndicator[] {
  const r = runScan({ repo: "benchmark/interprocedural", pr_number: 1, commit_sha: "0000000", branch: "main", files: [{ path: c.path, content: code }] });
  return r.files.flatMap(f => f.indicators).filter(i => c.ids.includes(i.id));
}

export function scoreCase(c: InterproceduralCase): CaseResult {
  const code = fixtureSource(c);
  const sinkLine = lineOf(code, c.sink), sourceLine = lineOf(code, c.source);
  const atSink = findings(c, code).filter(i => i.line === sinkLine);
  const flows = atSink.filter(i => i.trace?.length);
  // the most complete trace at the sink
  const missingFor = (i: ScanIndicator) => {
    const lines = new Set((i.trace ?? []).map(s => s.line));
    const miss: string[] = [];
    if ((i.trace ?? [])[0]?.line !== sourceLine) miss.push(`source: ${c.source}`);
    for (const s of c.steps) if (!lines.has(lineOf(code, s))) miss.push(`step: ${s}`);
    return miss;
  };
  const best = flows.map(i => ({ i, miss: missingFor(i) })).sort((a, b) => a.miss.length - b.miss.length)[0];
  const outcome: Outcome = best && best.miss.length === 0 ? "pass" : atSink.length ? "partial" : "miss";
  const missing = best ? best.miss : atSink.length ? ["no trace (pattern rule)"] : ["no finding at the sink"];
  const detail = best ? (best.i.trace ?? []).map(s => `${s.kind}@${s.line}`).join(" > ") : atSink.map(i => i.id).join(",");

  // safe twin: the source replaced by a constant
  const twinCode = code.replace(c.source, c.constant);
  const twinFlows = findings(c, twinCode).filter(i => i.trace?.length);
  return { id: c.id, outcome, twin: twinFlows.length ? "fp" : "clean", missing, detail };
}

export function runInterprocedural(): CaseResult[] {
  return INTERPROCEDURAL_CASES.map(scoreCase);
}
