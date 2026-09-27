// ── Which functions get SSA taint analysis ───────────────────────────────────
//
// SSA construction (dominators, phi insertion, renaming) is the most expensive per-function analysis analyzeFile
// runs, so it is applied to a bounded subset of a file's functions. The subset used to be "the 3 most complex":
// a proxy for "the interesting ones" that has nothing to do with security. Real handlers are frequently SHORT
// (`app.get("/x", (req, res) => db.query(req.query.id))` is complexity 1) while utility code -- parsers,
// formatters, state machines -- is where cyclomatic complexity lives. In a file with a handful of complex
// helpers, the one function that actually holds a finding was routinely never analyzed, and its data-flow
// path (which cross-file exposure detection and the PR view consume) was silently missing.
//
// So selection is ranked by SECURITY EXPOSURE first and complexity only as the tiebreak:
//   1. functions that contain a security finding, weighted by severity (a critical outranks any number of lows);
//   2. then complexity, then source order -- deterministic, never dependent on hash/iteration order.
// A finding is attributed to its INNERMOST enclosing function only: crediting every enclosing function would
// spend the budget re-analyzing the outer body once per nested closure.
//
// The cost bound moved from a function COUNT to a LINE budget, because SSA's cost scales with body size, not with
// how many functions there are. Three 900-line functions are far more expensive than eight 40-line ones.

import type { FunctionInfo } from "./ast";

export interface SsaFinding {
  /** 1-based line of the finding; findings without a line (file-level signals) never select a function. */
  line?: number;
  severity: "critical" | "high" | "medium" | "low" | "info";
}

/** Upper bound on functions analyzed per file. Higher than the old 3: only finding-bearing functions and the
 * complexity tiebreak compete for it, and the line budget below is the real cost control. */
export const SSA_MAX_FUNCTIONS = 8;
/** Total function-body lines SSA is willing to build per file. */
export const SSA_LINE_BUDGET = 1500;
/** A single function above this is never analyzed (SSA construction is superlinear in body size). */
export const SSA_MAX_FUNCTION_LINES = 800;

const SEVERITY_WEIGHT: Record<SsaFinding["severity"], number> = { critical: 8, high: 4, medium: 2, low: 1, info: 0 };

const spanOf = (f: FunctionInfo): number => f.endLine - f.line;

/** The innermost function whose [line, endLine] range contains `line`, or null. Ties (identical range) go to the
 * earlier-declared one, so the result is order-independent for equal spans. */
function innermostContaining(functions: readonly FunctionInfo[], line: number): FunctionInfo | null {
  let best: FunctionInfo | null = null;
  for (const f of functions) {
    if (line < f.line || line > f.endLine) continue;
    if (!best || spanOf(f) < spanOf(best) || (spanOf(f) === spanOf(best) && f.line < best.line)) best = f;
  }
  return best;
}

export function selectSsaFunctions(
  functions: readonly FunctionInfo[], findings: readonly SsaFinding[],
  limits: { maxFunctions?: number; lineBudget?: number; maxFunctionLines?: number } = {},
): FunctionInfo[] {
  const maxFunctions = limits.maxFunctions ?? SSA_MAX_FUNCTIONS;
  const lineBudget = limits.lineBudget ?? SSA_LINE_BUDGET;
  const maxFunctionLines = limits.maxFunctionLines ?? SSA_MAX_FUNCTION_LINES;

  const exposure = new Map<FunctionInfo, number>();
  for (const finding of findings) {
    const w = SEVERITY_WEIGHT[finding.severity];
    if (!finding.line || w === 0) continue;
    const owner = innermostContaining(functions, finding.line);
    if (owner) exposure.set(owner, (exposure.get(owner) ?? 0) + w);
  }

  const ranked = [...functions]
    .filter(f => spanOf(f) <= maxFunctionLines)
    .sort((a, b) => {
      const ea = exposure.get(a) ?? 0, eb = exposure.get(b) ?? 0;
      if ((ea > 0) !== (eb > 0)) return ea > 0 ? -1 : 1;     // any finding-bearing function beats any without
      if (ea !== eb) return eb - ea;
      if (a.complexity !== b.complexity) return b.complexity - a.complexity;
      return a.line - b.line;
    });

  const chosen: FunctionInfo[] = [];
  let lines = 0;
  for (const f of ranked) {
    if (chosen.length >= maxFunctions) break;
    const cost = Math.max(1, spanOf(f));
    if (lines + cost > lineBudget) continue;                 // a smaller, lower-ranked function may still fit
    chosen.push(f);
    lines += cost;
  }
  return chosen;
}
