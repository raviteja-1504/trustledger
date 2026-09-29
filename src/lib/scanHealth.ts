/**
 * Scan health and telemetry: how complete a scan's analysis really was, and where its time went.
 *
 * The data-flow engines skip a file rather than fail the scan -- a language parser that hasn't finished
 * loading (a cold serverless start), a file over the AST line cap, minified/generated code, or content that
 * could not be fetched. Each skip is correct on its own, but invisible: the file silently gets pattern-level
 * analysis only. This module records every such gap so a scan can say what it did NOT fully analyze.
 *
 *  - "degraded": something that should have been analyzed wasn't -- an engine was unavailable or content was
 *    missing. Transient; a rescan normally fixes it.
 *  - "partial": only by-design limits (too large, minified/generated). A rescan won't change it.
 *  - "complete": every scanned file got the full analysis its language supports.
 *
 * Client-safe: no imports.
 */

export type CoverageGapReason = "engine-unavailable" | "content-unavailable" | "too-large" | "minified-or-generated";

export interface CoverageGap { file: string; language: string; reason: CoverageGapReason }

export type ScanHealthStatus = "complete" | "partial" | "degraded";

export interface ScanHealth {
  status: ScanHealthStatus;
  /** The analysis engine that produced this scan -- compared with the current one to offer a rescan. */
  engine_version: string;
  gap_counts: Partial<Record<CoverageGapReason, number>>;
  /** Languages whose data-flow engine was not loaded when the scan ran. */
  engines_unavailable: string[];
  /** The gaps themselves, capped (see MAX_GAPS). */
  gaps: CoverageGap[];
}

export interface ScanTelemetry {
  engine_version: string;
  total_ms: number;
  /** Cross-file preparation before per-file analysis (import graph, summaries, service facts). */
  cross_file_ms: number;
  /** Per-file analysis, summed. */
  per_file_ms: number;
  /** Everything after per-file analysis (semantic graph, correlation, scoring). */
  post_ms: number;
  files_analyzed: number;
  files_reused: number;
  slowest: Array<{ file: string; ms: number }>;
}

export const MAX_GAPS = 50;
const DEGRADING: ReadonlySet<CoverageGapReason> = new Set(["engine-unavailable", "content-unavailable"]);

export function summarizeHealth(gaps: readonly CoverageGap[], engineVersion: string): ScanHealth {
  const gap_counts: Partial<Record<CoverageGapReason, number>> = {};
  for (const g of gaps) gap_counts[g.reason] = (gap_counts[g.reason] ?? 0) + 1;
  const status: ScanHealthStatus = gaps.some(g => DEGRADING.has(g.reason)) ? "degraded" : gaps.length ? "partial" : "complete";
  const engines_unavailable = [...new Set(gaps.filter(g => g.reason === "engine-unavailable").map(g => g.language))].sort();
  // Degrading gaps first: they are the ones a reader can act on.
  const ordered = [...gaps].sort((a, b) => Number(DEGRADING.has(b.reason)) - Number(DEGRADING.has(a.reason)) || a.file.localeCompare(b.file));
  return { status, engine_version: engineVersion, gap_counts, engines_unavailable, gaps: ordered.slice(0, MAX_GAPS) };
}

const LANGUAGE_NAMES: Record<string, string> = { python: "Python", golang: "Go", csharp: "C#", php: "PHP", java: "Java", javascript: "JavaScript", typescript: "TypeScript" };
export const languageName = (lang: string) => LANGUAGE_NAMES[lang] ?? lang;

export const GAP_REASON_TEXT: Record<CoverageGapReason, string> = {
  "engine-unavailable": "data-flow engine not loaded yet",
  "content-unavailable": "file content could not be fetched",
  "too-large": "over the data-flow size limit",
  "minified-or-generated": "minified or generated code",
};

/** One sentence for a banner. */
export function describeHealth(h: Pick<ScanHealth, "status" | "gap_counts" | "engines_unavailable">): string {
  const n = (r: CoverageGapReason) => h.gap_counts[r] ?? 0;
  if (h.status === "complete") return "Every scanned file got full analysis.";
  const parts: string[] = [];
  if (n("engine-unavailable")) parts.push(`${n("engine-unavailable")} file${n("engine-unavailable") === 1 ? "" : "s"} got pattern checks only because the ${h.engines_unavailable.map(languageName).join("/")} data-flow engine wasn't loaded yet`);
  if (n("content-unavailable")) parts.push(`${n("content-unavailable")} file${n("content-unavailable") === 1 ? "" : "s"} couldn't be fetched`);
  if (n("too-large")) parts.push(`${n("too-large")} file${n("too-large") === 1 ? " is" : "s are"} over the data-flow size limit`);
  if (n("minified-or-generated")) parts.push(`${n("minified-or-generated")} minified or generated file${n("minified-or-generated") === 1 ? "" : "s"} were checked with patterns only`);
  return parts.join("; ") + ".";
}

/** Keep the N slowest files. */
export function slowestFiles(timings: ReadonlyMap<string, number>, n = 5): Array<{ file: string; ms: number }> {
  return [...timings].map(([file, ms]) => ({ file, ms: Math.round(ms) })).sort((a, b) => b.ms - a.ms).slice(0, n);
}
