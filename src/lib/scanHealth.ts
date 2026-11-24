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

// ── Task 9: engine-stage types ────────────────────────────────────────────────

/**
 * The nine independently-measured analysis stages of a single-file scan.
 * Recorded by engineMetrics.ts via recordStageTime(); consumed by runScan()
 * to populate ScanTelemetry.engine_stages.
 */
export type EngineStage =
  | "ast-parse"
  | "ssa"
  | "call-graph"
  | "taint-propagation"
  | "cross-file"
  | "reachability"
  | "vuln-detection"
  | "ai-attribution"
  | "compliance";

/** Per-stage metrics collected over all files in a single scan. */
export interface EngineStageMetrics {
  /** Total milliseconds spent in this stage across all files. */
  total_ms: number;
  /** Number of times this stage was invoked (one per eligible file). */
  invocations: number;
  /** Number of invocations that raised a parse/analysis error. */
  failures: number;
  /** Number of invocations that were cut short by the time budget. */
  timeouts: number;
  /** Median latency per invocation (ms). */
  p50_ms?: number;
  /** 95th-percentile latency per invocation (ms). */
  p95_ms?: number;
  /** 99th-percentile latency per invocation (ms). */
  p99_ms?: number;
}

/** CPU and memory snapshot taken at scan completion. */
export interface ResourceSnapshot {
  heap_used_bytes:  number;
  heap_total_bytes: number;
  rss_bytes:        number;
  /** Microseconds of user-mode CPU used by this process since it started. */
  cpu_user_us:      number;
  /** Microseconds of kernel-mode CPU used by this process since it started. */
  cpu_system_us:    number;
}

export type CoverageGapReason = "engine-unavailable" | "content-unavailable" | "parse-failed" | "analysis-failed" | "too-large" | "minified-or-generated" | "time-budget";

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

  // ── Scan reproducibility (task 5 §C) ──────────────────────────────────────
  /** The PR base commit SHA at the time of scan (before_sha from the webhook event). */
  base_commit_sha?: string | null;
  /** Number of files in this PR that existed but were not scanned (removed, binary, over-size, etc.). */
  files_skipped?: number;
  /** Explicit completion status of this scan invocation. */
  completion_status?: "complete" | "partial" | "timeout" | "error";
  /** Number of files that were added to the scan by dependency-aware delta invalidation. */
  dep_expanded_files?: number;

  // ── Task 9: engine observability ──────────────────────────────────────────
  /**
   * Per-stage breakdown: latency (P50/P95/P99), invocation count, failures,
   * and timeouts for each of the nine independently-measured analysis stages.
   */
  engine_stages?: Partial<Record<EngineStage, EngineStageMetrics>>;
  /** CPU and memory snapshot captured at scan completion. */
  resource_snapshot?: ResourceSnapshot;
  /** Wall-clock milliseconds from job enqueue to scan worker start (queue depth signal). */
  queue_latency_ms?: number;
  /** Total milliseconds spent in DB round-trips during this scan. */
  db_latency_ms?: number;
  /**
   * Fraction of files served from cache: files_reused / (files_analyzed + files_reused).
   * 0 on a cold cache; 1 when all files were unchanged and reused.
   */
  cache_hit_rate?: number;
  /** Files whose AST parse failed outright (gap reason "parse-failed"). */
  parser_failures?: number;
  /** Files dropped to the pattern layer by the time budget (gap reason "time-budget"). */
  timeout_counts?: number;
  /**
   * false only when every scanned file received the full analysis its language supports.
   * true whenever health.status is "partial" or "degraded" — an explicit assertion that
   * performance optimizations never cause silent analysis skipping.
   */
  coverage_incomplete?: boolean;
}

export const MAX_GAPS = 50;
const DEGRADING: ReadonlySet<CoverageGapReason> = new Set(["engine-unavailable", "content-unavailable", "parse-failed", "analysis-failed", "time-budget"]);

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
  "parse-failed": "the file could not be parsed for data-flow analysis",
  "analysis-failed": "data-flow analysis failed on this file",
  "too-large": "over the data-flow size limit",
  "minified-or-generated": "minified or generated code",
  "time-budget": "the scan's time budget ran out before data-flow analysis reached this file",
};

/** One sentence for a banner. */
export function describeHealth(h: Pick<ScanHealth, "status" | "gap_counts" | "engines_unavailable">): string {
  const n = (r: CoverageGapReason) => h.gap_counts[r] ?? 0;
  if (h.status === "complete") return "Every scanned file got full analysis.";
  const parts: string[] = [];
  if (n("engine-unavailable")) parts.push(`${n("engine-unavailable")} file${n("engine-unavailable") === 1 ? "" : "s"} got pattern checks only because the ${h.engines_unavailable.map(languageName).join("/")} data-flow engine wasn't loaded yet`);
  if (n("content-unavailable")) parts.push(`${n("content-unavailable")} file${n("content-unavailable") === 1 ? "" : "s"} couldn't be fetched`);
  if (n("parse-failed")) parts.push(`${n("parse-failed")} file${n("parse-failed") === 1 ? "" : "s"} could not be parsed for data-flow analysis`);
  if (n("analysis-failed")) parts.push(`data-flow analysis failed on ${n("analysis-failed")} file${n("analysis-failed") === 1 ? "" : "s"} (an empty result there is not a clean result)`);
  if (n("too-large")) parts.push(`${n("too-large")} file${n("too-large") === 1 ? " is" : "s are"} over the data-flow size limit`);
  if (n("minified-or-generated")) parts.push(`${n("minified-or-generated")} minified or generated file${n("minified-or-generated") === 1 ? "" : "s"} were checked with patterns only`);
  if (n("time-budget")) parts.push(`the scan ran out of time, so ${n("time-budget")} file${n("time-budget") === 1 ? "" : "s"} got pattern checks only (rescan to cover ${n("time-budget") === 1 ? "it" : "them"})`);
  return parts.join("; ") + ".";
}

/** Keep the N slowest files. */
export function slowestFiles(timings: ReadonlyMap<string, number>, n = 5): Array<{ file: string; ms: number }> {
  return [...timings].map(([file, ms]) => ({ file, ms: Math.round(ms) })).sort((a, b) => b.ms - a.ms).slice(0, n);
}
