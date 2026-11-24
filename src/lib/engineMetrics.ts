/**
 * Engine-level metrics for the security scan pipeline.
 *
 * Tracks per-stage latency (P50/P95/P99), CPU/memory, cache hits,
 * parser failures, and timeout counts.
 *
 * Uses a module-level accumulator reset by runScan() at the start of each
 * scan and collected at the end.  analyzeFile() is synchronous, so there is
 * no need for AsyncLocalStorage — a plain module-level Map suffices.
 *
 * Also maintains a rolling cross-scan window so caller dashboards can
 * display P50/P95/P99 across recent scans, not just the current one.
 */

import type { EngineStage, EngineStageMetrics, ResourceSnapshot } from "./scanHealth";

// ── Per-scan accumulator ──────────────────────────────────────────────────────

interface StageEntry {
  samples:  number[];
  failures: number;
  timeouts: number;
}

const _stages = new Map<EngineStage, StageEntry>();

function ensureStage(stage: EngineStage): StageEntry {
  let entry = _stages.get(stage);
  if (!entry) {
    entry = { samples: [], failures: 0, timeouts: 0 };
    _stages.set(stage, entry);
  }
  return entry;
}

/** Record a completed engine stage invocation (call once per file/pass). */
export function recordStageTime(stage: EngineStage, ms: number): void {
  ensureStage(stage).samples.push(ms);
}

/** Record a parse or analysis failure for a stage (file count, not scan count). */
export function recordStageFailure(stage: EngineStage): void {
  ensureStage(stage).failures++;
}

/** Record a stage invocation that hit the time budget. */
export function recordStageTimeout(stage: EngineStage): void {
  ensureStage(stage).timeouts++;
}

/** Reset the accumulator at the start of each scan. */
export function resetStageAccumulator(): void {
  _stages.clear();
}

/**
 * Collect per-stage metrics and return them (does NOT reset).
 * Call resetStageAccumulator() separately after runScan() finishes.
 */
export function collectStageMetrics(): Partial<Record<EngineStage, EngineStageMetrics>> {
  const result: Partial<Record<EngineStage, EngineStageMetrics>> = {};
  for (const [stage, entry] of _stages) {
    const { p50, p95, p99 } = computePercentiles(entry.samples);
    const total_ms = entry.samples.reduce((s, v) => s + v, 0);
    result[stage] = {
      total_ms,
      invocations: entry.samples.length,
      failures:    entry.failures,
      timeouts:    entry.timeouts,
      p50_ms: p50,
      p95_ms: p95,
      p99_ms: p99,
    };
  }
  return result;
}

// ── Percentile computation ────────────────────────────────────────────────────

/** Compute P50/P95/P99 from an array of duration samples (ms). */
export function computePercentiles(samples: readonly number[]): { p50: number; p95: number; p99: number } {
  if (samples.length === 0) return { p50: 0, p95: 0, p99: 0 };
  const sorted = [...samples].sort((a, b) => a - b);
  return {
    p50: _percentile(sorted, 0.50),
    p95: _percentile(sorted, 0.95),
    p99: _percentile(sorted, 0.99),
  };
}

function _percentile(sorted: number[], p: number): number {
  if (sorted.length === 1) return sorted[0];
  const idx = p * (sorted.length - 1);
  const lo  = Math.floor(idx);
  const hi  = Math.ceil(idx);
  if (lo === hi) return sorted[lo];
  const frac = idx - lo;
  return Math.round(sorted[lo] * (1 - frac) + sorted[hi] * frac);
}

// ── Resource snapshot ─────────────────────────────────────────────────────────

/** Capture the process's current CPU and memory usage. */
export function captureResourceSnapshot(): ResourceSnapshot {
  const mem = process.memoryUsage();
  const cpu = process.cpuUsage();
  return {
    heap_used_bytes:  mem.heapUsed,
    heap_total_bytes: mem.heapTotal,
    rss_bytes:        mem.rss,
    cpu_user_us:      cpu.user,
    cpu_system_us:    cpu.system,
  };
}

// ── Rolling cross-scan window (P50/P95/P99 across recent scans) ───────────────

const WINDOW_SIZE = 500;
const _crossScanSamples = new Map<EngineStage, number[]>();

/** Record a scan-level total for a stage into the rolling cross-scan window. */
export function recordCrossScanStageTotal(stage: EngineStage, total_ms: number): void {
  let arr = _crossScanSamples.get(stage);
  if (!arr) {
    arr = [];
    _crossScanSamples.set(stage, arr);
  }
  arr.push(total_ms);
  if (arr.length > WINDOW_SIZE) arr.splice(0, arr.length - WINDOW_SIZE);
}

/** Get cross-scan percentiles for a stage from the rolling window, or undefined if no samples yet. */
export function getCrossScanPercentiles(stage: EngineStage): { p50: number; p95: number; p99: number } | undefined {
  const arr = _crossScanSamples.get(stage);
  if (!arr || arr.length === 0) return undefined;
  return computePercentiles(arr);
}
