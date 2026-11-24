/**
 * Per-organization scan quotas and latency tracking.
 *
 * OrgQuotaTracker: sliding-window rate limiter.  Each org gets a fixed
 * number of scan starts per time window.  Quota refills naturally as the
 * window slides.
 *
 * This is intentionally in-memory: an org that starts many scans from
 * multiple replicas gets the quota per-replica, which is acceptable for
 * a first approximation.  A distributed counter (Redis INCR + TTL) can
 * replace this if tighter multi-replica enforcement is required.
 *
 * LatencyTracker: rolling P50/P95/P99 for queue-to-worker and DB
 * round-trip latency.  Readings populate ScanTelemetry so dashboards can
 * surface queue depth / DB health alongside scan health.
 */

import { computePercentiles } from "./engineMetrics";

// ── Per-org quota ─────────────────────────────────────────────────────────────

interface QuotaRecord {
  timestamps: number[];
}

export interface QuotaResult {
  allowed: boolean;
  /** When !allowed, milliseconds until the oldest token expires. */
  retryAfterMs?: number;
  /** How many scan tokens have been consumed in the current window. */
  used: number;
  limit: number;
  windowMs: number;
}

export class OrgQuotaTracker {
  private readonly _records = new Map<string, QuotaRecord>();

  constructor(
    private readonly _maxPerWindow: number = 20,
    private readonly _windowMs:     number = 60_000,
  ) {}

  /**
   * Check and, if allowed, consume one quota token for `orgId`.
   * `now` can be injected for testing (default: Date.now()).
   */
  check(orgId: string, now = Date.now()): QuotaResult {
    let rec = this._records.get(orgId);
    if (!rec) {
      rec = { timestamps: [] };
      this._records.set(orgId, rec);
    }

    // Slide the window: remove timestamps older than the window.
    const cutoff = now - this._windowMs;
    while (rec.timestamps.length > 0 && rec.timestamps[0] < cutoff) {
      rec.timestamps.shift();
    }

    const used = rec.timestamps.length;
    if (used >= this._maxPerWindow) {
      const oldest      = rec.timestamps[0];
      const retryAfterMs = Math.max(0, oldest + this._windowMs - now);
      return { allowed: false, retryAfterMs, used, limit: this._maxPerWindow, windowMs: this._windowMs };
    }

    rec.timestamps.push(now);
    return { allowed: true, used: used + 1, limit: this._maxPerWindow, windowMs: this._windowMs };
  }

  /** Current usage count for an org without consuming a quota token. */
  peek(orgId: string, now = Date.now()): number {
    const rec = this._records.get(orgId);
    if (!rec) return 0;
    const cutoff = now - this._windowMs;
    return rec.timestamps.filter(t => t >= cutoff).length;
  }

  /** Reset quota for an org (admin / test use). */
  reset(orgId: string): void {
    this._records.delete(orgId);
  }
}

// ── Latency tracker ───────────────────────────────────────────────────────────

const LATENCY_WINDOW_SIZE = 1_000;

export class LatencyTracker {
  private readonly _samples: number[] = [];

  record(ms: number): void {
    this._samples.push(ms);
    if (this._samples.length > LATENCY_WINDOW_SIZE) {
      this._samples.splice(0, this._samples.length - LATENCY_WINDOW_SIZE);
    }
  }

  stats(): { p50: number; p95: number; p99: number; count: number } {
    const { p50, p95, p99 } = computePercentiles(this._samples);
    return { p50, p95, p99, count: this._samples.length };
  }

  reset(): void {
    this._samples.length = 0;
  }
}

// ── Module-level singletons ───────────────────────────────────────────────────

/** Global quota tracker — 20 scan starts per org per minute. */
export const globalOrgQuotas = new OrgQuotaTracker(20, 60_000);

/** Rolling latency tracker for queue-to-worker time. */
export const queueLatencyTracker = new LatencyTracker();

/** Rolling latency tracker for DB round-trip time. */
export const dbLatencyTracker = new LatencyTracker();

/**
 * Record the wall-clock time from job enqueue to scan worker start.
 * Returns the computed latency in milliseconds.
 */
export function recordQueueLatency(
  enqueueTimestamp: number,
  startTimestamp = Date.now(),
): number {
  const ms = Math.max(0, startTimestamp - enqueueTimestamp);
  queueLatencyTracker.record(ms);
  return ms;
}

/** Record a DB round-trip duration. */
export function recordDbLatency(ms: number): void {
  dbLatencyTracker.record(ms);
}
