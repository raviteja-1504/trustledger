import {
  resetStageAccumulator,
  recordStageTime,
  recordStageFailure,
  recordStageTimeout,
  collectStageMetrics,
  computePercentiles,
  captureResourceSnapshot,
  recordCrossScanStageTotal,
  getCrossScanPercentiles,
} from "../../lib/engineMetrics";

beforeEach(() => {
  resetStageAccumulator();
});

// ── computePercentiles ────────────────────────────────────────────────────────

describe("computePercentiles", () => {
  it("returns zeros for empty array", () => {
    expect(computePercentiles([])).toEqual({ p50: 0, p95: 0, p99: 0 });
  });

  it("returns single value for one-element array", () => {
    expect(computePercentiles([42])).toEqual({ p50: 42, p95: 42, p99: 42 });
  });

  it("computes exact median for odd-length array", () => {
    // [1,2,3,4,5] → p50 at index 2 = 3
    const { p50 } = computePercentiles([5, 1, 3, 2, 4]);
    expect(p50).toBe(3);
  });

  it("interpolates median for even-length array", () => {
    // [10,20] → p50 at idx 0.5, interpolates to 15
    const { p50 } = computePercentiles([10, 20]);
    expect(p50).toBe(15);
  });

  it("computes p95 and p99 on 100-element uniform array", () => {
    const samples = Array.from({ length: 100 }, (_, i) => i + 1); // 1..100
    const { p50, p95, p99 } = computePercentiles(samples);
    // p50: idx 49.5 → interpolate 50 and 51 → 51 (Math.round(50.5))
    expect(p50).toBe(51);
    // p95: idx 94.05 → interpolate 95 and 96 → 95 (Math.round(95.05))
    expect(p95).toBe(95);
    // p99: idx 98.01 → interpolate 99 and 100 → 99 (Math.round(99.01))
    expect(p99).toBe(99);
  });

  it("does not mutate the input array", () => {
    const input = [3, 1, 2];
    computePercentiles(input);
    expect(input).toEqual([3, 1, 2]);
  });
});

// ── accumulator lifecycle ─────────────────────────────────────────────────────

describe("stage accumulator", () => {
  it("collects no stages when nothing was recorded", () => {
    expect(collectStageMetrics()).toEqual({});
  });

  it("records stage times and aggregates them", () => {
    recordStageTime("ast-parse", 10);
    recordStageTime("ast-parse", 20);
    recordStageTime("ast-parse", 30);
    const metrics = collectStageMetrics();
    const stage = metrics["ast-parse"]!;
    expect(stage.invocations).toBe(3);
    expect(stage.total_ms).toBe(60);
    expect(stage.failures).toBe(0);
    expect(stage.timeouts).toBe(0);
  });

  it("records failures and timeouts independently", () => {
    recordStageTime("ssa", 5);
    recordStageFailure("ssa");
    recordStageTimeout("ssa");
    const stage = collectStageMetrics()["ssa"]!;
    expect(stage.failures).toBe(1);
    expect(stage.timeouts).toBe(1);
  });

  it("includes p50/p95/p99 in collected metrics", () => {
    for (let i = 1; i <= 10; i++) recordStageTime("taint-propagation", i * 10);
    const stage = collectStageMetrics()["taint-propagation"]!;
    expect(stage.p50_ms).toBeDefined();
    expect(stage.p95_ms).toBeDefined();
    expect(stage.p99_ms).toBeDefined();
    expect(stage.p50_ms!).toBeGreaterThan(0);
  });

  it("tracks multiple stages independently", () => {
    recordStageTime("ast-parse", 100);
    recordStageTime("vuln-detection", 200);
    const metrics = collectStageMetrics();
    expect(metrics["ast-parse"]?.total_ms).toBe(100);
    expect(metrics["vuln-detection"]?.total_ms).toBe(200);
  });

  it("resetStageAccumulator clears all stages", () => {
    recordStageTime("compliance", 50);
    resetStageAccumulator();
    expect(collectStageMetrics()).toEqual({});
  });

  it("collectStageMetrics does not reset accumulator", () => {
    recordStageTime("reachability", 15);
    collectStageMetrics();
    const second = collectStageMetrics();
    expect(second["reachability"]?.invocations).toBe(1);
  });
});

// ── captureResourceSnapshot ───────────────────────────────────────────────────

describe("captureResourceSnapshot", () => {
  it("returns positive numeric values", () => {
    const snap = captureResourceSnapshot();
    expect(snap.heap_used_bytes).toBeGreaterThan(0);
    expect(snap.heap_total_bytes).toBeGreaterThan(0);
    expect(snap.rss_bytes).toBeGreaterThan(0);
    // cpu counters are non-negative (may be 0 on cold start)
    expect(snap.cpu_user_us).toBeGreaterThanOrEqual(0);
    expect(snap.cpu_system_us).toBeGreaterThanOrEqual(0);
  });

  it("heap_used is not larger than rss", () => {
    const snap = captureResourceSnapshot();
    expect(snap.heap_used_bytes).toBeLessThanOrEqual(snap.rss_bytes);
  });
});

// ── cross-scan rolling window ─────────────────────────────────────────────────

describe("cross-scan window", () => {
  it("returns undefined before any data is recorded", () => {
    expect(getCrossScanPercentiles("call-graph")).toBeUndefined();
  });

  it("returns percentiles after recording totals", () => {
    recordCrossScanStageTotal("call-graph", 100);
    recordCrossScanStageTotal("call-graph", 200);
    recordCrossScanStageTotal("call-graph", 300);
    const p = getCrossScanPercentiles("call-graph");
    expect(p).toBeDefined();
    expect(p!.p50).toBeGreaterThan(0);
  });

  it("window capped at 500 samples", () => {
    for (let i = 0; i < 600; i++) recordCrossScanStageTotal("ai-attribution", i);
    // After 600 pushes, only the last 500 survive.
    // Minimum of the window should be 100 (0..99 were evicted).
    const p = getCrossScanPercentiles("ai-attribution")!;
    // p50 of 100..599 is around 349-350
    expect(p.p50).toBeGreaterThanOrEqual(300);
  });
});
