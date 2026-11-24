import {
  OrgQuotaTracker,
  LatencyTracker,
  recordQueueLatency,
  recordDbLatency,
  queueLatencyTracker,
  dbLatencyTracker,
} from "../../lib/orgQuotas";

// ── OrgQuotaTracker ───────────────────────────────────────────────────────────

describe("OrgQuotaTracker", () => {
  it("allows requests up to the limit", () => {
    const tracker = new OrgQuotaTracker(3, 60_000);
    const now = Date.now();
    for (let i = 0; i < 3; i++) {
      const result = tracker.check("org-a", now);
      expect(result.allowed).toBe(true);
      expect(result.limit).toBe(3);
    }
  });

  it("denies the request beyond the limit", () => {
    const tracker = new OrgQuotaTracker(2, 60_000);
    const now = Date.now();
    tracker.check("org-b", now);
    tracker.check("org-b", now);
    const result = tracker.check("org-b", now);
    expect(result.allowed).toBe(false);
    expect(result.retryAfterMs).toBeGreaterThan(0);
  });

  it("used count reflects consumed tokens", () => {
    const tracker = new OrgQuotaTracker(5, 60_000);
    const now = Date.now();
    tracker.check("org-c", now);
    tracker.check("org-c", now);
    const result = tracker.check("org-c", now);
    expect(result.used).toBe(3);
  });

  it("sliding window allows new tokens after old ones expire", () => {
    const tracker = new OrgQuotaTracker(2, 1000); // 1-second window
    const t0 = 1_000_000;
    tracker.check("org-d", t0);
    tracker.check("org-d", t0);
    // Both slots consumed; deny at t0
    expect(tracker.check("org-d", t0).allowed).toBe(false);
    // After window elapses, the old timestamps expire
    const t1 = t0 + 1001;
    expect(tracker.check("org-d", t1).allowed).toBe(true);
  });

  it("retryAfterMs is > 0 and <= windowMs when denied", () => {
    const tracker = new OrgQuotaTracker(1, 60_000);
    const now = 2_000_000;
    tracker.check("org-e", now);
    const result = tracker.check("org-e", now);
    expect(result.allowed).toBe(false);
    expect(result.retryAfterMs).toBeGreaterThan(0);
    expect(result.retryAfterMs!).toBeLessThanOrEqual(60_000);
  });

  it("peek does not consume a token", () => {
    const tracker = new OrgQuotaTracker(1, 60_000);
    const now = Date.now();
    tracker.check("org-f", now); // consume the only token
    const peeked = tracker.peek("org-f", now);
    expect(peeked).toBe(1);
    // peek did not add a token; still denied
    expect(tracker.check("org-f", now).allowed).toBe(false);
  });

  it("reset clears the org's quota", () => {
    const tracker = new OrgQuotaTracker(1, 60_000);
    const now = Date.now();
    tracker.check("org-g", now);
    tracker.reset("org-g");
    expect(tracker.check("org-g", now).allowed).toBe(true);
  });

  it("orgs are isolated from each other", () => {
    const tracker = new OrgQuotaTracker(1, 60_000);
    const now = Date.now();
    tracker.check("org-h", now); // exhaust org-h
    expect(tracker.check("org-i", now).allowed).toBe(true); // org-i unaffected
  });
});

// ── LatencyTracker ────────────────────────────────────────────────────────────

describe("LatencyTracker", () => {
  it("returns zeros when empty", () => {
    const tracker = new LatencyTracker();
    const stats = tracker.stats();
    expect(stats).toEqual({ p50: 0, p95: 0, p99: 0, count: 0 });
  });

  it("computes stats from a single sample", () => {
    const tracker = new LatencyTracker();
    tracker.record(100);
    const stats = tracker.stats();
    expect(stats.p50).toBe(100);
    expect(stats.p95).toBe(100);
    expect(stats.p99).toBe(100);
    expect(stats.count).toBe(1);
  });

  it("count increments correctly", () => {
    const tracker = new LatencyTracker();
    tracker.record(10);
    tracker.record(20);
    tracker.record(30);
    expect(tracker.stats().count).toBe(3);
  });

  it("percentiles reflect recorded distribution", () => {
    const tracker = new LatencyTracker();
    for (let i = 1; i <= 100; i++) tracker.record(i);
    const { p50, p95 } = tracker.stats();
    expect(p50).toBeGreaterThan(40);
    expect(p95).toBeGreaterThan(80);
  });

  it("window caps at 1000 samples", () => {
    const tracker = new LatencyTracker();
    for (let i = 0; i < 1200; i++) tracker.record(i);
    expect(tracker.stats().count).toBe(1000);
  });

  it("reset clears all samples", () => {
    const tracker = new LatencyTracker();
    tracker.record(50);
    tracker.reset();
    expect(tracker.stats()).toEqual({ p50: 0, p95: 0, p99: 0, count: 0 });
  });
});

// ── recordQueueLatency / recordDbLatency ──────────────────────────────────────

describe("recordQueueLatency", () => {
  beforeEach(() => {
    queueLatencyTracker.reset();
    dbLatencyTracker.reset();
  });

  it("computes elapsed time correctly", () => {
    const enqueue = 1_000_000;
    const start   = 1_000_250;
    const ms = recordQueueLatency(enqueue, start);
    expect(ms).toBe(250);
  });

  it("clamps negative elapsed to 0", () => {
    const ms = recordQueueLatency(1_000_500, 1_000_000);
    expect(ms).toBe(0);
  });

  it("records into queueLatencyTracker", () => {
    recordQueueLatency(1_000_000, 1_000_100);
    expect(queueLatencyTracker.stats().count).toBe(1);
    expect(queueLatencyTracker.stats().p50).toBe(100);
  });

  it("recordDbLatency stores in dbLatencyTracker", () => {
    recordDbLatency(75);
    expect(dbLatencyTracker.stats().count).toBe(1);
    expect(dbLatencyTracker.stats().p50).toBe(75);
  });
});
