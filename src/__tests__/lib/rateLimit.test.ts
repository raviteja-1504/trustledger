import { checkRateLimit } from "@/lib/rateLimit";

describe("checkRateLimit (in-memory fallback — no Upstash configured)", () => {
  const originalUrl   = process.env.UPSTASH_REDIS_REST_URL;
  const originalToken = process.env.UPSTASH_REDIS_REST_TOKEN;

  beforeAll(() => {
    delete process.env.UPSTASH_REDIS_REST_URL;
    delete process.env.UPSTASH_REDIS_REST_TOKEN;
  });
  afterAll(() => {
    process.env.UPSTASH_REDIS_REST_URL   = originalUrl;
    process.env.UPSTASH_REDIS_REST_TOKEN = originalToken;
  });

  it("allows requests under the limit and decrements remaining", async () => {
    const config = { limit: 3, windowMs: 60_000, prefix: "test-under" };
    const r1 = await checkRateLimit("user-a", config);
    const r2 = await checkRateLimit("user-a", config);
    expect(r1.success).toBe(true);
    expect(r1.remaining).toBe(2);
    expect(r2.success).toBe(true);
    expect(r2.remaining).toBe(1);
  });

  it("blocks once the limit is exceeded", async () => {
    const config = { limit: 2, windowMs: 60_000, prefix: "test-block" };
    await checkRateLimit("user-b", config);
    await checkRateLimit("user-b", config);
    const blocked = await checkRateLimit("user-b", config);
    expect(blocked.success).toBe(false);
    expect(blocked.remaining).toBe(0);
  });

  it("tracks each identifier independently", async () => {
    const config = { limit: 1, windowMs: 60_000, prefix: "test-iso" };
    const a = await checkRateLimit("tenant-a", config);
    const b = await checkRateLimit("tenant-b", config);
    expect(a.success).toBe(true);
    expect(b.success).toBe(true); // different identifier, own counter
  });

  it("resets the count after the window elapses", async () => {
    jest.useFakeTimers();
    try {
      const config = { limit: 1, windowMs: 1000, prefix: "test-reset" };
      const first  = await checkRateLimit("user-c", config);
      expect(first.success).toBe(true);
      const second = await checkRateLimit("user-c", config);
      expect(second.success).toBe(false);

      jest.advanceTimersByTime(1100);

      const third = await checkRateLimit("user-c", config);
      expect(third.success).toBe(true);
    } finally {
      jest.useRealTimers();
    }
  });

  it("returns standard rate-limit headers", async () => {
    const config = { limit: 5, windowMs: 60_000, prefix: "test-headers" };
    const result = await checkRateLimit("user-d", config);
    expect(result.headers["X-RateLimit-Limit"]).toBe("5");
    expect(result.headers).toHaveProperty("X-RateLimit-Remaining");
    expect(result.headers).toHaveProperty("X-RateLimit-Reset");
    expect(result.headers).toHaveProperty("Retry-After");
  });

  // NOTE: this in-memory store is a module-level Map. On Vercel's serverless
  // runtime each invocation can land on a different, independently-scaled
  // instance with its own memory, so this fallback does NOT enforce a
  // correct global limit in production — it only limits requests that
  // happen to hit the same warm instance. Configuring UPSTASH_REDIS_REST_URL
  // / UPSTASH_REDIS_REST_TOKEN is required for real rate limiting on Vercel;
  // this suite documents that the fallback's *local* counting logic is
  // correct, not that it's sufficient in a multi-instance deployment.
});
