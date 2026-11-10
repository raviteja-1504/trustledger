/**
 * @jest-environment node
 *
 * With Redis connected, every limit used to become the one built into the shared limiter (100 per minute): the
 * 10-per-15-minutes login-code limit and the 10-per-hour key-creation limit included. Each caller's own numbers must
 * reach the limiter, analytics must stay off (it adds commands to every check), and a memory-only limit must not
 * touch Redis at all.
 */
const built: Array<{ window: string; limit: number; analytics: unknown; prefix: unknown }> = [];
const checked: string[] = [];

jest.mock("@upstash/redis", () => ({ Redis: class {} }));
jest.mock("@upstash/ratelimit", () => ({
  Ratelimit: class {
    static slidingWindow(limit: number, window: string) { return { limit, window }; }
    private cfg: { limiter: { limit: number; window: string }; analytics: unknown; prefix: unknown };
    constructor(cfg: { limiter: { limit: number; window: string }; analytics: unknown; prefix: unknown }) {
      this.cfg = cfg;
      built.push({ window: cfg.limiter.window, limit: cfg.limiter.limit, analytics: cfg.analytics, prefix: cfg.prefix });
    }
    async limit(key: string) { checked.push(key); return { success: true, remaining: this.cfg.limiter.limit - 1, reset: Date.now() + 1000 }; }
  },
}));

process.env.UPSTASH_REDIS_REST_URL = "https://fake.upstash.io";
process.env.UPSTASH_REDIS_REST_TOKEN = "t";

import { checkRateLimit, RATE_LIMITS } from "@/lib/rateLimit";

beforeEach(() => { built.length = 0; checked.length = 0; });

describe("rate limits through Redis", () => {
  it("each limit is built with its own number and window", async () => {
    await checkRateLimit("u1", { limit: 10, windowMs: 15 * 60_000, prefix: "2fa-login-t" });
    await checkRateLimit("o1", { limit: 10, windowMs: 3_600_000, prefix: "keyc-t" });
    expect(built.find(b => b.prefix === "tl:rl" && b.limit === 10 && b.window === `${15 * 60_000} ms`)).toBeTruthy();
    expect(built.find(b => b.limit === 10 && b.window === "3600000 ms")).toBeTruthy();
    expect(built.some(b => b.limit === 100)).toBe(false);
  });

  it("the same limit reuses one limiter, and analytics stay off", async () => {
    const cfg = { limit: 7, windowMs: 60_000, prefix: "reuse-t" };
    await checkRateLimit("a", cfg);
    await checkRateLimit("b", cfg);
    expect(built.filter(b => b.limit === 7)).toHaveLength(1);
    expect(built.every(b => b.analytics === false)).toBe(true);
    expect(checked).toEqual(["reuse-t:a", "reuse-t:b"]);
  });

  it("a memory-only limit never touches Redis but still limits", async () => {
    const cfg = { limit: 2, windowMs: 60_000, prefix: "mem-t", memoryOnly: true };
    expect((await checkRateLimit("ip", cfg)).success).toBe(true);
    expect((await checkRateLimit("ip", cfg)).success).toBe(true);
    expect((await checkRateLimit("ip", cfg)).success).toBe(false);
    expect(built).toHaveLength(0);
    expect(checked).toHaveLength(0);
  });

  it("the predefined limits keep their real numbers", async () => {
    await checkRateLimit("o", RATE_LIMITS.keyCreate);
    expect(built.some(b => b.limit === RATE_LIMITS.keyCreate.limit && b.window === `${RATE_LIMITS.keyCreate.windowMs} ms`)).toBe(true);
  });

  it("the blanket per-request limit in the middleware stays in memory", () => {
    // it runs on every API request; through Redis each check costs several commands
    const src = require("fs").readFileSync(require("path").join(process.cwd(), "src/middleware.ts"), "utf8") as string;
    expect(src).toMatch(/GLOBAL_API_LIMIT\s*=\s*\{[^}]*memoryOnly:\s*true/);
  });
});
