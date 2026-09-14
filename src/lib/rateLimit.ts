/**
 * Rate limiting using Upstash Redis (serverless).
 * Falls back to in-memory rate limiting when Redis is not configured.
 * Used on: /api/scans, /api/webhook/github, /api/attest, /api/keys
 */

// ── In-memory fallback (for dev / when Upstash not configured) ───────────────

const memStore = new Map<string, { count: number; reset: number }>();

function memLimit(key: string, limit: number, windowMs: number): { success: boolean; remaining: number; reset: number } {
  const now    = Date.now();
  const entry  = memStore.get(key);
  const reset  = entry && entry.reset > now ? entry.reset : now + windowMs;

  if (!entry || entry.reset <= now) {
    memStore.set(key, { count: 1, reset });
    return { success: true, remaining: limit - 1, reset };
  }

  if (entry.count >= limit) {
    return { success: false, remaining: 0, reset: entry.reset };
  }

  entry.count++;
  return { success: true, remaining: limit - entry.count, reset: entry.reset };
}

// ── Upstash Redis (production) ────────────────────────────────────────────────

let _ratelimiter: unknown | null = null;

async function getUpstashLimiter() {
  if (_ratelimiter) return _ratelimiter as { limit: (key: string) => Promise<{ success: boolean; remaining: number; reset: number }> };

  const redisUrl   = process.env.UPSTASH_REDIS_REST_URL;
  const redisToken = process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!redisUrl || !redisToken) return null;

  try {
    const { Ratelimit } = await import("@upstash/ratelimit");
    const { Redis }     = await import("@upstash/redis");
    const redis         = new Redis({ url: redisUrl, token: redisToken });
    _ratelimiter        = new Ratelimit({
      redis,
      limiter:   Ratelimit.slidingWindow(100, "1 m"),
      analytics: true,
      prefix:    "tl:rl",
    });
    return _ratelimiter as typeof _ratelimiter & { limit: (key: string) => Promise<{ success: boolean; remaining: number; reset: number }> };
  } catch {
    return null;
  }
}

// ── Exported rate-limit check ────────────────────────────────────────────────

export interface RateLimitConfig {
  /** Max requests per window */
  limit:    number;
  /** Window in milliseconds */
  windowMs: number;
  /** Key prefix for namespacing */
  prefix?:  string;
}

export interface RateLimitResult {
  success:   boolean;
  remaining: number;
  reset:     number;         // Unix ms timestamp
  headers:   Record<string, string>;
}

/**
 * Check rate limit for a given identifier (IP, org_id, or API key).
 * Returns success=false when the limit is exceeded.
 */
export async function checkRateLimit(
  identifier: string,
  config: RateLimitConfig,
): Promise<RateLimitResult> {
  const key = `${config.prefix ?? "tl"}:${identifier}`;

  // Try Upstash first
  const upstash = await getUpstashLimiter();
  if (upstash) {
    try {
      const result = await upstash.limit(key);
      return {
        success:   result.success,
        remaining: result.remaining,
        reset:     result.reset,
        headers: {
          "X-RateLimit-Limit":     String(config.limit),
          "X-RateLimit-Remaining": String(result.remaining),
          "X-RateLimit-Reset":     String(Math.ceil(result.reset / 1000)),
          "Retry-After":           result.success ? "0" : String(Math.ceil((result.reset - Date.now()) / 1000)),
        },
      };
    } catch { /* fall through to memory */ }
  }

  // In-memory fallback
  const result = memLimit(key, config.limit, config.windowMs);
  return {
    ...result,
    headers: {
      "X-RateLimit-Limit":     String(config.limit),
      "X-RateLimit-Remaining": String(result.remaining),
      "X-RateLimit-Reset":     String(Math.ceil(result.reset / 1000)),
      "Retry-After":           result.success ? "0" : String(Math.ceil((result.reset - Date.now()) / 1000)),
    },
  };
}

// ── Pre-defined limits ────────────────────────────────────────────────────────

export const RATE_LIMITS = {
  // Scan submission — 60/minute per org (generous for CI/CD pipelines)
  scan:         { limit: 60,   windowMs: 60_000,   prefix: "scan"    },
  // Attestation — 120/minute per org
  attest:       { limit: 120,  windowMs: 60_000,   prefix: "attest"  },
  // GitHub webhook — 300/minute per installation (high-traffic repos)
  webhook:      { limit: 300,  windowMs: 60_000,   prefix: "webhook" },
  // API key creation — 10/hour per org
  keyCreate:    { limit: 10,   windowMs: 3600_000, prefix: "keyc"    },
  // Report generation — 20/hour per org
  report:       { limit: 20,   windowMs: 3600_000, prefix: "report"  },
  // Login attempts — 5/minute per IP
  login:        { limit: 5,    windowMs: 60_000,   prefix: "login"   },
} as const;
