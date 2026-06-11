/**
 * Redis caching layer using Upstash.
 * Falls back to in-memory Map when Redis is not configured.
 * Used to cache expensive dashboard queries and scan results.
 */

const MEM_CACHE = new Map<string, { value: string; expires: number }>();

// ── In-memory fallback ─────────────────────────────────────────────────────

function memGet(key: string): string | null {
  const entry = MEM_CACHE.get(key);
  if (!entry) return null;
  if (Date.now() > entry.expires) { MEM_CACHE.delete(key); return null; }
  return entry.value;
}

function memSet(key: string, value: string, ttlSeconds: number): void {
  MEM_CACHE.set(key, { value, expires: Date.now() + ttlSeconds * 1000 });
  // Evict expired entries periodically
  if (MEM_CACHE.size > 500) {
    const now = Date.now();
    Array.from(MEM_CACHE.entries()).forEach(([k, v]) => { if (now > v.expires) MEM_CACHE.delete(k); });
  }
}

function memDel(pattern: string): void {
  Array.from(MEM_CACHE.keys()).forEach(key => { if (key.startsWith(pattern)) MEM_CACHE.delete(key); });
}

// ── Upstash Redis ──────────────────────────────────────────────────────────

let _redis: { get: (k: string) => Promise<string | null>; set: (k: string, v: string, opts: { ex: number }) => Promise<unknown>; del: (...k: string[]) => Promise<unknown> } | null = null;
let _redisInit = false;

async function getRedis() {
  if (_redisInit) return _redis;
  _redisInit = true;

  const url   = process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;
  if (!url || !token) return null;

  try {
    const { Redis } = await import("@upstash/redis");
    _redis = new Redis({ url, token });
    return _redis;
  } catch { return null; }
}

// ── Public API ─────────────────────────────────────────────────────────────

export async function cacheGet<T>(key: string): Promise<T | null> {
  try {
    const redis = await getRedis();
    const raw   = redis ? await redis.get(key) : memGet(key);
    if (!raw) return null;
    return JSON.parse(typeof raw === "string" ? raw : JSON.stringify(raw)) as T;
  } catch { return null; }
}

export async function cacheSet<T>(key: string, value: T, ttlSeconds = 300): Promise<void> {
  try {
    const serialised = JSON.stringify(value);
    const redis      = await getRedis();
    if (redis) await redis.set(key, serialised, { ex: ttlSeconds });
    else        memSet(key, serialised, ttlSeconds);
  } catch { /* non-fatal */ }
}

/** Delete a specific cache key. Pass the full key (not a prefix) when Redis is active. */
export async function cacheDel(key: string): Promise<void> {
  try {
    const redis = await getRedis();
    if (redis) {
      await redis.del(key);
    } else {
      memDel(key);
    }
  } catch { /* non-fatal */ }
}

/** Delete all in-memory keys with a given prefix. Redis: deletes the exact key only. */
export async function cacheDelPrefix(prefix: string): Promise<void> {
  try {
    const redis = await getRedis();
    if (redis) {
      // Upstash serverless doesn't support SCAN/KEYS — delete the single exact key
      await redis.del(prefix);
    } else {
      memDel(prefix); // in-memory uses startsWith scan
    }
  } catch { /* non-fatal */ }
}

/** Wrap an async function with caching. */
export async function cached<T>(
  key:        string,
  ttlSeconds: number,
  fn:         () => Promise<T>,
): Promise<T> {
  const hit = await cacheGet<T>(key);
  if (hit !== null) return hit;
  const result = await fn();
  await cacheSet(key, result, ttlSeconds);
  return result;
}

// ── Cache key builders ─────────────────────────────────────────────────────

export const cacheKeys = {
  dashboard:  (orgId: string, days: number) => `dash:${orgId}:${days}`,
  scan:       (scanId: string)              => `scan:${scanId}`,
  violations: (orgId: string, status: string) => `viol:${orgId}:${status}`,
  orgSettings:(orgId: string)              => `org:${orgId}`,
  billing:    (orgId: string)              => `bill:${orgId}`,
};

// ── TTL presets ────────────────────────────────────────────────────────────

export const TTL = {
  DASHBOARD:   300,  //  5 minutes
  SCAN:        3600, //  1 hour (immutable after creation)
  VIOLATIONS:  60,   //  1 minute (changes frequently)
  ORG_SETTINGS:600,  // 10 minutes
  BILLING:     300,  //  5 minutes
};
