/**
 * Redis caching layer using Upstash.
 * Falls back to in-memory Map when Redis is not configured.
 * Used to cache expensive dashboard queries and scan results.
 */

import { gzipSync, gunzipSync, constants as zlibConstants } from "zlib";

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

let _redis: { get: (k: string) => Promise<string | null>; mget?: (...k: string[]) => Promise<unknown[]>; set: (k: string, v: string, opts: { ex: number }) => Promise<unknown>; del: (...k: string[]) => Promise<unknown> } | null = null;
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

// ── Large values ───────────────────────────────────────────────────────────
// Upstash's REST API rejects a request body over about 1 MB. A scan's files (their source included) are several MB,
// so before this the write failed silently (the catch below) and a big scan was never cached: every view read the
// whole scan from the database again, which was most of the project's database egress. Values over LARGE_VALUE are
// gzipped; one that is still over CHUNK is split across several keys. Small values are stored exactly as before.

const LARGE_VALUE = 64_000;
const CHUNK       = 700_000;

/** What to store for `key`: the main value, and any extra chunks (stored under `${key}~${i}`). */
function encodeForRedis(serialised: string): { main: string; chunks: string[] } {
  if (serialised.length <= LARGE_VALUE) return { main: serialised, chunks: [] };
  const packed = "gz:" + gzipSync(serialised, { level: zlibConstants.Z_BEST_SPEED }).toString("base64");
  if (packed.length <= CHUNK) return { main: packed, chunks: [] };
  const chunks: string[] = [];
  for (let i = 0; i < packed.length; i += CHUNK) chunks.push(packed.slice(i, i + CHUNK));
  return { main: `gzc:${chunks.length}`, chunks };
}

/** The serialised JSON behind a stored value, or null when a chunk is missing (expired or not yet written). */
async function decodeFromRedis(redis: NonNullable<typeof _redis>, key: string, raw: unknown): Promise<string | null> {
  if (typeof raw === "string" && raw.startsWith("gzc:")) {
    const n = Number(raw.slice(4));
    if (!Number.isInteger(n) || n < 1 || n > 64) return null;
    const parts = await Promise.all(Array.from({ length: n }, (_, i) => redis.get(`${key}~${i}`)));
    if (parts.some(p => typeof p !== "string")) return null;
    return gunzipSync(Buffer.from((parts as string[]).join("").slice(3), "base64")).toString("utf8");
  }
  if (typeof raw === "string" && raw.startsWith("gz:")) return gunzipSync(Buffer.from(raw.slice(3), "base64")).toString("utf8");
  return typeof raw === "string" ? raw : JSON.stringify(raw);
}

export async function cacheGet<T>(key: string): Promise<T | null> {
  try {
    const redis = await getRedis();
    if (!redis) {
      const raw = memGet(key);
      return raw ? JSON.parse(raw) as T : null;
    }
    const raw = await redis.get(key);
    if (!raw) return null;
    const text = await decodeFromRedis(redis, key, raw);
    if (text == null) return null;
    // The client hands a stored JSON string back already unwrapped ("hello", not "\"hello\""), which does not parse.
    try { return JSON.parse(text) as T; } catch { return raw as T; }
  } catch { return null; }
}

/** Several keys at once (one round trip per 100 keys on Redis); a missing or unreadable key is null. */
export async function cacheGetMany<T>(keys: string[]): Promise<Array<T | null>> {
  if (keys.length === 0) return [];
  try {
    const redis = await getRedis();
    if (!redis) return keys.map(k => { const raw = memGet(k); return raw ? JSON.parse(raw) as T : null; });
    const out: Array<T | null> = [];
    for (let i = 0; i < keys.length; i += 100) {
      const chunk = keys.slice(i, i + 100);
      const raws = redis.mget ? await redis.mget(...chunk) : await Promise.all(chunk.map(k => redis.get(k)));
      for (let j = 0; j < chunk.length; j++) {
        try {
          const raw = raws[j];
          if (!raw) { out.push(null); continue; }
          const text = await decodeFromRedis(redis, chunk[j], raw);
          out.push(text == null ? null : JSON.parse(text) as T);
        } catch { out.push(null); }
      }
    }
    return out;
  } catch { return keys.map(() => null); }
}

export async function cacheSet<T>(key: string, value: T, ttlSeconds = 300): Promise<void> {
  try {
    const serialised = JSON.stringify(value);
    const redis      = await getRedis();
    if (!redis) { memSet(key, serialised, ttlSeconds); return; }
    const { main, chunks } = encodeForRedis(serialised);
    // Chunks first: the main value is what readers look for, so it must never be visible before its chunks.
    if (chunks.length > 0) await Promise.all(chunks.map((c, i) => redis.set(`${key}~${i}`, c, { ex: ttlSeconds })));
    await redis.set(key, main, { ex: ttlSeconds });
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

/** Misses being computed in this instance, by key: concurrent callers of the same key share one computation (pages
 *  that load together -- the sidebar badge and the page itself -- each used to recompute the same expensive result). */
const computing = new Map<string, Promise<unknown>>();

/** Runs `fn` once for concurrent callers of the same key in this instance; they all get its result. */
export async function singleFlight<T>(key: string, fn: () => Promise<T>): Promise<T> {
  const pending = computing.get(key);
  if (pending) return pending as Promise<T>;
  const run = fn();
  computing.set(key, run);
  try {
    return await run;
  } finally {
    if (computing.get(key) === run) computing.delete(key);
  }
}

/** Wrap an async function with caching. */
export async function cached<T>(
  key:        string,
  ttlSeconds: number,
  fn:         () => Promise<T>,
): Promise<T> {
  const hit = await cacheGet<T>(key);
  if (hit !== null) return hit;
  return singleFlight(key, async () => {
    const result = await fn();
    await cacheSet(key, result, ttlSeconds);
    return result;
  });
}

// ── Cache key builders ─────────────────────────────────────────────────────

export const cacheKeys = {
  dashboard:  (orgId: string, days: number) => `dash:${orgId}:${days}`,
  scan:       (scanId: string)              => `scan:${scanId}`,
  violations: (orgId: string, status: string) => `viol:${orgId}:${status}`,
  secrets:    (orgId: string, status: string) => `sec:${orgId}:${status}`,
  orgSettings:(orgId: string)              => `org:${orgId}`,
  billing:    (orgId: string)              => `bill:${orgId}`,
  dependencies:(orgId: string)             => `deps:${orgId}`,
  apiSecurity: (orgId: string)             => `apisec:${orgId}`,
  autoIncidentState: (orgId: string)       => `aincsync:${orgId}`,
  osvPackage: (ecosystem: string, name: string, version: string) => `osvpkg:${ecosystem}:${name}:${version}`,
  // v2: details now carry the advisory's vulnerable functions (osvClient.ts extractAffectedSymbols).
  osvVulnId:  (id: string)                 => `osvvuln:v2:${id}`,
  npmLicense: (name: string, version: string) => `npmlic:${name}:${version}`,
};

// Every status value each of the above list endpoints can be filtered to,
// including "" for the unfiltered/all-statuses request -- used to bust every
// cached variant on write, since Upstash's REST API can't pattern-delete.
export const VIOLATION_STATUS_VARIANTS = ["", "open", "in_review", "resolved", "unresolved"];
export const SECRET_STATUS_VARIANTS    = ["", "open", "resolved"];

/** Bust every cached GET /api/violations variant for an org. */
export async function invalidateViolationsCache(orgId: string): Promise<void> {
  await Promise.all(
    VIOLATION_STATUS_VARIANTS.flatMap(s => [100, 500].map(lim =>
      cacheDel(`${cacheKeys.violations(orgId, s)}:${lim}`)
    )),
  );
}

/** Bust every cached GET /api/secrets variant for an org. */
export async function invalidateSecretsCache(orgId: string): Promise<void> {
  await Promise.all(SECRET_STATUS_VARIANTS.map(s => cacheDel(cacheKeys.secrets(orgId, s))));
}

// ── TTL presets ────────────────────────────────────────────────────────────

export const TTL = {
  DASHBOARD:   300,  //  5 minutes
  SCAN:        3600, //  1 hour (immutable after creation)
  VIOLATIONS:  60,   //  1 minute (changes frequently)
  SECRETS:     60,   //  1 minute (changes frequently)
  ORG_SETTINGS:600,  // 10 minutes
  BILLING:     300,  //  5 minutes
  DEPENDENCIES:3600, //  1 hour: keyed by the org's latest scan and the deployment, so a new scan or release is a new
                     //  key at once; the TTL only bounds how long advisory data fetched during the parse is reused
  VULN_INTEL:  86400,// 24 hours (CVE data changes slowly — day-scale, not request-scale)
};
