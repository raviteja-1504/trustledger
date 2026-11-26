/**
 * The caller's IP address, for IP allowlists and rate-limit keys.
 *
 * The left-most X-Forwarded-For entry is whatever the client chose to send, so it must not be trusted. Instead:
 *   1. on Vercel, the platform-set x-vercel-forwarded-for / x-real-ip (Vercel overwrites these; a client cannot set them);
 *   2. otherwise the X-Forwarded-For entry TRUSTED_PROXY_HOPS from the right (default 1: the single proxy in front of the app
 *      appended the address it saw as the last entry);
 *   3. then x-real-ip, then "unknown".
 *
 * Edge-safe: no Node imports (middleware.ts uses it).
 */

function proxyHops(): number {
  const n = parseInt(process.env.TRUSTED_PROXY_HOPS ?? "1", 10);
  return Number.isFinite(n) && n >= 1 ? n : 1;
}

function first(value: string | null): string | null {
  const v = value?.split(",")[0]?.trim();
  return v ? v : null;
}

export function getClientIp(headers: Pick<Headers, "get">): string {
  if (process.env.VERCEL) {
    const platform = first(headers.get("x-vercel-forwarded-for")) ?? first(headers.get("x-real-ip"));
    if (platform) return platform;
  }
  const xff = (headers.get("x-forwarded-for") ?? "").split(",").map(s => s.trim()).filter(Boolean);
  if (xff.length > 0) return xff[Math.max(0, xff.length - proxyHops())];
  return first(headers.get("x-real-ip")) ?? "unknown";
}
