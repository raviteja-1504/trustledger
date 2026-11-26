/**
 * CORS for /api/*. Default-deny: a browser page on another origin gets no CORS headers (so it cannot read responses)
 * unless its origin is the app's own (NEXT_PUBLIC_APP_URL) or listed in API_CORS_ALLOWED_ORIGINS (comma-separated).
 * Never "*", and no Allow-Credentials: SDK / CI callers send an API key header, which needs no cookies.
 * Edge-safe: no Node imports.
 */

const ALLOW_METHODS = "GET, POST, PATCH, PUT, DELETE, OPTIONS";
const ALLOW_HEADERS = "Content-Type, Authorization, X-TrustLedger-Key, X-Gitlab-Token, X-Hub-Signature-256";

function originOf(value: string): string | null {
  try { return new URL(value).origin; } catch { return null; }
}

export function allowedOrigins(): Set<string> {
  const out = new Set<string>();
  for (const v of [process.env.NEXT_PUBLIC_APP_URL ?? "", ...(process.env.API_CORS_ALLOWED_ORIGINS ?? "").split(",")]) {
    const o = originOf(v.trim());
    if (o) out.add(o);
  }
  return out;
}

export function corsOriginAllowed(origin: string | null): origin is string {
  return !!origin && allowedOrigins().has(origin);
}

/** Add CORS headers for an allowed origin (and Vary: Origin always, so caches keep per-origin answers apart). */
export function applyCors(res: Response, origin: string | null, preflight = false): void {
  res.headers.append("Vary", "Origin");
  if (!corsOriginAllowed(origin)) return;
  res.headers.set("Access-Control-Allow-Origin", origin);
  if (preflight) {
    res.headers.set("Access-Control-Allow-Methods", ALLOW_METHODS);
    res.headers.set("Access-Control-Allow-Headers", ALLOW_HEADERS);
    res.headers.set("Access-Control-Max-Age", "86400");
  }
}
