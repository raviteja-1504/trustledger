/**
 * The shared secret the queue's direct-call fallback sends to /api/scan-worker (header x-internal-secret).
 *
 * INTERNAL_SECRET when it is set. Without it, the well-known "dev" value is used ONLY outside production
 * (local dev / tests); in production -- NODE_ENV or VERCEL_ENV "production" -- there is no secret, so the
 * worker accepts only QStash-signed requests. (A "dev" fallback in production let anyone post a forged scan job
 * naming any installation, repo and org.)
 */
export function internalSecret(): string | null {
  const v = (process.env.INTERNAL_SECRET ?? "").replace(/^\uFEFF/, "").trim();
  if (v) return v;
  const prod = process.env.NODE_ENV === "production" || process.env.VERCEL_ENV === "production";
  return prod ? null : "dev";
}
