/**
 * The demo / local-development switch: NEXT_PUBLIC_SKIP_AUTH=true.
 *
 * With it on, the app skips sign-in, treats every request as an admin and (in the scans route) skips plan limits and
 * persistence. That is right for `next dev` and the e2e tests and catastrophic in production, so server-side code asks THIS
 * function instead of reading the variable: it never answers "bypass" in a production runtime, whatever the variable says
 * (a build made with it on, a dashboard value copied across, a CI setting that leaked). lib/env.ts additionally refuses to
 * start; this is the request-time backstop.
 *
 * "Production" = NODE_ENV or VERCEL_ENV is "production" (the same test lib/internalSecret.ts uses). A `next build` output, run
 * with `next start` or on Vercel, is NODE_ENV=production; `next dev` and the jest / Playwright runs are not.
 *
 * Edge-safe: no Node imports (middleware.ts uses it).
 */

/** True in a production runtime. */
export function isProductionRuntime(): boolean {
  return process.env.NODE_ENV === "production" || process.env.VERCEL_ENV === "production";
}

/** True only when the demo switch is on AND this is not a production runtime. Server code must use this, never the raw variable. */
export function authBypassEnabled(): boolean {
  return process.env.NEXT_PUBLIC_SKIP_AUTH === "true" && !isProductionRuntime();
}
