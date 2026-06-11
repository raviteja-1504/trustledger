/**
 * Observability helpers — logging + Sentry context.
 *
 * Sentry error capture is handled automatically by:
 *   - sentry.server.config.ts + instrumentation.ts  (Node.js server / API routes)
 *   - sentry.client.config.ts                       (browser)
 *
 * These helpers add structured logging and span timing. They intentionally do
 * NOT require("@sentry/nextjs") — importing that package in a file used by
 * client components pulls @sentry/node → @opentelemetry → require-in-the-middle
 * into the browser bundle, triggering a webpack "Critical dependency" warning.
 */

import { logger } from "./logger";

export async function withSpan<T>(
  name: string,
  op:   string,
  fn:   () => Promise<T>,
): Promise<T> {
  const start = Date.now();
  try {
    const result = await fn();
    logger.debug(`Span: ${op}/${name}`, { duration_ms: Date.now() - start });
    return result;
  } catch (err) {
    captureError(err, { span: `${op}/${name}` });
    throw err;
  }
}

export function captureError(err: unknown, context?: Record<string, unknown>) {
  logger.error(err instanceof Error ? err.message : String(err), {
    stack: err instanceof Error ? err.stack?.split("\n")[1]?.trim() : undefined,
    ...context,
  });
}

export function setUserContext(_userId: string, _email?: string, _orgId?: string) {
  // Sentry user context is set automatically via sentry.server.config.ts (server)
  // and sentry.client.config.ts (browser). No-op here.
}
