/**
 * Browser error reporting. Importing this module initialises Sentry in the browser (sentry.client.config.ts);
 * captureClientError sends a caught error with optional context. No-op when Sentry isn't configured.
 */
import * as Sentry from "@sentry/nextjs";
import "../../sentry.client.config";

export function captureClientError(err: unknown, context: Record<string, unknown> = {}): void {
  try {
    if (!Sentry.getClient()) return;
    Sentry.withScope(scope => {
      for (const [k, v] of Object.entries(context)) if (typeof v === "string" || typeof v === "number") scope.setTag(k, String(v));
      Sentry.captureException(err instanceof Error ? err : new Error(String(err)));
    });
  } catch { /* reporting must never throw */ }
}
