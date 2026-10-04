/**
 * Server-side error reporting to Sentry (configured in sentry.server.config.ts, loaded by instrumentation.ts).
 * Server-only — kept out of lib/observability.ts, which browser code imports.
 *
 * Each report carries the trace ID and, for API errors, the ref_id the user was shown, so a support message
 * "it failed, ref 3f9a1c22" leads straight to the stack trace and the Trace page timeline.
 */
import * as Sentry from "@sentry/nextjs";
import { currentTrace } from "@/lib/trace";

export function reportServerError(err: unknown, context: { code?: string; ref_id?: string; [k: string]: unknown } = {}): void {
  try {
    if (!Sentry.getClient()) return;            // Sentry not configured (no DSN): nothing to send
    const t = currentTrace();
    Sentry.withScope(scope => {
      if (t?.trace_id) scope.setTag("trace_id", t.trace_id);
      if (context.ref_id) scope.setTag("ref_id", context.ref_id);
      if (context.code) scope.setTag("error_code", context.code);
      if (t?.org_id) scope.setTag("org_id", t.org_id);
      if (t?.repo) scope.setTag("repo", t.repo);
      if (t?.scan_id) scope.setTag("scan_id", t.scan_id);
      scope.setContext("details", context);
      Sentry.captureException(err instanceof Error ? err : new Error(String(err)));
    });
  } catch { /* reporting must never throw */ }
}
