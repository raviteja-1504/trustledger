// Sentry for API routes and server rendering (Node runtime). Loaded by src/instrumentation.ts.
// Does nothing until NEXT_PUBLIC_SENTRY_DSN is set.
import * as Sentry from "@sentry/nextjs";
import { scrubEvent, sentryCommon } from "./src/lib/sentryScrub";

if (sentryCommon.dsn) {
  Sentry.init({
    ...sentryCommon,
    beforeSend(event, hint) {
      const err = hint.originalException;
      if (err instanceof Error && err.message.includes("supabaseUrl is required")) {
        return null; // Suppress "Supabase not configured" errors
      }
      return scrubEvent(event);
    },
    beforeSendTransaction: event => scrubEvent(event),
  });
}
