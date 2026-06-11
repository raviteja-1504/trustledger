import * as Sentry from "@sentry/nextjs";

const SENTRY_DSN = process.env.NEXT_PUBLIC_SENTRY_DSN;

if (SENTRY_DSN) {
  Sentry.init({
    dsn: SENTRY_DSN,
    environment: process.env.NODE_ENV,
    tracesSampleRate: process.env.NODE_ENV === "production" ? 0.1 : 1.0,

    // Tag every server error with org context when available
    beforeSend(event, hint) {
      const err = hint.originalException;
      if (err instanceof Error && err.message.includes("supabaseUrl is required")) {
        return null; // Suppress "Supabase not configured" errors
      }
      return event;
    },
  });
}
