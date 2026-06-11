import * as Sentry from "@sentry/nextjs";

const SENTRY_DSN = process.env.NEXT_PUBLIC_SENTRY_DSN;

if (SENTRY_DSN) {
  Sentry.init({
    dsn: SENTRY_DSN,
    environment: process.env.NODE_ENV,

    // Capture 10% of transactions for performance monitoring
    tracesSampleRate: process.env.NODE_ENV === "production" ? 0.1 : 1.0,

    // Replay 0% of sessions normally, 100% on error
    replaysSessionSampleRate: 0,
    replaysOnErrorSampleRate:  1.0,

    integrations: [
      Sentry.replayIntegration({
        maskAllText:   false,
        blockAllMedia: false,
      }),
    ],

    // Filter out noise
    beforeSend(event) {
      // Don't send events when Supabase is not configured (dev mode)
      if (!process.env.NEXT_PUBLIC_SUPABASE_URL) return null;
      // Don't send demo/seed errors
      if (typeof window !== "undefined" && localStorage.getItem("tl_force_seed") === "1") return null;
      return event;
    },

    // Add org context to all events
    initialScope: {
      tags: {
        product: "trustledger",
        component: "dashboard",
      },
    },
  });
}
