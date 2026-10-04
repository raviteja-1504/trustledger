// Sentry for the browser. Imported once by src/lib/clientErrors.ts (loaded from Providers).
// Does nothing until NEXT_PUBLIC_SENTRY_DSN is set.
//
// No session replay: it recorded users' screens — code, findings, emails — with text masking switched off.
import * as Sentry from "@sentry/nextjs";
import { scrubEvent, sentryCommon } from "./src/lib/sentryScrub";

if (sentryCommon.dsn) {
  Sentry.init({
    ...sentryCommon,
    beforeSend(event) {
      // Don't send events when Supabase is not configured (dev mode)
      if (!process.env.NEXT_PUBLIC_SUPABASE_URL) return null;
      // Don't send demo/seed errors
      try { if (typeof window !== "undefined" && localStorage.getItem("tl_force_seed") === "1") return null; } catch { /* storage blocked */ }
      return scrubEvent(event);
    },
    beforeSendTransaction: event => scrubEvent(event),
  });
}
