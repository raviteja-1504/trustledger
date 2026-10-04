// Sentry for edge middleware. Loaded by src/instrumentation.ts. Does nothing until NEXT_PUBLIC_SENTRY_DSN is set.
import * as Sentry from "@sentry/nextjs";
import { scrubEvent, sentryCommon } from "./src/lib/sentryScrub";

if (sentryCommon.dsn) {
  Sentry.init({
    ...sentryCommon,
    beforeSend: event => scrubEvent(event),
    beforeSendTransaction: event => scrubEvent(event),
  });
}
