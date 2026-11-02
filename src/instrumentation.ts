/**
 * Next.js 13 Instrumentation hook — runs once on server startup.
 * Used to validate environment variables before the app starts serving requests.
 * https://nextjs.org/docs/app/building-your-application/optimizing/instrumentation
 */

export async function register() {
  // Error tracking first, so anything that fails during start-up is reported too. Both configs do nothing until
  // NEXT_PUBLIC_SENTRY_DSN is set. (They were never loaded before, so no server errors reached Sentry.)
  if (process.env.NEXT_RUNTIME === "nodejs") await import("../sentry.server.config");
  if (process.env.NEXT_RUNTIME === "edge") await import("../sentry.edge.config");

  if (process.env.NEXT_RUNTIME === "nodejs") {
    // Every log line written inside a trace carries the trace ID (lib/trace.ts registers itself with the logger).
    await import("./lib/trace");

    // 1. Validate environment variables (throws in production if missing)
    const { validateEnv } = await import("./lib/env");
    validateEnv();

    // 2. Register graceful shutdown handlers
    const { registerShutdownHandlers } = await import("./lib/shutdown");
    registerShutdownHandlers();

    // 3. The tree-sitter data-flow engines are NOT loaded here. This hook runs on the cold start of every Node.js
    //    function -- /healthz, /api/me, every page's data -- and Next.js waits for it before serving the first
    //    request, so importing all eight engines here added their load time to every cold request (enough to fail
    //    the status bar's health check, which then showed "API offline"). The routes that scan wait for the engines
    //    themselves before scanning (lib/engineWarmup.ts ensureTaintEngines; the demo warms what its samples need).

    // 4. Log startup banner
    const isDemo = process.env.NEXT_PUBLIC_SKIP_AUTH === "true";
    const org    = process.env.NEXT_PUBLIC_ORG ?? "unknown";
    const appUrl = process.env.NEXT_PUBLIC_APP_URL ?? "http://localhost:3000";

    console.log(`
┌─────────────────────────────────────────────────┐
│  TrustLedger starting up                        │
│  Mode:    ${isDemo ? "DEMO (NEXT_PUBLIC_SKIP_AUTH=true)  " : "PRODUCTION                        "}│
│  Org:     ${org.padEnd(38)}│
│  URL:     ${appUrl.padEnd(38)}│
│  Node.js: ${process.version.padEnd(38)}│
└─────────────────────────────────────────────────┘`);
  }
}
