/**
 * Next.js 13 Instrumentation hook — runs once on server startup.
 * Used to validate environment variables before the app starts serving requests.
 * https://nextjs.org/docs/app/building-your-application/optimizing/instrumentation
 */

export async function register() {
  if (process.env.NEXT_RUNTIME === "nodejs") {
    // 1. Validate environment variables (throws in production if missing)
    const { validateEnv } = await import("./lib/env");
    validateEnv();

    // 2. Register graceful shutdown handlers
    const { registerShutdownHandlers } = await import("./lib/shutdown");
    registerShutdownHandlers();

    // 3. Log startup banner
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
