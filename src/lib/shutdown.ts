/**
 * Graceful shutdown handler.
 * Catches SIGTERM and SIGINT signals, flushes pending operations,
 * then exits cleanly. Critical for Kubernetes/Docker deployments.
 *
 * Initialised once in instrumentation.ts on server startup.
 */

const SHUTDOWN_TIMEOUT_MS = 10_000; // 10 seconds max

let isShuttingDown   = false;
const shutdownTasks: Array<() => Promise<void>> = [];

/** Register a cleanup task to run on shutdown. */
export function onShutdown(task: () => Promise<void>): void {
  shutdownTasks.push(task);
}

async function gracefulShutdown(signal: string): Promise<void> {
  if (isShuttingDown) return;
  isShuttingDown = true;

  console.log(`\n[TrustLedger] Received ${signal} — shutting down gracefully...`);

  const timeout = setTimeout(() => {
    console.error("[TrustLedger] Shutdown timeout exceeded — forcing exit");
    process.exit(1);
  }, SHUTDOWN_TIMEOUT_MS);

  try {
    // Run all registered cleanup tasks in parallel
    await Promise.allSettled(shutdownTasks.map(task => task()));

    // Flush Sentry if configured
    if (process.env.NEXT_PUBLIC_SENTRY_DSN) {
      try {
        // eslint-disable-next-line @typescript-eslint/no-require-imports
        const Sentry = require("@sentry/nextjs");
        await Sentry.close(2000);
      } catch { /* ignore */ }
    }

    clearTimeout(timeout);
    console.log("[TrustLedger] Graceful shutdown complete");
    process.exit(0);
  } catch (err) {
    clearTimeout(timeout);
    console.error("[TrustLedger] Error during shutdown:", err);
    process.exit(1);
  }
}

/** Call once on server startup to register signal handlers. */
export function registerShutdownHandlers(): void {
  if (typeof process === "undefined") return;
  if ((process as NodeJS.Process & { __tl_shutdown?: boolean }).__tl_shutdown) return;
  (process as NodeJS.Process & { __tl_shutdown?: boolean }).__tl_shutdown = true;

  process.on("SIGTERM", () => gracefulShutdown("SIGTERM"));
  process.on("SIGINT",  () => gracefulShutdown("SIGINT"));

  process.on("uncaughtException", (err) => {
    console.error("[TrustLedger] Uncaught exception:", err);
    gracefulShutdown("uncaughtException");
  });

  process.on("unhandledRejection", (reason) => {
    console.error("[TrustLedger] Unhandled rejection:", reason);
    // Don't exit for unhandled rejections — just log
  });
}
