/**
 * Structured JSON logger for production.
 * Outputs machine-readable JSON in production for log aggregation (Datadog, CloudWatch, etc.)
 * Outputs human-readable coloured text in development.
 *
 * Usage:
 *   import { logger } from "@/lib/logger";
 *   logger.info("Scan completed", { scan_id, org_id, duration_ms });
 *   logger.error("Webhook failed", { error: err.message, repo });
 */

type LogLevel = "debug" | "info" | "warn" | "error";
type LogContext = Record<string, unknown>;

interface LogEntry {
  timestamp: string;
  level:     LogLevel;
  message:   string;
  service:   string;
  version:   string;
  [key: string]: unknown;
}

const IS_PROD = process.env.NODE_ENV === "production";
const SERVICE = "trustledger-dashboard";
const VERSION = process.env.npm_package_version ?? "0.0.1";

// ANSI colours for dev
const COLOURS: Record<LogLevel, string> = {
  debug: "\x1b[36m", // cyan
  info:  "\x1b[32m", // green
  warn:  "\x1b[33m", // yellow
  error: "\x1b[31m", // red
};
const RESET = "\x1b[0m";

function log(level: LogLevel, message: string, context?: LogContext): void {
  const timestamp = new Date().toISOString();

  if (IS_PROD) {
    const entry: LogEntry = {
      timestamp,
      level,
      message,
      service: SERVICE,
      version: VERSION,
      ...context,
    };
    // Structured JSON for log aggregation
    const output = JSON.stringify(entry);
    if (level === "error" || level === "warn") {
      process.stderr.write(output + "\n");
    } else {
      process.stdout.write(output + "\n");
    }
  } else {
    // Human-readable for dev
    const colour = COLOURS[level];
    const ctx    = context && Object.keys(context).length > 0
      ? " " + JSON.stringify(context)
      : "";
    const prefix = `${colour}[${level.toUpperCase()}]${RESET} ${timestamp}`;
    const msg    = `${prefix} ${message}${ctx}`;
    if (level === "error") console.error(msg);
    else if (level === "warn") console.warn(msg);
    else console.log(msg);
  }
}

export const logger = {
  debug: (msg: string, ctx?: LogContext) => log("debug", msg, ctx),
  info:  (msg: string, ctx?: LogContext) => log("info",  msg, ctx),
  warn:  (msg: string, ctx?: LogContext) => log("warn",  msg, ctx),
  error: (msg: string, ctx?: LogContext) => log("error", msg, ctx),

  /** Log an API request with timing. */
  request: (method: string, path: string, status: number, durationMs: number, ctx?: LogContext) =>
    log(status >= 400 ? "warn" : "info", `${method} ${path} ${status}`, {
      duration_ms: durationMs,
      http_method: method,
      http_path:   path,
      http_status: status,
      ...ctx,
    }),

  /** Log a scan with full context. */
  scan: (scanId: string, repo: string, risk: string, durationMs: number, orgId?: string) =>
    log("info", "Scan completed", {
      scan_id:     scanId,
      repo,
      overall_risk: risk,
      duration_ms:  durationMs,
      org_id:       orgId,
      event:        "scan_completed",
    }),
};
