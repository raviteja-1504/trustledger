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
const RELEASE = process.env.VERCEL_GIT_COMMIT_SHA?.slice(0, 7);

// Server code registers the active trace (lib/trace.ts) so every line carries trace_id / org / repo / scan.
// A hook rather than an import, because this logger is also bundled into browser code.
let contextProvider: (() => LogContext | undefined) | null = null;
export function setLogContextProvider(fn: () => LogContext | undefined): void { contextProvider = fn; }

// Values that must never reach a log line, whatever key they hide under.
const SECRET_KEY = /(^|_|-)(token|secret|password|passwd|authorization|cookie|api[_-]?key|private[_-]?key|signature|dsn)($|_|-)/i;
const SECRET_VALUE = /\b(gh[pousr]_[A-Za-z0-9]{20,}|tl_live_[A-Za-z0-9]{16,}|sk_(?:live|test)_[A-Za-z0-9]{10,}|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+|-----BEGIN [A-Z ]*PRIVATE KEY-----)/g;

/** Masks secrets in log context: by key name anywhere in the object, and by recognisable token shape in strings. */
export function redact(value: unknown, depth = 0): unknown {
  if (typeof value === "string") return value.replace(SECRET_VALUE, "[redacted]");
  if (depth > 6 || value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map(v => redact(v, depth + 1));
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    out[k] = SECRET_KEY.test(k) ? "[redacted]" : redact(v, depth + 1);
  }
  return out;
}

// ANSI colours for dev
const COLOURS: Record<LogLevel, string> = {
  debug: "\x1b[36m", // cyan
  info:  "\x1b[32m", // green
  warn:  "\x1b[33m", // yellow
  error: "\x1b[31m", // red
};
const RESET = "\x1b[0m";

function log(level: LogLevel, message: string, rawContext?: LogContext): void {
  const timestamp = new Date().toISOString();
  let traceCtx: LogContext | undefined;
  try { traceCtx = contextProvider?.(); } catch { traceCtx = undefined; }
  const context = redact({ ...(traceCtx ?? {}), ...(rawContext ?? {}) }) as LogContext;
  message = redact(message) as string;

  if (IS_PROD) {
    const entry: LogEntry = {
      timestamp,
      level,
      message,
      service: SERVICE,
      version: VERSION,
      ...(RELEASE ? { release: RELEASE } : {}),
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
