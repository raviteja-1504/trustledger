// Small structured logger used across the payments-api services.
// Kept dependency-free so it can run in any Node runtime.

type Level = "debug" | "info" | "warn" | "error";

function write(level: Level, msg: string, meta?: Record<string, unknown>) {
  const line = {
    ts: new Date().toISOString(),
    level,
    msg,
    ...meta,
  };
  if (level === "error" || level === "warn") {
    console.error(JSON.stringify(line));
  } else {
    console.log(JSON.stringify(line));
  }
}

export const logger = {
  debug: (msg: string, meta?: Record<string, unknown>) => write("debug", msg, meta),
  info:  (msg: string, meta?: Record<string, unknown>) => write("info", msg, meta),
  warn:  (msg: string, meta?: Record<string, unknown>) => write("warn", msg, meta),
  error: (msg: string, meta?: Record<string, unknown>) => write("error", msg, meta),
};
