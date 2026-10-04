/**
 * Trace context: one ID that follows a piece of work across every step — an API request, or a pull-request scan
 * from the GitHub webhook through the queue and worker to the check run. The logger stamps it on every line and
 * ops events (lib/opsEvents.ts) store it, so the Trace page can show one request's or one PR's whole timeline.
 *
 * Node runtime only (AsyncLocalStorage). Edge middleware just generates the ID and passes it as x-request-id.
 */
import { AsyncLocalStorage } from "async_hooks";
import crypto from "crypto";
import { setLogContextProvider } from "./logger";

export interface TraceContext {
  trace_id: string;
  org_id?: string | null;
  repo?: string | null;
  pr_number?: number | null;
  scan_id?: string | null;
  delivery_id?: string | null;
}

const storage = new AsyncLocalStorage<TraceContext>();

// Every log line written inside a trace carries its fields.
setLogContextProvider(() => {
  const t = storage.getStore();
  if (!t) return undefined;
  return Object.fromEntries(Object.entries(t).filter(([, v]) => v != null));
});

/** 16 hex characters — short enough to read out, long enough not to collide in 30 days of events. */
export function newTraceId(): string {
  return crypto.randomBytes(8).toString("hex");
}

/** A trace ID from an incoming request's x-request-id (set by middleware) when it looks like one, else a new one. */
export function traceIdFrom(headerValue: string | null | undefined): string {
  return headerValue && /^[A-Za-z0-9-]{8,64}$/.test(headerValue) ? headerValue : newTraceId();
}

/** Runs `fn` with this trace context; everything it logs or records inherits the trace ID. */
export function runWithTrace<T>(ctx: TraceContext, fn: () => T): T {
  return storage.run({ ...ctx }, fn);
}

/** The active trace, if any. */
export function currentTrace(): TraceContext | undefined {
  return storage.getStore();
}

/** Adds detail to the active trace as it becomes known (e.g. the scan id once created). */
export function annotateTrace(fields: Partial<Omit<TraceContext, "trace_id">>): void {
  const t = storage.getStore();
  if (t) Object.assign(t, fields);
}

/** Switches the active trace to an ID handed over from earlier work (e.g. the webhook that queued this job). */
export function adoptTraceId(traceId: string): void {
  const t = storage.getStore();
  if (t && /^[A-Za-z0-9-]{8,64}$/.test(traceId)) t.trace_id = traceId;
}
