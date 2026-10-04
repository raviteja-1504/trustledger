/**
 * Safe error responses for API routes.
 *
 * Route handlers were returning raw exception messages and Supabase/Postgres
 * error text straight to the client (`detail: err.message`, `String(err)`).
 * That leaks internals a client should never see -- constraint names, column
 * values, file paths, occasionally a fragment of a query -- and isn't
 * actually more useful to a real user than a clear plain-language sentence.
 *
 * safeError() records the full error server-side and returns only a stable machine-readable code, a
 * human-readable message safe to display as-is, and a ref_id. That ref_id finds everything about the failure:
 * the structured log line, the "api.error" event on the Trace page (with its trace ID), and — for server faults —
 * the Sentry report with the stack trace.
 */

import { NextResponse } from "next/server";
import crypto from "crypto";
import { recordEvent } from "./opsEvents";
import { reportServerError } from "./serverErrors";
import { currentTrace } from "./trace";

export interface SafeErrorOptions {
  /** Stable machine-readable code, e.g. "attestation_failed". Safe to key UI copy off of. */
  code: string;
  /** Human-readable sentence, safe to render as-is. No interpolated error text. */
  message: string;
  /** HTTP status code. Default 500. */
  status?: number;
  /** Extra context for the server-side log line only -- never sent to the client. */
  context?: Record<string, unknown>;
}

/** Extracts a loggable message from an Error, a Supabase/PostgREST error object, or anything else. */
function extractDetail(err: unknown): string {
  if (err instanceof Error) return err.message;
  if (err && typeof err === "object" && "message" in err) {
    return String((err as { message: unknown }).message);
  }
  return String(err);
}

export function safeError(err: unknown, opts: SafeErrorOptions): NextResponse {
  const status = opts.status ?? 500;
  const refId  = crypto.randomBytes(4).toString("hex");

  // The log line and the Trace-page event (recordEvent writes both) …
  void recordEvent({
    kind: "api.error",
    message: opts.code,
    ref_id: refId,
    data: {
      status,
      detail: extractDetail(err),
      ...(err instanceof Error && err.stack ? { stack: err.stack.split("\n").slice(0, 4).join(" | ") } : {}),
      ...opts.context,
    },
  });
  // … and, for a server fault with an actual error, the Sentry report with the full stack.
  if (status >= 500 && err !== undefined) reportServerError(err, { code: opts.code, ref_id: refId, status });

  const trace = currentTrace()?.trace_id;
  return NextResponse.json(
    { error: opts.code, message: opts.message, ref_id: refId },
    { status, headers: { "X-Ref-Id": refId, ...(trace ? { "X-Trace-Id": trace } : {}) } },
  );
}

/** Shorthand for the common "no err object, just a known failure" case. */
export function safeErrorMessage(opts: SafeErrorOptions): NextResponse {
  return safeError(undefined, opts);
}
