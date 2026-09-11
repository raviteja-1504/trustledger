/**
 * Safe error responses for API routes.
 *
 * Route handlers were returning raw exception messages and Supabase/Postgres
 * error text straight to the client (`detail: err.message`, `String(err)`).
 * That leaks internals a client should never see -- constraint names, column
 * values, file paths, occasionally a fragment of a query -- and isn't
 * actually more useful to a real user than a clear plain-language sentence.
 *
 * safeError() logs the full error server-side (Vercel logs, structured JSON,
 * grep-able by ref_id) and returns only a stable machine-readable code, a
 * human-readable message safe to display as-is, and that ref_id so a user
 * can hand it to support and an operator can find the matching log line.
 */

import { NextResponse } from "next/server";
import { logger } from "./logger";
import crypto from "crypto";

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

  logger.error(opts.code, {
    ref_id: refId,
    status,
    detail: extractDetail(err),
    ...(err instanceof Error && err.stack ? { stack: err.stack.split("\n").slice(0, 4).join(" | ") } : {}),
    ...opts.context,
  });

  return NextResponse.json(
    { error: opts.code, message: opts.message, ref_id: refId },
    { status },
  );
}

/** Shorthand for the common "no err object, just a known failure" case. */
export function safeErrorMessage(opts: SafeErrorOptions): NextResponse {
  return safeError(undefined, opts);
}
