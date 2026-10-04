/**
 * Operational events — the timeline behind the Trace page (see migrations/20261004_ops_events.sql).
 *
 * recordEvent() writes one row and the same thing to the logger. It never throws and never slows a request
 * down meaningfully: tracing must not be the thing that breaks a scan. Fields not given are taken from the active
 * trace (lib/trace.ts).
 */
import { createServiceClient } from "@/lib/supabase";
import { logger, redact } from "@/lib/logger";
import { currentTrace, newTraceId } from "@/lib/trace";

export type OpsEventKind =
  | "webhook.received" | "webhook.ignored"
  | "scan.queued" | "scan.enqueue_failed" | "scan.started" | "scan.skipped" | "scan.superseded"
  | "scan.files_fetched" | "scan.completed" | "scan.failed"
  | "checkrun.updated" | "checkrun.failed"
  | "api.error"
  | "pipeline.stuck";

export interface OpsEvent {
  kind: OpsEventKind;
  level?: "info" | "warn" | "error";
  message?: string;
  org_id?: string | null;
  trace_id?: string;
  scan_id?: string | null;
  delivery_id?: string | null;
  repo?: string | null;
  pr_number?: number | null;
  ref_id?: string | null;
  duration_ms?: number | null;
  data?: Record<string, unknown>;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
let tableMissing = false;   // before the migration has run: log only, don't retry the insert every time

export async function recordEvent(e: OpsEvent): Promise<void> {
  const t = currentTrace();
  const row = {
    trace_id:    e.trace_id ?? t?.trace_id ?? newTraceId(),
    kind:        e.kind,
    level:       e.level ?? (e.kind.endsWith("failed") || e.kind === "api.error" ? "error" : e.kind === "pipeline.stuck" ? "warn" : "info"),
    message:     e.message ?? null,
    org_id:      validUuid(e.org_id ?? t?.org_id),
    scan_id:     validUuid(e.scan_id ?? t?.scan_id),
    delivery_id: e.delivery_id ?? t?.delivery_id ?? null,
    repo:        e.repo ?? t?.repo ?? null,
    pr_number:   e.pr_number ?? t?.pr_number ?? null,
    ref_id:      e.ref_id ?? null,
    duration_ms: e.duration_ms != null ? Math.round(e.duration_ms) : null,
    data:        (redact(e.data ?? {}) as Record<string, unknown>),
  };

  const logFields = { event: row.kind, trace_id: row.trace_id, scan_id: row.scan_id, delivery_id: row.delivery_id, repo: row.repo, pr_number: row.pr_number, ref_id: row.ref_id, duration_ms: row.duration_ms, ...row.data };
  const msg = row.message ?? row.kind;
  if (row.level === "error") logger.error(msg, logFields);
  else if (row.level === "warn") logger.warn(msg, logFields);
  else logger.info(msg, logFields);

  if (tableMissing) return;
  try {
    const { error } = await createServiceClient().from("ops_events").insert(row);
    if (error && /ops_events|42P01|does not exist/i.test(`${error.code ?? ""} ${error.message ?? ""}`)) tableMissing = true;
  } catch { /* tracing is best-effort */ }
}

function validUuid(v: string | null | undefined): string | null {
  return v && UUID.test(v) ? v : null;
}
