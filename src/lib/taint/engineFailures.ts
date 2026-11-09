/**
 * Per-file record of data-flow engine FAILURES (a parse that threw, an analysis that threw). The engines return no findings
 * when that happens -- which would read as "clean" -- so each failure is recorded here and the scanner reports the file as
 * a coverage gap (scanHealth: "parse-failed" / "analysis-failed") and does not cache its result.
 *
 * Time-stamped rather than reset per scan, so concurrent scans in one process never clear each other's failures.
 */
export type EngineFailureKind = "parse-failed" | "analysis-failed";

const MAX_TRACKED = 5000;
const failures = new Map<string, { kind: EngineFailureKind; at: number }>();

export function recordEngineFailure(file: string, kind: EngineFailureKind): void {
  const prior = failures.get(file);
  failures.delete(file);                                   // re-insert: Map order = recency, so the oldest is evicted first
  failures.set(file, { kind: prior?.kind === "analysis-failed" ? "analysis-failed" : kind, at: Date.now() });
  if (failures.size > MAX_TRACKED) failures.delete(failures.keys().next().value as string);
}

/** The failure recorded for `file` at or after `sinceMs`, or null. */
export function engineFailureSince(file: string, sinceMs: number): EngineFailureKind | null {
  const f = failures.get(file);
  return f && f.at >= sinceMs ? f.kind : null;
}
