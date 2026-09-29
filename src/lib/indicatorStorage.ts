import type { ScanIndicator } from "./scanner";
import type { FileIndicator } from "@/types";
import type { TraceStep } from "./taint/taintCore";

/**
 * The one projection of a scanner indicator into what is persisted in scan_files.indicators (a jsonb
 * column, so adding fields needs no migration). It used to be copy-pasted into four ingestion routes
 * (GitHub scan-worker, GitLab, Bitbucket, api/scans/[id] re-analysis); each listed fields by hand and all
 * four silently dropped `fingerprint` and `confidence`, so the stable identity computed by the scanner was
 * thrown away at the persistence boundary and could never be used to track a finding across scans.
 *
 * `trace` and `supportingDetectors` are kept because the PR page renders them inline under the flagged
 * line, and the stored snapshot is what that page falls back to whenever live re-analysis doesn't run
 * (content unavailable, or past api/scans/[id]'s per-request re-analysis cap). The trace is capped so one
 * pathological finding can't bloat the row. Only line-bearing indicators are stored; line-less ones are
 * aggregate AI signals the UI derives from other columns.
 */
const MAX_STORED_TRACE_STEPS = 12;
const MAX_TRACE_TEXT = 160;
const MAX_RELATED_LOCATIONS = 12;

function capTrace(trace: readonly TraceStep[] | undefined): TraceStep[] | undefined {
  if (!trace || trace.length === 0) return undefined;
  // Keep the sink: it is the step that ties the trace back to the flagged line.
  const kept = trace.length <= MAX_STORED_TRACE_STEPS
    ? trace
    : [...trace.slice(0, MAX_STORED_TRACE_STEPS - 1), trace[trace.length - 1]];
  return kept.map(s => ({
    file: s.file, line: s.line, kind: s.kind,
    label: s.label.slice(0, MAX_TRACE_TEXT), snippet: s.snippet.slice(0, MAX_TRACE_TEXT),
  }));
}

export function toStoredIndicator(i: ScanIndicator): FileIndicator {
  return {
    id: i.id, label: i.label, severity: i.severity, line: i.line, detail: i.detail,
    codeCategory: i.codeCategory, cwe: i.cwe,
    reachability: i.reachability, exploitability_score: i.exploitability_score, remediation_urgency: i.remediation_urgency,
    fingerprint: i.fingerprint, confidence: i.confidence, sourceExpr: i.sourceExpr, sinkExpr: i.sinkExpr,
    ...(i.introduced != null ? { introduced: i.introduced } : {}),
    trace: capTrace(i.trace),
    supportingDetectors: i.supportingDetectors?.length ? [...i.supportingDetectors] : undefined,
    relatedLocations: i.relatedLocations?.length
      ? i.relatedLocations.slice(0, MAX_RELATED_LOCATIONS).map(r => ({ ...r, label: r.label.slice(0, MAX_TRACE_TEXT) }))
      : undefined,
    reachedFrom: i.reachedFrom?.length
      ? i.reachedFrom.slice(0, MAX_RELATED_LOCATIONS).map(o => ({ ...o, source: o.source?.slice(0, MAX_TRACE_TEXT) }))
      : undefined,
    functionName: i.functionName,
    flow: i.flow ? {
      ...i.flow,
      source: { ...i.flow.source, expr: i.flow.source.expr.slice(0, MAX_TRACE_TEXT) },
      sink: { ...i.flow.sink, expr: i.flow.sink.expr.slice(0, MAX_TRACE_TEXT) },
      files: i.flow.files.slice(0, MAX_RELATED_LOCATIONS),
      sanitizers: i.flow.sanitizers.slice(0, MAX_RELATED_LOCATIONS),
    } : undefined,
  };
}

export function toStoredIndicators(indicators: readonly ScanIndicator[] | undefined): FileIndicator[] {
  return (indicators ?? []).filter(i => i.line).map(toStoredIndicator);
}
