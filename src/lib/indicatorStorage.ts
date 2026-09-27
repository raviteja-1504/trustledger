import type { ScanIndicator } from "./scanner";
import type { FileIndicator } from "@/types";

/**
 * The one projection of a scanner indicator into what is persisted in scan_files.indicators (a jsonb
 * column, so adding fields needs no migration). It used to be copy-pasted into four ingestion routes
 * (GitHub scan-worker, GitLab, Bitbucket, api/scans/[id] re-analysis); each listed fields by hand and all
 * four silently dropped `fingerprint` and `confidence`, so the stable identity computed by the scanner was
 * thrown away at the persistence boundary and could never be used to track a finding across scans.
 *
 * Deliberately NOT persisted: `trace` (an array per finding -- bulky, and re-derivable by re-analysis) and
 * `supportingDetectors` (detector labels, display-only). Only line-bearing indicators are stored; line-less
 * ones are aggregate AI signals the UI derives from other columns.
 */
export function toStoredIndicator(i: ScanIndicator): FileIndicator {
  return {
    id: i.id, label: i.label, severity: i.severity, line: i.line, detail: i.detail,
    codeCategory: i.codeCategory, cwe: i.cwe,
    reachability: i.reachability, exploitability_score: i.exploitability_score, remediation_urgency: i.remediation_urgency,
    fingerprint: i.fingerprint, confidence: i.confidence, sourceExpr: i.sourceExpr, sinkExpr: i.sinkExpr,
  };
}

export function toStoredIndicators(indicators: readonly ScanIndicator[] | undefined): FileIndicator[] {
  return (indicators ?? []).filter(i => i.line).map(toStoredIndicator);
}
