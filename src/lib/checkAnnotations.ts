/**
 * GitHub check-run annotations built from the unified finding report: GitHub renders each one inline on the
 * flagged line in the PR's "Files changed" view, the same place CodeQL puts its alerts. Each carries the
 * finding's name and CWE, the plain-language explanation, input -> sink, and the fix; the full data-flow path
 * and "why this was flagged" checklist go in raw_details (GitHub's expandable "Raw output").
 */
import type { FileIndicator, FixSuggestion } from "@/types";
import { collectFindingReports, inputToSink, partsToText, reportAsPlainText, reportHeading, type FindingReport } from "./findingReport";

export interface CheckAnnotation {
  path: string;
  start_line: number;
  end_line: number;
  annotation_level: "notice" | "warning" | "failure";
  title: string;
  message: string;
  raw_details?: string;
}

/** GitHub accepts at most 50 annotations per check-run update. We send only the 50 most important rather
 * than paging through more: past that, a PR is better reviewed in TrustLedger than line by line. */
export const MAX_CHECK_ANNOTATIONS = 50;
// GitHub's own field limits.
const MAX_MESSAGE = 64 * 1024;
const MAX_TITLE = 255;

function level(sev: FindingReport["severity"]): CheckAnnotation["annotation_level"] {
  return sev === "critical" || sev === "high" ? "failure" : sev === "medium" ? "warning" : "notice";
}

export function toCheckAnnotation(r: FindingReport, reviewUrl?: string): CheckAnnotation {
  const lines = [partsToText(r.evidence.summary)];
  const path = inputToSink(r);
  if (path) lines.push(`Input → sink: ${path}`);
  lines.push(`${r.evidence.analysisLabel}${r.functionName ? ` · in ${r.functionName}()` : ""}`);
  if (r.fix) lines.push(`Fix: ${r.fix.title}. ${r.fix.description}`);
  if (reviewUrl) lines.push(`Full evidence: ${reviewUrl}`);
  return {
    path: r.filePath,
    start_line: r.line!,
    end_line: r.line!,
    annotation_level: level(r.severity),
    title: `${reportHeading(r)} · ${r.severity.toUpperCase()}`.slice(0, MAX_TITLE),
    message: lines.join("\n").slice(0, MAX_MESSAGE),
    raw_details: reportAsPlainText(r).slice(0, MAX_MESSAGE),
  };
}

/** Annotations for a scan's reportable security findings (medium severity and up), most important first. */
export function buildCheckAnnotations(
  files: readonly { file_path: string; indicators?: readonly FileIndicator[]; fix_suggestions?: readonly FixSuggestion[] }[],
  opts: { fixesById?: ReadonlyMap<string, FixSuggestion>; reviewUrl?: string } = {},
): CheckAnnotation[] {
  return collectFindingReports(files, opts.fixesById)
    .filter(r => r.severity === "critical" || r.severity === "high" || r.severity === "medium")
    .slice(0, MAX_CHECK_ANNOTATIONS)
    .map(r => toCheckAnnotation(r, opts.reviewUrl));
}
