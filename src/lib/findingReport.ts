/**
 * Unified finding evidence: ONE description of a finding -- name, CWE, explanation, data-flow path, the
 * reasons it was flagged, and the fix -- that every surface renders instead of re-deriving its own. The PR
 * page's inline panels, the SARIF export, GitHub check-run annotations, the PR comment and the check summary
 * all go through buildFindingReport(), so a finding reads the same wherever a reviewer meets it.
 *
 * Client-safe: the catalog, the evidence builder and this module have no server imports.
 */
import type { FileIndicator, FixSuggestion } from "@/types";
import { buildFindingEvidence, type CheckTone, type FindingEvidence, type Part } from "./findingEvidence";
import { findingMeta } from "./findingCatalog";

export type ReportSeverity = "critical" | "high" | "medium" | "low" | "info";

export interface FindingReport {
  id: string;
  title: string;
  cwe?: string;
  severity: ReportSeverity;
  filePath: string;
  line?: number;
  functionName?: string;
  fingerprint?: string;
  evidence: FindingEvidence;
  fix?: FixSuggestion;
}

const SEV_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

/** A CWE-mapped finding in the project's own code -- the ones worth putting in front of a reviewer outside
 * the app. AI-authorship signals, and findings in vendored or test code, are excluded. */
export function isReportableSecurityFinding(ind: FileIndicator): boolean {
  if (ind.line == null) return false;
  if (ind.codeCategory === "third_party" || ind.codeCategory === "test_code") return false;
  return !!(ind.cwe ?? findingMeta(ind.id).cwe);
}

export function buildFindingReport(
  ind: FileIndicator, filePath: string, siblings: readonly FileIndicator[] = [], fix?: FixSuggestion,
): FindingReport {
  const meta = findingMeta(ind.id, ind.label);
  return {
    id: ind.id,
    title: meta.title,
    cwe: ind.cwe ?? meta.cwe,
    severity: (SEV_RANK[ind.severity] != null ? ind.severity : "low") as ReportSeverity,
    filePath,
    line: ind.line,
    functionName: ind.functionName,
    fingerprint: ind.fingerprint,
    evidence: buildFindingEvidence(ind, filePath, siblings),
    fix,
  };
}

/** Every reportable finding across files, most severe (then most exploitable) first. */
export function collectFindingReports(
  files: readonly { file_path: string; indicators?: readonly FileIndicator[]; fix_suggestions?: readonly FixSuggestion[] }[],
  fixesById?: ReadonlyMap<string, FixSuggestion>,
): FindingReport[] {
  const scored: Array<{ report: FindingReport; exploit: number }> = [];
  for (const f of files) {
    const inds = f.indicators ?? [];
    const fileFixes = new Map((f.fix_suggestions ?? []).map(x => [x.vuln_id, x]));
    for (const ind of inds) {
      if (!isReportableSecurityFinding(ind)) continue;
      const fix = fileFixes.get(ind.id) ?? fixesById?.get(ind.id);
      scored.push({ report: buildFindingReport(ind, f.file_path, inds, fix), exploit: ind.exploitability_score ?? 0 });
    }
  }
  scored.sort((a, b) =>
    (SEV_RANK[b.report.severity] ?? 0) - (SEV_RANK[a.report.severity] ?? 0) || b.exploit - a.exploit ||
    a.report.filePath.localeCompare(b.report.filePath) || (a.report.line ?? 0) - (b.report.line ?? 0));
  return scored.map(s => s.report);
}

// ── Text renderers ───────────────────────────────────────────────────────────

const oneLine = (s: string) => s.replace(/\s+/g, " ").trim();

/** Inline code for Markdown that survives backticks inside the value (JS template literals). */
function mdCode(s: string): string {
  const v = oneLine(s);
  const runs = v.match(/`+/g) ?? [];
  const fence = "`".repeat(Math.max(0, ...runs.map(r => r.length)) + 1);
  return fence.length > 1 || v.startsWith("`") || v.endsWith("`") ? `${fence} ${v} ${fence}` : `\`${v}\``;
}
/** Engine/free text in Markdown: keep it from being read as HTML or table syntax. */
function mdText(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/\|/g, "\\|");
}

export function partsToText(parts: Part[], style: "plain" | "markdown" = "plain"): string {
  return oneLine(parts.map(p => (typeof p === "string"
    ? (style === "markdown" ? mdText(p) : p)
    : (style === "markdown" ? mdCode(p.code) : `\`${oneLine(p.code)}\``))).join(""));
}

const TONE_MARK: Record<CheckTone, string> = { confirmed: "✓", absent: "✗", caution: "!", neutral: "•" };

/** `L4 Input: request.GET.get("name")` per step, source first. */
export function flowLines(r: FindingReport): string[] {
  return r.evidence.flow.map(s => {
    const where = s.otherFile ? `${s.otherFile}${s.line ? `:${s.line}` : ""}` : s.line ? `L${s.line}` : "";
    return `${where ? `${where} ` : ""}${s.kindLabel}: ${oneLine(s.text)}`;
  });
}

/** One-line "input → … → sink" for a data-flow finding, else undefined. */
export function inputToSink(r: FindingReport, style: "plain" | "markdown" = "plain"): string | undefined {
  const flow = r.evidence.flow;
  if (!r.evidence.isDataFlow || flow.length < 2) return undefined;
  const code = (s: string) => (style === "markdown" ? mdCode(s) : `\`${oneLine(s)}\``);
  const mid = flow.length > 2 ? ` → ${flow.length - 2} step${flow.length - 2 === 1 ? "" : "s"}` : "";
  return `${code(flow[0].text)}${mid} → ${code(flow[flow.length - 1].text)}`;
}

export function checkLines(r: FindingReport, style: "plain" | "markdown" = "plain"): string[] {
  return r.evidence.checks.map(c => `${TONE_MARK[c.tone]} ${partsToText(c.parts, style)}`);
}

export function reportHeading(r: FindingReport): string {
  return `${r.title}${r.cwe ? ` (${r.cwe})` : ""}`;
}

/** The full evidence as plain text (check-run raw details, SARIF help text). */
export function reportAsPlainText(r: FindingReport): string {
  const out = [`${reportHeading(r)} — ${r.severity.toUpperCase()} · ${r.evidence.analysisLabel}`, "", partsToText(r.evidence.summary)];
  if (r.functionName) out.push(`In ${r.functionName}()`);
  if (r.evidence.flow.length) out.push("", "Data flow:", ...flowLines(r).map(l => `  ${l}`));
  if (r.evidence.checks.length) out.push("", "Why this was flagged:", ...checkLines(r).map(l => `  ${l}`));
  if (r.fix) out.push("", `Recommended fix: ${r.fix.title}. ${r.fix.description}`);
  return out.join("\n");
}
