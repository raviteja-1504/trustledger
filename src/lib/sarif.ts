/**
 * SARIF 2.1.0 export.
 *
 * Converts persisted scan findings into a SARIF log so results can be
 * uploaded to GitHub Code Scanning (github/codeql-action/upload-sarif) or
 * GitLab's Security Dashboard, both of which expect this format rather than
 * a proprietary JSON shape.
 *
 * Messages, data-flow paths and rule help come from the unified finding report (findingReport.ts), so a
 * finding reads the same here as on the PR page: `codeFlows` carries the source -> sink path (Code Scanning's
 * "Show paths"), and `partialFingerprints` carries the scanner's stable fingerprint so an alert keeps its
 * identity across runs when unrelated lines shift.
 *
 * Schema reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/
 */
import type { FileIndicator, FixSuggestion } from "@/types";
import { findingMeta } from "./findingCatalog";
import { buildFindingReport, reportAsPlainText, partsToText, type FindingReport } from "./findingReport";

export type SarifIndicator = FileIndicator;

export interface SarifSourceFile {
  file_path:  string;
  indicators: SarifIndicator[];
}

type Sev = "critical" | "high" | "medium" | "low" | "info";

function severityToLevel(sev: Sev): "error" | "warning" | "note" {
  if (sev === "critical" || sev === "high") return "error";
  if (sev === "medium") return "warning";
  return "note";
}

function severityScore(sev: Sev): string {
  return { critical: "9.0", high: "7.0", medium: "5.0", low: "3.0", info: "1.0" }[sev];
}

function ruleHelp(id: string, fix: FixSuggestion | undefined): { text: string; markdown: string } {
  const meta = findingMeta(id);
  const text = [meta.description, fix ? `Recommended fix: ${fix.title}. ${fix.description}` : ""].filter(Boolean).join("\n\n");
  const md = [meta.description];
  if (fix) {
    md.push(`**Recommended fix: ${fix.title}.** ${fix.description}`);
    if (fix.code_before) md.push("Before:\n```\n" + fix.code_before + "\n```");
    if (fix.code_after) md.push("After:\n```\n" + fix.code_after + "\n```");
  }
  return { text, markdown: md.join("\n\n") };
}

function codeFlows(r: FindingReport) {
  // Only steps with a real location can be shown as a path; a flow needs at least a start and an end.
  const steps = r.evidence.flow.filter(s => s.line != null);
  if (!r.evidence.isDataFlow || steps.length < 2) return undefined;
  return [{
    threadFlows: [{
      locations: steps.map(s => ({
        location: {
          physicalLocation: { artifactLocation: { uri: s.otherFile ?? r.filePath }, region: { startLine: Math.max(1, s.line!) } },
          message: { text: `${s.kindLabel}: ${s.text}` },
        },
      })),
    }],
  }];
}

/** Build a SARIF 2.1.0 log for one scan (one GitHub code-scanning "run"). `fixesById` supplies remediation
 * guidance for rule help (see scanner.ts getFixSuggestions). */
export function buildSarifReport(
  files:    SarifSourceFile[],
  toolInfo: { name?: string; version?: string; informationUri?: string } = {},
  fixesById: ReadonlyMap<string, FixSuggestion> = new Map(),
): object {
  const ruleIds = new Set<string>();
  for (const f of files) for (const ind of f.indicators) ruleIds.add(ind.id);

  const rules = Array.from(ruleIds).map(id => {
    const meta = findingMeta(id);
    return {
      id,
      name: meta.title,
      shortDescription: { text: meta.title },
      fullDescription:  { text: meta.description },
      help: ruleHelp(id, fixesById.get(id)),
      helpUri: "https://github.com/trustledger",
      properties: meta.cwe ? { tags: ["security", meta.cwe], cwe: meta.cwe } : {},
    };
  });

  const results = files.flatMap(f =>
    f.indicators.map(ind => {
      const r = buildFindingReport(ind, f.file_path, f.indicators, fixesById.get(ind.id));
      const sev = r.severity;
      const flows = codeFlows(r);
      return {
        ruleId:  ind.id,
        level:   severityToLevel(sev),
        message: { text: partsToText(r.evidence.summary) },
        locations: [{
          physicalLocation: {
            artifactLocation: { uri: f.file_path },
            region: { startLine: Math.max(1, ind.line ?? 1) },
          },
        }],
        ...(ind.fingerprint ? { partialFingerprints: { "trustledgerFinding/v1": ind.fingerprint } } : {}),
        ...(flows ? { codeFlows: flows } : {}),
        // Other places this same issue was reported, merged into this one result (findingCorrelation.ts).
        ...(ind.relatedLocations?.length ? {
          relatedLocations: ind.relatedLocations.map((loc, i) => ({
            id: i + 1,
            physicalLocation: { artifactLocation: { uri: f.file_path }, region: { startLine: Math.max(1, loc.line) } },
            message: { text: `Same issue: ${loc.label}${loc.reason === "on-path" ? " (on this finding's data-flow path)" : ""}` },
          })),
        } : {}),
        properties: {
          "security-severity": severityScore(sev),
          "trustledger/analysis": r.evidence.analysisLabel,
          "trustledger/evidence": reportAsPlainText(r),
          ...(ind.confidence != null ? { "trustledger/confidence": ind.confidence } : {}),
          ...(ind.reachability ? { "trustledger/reachability": ind.reachability } : {}),
        },
      };
    }),
  );

  return {
    $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: {
        driver: {
          name:            toolInfo.name ?? "TrustLedger",
          version:         toolInfo.version ?? "1.0.0",
          informationUri:  toolInfo.informationUri ?? "https://github.com/trustledger",
          rules,
        },
      },
      results,
    }],
  };
}
