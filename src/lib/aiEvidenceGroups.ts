/**
 * The evidence behind a scan's AI percentage, grouped by KIND, with how much each kind can be trusted and how sure the
 * scan is overall.
 *
 * The scanner has ~47 code signals plus pull-request, git, tooling and baseline evidence. Listed one by one they read
 * like 47 independent witnesses; they are not (naming, comment style and identifier length are all consequences of one
 * writing style). Grouping them says what KIND of evidence supports the number, and each group states what it cannot
 * show. This only REPORTS: it does not change the score. Pure.
 *
 * Confidence is a separate question from likelihood. "How AI-like is this code?" is the percentage; "how much should
 * you rely on it?" depends on how much of the code could be analysed and whether anything other than the code's own
 * style points the same way. A repository where 20% of the code was analysed can show a high percentage and still be
 * low confidence.
 */
import type { AIAttributionSummary } from "./aiAttributionSummary";

export type EvidenceGroupId = "direct_provenance" | "code_structure" | "linguistic_patterns" | "code_evolution" | "tool_metadata" | "developer_baseline" | "pr_context";
export type Confidence = "none" | "low" | "medium" | "high";

export interface EvidenceGroup {
  id: EvidenceGroupId;
  label: string;
  /** 0-1 strength of the evidence in this group; 0 when the group is not applicable. */
  score: number;
  /** Whether the data for this group exists for this scan. A group with no data says nothing (it is not "human"). */
  applicable: boolean;
  /** How far this KIND of evidence can be trusted on its own, given what was available. */
  confidence: Confidence;
  /** Weight in the blended evidence score (0 = reported for context, not part of the score). */
  weight: number;
  evidence: string[];
  limitations: string[];
}

export interface AttributionConfidence {
  level: Confidence;
  /** Why, in plain words. */
  reasons: string[];
  /** Evidence that does not exist for this scan, so it neither raised nor lowered the number. */
  unavailable: string[];
}

export interface AIEvidenceReport { groups: EvidenceGroup[]; confidence: AttributionConfidence }

/** Weights of the blended evidence score (scanner.ts runScan): shown, not decided, here. */
export const GROUP_WEIGHTS = { code_structure: 0.25, pr_context: 0.25, code_evolution: 0.25, developer_baseline: 0.15, tool_metadata: 0.10, direct_provenance: 0, linguistic_patterns: 0 } as const;

/** The code signals that are about wording (comments, messages, documentation), as opposed to code shape. */
export const LINGUISTIC_SIGNAL_IDS: ReadonlySet<string> = new Set([
  "comment-phrasing", "error-message-phrasing", "prompt-leakage", "comment-density", "doc-coverage", "jsdoc-completeness",
]);

export interface EvidenceFile {
  line_count: number;
  explained_signals: ReadonlyArray<{ id: string; value: number }>;
  watermarks: ReadonlyArray<unknown>;
}

export interface EvidenceGroupsInput {
  codeEvidence: number;
  analysis: AIAttributionSummary;
  files: readonly EvidenceFile[];
  pr: { applicable: boolean; score: number; notes: readonly string[] };
  git: { applicable: boolean; score: number; aiCommits: number; totalCommits: number };
  baseline: { applicable: boolean; score: number; reasons: readonly string[] };
  tools: readonly string[];
  toolScore: number;
  mixedAuthorship: boolean;
}

const clamp01 = (n: number) => (Number.isFinite(n) ? Math.min(1, Math.max(0, n)) : 0);
const pct = (n: number) => `${Math.round(n * 100)}%`;
const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

/** Confidence of a group that has data: not applicable → none; otherwise by how much of the code its data covers. */
function byCoverage(applicable: boolean, coverage: number, cap: Confidence = "high"): Confidence {
  if (!applicable) return "none";
  const level: Confidence = coverage >= 0.8 ? "high" : coverage >= 0.5 ? "medium" : "low";
  const order: Confidence[] = ["none", "low", "medium", "high"];
  return order[Math.min(order.indexOf(level), order.indexOf(cap))];
}

export function buildEvidenceGroups(input: EvidenceGroupsInput): AIEvidenceReport {
  const a = input.analysis;
  const analysed = a.analyzed_loc > 0;
  const coverage = a.analysis_coverage;

  // Wording evidence: per analysed file the strongest wording signal, weighted by the file's lines.
  let lingLoc = 0, lingSum = 0, lingFiles = 0;
  for (const f of input.files) {
    if (f.line_count <= 20) continue;
    const top = Math.max(0, ...f.explained_signals.filter(s => LINGUISTIC_SIGNAL_IDS.has(s.id)).map(s => s.value));
    lingLoc += f.line_count; lingSum += f.line_count * top;
    if (top > 0.15) lingFiles++;
  }
  const lingScore = lingLoc > 0 ? lingSum / lingLoc : 0;
  const watermarkFiles = input.files.filter(f => f.watermarks.length > 0).length;

  const groups: EvidenceGroup[] = [
    {
      id: "direct_provenance", label: "Direct provenance", weight: GROUP_WEIGHTS.direct_provenance,
      applicable: watermarkFiles > 0, score: watermarkFiles > 0 ? 1 : 0,
      confidence: watermarkFiles > 0 ? "medium" : "none",
      evidence: watermarkFiles > 0 ? [`Invisible watermark characters in ${plural(watermarkFiles, "file")}`] : [],
      limitations: [
        "No authenticated generation record is available, so nothing here proves who or what wrote the code.",
        ...(watermarkFiles > 0 ? ["Watermark-like characters can also come from copy-pasting text out of a web page or document."] : []),
      ],
    },
    {
      id: "code_structure", label: "Code structure and style", weight: GROUP_WEIGHTS.code_structure,
      applicable: analysed, score: analysed ? clamp01(input.codeEvidence) : 0,
      confidence: byCoverage(analysed, coverage),
      evidence: analysed ? [`${pct(a.estimated_ai_percentage)} of ${plural(a.analyzed_loc, "analysed source line")} look AI-written by file score`] : [],
      limitations: [
        "Heuristic signals about how the code reads; the scores have not been calibrated against labelled code.",
        "Includes the wording signals below, so the two are not independent.",
        ...(a.unknown_loc > 0 ? [`${plural(a.unknown_loc, "line")} in files too short to judge are not included.`] : []),
      ],
    },
    {
      id: "linguistic_patterns", label: "Comments and wording", weight: GROUP_WEIGHTS.linguistic_patterns,
      applicable: lingLoc > 0, score: clamp01(lingScore),
      confidence: byCoverage(lingLoc > 0, coverage, "medium"),
      evidence: lingFiles > 0 ? [`Formulaic comment, message or documentation wording in ${plural(lingFiles, "file")}`] : [],
      limitations: ["Shown for context: it is already part of the code-structure score. Many people, and style guides, write documentation this way."],
    },
    {
      id: "code_evolution", label: "Git history", weight: GROUP_WEIGHTS.code_evolution,
      applicable: input.git.applicable, score: input.git.applicable ? clamp01(input.git.score) : 0,
      confidence: input.git.applicable ? (input.git.aiCommits > 0 ? "medium" : "low") : "none",
      evidence: input.git.applicable && input.git.aiCommits > 0 ? [`${input.git.aiCommits} of ${plural(input.git.totalCommits, "commit")} name an AI tool in the message`] : [],
      limitations: [
        "Only commit messages are read: an AI-written commit that says nothing about it looks human here.",
        "A suspicious history (unsigned commits, odd authors) is a separate trust finding, not AI evidence.",
      ],
    },
    {
      id: "tool_metadata", label: "AI tooling in the repository", weight: GROUP_WEIGHTS.tool_metadata,
      applicable: input.tools.length > 0, score: input.tools.length > 0 ? clamp01(input.toolScore) : 0,
      confidence: input.tools.length > 0 ? "low" : "none",
      evidence: input.tools.length > 0 ? [`Found: ${input.tools.join(", ")}`] : [],
      limitations: ["A tool's config file shows the tool is set up here, not that this code came from it."],
    },
    {
      id: "developer_baseline", label: "Difference from the author's usual work", weight: GROUP_WEIGHTS.developer_baseline,
      applicable: input.baseline.applicable, score: input.baseline.applicable ? clamp01(input.baseline.score) : 0,
      confidence: input.baseline.applicable ? "medium" : "none",
      evidence: input.baseline.applicable ? [...input.baseline.reasons] : [],
      limitations: ["Needs a history of the author's earlier pull requests; a change in working pattern has many causes besides AI."],
    },
    {
      id: "pr_context", label: "Pull-request behaviour", weight: GROUP_WEIGHTS.pr_context,
      applicable: input.pr.applicable, score: input.pr.applicable ? clamp01(input.pr.score) : 0,
      confidence: input.pr.applicable ? "low" : "none",
      evidence: input.pr.applicable ? [...input.pr.notes] : [],
      limitations: ["Size, speed and file count describe the change, not who wrote it. Weak evidence on its own."],
    },
  ];

  // Overall: how much to rely on the percentage.
  const reasons: string[] = [];
  const unavailable: string[] = [];
  if (!input.git.applicable) unavailable.push("git history");
  if (!input.baseline.applicable) unavailable.push("the author's baseline");
  if (!input.pr.applicable) unavailable.push("pull-request details");

  let level: Confidence;
  if (!analysed) {
    level = "none";
    reasons.push("No source file was long enough to analyse, so there is no percentage to rely on.");
  } else {
    // Independent corroboration: evidence about the code's history or author, not about how the code itself reads.
    const corroborating = groups.filter(g => (g.id === "direct_provenance" || g.id === "code_evolution" || g.id === "developer_baseline") && g.applicable);
    level = coverage < 0.5 ? "low" : coverage >= 0.8 && corroborating.length > 0 ? "high" : "medium";
    reasons.push(`${pct(coverage)} of the source code could be analysed.`);
    if (corroborating.length === 0) reasons.push("Only the code's own style supports the number: nothing about its history or author can confirm it.");
    else reasons.push(`Also available: ${corroborating.map(g => g.label.toLowerCase()).join(", ")}.`);
    if (input.mixedAuthorship && level === "high") { level = "medium"; }
    if (input.mixedAuthorship) reasons.push("The files disagree strongly (some look AI-written, some human), so one percentage describes the repository poorly.");
  }
  return { groups, confidence: { level, reasons, unavailable } };
}
