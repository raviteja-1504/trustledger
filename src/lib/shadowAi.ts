/**
 * Shadow AI: which AI coding tools a team actually uses, compared with the org's approved-tools policy.
 *
 * Built from what scans already store, never from guesses about people:
 *   - EXPLICIT evidence (scans.ai_tooling): a tool's config file in the repo (.cursorrules, CLAUDE.md, Copilot
 *     instructions...), an attribution marker in code ("Co-authored-by: Claude"), or a signed commit
 *     (co-author trailer, bot author -- aiTools.ts detectCommitEvidence). Only explicit evidence of an
 *     UNAPPROVED tool is a violation.
 *   - HINTS (scan_files.attribution): the style guesser's opinion of which model a file "looks like". Style-based
 *     attribution is unreliable, so a hint is shown for context and is never a violation.
 *
 * A detection is one (repo, tool, evidence location), however many scans saw it, so a triage decision sticks.
 * Without a configured policy nothing is a violation: every tool is "unreviewed" until an admin decides.
 *
 * Client-safe: pure, no I/O.
 */
import { toolId, toolLabel, UNSPECIFIED_TOOL } from "./aiTools";

export type DetectionTier = "explicit" | "hint";
export type Approval = "approved" | "unapproved" | "unreviewed" | "unidentified";
export type ShadowStatus = "open" | "investigating" | "acceptable" | "resolved";

export interface ScanRow {
  id: string;
  repo_full_name: string;
  pr_number: number | null;
  pr_author: string | null;
  created_at: string;
  ai_tooling: Array<{ tool?: string; file?: string; label?: string }> | null;
}
export interface FileRow { scan_id: string; file_path: string; attribution: { model?: string; confidence?: number; signals?: string[] } | null }
export interface TriageRow { status: ShadowStatus; notes: Array<{ at: string; by: string | null; text: string }>; updated_at: string }

export interface Detection {
  key: string;
  tier: DetectionTier;
  tool: string;
  tool_label: string;
  repo: string;
  /** File path, or "commit:<sha>" for commit evidence. */
  location: string;
  evidence: string[];
  /** 1 for explicit evidence; the style guesser's confidence for a hint. */
  confidence: number;
  developers: string[];
  pull_requests: number[];
  scans: number;
  first_seen: string;
  last_seen: string;
  approval: Approval;
  /** Explicit evidence of an unapproved tool. */
  violation: boolean;
  status: ShadowStatus;
  /** A "resolved" decision that newer evidence has since contradicted. */
  reopened: boolean;
  notes: TriageRow["notes"];
}

export const HINT_MIN_CONFIDENCE = 0.6;

/**
 * Unapproved AI tools in ONE scan's explicit evidence, grouped by tool. Empty without a policy. Evidence a reviewer
 * has ACCEPTED for this repository (triage "acceptable" on its detection) is left out: it used to be flagged on the
 * PR check, and raise an alert, again on every pull request.
 */
export function unapprovedToolsInScan(
  aiTooling: ReadonlyArray<{ tool?: string; file?: string; label?: string }> | null | undefined,
  policy: readonly string[] | null,
  accepted?: { repo: string; triage: ReadonlyMap<string, Pick<TriageRow, "status">> },
): Array<{ tool: string; label: string; evidence: string[] }> {
  if (!policy) return [];
  const byTool = new Map<string, string[]>();
  for (const a of aiTooling ?? []) {
    const tool = toolId(a.tool);
    if (!tool || !a.file || approvalOf(tool, policy) !== "unapproved") continue;
    if (accepted && accepted.triage.get(detectionKey(accepted.repo, tool, a.file))?.status === "acceptable") continue;
    const where = a.file.startsWith("commit:") ? `commit ${a.file.slice(7)}` : `\`${a.file}\``;
    const list = byTool.get(tool) ?? [];
    list.push(a.label ? `${where} (${a.label})` : where);
    byTool.set(tool, list);
  }
  return [...byTool.entries()].map(([tool, evidence]) => ({ tool, label: toolLabel(tool), evidence }));
}

/** The GitHub check-run section warning about unapproved AI tools in a PR. Never blocks the merge. "" if none. */
export function shadowAiCheckMarkdown(found: ReturnType<typeof unapprovedToolsInScan>, shadowAiUrl: string): string {
  if (found.length === 0) return "";
  const lines = found.map(f => `- **${f.label}**: ${f.evidence.slice(0, 3).join("; ")}${f.evidence.length > 3 ? `; and ${f.evidence.length - 3} more` : ""}`);
  return [
    "", "", "### Unapproved AI tools (warning)",
    "This pull request shows evidence of AI tools your organisation has not approved. This is a warning only: it does not block the merge.",
    ...lines,
    shadowAiUrl ? `Review it in [Shadow AI](${shadowAiUrl}).` : "",
  ].join("\n");
}

export function detectionKey(repo: string, tool: string, location: string): string {
  return `${repo}|${tool}|${location}`;
}

export function approvalOf(tool: string, policy: readonly string[] | null): Approval {
  if (tool === UNSPECIFIED_TOOL) return "unidentified";
  if (!policy) return "unreviewed";
  return policy.includes(tool) ? "approved" : "unapproved";
}

export function buildDetections(
  scans: readonly ScanRow[],
  files: readonly FileRow[],
  policy: readonly string[] | null,
  triage: ReadonlyMap<string, TriageRow>,
): Detection[] {
  const byScan = new Map(scans.map(s => [s.id, s]));
  type Acc = Omit<Detection, "approval" | "violation" | "status" | "reopened" | "notes" | "developers" | "pull_requests" | "evidence"> & {
    developers: Set<string>; pull_requests: Set<number>; evidence: Set<string>; scanIds: Set<string>;
  };
  const acc = new Map<string, Acc>();

  const add = (scan: ScanRow, tier: DetectionTier, tool: string, location: string, evidence: string, confidence: number) => {
    const key = detectionKey(scan.repo_full_name, tool, location);
    let d = acc.get(key);
    if (!d) {
      d = {
        key, tier, tool, tool_label: toolLabel(tool), repo: scan.repo_full_name, location, confidence,
        scans: 0, first_seen: scan.created_at, last_seen: scan.created_at,
        developers: new Set(), pull_requests: new Set(), evidence: new Set(), scanIds: new Set(),
      };
      acc.set(key, d);
    }
    // Explicit evidence is collected first (below), so a location with any explicit evidence stays explicit and a
    // later hint for it only adds to its evidence; a hint-only location keeps its strongest guess.
    if (d.tier === "hint") d.confidence = Math.max(d.confidence, confidence);
    d.evidence.add(evidence);
    if (scan.pr_author) d.developers.add(scan.pr_author);
    if (scan.pr_number) d.pull_requests.add(scan.pr_number);
    if (!d.scanIds.has(scan.id)) { d.scanIds.add(scan.id); d.scans++; }
    if (scan.created_at < d.first_seen) d.first_seen = scan.created_at;
    if (scan.created_at > d.last_seen) d.last_seen = scan.created_at;
  };

  for (const scan of scans) {
    for (const a of scan.ai_tooling ?? []) {
      const tool = toolId(a.tool);
      if (!tool || !a.file) continue;
      add(scan, "explicit", tool, a.file, a.label ?? "AI tool evidence", 1);
    }
  }
  for (const f of files) {
    const scan = byScan.get(f.scan_id);
    const tool = toolId(f.attribution?.model);
    const conf = f.attribution?.confidence ?? 0;
    if (!scan || !tool || tool === UNSPECIFIED_TOOL || conf < HINT_MIN_CONFIDENCE) continue;
    add(scan, "hint", tool, f.file_path, `Code style resembles ${toolLabel(tool)} (${Math.round(conf * 100)}%)`, conf);
  }

  return [...acc.values()].map(d => {
    const approval = approvalOf(d.tool, policy);
    const t = triage.get(d.key);
    const reopened = !!t && t.status === "resolved" && d.last_seen > t.updated_at;
    const { scanIds: _scanIds, ...rest } = d;
    void _scanIds;
    return {
      ...rest,
      developers: [...d.developers].sort(),
      pull_requests: [...d.pull_requests].sort((a, b) => a - b),
      evidence: [...d.evidence],
      approval,
      violation: d.tier === "explicit" && approval === "unapproved",
      status: reopened ? "open" : t?.status ?? "open",
      reopened,
      notes: t?.notes ?? [],
    };
  }).sort((a, b) => Number(b.violation) - Number(a.violation) || (a.last_seen < b.last_seen ? 1 : a.last_seen > b.last_seen ? -1 : 0));
}

export interface ShadowSummary {
  policy_configured: boolean;
  /** Explicit evidence of unapproved tools that is still open or under investigation. */
  open_violations: number;
  violations: number;
  approved_usage: number;
  unreviewed: number;
  unidentified: number;
  /** Explicit evidence nobody has decided on: no identifiable tool, or (without a policy) any tool -- minus what a
   *  reviewer has accepted or resolved. */
  needs_review: number;
  hints: number;
  developers_with_violations: number;
  /** Per tool: its violations split by triage status, so an accepted one doesn't read as an open violation. */
  by_tool: Array<{ tool: string; label: string; detections: number; violations: number; open: number; accepted: number; resolved: number; approval: Approval }>;
  /** Share of explicit tool evidence that is for approved tools (null until a policy exists or nothing is seen). */
  compliance: number | null;
}

export function summarize(detections: readonly Detection[], policy: readonly string[] | null): ShadowSummary {
  const explicit = detections.filter(d => d.tier === "explicit" && d.approval !== "unidentified");
  const violations = detections.filter(d => d.violation);
  const isOpen = (d: Detection) => d.status === "open" || d.status === "investigating";
  const tools = new Map<string, { detections: number; violations: number; open: number; accepted: number; resolved: number }>();
  for (const d of detections) {
    const t = tools.get(d.tool) ?? { detections: 0, violations: 0, open: 0, accepted: 0, resolved: 0 };
    t.detections++;
    if (d.violation) {
      t.violations++;
      if (isOpen(d)) t.open++; else if (d.status === "acceptable") t.accepted++; else t.resolved++;
    }
    tools.set(d.tool, t);
  }
  const decided = (d: Detection) => d.status === "acceptable" || d.status === "resolved";
  const counted = explicit.filter(d => !(d.violation && (d.status === "acceptable" || d.status === "resolved")));
  return {
    policy_configured: !!policy,
    open_violations: violations.filter(isOpen).length,
    violations: violations.length,
    approved_usage: detections.filter(d => d.approval === "approved" && d.tier === "explicit").length,
    unreviewed: detections.filter(d => d.approval === "unreviewed" && d.tier === "explicit").length,
    unidentified: detections.filter(d => d.approval === "unidentified").length,
    needs_review: detections.filter(d => d.tier === "explicit" && (d.approval === "unidentified" || d.approval === "unreviewed") && !decided(d)).length,
    hints: detections.filter(d => d.tier === "hint").length,
    developers_with_violations: new Set(violations.filter(isOpen).flatMap(d => d.developers)).size,
    by_tool: [...tools.entries()].map(([tool, v]) => ({ tool, label: toolLabel(tool), ...v, approval: approvalOf(tool, policy) }))
      .sort((a, b) => b.open - a.open || b.violations - a.violations || b.detections - a.detections),
    compliance: !policy || counted.length === 0 ? null : counted.filter(d => !d.violation).length / counted.length,
  };
}
