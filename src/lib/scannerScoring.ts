/**
 * Evidence breakdown types, author-baseline deviation and PR-behavior scoring, split out of scanner.ts
 * (Task 9, scanner modularization). scanner.ts re-exports the public names, so importers are unchanged.
 */
import type { PRMetadata, AILikelihoodBand } from "./scanner";
import type { AIEvidenceReport } from "./aiEvidenceGroups";

// ── Evidence Breakdown ───────────────────────────────────────────────────────

export interface DeveloperBaseline {
  pr_count:          number;
  avg_loc_per_pr:    number;
  avg_commits_per_pr: number;
  avg_files_per_pr:  number;
  avg_ai_percentage: number;
}

export interface BaselineDeviation {
  score:            number;   // 0–1: how far this PR deviates from author's norm
  loc_deviation:    number;   // multiplier: 3x = 3× their usual LOC
  commit_deviation: number;   // multiplier: 0.2x = far fewer commits than usual
  reasons:          string[];
}

// Confidence multiplier by sample size. A hard "need 3+ PRs" cliff meant
// baseline_evidence stayed at exactly 0 for every author until their 4th
// scan (the baseline is fetched *before* this PR is added, so PR #3 still
// sees pr_count=2) -- in practice this made the signal look permanently
// broken for any org without long same-author scan history. A single prior
// PR is weak evidence but not zero evidence, so scale in gradually instead
// of gating outright; full confidence still requires the same 3-PR bar.
function baselineConfidence(prCount: number): number {
  if (prCount <= 0) return 0;
  if (prCount === 1) return 0.35;
  if (prCount === 2) return 0.65;
  return 1;
}

export function scoreBaselineDeviation(
  meta: PRMetadata,
  baseline: DeveloperBaseline,
): BaselineDeviation {
  const reasons: string[] = [];
  let score = 0;

  const confidence = baselineConfidence(baseline.pr_count);
  if (confidence === 0) {
    return { score: 0, loc_deviation: 1, commit_deviation: 1, reasons: [] };
  }

  // LOC deviation
  const locDev = baseline.avg_loc_per_pr > 0
    ? meta.additions / baseline.avg_loc_per_pr
    : 1;
  if (locDev > 5) {
    score += 0.35;
    reasons.push(`${Math.round(locDev)}× more LOC than their usual PRs (avg: ${Math.round(baseline.avg_loc_per_pr)} lines)`);
  } else if (locDev > 3) {
    score += 0.20;
    reasons.push(`${Math.round(locDev)}× more LOC than their usual PRs`);
  } else if (locDev > 2) {
    score += 0.10;
  }

  // Commit count deviation (far fewer commits than usual = AI generated in one go)
  const commitDev = baseline.avg_commits_per_pr > 0
    ? meta.commits / baseline.avg_commits_per_pr
    : 1;
  if (commitDev < 0.3 && meta.additions > 100) {
    score += 0.30;
    reasons.push(`Only ${meta.commits} commit(s) vs their usual ${Math.round(baseline.avg_commits_per_pr)} — unusually low for this author`);
  } else if (commitDev < 0.5) {
    score += 0.15;
    reasons.push(`Fewer commits than this author's typical pattern`);
  }

  // Files changed deviation
  const filesDev = baseline.avg_files_per_pr > 0
    ? meta.changed_files / baseline.avg_files_per_pr
    : 1;
  if (filesDev > 4 && meta.commits <= 2) {
    score += 0.20;
    reasons.push(`${meta.changed_files} files in ${meta.commits} commit(s) — this author usually touches ${Math.round(baseline.avg_files_per_pr)} files`);
  }

  if (confidence < 1 && reasons.length > 0) {
    reasons.push(`(limited confidence — only ${baseline.pr_count} prior PR${baseline.pr_count === 1 ? "" : "s"} on file for this author)`);
  }

  return {
    score:            Math.min(1, score * confidence),
    loc_deviation:    locDev,
    commit_deviation: commitDev,
    reasons,
  };
}

export interface EvidenceBreakdown {
  code_evidence:      number;  // 0–1: style/structure/AI-pattern signals
  pr_evidence:        number;  // 0–1: PR behavior (LOC, commits, timing)
  git_evidence:       number;  // 0–1: git provenance (commit velocity, history)
  tool_evidence:      number;  // 0–1: explicit tool artifacts (Cursor, Copilot, etc.)
  baseline_evidence:  number;  // 0–1: deviation from developer's historical patterns
  combined:           number;  // 0–1: weighted combination
  likelihood:         AILikelihoodBand;
  boosts:             string[]; // human-readable reasons for score boosts
  baseline_deviation?: BaselineDeviation; // developer baseline comparison detail
  // The evidence grouped by kind, and how much to rely on the percentage (aiEvidenceGroups.ts). Rides in this stored
  // JSON so a saved scan keeps it without a new column. Reporting only: it does not change `combined`.
  attribution?:       AIEvidenceReport;
}

// ── PR Behavior Scoring ──────────────────────────────────────────────────────
// Weights: PR Behavior 25%, Git Provenance 30%, Code Structure 25%,
//          Tool Evidence 15%, Attestation/Baseline 5%

export const GENERATED_PATH_RE = /(?:^|\/)(?:dist|vendor|generated|proto|protobuf|openapi|\.next|node_modules|__generated__|migrations)\//;

export function scorePRBehavior(meta: PRMetadata, totalFileLines: number): {
  score:  number;
  boosts: string[];
} {
  const boosts: string[] = [];
  let score = 0;

  const linesAdded  = meta.additions;
  const commitCount = Math.max(1, meta.commits);
  const fileCount   = Math.max(1, meta.changed_files);
  const locPerCommit = linesAdded / commitCount;

  // Signal 1: LOC vs commit count (very high weight)
  // >500 LOC in a single commit is a strong AI indicator
  if (locPerCommit > 1000) {
    score += 0.30;
    boosts.push(`${linesAdded} lines added in ${commitCount} commit(s) — ${Math.round(locPerCommit)} LOC/commit`);
  } else if (locPerCommit > 500) {
    score += 0.20;
    boosts.push(`High LOC/commit ratio: ${Math.round(locPerCommit)} lines per commit`);
  } else if (locPerCommit > 200) {
    score += 0.10;
  }

  // Signal 2: Single commit for entire feature
  if (commitCount === 1 && linesAdded > 300) {
    score += 0.15;
    boosts.push(`Entire feature in 1 commit (${linesAdded} lines)`);
  } else if (commitCount <= 2 && linesAdded > 500) {
    score += 0.10;
    boosts.push(`${linesAdded} lines in only ${commitCount} commits`);
  }

  // Signal 3: Files changed vs commits ratio
  const filesPerCommit = fileCount / commitCount;
  if (filesPerCommit > 8 && commitCount <= 2) {
    score += 0.10;
    boosts.push(`${fileCount} files changed in ${commitCount} commit(s)`);
  } else if (filesPerCommit > 5) {
    score += 0.05;
  }

  // Signal 4: Branch-to-PR timing (if available)
  if (meta.created_at && meta.head_pushed_at) {
    const prCreated   = new Date(meta.created_at).getTime();
    const branchPush  = new Date(meta.head_pushed_at).getTime();
    const minutesDiff = Math.abs(prCreated - branchPush) / 60000;
    if (minutesDiff < 10 && linesAdded > 200) {
      score += 0.20;
      boosts.push(`PR opened ${Math.round(minutesDiff)} min after push with ${linesAdded} lines`);
    } else if (minutesDiff < 30 && linesAdded > 500) {
      score += 0.10;
      boosts.push(`${linesAdded} lines pushed and PR opened within ${Math.round(minutesDiff)} min`);
    }
  }

  // Exemption: reduce score if many files look generated
  // (this would need file paths — applied in runScan)

  return { score: Math.min(1, score), boosts };
}
