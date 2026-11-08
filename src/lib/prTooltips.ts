import { rateText } from "./limits";
/**
 * The PR page's tooltip wording, in one place. Each says what the thing IS and what it means for the reviewer,
 * in the page's own terms (see lib/scanCounts.ts for the counts, lib/findingLifecycle.ts for the statuses).
 */

export const RISK_TIP: Record<string, string> = {
  CRITICAL: "Rated by the file's worst finding: critical. Needs a reviewer's sign-off before merge.",
  HIGH: "Rated by the file's worst finding: high. Needs a reviewer's sign-off before merge, unless your policy lets High through.",
  MEDIUM: "Rated by the file's worst finding: medium. Shown for review; doesn't need a sign-off.",
  LOW: "Nothing serious found in this file. Doesn't need a sign-off.",
  UNKNOWN: "This file couldn't be rated, for example because it wasn't fully analysed.",
};

export const SEVERITY_TIP: Record<string, string> = {
  critical: "Critical: can be exploited with little effort and has a severe impact, such as running attacker code or taking over data.",
  high: "High: a serious weakness that is likely exploitable, such as injecting into a query or reading arbitrary files.",
  medium: "Medium: exploitable only under some conditions, or with a limited impact.",
  low: "Low: a minor weakness, or hard to exploit.",
};

export const COUNT_TIP = {
  files: "How many files the scan read, how many of those are rated High or Critical (they need a reviewer's sign-off), and how many of those a reviewer has already signed off. A file is rated by its worst finding.",
  findings: "Vulnerabilities the scanner found, each tied to a weakness type (a CWE) such as SQL injection or XSS. AI-provenance and code-hygiene signals are not vulnerabilities and are not counted here.",
  changes: "Compared with the previous scan of this PR. New: not in that scan. Fixed: in that scan, gone now. Unchanged: in both. The first scan of a PR has nothing to compare with.",
  needReview: "Files whose worst finding is High or Critical. A reviewer signs them off (Attest) before the PR can merge, unless your policy says otherwise.",
  signedOff: "Files a reviewer has attested: they read the findings and accepted the file.",
  introduced: "On lines this pull request adds or changes.",
  preexisting: "In code that was there before this pull request, in a file it changes. Listed for context; the PR didn't introduce them.",
  decision: "Findings a reviewer accepted as a risk or marked as a false positive. They stay listed but don't block merges.",
  otherSignals: "AI-provenance and code-hygiene hints. They are not vulnerabilities, so they are not part of the security finding counts.",
} as const;

export const ACTION_TIP = {
  rescan: "Scan the PR's latest commit again with the current scanner and your triage decisions. It creates a new scan; this page stays as it is and links to the new one when it finishes. Limit: " + rateText("rescan") + ".",
  rescanNow: "Apply your saved triage decisions: scan the PR again. The merge check and file risk ratings update from the new scan.",
  copySummary: "Copy a markdown summary of this scan to paste into the pull request.",
  trustRecord: "Download a signed JSON record of this scan: its findings, triage decisions, attestations and the merge-gate outcome.",
  baseline: "Accept every current finding in this PR as known, so only new findings block merges from now on. Each can still be reopened one by one.",
  acceptBaseline: "Record all of these as accepted risk (reason: Baseline). Takes effect on the merge check after a rescan.",
  whichFiles: "List the files the scan could only partly analyse, and why.",
  olderEngine: "This scan used an older version of the scanner. A rescan uses the current one and may find more or fewer issues.",
  timing: "How long the scan took, and where the time went.",
  reviewFlagged: "Open a full-screen view of every file with security findings: a file list on the left, the code and each finding's data flow on the right.",
  openReview: "Open this file in the full-screen review, with the list of all flagged files alongside.",
  prevFile: "Previous flagged file (worst first).",
  nextFile: "Next flagged file (worst first).",
  attest: "Sign off this file: you have read its findings and accept it. Required for High and Critical files before merge.",
  needsReviewer: "Your role can't sign this file off. A security reviewer or admin has to.",
  prevFinding: "Previous finding in this file (p). At the first one, goes to the previous flagged file when there is one.",
  nextFinding: "Next finding in this file (n). At the last one, goes to the next flagged file when there is one.",
  closeReview: "Close the full-screen review (Esc).",
  prevReviewFile: "Previous flagged file ([).",
  nextReviewFile: "Next flagged file (]).",
} as const;

export const STATUS_TIP = {
  verified: "A reviewer attested this file.",
  pending: "Rated High or Critical and not yet signed off.",
  ok: "Not rated High or Critical: no sign-off needed.",
  signals: "How many different detections fired in this file: security findings and AI-provenance hints together.",
  aiContent: "An estimate of how much of this file looks AI-written, from style patterns. It is a hint, not proof of authorship.",
} as const;

export const COLUMN_TIP: Record<string, string> = {
  File: "The changed file. Click a row to open its findings and code.",
  Lang: "The language the file was analysed as.",
  "AI Content": STATUS_TIP.aiContent,
  Risk: "The file's rating, from its worst finding: Low, Medium, High or Critical.",
  Signals: STATUS_TIP.signals,
  Status: "Whether the file still needs a reviewer's sign-off.",
  Action: "Sign off the file, when it needs it and your role allows it.",
};

export const FILTER_TIP: Record<string, string> = {
  high: "Only files rated High or Critical, the ones that need review.",
  unattested: "High and Critical files that no reviewer has signed off yet.",
  all: "Every file in the scan, including Low and Medium.",
};

export const EVIDENCE_TIP: Record<string, string> = {
  code_evidence: "Writing-style patterns in the code that are typical of AI generation. Counts 25% of the combined score.",
  pr_evidence: "How the PR itself behaves: its size, how many commits, how fast it landed. Counts 25%.",
  git_evidence: "Git history signals: one huge commit, co-author trailers, generated-by markers. Counts 25%.",
  baseline_evidence: "How far this PR is from the author's usual habits. Counts 15%.",
  tool_evidence: "Explicit AI-tool artifacts found in the repo, such as agent config files. Counts 10%.",
};

export const OVERALL_TIP = {
  risk: "The PR's overall risk: the worst rating among its files.",
  commit: "The commit this scan analysed.",
  progress: "How many High and Critical files a reviewer has signed off. The PR can merge when all of them are, subject to your policy.",
} as const;
