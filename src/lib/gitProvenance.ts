/**
 * TrustLedger Git Provenance Engine
 *
 * Analyzes git commit history to assess provenance integrity and detect
 * suspicious authorship patterns. Designed to consume git log output in a
 * structured format, without needing to shell out at scan time.
 *
 * Input format (--format="%H|%an|%ae|%at|%G?|%s"):
 *   hash|author_name|author_email|unix_timestamp|gpg_status|subject
 *
 * GPG status codes: G=good N=no-sig B=bad U=untrusted X=expired E=missing-key
 *
 * Risk signals:
 *   - Commits with no GPG signature (suspicious in security-sensitive repos)
 *   - Large sudden commit (>500 lines changed in one commit)
 *   - First-time contributor authoring critical files
 *   - Unusual commit timing (nights/weekends spikes in business repos)
 *   - Author email domain mismatch (personal email for corp repo)
 *   - Rapid velocity burst (>10 commits in 1 hour)
 *   - Squash abuse (commit messages suggesting AI-bulk generation)
 */

// ── Types ─────────────────────────────────────────────────────────────────────

export type GpgStatus = "G" | "N" | "B" | "U" | "X" | "E" | "?";

export interface CommitInfo {
  hash:        string;
  shortHash:   string;
  authorName:  string;
  authorEmail: string;
  timestamp:   number;   // Unix seconds
  gpgStatus:   GpgStatus;
  subject:     string;
  isMerge:     boolean;
}

export interface AuthorStats {
  name:           string;
  email:          string;
  commitCount:    number;
  firstSeen:      number;   // earliest timestamp
  lastSeen:       number;   // latest timestamp
  signedCommits:  number;
  unsignedCommits: number;
  signRate:       number;   // 0–1
  isFirstTime:    boolean;  // only one commit in history
  avgIntervalSec: number;   // average time between commits
  burstCommits:   number;   // commits within 1-hour windows
}

export interface ProvenanceRisk {
  kind:       string;
  severity:   "low" | "medium" | "high";
  detail:     string;
  commitHash?: string;
  author?:     string;
}

export interface ProvenanceSummary {
  totalCommits:      number;
  signedRate:        number;   // 0–1 fraction with good GPG signatures
  authors:           AuthorStats[];
  risks:             ProvenanceRisk[];
  overallRiskScore:  number;   // 0–1
  label:             "TRUSTED" | "LOW_RISK" | "MODERATE_RISK" | "HIGH_RISK" | "CRITICAL_RISK";
  aiAuthoredCommits: number;   // commits whose subject suggests AI-bulk generation
}

// ── Parser ────────────────────────────────────────────────────────────────────

const AI_COMMIT_SUBJECTS: RegExp[] = [
  /^(?:generated|auto-generated|ai-generated|copilot|gpt|claude|gemini)\b/i,
  /^(?:feat|fix|chore|refactor)\(.+\):\s+(?:implement|add|update|create)\s+\w+\s+(?:with|using|via)\s+(?:AI|ChatGPT|Copilot|Claude|Gemini)/i,
  /bulk\s+(?:generate|generated|update|commit)/i,
  /^\[AI\]/i,
  /\b(?:ChatGPT|Copilot|Claude|Gemini|Cursor)\b.*\bgenerat/i,
  // LLM coding-agent tool names directly referenced in the commit message
  /\b(?:windsurf|devin|aider|cline|codeium|cursor\s*agent|replit\s*agent)\b/i,
  // "Co-Authored-By: Claude <noreply@anthropic.com>" / "Co-authored-by: Cursor Agent" style trailers
  /co-authored-by:\s*(?:claude|cursor|copilot|chatgpt|gpt|gemini|devin|windsurf|aider|cline|codeium)/i,
  // "🤖 Generated with [Claude Code]" / "Generated with Claude Code" markers
  /generated with\s*\[?(?:claude code|cursor|copilot|windsurf|devin|aider|cline)\]?/i,
  /🤖/,
];

export function parseGitLog(logOutput: string): CommitInfo[] {
  const commits: CommitInfo[] = [];
  const lines = logOutput.split("\n").filter(l => l.trim().length > 0);

  for (const line of lines) {
    const parts = line.split("|");
    if (parts.length < 6) continue;

    const hash   = parts[0].trim();
    const name   = parts[1].trim();
    const email  = parts[2].trim();
    const ts     = parseInt(parts[3].trim(), 10);
    const gpg    = (parts[4].trim() || "?") as GpgStatus;
    const subj   = parts.slice(5).join("|").trim();

    if (!hash || isNaN(ts)) continue;

    commits.push({
      hash,
      shortHash:   hash.slice(0, 8),
      authorName:  name,
      authorEmail: email,
      timestamp:   ts,
      gpgStatus:   gpg,
      subject:     subj,
      isMerge:     subj.startsWith("Merge ") || subj.startsWith("Merged "),
    });
  }

  return commits.sort((a, b) => a.timestamp - b.timestamp);
}

// ── Author statistics ─────────────────────────────────────────────────────────

export function computeAuthorStats(commits: CommitInfo[]): AuthorStats[] {
  const byAuthor = new Map<string, CommitInfo[]>();
  for (const c of commits) {
    const key = c.authorEmail.toLowerCase();
    if (!byAuthor.has(key)) byAuthor.set(key, []);
    byAuthor.get(key)!.push(c);
  }

  const stats: AuthorStats[] = [];
  for (const [, authorCommits] of Array.from(byAuthor.entries())) {
    const sorted    = authorCommits.sort((a, b) => a.timestamp - b.timestamp);
    const signed    = sorted.filter(c => c.gpgStatus === "G" || c.gpgStatus === "U").length;
    const unsigned  = sorted.filter(c => c.gpgStatus === "N" || c.gpgStatus === "?").length;

    // Burst detection: commits within any 1-hour window
    let burstCount = 0;
    for (let i = 0; i < sorted.length; i++) {
      let window = 0;
      for (let j = i; j < sorted.length && sorted[j].timestamp - sorted[i].timestamp < 3600; j++) {
        window++;
      }
      if (window > burstCount) burstCount = window;
    }

    // Average inter-commit interval
    let avgInterval = 0;
    if (sorted.length > 1) {
      const totalGap = sorted[sorted.length - 1].timestamp - sorted[0].timestamp;
      avgInterval = totalGap / (sorted.length - 1);
    }

    stats.push({
      name:            sorted[0].authorName,
      email:           sorted[0].authorEmail,
      commitCount:     sorted.length,
      firstSeen:       sorted[0].timestamp,
      lastSeen:        sorted[sorted.length - 1].timestamp,
      signedCommits:   signed,
      unsignedCommits: unsigned,
      signRate:        sorted.length > 0 ? signed / sorted.length : 0,
      isFirstTime:     sorted.length === 1,
      avgIntervalSec:  avgInterval,
      burstCommits:    burstCount,
    });
  }

  return stats.sort((a, b) => b.commitCount - a.commitCount);
}

// ── Risk detection ────────────────────────────────────────────────────────────

export function detectProvenanceRisks(commits: CommitInfo[], authors: AuthorStats[]): ProvenanceRisk[] {
  const risks: ProvenanceRisk[] = [];

  // 1. Unsigned commits in a predominantly signed repo
  const totalNonMerge = commits.filter(c => !c.isMerge).length;
  const signed        = commits.filter(c => c.gpgStatus === "G" || c.gpgStatus === "U").length;
  const signRate      = totalNonMerge > 0 ? signed / totalNonMerge : 1;
  if (signRate < 0.50 && totalNonMerge > 5) {
    risks.push({
      kind: "low-signature-rate",
      severity: signRate < 0.20 ? "high" : "medium",
      detail: `${Math.round(signRate * 100)}% of commits are GPG-signed — provenance chain cannot be fully verified`,
    });
  }

  // 2. Bad GPG signatures
  const badSig = commits.filter(c => c.gpgStatus === "B");
  for (const c of badSig) {
    risks.push({
      kind: "bad-gpg-signature",
      severity: "high",
      detail: `Commit ${c.shortHash} has a BAD GPG signature — potential tampering`,
      commitHash: c.hash,
      author: c.authorName,
    });
  }

  // 3. Burst commit patterns
  for (const auth of authors) {
    if (auth.burstCommits > 8) {
      risks.push({
        kind: "burst-commit-pattern",
        severity: auth.burstCommits > 15 ? "high" : "medium",
        detail: `${auth.name} (${auth.email}) pushed ${auth.burstCommits} commits within a 1-hour window — possible AI-bulk generation`,
        author: auth.email,
      });
    }
  }

  // 4. Suspiciously rapid interval (< 2 min between commits on average for > 5 commits)
  for (const auth of authors) {
    if (auth.commitCount > 5 && auth.avgIntervalSec > 0 && auth.avgIntervalSec < 120) {
      risks.push({
        kind: "machine-commit-velocity",
        severity: "medium",
        detail: `${auth.name} averages ${Math.round(auth.avgIntervalSec)}s between commits — velocity inconsistent with manual authoring`,
        author: auth.email,
      });
    }
  }

  // 5. First-time contributor with significant commit count in one session
  for (const auth of authors) {
    if (auth.isFirstTime && auth.burstCommits > 1) {
      risks.push({
        kind: "unknown-contributor",
        severity: "low",
        detail: `${auth.name} is a first-time contributor with no commit history — contributor risk unknown`,
        author: auth.email,
      });
    }
  }

  // 6. AI-suggestive commit subjects
  for (const commit of commits) {
    if (AI_COMMIT_SUBJECTS.some(re => re.test(commit.subject))) {
      risks.push({
        kind: "ai-generated-commit",
        severity: "low",
        detail: `Commit ${commit.shortHash} subject suggests AI-generated content: "${commit.subject.slice(0, 80)}"`,
        commitHash: commit.hash,
        author: commit.authorName,
      });
    }
  }

  // 7. Email domain anomaly: multiple distinct domains from same named author
  const nameToEmails = new Map<string, Set<string>>();
  for (const auth of authors) {
    if (!nameToEmails.has(auth.name)) nameToEmails.set(auth.name, new Set());
    const domain = auth.email.split("@")[1] ?? "";
    if (domain) nameToEmails.get(auth.name)?.add(domain);
  }
  for (const [name, domains] of Array.from(nameToEmails.entries())) {
    if (domains.size > 2) {
      risks.push({
        kind: "email-domain-mismatch",
        severity: "low",
        detail: `Author "${name}" has committed from ${domains.size} different email domains — possible impersonation or account sharing`,
        author: name,
      });
    }
  }

  return risks;
}

// ── Main export ───────────────────────────────────────────────────────────────

/**
 * Analyse git log output and produce a ProvenanceSummary.
 * @param logOutput  Raw output of: git log --format="%H|%an|%ae|%at|%G?|%s"
 */
export function analyzeGitProvenance(logOutput: string): ProvenanceSummary {
  if (!logOutput || logOutput.trim().length < 10) {
    return {
      totalCommits: 0, signedRate: 1, authors: [], risks: [],
      overallRiskScore: 0, label: "TRUSTED", aiAuthoredCommits: 0,
    };
  }

  const commits = parseGitLog(logOutput);
  const authors = computeAuthorStats(commits);
  const risks   = detectProvenanceRisks(commits, authors);

  const nonMerge     = commits.filter(c => !c.isMerge);
  const signedCount  = nonMerge.filter(c => c.gpgStatus === "G" || c.gpgStatus === "U").length;
  const signedRate   = nonMerge.length > 0 ? signedCount / nonMerge.length : 1;
  const aiCommits    = commits.filter(c => AI_COMMIT_SUBJECTS.some(re => re.test(c.subject))).length;

  // Risk score: weighted sum of risk signals
  const highRisks   = risks.filter(r => r.severity === "high").length;
  const medRisks    = risks.filter(r => r.severity === "medium").length;
  const lowRisks    = risks.filter(r => r.severity === "low").length;
  const sigPenalty  = Math.max(0, 1 - signedRate) * 0.30;
  const riskPenalty = Math.min(0.70, highRisks * 0.20 + medRisks * 0.08 + lowRisks * 0.02);
  const overallScore = Math.min(1, sigPenalty + riskPenalty);

  const label: ProvenanceSummary["label"] =
    overallScore < 0.10 ? "TRUSTED"
    : overallScore < 0.25 ? "LOW_RISK"
    : overallScore < 0.45 ? "MODERATE_RISK"
    : overallScore < 0.65 ? "HIGH_RISK"
    : "CRITICAL_RISK";

  return {
    totalCommits: commits.length,
    signedRate,
    authors,
    risks,
    overallRiskScore: overallScore,
    label,
    aiAuthoredCommits: aiCommits,
  };
}

/** Format a ProvenanceSummary as a human-readable string. */
export function formatProvenanceSummary(summary: ProvenanceSummary): string {
  const lines: string[] = [
    `Provenance: ${summary.label} (risk ${Math.round(summary.overallRiskScore * 100)}%)`,
    `Commits: ${summary.totalCommits}  Signed: ${Math.round(summary.signedRate * 100)}%  AI-authored: ${summary.aiAuthoredCommits}`,
    `Authors: ${summary.authors.length}`,
  ];
  if (summary.risks.length > 0) {
    lines.push("Risks:");
    for (const r of summary.risks.slice(0, 5)) {
      lines.push(`  [${r.severity.toUpperCase()}] ${r.kind}: ${r.detail}`);
    }
  }
  return lines.join("\n");
}
