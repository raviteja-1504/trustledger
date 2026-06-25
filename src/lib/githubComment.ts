/**
 * GitHub PR comment builder — shared between webhook route and comment API.
 */

const RISK_EMOJI: Record<string, string> = {
  CRITICAL:"🔴", HIGH:"🟠", MEDIUM:"🟡", LOW:"🟢", UNKNOWN:"⚪",
};

const INDICATOR_LABEL: Record<string, string> = {
  "hardcoded-secret":   "Hardcoded credential",
  "sql-injection":      "SQL injection",
  "eval-exec":          "Code execution (eval/exec)",
  "jwt-none-alg":       "JWT none-algorithm",
  "command-injection":  "Command injection",
  "ai-comment-pattern": "AI comment pattern",
};

const LIKELIHOOD_EMOJI: Record<string, string> = {
  "Likely Human":               "🟢",
  "Human with Tool Assistance": "🔵",
  "Mixed Authorship":           "🟡",
  "Likely AI-Assisted":         "🟠",
  "Strong AI Evidence":         "🔴",
};

interface EvidenceBreakdown {
  code_evidence:      number;
  pr_evidence:        number;
  git_evidence:       number;
  tool_evidence:      number;
  baseline_evidence:  number;
  combined:           number;
  likelihood:         string;
  boosts:             string[];
}

export function buildPRCommentDirect(scan: {
  scan_id:              string;
  repo:                 string;
  pr_number:            number;
  overall_risk:         string;
  total_ai_percentage:  number;
  files: Array<{ file_path:string; risk_score:string; ai_percentage:number; risk_indicators:string[]; attested:boolean }>;
  appUrl:               string;
  evidence_breakdown?:  EvidenceBreakdown;
}): string {
  const counts   = scan.files.reduce((acc, f) => { acc[f.risk_score] = (acc[f.risk_score]??0)+1; return acc; }, {} as Record<string,number>);
  const blocked  = scan.overall_risk === "CRITICAL" || scan.overall_risk === "HIGH";
  const aiPct    = (scan.total_ai_percentage * 100).toFixed(0);
  const reviewUrl= `${scan.appUrl}/pr/${scan.scan_id}`;
  const ev       = scan.evidence_breakdown;

  const lines = [
    `## ${RISK_EMOJI[scan.overall_risk]??""} TrustLedger AI Governance — ${scan.overall_risk} Risk`,
    "",
    blocked
      ? `> ⛔ **Merge blocked** — ${(counts.CRITICAL??0)+(counts.HIGH??0)} file(s) require attestation.`
      : `> ✅ **Policy gate passed** — all AI governance checks met.`,
    "",
    `| Metric | Value |`,
    `|-|-|`,
    `| Overall Risk | ${RISK_EMOJI[scan.overall_risk]} **${scan.overall_risk}** |`,
    `| AI Likelihood | ${ev ? `${LIKELIHOOD_EMOJI[ev.likelihood]??""} **${Math.round(ev.combined*100)}%** — ${ev.likelihood}` : `${aiPct}%`} |`,
    `| Files | ${scan.files.length} scanned |`,
    ...(counts.CRITICAL ? [`| 🔴 CRITICAL | ${counts.CRITICAL} |`] : []),
    ...(counts.HIGH     ? [`| 🟠 HIGH | ${counts.HIGH} |`]         : []),
  ];

  // Evidence breakdown section — only shown when multi-signal data is available
  if (ev && ev.combined > 0) {
    const pct = (v: number) => `${Math.round(v * 100)}%`;
    const bar = (v: number) => {
      const filled = Math.round(v * 10);
      return "█".repeat(filled) + "░".repeat(10 - filled);
    };

    lines.push(
      "",
      "<details>",
      "<summary>📊 AI Evidence Breakdown</summary>",
      "",
      "| Signal | Weight | Score | |",
      "|--------|--------|-------|--|",
      `| Code Patterns    | 25% | ${pct(ev.code_evidence)}     | \`${bar(ev.code_evidence)}\` |`,
      `| PR Behavior      | 25% | ${pct(ev.pr_evidence)}       | \`${bar(ev.pr_evidence)}\` |`,
      `| Git Provenance   | 25% | ${pct(ev.git_evidence)}      | \`${bar(ev.git_evidence)}\` |`,
      `| Author Baseline  | 15% | ${pct(ev.baseline_evidence)} | \`${bar(ev.baseline_evidence)}\` |`,
      `| Tool Artifacts   | 10% | ${pct(ev.tool_evidence)}     | \`${bar(ev.tool_evidence)}\` |`,
    );

    if (ev.boosts.length > 0) {
      lines.push("", "**⚡ Key signals:**");
      ev.boosts.slice(0, 3).forEach(b => lines.push(`- ${b}`));
    }

    lines.push("", "</details>");
  }

  const highRisk = scan.files.filter(f => f.risk_score==="CRITICAL"||f.risk_score==="HIGH").slice(0,8);
  if (highRisk.length > 0) {
    lines.push("","**Files requiring attestation:**","");
    highRisk.forEach(f => {
      const secInds = f.risk_indicators.filter(i => INDICATOR_LABEL[i]).slice(0,2).map(i => INDICATOR_LABEL[i]).join(", ");
      lines.push(`- ${f.attested?"✅":"⏳"} \`${f.file_path.split("/").slice(-2).join("/")}\` — ${RISK_EMOJI[f.risk_score]} ${f.risk_score}${secInds ? ` · ${secInds}` : ""}`);
    });
  }

  lines.push("","---",`**[📋 Review in TrustLedger](${reviewUrl})** · Scan \`${scan.scan_id.slice(0,8)}\``);
  return lines.join("\n");
}
