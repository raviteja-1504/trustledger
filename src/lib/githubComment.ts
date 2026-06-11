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

export function buildPRCommentDirect(scan: {
  scan_id:            string;
  repo:               string;
  pr_number:          number;
  overall_risk:       string;
  total_ai_percentage:number;
  files: Array<{ file_path:string; risk_score:string; ai_percentage:number; risk_indicators:string[]; attested:boolean }>;
  appUrl:             string;
}): string {
  const counts   = scan.files.reduce((acc, f) => { acc[f.risk_score] = (acc[f.risk_score]??0)+1; return acc; }, {} as Record<string,number>);
  const blocked  = scan.overall_risk === "CRITICAL" || scan.overall_risk === "HIGH";
  const aiPct    = (scan.total_ai_percentage * 100).toFixed(0);
  const reviewUrl= `${scan.appUrl}/pr/${scan.scan_id}`;

  const lines = [
    `## ${RISK_EMOJI[scan.overall_risk]??""} TrustLedger AI Governance — ${scan.overall_risk} Risk`,
    "",
    blocked
      ? `> ⛔ **Merge blocked** — ${(counts.CRITICAL??0)+(counts.HIGH??0)} file(s) require attestation.`
      : `> ✅ **Policy gate passed** — all AI governance checks met.`,
    "",
    `| | |`,
    `|-|-|`,
    `| Overall Risk | ${RISK_EMOJI[scan.overall_risk]} **${scan.overall_risk}** |`,
    `| AI Content | ${aiPct}% avg |`,
    `| Files | ${scan.files.length} scanned |`,
    ...(counts.CRITICAL ? [`| 🔴 CRITICAL | ${counts.CRITICAL} |`] : []),
    ...(counts.HIGH     ? [`| 🟠 HIGH | ${counts.HIGH} |`]         : []),
  ];

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
