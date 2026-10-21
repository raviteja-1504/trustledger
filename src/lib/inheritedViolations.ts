/**
 * Which carried-over files still block a pull request's merge after a new push.
 *
 * A push to an open PR is scanned as a delta: only the files it changed are re-analysed, and every other file of
 * the PR is inherited from the previous scan along with any attestation it had. Violations used to be recorded only
 * for the re-analysed files, and the check run counts the new scan's violations, so an inherited HIGH/CRITICAL
 * file that nobody had attested stopped blocking: pushing any unrelated change turned the check green.
 *
 * An inherited file is still a violation of the new scan when its risk -- after active triage decisions, the same
 * rule the re-analysed files get -- is HIGH or CRITICAL and it carried no attestation over. It keeps the fix
 * deadline it already had, so pushing again doesn't extend the SLA.
 *
 * Pure: the scan worker loads the inputs and inserts the rows.
 */

export type BlockingRisk = "CRITICAL" | "HIGH";

export interface InheritedFile {
  file_path: string;
  /** The risk with every finding counted, as stored on the previous scan. */
  risk_score: string;
}

export interface InheritedViolation {
  file_path: string;
  risk_score: BlockingRisk;
  sla_deadline: string;
}

export function inheritedViolations(
  files: readonly InheritedFile[],
  /** Files whose attestation was carried over to the new scan. */
  attested: ReadonlySet<string>,
  /** The file's risk after active triage decisions (accepted risk, false positive). */
  riskAfterTriage: (file: InheritedFile) => string,
  /** The deadline each file's violation already had on the previous scan. */
  priorDeadlines: ReadonlyMap<string, string>,
  /** The deadline for a file that had no violation before. */
  defaultDeadline: string,
): InheritedViolation[] {
  const out: InheritedViolation[] = [];
  for (const f of files) {
    if (attested.has(f.file_path)) continue;
    const risk = riskAfterTriage(f);
    if (risk !== "CRITICAL" && risk !== "HIGH") continue;
    // the violation row keeps the file's stored risk, like the re-analysed files' rows do
    const stored: BlockingRisk = f.risk_score === "CRITICAL" ? "CRITICAL" : "HIGH";
    out.push({ file_path: f.file_path, risk_score: stored, sla_deadline: priorDeadlines.get(f.file_path) ?? defaultDeadline });
  }
  return out;
}
