/**
 * A compact, paste-ready security summary of one PR scan (GitHub-flavoured markdown): what the PR introduces,
 * what changed since the last push, how complete the scan was, and the top findings with location, confidence
 * and status. Built from exactly what the PR page shows, so the two never disagree.
 * Client-safe.
 */
import type { ScanResult, FileIndicator } from "@/types";
import { findingMeta } from "./findingCatalog";
import { confidenceLevel, CONFIDENCE_LABEL } from "./confidence";
import { STATUS_LABEL, isActive, type LifecycleSummary } from "./findingLifecycle";
import { describeHealth } from "./scanHealth";

const SEV_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const cap = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);
const MAX_ROWS = 10;

export function isSecurityFinding(i: FileIndicator): boolean {
  return !!(i.cwe ?? findingMeta(i.id, i.label).cwe);
}

export function buildPrSecuritySummary(scan: ScanResult, opts: { reviewUrl?: string; lifecycle?: LifecycleSummary } = {}): string {
  const rows = scan.files.flatMap(f => (f.indicators ?? []).filter(isSecurityFinding).map(i => ({ f, i })))
    .sort((a, b) => (SEV_RANK[a.i.severity] ?? 9) - (SEV_RANK[b.i.severity] ?? 9) || a.f.file_path.localeCompare(b.f.file_path) || (a.i.line ?? 0) - (b.i.line ?? 0));
  const out: string[] = [];
  out.push(`### TrustLedger security summary — PR #${scan.pr_number} (\`${scan.commit_sha.slice(0, 7)}\`)`);
  out.push("");

  const known = rows.filter(r => r.i.introduced != null);
  if (known.length) {
    const intro = known.filter(r => r.i.introduced);
    const bySev = ["critical", "high"].map(s => [s, intro.filter(r => r.i.severity === s).length] as const).filter(([, n]) => n > 0);
    out.push(`**Introduced by this PR:** ${intro.length}${bySev.length ? ` (${bySev.map(([s, n]) => `${n} ${s}`).join(", ")})` : ""} · ${known.length - intro.length} already in the files it touches`);
  }
  const l = opts.lifecycle;
  if (l) {
    const parts = ([["new", l.new], ["reopened", l.reopened], ["fixed", l.fixed], ["accepted", l.accepted], ["false_positive", l.false_positive]] as const)
      .filter(([, n]) => n > 0).map(([k, n]) => `${n} ${STATUS_LABEL[k].toLowerCase()}`);
    if (parts.length) out.push(`**Since the last push:** ${parts.join(" · ")}`);
  }
  if (scan.health && scan.health.status !== "complete") {
    out.push(`**Coverage:** ${scan.health.status === "degraded" ? "⚠️ incomplete" : "partial"} — ${describeHealth(scan.health)}`);
  }
  out.push(`**Overall risk:** ${scan.overall_risk} · ${rows.length} security finding${rows.length === 1 ? "" : "s"}`);
  out.push("");

  if (rows.length) {
    out.push("| Severity | Finding | Location | Confidence | Status |");
    out.push("|---|---|---|---|---|");
    for (const { f, i } of rows.slice(0, MAX_ROWS)) {
      const meta = findingMeta(i.id, i.label);
      const conf = confidenceLevel({ confidence: i.confidence, sourceExpr: i.sourceExpr, sourceAssumed: i.flow?.source.assumed });
      const status = [
        i.lifecycle_status ? STATUS_LABEL[i.lifecycle_status] : null,
        i.introduced === true ? "introduced" : i.introduced === false ? "pre-existing" : null,
        isActive(i.triage) && i.triage?.reason ? `“${i.triage.reason.replace(/\|/g, "/").slice(0, 80)}”` : null,
      ].filter(Boolean).join(" · ");
      const cwe = i.cwe ?? meta.cwe;
      out.push(`| ${cap(i.severity)} | ${meta.title.replace(/\|/g, "/")}${cwe ? ` (${cwe})` : ""} | \`${f.file_path}${i.line ? `:${i.line}` : ""}\` | ${conf ? CONFIDENCE_LABEL[conf] : "—"} | ${status || "—"} |`);
    }
    if (rows.length > MAX_ROWS) out.push(`\n_…and ${rows.length - MAX_ROWS} more._`);
    out.push("");
  } else {
    out.push("No security findings.");
    out.push("");
  }
  if (opts.reviewUrl) out.push(`Full review: ${opts.reviewUrl}`);
  return out.join("\n").trim() + "\n";
}
