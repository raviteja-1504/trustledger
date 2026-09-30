/**
 * Security regression check, run after every scan of a PR: what this push added compared with the PR's
 * previous scan (new security findings, by severity), what it fixed, and which new findings are already
 * covered by a triage decision. Rendered into the GitHub check run so a regression is visible where the
 * merge decision is made. Keyed on fingerprints (findingIdentity.ts); pure and client-safe.
 */
import { findingMeta } from "./findingCatalog";
import { isActive, type TriageDecision } from "./findingLifecycle";

interface Ind { id: string; label: string; severity: string; line?: number; fingerprint?: string; cwe?: string }
interface FileLike { file_path: string; indicators?: readonly Ind[] | null }

export interface RegressionFinding { id: string; title: string; severity: string; file: string; line?: number }

export interface RegressionReport {
  hasPrevious: boolean;
  /** New unsuppressed security findings since the previous scan, most severe first. */
  added: RegressionFinding[];
  /** New since the previous scan but already under an active triage decision. */
  addedSuppressed: number;
  /** Security findings the previous scan had and this one doesn't, among files this scan looked at. */
  fixed: RegressionFinding[];
}

const SEV_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const isSecurity = (i: Ind) => !!(i.cwe ?? findingMeta(i.id, i.label).cwe);
const toFinding = (i: Ind, file: string): RegressionFinding => ({ id: i.id, title: findingMeta(i.id, i.label).title, severity: i.severity, file, line: i.line });
const bySeverity = (a: RegressionFinding, b: RegressionFinding) => (SEV_RANK[a.severity] ?? 9) - (SEV_RANK[b.severity] ?? 9) || a.file.localeCompare(b.file) || (a.line ?? 0) - (b.line ?? 0);

export function securityRegression(
  current: readonly FileLike[], previous: readonly FileLike[] | null,
  triage: ReadonlyMap<string, TriageDecision>, now: Date = new Date(),
): RegressionReport {
  if (!previous) return { hasPrevious: false, added: [], addedSuppressed: 0, fixed: [] };
  const prevFps = new Set(previous.flatMap(f => (f.indicators ?? []).filter(isSecurity).map(i => i.fingerprint).filter((x): x is string => !!x)));
  const currFps = new Set(current.flatMap(f => (f.indicators ?? []).filter(isSecurity).map(i => i.fingerprint).filter((x): x is string => !!x)));
  const scanned = new Set(current.map(f => f.file_path));
  const added: RegressionFinding[] = [];
  let addedSuppressed = 0;
  for (const f of current) {
    for (const i of (f.indicators ?? []).filter(isSecurity)) {
      if (!i.fingerprint || prevFps.has(i.fingerprint)) continue;
      if (isActive(triage.get(i.fingerprint), now)) addedSuppressed++;
      else added.push(toFinding(i, f.file_path));
    }
  }
  const fixed = previous.filter(f => scanned.has(f.file_path)).flatMap(f =>
    (f.indicators ?? []).filter(i => isSecurity(i) && i.fingerprint && !currFps.has(i.fingerprint)).map(i => toFinding(i, f.file_path)));
  return { hasPrevious: true, added: added.sort(bySeverity), addedSuppressed, fixed: fixed.sort(bySeverity) };
}

const MAX_LISTED = 10;

/** A markdown section for the GitHub check-run summary; empty when there is no previous scan. */
export function regressionMarkdown(r: RegressionReport): string {
  if (!r.hasPrevious) return "";
  const lines: string[] = ["", "### Since the last push"];
  if (r.added.length === 0 && r.fixed.length === 0 && r.addedSuppressed === 0) {
    lines.push("No change in security findings.");
    return lines.join("\n");
  }
  const counts = ["critical", "high", "medium", "low"].map(s => [s, r.added.filter(f => f.severity === s).length] as const).filter(([, n]) => n > 0);
  lines.push(r.added.length
    ? `⚠️ **${r.added.length} new security finding${r.added.length === 1 ? "" : "s"}**${counts.length ? ` (${counts.map(([s, n]) => `${n} ${s}`).join(", ")})` : ""}:`
    : "✅ No new security findings.");
  for (const f of r.added.slice(0, MAX_LISTED)) lines.push(`- ${f.severity.toUpperCase()} · ${f.title} — \`${f.file}${f.line ? `:${f.line}` : ""}\``);
  if (r.added.length > MAX_LISTED) lines.push(`- …and ${r.added.length - MAX_LISTED} more`);
  if (r.addedSuppressed) lines.push(`${r.addedSuppressed} more new finding${r.addedSuppressed === 1 ? " is" : "s are"} already accepted or marked false positive.`);
  if (r.fixed.length) lines.push(`✅ **${r.fixed.length} fixed** since the last push.`);
  return lines.join("\n");
}
