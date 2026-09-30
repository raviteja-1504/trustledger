/**
 * Finding lifecycle and triage, keyed on the scanner's stable fingerprints (findingIdentity.ts).
 *
 * Two separate things:
 *
 *  - LIFECYCLE is derived, never stored: a PR's own scan history says whether a finding is new this push,
 *    was already there, came back after disappearing (reopened), or disappeared (fixed). Deriving it per PR
 *    avoids the flapping a repo-wide state would have, where one branch fixes a finding another still has.
 *
 *  - TRIAGE is a decision, stored per (repo, fingerprint): "accepted" (risk accepted, e.g. a baseline) or
 *    "false_positive", with a reason and an optional expiry. It follows the finding across PRs and pushes
 *    because the fingerprint does. An expired decision stops suppressing and the finding reads "reopened".
 *
 * A suppressed finding is still recorded and shown; it just doesn't block a merge (see effectiveFileRisk).
 * Client-safe: no imports beyond types.
 */

export type TriageStatus = "accepted" | "false_positive";

export interface TriageDecision {
  status: TriageStatus;
  reason: string | null;
  expires_at: string | null;
  set_by_email: string | null;
  set_at: string;
}

export type FindingStatus = "new" | "existing" | "reopened" | "accepted" | "false_positive";

export const STATUS_LABEL: Record<FindingStatus | "fixed", string> = {
  new: "New", existing: "Existing", reopened: "Reopened", accepted: "Accepted risk", false_positive: "False positive", fixed: "Fixed",
};

/** Is this decision still in force at `now`? */
export function isActive(d: TriageDecision | undefined, now: Date = new Date()): d is TriageDecision {
  return !!d && (!d.expires_at || Date.parse(d.expires_at) > now.getTime());
}

/** Fingerprints seen in a PR's earlier scans: the one just before this scan, and every one before that. */
export interface PrHistory { previous: ReadonlySet<string> | null; earlier: ReadonlySet<string> }

/**
 * The status of one finding (by fingerprint) in the current scan.
 * A finding with no fingerprint (legacy stored data) is "existing": nothing can be claimed about it.
 */
export function findingStatus(fingerprint: string | undefined, history: PrHistory, triage: ReadonlyMap<string, TriageDecision>, now: Date = new Date()): FindingStatus {
  if (!fingerprint) return "existing";
  const decision = triage.get(fingerprint);
  if (isActive(decision, now)) return decision.status;
  if (decision) return "reopened";                                   // a decision that expired
  if (!history.previous) return "new";                               // first scan of the PR
  if (history.previous.has(fingerprint)) return "existing";
  return history.earlier.has(fingerprint) ? "reopened" : "new";
}

export interface FixedFinding { fingerprint: string; id: string; label: string; file_path: string; line?: number }

/**
 * Findings the previous scan had that this one doesn't, among files this scan actually looked at (a file
 * the scan didn't include tells us nothing).
 */
export function fixedSincePrevious(
  previousFiles: ReadonlyArray<{ file_path: string; indicators: ReadonlyArray<{ id: string; label: string; line?: number; fingerprint?: string }> }>,
  current: ReadonlySet<string>,
  scannedPaths: ReadonlySet<string>,
): FixedFinding[] {
  const out: FixedFinding[] = [];
  for (const f of previousFiles) {
    if (!scannedPaths.has(f.file_path)) continue;
    for (const i of f.indicators) {
      if (i.fingerprint && !current.has(i.fingerprint)) out.push({ fingerprint: i.fingerprint, id: i.id, label: i.label, file_path: f.file_path, line: i.line });
    }
  }
  return out;
}

export interface LifecycleSummary { new: number; existing: number; reopened: number; accepted: number; false_positive: number; fixed: number }

export function summarize(statuses: readonly FindingStatus[], fixed: number): LifecycleSummary {
  const s: LifecycleSummary = { new: 0, existing: 0, reopened: 0, accepted: 0, false_positive: 0, fixed };
  for (const st of statuses) s[st]++;
  return s;
}

/** The indicators that still count toward risk and merge gating: everything not under an active decision. */
export function unsuppressed<T extends { fingerprint?: string }>(indicators: readonly T[], triage: ReadonlyMap<string, TriageDecision>, now: Date = new Date()): T[] {
  return indicators.filter(i => !i.fingerprint || !isActive(triage.get(i.fingerprint), now));
}

/** Attach each finding's triage decision (by fingerprint) -- the one step every view and export shares, so the
 * dashboard, SARIF and the Trust Record agree on which findings are suppressed. Returns new objects. */
export function attachTriage<F extends { indicators?: ReadonlyArray<{ fingerprint?: string }> | null }>(
  files: readonly F[], triage: ReadonlyMap<string, TriageDecision>,
): F[] {
  if (!triage.size) return [...files];
  return files.map(f => ({
    ...f,
    indicators: (f.indicators ?? []).map(i => {
      const d = i.fingerprint ? triage.get(i.fingerprint) : undefined;
      return d ? { ...i, triage: d } : i;
    }),
  }));
}

/** Allowed expiry choices for a decision, in days (null = no expiry). */
export const EXPIRY_CHOICES: ReadonlyArray<{ label: string; days: number | null }> = [
  { label: "30 days", days: 30 }, { label: "90 days", days: 90 }, { label: "1 year", days: 365 }, { label: "No expiry", days: null },
];
