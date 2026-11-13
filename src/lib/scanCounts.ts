/**
 * The numbers on a PR scan page, each defined once with its unit.
 *
 * The page used to show three counts side by side that measure different things -- files rated High/Critical,
 * security findings the PR introduced, and "new" findings since the last push (which counted every indicator,
 * AI-provenance signals included) -- so 80, 160 and 643 sat next to each other with nothing saying why.
 *
 *   FILES      scanned -> rated High/Critical ("need review") -> signed off (attested)
 *   FINDINGS   security findings only (those with a CWE): total, by severity, introduced by this PR vs already there,
 *              and how many are under an accepted-risk / false-positive decision
 *   OTHER      indicators that are not security findings (AI-provenance and code-hygiene hints): never added in
 *   CHANGES    since the previous scan of this PR, again security findings only: new / still open / reopened / fixed
 *
 * A file is rated by its worst finding, so the file count and the finding count are different units: 80 files can
 * hold 160 findings. Client-safe: no imports beyond types.
 */
import { isActive, type FindingStatus, type TriageDecision } from "./findingLifecycle";

export type CountSeverity = "critical" | "high" | "medium" | "low";

export interface CountIndicator {
  id: string;
  label?: string;
  severity?: string;
  cwe?: string;
  line?: number;
  fingerprint?: string;
  introduced?: boolean;
  lifecycle_status?: FindingStatus;
  triage?: TriageDecision;
}
export interface CountFile {
  file_path: string;
  risk_score?: string;
  attested?: boolean;
  indicators?: readonly CountIndicator[] | null;
}

export interface ScanCounts {
  files: { scanned: number; toReview: number; signedOff: number; withFindings: number };
  security: {
    total: number;
    bySeverity: Record<CountSeverity, number>;
    /** Under an active accepted-risk / false-positive decision (still listed, no longer blocking). */
    suppressed: number;
    /** Not suppressed. */
    open: number;
    /** Added or changed by this PR / already in the files it touches; null when the scan has no PR diff to say. */
    introduced: number | null;
    preexisting: number | null;
  };
  /** Indicators that are not security findings. */
  otherSignals: number;
  /** Against the PR's previous scan; null for a first scan (nothing to compare with) or without lifecycle data. */
  changes: {
    new: number; existing: number; reopened: number; accepted: number; falsePositive: number;
    fixed: number;
    /** The fixed list the page received is capped, so `fixed` is "at least this many". */
    fixedIsLowerBound: boolean;
  } | null;
}

export interface LifecycleInput {
  hasPreviousScan: boolean;
  /** Fixed findings the page was given (capped by the API), and the uncapped total. */
  fixed: ReadonlyArray<{ id: string; label?: string }>;
  fixedTotal: number;
}

/**
 * One file's numbers, in the SAME units as the page's cards: its security findings (what the "Security findings" card adds up across
 * files) and its other signals (AI-provenance and code-hygiene hints, what the "Other signals" count adds up). A file row that showed
 * a third number (how many different detections fired) never added up to the card.
 */
export function fileCounts(
  indicators: readonly CountIndicator[] | null | undefined,
  isSecurity: (i: { id: string; label?: string; cwe?: string }) => boolean,
): { security: number; other: number } {
  let security = 0, other = 0;
  for (const i of indicators ?? []) { if (isSecurity(i)) security++; else other++; }
  return { security, other };
}

const sevOf = (s: string | undefined): CountSeverity => (s === "critical" || s === "high" || s === "medium" ? s : "low");

export function computeScanCounts(
  files: readonly CountFile[],
  opts: {
    /** Is this indicator a security finding (a vulnerability), as opposed to an AI-provenance or hygiene signal? */
    isSecurity: (i: { id: string; label?: string; cwe?: string }) => boolean;
    /** Paths signed off in this session, on top of each file's own `attested` flag. */
    attestedPaths?: ReadonlySet<string>;
    lifecycle?: LifecycleInput;
    now?: Date;
  },
): ScanCounts {
  const now = opts.now ?? new Date();
  const isHigh = (f: CountFile) => f.risk_score === "HIGH" || f.risk_score === "CRITICAL";
  const signed = (f: CountFile) => !!f.attested || !!opts.attestedPaths?.has(f.file_path);

  const bySeverity: Record<CountSeverity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  let total = 0, suppressed = 0, other = 0, withFindings = 0;
  let introduced = 0, known = 0;
  const st = { new: 0, existing: 0, reopened: 0, accepted: 0, falsePositive: 0 };

  for (const f of files) {
    let fileHasFinding = false;
    for (const i of f.indicators ?? []) {
      if (!opts.isSecurity(i)) { other++; continue; }
      fileHasFinding = true;
      total++;
      bySeverity[sevOf(i.severity)]++;
      if (isActive(i.triage, now)) suppressed++;
      if (i.introduced != null) { known++; if (i.introduced) introduced++; }
      switch (i.lifecycle_status) {
        case "new": st.new++; break;
        case "reopened": st.reopened++; break;
        case "accepted": st.accepted++; break;
        case "false_positive": st.falsePositive++; break;
        default: st.existing++;
      }
    }
    if (fileHasFinding) withFindings++;
  }

  const lc = opts.lifecycle;
  let changes: ScanCounts["changes"] = null;
  if (lc?.hasPreviousScan) {
    const fixedSecurity = lc.fixed.filter(f => opts.isSecurity({ id: f.id, label: f.label })).length;
    const capped = lc.fixed.length < lc.fixedTotal;
    changes = { ...st, fixed: fixedSecurity, fixedIsLowerBound: capped };
  }

  return {
    files: { scanned: files.length, toReview: files.filter(isHigh).length, signedOff: files.filter(f => isHigh(f) && signed(f)).length, withFindings },
    security: {
      total, bySeverity, suppressed, open: total - suppressed,
      introduced: known > 0 ? introduced : null,
      preexisting: known > 0 ? known - introduced : null,
    },
    otherSignals: other,
    changes,
  };
}

/** One finding that is new (or came back) since the previous scan, for the "what changed" list. */
export interface ChangedFinding { file: string; line?: number; id: string; label: string; severity: CountSeverity; status: "new" | "reopened" }

/** The security findings that are new or reopened since the previous scan, most severe first. */
export function listNewFindings(
  files: readonly CountFile[],
  isSecurity: (i: { id: string; label?: string; cwe?: string }) => boolean,
  labelOf: (i: { id: string; label?: string }) => string = i => i.label ?? i.id,
): ChangedFinding[] {
  const rank: Record<CountSeverity, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  const out: ChangedFinding[] = [];
  for (const f of files) {
    for (const i of f.indicators ?? []) {
      if ((i.lifecycle_status === "new" || i.lifecycle_status === "reopened") && isSecurity(i)) {
        out.push({ file: f.file_path, line: i.line, id: i.id, label: labelOf(i), severity: sevOf(i.severity), status: i.lifecycle_status });
      }
    }
  }
  return out.sort((a, b) => rank[a.severity] - rank[b.severity] || a.file.localeCompare(b.file) || (a.line ?? 0) - (b.line ?? 0));
}

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

/** The change counts as plain sentences, so nobody has to decode "new / existing / fixed". */
export function describeChanges(c: NonNullable<ScanCounts["changes"]>): string[] {
  const out: string[] = [];
  const fixed = `${c.fixed}${c.fixedIsLowerBound ? "+" : ""}`;
  out.push(c.new === 0 ? "No new security findings" : `${plural(c.new, "new security finding")}: not in the previous scan`);
  if (c.reopened > 0) out.push(`${plural(c.reopened, "finding")} came back: fixed or accepted before, present again`);
  if (c.fixed > 0) out.push(`${fixed} fixed: in the previous scan, gone now`);
  if (c.existing > 0) out.push(`${c.existing} unchanged: already in the previous scan, still here`);
  const decided = c.accepted + c.falsePositive;
  if (decided > 0) out.push(`${plural(decided, "finding")} under a triage decision (${c.accepted} accepted risk, ${c.falsePositive} false positive)`);
  return out;
}
