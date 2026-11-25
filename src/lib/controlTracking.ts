/**
 * Control ownership, missing-evidence tracking and remediation status (Task 12).
 *
 * Pure: builds one report from three things already stored elsewhere:
 *   - the coverage of each control by evidence (lib/controlMapping.ts, with hash-verified records only),
 *   - who owns each control (control_owners),
 *   - the remediation register (compliance_exceptions: title, owner, due date, status, accepted risk).
 *
 * "Tracked" means a gap has a named response: an open or in-progress exception that says how and by when it will be
 * closed (or that the risk was accepted). An untracked gap is one nobody has taken up yet. Closing an exception does
 * not close a gap: only fresh, verified evidence does, so a resolved exception whose gap remains is flagged.
 *
 * Nothing here says a control is compliant. Complete evidence only means the evidence TrustLedger collects is present.
 */
import type { EvidenceType } from "./evidenceRecord";
import type { ControlCoverageResult, ControlCoverageStatus } from "./controlMapping";

export interface ControlOwner { control_id: string; owner_email: string; assigned_at?: string | null; assigned_by_email?: string | null }

/** A row of the remediation register (compliance_exceptions). */
export interface RemediationItem {
  id:            string;
  control_id:    string;
  title:         string;
  status:        string;            // open | in-progress | resolved
  owner_email:   string | null;
  due_date:      string | null;     // YYYY-MM-DD
  risk_accepted: boolean;
  remediation:   string | null;
}

export type GapKind = "missing" | "expired" | "unverified";
export interface EvidenceGap { evidence_type: EvidenceType; kind: GapKind }

export type ControlFlag =
  | "no_owner"                 // nobody is responsible for this control
  | "gap_untracked"            // evidence is missing/expired/unverified and no exception responds to it
  | "remediation_overdue"      // an open exception is past its due date
  | "resolved_but_gap_remains" // an exception was closed, yet the evidence gap is still there
  | "risk_accepted";           // a recorded decision to live with the gap (not the same as closing it)

export interface TrackedControl {
  control_id:   string;
  control_name: string;
  status:       ControlCoverageStatus;
  /** Always false: evidence on file supports a control, it does not establish compliance. */
  sufficient_alone: false;
  owner:        string | null;
  gaps:         EvidenceGap[];
  remediations: Array<RemediationItem & { overdue: boolean }>;
  flags:        ControlFlag[];
}

export interface TrackingSummary {
  controls:          number;
  with_gaps:         number;
  unowned:           number;
  untracked_gaps:    number;
  overdue:           number;
  resolved_but_gap_remains: number;
}

export interface GapReport { summary: TrackingSummary; controls: TrackedControl[] }

const isOpen = (r: RemediationItem) => r.status !== "resolved";

export function gapsOf(c: Pick<ControlCoverageResult, "missing_types" | "expired_types" | "unverified_types">): EvidenceGap[] {
  const unverified = new Set(c.unverified_types ?? []);
  return [
    ...c.missing_types.filter(t => !unverified.has(t)).map(evidence_type => ({ evidence_type, kind: "missing" as const })),
    ...(c.unverified_types ?? []).map(evidence_type => ({ evidence_type, kind: "unverified" as const })),
    ...c.expired_types.map(evidence_type => ({ evidence_type, kind: "expired" as const })),
  ];
}

/** `today` is a YYYY-MM-DD string; a due date before it is overdue. */
export function buildGapReport(
  coverage: readonly ControlCoverageResult[], owners: readonly ControlOwner[], remediations: readonly RemediationItem[], today: string,
): GapReport {
  const ownerOf = new Map(owners.map(o => [o.control_id, o.owner_email]));
  const controls: TrackedControl[] = coverage.map(cov => {
    const gaps = gapsOf(cov);
    const mine = remediations.filter(r => r.control_id === cov.control_id).map(r => ({ ...r, overdue: isOpen(r) && !!r.due_date && r.due_date < today }));
    const open = mine.filter(isOpen);
    const flags: ControlFlag[] = [];
    if (!ownerOf.has(cov.control_id)) flags.push("no_owner");
    if (gaps.length > 0) {
      // A recorded decision to accept the risk is a response to the gap even once its exception is marked resolved.
      if (mine.some(r => r.risk_accepted)) flags.push("risk_accepted");
      else if (open.length === 0) flags.push(mine.length > 0 ? "resolved_but_gap_remains" : "gap_untracked");
    }
    if (open.some(r => r.overdue)) flags.push("remediation_overdue");
    return {
      control_id: cov.control_id, control_name: cov.control_name, status: cov.status, sufficient_alone: false,
      owner: ownerOf.get(cov.control_id) ?? null, gaps, remediations: mine, flags,
    };
  });
  const count = (f: ControlFlag) => controls.filter(c => c.flags.includes(f)).length;
  return {
    controls,
    summary: {
      controls: controls.length,
      with_gaps: controls.filter(c => c.gaps.length > 0).length,
      unowned: count("no_owner"),
      untracked_gaps: count("gap_untracked") + count("resolved_but_gap_remains"),
      overdue: count("remediation_overdue"),
      resolved_but_gap_remains: count("resolved_but_gap_remains"),
    },
  };
}

const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
export function isValidOwnerEmail(v: unknown): v is string { return typeof v === "string" && v.length <= 254 && EMAIL.test(v); }
