/**
 * Branch-protection snapshot: how each repository's default branch is protected when the evidence is collected --
 * whether merging needs a pull request with approvals, whether new pushes dismiss them, required status checks, and
 * whether force pushes are blocked. It is the design of the change-management control (CC8.1 / A.8.32 / 6.2.3):
 * the change register shows how it operated, this shows how it was set up.
 *
 * A point-in-time state, not period evidence: each report keeps the snapshot taken when it was generated, so a
 * series of reports shows the settings over time. GitHub settings TrustLedger can't read are stated in `limits`.
 *
 * Settings come from two places, combined: repository rulesets (readable by the GitHub App) and classic branch
 * protection (readable only with the Administration: read permission). Client-safe: pure, no I/O; lib/github.ts
 * fetches the raw responses.
 */

/** GET /repos/{o}/{r}/rules/branches/{branch}: the active ruleset rules for the branch. */
export interface RawRulesetRule { type: string; parameters?: Record<string, unknown> }

/** GET /repos/{o}/{r}/branches/{branch}/protection (classic branch protection), the parts read here. */
export interface RawClassicProtection {
  required_pull_request_reviews?: { required_approving_review_count?: number; dismiss_stale_reviews?: boolean; require_code_owner_reviews?: boolean; require_last_push_approval?: boolean } | null;
  required_status_checks?: { contexts?: string[]; checks?: Array<{ context: string }> } | null;
  enforce_admins?: { enabled?: boolean } | null;
  allow_force_pushes?: { enabled?: boolean } | null;
}

export interface RawProtection {
  repo: string;
  branch: string | null;
  /** The branch's `protected` flag (GET /repos/{o}/{r}/branches/{branch}). */
  protected: boolean | null;
  rules: RawRulesetRule[] | null;
  /** Classic protection; "none" when the branch has none, "unreadable" when the App may not read it. */
  classic: RawClassicProtection | "none" | "unreadable";
  /** Set when GitHub couldn't be read for this repository at all. */
  error?: string;
}

export interface BranchProtection {
  repo: string;
  branch: string | null;
  /** Whether GitHub was read for this repository at all (false: every setting is unknown, see `limits`). */
  read: boolean;
  /** Approvals needed to merge into the branch: 0 when a pull request isn't required, null when it couldn't be read. */
  approvals_required: number | null;
  pull_request_required: boolean | null;
  dismiss_stale_approvals: boolean | null;
  code_owner_review: boolean | null;
  last_push_approval: boolean | null;
  required_status_checks: string[];
  force_push_blocked: boolean | null;
  /** Classic protection's "include administrators"; null when unknown (rulesets' bypass lists aren't readable). */
  admins_included: boolean | null;
  sources: Array<"ruleset" | "classic">;
  /** What couldn't be read, so nobody takes a missing setting for an absent one. */
  limits: string[];
}

const anyTrue = (...v: Array<boolean | undefined | null>) => v.some(x => x === true);

export function normalizeProtection(raw: RawProtection): BranchProtection {
  const empty: BranchProtection = {
    repo: raw.repo, branch: raw.branch, read: false, approvals_required: null, pull_request_required: null, dismiss_stale_approvals: null,
    code_owner_review: null, last_push_approval: null, required_status_checks: [], force_push_blocked: null, admins_included: null,
    sources: [], limits: [],
  };
  if (raw.error) return { ...empty, limits: [`GitHub couldn't be read for this repository (${raw.error})`] };

  const rules = raw.rules ?? [];
  const pr = rules.filter(r => r.type === "pull_request").map(r => r.parameters ?? {});
  const statusRules = rules.filter(r => r.type === "required_status_checks")
    .flatMap(r => ((r.parameters?.required_status_checks ?? []) as Array<{ context?: string }>).map(c => c.context ?? "")).filter(Boolean);
  const classic = typeof raw.classic === "object" ? raw.classic : null;
  const reviews = classic?.required_pull_request_reviews ?? null;
  const classicChecks = [...(classic?.required_status_checks?.contexts ?? []), ...(classic?.required_status_checks?.checks ?? []).map(c => c.context)];

  // classic protection is on but its settings can't be read: anything it alone sets is unknown, not absent
  const classicUnknown = raw.classic === "unreadable" && raw.protected !== false;
  const limits: string[] = [];
  if (classicUnknown) limits.push("Classic branch protection is on, but the TrustLedger GitHub App can't read its settings (it needs the Administration: read permission); settings shown come from rulesets only.");
  if (rules.length > 0) limits.push("Who may bypass the rulesets isn't readable, so administrator bypass is not shown.");
  if (raw.rules == null) limits.push("Repository rulesets couldn't be read.");

  const prRequired = pr.length > 0 || !!reviews;
  const approvals = Math.max(0, ...pr.map(p => Number(p.required_approving_review_count ?? 0)), reviews?.required_approving_review_count ?? 0);
  const known = (v: boolean) => (v ? true : classicUnknown ? null : false);

  return {
    repo: raw.repo, branch: raw.branch, read: true,
    pull_request_required: known(prRequired),
    approvals_required: prRequired ? approvals : classicUnknown ? null : 0,
    dismiss_stale_approvals: known(anyTrue(...pr.map(p => p.dismiss_stale_reviews_on_push as boolean), reviews?.dismiss_stale_reviews)),
    code_owner_review: known(anyTrue(...pr.map(p => p.require_code_owner_review as boolean), reviews?.require_code_owner_reviews)),
    last_push_approval: known(anyTrue(...pr.map(p => p.require_last_push_approval as boolean), reviews?.require_last_push_approval)),
    required_status_checks: [...new Set([...statusRules, ...classicChecks])].sort(),
    force_push_blocked: known(rules.some(r => r.type === "non_fast_forward") || (!!classic && classic.allow_force_pushes?.enabled !== true)),
    admins_included: classic?.enforce_admins ? !!classic.enforce_admins.enabled : null,
    sources: [...(rules.length ? ["ruleset" as const] : []), ...(classic ? ["classic" as const] : [])],
    limits,
  };
}

/** A setting's value in words, for tables. */
export function protectionValue(v: boolean | number | null): string {
  if (v === null) return "Unknown";
  if (typeof v === "number") return String(v);
  return v ? "Yes" : "No";
}
