/**
 * Every limit a user can run into, in one place -- plan quotas, rate limits and the internal caps -- so the server
 * enforces and the UI shows the SAME numbers (plan limits used to be written out twice, in api/billing and
 * api/usage, and the internal caps were private constants nobody could see). Client-safe: no imports.
 *
 * A limit of -1 means unlimited.
 */

// ── Plan quotas ─────────────────────────────────────────────────────────────

export interface PlanLimits { scans: number; attestations: number; repos: number; members: number; reports: number }

/**
 * The only plan for now: a free trial. Scans are what is limited; viewing and attesting existing scans is never blocked
 * (attestations unlimited). Enforced by lib/planGate.ts. There are no prices: more is by contacting us.
 */
export const PLAN_LIMITS: Record<string, PlanLimits> = {
  free: { scans: 3, attestations: -1, repos: 1, members: 2, reports: 1 },
};

/** The limits of a plan; any plan name is the free trial, the only one there is. */
export const planLimits = (_plan?: string | null): PlanLimits => PLAN_LIMITS.free;

/** Usage at or above this share of a limit is a warning. */
export const WARN_AT = 0.8;

export type LimitLevel = "unlimited" | "ok" | "warn" | "full" | "over";
export interface LimitStatus {
  used: number;
  limit: number;
  /** 0-100, capped; 0 for unlimited. */
  pct: number;
  level: LimitLevel;
  /** How many more fit; null when unlimited. Never negative. */
  remaining: number | null;
}

export function limitStatus(used: number, limit: number): LimitStatus {
  const u = Math.max(0, Number.isFinite(used) ? used : 0);
  if (limit < 0) return { used: u, limit, pct: 0, level: "unlimited", remaining: null };
  const pct = limit === 0 ? (u > 0 ? 100 : 0) : Math.min(100, Math.round((u / limit) * 100));
  const level: LimitLevel = u > limit ? "over" : u === limit ? "full" : u >= limit * WARN_AT ? "warn" : "ok";
  return { used: u, limit, pct, level, remaining: Math.max(0, limit - u) };
}

const n = (v: number) => v.toLocaleString("en-US");

/** The sentence for a limit nearing or past its cap; null while there is plenty of room. */
export function limitMessage(noun: string, s: LimitStatus, opts: { upgrade?: boolean } = {}): string | null {
  const up = opts.upgrade === false ? "" : " Contact us to raise it.";
  if (s.level === "over") return `Over the limit: ${n(s.used)} ${noun} against ${n(s.limit)} on your plan.${up}`;
  if (s.level === "full") return `At the limit: all ${n(s.limit)} ${noun} on your plan are used.${up}`;
  if (s.level === "warn") return `${n(s.remaining ?? 0)} of ${n(s.limit)} ${noun} left on your plan.${opts.upgrade === false ? "" : " Contact us before you reach it."}`;
  return null;
}

// ── Internal caps ───────────────────────────────────────────────────────────

export interface Cap { value: number; unit: string; /** What happens past it, in the user's terms. */ effect: string; /** What to do about it. */ advice: string }

export const CAPS = {
  baselineFindings: { value: 5_000, unit: "findings", effect: "Baseline accepts at most 5,000 findings in one go.", advice: "Run Baseline again to accept the rest." },
  liveReanalysisFiles: { value: 60, unit: "files", effect: "Only the 60 files with the most AI signal are re-analysed with the newest scanner when you open a scan; the rest show what was stored when the scan ran.", advice: "Rescan the PR to re-analyse every file." },
  checkAnnotations: { value: 50, unit: "annotations", effect: "GitHub shows at most 50 inline annotations per check run, most severe first.", advice: "Open the review page for the full list." },
  fixedFindingsListed: { value: 100, unit: "findings", effect: "The list of fixed findings shows the first 100.", advice: "The count is exact; the list is capped." },
  maxFileBytes: { value: 1024 * 1024, unit: "bytes", effect: "Files over 1 MB are skipped by the scanner.", advice: "Split generated or bundled files, or exclude them." },
  apiSecurityEndpoints: { value: 2_000, unit: "endpoints", effect: "The API security report covers up to 2,000 endpoints.", advice: "Filter by repository to see the rest." },
  riskRegisterSync: { value: 500, unit: "risks", effect: "Syncing the risk register processes up to 500 risks at a time.", advice: "Close or merge old risks to keep the register under it." },
  incidents: { value: 1_000, unit: "incidents", effect: "The incident list shows the most recent 1,000.", advice: "Filter by status or date to see older ones." },
  tableRows: { value: 20_000, unit: "rows", effect: "Large pages read up to 20,000 rows, newest first.", advice: "Narrow the filters if the total looks short." },
  bulkRows: { value: 50_000, unit: "rows", effect: "Dependency and API-security data covers the newest 50,000 rows.", advice: "Filter by repository to focus." },
  providerFilesRead: { value: 50, unit: "files", effect: "GitLab and Bitbucket scans read up to 50 files per push.", advice: "The most-changed files are read first." },
  orgsListed: { value: 100, unit: "organisations", effect: "The organisation list shows the 100 newest.", advice: "Organisations beyond the first 100 are not listed here." },
  ruleLocations: { value: 2_000, unit: "files", effect: "Show all files lists up to 2,000 files for one rule.", advice: "Filter by repository to see the rest." },
  locationsPerRule: { value: 10, unit: "locations", effect: "Each rule lists up to 10 example locations at first.", advice: "Use \"Show all\" to load every location." },
} as const satisfies Record<string, Cap>;

export type CapId = keyof typeof CAPS;

// ── Rate limits ─────────────────────────────────────────────────────────────

export interface RateCap { limit: number; per: string; what: string }

/** Rate limits as users meet them (the enforcing values live in lib/rateLimit.ts RATE_LIMITS). */
export const RATE_CAPS = {
  scan: { limit: 60, per: "minute", what: "scan submissions per organisation" },
  attest: { limit: 120, per: "minute", what: "attestations per organisation" },
  report: { limit: 20, per: "hour", what: "generated reports per organisation" },
  keyCreate: { limit: 10, per: "hour", what: "API keys created per organisation" },
  rescan: { limit: 1, per: "minute", what: "rescan of the same pull request" },
} as const satisfies Record<string, RateCap>;

/** "60 scan submissions per organisation per minute". */
export const rateText = (id: keyof typeof RATE_CAPS): string => `${RATE_CAPS[id].limit} ${RATE_CAPS[id].what} per ${RATE_CAPS[id].per}`;

/** Whether a list was cut at a cap: it is exactly as long as the cap (the API stops there) or reports a larger total. */
export function isTruncated(shown: number, cap: number, total?: number | null): boolean {
  return total != null ? total > shown : shown >= cap;
}
