/**
 * What the Organisations page says about each organisation: how it is doing, why it may need attention, how its
 * scan activity is trending, and how to sort and filter the list. Pure and client-safe (no imports beyond limits).
 */
import { limitStatus, planLimits } from "./limits";

export interface OrgMetrics {
  plan: string;
  created_at: string;
  scans_30d: number;
  scans_prev_30d: number;
  scans_this_month: number;
  open_violations: number;
  /** Open or in-review violations rated CRITICAL. */
  open_critical: number;
  /** Open or in-review violations past their SLA deadline. */
  overdue: number;
  member_count: number;
  repo_count: number;
  latest_risk: string;
  latest_ai_pct: number;
  last_scan: string | null;
}

export type OrgHealth = "at_risk" | "watch" | "healthy" | "inactive" | "new";
export interface Attention { level: "critical" | "warning" | "info"; text: string }

/** No scan for this long counts as quiet. */
export const STALE_DAYS = 14;
/** A new organisation gets this long before "no scans yet" is a problem. */
export const NEW_DAYS = 7;

const DAY = 86_400_000;
const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

export function daysSince(iso: string | null, now: Date): number | null {
  if (!iso) return null;
  const t = Date.parse(iso);
  return Number.isFinite(t) ? Math.max(0, Math.floor((now.getTime() - t) / DAY)) : null;
}

/** Why an organisation needs a look, most serious first. Empty when there is nothing to flag. */
export function orgAttention(o: OrgMetrics, now: Date = new Date()): Attention[] {
  const out: Attention[] = [];
  if (o.open_critical > 0) out.push({ level: "critical", text: `${plural(o.open_critical, "critical violation")} still open` });
  if (o.overdue > 0) out.push({ level: "critical", text: `${plural(o.overdue, "violation")} past ${o.overdue === 1 ? "its" : "their"} SLA deadline` });

  const idle = daysSince(o.last_scan, now);
  const age = daysSince(o.created_at, now) ?? 0;
  if (o.repo_count === 0) out.push({ level: "warning", text: "No repositories connected yet. Import repositories to start scanning." });
  else if (idle === null && age >= NEW_DAYS) out.push({ level: "warning", text: "Repositories are connected but no scan has run" });
  else if (idle !== null && idle >= STALE_DAYS) out.push({ level: "warning", text: `No scan in ${idle} days` });

  const lim = planLimits(o.plan);
  for (const [noun, used, limit] of [["scans", o.scans_this_month, lim.scans], ["repositories", o.repo_count, lim.repos], ["members", o.member_count, lim.members]] as const) {
    const s = limitStatus(used, limit);
    const Noun = `${noun[0].toUpperCase()}${noun.slice(1)}`;
    if (s.level === "warn") out.push({ level: "info", text: `${Noun} at ${s.pct}% of the plan limit (${used} of ${limit})` });
    else if (s.level === "full" && noun !== "repositories") out.push({ level: "warning", text: `${Noun} at the plan limit (${limit})` });
    else if (s.level === "over") out.push({ level: "warning", text: `${Noun} over the plan limit (${used} of ${limit})` });
  }

  if (o.scans_prev_30d >= 10 && o.scans_30d <= o.scans_prev_30d * 0.5) {
    out.push({ level: "info", text: `Scan activity down ${Math.round((1 - o.scans_30d / o.scans_prev_30d) * 100)}% on the previous 30 days` });
  }
  const rank = { critical: 0, warning: 1, info: 2 } as const;
  return out.sort((a, b) => rank[a.level] - rank[b.level]);
}

export function orgHealth(o: OrgMetrics, attention: readonly Attention[] = orgAttention(o), now: Date = new Date()): OrgHealth {
  if (attention.some(a => a.level === "critical")) return "at_risk";
  const age = daysSince(o.created_at, now) ?? 0;
  if (o.last_scan === null && o.repo_count === 0 && age < NEW_DAYS) return "new";
  const idle = daysSince(o.last_scan, now);
  if (o.last_scan === null || (idle !== null && idle >= STALE_DAYS * 2)) return "inactive";
  if (attention.some(a => a.level === "warning")) return "watch";
  return "healthy";
}

export const HEALTH_LABEL: Record<OrgHealth, string> = { at_risk: "At risk", watch: "Needs a look", healthy: "Healthy", inactive: "Inactive", new: "New" };
export const HEALTH_TIP: Record<OrgHealth, string> = {
  at_risk: "Critical violations are open or past their SLA deadline.",
  watch: "Nothing critical, but something needs a look: scanning has gone quiet, repositories are missing, or a plan limit is close.",
  healthy: "Scanning regularly, with no critical violations open and room left on the plan.",
  inactive: "No scan in a long time, or none has ever run.",
  new: "Created in the last week; no repositories or scans yet.",
};

/** Change in scan count against the previous 30 days. `pct` is null when there is nothing to compare with. */
export function scanTrend(current: number, previous: number): { dir: "up" | "down" | "flat"; pct: number | null } {
  if (previous <= 0) return { dir: current > 0 ? "up" : "flat", pct: null };
  const pct = Math.round(((current - previous) / previous) * 100);
  return { dir: pct > 0 ? "up" : pct < 0 ? "down" : "flat", pct };
}

export type OrgSortKey = "attention" | "name" | "risk" | "last_scan" | "violations";
const RISK_RANK: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, UNKNOWN: 4 };
const HEALTH_RANK: Record<OrgHealth, number> = { at_risk: 0, watch: 1, inactive: 2, new: 3, healthy: 4 };

export interface ListedOrg extends OrgMetrics { id: string; name: string; slug: string; github_org: string | null; health: OrgHealth; attention: Attention[] }

export function sortOrgs<T extends ListedOrg>(orgs: readonly T[], key: OrgSortKey): T[] {
  const by: Record<OrgSortKey, (a: T, b: T) => number> = {
    attention: (a, b) => HEALTH_RANK[a.health] - HEALTH_RANK[b.health] || b.open_critical - a.open_critical || b.attention.length - a.attention.length,
    name: (a, b) => a.name.localeCompare(b.name),
    risk: (a, b) => (RISK_RANK[a.latest_risk] ?? 4) - (RISK_RANK[b.latest_risk] ?? 4),
    last_scan: (a, b) => (b.last_scan ? Date.parse(b.last_scan) : 0) - (a.last_scan ? Date.parse(a.last_scan) : 0),
    violations: (a, b) => b.open_violations - a.open_violations,
  };
  return [...orgs].sort((a, b) => by[key](a, b) || a.name.localeCompare(b.name));
}

export function filterOrgs<T extends ListedOrg>(orgs: readonly T[], query: string, health: OrgHealth | "all"): T[] {
  const q = query.trim().toLowerCase();
  return orgs.filter(o =>
    (health === "all" || o.health === health) &&
    (!q || o.name.toLowerCase().includes(q) || o.slug.toLowerCase().includes(q) || (o.github_org ?? "").toLowerCase().includes(q)));
}

/** Totals across the listed organisations, for the summary strip. */
export function portfolioTotals(orgs: readonly ListedOrg[]) {
  return {
    orgs: orgs.length,
    needAttention: orgs.filter(o => o.health === "at_risk" || o.health === "watch").length,
    atRisk: orgs.filter(o => o.health === "at_risk").length,
    openCritical: orgs.reduce((n, o) => n + o.open_critical, 0),
    openViolations: orgs.reduce((n, o) => n + o.open_violations, 0),
    scans30d: orgs.reduce((n, o) => n + o.scans_30d, 0),
  };
}
