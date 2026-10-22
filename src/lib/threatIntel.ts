/**
 * Threat intel: advisories that affect packages the org actually uses, grouped from dependency findings
 * (lib/dependencyScan.ts). One row per advisory and package version, listing every repository that uses it.
 * Pure, client-safe.
 */
import type { DepFinding } from "./dependencyScan";

export type AdvisoryFinding = Pick<DepFinding,
  "id" | "package_name" | "version_used" | "ecosystem" | "risk" | "type" | "repo" | "file_path" | "scan_id" | "description" |
  "fix" | "cve" | "cvss" | "exploit_public" | "exploit_detail"> &
  Partial<Pick<DepFinding, "advisories" | "is_transitive" | "pulled_by" | "scope" | "ai_introduced" | "latest_version" | "pr_number">> &
  { reachability?: { tier: string; summary?: string } };

/** How urgent an advisory is for YOU: a public exploit, or reachable and HIGH+, is "fix now"; a package used only to
 *  develop / test, or whose vulnerable code isn't reachable, is "monitor"; the rest is "plan". */
export type Priority = "fix-now" | "plan" | "monitor";
export const PRIORITY_LABEL: Record<Priority, string> = { "fix-now": "Fix now", plan: "Plan", monitor: "Monitor" };
const PRIORITY_ORDER: Record<Priority, number> = { "fix-now": 0, plan: 1, monitor: 2 };

/** One repository's use of the package version: which scan saw it, and how it got there. */
export interface AdvisoryUsage {
  repo: string; scan_id: string; pr_number: number | null; file_path: string;
  transitive: boolean; pulled_by?: string; dev_only: boolean; ai_introduced: boolean;
}

export interface Advisory {
  key: string;
  /** Advisory id (CVE / GHSA / OSV id) when the finding carries one. */
  id?: string;
  package_name: string;
  version_used: string;
  ecosystem: string;
  risk: string;
  cvss: number | null;
  exploit_public: boolean;
  exploit_detail?: string;
  /** true: the vulnerable code is called / reachable; false: it isn't; undefined: unknown. */
  reachable?: boolean;
  /** The reachability verdict in words, from the repository where it's most urgent. */
  reach_summary?: string;
  description: string;
  fix?: string;
  repos: string[];
  /** EVERY advisory against this version, worst first (the row used to show only the worst). */
  all_advisories: Array<{ id: string; severity: string; summary?: string; fixedIn?: string }>;
  /** The lowest version that fixes all of them, when every one has a fix. */
  fix_version?: string;
  usages: AdvisoryUsage[];
  /** Only used to develop / test / build in every repository. */
  dev_only: boolean;
  /** Pulled in only by other packages, never declared directly. */
  transitive_only: boolean;
  /** Added by AI-written code in at least one repository. */
  ai_introduced: boolean;
  priority: Priority;
}

/** The priority of an advisory (see Priority). */
export function priorityOf(a: Pick<Advisory, "exploit_public" | "reachable" | "risk" | "dev_only">): Priority {
  if (a.exploit_public || (a.reachable === true && (a.risk === "CRITICAL" || a.risk === "HIGH"))) return "fix-now";
  if (a.dev_only || a.reachable === false) return "monitor";
  return "plan";
}

const RISK_ORDER: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
const REACHABLE = new Set(["called", "reachable"]);
const NOT_REACHABLE = new Set(["not-called", "test-only", "not-imported"]);

export interface ThreatFilters {
  repo: string;        // "all" or "owner/name"
  ecosystem: string;   // "all" or e.g. "npm"
  severity: string;    // "all" or CRITICAL / HIGH / MEDIUM / LOW
}
export const NO_FILTERS: ThreatFilters = { repo: "all", ecosystem: "all", severity: "all" };

/** The repositories and ecosystems present, for the filter menus (sorted). */
export function filterOptions(findings: readonly AdvisoryFinding[]): { repos: string[]; ecosystems: string[] } {
  return {
    repos: [...new Set(findings.map(f => f.repo).filter(Boolean))].sort(),
    ecosystems: [...new Set(findings.map(f => f.ecosystem).filter(Boolean))].sort(),
  };
}

/** Findings narrowed to one repository and/or ecosystem -- applied BEFORE grouping, so the stats, the reachability
 *  verdict and the supply-chain list describe that repository alone, not every repository that shares a package. */
export function filterFindings(findings: readonly AdvisoryFinding[], f: Pick<ThreatFilters, "repo" | "ecosystem">): AdvisoryFinding[] {
  return findings.filter(x => (f.repo === "all" || x.repo === f.repo) && (f.ecosystem === "all" || x.ecosystem === f.ecosystem));
}

export function buildAdvisories(findings: readonly AdvisoryFinding[]): {
  advisories: Advisory[];
  supplyChain: AdvisoryFinding[];
  stats: { advisories: number; advisory_ids: number; packages: number; repos: number; exploits: number; reachable: number; fix_now: number };
} {
  const byKey = new Map<string, Advisory>();
  for (const f of findings) {
    if (f.type !== "vulnerable") continue;
    const key = `${f.cve ?? f.description}::${f.ecosystem}::${f.package_name}@${f.version_used}`;
    const tier = f.reachability?.tier;
    const reach = tier && REACHABLE.has(tier) ? true : tier && NOT_REACHABLE.has(tier) ? false : undefined;
    const usage: AdvisoryUsage = {
      repo: f.repo, scan_id: f.scan_id, pr_number: f.pr_number ?? null, file_path: f.file_path,
      transitive: !!f.is_transitive, pulled_by: f.pulled_by, dev_only: f.scope === "dev", ai_introduced: !!f.ai_introduced,
    };
    const listed = f.advisories && f.advisories.length > 0
      ? f.advisories.map(x => ({ id: x.id, severity: x.severity, summary: x.summary, fixedIn: x.fixedIn }))
      : f.cve ? [{ id: f.cve, severity: f.risk }] : [];
    const cur = byKey.get(key);
    if (!cur) {
      byKey.set(key, {
        key, id: f.cve, package_name: f.package_name, version_used: f.version_used, ecosystem: f.ecosystem, risk: f.risk,
        cvss: f.cvss ?? null, exploit_public: f.exploit_public, exploit_detail: f.exploit_detail, reachable: reach,
        reach_summary: f.reachability?.summary,
        description: f.description, fix: f.fix, repos: [f.repo],
        all_advisories: listed, fix_version: f.latest_version, usages: [usage],
        dev_only: usage.dev_only, transitive_only: usage.transitive, ai_introduced: usage.ai_introduced,
        priority: "plan",
      });
    } else {
      if (!cur.repos.includes(f.repo)) cur.repos.push(f.repo);
      cur.usages.push(usage);
      cur.exploit_public ||= f.exploit_public;
      // Reachable anywhere wins; "not reachable" only when no repo is unknown or reachable.
      if (reach === true) { cur.reachable = true; cur.reach_summary = f.reachability?.summary ?? cur.reach_summary; }
      else if (reach === undefined && cur.reachable === false) cur.reachable = undefined;
      // Dev-only / transitive only while EVERY use is; AI-introduced if any is.
      cur.dev_only &&= usage.dev_only;
      cur.transitive_only &&= usage.transitive;
      cur.ai_introduced ||= usage.ai_introduced;
      for (const x of listed) if (!cur.all_advisories.some(y => y.id === x.id)) cur.all_advisories.push(x);
    }
  }
  for (const a of byKey.values()) a.priority = priorityOf(a);
  // Fix now first; within a priority, public exploit, then reachable, then severity and CVSS.
  const advisories = [...byKey.values()].sort((a, b) =>
    PRIORITY_ORDER[a.priority] - PRIORITY_ORDER[b.priority]
    || Number(b.exploit_public) - Number(a.exploit_public)
    || Number(b.reachable === true) - Number(a.reachable === true)
    || (RISK_ORDER[a.risk] ?? 9) - (RISK_ORDER[b.risk] ?? 9)
    || (b.cvss ?? 0) - (a.cvss ?? 0)
    || a.package_name.localeCompare(b.package_name));
  advisories.forEach(a => { a.repos.sort(); a.usages.sort((x, y) => x.repo.localeCompare(y.repo)); });
  const supplyChain = findings.filter(f => f.type === "hallucinated" || f.type === "typosquatting");
  return {
    advisories, supplyChain,
    stats: {
      advisories: advisories.length,
      advisory_ids: new Set(advisories.flatMap(a => a.all_advisories.map(x => x.id))).size,
      packages: new Set(advisories.map(a => `${a.ecosystem}:${a.package_name}@${a.version_used}`)).size,
      repos: new Set(advisories.flatMap(a => a.repos)).size,
      exploits: advisories.filter(a => a.exploit_public).length,
      reachable: advisories.filter(a => a.reachable === true).length,
      fix_now: advisories.filter(a => a.priority === "fix-now").length,
    },
  };
}

/** One upgrade: a package, the version that fixes every advisory against the versions in use, and what it clears. */
export interface FixStep {
  ecosystem: string;
  package_name: string;
  /** Versions in use today. */
  from: string[];
  /** The version to move to: the highest of the per-version fixes. Undefined when some advisory has no fix yet. */
  to?: string;
  advisories: number;
  repos: string[];
  priority: Priority;
  /** Advisories with no fixed version published. */
  unfixed: number;
}

/**
 * The fix plan: one upgrade per package, most urgent first -- "move lodash to 4.17.21: clears 3 advisories in 2
 * repositories". Built from the advisories as shown, so it follows the page's filters.
 */
export function fixPlan(advisories: readonly Advisory[], compare: (a: string, b: string) => number): FixStep[] {
  const byPkg = new Map<string, FixStep & { ids: Set<string>; repoSet: Set<string>; anyUnknownFix: boolean }>();
  for (const a of advisories) {
    const k = `${a.ecosystem}::${a.package_name}`;
    const s = byPkg.get(k) ?? { ecosystem: a.ecosystem, package_name: a.package_name, from: [], advisories: 0, repos: [], priority: a.priority,
      unfixed: 0, ids: new Set<string>(), repoSet: new Set<string>(), anyUnknownFix: false };
    if (!s.from.includes(a.version_used)) s.from.push(a.version_used);
    for (const x of a.all_advisories) {
      if (s.ids.has(x.id)) continue;
      s.ids.add(x.id);
      if (!x.fixedIn) s.unfixed++;
    }
    a.repos.forEach(r => s.repoSet.add(r));
    if (PRIORITY_ORDER[a.priority] < PRIORITY_ORDER[s.priority]) s.priority = a.priority;
    if (!a.fix_version) s.anyUnknownFix = true;
    else if (!s.to || compare(a.fix_version, s.to) > 0) s.to = a.fix_version;
    byPkg.set(k, s);
  }
  return [...byPkg.values()].map(({ ids, repoSet, anyUnknownFix, ...s }) => ({
    ...s, to: anyUnknownFix ? undefined : s.to, advisories: ids.size, repos: [...repoSet].sort(), from: s.from.sort(compare),
  })).sort((a, b) => PRIORITY_ORDER[a.priority] - PRIORITY_ORDER[b.priority] || b.advisories - a.advisories || b.repos.length - a.repos.length
    || a.package_name.localeCompare(b.package_name));
}
