/**
 * Threat intel: advisories that affect packages the org actually uses, grouped from dependency findings
 * (lib/dependencyScan.ts). One row per advisory and package version, listing every repository that uses it.
 * Pure, client-safe.
 */
import type { DepFinding } from "./dependencyScan";

export type AdvisoryFinding = Pick<DepFinding,
  "id" | "package_name" | "version_used" | "ecosystem" | "risk" | "type" | "repo" | "file_path" | "scan_id" | "description" |
  "fix" | "cve" | "cvss" | "exploit_public" | "exploit_detail"> & { reachability?: { tier: string } };

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
  description: string;
  fix?: string;
  repos: string[];
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
  stats: { advisories: number; packages: number; repos: number; exploits: number; reachable: number };
} {
  const byKey = new Map<string, Advisory>();
  for (const f of findings) {
    if (f.type !== "vulnerable") continue;
    const key = `${f.cve ?? f.description}::${f.ecosystem}::${f.package_name}@${f.version_used}`;
    const tier = f.reachability?.tier;
    const reach = tier && REACHABLE.has(tier) ? true : tier && NOT_REACHABLE.has(tier) ? false : undefined;
    const cur = byKey.get(key);
    if (!cur) {
      byKey.set(key, {
        key, id: f.cve, package_name: f.package_name, version_used: f.version_used, ecosystem: f.ecosystem, risk: f.risk,
        cvss: f.cvss ?? null, exploit_public: f.exploit_public, exploit_detail: f.exploit_detail, reachable: reach,
        description: f.description, fix: f.fix, repos: [f.repo],
      });
    } else {
      if (!cur.repos.includes(f.repo)) cur.repos.push(f.repo);
      cur.exploit_public ||= f.exploit_public;
      // Reachable anywhere wins; "not reachable" only when no repo is unknown or reachable.
      if (reach === true) cur.reachable = true;
      else if (reach === undefined && cur.reachable === false) cur.reachable = undefined;
    }
  }
  // Public exploit first, then reachable (so exploitable + reachable lead), then severity and CVSS.
  const advisories = [...byKey.values()].sort((a, b) =>
    Number(b.exploit_public) - Number(a.exploit_public)
    || Number(b.reachable === true) - Number(a.reachable === true)
    || (RISK_ORDER[a.risk] ?? 9) - (RISK_ORDER[b.risk] ?? 9)
    || (b.cvss ?? 0) - (a.cvss ?? 0)
    || a.package_name.localeCompare(b.package_name));
  advisories.forEach(a => a.repos.sort());
  const supplyChain = findings.filter(f => f.type === "hallucinated" || f.type === "typosquatting");
  return {
    advisories, supplyChain,
    stats: {
      advisories: advisories.length,
      packages: new Set(advisories.map(a => `${a.ecosystem}:${a.package_name}@${a.version_used}`)).size,
      repos: new Set(advisories.flatMap(a => a.repos)).size,
      exploits: advisories.filter(a => a.exploit_public).length,
      reachable: advisories.filter(a => a.reachable === true).length,
    },
  };
}
