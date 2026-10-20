/**
 * Threat intel (lib/threatIntel.ts): advisories from real dependency findings, one per advisory + package version
 * with every repo that uses it; exploitable + reachable first.
 */
import { buildAdvisories, filterFindings, filterOptions, type AdvisoryFinding } from "@/lib/threatIntel";

const f = (o: Partial<AdvisoryFinding>): AdvisoryFinding => ({
  id: Math.random().toString(36).slice(2), package_name: "lodash", version_used: "4.17.15", ecosystem: "npm", risk: "HIGH", type: "vulnerable",
  repo: "acme/api", file_path: "package.json", scan_id: "s1", description: "Prototype pollution", fix: "Upgrade to 4.17.21",
  cve: "CVE-2020-8203", cvss: 7.4, exploit_public: false, ...o,
} as AdvisoryFinding);

describe("buildAdvisories", () => {
  it("groups the same advisory and version across repos", () => {
    const { advisories, stats } = buildAdvisories([f({ repo: "acme/web" }), f({ repo: "acme/api" }), f({ repo: "acme/api", file_path: "sub/package.json" })]);
    expect(advisories).toHaveLength(1);
    expect(advisories[0]).toMatchObject({ id: "CVE-2020-8203", package_name: "lodash", repos: ["acme/api", "acme/web"], fix: "Upgrade to 4.17.21" });
    expect(stats).toMatchObject({ advisories: 1, packages: 1, repos: 2, exploits: 0, reachable: 0 });
  });

  it("a different version of the same package is its own row", () => {
    expect(buildAdvisories([f({}), f({ version_used: "4.17.19" })]).advisories).toHaveLength(2);
  });

  it("exploitable and reachable first, then exploitable, reachable, severity, CVSS", () => {
    const { advisories } = buildAdvisories([
      f({ package_name: "low", cve: "C-1", risk: "LOW", cvss: 3 }),
      f({ package_name: "crit", cve: "C-2", risk: "CRITICAL", cvss: 9.8 }),
      f({ package_name: "reach", cve: "C-3", risk: "MEDIUM", reachability: { tier: "called" } }),
      f({ package_name: "exploit", cve: "C-4", risk: "MEDIUM", exploit_public: true }),
      f({ package_name: "both", cve: "C-5", risk: "LOW", exploit_public: true, reachability: { tier: "reachable" } }),
      f({ package_name: "high", cve: "C-6", risk: "HIGH", cvss: 8 }),
    ]);
    expect(advisories.map(a => a.package_name)).toEqual(["both", "exploit", "reach", "crit", "high", "low"]);
  });

  it("reachability: reachable anywhere wins; 'not reachable' only if every repo is not reachable", () => {
    const one = (tiers: Array<string | undefined>) =>
      buildAdvisories(tiers.map((t, i) => f({ repo: `r${i}`, reachability: t ? { tier: t } : undefined }))).advisories[0].reachable;
    expect(one(["not-called", "called"])).toBe(true);
    expect(one(["not-called", "test-only"])).toBe(false);
    expect(one(["not-called", undefined])).toBeUndefined();
    expect(one(["imported"])).toBeUndefined();
  });

  it("supply-chain risks are listed separately; other finding types are ignored", () => {
    const { advisories, supplyChain } = buildAdvisories([
      f({ type: "hallucinated", package_name: "react-utils-pro" }), f({ type: "typosquatting", package_name: "lodahs" }), f({ type: "outdated" as never }),
    ]);
    expect(advisories).toHaveLength(0);
    expect(supplyChain.map(s => s.package_name)).toEqual(["react-utils-pro", "lodahs"]);
  });

  it("filter menus list each repository / ecosystem once, sorted; filtering keeps only the chosen ones", () => {
    const all = [f({ repo: "zeta/svc", ecosystem: "python" }), f({ repo: "acme/web" }), f({ repo: "acme/api" }), f({ repo: "acme/web", ecosystem: "python" })];
    expect(filterOptions(all)).toEqual({ repos: ["acme/api", "acme/web", "zeta/svc"], ecosystems: ["npm", "python"] });
    expect(filterFindings(all, { repo: "acme/web", ecosystem: "all" }).map(x => x.ecosystem)).toEqual(["npm", "python"]);
    expect(filterFindings(all, { repo: "acme/web", ecosystem: "python" })).toHaveLength(1);
    expect(filterFindings(all, { repo: "all", ecosystem: "all" })).toHaveLength(4);
  });
});
