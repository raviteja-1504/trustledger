/**
 * Threat intel (lib/threatIntel.ts): advisories from real dependency findings, one per advisory + package version
 * with every repo that uses it; exploitable + reachable first.
 */
import { buildAdvisories, filterFindings, filterOptions, fixPlan, priorityOf, type AdvisoryFinding } from "@/lib/threatIntel";
import { compareVersions } from "@/lib/lockfiles";

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

describe("priority, every advisory, and where it's used", () => {
  const adv = (id: string, severity: string, fixedIn?: string) => ({ id, aliases: [], severity: severity as "HIGH", fixedIn });

  it("Fix now: a public exploit, or reachable and HIGH/CRITICAL; Monitor: dev-only or not reachable; else Plan", () => {
    expect(priorityOf({ exploit_public: true, reachable: false, risk: "LOW", dev_only: true })).toBe("fix-now");
    expect(priorityOf({ exploit_public: false, reachable: true, risk: "CRITICAL", dev_only: false })).toBe("fix-now");
    expect(priorityOf({ exploit_public: false, reachable: true, risk: "HIGH", dev_only: true })).toBe("fix-now");
    expect(priorityOf({ exploit_public: false, reachable: true, risk: "MEDIUM", dev_only: false })).toBe("plan");
    expect(priorityOf({ exploit_public: false, reachable: undefined, risk: "CRITICAL", dev_only: false })).toBe("plan");
    expect(priorityOf({ exploit_public: false, reachable: undefined, risk: "CRITICAL", dev_only: true })).toBe("monitor");
    expect(priorityOf({ exploit_public: false, reachable: false, risk: "CRITICAL", dev_only: false })).toBe("monitor");
  });

  it("sorts Fix now first, whatever the severity", () => {
    const { advisories } = buildAdvisories([
      f({ package_name: "a", risk: "CRITICAL", scope: "dev" }),
      f({ package_name: "b", risk: "MEDIUM", exploit_public: true }),
      f({ package_name: "c", risk: "HIGH" }),
    ]);
    expect(advisories.map(a => [a.package_name, a.priority])).toEqual([["b", "fix-now"], ["c", "plan"], ["a", "monitor"]]);
  });

  it("lists every advisory against the version (the row used to show only the worst), merged across repos", () => {
    const { advisories, stats } = buildAdvisories([
      f({ repo: "acme/api", advisories: [adv("CVE-1", "HIGH", "4.17.19"), adv("CVE-2", "MEDIUM", "4.17.21")], latest_version: "4.17.21" }),
      f({ repo: "acme/web", advisories: [adv("CVE-1", "HIGH", "4.17.19"), adv("CVE-3", "LOW")] }),
    ]);
    expect(advisories).toHaveLength(1);
    expect(advisories[0].all_advisories.map(x => x.id)).toEqual(["CVE-1", "CVE-2", "CVE-3"]);
    expect(advisories[0].fix_version).toBe("4.17.21");
    expect(stats.advisory_ids).toBe(3);
    // a finding with no list still names its one advisory
    expect(buildAdvisories([f({ cve: "CVE-9" })]).advisories[0].all_advisories).toEqual([{ id: "CVE-9", severity: "HIGH" }]);
  });

  it("each use names its PR and how the package got there; dev-only / transitive only while EVERY use is", () => {
    const { advisories } = buildAdvisories([
      f({ repo: "acme/web", scan_id: "w1", pr_number: 9, scope: "dev", is_transitive: true, pulled_by: "jest", ai_introduced: true }),
      f({ repo: "acme/api", scan_id: "a1", pr_number: 4, scope: "runtime", is_transitive: true, pulled_by: "express" }),
    ]);
    const a = advisories[0];
    expect(a.usages.map(u => [u.repo, u.scan_id, u.pr_number, u.pulled_by, u.dev_only])).toEqual([
      ["acme/api", "a1", 4, "express", false], ["acme/web", "w1", 9, "jest", true],
    ]);
    expect([a.dev_only, a.transitive_only, a.ai_introduced]).toEqual([false, true, true]);
    const devOnly = buildAdvisories([f({ scope: "dev" }), f({ repo: "acme/web", scope: "dev" })]).advisories[0];
    expect([devOnly.dev_only, devOnly.transitive_only, devOnly.ai_introduced]).toEqual([true, false, false]);
  });
});

describe("fixPlan", () => {
  const adv = (id: string, fixedIn?: string) => ({ id, aliases: [], severity: "HIGH" as const, fixedIn });

  it("one upgrade per package, to the highest fix across the versions in use, most urgent first", () => {
    const { advisories } = buildAdvisories([
      f({ package_name: "lodash", version_used: "4.17.15", repo: "acme/api", advisories: [adv("L1", "4.17.19"), adv("L2", "4.17.21")], latest_version: "4.17.21" }),
      f({ package_name: "lodash", version_used: "4.17.20", repo: "acme/web", advisories: [adv("L2", "4.17.21")], latest_version: "4.17.21" }),
      f({ package_name: "axios", version_used: "0.21.0", repo: "acme/web", exploit_public: true, advisories: [adv("A1", "0.21.2")], latest_version: "0.21.2" }),
      f({ package_name: "minimist", version_used: "1.2.0", repo: "acme/api", advisories: [adv("M1", "1.2.6"), adv("M2")] }),
    ]);
    const plan = fixPlan(advisories, compareVersions);
    expect(plan.map(p => [p.package_name, p.priority, p.from, p.to, p.advisories, p.repos, p.unfixed])).toEqual([
      ["axios", "fix-now", ["0.21.0"], "0.21.2", 1, ["acme/web"], 0],
      // two versions in use, two distinct advisories, both repos
      ["lodash", "plan", ["4.17.15", "4.17.20"], "4.17.21", 2, ["acme/api", "acme/web"], 0],
      // one advisory has no fix: no single target version
      ["minimist", "plan", ["1.2.0"], undefined, 2, ["acme/api"], 1],
    ]);
  });
});

describe("merging uses and versions", () => {
  const adv = (id: string, fixedIn?: string) => ({ id, aliases: [], severity: "HIGH" as const, fixedIn });

  it("transitive only while every use is; AI-introduced if any use is, whichever comes first", () => {
    const a = buildAdvisories([
      f({ repo: "acme/api", is_transitive: true, pulled_by: "express" }),
      f({ repo: "acme/web", is_transitive: false, ai_introduced: true }),
    ]).advisories[0];
    expect([a.transitive_only, a.ai_introduced]).toEqual([false, true]);
  });

  it("a package's plan takes its most urgent version, the highest fix, and stops at an unfixed version", () => {
    const { advisories } = buildAdvisories([
      // the older version is lower priority and has the lower fix; it comes first
      f({ package_name: "qs", version_used: "6.5.0", repo: "acme/api", risk: "MEDIUM", advisories: [adv("Q1", "6.5.3"), adv("QX")], latest_version: "6.5.3" }),
      f({ package_name: "qs", version_used: "6.9.0", repo: "acme/web", exploit_public: true, advisories: [adv("Q2", "6.10.3"), adv("QX")], latest_version: "6.10.3" }),
    ]);
    const [qs] = fixPlan(advisories, compareVersions);
    expect([qs.priority, qs.to, qs.advisories, qs.unfixed]).toEqual(["fix-now", "6.10.3", 3, 1]);
    // the same in any order: the less urgent version, with the lower fix, first
    const [rev] = fixPlan([...advisories].reverse(), compareVersions);
    expect([rev.priority, rev.to]).toEqual(["fix-now", "6.10.3"]);
    // one version with no single fix version: no target for the package
    const partly = buildAdvisories([
      f({ package_name: "qs", version_used: "6.5.0", advisories: [adv("Q1", "6.5.3")], latest_version: "6.5.3" }),
      f({ package_name: "qs", version_used: "6.9.0", advisories: [adv("Q3")] }),
    ]).advisories;
    expect(fixPlan(partly, compareVersions)[0].to).toBeUndefined();
  });
});
