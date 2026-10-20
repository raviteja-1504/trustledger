jest.mock("@/lib/osvClient", () => ({
  lookupVulnerabilities: jest.fn(),
  OSV_ECOSYSTEM: {
    javascript: "npm", typescript: "npm", python: "PyPI", go: "Go",
    java: "Maven", rust: "crates.io", ruby: "RubyGems", csharp: "NuGet", php: "Packagist",
  },
}));
jest.mock("@/lib/npmLicense", () => ({ lookupNpmLicense: jest.fn() }));

import { deriveFindings, fixingVersion, isBuiltinImport, nonCveFor, packageOccurrences, type ScanForDeps } from "@/lib/dependencyScan";
import { lookupVulnerabilities } from "@/lib/osvClient";
import { lookupNpmLicense } from "@/lib/npmLicense";

const mockLookupVulnerabilities = lookupVulnerabilities as jest.MockedFunction<typeof lookupVulnerabilities>;
const mockLookupNpmLicense = lookupNpmLicense as jest.MockedFunction<typeof lookupNpmLicense>;

function scanWithPackageJson(deps: Record<string, string>): ScanForDeps {
  return {
    repo: "acme/demo", pr_number: 1, scan_id: "scan_1",
    files: [{ file_path: "package.json", content: JSON.stringify({ dependencies: deps }), ai_percentage: 0.5 }],
  };
}

function scanWithRequirementsTxt(lines: string[]): ScanForDeps {
  return {
    repo: "acme/demo", pr_number: 1, scan_id: "scan_1",
    files: [{ file_path: "requirements.txt", content: lines.join("\n"), ai_percentage: 0.5 }],
  };
}

describe("dependencyScan.deriveFindings", () => {
  beforeEach(() => {
    mockLookupVulnerabilities.mockReset().mockResolvedValue(new Map());
    mockLookupNpmLicense.mockReset().mockResolvedValue(null);
  });

  it("still flags a NON_CVE_RISK_DB package (hallucinated) even when OSV returns nothing for it", async () => {
    const findings = await deriveFindings([scanWithRequirementsTxt(["ml-utils-fast==1.0.0"])]);

    const f = findings.find(f => f.package_name === "ml-utils-fast");
    expect(f).toBeDefined();
    expect(f!.type).toBe("hallucinated");
    expect(f!.risk).toBe("CRITICAL");
  });

  it("emits a type:'safe' finding for a clean package with no DB entry and no OSV vulns (SBOM completeness)", async () => {
    const findings = await deriveFindings([scanWithPackageJson({ "some-clean-pkg": "^1.0.0" })]);

    const f = findings.find(f => f.package_name === "some-clean-pkg");
    expect(f).toBeDefined();
    expect(f!.type).toBe("safe");
    expect(f!.risk).toBe("SAFE");
  });

  it("lets NON_CVE_RISK_DB take precedence over any OSV result for the same package", async () => {
    mockLookupVulnerabilities.mockResolvedValue(new Map([
      ["npm|moment|2.0.0", [{ id: "GHSA-fake", aliases: ["CVE-9999-0001"], severity: "CRITICAL" as const, summary: "fabricated for this test" }]],
    ]));

    const findings = await deriveFindings([scanWithPackageJson({ moment: "2.0.0" })]);

    const f = findings.find(f => f.package_name === "moment");
    expect(f).toBeDefined();
    expect(f!.type).toBe("unmaintained"); // NON_CVE_RISK_DB's classification, not OSV's
    expect(f!.cve).toBeUndefined();
  });

  it("never triggers an OSV lookup for ecosystem 'unknown'", async () => {
    const scan: ScanForDeps = {
      repo: "acme/demo", pr_number: 1, scan_id: "scan_1",
      files: [{ file_path: "README.md", content: "some-clean-pkg is a dependency", ai_percentage: 0.1 }],
    };

    const findings = await deriveFindings([scan]);

    expect(findings).toHaveLength(0);
    expect(mockLookupVulnerabilities).not.toHaveBeenCalled();
  });

  it("returns a synthesized vulnerable finding from a real OSV result", async () => {
    mockLookupVulnerabilities.mockResolvedValue(new Map([
      ["npm|left-pad|1.0.0", [{ id: "GHSA-abcd", aliases: ["CVE-2020-0001"], severity: "HIGH" as const, summary: "test vuln", fixedIn: "1.0.1" }]],
    ]));

    const findings = await deriveFindings([scanWithPackageJson({ "left-pad": "1.0.0" })]);

    const f = findings.find(f => f.package_name === "left-pad");
    expect(f).toBeDefined();
    expect(f).toMatchObject({ type: "vulnerable", risk: "HIGH", cve: "CVE-2020-0001", latest_version: "1.0.1" });
  });

  it("returns a full, degraded (not crashed) result when the OSV client rejects", async () => {
    mockLookupVulnerabilities.mockRejectedValue(new Error("osv down"));

    const findings = await deriveFindings([scanWithPackageJson({ "some-clean-pkg": "^1.0.0" })]);

    // osvClient itself already fails open internally (see osvClient.test.ts);
    // this covers deriveFindings' own defense-in-depth try/catch around that
    // call, in case a future regression there ever throws anyway.
    const f = findings.find(f => f.package_name === "some-clean-pkg");
    expect(f).toBeDefined();
    expect(f!.type).toBe("safe");
  });
});

describe("dependencyScan.deriveFindings -- composer.json / .csproj (PHP/C# manifest support)", () => {
  beforeEach(() => {
    mockLookupVulnerabilities.mockReset().mockResolvedValue(new Map());
    mockLookupNpmLicense.mockReset().mockResolvedValue(null);
  });

  it("parses composer.json and queries OSV against the Packagist ecosystem", async () => {
    mockLookupVulnerabilities.mockResolvedValue(new Map([
      ["Packagist|guzzlehttp/guzzle|6.5.0", [{ id: "GHSA-fake", aliases: ["CVE-2022-29248"], severity: "HIGH" as const, summary: "test vuln", fixedIn: "7.4.5" }]],
    ]));
    const scan: ScanForDeps = {
      repo: "acme/demo", pr_number: 1, scan_id: "scan_1",
      files: [{ file_path: "composer.json", content: JSON.stringify({ require: { php: ">=7.2", "guzzlehttp/guzzle": "6.5.0" } }), ai_percentage: 0.1 }],
    };
    const findings = await deriveFindings([scan]);
    const f = findings.find(x => x.package_name === "guzzlehttp/guzzle");
    expect(f).toBeDefined();
    expect(f!.ecosystem).toBe("php");
    expect(f).toMatchObject({ type: "vulnerable", risk: "HIGH", cve: "CVE-2022-29248" });
    // "php" the runtime requirement itself is not a real Packagist package.
    expect(findings.some(x => x.package_name === "php")).toBe(false);
  });

  it("parses a .csproj and queries OSV against the NuGet ecosystem", async () => {
    // Newtonsoft.Json is deliberately NOT used here -- it's in NON_CVE_RISK_DB, which takes
    // precedence over OSV by design (see the earlier "lets NON_CVE_RISK_DB take precedence" test).
    mockLookupVulnerabilities.mockResolvedValue(new Map([
      ["NuGet|Serilog|2.10.0", [{ id: "GHSA-fake", aliases: ["CVE-2024-99999"], severity: "HIGH" as const, summary: "test vuln", fixedIn: "2.12.0" }]],
    ]));
    const scan: ScanForDeps = {
      repo: "acme/demo", pr_number: 1, scan_id: "scan_1",
      files: [{ file_path: "src/Api.csproj", content: `<Project><ItemGroup><PackageReference Include="Serilog" Version="2.10.0" /></ItemGroup></Project>`, ai_percentage: 0.1 }],
    };
    const findings = await deriveFindings([scan]);
    const f = findings.find(x => x.package_name === "Serilog");
    expect(f).toBeDefined();
    expect(f!.ecosystem).toBe("csharp");
    expect(f).toMatchObject({ type: "vulnerable", risk: "HIGH", cve: "CVE-2024-99999" });
  });
});

describe("dependencyScan.deriveFindings -- base-image CVE lookup (Decision 2, new capability)", () => {
  beforeEach(() => {
    mockLookupVulnerabilities.mockReset().mockResolvedValue(new Map());
    mockLookupNpmLicense.mockReset().mockResolvedValue(null);
  });

  function scanWithDockerfile(content: string): ScanForDeps {
    return {
      repo: "acme/demo", pr_number: 1, scan_id: "scan_1",
      files: [{ file_path: "Dockerfile", content, ai_percentage: 0.2 }],
    };
  }

  it("queries OSV's Alpine ecosystem, release-qualified, for a curated base image", async () => {
    await deriveFindings([scanWithDockerfile("FROM node:20-alpine\nCMD [\"node\", \"app.js\"]\n")]);

    expect(mockLookupVulnerabilities).toHaveBeenCalled();
    const lookups = mockLookupVulnerabilities.mock.calls[0][0];
    expect(lookups.some(l => l.ecosystem === "Alpine:v3.19" && l.name === "openssl")).toBe(true);
    // Package-wide query (no fabricated version), per this module's own
    // established convention for unparseable/unknown exact versions.
    expect(lookups.every(l => l.ecosystem !== "Alpine:v3.19" || l.version === "")).toBe(true);
  });

  it("returns a real vulnerable finding, ecosystem 'docker', from a mocked OSV base-image OS package result", async () => {
    mockLookupVulnerabilities.mockResolvedValue(new Map([
      ["Alpine:v3.19|openssl|", [{ id: "CVE-2024-0001", aliases: ["CVE-2024-0001"], severity: "HIGH" as const, summary: "test OS package vuln", fixedIn: "3.1.5-r0" }]],
    ]));

    const findings = await deriveFindings([scanWithDockerfile("FROM node:20-alpine\n")]);

    const f = findings.find(f => f.package_name === "openssl");
    expect(f).toBeDefined();
    expect(f).toMatchObject({ ecosystem: "docker", type: "vulnerable", risk: "HIGH", cve: "CVE-2024-0001" });
  });

  it("silently skips a base image not in the curated table -- no findings, no OSV call for it", async () => {
    const findings = await deriveFindings([scanWithDockerfile("FROM my-private-registry.internal/custom-app:v3\n")]);
    expect(findings).toHaveLength(0);
    expect(mockLookupVulnerabilities).not.toHaveBeenCalled();
  });

  it("resolves a Debian-based curated image to the Debian ecosystem, not Alpine", async () => {
    await deriveFindings([scanWithDockerfile("FROM postgres:16\n")]);
    const lookups = mockLookupVulnerabilities.mock.calls[0][0];
    expect(lookups.some(l => l.ecosystem === "Debian:12" && l.name === "openssl")).toBe(true);
  });
});

describe("dependencyScan: lockfiles, transitives, imports", () => {
  const scan = (files: Array<{ file_path: string; content: string }>): ScanForDeps =>
    ({ repo: "acme/demo", pr_number: 1, scan_id: "scan_1", files: files.map(f => ({ ...f, ai_percentage: 0 })) });
  const pkgJson = { file_path: "package.json", content: JSON.stringify({ dependencies: { lodash: "^4.17.0" }, devDependencies: { jest: "^29.0.0" } }) };
  const lock = { file_path: "package-lock.json", content: JSON.stringify({ lockfileVersion: 3, packages: {
    "": { dependencies: { lodash: "^4.17.0" }, devDependencies: { jest: "^29.0.0" } },
    "node_modules/lodash": { version: "4.17.21" },
    "node_modules/jest": { version: "29.7.0", dev: true },
    "node_modules/old-lib": { version: "1.0.0" },
    "node_modules/old-lib/node_modules/lodash": { version: "4.17.15" },
  } }) };
  beforeEach(() => {
    mockLookupNpmLicense.mockReset().mockResolvedValue(null);
    mockLookupVulnerabilities.mockReset().mockResolvedValue(new Map());
  });

  it("a declared package's version comes from the lockfile: what's installed, not the range's floor", () => {
    const occ = packageOccurrences(scan([pkgJson, lock]));
    expect(occ.find(o => o.pkg === "lodash" && !o.isTransitive)).toMatchObject({ version: "4.17.21", versionSource: "lockfile", versionRange: "^4.17.0", dev: false });
    expect(occ.find(o => o.pkg === "jest")).toMatchObject({ version: "29.7.0", dev: true, isTransitive: false });
  });

  it("other locked packages are transitive at their locked versions -- including an older nested copy", () => {
    const t = packageOccurrences(scan([pkgJson, lock])).filter(o => o.isTransitive);
    expect(t.map(o => `${o.pkg}@${o.version}`).sort()).toEqual(["lodash@4.17.15", "old-lib@1.0.0"]);
    expect(t.find(o => o.pkg === "lodash")).toMatchObject({ pulledBy: "old-lib", filePath: "package-lock.json", versionSource: "lockfile" });
  });

  it("the direct copy is used for a declared package even when a nested copy comes first in the lockfile", () => {
    const nestedFirst = { file_path: "package-lock.json", content: JSON.stringify({ packages: {
      "": { dependencies: { lodash: "^4.17.0" } },
      "node_modules/a/node_modules/lodash": { version: "4.17.10" },
      "node_modules/lodash": { version: "4.17.21" },
      "node_modules/a": { version: "1.0.0" },
    } }) };
    const occ = packageOccurrences(scan([{ file_path: "package.json", content: JSON.stringify({ dependencies: { lodash: "^4.17.0" } }) }, nestedFirst]));
    expect(occ.find(o => o.pkg === "lodash" && !o.isTransitive)!.version).toBe("4.17.21");
    expect(occ.find(o => o.pkg === "lodash" && o.isTransitive)!.version).toBe("4.17.10");
  });

  it("a lockfile alone: its own direct flags decide; with a manifest, only what the manifest declares is direct", () => {
    const lockOnly = { file_path: "package-lock.json", content: JSON.stringify({ packages: {
      "": { dependencies: { lodash: "^4", "left-pad": "^1" } },
      "node_modules/lodash": { version: "4.17.21" }, "node_modules/left-pad": { version: "1.3.0" }, "node_modules/x": { version: "2.0.0" },
    } }) };
    const alone = packageOccurrences(scan([lockOnly]));
    expect(alone.filter(o => !o.isTransitive).map(o => o.pkg).sort()).toEqual(["left-pad", "lodash"]);
    expect(alone.find(o => o.pkg === "x")!.isTransitive).toBe(true);
    // A stale lockfile still lists left-pad as direct, but the manifest no longer declares it: transitive.
    const withManifest = packageOccurrences(scan([{ file_path: "package.json", content: JSON.stringify({ dependencies: { lodash: "^4" } }) }, lockOnly]));
    expect(withManifest.find(o => o.pkg === "left-pad")!.isTransitive).toBe(true);
  });

  it("the nearest lockfile wins in a monorepo; a manifest without one keeps its range", () => {
    const occ = packageOccurrences(scan([
      { file_path: "package-lock.json", content: JSON.stringify({ packages: { "": {}, "node_modules/react": { version: "17.0.0" } } }) },
      { file_path: "web/package.json", content: JSON.stringify({ dependencies: { react: "^18.0.0" } }) },
      { file_path: "web/package-lock.json", content: JSON.stringify({ packages: { "": { dependencies: { react: "^18" } }, "node_modules/react": { version: "18.2.0" } } }) },
      { file_path: "tools/requirements.txt", content: "requests>=2.0\n" },
    ]));
    expect(occ.find(o => o.pkg === "react" && o.filePath === "web/package.json")).toMatchObject({ version: "18.2.0", versionSource: "lockfile" });
    expect(occ.find(o => o.pkg === "requests")).toMatchObject({ version: ">=2.0", versionSource: "manifest" });
  });

  it("imports are only used for a language with no manifest, and never for built-in modules", () => {
    const withManifest = packageOccurrences(scan([pkgJson, { file_path: "src/a.ts", content: `import x from "left-pad";\nimport fs from "fs";` }]));
    expect(withManifest.some(o => o.pkg === "left-pad")).toBe(false);
    const py = packageOccurrences(scan([{ file_path: "app.py", content: "import json\nimport os.path\nimport requests\nfrom flask import Flask\n" }]));
    expect(py.map(o => o.pkg).sort()).toEqual(["flask", "requests"]);
    expect(py[0]).toMatchObject({ version: "", versionSource: "none" });
    expect(isBuiltinImport("node:crypto", "javascript")).toBe(true);
    expect(isBuiltinImport("fs/promises", "typescript")).toBe(true);
    expect(isBuiltinImport("express", "javascript")).toBe(false);
  });

  it("new manifests: Cargo.toml, Gemfile, pyproject.toml, Pipfile, requirements-dev.txt", () => {
    const occ = packageOccurrences(scan([
      { file_path: "Cargo.toml", content: `[dependencies]\nserde = "1.0"\n` },
      { file_path: "Gemfile", content: `gem "rails", "~> 7.1"\n` },
      { file_path: "py/pyproject.toml", content: `[project]\ndependencies = ["django>=4.2"]\n` },
      { file_path: "Pipfile", content: `[packages]\nflask = "==2.3.0"\n` },
      { file_path: "requirements-dev.txt", content: "pytest==8.0.0\n" },
    ]));
    expect(occ.map(o => [o.pkg, o.eco, !!o.dev]).sort()).toEqual([
      ["django", "python", false], ["flask", "python", false], ["pytest", "python", true], ["rails", "ruby", false], ["serde", "rust", false],
    ]);
  });

  it("findings carry scope, version source and range; transitive ids include the version", async () => {
    mockLookupVulnerabilities.mockResolvedValue(new Map([
      ["npm|lodash|4.17.15", [{ id: "GHSA-a", aliases: ["CVE-2021-23337"], severity: "HIGH" as const, fixedIn: "4.17.21" }]],
    ]));
    const findings = await deriveFindings([scan([pkgJson, lock])]);
    const direct = findings.find(f => f.package_name === "lodash" && !f.is_transitive)!;
    expect(direct).toMatchObject({ type: "safe", version_used: "4.17.21", version_source: "lockfile", version_range: "^4.17.0", scope: "runtime" });
    const nested = findings.find(f => f.package_name === "lodash" && f.is_transitive)!;
    expect(nested).toMatchObject({ type: "transitive", risk: "HIGH", version_used: "4.17.15", pulled_by: "old-lib", id: "scan_1::package-lock.json::lodash@4.17.15-t" });
    expect(findings.find(f => f.package_name === "jest")!.scope).toBe("dev");
  });
});

describe("dependencyScan: advisories and fixes", () => {
  const scan = (deps: Record<string, string>): ScanForDeps =>
    ({ repo: "acme/demo", pr_number: 1, scan_id: "scan_1", files: [{ file_path: "package.json", content: JSON.stringify({ dependencies: deps }), ai_percentage: 0 }] });
  beforeEach(() => mockLookupNpmLicense.mockReset().mockResolvedValue(null));

  it("every advisory is kept, worst first; the fix version clears all of them", async () => {
    mockLookupVulnerabilities.mockReset().mockResolvedValue(new Map([
      ["npm|axios|0.21.0", [
        { id: "GHSA-low", aliases: [], severity: "MEDIUM" as const, summary: "m", fixedIn: "1.6.0" },
        { id: "GHSA-hi", aliases: ["CVE-2021-3749"], severity: "HIGH" as const, summary: "ReDoS", fixedIn: "0.21.2" },
      ]],
    ]));
    const f = (await deriveFindings([scan({ axios: "0.21.0" })])).find(x => x.package_name === "axios")!;
    expect(f).toMatchObject({ risk: "HIGH", cve: "CVE-2021-3749", latest_version: "1.6.0", fix: "Update axios to 1.6.0 or later (fixes all 2 advisories)", description: "ReDoS (+1 more advisory)" });
    expect(f.advisories!.map(a => a.id)).toEqual(["GHSA-hi", "GHSA-low"]);
  });

  it("when an advisory has no fix, the fix says so", async () => {
    mockLookupVulnerabilities.mockReset().mockResolvedValue(new Map([
      ["npm|x|1.0.0", [{ id: "A", aliases: [], severity: "HIGH" as const, fixedIn: "1.2.0" }, { id: "B", aliases: [], severity: "LOW" as const }]],
    ]));
    const f = (await deriveFindings([scan({ x: "1.0.0" })])).find(x => x.package_name === "x")!;
    expect(f.fix).toBe("Update x to 1.2.0 or later (fixes the most severe; 1 advisory has no fix yet)");
  });

  it("fixingVersion / nonCveFor", () => {
    expect(fixingVersion([{ id: "a", aliases: [], severity: "LOW", fixedIn: "1.10.0" }, { id: "b", aliases: [], severity: "LOW", fixedIn: "1.9.0" }])).toBe("1.10.0");
    expect(fixingVersion([])).toBeUndefined();
    // "Outdated" only for a known, older version -- an up-to-date numpy isn't flagged.
    expect(nonCveFor("numpy", "==1.20.0")?.type).toBe("outdated");
    expect(nonCveFor("numpy", "==2.0.0")).toBeNull();
    expect(nonCveFor("numpy", "")).toBeNull();
    expect(nonCveFor("ml-utils-fast", "")?.type).toBe("hallucinated");
    expect(nonCveFor("left-pad", "1.0.0")).toBeNull();
  });
});

describe("dependencyScan.deriveFindings: reachability of vulnerable packages", () => {
  const scan = (files: Array<{ file_path: string; content: string }>): ScanForDeps =>
    ({ repo: "acme/demo", pr_number: 1, scan_id: "scan_1", files: files.map(f => ({ ...f, ai_percentage: 0 })) });
  const manifest = { file_path: "package.json", content: JSON.stringify({ dependencies: { lodash: "4.17.15", axios: "0.21.0", "left-pad": "1.0.0" } }) };
  const route = { file_path: "src/routes/t.ts", content: `import _ from "lodash";\napp.get("/t", (req, res) => res.send(_.template(req.query.t)()));\n` };
  beforeEach(() => {
    mockLookupNpmLicense.mockReset().mockResolvedValue(null);
    mockLookupVulnerabilities.mockReset().mockResolvedValue(new Map([
      ["npm|lodash|4.17.15", [{ id: "GHSA-a", aliases: ["CVE-2021-23337"], severity: "HIGH" as const, affectedSymbols: ["lodash.template"] }]],
      ["npm|axios|0.21.0", [{ id: "GHSA-b", aliases: ["CVE-2021-3749"], severity: "HIGH" as const }]],
    ]));
  });

  it("the vulnerable function called from a route; a vulnerable package never imported; a clean package gets no verdict", async () => {
    const findings = await deriveFindings([scan([manifest, route])]);
    const lodash = findings.find(f => f.package_name === "lodash")!;
    expect(lodash.reachability?.tier).toBe("called");
    expect(lodash.reachability?.evidence[0]).toMatchObject({ file: "src/routes/t.ts", line: 2, kind: "call" });
    expect(findings.find(f => f.package_name === "axios")!.reachability?.tier).toBe("not-imported");
    expect(findings.find(f => f.package_name === "left-pad")!.reachability).toBeUndefined();
  });

  it("an advisory without a function list makes the verdict import-level, never 'not called'", async () => {
    const findings = await deriveFindings([scan([manifest, { file_path: "src/routes/h.ts", content: `import axios from "axios";\napp.get("/h", async (req, res) => res.send(await axios.get("https://x")));\n` }])]);
    expect(findings.find(f => f.package_name === "axios")!.reachability?.tier).toBe("reachable");
  });
});
