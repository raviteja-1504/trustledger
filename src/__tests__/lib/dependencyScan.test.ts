jest.mock("@/lib/osvClient", () => ({
  lookupVulnerabilities: jest.fn(),
  OSV_ECOSYSTEM: {
    javascript: "npm", typescript: "npm", python: "PyPI", go: "Go",
    java: "Maven", rust: "crates.io", ruby: "RubyGems", csharp: "NuGet", php: "Packagist",
  },
}));
jest.mock("@/lib/npmLicense", () => ({ lookupNpmLicense: jest.fn() }));

import { deriveFindings, type ScanForDeps } from "@/lib/dependencyScan";
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
