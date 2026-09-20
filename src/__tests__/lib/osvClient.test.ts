// Mock the shared cache layer so tests are deterministic and don't leak
// state between cases via the real module-level MEM_CACHE (TTL.VULN_INTEL
// is 24h — without this, a later test's lookup could silently hit an
// earlier test's cached mock response instead of exercising fetch).
jest.mock("@/lib/cache", () => ({
  cached: async (_key: string, _ttl: number, fn: () => unknown) => fn(),
  cacheGet: async () => null,
  cacheSet: async () => {},
  cacheKeys: {
    osvPackage: (eco: string, name: string, version: string) => `osvpkg:${eco}:${name}:${version}`,
    osvVulnId:  (id: string) => `osvvuln:${id}`,
    npmLicense: (name: string, version: string) => `npmlic:${name}:${version}`,
  },
  TTL: { VULN_INTEL: 86400 },
}));

import { lookupVulnerabilities, OSV_ECOSYSTEM } from "@/lib/osvClient";

const originalFetch = global.fetch;

function jsonResponse(body: unknown, ok = true, status = 200) {
  return { ok, status, json: async () => body } as Response;
}

describe("osvClient.lookupVulnerabilities", () => {
  afterEach(() => {
    global.fetch = originalFetch;
    jest.restoreAllMocks();
  });

  it("returns a real finding shape for a known-vulnerable package", async () => {
    const fetchMock = jest.fn()
      .mockResolvedValueOnce(jsonResponse({ results: [{ vulns: [{ id: "GHSA-xxxx-yyyy-zzzz" }] }] })) // querybatch
      .mockResolvedValueOnce(jsonResponse({ // detail
        id: "GHSA-xxxx-yyyy-zzzz",
        aliases: ["CVE-2021-23337"],
        summary: "Command injection via template",
        database_specific: { severity: "HIGH" },
        affected: [{ ranges: [{ events: [{ fixed: "4.17.21" }] }] }],
      }));
    global.fetch = fetchMock as unknown as typeof fetch;

    const result = await lookupVulnerabilities([{ ecosystem: "npm", name: "lodash", version: "4.17.20" }]);
    const vulns = result.get("npm|lodash|4.17.20");

    expect(vulns).toHaveLength(1);
    expect(vulns![0]).toMatchObject({
      id: "GHSA-xxxx-yyyy-zzzz",
      aliases: ["CVE-2021-23337"],
      severity: "HIGH",
      fixedIn: "4.17.21",
    });
    expect(fetchMock).toHaveBeenCalledWith(expect.stringContaining("querybatch"), expect.anything());
    expect(fetchMock).toHaveBeenCalledWith(expect.stringContaining("GHSA-xxxx-yyyy-zzzz"), expect.anything());
  });

  it("returns no vulnerabilities for a clean package without false-positiving", async () => {
    const fetchMock = jest.fn().mockResolvedValueOnce(jsonResponse({ results: [{}] }));
    global.fetch = fetchMock as unknown as typeof fetch;

    const result = await lookupVulnerabilities([{ ecosystem: "npm", name: "left-pad", version: "1.3.0" }]);

    expect(result.get("npm|left-pad|1.3.0")).toEqual([]);
    expect(fetchMock).toHaveBeenCalledTimes(1); // no detail fetch when there are no ids
  });

  it("fails open when OSV is unreachable (network error)", async () => {
    global.fetch = jest.fn().mockRejectedValue(new Error("network down")) as unknown as typeof fetch;

    const result = await lookupVulnerabilities([{ ecosystem: "npm", name: "axios", version: "1.0.0" }]);

    expect(result.get("npm|axios|1.0.0")).toEqual([]);
  });

  it("fails open on a non-2xx querybatch response", async () => {
    global.fetch = jest.fn().mockResolvedValue(jsonResponse({}, false, 503)) as unknown as typeof fetch;

    const result = await lookupVulnerabilities([{ ecosystem: "PyPI", name: "requests", version: "2.0.0" }]);

    expect(result.get("PyPI|requests|2.0.0")).toEqual([]);
  });

  it("returns an empty map for an empty lookup list without calling fetch", async () => {
    const fetchMock = jest.fn();
    global.fetch = fetchMock as unknown as typeof fetch;

    const result = await lookupVulnerabilities([]);

    expect(result.size).toBe(0);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("maps this codebase's ecosystems to OSV's proper-noun strings", () => {
    expect(OSV_ECOSYSTEM.javascript).toBe("npm");
    expect(OSV_ECOSYSTEM.typescript).toBe("npm");
    expect(OSV_ECOSYSTEM.python).toBe("PyPI");
    expect(OSV_ECOSYSTEM.go).toBe("Go");
    expect(OSV_ECOSYSTEM.unknown).toBeUndefined();
  });
});
