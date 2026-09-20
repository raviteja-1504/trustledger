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

import { lookupNpmLicense } from "@/lib/npmLicense";

const originalFetch = global.fetch;

function jsonResponse(body: unknown, ok = true) {
  return { ok, json: async () => body } as Response;
}

describe("npmLicense.lookupNpmLicense", () => {
  afterEach(() => {
    global.fetch = originalFetch;
    jest.restoreAllMocks();
  });

  it("returns the SPDX license string for a versioned lookup", async () => {
    const fetchMock = jest.fn().mockResolvedValueOnce(jsonResponse({ license: "MIT" }));
    global.fetch = fetchMock as unknown as typeof fetch;

    const result = await lookupNpmLicense("axios", "1.6.2");

    expect(result).toBe("MIT");
    expect(fetchMock).toHaveBeenCalledWith(expect.stringContaining("/axios/1.6.2"), expect.anything());
  });

  it("handles the { type } license object shape", async () => {
    global.fetch = jest.fn().mockResolvedValueOnce(jsonResponse({ license: { type: "Apache-2.0" } })) as unknown as typeof fetch;

    const result = await lookupNpmLicense("some-pkg", "1.0.0");

    expect(result).toBe("Apache-2.0");
  });

  it("falls back to the unversioned endpoint when the exact version 404s", async () => {
    const fetchMock = jest.fn()
      .mockResolvedValueOnce(jsonResponse({}, false))              // versioned 404
      .mockResolvedValueOnce(jsonResponse({ license: "BSD-3-Clause" })); // unversioned fallback
    global.fetch = fetchMock as unknown as typeof fetch;

    const result = await lookupNpmLicense("some-pkg", "999.0.0");

    expect(result).toBe("BSD-3-Clause");
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("scopes @org/pkg names correctly in the request URL", async () => {
    const fetchMock = jest.fn().mockResolvedValueOnce(jsonResponse({ license: "MIT" }));
    global.fetch = fetchMock as unknown as typeof fetch;

    await lookupNpmLicense("@babel/core", "7.0.0");

    expect(fetchMock).toHaveBeenCalledWith(expect.stringContaining("@babel%2Fcore/7.0.0"), expect.anything());
  });

  it("fails open (returns null) on a network error", async () => {
    global.fetch = jest.fn().mockRejectedValue(new Error("registry down")) as unknown as typeof fetch;

    const result = await lookupNpmLicense("axios", "1.0.0");

    expect(result).toBeNull();
  });

  it("returns null when no license field is present anywhere", async () => {
    global.fetch = jest.fn().mockResolvedValue(jsonResponse({})) as unknown as typeof fetch;

    const result = await lookupNpmLicense("no-license-pkg");

    expect(result).toBeNull();
  });
});
