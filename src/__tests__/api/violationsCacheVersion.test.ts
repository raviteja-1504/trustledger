/**
 * @jest-environment node
 *
 * GET /api/violations: the shared org-wide cache is keyed by the org's data version, so a list cached before a
 * sign-off or status change is never served after it (the "15 → 13 → back to 15" bug), and isn't cached by the browser.
 */
import { NextRequest } from "next/server";

const store = new Map<string, unknown>();
let version: string | null = "v1";
let fetched = 0;

jest.mock("@/lib/cache", () => ({
  cached: async (k: string, _t: number, fn: () => Promise<unknown>) => {
    if (store.has(k)) return store.get(k);
    const v = await fn(); store.set(k, v); return v;
  },
  cacheDel: async () => {},
  invalidateViolationsCache: async () => {},
  cacheKeys: { violations: (o: string, s: string) => `viol:${o}:${s}`, dashboard: (o: string, d: number) => `dash:${o}:${d}` },
  TTL: { VIOLATIONS: 60 },
}));
jest.mock("@/lib/orgDataVersion", () => ({
  orgDataVersion: async () => version,
  versionedKey: (k: string, v: string) => `${k}:v:${v}`,
}));
jest.mock("@/lib/autoIncidents", () => ({ syncAutoIncidents: async () => {} }));
jest.mock("@/lib/audit", () => ({ writeAuditLog: async () => {} }));
jest.mock("@/app/api/_middleware", () => ({ verifyApiKey: async () => ({ org_id: "org-1", role: "admin", user_id: "u1" }), requirePermission: async () => null }));
jest.mock("@/lib/supabase", () => ({
  createServiceClient: () => ({
    from: () => {
      const q = {
        select: () => q, eq: () => q, neq: () => q, order: () => q, limit: () => q,
        then: (res: (v: unknown) => unknown) => { fetched++; return Promise.resolve({ data: [{ id: `v${fetched}`, file_path: "a.ts", status: "open", scans: { repo_full_name: "acme/api" } }], error: null }).then(res); },
      };
      return q;
    },
  }),
}));

import { GET } from "@/app/api/violations/route";

const get = async () => {
  const res = await GET(new NextRequest(new URL("/api/violations?status=unresolved&limit=1000", "https://app.example")));
  return { res, body: (await res.json()) as { violations: { id: string }[] } };
};

beforeEach(() => { store.clear(); version = "v1"; fetched = 0; });

describe("violations list cache is versioned", () => {
  it("same version → served from cache; a new version → fetched again", async () => {
    expect((await get()).body.violations[0].id).toBe("v1");
    expect((await get()).body.violations[0].id).toBe("v1");
    version = "v2";
    expect((await get()).body.violations[0].id).toBe("v2");
    expect([...store.keys()]).toEqual(["viol:org-1:unresolved:1000:v:v1", "viol:org-1:unresolved:1000:v:v2"]);
  });

  it("no version → no cache", async () => {
    version = null;
    await get(); await get();
    expect(fetched).toBe(2);
    expect(store.size).toBe(0);
  });

  it("responses are not cached by the browser", async () => {
    expect((await get()).res.headers.get("Cache-Control")).toBe("private, no-store");
  });
});
