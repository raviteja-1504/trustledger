/**
 * @jest-environment node
 *
 * /api/dashboard cache: the org's data version (latest attestation / scan / violation-status change) is part of the
 * key, so numbers computed before a sign-off are never served after it -- even from another server instance's
 * in-memory cache, or when an in-flight request re-saved the old copy right after the attestation's delete.
 */
import { NextRequest } from "next/server";

const store = new Map<string, unknown>();
let latest: Record<string, string | null> = { attestations: "2026-10-19T10:00:00Z", scans: "2026-10-19T09:00:00Z", violation_overrides: null };
let failTable: string | null = null;
let computed = 0;

jest.mock("@/lib/cache", () => ({
  cached: async (k: string, _t: number, fn: () => Promise<unknown>) => {
    if (store.has(k)) return store.get(k);
    const v = await fn(); store.set(k, v); return v;
  },
  cacheDel: async (k: string) => { store.delete(k); },
  cacheKeys: { dashboard: (o: string, d: number) => `dash:${o}:${d}` },
  TTL: { DASHBOARD: 300 },
}));
jest.mock("@/lib/dashboardAggregate", () => ({ fetchDashboard: async () => ({ repos: [], computed: ++computed }) }));
let role = "admin";
jest.mock("@/app/api/_middleware", () => ({ verifyApiKey: async () => ({ org_id: "org-1", role, user_id: "u1" }) }));
const orgFilters: string[] = [];
const eventFilters: string[] = [];
jest.mock("@/lib/supabase", () => ({
  createServiceClient: () => ({
    from: (table: string) => {
      const q = {
        select: () => q,
        eq: (col: string, val: string) => {
          if (col === "org_id") orgFilters.push(`${table}=${val}`);
          if (col === "event_type") eventFilters.push(`${table}=${val}`);
          return q;
        },
        order: () => q, limit: () => q, single: async () => ({ data: { github_login: "dev1" } }),
        maybeSingle: async () => failTable === table
          ? { data: null, error: { message: "boom" } }
          : { data: latest[table] == null ? null : { created_at: latest[table], updated_at: latest[table] }, error: null },
      };
      return q;
    },
  }),
}));

import { GET } from "@/app/api/dashboard/route";

const get = async () => (await (await GET(new NextRequest(new URL("/api/dashboard?days=30", "https://app.example")))).json()) as { computed: number };

beforeEach(() => {
  store.clear(); computed = 0; failTable = null; role = "admin"; orgFilters.length = 0; eventFilters.length = 0;
  latest = { attestations: "2026-10-19T10:00:00Z", scans: "2026-10-19T09:00:00Z", violation_overrides: null };
});

describe("dashboard cache is keyed by the org's data version", () => {
  it("same version → served from cache", async () => {
    expect((await get()).computed).toBe(1);
    expect((await get()).computed).toBe(1);
  });

  it("a new attestation changes the version → recomputed, even though the old entry is still cached", async () => {
    await get();
    latest.attestations = "2026-10-19T10:05:00Z";
    expect((await get()).computed).toBe(2);
    // The stale copy is never served again: the old entry is still in the store but under the old version's key.
    expect([...store.keys()].filter(k => k.startsWith("dash:org-1:30:v:"))).toHaveLength(2);
    expect((await get()).computed).toBe(2);
  });

  it("a new scan or a violation status change also changes the version", async () => {
    await get();
    latest.scans = "2026-10-19T11:00:00Z";
    expect((await get()).computed).toBe(2);
    latest.violation_overrides = "2026-10-19T11:30:00Z";
    expect((await get()).computed).toBe(3);
  });

  it("a status change on the violations page (incl. reopening) changes the version, via its audit entry", async () => {
    await get();
    latest.audit_log = "2026-10-19T11:45:00Z";
    expect((await get()).computed).toBe(2);
    expect(eventFilters).toContain("audit_log=violation_resolved");
  });

  it("an audit log that can't be read doesn't stop caching", async () => {
    failTable = "audit_log";
    expect((await get()).computed).toBe(1);
    expect((await get()).computed).toBe(1);
  });

  it("can't read the version → no cache at all (never risk stale numbers)", async () => {
    failTable = "attestations";
    expect((await get()).computed).toBe(1);
    expect((await get()).computed).toBe(2);
    expect(store.size).toBe(0);
  });

  it("an older database without violation_overrides still caches", async () => {
    failTable = "violation_overrides";
    expect((await get()).computed).toBe(1);
    expect((await get()).computed).toBe(1);
  });

  it("developer views are versioned the same way", async () => {
    role = "developer";
    await get();
    latest.attestations = "2026-10-19T12:00:00Z";
    expect((await get()).computed).toBe(2);
    expect([...store.keys()].every(k => k.includes(":dev:dev1:v:"))).toBe(true);
  });

  it("the version lookups are scoped to the caller's org", async () => {
    await get();
    expect(orgFilters).toEqual(expect.arrayContaining(["attestations=org-1", "scans=org-1", "violation_overrides=org-1", "audit_log=org-1"]));
  });
});
