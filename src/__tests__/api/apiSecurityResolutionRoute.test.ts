/**
 * @jest-environment node
 *
 * GET /api/api-security with resolutions: a decision on an endpoint is laid over the (cached) report at once, only
 * for this organisation and only the API rules, and it stops applying when it expires.
 */
import { NextRequest } from "next/server";
import { fakeSupabase } from "../helpers/fakeSupabase";

let db: ReturnType<typeof fakeSupabase>;
const store = new Map<string, unknown>();
jest.mock("@/lib/supabase", () => ({ createServiceClient: () => db.client }));
jest.mock("@/app/api/_middleware", () => ({ verifyApiKey: async () => ({ org_id: "org-1" }) }));
jest.mock("@/lib/orgDataVersion", () => ({ orgDataVersion: async () => "v1", versionedKey: (k: string, v: string) => `${k}:v:${v}` }));
jest.mock("@/lib/cache", () => ({
  cached: async (k: string, _t: number, fn: () => Promise<unknown>) => { if (store.has(k)) return store.get(k); const v = await fn(); store.set(k, v); return v; },
  cacheKeys: { apiSecurity: (o: string) => `api:${o}` }, TTL: { DEPENDENCIES: 300 },
}));
jest.mock("@/lib/contentByHash", () => ({ fetchContentByHash: async () => new Map() }));

import { GET } from "@/app/api/api-security/route";
import { endpointKey } from "@/lib/api/apiResolution";

type R = { counts: { flagged: number; findings: number; resolvedEndpoints?: number }; endpoints: Array<{ method: string; path: string; flagged: boolean; resolution?: { kind: string; reason: string } }>; findings: Array<{ resolution?: unknown }> };
const get = async () => (await (await GET(new NextRequest(new URL("/api/api-security", "https://app.example")))).json()) as R;
const triageRows = () => (db.client.from("finding_triage") as unknown as { rows: Array<Record<string, unknown>> }).rows;
const DELETE_KEY = endpointKey("o/api", "DELETE", "/orders/:id");
const decision = (over: Record<string, unknown> = {}) => ({
  org_id: "org-1", repo_full_name: "o/api", fingerprint: DELETE_KEY, rule_id: "api-auth-elsewhere", status: "accepted", reason: "gateway checks it",
  expires_at: null, set_by_email: "rev@x.io", set_at: "2026-06-01T00:00:00Z", ...over,
});

beforeEach(() => {
  store.clear();
  db = fakeSupabase({
    repositories: [{ org_id: "org-1", repo_full_name: "o/api", is_active: true }],
    scans: [{ id: "s1", org_id: "org-1", repo_full_name: "o/api", created_at: "2026-10-05T00:00:00Z" }],
    scan_files: [{ org_id: "org-1", scan_id: "s1", file_path: "src/routes.ts", content_hash: null,
      content: `const router = express.Router();\nrouter.get("/orders", requireUser, list);\nrouter.post("/orders", requireUser, create);\nrouter.delete("/orders/:id", remove);\n` }],
    finding_triage: [],
  });
});

describe("GET /api/api-security: resolutions", () => {
  it("with no decisions, the unprotected route is flagged", async () => {
    const r = await get();
    expect(r.counts.flagged).toBe(1);
    expect(r.endpoints.find(e => e.method === "DELETE")).toMatchObject({ flagged: true });
    expect(r.endpoints.every(e => !e.resolution)).toBe(true);
  });

  it("a stored decision resolves it at once, without waiting for the cached report to expire", async () => {
    const before = await get();                                   // fills the cache
    expect(before.counts.flagged).toBe(1);
    triageRows().push(decision());
    const after = await get();                                    // same data version: served from cache, resolution overlaid
    expect(store.size).toBe(1);
    expect(after.counts.flagged).toBe(0);
    expect(after.counts.resolvedEndpoints).toBe(1);
    expect(after.endpoints.find(e => e.method === "DELETE")!.resolution).toMatchObject({ kind: "auth-elsewhere", reason: "gateway checks it" });
    expect(before.findings.length).toBeGreaterThan(0);               // the missing-auth finding existed...
    expect(after.findings.every(f => f.resolution)).toBe(true);       // ...and resolving its endpoint settled it too
    expect(after.counts.findings).toBe(0);
  });

  it("reopening (deleting the decision) brings it back", async () => {
    triageRows().push(decision());
    expect((await get()).counts.flagged).toBe(0);
    triageRows().length = 0;
    expect((await get()).counts.flagged).toBe(1);
  });

  it("the cached report itself is never changed by a resolution", async () => {
    triageRows().push(decision());
    await get();
    const cachedReport = [...store.values()][0] as R;
    expect(cachedReport.counts.flagged).toBe(1);
    expect(cachedReport.endpoints.every(e => !e.resolution)).toBe(true);
  });

  it("ignores an expired decision, another organisation's, and one recorded under a different rule", async () => {
    triageRows().push(
      decision({ expires_at: "2020-01-01T00:00:00Z" }),
      decision({ org_id: "org-2", fingerprint: DELETE_KEY }),
      decision({ rule_id: "sql-injection" }),
    );
    const r = await get();
    expect(r.counts.flagged).toBe(1);
    expect(r.endpoints.every(e => !e.resolution)).toBe(true);
  });

  it("a decision that expires later still applies now", async () => {
    triageRows().push(decision({ expires_at: new Date(Date.now() + 5 * 86_400_000).toISOString() }));
    expect((await get()).counts.flagged).toBe(0);
  });

  it("when the triage table is unavailable the report still loads (nothing resolved)", async () => {
    delete (db.client as unknown as { from?: unknown }).from;
    db = { ...db, client: { ...db.client, from: (t: string) => { if (t === "finding_triage") throw new Error("relation does not exist"); return fakeSupabase({ repositories: [], scans: [] }).client.from(t); } } } as typeof db;
    const res = await GET(new NextRequest(new URL("/api/api-security", "https://app.example")));
    expect(res.status).toBe(200);
  });
});
