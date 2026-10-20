/**
 * @jest-environment node
 *
 * GET /api/api-security: latest scan of each active repository, all files past the 1000-row cap, versioned cache.
 */
import { NextRequest } from "next/server";
import { fakeSupabase } from "../helpers/fakeSupabase";

let db: ReturnType<typeof fakeSupabase>;
const store = new Map<string, unknown>();
let version: string | null = "v1";
jest.mock("@/lib/supabase", () => ({ createServiceClient: () => db.client }));
jest.mock("@/app/api/_middleware", () => ({ verifyApiKey: async () => ({ org_id: "org-1" }) }));
jest.mock("@/lib/orgDataVersion", () => ({ orgDataVersion: async () => version, versionedKey: (k: string, v: string) => `${k}:v:${v}` }));
jest.mock("@/lib/cache", () => ({
  cached: async (k: string, _t: number, fn: () => Promise<unknown>) => { if (store.has(k)) return store.get(k); const v = await fn(); store.set(k, v); return v; },
  cacheKeys: { apiSecurity: (o: string) => `api:${o}` }, TTL: { DEPENDENCIES: 300 },
}));
jest.mock("@/lib/contentByHash", () => ({ fetchContentByHash: async () => new Map() }));

import { GET } from "@/app/api/api-security/route";

const get = async () => (await (await GET(new NextRequest(new URL("/api/api-security", "https://app.example")))).json()) as { counts: { endpoints: number }; repos: Array<{ repo: string; scan_id: string; endpoints: number }> };
const scan = (id: string, repo: string, at: string) => ({ id, org_id: "org-1", repo_full_name: repo, created_at: at });
const route = (scan_id: string, i: number) => ({ org_id: "org-1", scan_id, file_path: `src/r${String(i).padStart(4, "0")}.ts`, content: `router.get("/x${i}", requireUser, h);\n`, content_hash: null });

function seed() {
  const busy = Array.from({ length: 1200 }, (_, i) => scan(`a${i}`, "o/api", `2026-09-${String(1 + (i % 28)).padStart(2, "0")}T00:00:00Z`));
  db = fakeSupabase({
    repositories: [{ org_id: "org-1", repo_full_name: "o/api", is_active: true }, { org_id: "org-1", repo_full_name: "o/web", is_active: true }, { org_id: "org-1", repo_full_name: "o/off", is_active: false }],
    scans: [scan("w-old", "o/web", "2026-01-01T00:00:00Z"), ...busy, scan("a-latest", "o/api", "2026-10-05T00:00:00Z"), scan("off", "o/off", "2026-10-06T00:00:00Z")],
    scan_files: [...Array.from({ length: 1100 }, (_, i) => route("a-latest", i)), route("w-old", 0), route("off", 0)],
  }, { maxRows: 1000 });
}

beforeEach(() => { store.clear(); version = "v1"; seed(); });

describe("GET /api/api-security", () => {
  it("every active repository's latest scan and all of its files", async () => {
    const r = await get();
    expect(r.repos.map(x => [x.repo, x.scan_id, x.endpoints]).sort()).toEqual([["o/api", "a-latest", 1100], ["o/web", "w-old", 1]]);
    expect(r.counts.endpoints).toBe(1101);
  });

  it("a new data version recomputes instead of serving the cached report", async () => {
    await get();
    expect(store.size).toBe(1);
    version = "v2";
    await get();
    expect([...store.keys()]).toEqual(["api:org-1:v:v1", "api:org-1:v:v2"]);
  });
});
