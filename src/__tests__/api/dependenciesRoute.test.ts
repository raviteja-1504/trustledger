/**
 * @jest-environment node
 *
 * GET /api/dependencies reads every repository's latest scan and all of its files, past the 1000-row cap -- a
 * repository whose latest scan is older than the org's newest 1000 used to drop out, and so did files (manifests
 * included) beyond row 1000.
 */
import { NextRequest } from "next/server";
import { fakeSupabase } from "../helpers/fakeSupabase";

let db: ReturnType<typeof fakeSupabase>;
let seen: Array<{ repo: string; scan_id: string; files: Array<{ file_path: string; content: string | null }> }> = [];
jest.mock("@/lib/supabase", () => ({ createServiceClient: () => db.client }));
jest.mock("@/app/api/_middleware", () => ({ verifyApiKey: async () => ({ org_id: "org-1" }) }));
const store = new Map<string, unknown>();
jest.mock("@/lib/cache", () => {
  const actual = jest.requireActual("@/lib/cache");
  return {
    singleFlight: actual.singleFlight,
    cacheGet: async (k: string) => (store.has(k) ? store.get(k) : null),
    cacheSet: async (k: string, v: unknown) => { store.set(k, JSON.parse(JSON.stringify(v))); },
    cacheKeys: { dependencies: (o: string) => `d:${o}` }, TTL: { DEPENDENCIES: 1 },
  };
});
let computations = 0;
jest.mock("@/lib/dependencyScan", () => ({ deriveFindings: async (scans: typeof seen) => { computations++; seen = scans; return []; } }));
jest.mock("@/lib/manifestPackages", () => ({ collectManifestPackages: () => [] }));
jest.mock("@/lib/contentByHash", () => ({ fetchContentByHash: async (_db: unknown, _o: string, hashes: string[]) => new Map(hashes.map(h => [h, `content of ${h}`])) }));

import { GET } from "@/app/api/dependencies/route";

const scan = (id: string, repo: string, at: string) => ({ id, org_id: "org-1", repo_full_name: repo, pr_number: 1, created_at: at });
const file = (scan_id: string, path: string, content: string | null, hash: string | null = null) => ({ org_id: "org-1", scan_id, file_path: path, content, content_hash: hash, ai_percentage: 0.5 });

beforeEach(() => { store.clear(); computations = 0; });
const get = () => GET(new NextRequest(new URL("/api/dependencies", "https://app.example")));

describe("caching: reused until a scan lands, never stale", () => {
  const seed = () => { db = fakeSupabase({ scans: [scan("s1", "o/api", "2026-10-01T00:00:00Z")], scan_files: [file("s1", "package.json", "{}")] }); };

  it("a repeat call reuses the result", async () => {
    seed();
    await get(); await get();
    expect(computations).toBe(1);
  });

  it("a new scan is a new version: recomputed at once", async () => {
    seed();
    await get();
    (db.client.from("scans") as unknown as { rows: unknown[] }).rows.push(scan("s2", "o/api", "2026-10-02T00:00:00Z"));
    await get();
    expect(computations).toBe(2);
    expect(seen[0].scan_id).toBe("s2");
  });

  it("the scan pipeline deleting the key (once a scan's files are written) forces a recompute", async () => {
    seed();
    await get();
    store.delete("d:org-1");
    await get();
    expect(computations).toBe(2);
  });

  it("calls arriving together share one computation", async () => {
    seed();
    await Promise.all([get(), get(), get(), get()]);
    expect(computations).toBe(1);
  });
});

it("every repository's latest scan, and every file of it, reach the dependency analysis", async () => {
  const busy = Array.from({ length: 1500 }, (_, i) => scan(`a${i}`, "o/api", `2026-09-${String(1 + (i % 28)).padStart(2, "0")}T00:00:00Z`));
  const apiFiles = Array.from({ length: 1400 }, (_, i) => file("a-latest", `src/f${String(i).padStart(4, "0")}.ts`, "x"));
  db = fakeSupabase({
    scans: [scan("w-old", "o/web", "2026-01-01T00:00:00Z"), ...busy, scan("a-latest", "o/api", "2026-10-05T00:00:00Z"), { ...scan("other", "x/y", "2026-10-06T00:00:00Z"), org_id: "org-2" }],
    scan_files: [...apiFiles, file("a-latest", "zz/package.json", null, "h1"), file("w-old", "package.json", '{"dependencies":{}}'), { ...file("other", "package.json", "theirs"), org_id: "org-2" }],
  }, { maxRows: 1000 });
  const res = await GET(new NextRequest(new URL("/api/dependencies", "https://app.example")));
  expect(res.status).toBe(200);
  const byRepo = Object.fromEntries(seen.map(s => [s.repo, s]));
  expect(Object.keys(byRepo).sort()).toEqual(["o/api", "o/web"]);
  expect(byRepo["o/api"].scan_id).toBe("a-latest");
  expect(byRepo["o/api"].files).toHaveLength(1401);
  expect(byRepo["o/api"].files.find(f => f.file_path === "zz/package.json")!.content).toBe("content of h1");   // backfilled by hash
  expect(byRepo["o/web"].files.map(f => f.file_path)).toEqual(["package.json"]);
});
