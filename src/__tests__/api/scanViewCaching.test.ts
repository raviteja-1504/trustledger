/**
 * @jest-environment node
 *
 * Viewing a PR re-read the whole scan from the database every time: every file's source, and the findings of up to
 * six earlier scans for the lifecycle. That was most of the project's database egress. The scan and its history are
 * immutable, so a second view of the same scan must not read scan_files again (only the attestations and triage,
 * which do change, are read fresh).
 */
import { NextRequest } from "next/server";
import { fakeSupabase } from "../helpers/fakeSupabase";

let db = fakeSupabase({});
const reads: Record<string, number> = {};
jest.mock("@/lib/supabase", () => ({
  createServiceClient: () => ({ ...db.client, from: (t: string) => { reads[t] = (reads[t] ?? 0) + 1; return db.client.from(t); } }),
}));
jest.mock("@/app/api/_middleware", () => ({ verifyApiKey: async () => ({ org_id: "org-1", user_id: "u-1", actor_email: "lead@acme.dev", role: "admin" }) }));
let engineLoads = 0;
jest.mock("@/lib/engineWarmup", () => ({ ensureTaintEngines: async () => { engineLoads++; } }));
// An in-memory stand-in for the cache (the real one is exercised in lib/cacheLargeValues.test.ts).
const mem = new Map<string, string>();
jest.mock("@/lib/cache", () => {
  const actual = jest.requireActual("@/lib/cache");
  return {
    ...actual,
    cacheGet: async (k: string) => (mem.has(k) ? JSON.parse(mem.get(k) as string) : null),
    cacheSet: async (k: string, v: unknown) => { mem.set(k, JSON.stringify(v)); },
    cached: async (k: string, _t: number, fn: () => Promise<unknown>) => {
      if (mem.has(k)) return JSON.parse(mem.get(k) as string);
      const r = await fn(); mem.set(k, JSON.stringify(r)); return r;
    },
  };
});

import { GET } from "@/app/api/scans/[id]/route";

const SCAN = "11111111-1111-4111-8111-111111111111";
const PREV = "22222222-2222-4222-8222-222222222222";
const sql = (i: number) => `const q = "SELECT * FROM t WHERE id = " + req.query.id${i};\ndb.query(q);\n`;
const row = (scan: string, i: number) => ({
  id: `${scan}-${i}`, scan_id: scan, org_id: "org-1", file_path: `src/f${i}.js`, language: "javascript", ai_percentage: 0,
  risk_score: "LOW", risk_indicators: [], content_hash: `h${i}`, line_count: 2, content: sql(i),
  indicators: [{ id: "sql-injection", label: "SQL Injection", severity: "critical", line: 1, fingerprint: `fp-${i}` }], attribution: null, created_at: "2026-10-24T09:00:00Z",
});
const scanRow = (id: string, sha: string, at: string) => ({ id, org_id: "org-1", repo_full_name: "acme/app", pr_number: 7, commit_sha: sha, branch: "main", overall_risk: "LOW", total_ai_percentage: 0, created_at: at });

const view = async () => {
  const res = await GET(new NextRequest(new URL(`/api/scans/${SCAN}`, "http://localhost")), { params: Promise.resolve({ id: SCAN }) });
  return res.json() as Promise<{ files: Array<{ file_path: string; content?: string; indicators: unknown[]; attested: boolean }>; lifecycle: { has_previous_scan: boolean; fixed: unknown[] } }>;
};

beforeEach(() => {
  mem.clear();
  engineLoads = 0;
  for (const k of Object.keys(reads)) delete reads[k];
  db = fakeSupabase({
    scans: [scanRow(SCAN, "b2", "2026-10-24T10:00:00Z"), scanRow(PREV, "a1", "2026-10-24T09:00:00Z")],
    scan_files: [...Array.from({ length: 25 }, (_, i) => row(SCAN, i)), ...Array.from({ length: 25 }, (_, i) => row(PREV, i + 1))],
    attestations: [], violations: [], finding_triage: [], secret_findings: [], repositories: [], organizations: [{ id: "org-1", name: "Acme" }],
  });
});

describe("viewing the same scan twice", () => {
  it("serves the files and the PR history from the cache the second time", async () => {
    const first = await view();
    expect(first.files).toHaveLength(25);
    expect(first.files[0].content).toContain("SELECT");
    expect(first.lifecycle.has_previous_scan).toBe(true);
    const readsAfterFirst = reads["scan_files"];
    expect(readsAfterFirst).toBeGreaterThan(0);

    const second = await view();
    expect(second.files).toHaveLength(25);
    expect(second.files[0].content).toContain("SELECT");
    // the lifecycle is the same, computed from the cached history
    expect(second.lifecycle.has_previous_scan).toBe(true);
    expect(second.lifecycle.fixed).toEqual(first.lifecycle.fixed);
    expect(reads["scan_files"]).toBe(readsAfterFirst);
    // the re-analysed findings are cached too, so the data-flow engines are loaded and run once, not per view
    expect(engineLoads).toBe(1);
  });

  it("still reads attestations fresh, so a sign-off shows at once", async () => {
    await view();
    const atts = db.client.from("attestations") as unknown as { insert: (r: unknown) => PromiseLike<unknown> };
    await atts.insert({ org_id: "org-1", scan_id: SCAN, file_path: "src/f0.js", risk_score: "LOW", reviewer_email: "lead@acme.dev", reviewer_github: "lead" });
    const second = await view();
    expect(second.files.find(f => f.file_path === "src/f0.js")?.attested).toBe(true);
  });

  it("reports the same fixed findings from the cached history as from the database", async () => {
    const first = await view();
    const second = await view();
    // the previous scan's findings (their fingerprints differ from the live re-analysed ones) are listed as fixed
    expect(first.lifecycle.fixed.length).toBeGreaterThan(0);
    expect(second.lifecycle.fixed).toEqual(first.lifecycle.fixed);
  });
});
