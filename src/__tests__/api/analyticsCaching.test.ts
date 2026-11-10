/**
 * @jest-environment node
 *
 * GET /api/analytics read every violation, attestation and scan of the period (about 2 MB for a busy org) on every
 * call, and its page asks again every few minutes: most of the project's database egress while a tab sat open. The
 * computed result is now reused until the org's data changes, per org, period and scope.
 */
import { NextRequest } from "next/server";
import { fakeSupabase } from "../helpers/fakeSupabase";

let db = fakeSupabase({});
let auth: { org_id: string; role: string; user_id?: string } = { org_id: "org-1", role: "admin", user_id: "u1" };
const reads: Record<string, number> = {};
jest.mock("@/lib/supabase", () => ({
  createServiceClient: () => ({ ...db.client, from: (t: string) => { reads[t] = (reads[t] ?? 0) + 1; return db.client.from(t); } }),
}));
jest.mock("@/app/api/_middleware", () => ({ verifyApiKey: async () => auth }));
const mem = new Map<string, string>();
jest.mock("@/lib/cache", () => {
  const actual = jest.requireActual("@/lib/cache");
  return {
    ...actual,
    cached: async (k: string, _t: number, fn: () => Promise<unknown>) => {
      if (mem.has(k)) return JSON.parse(mem.get(k) as string);
      const r = await fn(); mem.set(k, JSON.stringify(r)); return r;
    },
  };
});

import { GET } from "@/app/api/analytics/route";

const ago = (h: number) => new Date(Date.now() - h * 3600_000).toISOString();
const att = (file: string, h: number) => ({ org_id: "org-1", scan_id: "s1", file_path: file, risk_score: "HIGH", reviewer_email: "c@a.test", reviewer_github: "c", created_at: ago(h) });
const get = async (q = "days=7") => (await (await GET(new NextRequest(new URL(`/api/analytics?${q}`, "https://app.example")))).json()) as { totals: { signoffs: number }; scope: string };

beforeEach(() => {
  mem.clear(); auth = { org_id: "org-1", role: "admin", user_id: "u1" };
  for (const k of Object.keys(reads)) delete reads[k];
  db = fakeSupabase({
    repositories: [{ org_id: "org-1", repo_full_name: "org-1/api", is_active: true }],
    scans: [{ id: "s1", org_id: "org-1", repo_full_name: "org-1/api", pr_number: 1, pr_author: "alice", created_at: ago(50), total_ai_percentage: 0.5, file_count: 2 }],
    violations: [{ id: "v1", org_id: "org-1", scan_id: "s1", file_path: "a.ts", risk_score: "HIGH", status: "open", created_at: ago(50), resolved_at: null, sla_deadline: null }],
    attestations: [att("a.ts", 5)],
    org_members: [{ org_id: "org-1", user_id: "u-dev", github_login: "alice" }],
    violation_overrides: [], audit_log: [],
  }, { maxRows: 1000 });
});

describe("GET /api/analytics result cache", () => {
  it("a second call reads no violations and only the one-row version probe of attestations", async () => {
    const first = await get();
    const v = reads["violations"], a = reads["attestations"];
    expect(v).toBeGreaterThan(0);
    const second = await get();
    expect(second).toEqual(first);
    expect(reads["violations"]).toBe(v);
    // the data version looks at the newest attestation (one row); the period's attestations are not read again
    expect(reads["attestations"]).toBe(a + 1);
  });

  it("a new sign-off shows at once (the data version is in the key)", async () => {
    expect((await get()).totals.signoffs).toBe(1);
    await (db.client.from("attestations") as unknown as { insert: (r: unknown) => PromiseLike<unknown> }).insert(att("b.ts", 0.01));
    expect((await get()).totals.signoffs).toBe(2);
  });

  it("each period and each scope has its own entry", async () => {
    await get("days=7");
    const after7 = reads["violations"];
    await get("days=30");
    expect(reads["violations"]).toBeGreaterThan(after7);
    auth = { org_id: "org-1", role: "developer", user_id: "u-dev" };
    expect((await get("days=7")).scope).toBe("own");
    auth = { org_id: "org-1", role: "admin", user_id: "u1" };
    expect((await get("days=7")).scope).toBe("org");
  });
});
