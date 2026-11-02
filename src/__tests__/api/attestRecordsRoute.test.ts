/**
 * @jest-environment node
 *
 * GET /api/attest: the period's sign-off records for the org, enriched; repo and developer scoping; paging.
 */
import { NextRequest } from "next/server";
import { fakeSupabase } from "../helpers/fakeSupabase";

let db: ReturnType<typeof fakeSupabase>;
let auth: Record<string, unknown> = { org_id: "org-1", role: "admin", user_id: "u1" };
jest.mock("@/lib/supabase", () => ({ createServiceClient: () => db.client }));
jest.mock("@/app/api/_middleware", () => ({ verifyApiKey: async () => auth, permissionsFor: async () => ({}) }));
jest.mock("@/lib/rateLimit", () => ({ checkRateLimit: async () => ({ success: true }), RATE_LIMITS: { attest: {} } }));

import { GET } from "@/app/api/attest/route";

const get = async (q: string) => {
  const res = await GET(new NextRequest(new URL(`/api/attest?${q}`, "https://app.example")));
  return { status: res.status, body: await res.json() as Record<string, any> };   // eslint-disable-line @typescript-eslint/no-explicit-any
};
const att = (id: string, scan: string, at: string, org = "org-1") =>
  ({ id, org_id: org, scan_id: scan, file_path: `${id}.ts`, risk_score: "HIGH", reviewer_email: "rev@x", reviewer_github: "rev", payload_hash: "h", created_at: at });

function seed(attestations: Record<string, unknown>[], opts: Parameters<typeof fakeSupabase>[1] = {}) {
  db = fakeSupabase({
    org_members: [{ org_id: "org-1", user_id: "u-dev", github_login: "dev1" }],
    scans: [
      { id: "s1", org_id: "org-1", repo_full_name: "o/api", pr_number: 7, commit_sha: "c1", branch: "b", pr_author: "dev1", created_at: "2026-09-30T00:00:00Z" },
      { id: "s2", org_id: "org-1", repo_full_name: "o/web", pr_number: 8, commit_sha: "c2", branch: "b", pr_author: "dev2", created_at: "2026-09-30T00:00:00Z" },
    ],
    scan_files: [{ org_id: "org-1", scan_id: "s1", file_path: "a1.ts", risk_score: "HIGH", risk_indicators: ["sql-injection"], ai_percentage: 0.5 }],
    attestations,
  }, opts);
}

beforeEach(() => {
  auth = { org_id: "org-1", role: "admin", user_id: "u1" };
  seed([att("a1", "s1", "2026-10-01T10:00:00Z"), att("a2", "s2", "2026-10-31T23:00:00Z"), att("a0", "s1", "2026-09-30T23:59:59Z"), att("x", "s1", "2026-10-02T00:00:00Z", "org-2")]);
});

describe("GET /api/attest", () => {
  it("records signed within the period's UTC days, for this org, explained", async () => {
    const { status, body } = await get("since=2026-10-01&until=2026-10-31");
    expect(status).toBe(200);
    expect(body.records.map((r: { id: string }) => r.id)).toEqual(["a2", "a1"]);
    expect(body.records[1]).toMatchObject({ repo: "o/api", pr_number: 7, findings: ["sql-injection"], hours_to_signoff: 34 });
    expect(body.period).toEqual({ start: "2026-10-01T00:00:00.000Z", end: "2026-10-31T23:59:59.999Z" });
    expect(body.summary.repos).toEqual(["o/api", "o/web"]);
  });

  it("one repository, or a developer's own pull requests", async () => {
    expect((await get("since=2026-10-01&until=2026-10-31&repo=o/web")).body.records.map((r: { id: string }) => r.id)).toEqual(["a2"]);
    auth = { org_id: "org-1", role: "developer", user_id: "u-dev" };
    const own = (await get("since=2026-10-01&until=2026-10-31")).body;
    expect(own.scope).toBe("own");
    expect(own.records.map((r: { id: string }) => r.id)).toEqual(["a1"]);
    auth = { org_id: "org-1", role: "developer", user_id: "u-nobody" };
    expect((await get("since=2026-10-01&until=2026-10-31")).body.records).toEqual([]);
  });

  it("a bad period is refused", async () => {
    expect((await get("since=yesterday&until=2026-10-31")).status).toBe(400);
    expect((await get("until=2026-10-31")).status).toBe(400);
  });

  it("each signed-off file is described from its own scan file, however many there are (paths read in chunks)", async () => {
    const many = Array.from({ length: 120 }, (_, i) => att(`m${i}`, "s1", "2026-10-05T00:00:00Z"));
    seed(many);
    const files = (db.client.from("scan_files") as unknown as { rows: Record<string, unknown>[] }).rows;
    files.length = 0;
    for (let i = 0; i < 120; i++) files.push({ org_id: "org-1", scan_id: "s1", file_path: `m${i}.ts`, risk_score: i === 7 ? "LOW" : "HIGH", risk_indicators: [`rule-${i}`], ai_percentage: 0.1 });
    // files nobody signed off are not needed
    for (let i = 0; i < 300; i++) files.push({ org_id: "org-1", scan_id: "s1", file_path: `other${i}.ts`, risk_score: "MEDIUM", risk_indicators: ["x"], ai_percentage: 0 });
    const { body } = await get("since=2026-10-01&until=2026-10-31");
    expect(body.records).toHaveLength(120);
    const byId = Object.fromEntries(body.records.map((r: { id: string; findings: string[] }) => [r.id, r.findings]));
    expect(byId.m0).toEqual(["rule-0"]);
    expect(byId.m119).toEqual(["rule-119"]);
    expect(byId.m7).toEqual(["rule-7"]);   // a LOW file someone signed off is described too
  });

  it("reads past the 1000-row cap", async () => {
    seed(Array.from({ length: 1500 }, (_, i) => att(`b${i}`, "s1", "2026-10-05T00:00:00Z")), { maxRows: 1000 });
    expect((await get("since=2026-10-01&until=2026-10-31")).body.summary.records).toBe(1500);
  });
});
