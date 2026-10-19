/**
 * @jest-environment node
 *
 * GET /api/analytics: scoped to the caller's org (developers: their own PRs), pages past the 1000-row cap, and is
 * never cached at the edge.
 */
import { NextRequest } from "next/server";
import { fakeSupabase } from "../helpers/fakeSupabase";

let db: ReturnType<typeof fakeSupabase>;
let auth: { org_id: string; role: string; user_id?: string } = { org_id: "org-1", role: "admin", user_id: "u1" };
jest.mock("@/lib/supabase", () => ({ createServiceClient: () => db.client }));
jest.mock("@/app/api/_middleware", () => ({ verifyApiKey: async () => auth }));

import { GET } from "@/app/api/analytics/route";

const ago = (h: number) => new Date(Date.now() - h * 3600_000).toISOString();
const scan = (id: string, org: string, author: string, hoursAgo: number) =>
  ({ id, org_id: org, repo_full_name: `${org}/api`, pr_number: 1, pr_author: author, created_at: ago(hoursAgo), total_ai_percentage: 0.5, file_count: 2 });

function seed(extraScans: Record<string, unknown>[] = []) {
  db = fakeSupabase({
    scans: [scan("s1", "org-1", "alice", 50), scan("s2", "org-1", "bob", 30), scan("x1", "org-2", "eve", 10), ...extraScans],
    violations: [
      { id: "v1", org_id: "org-1", scan_id: "s1", file_path: "a.ts", risk_score: "CRITICAL", status: "open", created_at: ago(50), resolved_at: null, sla_deadline: ago(26) },
      { id: "v2", org_id: "org-1", scan_id: "s2", file_path: "b.ts", risk_score: "HIGH", status: "resolved", created_at: ago(30), resolved_at: ago(5), sla_deadline: ago(-10) },
      { id: "vx", org_id: "org-2", scan_id: "x1", file_path: "z.ts", risk_score: "CRITICAL", status: "open", created_at: ago(10), resolved_at: null, sla_deadline: null },
    ],
    attestations: [
      { org_id: "org-1", scan_id: "s2", file_path: "b.ts", risk_score: "HIGH", reviewer_email: "carol@a.test", reviewer_github: "carol", created_at: ago(5) },
      { org_id: "org-2", scan_id: "x1", file_path: "z.ts", risk_score: "CRITICAL", reviewer_email: "mallory@b.test", reviewer_github: "m", created_at: ago(1) },
    ],
    org_members: [{ org_id: "org-1", user_id: "u-dev", github_login: "alice" }],
  }, { maxRows: 1000 });
}

const get = async (q = "days=7") => {
  const res = await GET(new NextRequest(new URL(`/api/analytics?${q}`, "https://app.example")));
  return { res, body: await res.json() };
};

beforeEach(() => { auth = { org_id: "org-1", role: "admin", user_id: "u1" }; seed(); });

describe("GET /api/analytics", () => {
  it("only the caller's org; never cached at the edge", async () => {
    const { res, body } = await get();
    expect(res.headers.get("cache-control")).toBe("private, no-store");
    expect(body.scope).toBe("org");
    expect(body.totals).toMatchObject({ scans: 2, opened: 2, closed: 1, signoffs: 1 });
    expect(body.reviewers.map((r: { reviewer: string }) => r.reviewer)).toEqual(["carol@a.test"]);
    expect(body.repos.map((r: { repo: string }) => r.repo)).toEqual(["org-1/api"]);
    expect(body.backlog).toMatchObject({ open: 1, overdue: 1 });
    expect(body.review_time.find((r: { severity: string }) => r.severity === "HIGH")).toMatchObject({ count: 1, median_hours: 25, on_time: 1 });
  });

  it("developers see only their own pull requests", async () => {
    auth = { org_id: "org-1", role: "developer", user_id: "u-dev" };
    const { body } = await get();
    expect(body.scope).toBe("own");
    expect(body.totals).toMatchObject({ scans: 1, opened: 1, signoffs: 0 });   // alice's s1 only; bob's s2 and its sign-off excluded
    expect(body.backlog.open).toBe(1);
  });

  it("a developer without a linked GitHub account gets an empty view, not the org's", async () => {
    auth = { org_id: "org-1", role: "developer", user_id: "u-unlinked" };
    const { body } = await get();
    expect(body).toMatchObject({ scope: "own", totals: { scans: 0, opened: 0 } });
  });

  it("pages past the 1000-row cap", async () => {
    seed(Array.from({ length: 2400 }, (_, i) => scan(`bulk-${i}`, "org-1", "bob", 1 + (i % 100))));
    const { body } = await get();
    expect(body.totals.scans).toBe(2402);
  });

  it("only 7, 30 or 90 days", async () => {
    expect((await get("days=7")).body.period.days).toBe(7);
    expect((await get("days=90")).body.period.days).toBe(90);
    expect((await get("days=9999")).body.period.days).toBe(30);
  });
});
