/**
 * @jest-environment node
 *
 * GET /api/orgs: every organisation comes back with the numbers the Organisations page reads (scan activity and its
 * trend, open / critical / overdue violations, people, repositories, the latest scan). A regular user gets their own
 * organisation WITH those numbers; a platform admin gets every organisation, each measured on its own data.
 */
import { NextRequest } from "next/server";
import { fakeSupabase } from "../helpers/fakeSupabase";

let db: ReturnType<typeof fakeSupabase>;
let role = "admin";
jest.mock("@/lib/supabase", () => ({ createServiceClient: () => db.client }));
jest.mock("@/app/api/_middleware", () => ({
  ...jest.requireActual("@/app/api/_middleware"),
  verifyApiKey: async () => ({ org_id: "org-a", user_id: "u1", role }),
}));

import { GET } from "@/app/api/orgs/route";

const NOW = Date.now();
const ago = (days: number) => new Date(NOW - days * 86_400_000).toISOString();
const ahead = (days: number) => new Date(NOW + days * 86_400_000).toISOString();
const orgRow = (id: string, name: string, over = {}) => ({ id, slug: id, name, github_org: null, plan: "growth", created_at: ago(100), ...over });
const scan = (org_id: string, days: number, risk = "LOW", ai = 0.2) => ({ id: `${org_id}-${days}-${Math.random()}`, org_id, created_at: ago(days), overall_risk: risk, total_ai_percentage: ai });
const vio = (org_id: string, status: string, risk: string, sla: string | null = null) => ({ id: Math.random().toString(), org_id, status, risk_score: risk, sla_deadline: sla });

beforeEach(() => {
  role = "admin";
  db = fakeSupabase({
    organizations: [orgRow("org-a", "Acme"), orgRow("org-b", "Beta", { created_at: ago(5), plan: "starter" })],
    org_members: [{ org_id: "org-a", user_id: "u1", role: "admin" }, { org_id: "org-a", user_id: "u2", role: "developer" }, { org_id: "org-b", user_id: "u9", role: "admin" }],
    repositories: [{ org_id: "org-a", is_active: true }, { org_id: "org-a", is_active: true }, { org_id: "org-a", is_active: false }, { org_id: "org-b", is_active: true }],
    scans: [
      scan("org-a", 1, "HIGH", 0.5), scan("org-a", 3), scan("org-a", 10),          // 3 in the last 30 days
      scan("org-a", 40), scan("org-a", 45),                                        // 2 in the 30 before
      scan("org-b", 2, "CRITICAL", 0.9),
    ],
    violations: [
      vio("org-a", "open", "CRITICAL", ago(2)),        // critical, overdue
      vio("org-a", "in_review", "HIGH", ahead(3)),     // open, not overdue
      vio("org-a", "open", "CRITICAL", ahead(1)),      // critical, not overdue
      vio("org-a", "resolved", "CRITICAL", ago(9)),    // resolved: counts for nothing
      vio("org-b", "open", "HIGH", null),
    ],
  });
});

const get = async () => (await GET(new NextRequest(new URL("/api/orgs", "https://app.example")))).json() as Promise<{
  orgs: Array<Record<string, unknown>>; total: number; current_org_id: string;
}>;

describe("a regular user", () => {
  it("sees only their own organisation, marked as current, with its numbers", async () => {
    const { orgs, total, current_org_id } = await get();
    expect(total).toBe(1);
    expect(current_org_id).toBe("org-a");
    expect(orgs).toHaveLength(1);
    expect(orgs[0]).toMatchObject({
      id: "org-a", name: "Acme", plan: "growth", is_current: true,
      scans_30d: 3, scans_prev_30d: 2, scans_this_month: expect.any(Number),
      open_violations: 3, open_critical: 2, overdue: 1,
      member_count: 2, repo_count: 2,
      latest_risk: "HIGH", latest_ai_pct: 0.5,
    });
    expect(orgs[0].last_scan).toBe(ago(1));
  });

  it("a resolved violation is not counted as open, critical or overdue", async () => {
    const { orgs } = await get();
    expect(orgs[0].open_violations).toBe(3);        // not 4
    expect(orgs[0].open_critical).toBe(2);          // not 3
    expect(orgs[0].overdue).toBe(1);                // the resolved one's past deadline is ignored
  });

  it("an organisation that has never scanned reads as UNKNOWN with no last scan", async () => {
    db = fakeSupabase({ organizations: [orgRow("org-a", "Acme")], org_members: [{ org_id: "org-a", user_id: "u1", role: "admin" }], repositories: [], scans: [], violations: [] });
    const { orgs } = await get();
    expect(orgs[0]).toMatchObject({ latest_risk: "UNKNOWN", last_scan: null, latest_ai_pct: 0, scans_30d: 0, repo_count: 0, open_violations: 0 });
  });
});

describe("a platform admin", () => {
  beforeEach(() => {
    (db.client.from("org_members") as unknown as { rows: Array<Record<string, unknown>> }).rows.find(r => r.user_id === "u1")!.role = "platform_admin";
  });

  it("sees every organisation, each measured on its own data, newest first", async () => {
    const { orgs, total } = await get();
    expect(total).toBe(2);
    expect(orgs.map(o => o.id)).toEqual(["org-b", "org-a"]);                       // newest created first
    const b = orgs[0];
    expect(b).toMatchObject({ name: "Beta", plan: "starter", is_current: false, scans_30d: 1, open_violations: 1, open_critical: 0, overdue: 0, member_count: 1, repo_count: 1, latest_risk: "CRITICAL" });
    expect(orgs[1]).toMatchObject({ name: "Acme", is_current: true, scans_30d: 3, open_critical: 2 });
  });

  it("one organisation's data never leaks into another's numbers", async () => {
    const { orgs } = await get();
    const sum = (k: string) => orgs.reduce((n, o) => n + (o[k] as number), 0);
    expect(sum("scans_30d")).toBe(4);
    expect(sum("open_violations")).toBe(4);
    expect(sum("member_count")).toBe(3);
  });
});
