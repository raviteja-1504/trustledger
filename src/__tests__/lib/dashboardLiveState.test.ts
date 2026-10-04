/**
 * @jest-environment node
 *
 * Dashboard: applying review state learned after load, and the API's date-range handling.
 */
import type { DashboardData } from "@/types";
import { applyLiveReviewState } from "@/lib/dashboardLiveState";

const file = (repo: string, path: string, risk: string, attested = false, scan = `${repo}-scan`) =>
  ({ repo, file_path: path, ai_pct: 0.5, risk_score: risk, pr_number: 1, attested, scan_id: scan });

function data(): DashboardData {
  return {
    repos: [
      { repo: "o/api", ai_pct: 0.5, attestation_rate: 0.9, last_scan: "2026-10-01", scan_count: 1, file_count: 4 }, // server figure too high
      { repo: "o/web", ai_pct: 0.2, attestation_rate: 1, last_scan: "2026-10-01", scan_count: 1, file_count: 9 },
    ],
    overall_ai_pct: 0.4, attestation_rate: 0.95, unattested_deploy_count: 7, scan_count: 2, file_count: 13, risk_trend: [],
    top_risk_files: [
      file("o/api", "a.ts", "CRITICAL", true),
      file("o/api", "b.ts", "HIGH"),
      file("o/api", "c.ts", "HIGH"),
      file("o/api", "d.ts", "HIGH"),
    ],
  } as unknown as DashboardData;
}

describe("applyLiveReviewState", () => {
  it("computes attestation from the files — never just keeps the higher server figure", () => {
    const { effectiveData } = applyLiveReviewState(data(), {});
    expect(effectiveData!.attestation_rate).toBeCloseTo(0.25);          // 1 of 4, not max(0.95, 0.25)
    expect(effectiveData!.repos.find(r => r.repo === "o/api")!.attestation_rate).toBeCloseTo(0.25);
    expect(effectiveData!.repos.find(r => r.repo === "o/web")!.attestation_rate).toBe(1);   // nothing to review
    expect(effectiveData).toMatchObject({ attested_high_crit: 1, total_high_crit: 4 });
  });

  it("a resolved violation counts as signed off; one in review does not (but leaves the waiting list)", () => {
    const { effectiveData, unresolvedRepoScans } = applyLiveReviewState(data(), {
      "high::o/api-scan::b.ts": "resolved",
      "high::o/api-scan::c.ts": "in_review",
    });
    expect(effectiveData!.attestation_rate).toBeCloseTo(0.5);           // a.ts + b.ts of 4
    expect(unresolvedRepoScans.map(r => r.repo)).toEqual(["o/api"]);     // d.ts still waiting
    expect(effectiveData!.unattested_deploy_count).toBe(1);             // repos awaiting sign-off
  });

  it("once every HIGH/CRITICAL file is handled, nothing awaits sign-off", () => {
    const { effectiveData, unresolvedRepoScans } = applyLiveReviewState(data(), {
      "high::o/api-scan::b.ts": "resolved", "high::o/api-scan::c.ts": "resolved", "high::o/api-scan::d.ts": "in_review",
    });
    expect(unresolvedRepoScans).toEqual([]);
    expect(effectiveData!.unattested_deploy_count).toBe(0);
  });

  it("handles no data", () => {
    expect(applyLiveReviewState(null, {})).toEqual({ effectiveData: null, firstUnresolvedScanId: null, unresolvedRepoScans: [] });
  });
});

describe("GET /api/dashboard date range", () => {
  const fetchDashboard = jest.fn(async () => ({ repos: [] }));
  beforeAll(() => {
    jest.doMock("@/lib/dashboardAggregate", () => ({ fetchDashboard: (...a: unknown[]) => fetchDashboard(...(a as [])) }));
    jest.doMock("@/app/api/_middleware", () => ({ verifyApiKey: async () => ({ org_id: "org-1", role: "admin" }) }));
    jest.doMock("@/lib/cache", () => ({ cached: async (_k: string, _t: number, fn: () => unknown) => fn(), cacheDel: jest.fn(), cacheKeys: { dashboard: (o: string, d: number) => `dash:${o}:${d}` }, TTL: { DASHBOARD: 300 } }));
    jest.doMock("@/lib/supabase", () => ({ createServiceClient: () => ({}) }));
  });
  const get = async (q: string) => {
    const { NextRequest } = await import("next/server");
    const { GET } = await import("@/app/api/dashboard/route");
    return GET(new NextRequest(new URL(`/api/dashboard?${q}`, "https://app.example")));
  };

  it("passes a custom range through (it used to be ignored, showing 90 days)", async () => {
    fetchDashboard.mockClear();
    expect((await get("org=x&start_date=2026-09-01&end_date=2026-09-10")).status).toBe(200);
    expect(fetchDashboard).toHaveBeenCalledWith("org-1", 10, null, { start: "2026-09-01", end: "2026-09-10" });
  });

  it("the preset windows still work", async () => {
    fetchDashboard.mockClear();
    await get("org=x&days=30");
    expect(fetchDashboard).toHaveBeenCalledWith("org-1", 30, null);
  });

  it("rejects a malformed or backwards range", async () => {
    for (const q of ["start_date=2026-09-10", "start_date=2026-09-10&end_date=2026-09-01", "start_date=bad&end_date=2026-09-01"]) {
      expect((await get(q)).status).toBe(400);
    }
  });
});
