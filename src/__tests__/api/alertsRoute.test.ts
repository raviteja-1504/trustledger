/**
 * @jest-environment node
 *
 * GET /api/alerts: a PR's policy alert reports live progress instead of the count frozen at scan time, and closes
 * itself once its scan is clear or a newer push of the PR replaced it.
 */
import { NextRequest } from "next/server";
import { fakeSupabase } from "../helpers/fakeSupabase";

let db: ReturnType<typeof fakeSupabase>;
jest.mock("@/lib/supabase", () => ({ createServiceClient: () => db.client }));
jest.mock("@/app/api/_middleware", () => ({
  ...jest.requireActual("@/app/api/_middleware"),
  verifyApiKey: async () => ({ org_id: "org-1", user_id: "u1", role: "admin" }),
}));
// the repo-wide check: something is still open in the repo, so only the per-PR rules decide
jest.mock("@/lib/repoViolations", () => ({ hasOpenRepoViolations: async () => true }));

import { GET } from "@/app/api/alerts/route";

const ORG = "org-1";
const alert = (id: string, scan_id: string) => ({ id, org_id: ORG, alert_type: "policy", severity: "P1", status: "firing", repo: "acme/sast",
  scan_id, title: "6 unattested files in sast PR #12", body: "", fired_at: "2026-10-02T00:00:00Z" });
const vio = (scan_id: string, file_path: string, status: string) => ({ id: `${scan_id}-${file_path}`, org_id: ORG, scan_id, file_path, risk_score: "HIGH", status });
const rows = (t: string) => (db.client.from(t) as unknown as { rows: Record<string, unknown>[] }).rows;

beforeEach(() => {
  db = fakeSupabase({
    scans: [
      { id: "s1", org_id: ORG, repo_full_name: "acme/sast", pr_number: 12, created_at: "2026-10-01T00:00:00Z" },
      { id: "s2", org_id: ORG, repo_full_name: "acme/sast", pr_number: 12, created_at: "2026-10-02T00:00:00Z" },
      { id: "s3", org_id: ORG, repo_full_name: "acme/sast", pr_number: 13, created_at: "2026-10-02T00:00:00Z" },
    ],
    alerts: [alert("a1", "s1"), alert("a2", "s2"), alert("a3", "s3")],
    violations: [
      vio("s1", "x.ts", "open"),
      ...["a", "b", "c", "d", "e"].map(f => vio("s2", `${f}.ts`, "resolved")), vio("s2", "f.ts", "open"),
      vio("s3", "y.ts", "resolved"),
    ],
  });
});

it("live progress in the title; done when the scan is clear or a newer push replaced it", async () => {
  const res = await GET(new NextRequest(new URL("/api/alerts?limit=200", "https://app.example")));
  const { alerts } = await res.json() as { alerts: Array<{ id: string; title: string; status: string; progress?: { open: number; total: number } }> };
  const byId = Object.fromEntries(alerts.map(a => [a.id, a]));
  // PR #12's latest push: 5 of 6 signed off
  expect(byId.a2).toMatchObject({ status: "firing", title: "1 of 6 files still needs sign-off in sast PR #12", progress: { open: 1, total: 6 } });
  // PR #12's older push: replaced by s2
  expect(byId.a1.status).toBe("resolved");
  // PR #13: everything signed off
  expect(byId.a3).toMatchObject({ status: "resolved", progress: { open: 0, total: 1 } });
  // and the closures are stored, not just shown
  expect(rows("alerts").filter(a => a.status === "resolved").map(a => a.id).sort()).toEqual(["a1", "a3"]);
});
