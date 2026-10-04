/**
 * @jest-environment node
 *
 * Dashboard numbers (lib/dashboardAggregate.ts), computed against an in-memory database.
 */
import { fakeSupabase } from "../helpers/fakeSupabase";

let db: ReturnType<typeof fakeSupabase>;
jest.mock("@/lib/supabase", () => ({ createServiceClient: () => db.client }));

import { fetchDashboard } from "@/lib/dashboardAggregate";

const ORG = "org-1";
const daysAgo = (n: number) => new Date(Date.now() - n * 86400_000).toISOString();
const scan = (id: string, repo: string, ageDays: number, ai: number, files: number) =>
  ({ id, org_id: ORG, repo_full_name: repo, overall_risk: "HIGH", total_ai_percentage: ai, file_count: files, created_at: daysAgo(ageDays), pr_author: "dev" });
const riskFile = (scanId: string, repo: string, path: string, risk = "HIGH", ai = 0.5) =>
  ({ org_id: ORG, scan_id: scanId, file_path: path, ai_percentage: ai, risk_score: risk, risk_indicators: [], created_at: daysAgo(1), scans: { repo_full_name: repo, pr_number: 7 } });

function seed(over: Record<string, Record<string, unknown>[]> = {}, opts: Parameters<typeof fakeSupabase>[1] = {}) {
  db = fakeSupabase({
    repositories: [
      { org_id: ORG, repo_full_name: "o/api", is_active: true },
      { org_id: ORG, repo_full_name: "o/web", is_active: true },
      { org_id: ORG, repo_full_name: "o/docs", is_active: true },      // connected, never scanned in the period
      { org_id: ORG, repo_full_name: "o/old", is_active: false },
    ],
    scans: [
      scan("a1", "o/api", 20, 0.9, 2),     // older scan of api
      scan("a2", "o/api", 2, 0.8, 2),      // latest api scan: 2 files
      scan("w1", "o/web", 3, 0.1, 198),    // web: 198 files, little AI
      scan("x1", "o/old", 1, 1, 50),       // switched-off repo — ignored
    ],
    scan_files: [
      riskFile("a2", "o/api", "src/pay.ts", "CRITICAL", 0.9),
      riskFile("a2", "o/api", "src/auth.ts", "HIGH", 0.8),
      riskFile("a2", "o/api", "src/db.ts", "HIGH", 0.4),
      riskFile("a2", "o/api", "src/util.ts", "HIGH", 0.2),
      // web's latest scan has no HIGH/CRITICAL files
    ],
    attestations: [
      { scan_id: "a2", file_path: "src/pay.ts", risk_score: "CRITICAL", reviewer_email: "r1@x", created_at: daysAgo(1) },
      { scan_id: "a2", file_path: "src/pay.ts", risk_score: "CRITICAL", reviewer_email: "r2@x", created_at: daysAgo(1) }, // second reviewer
    ],
    violations: [
      { id: "v1", scan_id: "a2", file_path: "src/auth.ts", risk_score: "HIGH", status: "open", sla_deadline: daysAgo(1) },
      { id: "v2", scan_id: "a2", file_path: "src/db.ts", risk_score: "HIGH", status: "open", sla_deadline: daysAgo(-2) },
    ],
    ...over,
  }, opts);
}

describe("attestation rate", () => {
  it("is attested files ÷ HIGH/CRITICAL files — a second reviewer doesn't count a file twice", async () => {
    seed();
    const d = await fetchDashboard(ORG, 90, null);
    expect(d.total_high_crit).toBe(4);
    expect(d.attested_high_crit).toBe(1);
    expect(d.attestation_rate).toBeCloseTo(0.25);
    expect(d.repos.find(r => r.repo === "o/api")!.attestation_rate).toBeCloseTo(0.25);
  });

  it("a repo with nothing to review doesn't pull the org figure up to 100%", async () => {
    seed();
    const d = await fetchDashboard(ORG, 90, null);
    expect(d.repos.find(r => r.repo === "o/web")!.attestation_rate).toBe(1);   // nothing to review
    expect(d.attestation_rate).toBeCloseTo(0.25);                              // not (0.25 + 1) / 2
  });
});

it("AI share is per file: each scan weighted by the files it analysed", async () => {
  seed();
  const d = await fetchDashboard(ORG, 90, null);
  // (0.9×2 + 0.8×2 + 0.1×198) / 202 — not the plain mean of 0.9, 0.8, 0.1
  expect(d.overall_ai_pct).toBeCloseTo((0.9 * 2 + 0.8 * 2 + 0.1 * 198) / 202, 6);
  expect(d.scan_count).toBe(3);
  expect(d.file_count).toBe(202);
});

it("reports every connected repo, scanned in the period or not (for coverage)", async () => {
  seed();
  const d = await fetchDashboard(ORG, 90, null);
  expect(d.connected_repo_count).toBe(3);
  expect(d.repos.map(r => r.repo).sort()).toEqual(["o/api", "o/web"]);
});

it("a custom date range is honoured", async () => {
  seed();
  const start = daysAgo(10).slice(0, 10), end = daysAgo(0).slice(0, 10);
  const d = await fetchDashboard(ORG, 11, null, { start, end });
  expect(d.scan_count).toBe(2);                // a1 (20 days ago) is outside the range
  expect(d.period).toEqual({ start, end });
  const older = await fetchDashboard(ORG, 3, null, { start: daysAgo(25).slice(0, 10), end: daysAgo(15).slice(0, 10) });
  expect(older.scan_count).toBe(1);            // only a1
});

it("open violations on the latest scan drive the unattested and SLA counts", async () => {
  seed();
  const d = await fetchDashboard(ORG, 90, null);
  expect(d.unattested_deploy_count).toBe(2);
  expect(d.sla_breach_high_count).toBe(1);
  expect(d.sla_breach_files!.map(f => f.file_path)).toEqual(["src/auth.ts"]);
});

it("reads past the 1000-row cap instead of silently truncating", async () => {
  const scans = [scan("latest", "o/api", 0.1, 0.5, 1), ...Array.from({ length: 2299 }, (_, i) => scan(`s${i}`, "o/api", (i % 80) + 1, 0.5, 1))];
  const files = Array.from({ length: 1500 }, (_, i) => riskFile("latest", "o/api", `f${i}.ts`, "HIGH", i / 1500));
  seed({ scans, scan_files: files, attestations: [], violations: [] }, { maxRows: 1000 });
  const d = await fetchDashboard(ORG, 90, null);
  expect(d.scan_count).toBe(2300);
  expect(d.file_count).toBe(2300);
  expect(d.total_high_crit).toBe(1500);
  expect(d.top_risk_files).toHaveLength(1500);
});
