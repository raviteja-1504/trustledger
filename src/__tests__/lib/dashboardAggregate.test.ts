/**
 * @jest-environment node
 *
 * Dashboard numbers (lib/dashboardAggregate.ts), computed against an in-memory database.
 */
import { fakeSupabase } from "../helpers/fakeSupabase";

let db: ReturnType<typeof fakeSupabase>;
jest.mock("@/lib/supabase", () => ({ createServiceClient: () => db.client }));

import { fetchDashboard, fetchUnattestedRiskState } from "@/lib/dashboardAggregate";

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

it("a repo's AI share is weighted by files the same way, so repo and org figures agree", async () => {
  seed({ scans: [scan("a1", "o/api", 20, 0.9, 30), scan("a2", "o/api", 2, 0.1, 10), scan("w0", "o/web", 3, 0.5, 0)] });
  const d = await fetchDashboard(ORG, 90, null);
  expect(d.repos.find(r => r.repo === "o/api")!.ai_pct).toBeCloseTo((0.9 * 30 + 0.1 * 10) / 40, 6);   // 0.7, not the mean 0.5
  expect(d.repos.find(r => r.repo === "o/web")!.ai_pct).toBeCloseTo(0.5, 6);                           // no file counts: plain mean
  expect(d.overall_ai_pct).toBeCloseTo((0.9 * 30 + 0.1 * 10) / 40, 6);
});

it("each repo's latest scan: its full timestamp and its own AI share (Recent activity showed midnight and the average)", async () => {
  seed();
  const api = (await fetchDashboard(ORG, 90, null)).repos.find(r => r.repo === "o/api")!;
  const a2 = (db.client.from("scans") as unknown as { rows: Array<{ id: string; created_at: string }> }).rows.find(s => s.id === "a2")!;
  expect(api).toMatchObject({ latest_scan_id: "a2", last_scan: a2.created_at, latest_ai_pct: 0.8 });
  expect(api.ai_pct).toBeCloseTo(0.85, 6);   // the period average stays as it was
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

it("incident state reads past the 1000-row cap too: the real latest scan, and every risky file in it", async () => {
  // The latest scan is inserted LAST, behind 2299 older ones: an unpaged read stops at 1000 rows and misses it.
  const scans = [...Array.from({ length: 2299 }, (_, i) => scan(`s${i}`, "o/api", (i % 80) + 1, 0.5, 1)), scan("latest", "o/api", 0.1, 0.5, 1)];
  const files = Array.from({ length: 1500 }, (_, i) => riskFile("latest", "o/api", `f${i}.ts`, "HIGH"));
  seed({ scans, scan_files: files, attestations: [], violations: [] }, { maxRows: 1000 });
  const s = await fetchUnattestedRiskState(ORG);
  expect(new Set(s.top_risk_files.map(f => f.scan_id))).toEqual(new Set(["latest"]));
  expect(s.top_risk_files).toHaveLength(1500);
});

describe("the SLA page's list (sla_open_files) is the dashboard's own SLA set", () => {
  it("every deadline of the breach set's files, so its overdue count IS the breach count", async () => {
    seed({
      scans: [scan("a1", "o/api", 20, 0.9, 2), { ...scan("a2", "o/api", 2, 0.8, 2), pr_number: 42 }, scan("w1", "o/web", 3, 0.1, 198)],
      violations: [
        { id: "v1", scan_id: "a2", file_path: "src/auth.ts", risk_score: "HIGH", status: "open", sla_deadline: daysAgo(1), assigned_email: "dev@x" },
        { id: "v2", scan_id: "a2", file_path: "src/db.ts", risk_score: "HIGH", status: "in_review", sla_deadline: daysAgo(-2) },
        { id: "v3", scan_id: "a2", file_path: "src/pay.ts", risk_score: "CRITICAL", status: "open", sla_deadline: daysAgo(3) },     // signed off: out
        { id: "v4", scan_id: "a1", file_path: "src/auth.ts", risk_score: "HIGH", status: "open", sla_deadline: daysAgo(15) },     // older scan: out
        { id: "v5", scan_id: "a2", file_path: "src/util.ts", risk_score: "HIGH", status: "resolved", sla_deadline: daysAgo(1) },  // resolved: out
      ],
    });
    const d = await fetchDashboard(ORG, 90, null);
    expect(d.sla_open_files!.map(f => f.id).sort()).toEqual(["v1", "v2"]);
    const overdue = d.sla_open_files!.filter(f => Date.parse(f.sla_deadline) < Date.now());
    expect(overdue.length).toBe(d.sla_breach_critical_count + d.sla_breach_high_count);
    expect(d.sla_open_files!.find(f => f.id === "v1")).toMatchObject({ repo: "o/api", pr_number: 42, assigned_email: "dev@x", status: "open" });
  });

  it("reads past the 1000-row cap: 1500 overdue files are all listed and all counted", async () => {
    const violations = Array.from({ length: 1500 }, (_, i) => ({
      id: `v${String(i).padStart(4, "0")}`, scan_id: "a2", file_path: `src/f${i}.ts`, risk_score: "HIGH", status: "open", sla_deadline: daysAgo(1),
    }));
    seed({ attestations: [], violations }, { maxRows: 1000 });
    const d = await fetchDashboard(ORG, 90, null);
    expect(d.sla_open_files!.length).toBe(1500);
    expect(d.sla_breach_high_count).toBe(1500);
  });
});

describe("risk trend and totals", () => {
  it("totals are the sum of the weekly (de-duplicated) trend, so the donut matches the chart", async () => {
    // get_risk_trend counts each file once, from its latest scan; the totals must come from the same rows, not from a
    // separate count over every scan's files (a PR scanned three times counted each file three times)
    seed({}, { rpc: { get_risk_trend: () => [
      { week_start: "2026-11-23", critical_count: 1, high_count: 4, medium_count: 2 },
      { week_start: "2026-11-16", critical_count: 0, high_count: 3, medium_count: 5 },
    ] } });
    const data = await fetchDashboard(ORG, 30, null);
    expect(data.risk_trend.map(t => t.high_count)).toEqual([3, 4]);
    expect(data.risk_totals).toEqual({ critical_count: 1, high_count: 7, medium_count: 7 });
  });

  it("is all zeros when nothing is flagged", async () => {
    seed({}, { rpc: { get_risk_trend: () => [] } });
    expect((await fetchDashboard(ORG, 30, null)).risk_totals).toEqual({ critical_count: 0, high_count: 0, medium_count: 0 });
  });
});

describe("review queue covers every open PR of a repo", () => {
  const prScan = (id: string, pr: number | null, ageDays: number) => ({ ...scan(id, "o/api", ageDays, 0.5, 3), pr_number: pr });
  const prFile = (scanId: string, pr: number, path: string, risk = "HIGH", ai = 0.5) =>
    ({ ...riskFile(scanId, "o/api", path, risk, ai), scans: { repo_full_name: "o/api", pr_number: pr } });

  const seedPrs = () => seed({
    scans: [prScan("p5new", 5, 1), prScan("p5old", 5, 6), prScan("p7", 7, 2), prScan("p9", 9, 3)],
    scan_files: [
      prFile("p5new", 5, "src/a.ts"),
      prFile("p5old", 5, "src/gone.ts"),            // fixed in PR 5's newer scan: not flagged there any more
      prFile("p7", 7, "src/b.ts", "CRITICAL", 0.9),
      prFile("p9", 9, "src/c.ts"),
    ],
    attestations: [], violations: [],
  });

  it("lists files from the latest scan of each PR, not only the repo's single latest scan", async () => {
    seedPrs();
    const d = await fetchDashboard(ORG, 90, null);
    expect(d.top_risk_files.map(f => f.file_path).sort()).toEqual(["src/a.ts", "src/b.ts", "src/c.ts"]);
    expect(d.top_risk_files.find(f => f.file_path === "src/b.ts")!.pr_number).toBe(7);
  });

  it("does not list a file only an older scan of its PR flagged", async () => {
    seedPrs();
    const d = await fetchDashboard(ORG, 90, null);
    expect(d.top_risk_files.some(f => f.file_path === "src/gone.ts")).toBe(false);
  });

  it("counts the same path in two PRs once, shown from the newer scan", async () => {
    seed({
      scans: [prScan("p5", 5, 4), prScan("p7", 7, 1)],
      scan_files: [prFile("p5", 5, "src/shared.ts", "HIGH", 0.95), prFile("p7", 7, "src/shared.ts", "HIGH", 0.2)],
      attestations: [], violations: [],
    });
    const d = await fetchDashboard(ORG, 90, null);
    expect(d.top_risk_files).toHaveLength(1);
    expect(d.top_risk_files[0]).toMatchObject({ scan_id: "p7", pr_number: 7 });
    expect(d.total_high_crit).toBe(1);
  });
});
