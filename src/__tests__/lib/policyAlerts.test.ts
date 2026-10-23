/**
 * @jest-environment node
 *
 * The PR "merge blocked" alert is ensured, not fired once (lib/policyAlerts.ts): each PR's latest scan with open
 * blocking files has one -- also when the scan that should have raised it didn't get that far.
 */
import { fakeSupabase } from "../helpers/fakeSupabase";
import { ensurePolicyAlerts, latestScanPerPr, policyAlertText } from "@/lib/policyAlerts";

const ORG = "org-1";
const ago = (h: number) => new Date(Date.now() - h * 3_600_000).toISOString();
const vio = (scan_id: string, file_path: string, risk_score: string, status = "open") => ({ id: `${scan_id}-${file_path}`, org_id: ORG, scan_id, file_path, risk_score, status });

function seed(blockHigh = true) {
  return fakeSupabase({
    organizations: [{ id: ORG, block_on_critical: true, block_on_high: blockHigh }],
    scans: [
      { id: "j1", org_id: ORG, repo_full_name: "acme/juice", pr_number: 1, created_at: ago(5) },   // original
      { id: "j2", org_id: ORG, repo_full_name: "acme/juice", pr_number: 1, created_at: ago(1) },   // rescan: the latest
      { id: "s1", org_id: ORG, repo_full_name: "acme/sast", pr_number: 4, created_at: ago(2) },
      { id: "h1", org_id: ORG, repo_full_name: "acme/high", pr_number: 9, created_at: ago(2) },
      { id: "c1", org_id: ORG, repo_full_name: "acme/clean", pr_number: 2, created_at: ago(2) },
      { id: "old", org_id: ORG, repo_full_name: "acme/old", pr_number: 3, created_at: ago(24 * 40) },
      { id: "x1", org_id: "org-2", repo_full_name: "other/x", pr_number: 1, created_at: ago(1) },
    ],
    violations: [
      vio("j1", "a.ts", "CRITICAL"), vio("j2", "a.ts", "CRITICAL"), vio("j2", "b.ts", "CRITICAL"), vio("j2", "c.ts", "HIGH"),
      vio("s1", "s.ts", "CRITICAL"),
      vio("h1", "h.ts", "HIGH"),
      vio("c1", "c.ts", "CRITICAL", "resolved"),
      vio("old", "o.ts", "CRITICAL"),
      { ...vio("x1", "x.ts", "CRITICAL"), org_id: "org-2" },
    ],
    // sast already has its alert (resolved by hand: not overruled)
    alerts: [{ id: "al-s1", org_id: ORG, alert_type: "policy", scan_id: "s1", status: "resolved" }],
  });
}
const rows = (db: ReturnType<typeof fakeSupabase>, t: string) => (db.client.from(t) as unknown as { rows: Record<string, unknown>[] }).rows;
const created = (db: ReturnType<typeof fakeSupabase>) => rows(db, "alerts").filter(a => a.id !== "al-s1");

it("each PR's latest scan with open blocking files gets its alert, once", async () => {
  const db = seed();
  expect(await ensurePolicyAlerts(db.client, ORG)).toBe(2);
  expect(created(db).map(a => a.scan_id).sort()).toEqual(["h1", "j2"]);
  expect(created(db).find(a => a.scan_id === "j2")).toMatchObject({
    org_id: ORG, alert_type: "policy", status: "firing", severity: "P1", repo: "acme/juice",
    title: "3 unattested files in juice PR #1", body: "2 CRITICAL and 1 HIGH files require attestation before merge.",
  });
  expect(created(db).find(a => a.scan_id === "h1")).toMatchObject({ severity: "P2", title: "1 unattested file in high PR #9" });
  // idempotent
  expect(await ensurePolicyAlerts(db.client, ORG)).toBe(0);
  expect(created(db)).toHaveLength(2);
});

it("follows the merge gate: with \"Block HIGH\" off, HIGH files alone raise nothing and aren't counted", async () => {
  const db = seed(false);
  await ensurePolicyAlerts(db.client, ORG);
  expect(created(db).map(a => a.scan_id)).toEqual(["j2"]);
  expect(created(db)[0]).toMatchObject({ title: "2 unattested files in juice PR #1", body: "2 CRITICAL files require attestation before merge." });
});

it("scanIds: only those scans, and only while they are their PR's latest", async () => {
  const db = seed();
  expect(await ensurePolicyAlerts(db.client, ORG, { scanIds: ["j1"] })).toBe(0);    // superseded by the rescan
  expect(await ensurePolicyAlerts(db.client, ORG, { scanIds: ["j2"] })).toBe(1);
  expect(created(db).map(a => a.scan_id)).toEqual(["j2"]);
});

it("a read error creates nothing", async () => {
  expect(await ensurePolicyAlerts({ from: () => { throw new Error("down"); } }, ORG)).toBe(0);
});

describe("helpers", () => {
  it("latestScanPerPr keeps the newest scan of each repo + PR, and skips scans without a PR", () => {
    expect(latestScanPerPr([
      { id: "1", repo_full_name: "a/x", pr_number: 1, created_at: "2026-10-01" },
      { id: "2", repo_full_name: "a/x", pr_number: 1, created_at: "2026-10-03" },
      { id: "3", repo_full_name: "a/y", pr_number: 1, created_at: "2026-10-02" },
      { id: "4", repo_full_name: "a/x", pr_number: null, created_at: "2026-10-04" },
    ]).map(s => s.id).sort()).toEqual(["2", "3"]);
  });
  it("policyAlertText", () => {
    expect(policyAlertText("acme/api", 7, ["HIGH", "HIGH"])).toEqual({ severity: "P2", title: "2 unattested files in api PR #7", body: "2 HIGH files require attestation before merge." });
  });
});
