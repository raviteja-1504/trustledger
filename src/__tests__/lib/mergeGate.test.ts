/**
 * @jest-environment node
 *
 * The merge gate (lib/mergeGate.ts): the org's "Block CRITICAL / Block HIGH" settings decide which unattested
 * files block a PR -- one answer every caller (GitHub check, alerts, Trust Record) shares. Fails closed.
 */
import { fakeSupabase } from "../helpers/fakeSupabase";
import { blockingRisks, blocksMerge, countOpenBlocking, loadGate, DEFAULT_GATE } from "@/lib/mergeGate";
import { hasOpenRepoViolations } from "@/lib/repoViolations";

describe("blockingRisks / blocksMerge", () => {
  it("follows the two settings", () => {
    expect(blockingRisks({ block_on_critical: true, block_on_high: true })).toEqual(["CRITICAL", "HIGH"]);
    expect(blockingRisks({ block_on_critical: true, block_on_high: false })).toEqual(["CRITICAL"]);
    expect(blockingRisks({ block_on_critical: false, block_on_high: true })).toEqual(["HIGH"]);
    expect(blockingRisks({ block_on_critical: false, block_on_high: false })).toEqual([]);
    const noHigh = { block_on_critical: true, block_on_high: false };
    expect([blocksMerge("CRITICAL", noHigh), blocksMerge("HIGH", noHigh), blocksMerge("critical", noHigh), blocksMerge("MEDIUM", DEFAULT_GATE), blocksMerge(null, DEFAULT_GATE)])
      .toEqual([true, false, true, false, false]);
  });
});

describe("loadGate fails closed", () => {
  const withOrg = (row: Record<string, unknown> | null) => fakeSupabase({ organizations: row ? [{ id: "o1", ...row }] : [] });

  it("reads the org's settings; a missing value or org blocks", async () => {
    expect(await loadGate(withOrg({ block_on_critical: true, block_on_high: false }).client, "o1")).toEqual({ block_on_critical: true, block_on_high: false });
    expect(await loadGate(withOrg({ block_on_critical: false, block_on_high: true }).client, "o1")).toEqual({ block_on_critical: false, block_on_high: true });
    expect(await loadGate(withOrg({ block_on_critical: null, block_on_high: null }).client, "o1")).toEqual(DEFAULT_GATE);
    expect(await loadGate(withOrg(null).client, "o1")).toEqual(DEFAULT_GATE);
    expect(await loadGate(withOrg({}).client, null)).toEqual(DEFAULT_GATE);
  });

  it("a read error blocks", async () => {
    const broken = { from: () => { throw new Error("db down"); } };
    expect(await loadGate(broken, "o1")).toEqual(DEFAULT_GATE);
  });
});

describe("countOpenBlocking", () => {
  const db = () => fakeSupabase({
    violations: [
      { id: "1", org_id: "o1", scan_id: "s1", risk_score: "CRITICAL", status: "open" },
      { id: "2", org_id: "o1", scan_id: "s1", risk_score: "HIGH", status: "open" },
      { id: "3", org_id: "o1", scan_id: "s1", risk_score: "HIGH", status: "resolved" },
      { id: "4", org_id: "o1", scan_id: "s2", risk_score: "CRITICAL", status: "open" },
      { id: "5", org_id: "o2", scan_id: "s1", risk_score: "CRITICAL", status: "open" },
    ],
  }).client;

  it("open violations of the scan, at the blocking risk levels, in this org", async () => {
    expect(await countOpenBlocking(db(), "s1", DEFAULT_GATE, "o1")).toBe(2);
    expect(await countOpenBlocking(db(), "s1", { block_on_critical: true, block_on_high: false }, "o1")).toBe(1);
    expect(await countOpenBlocking(db(), "s1", { block_on_critical: false, block_on_high: false }, "o1")).toBe(0);
    // another org's row on the same scan id never counts
    expect(await countOpenBlocking(db(), "s1", DEFAULT_GATE, "o2")).toBe(1);
  });
});

describe("hasOpenRepoViolations with the gate's risk levels", () => {
  const db = () => fakeSupabase({
    scans: [{ id: "s1", org_id: "o1", repo_full_name: "acme/api", created_at: "2026-10-01T00:00:00Z" }],
    violations: [
      { org_id: "o1", scan_id: "s1", file_path: "a.ts", risk_score: "CRITICAL", status: "resolved" },
      { org_id: "o1", scan_id: "s1", file_path: "b.ts", risk_score: "HIGH", status: "open" },
    ],
  }).client;

  it("an open HIGH file counts unless the gate leaves HIGH out", async () => {
    expect(await hasOpenRepoViolations(db(), "o1", "acme/api")).toBe(true);
    expect(await hasOpenRepoViolations(db(), "o1", "acme/api", ["CRITICAL", "HIGH"])).toBe(true);
    expect(await hasOpenRepoViolations(db(), "o1", "acme/api", ["CRITICAL"])).toBe(false);
  });
});
