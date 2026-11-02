/**
 * @jest-environment node
 *
 * Keeping a sign-off fast without changing what it does:
 *   - the org-wide incident sync can run after the response (a caller-supplied `defer`), and still runs;
 *   - a burst of syncs ("attest all": one per file) shares one queued run instead of queueing an aggregation each,
 *     and that run starts after the running one, so it sees every change made before it.
 */
const syncAutoIncidents = jest.fn(async () => {});
jest.mock("@/lib/autoIncidents", () => ({ syncAutoIncidents: (...a: unknown[]) => (syncAutoIncidents as jest.Mock)(...a) }));
jest.mock("@/lib/audit", () => ({ writeAuditLog: jest.fn(async () => {}) }));
jest.mock("@/lib/cache", () => ({ cacheDel: async () => {}, cached: (_k: string, _t: number, fn: () => unknown) => fn(), cacheKeys: { dashboard: () => "d", autoIncidentState: () => "s" } }));
jest.mock("@/lib/orgDataVersion", () => ({ orgDataVersion: async () => null, versionedKey: (k: string) => k }));
// the org-wide aggregation the burst handling saves: counted, and held until released
let aggregations = 0;
let releaseAggregation: () => void = () => {};
let aggregationGate = Promise.resolve();
jest.mock("@/lib/dashboardAggregate", () => ({
  fetchUnattestedRiskState: async () => { aggregations++; await aggregationGate; throw new Error("stop here: only counting"); },
}));
jest.mock("@/lib/repoViolations", () => ({ hasOpenRepoViolations: async () => true }));
jest.mock("@/lib/scanner", () => ({ buildAttestationHash: () => "hash" }));
jest.mock("@/lib/github", () => ({ getInstallationToken: jest.fn(async () => ({ token: "t" })), updateCheckRun: jest.fn(async () => {}) }));

import { fakeSupabase } from "../helpers/fakeSupabase";
import { performAttestation } from "@/lib/attestation";
import { ALL_PERMISSIONS } from "@/lib/permissions";

const ORG = "org-1";
const seed = () => fakeSupabase({
  scans: [{ id: "s1", org_id: ORG, repo_full_name: "acme/api", pr_number: 1, created_at: "2026-10-01T00:00:00Z" }],
  scan_files: [{ scan_id: "s1", org_id: ORG, file_path: "auth.ts", risk_score: "CRITICAL", content_hash: "A" }],
  attestations: [], violations: [], alerts: [],
});
const attest = (db: ReturnType<typeof seed>, defer?: (t: () => Promise<void>) => void) => performAttestation(db.client as never, {
  org_id: ORG, user_id: "u1", scan_id: "s1", file_path: "auth.ts", reviewer_email: "rev@a.test", permissions: ALL_PERMISSIONS,
}, defer ? { defer } : {});

beforeEach(() => syncAutoIncidents.mockClear());

describe("incident sync on a sign-off", () => {
  it("with a defer, the sign-off returns before the sync, which is handed over to run afterwards", async () => {
    const tasks: Array<() => Promise<void>> = [];
    const res = await attest(seed(), t => tasks.push(t));
    expect(res.ok).toBe(true);
    expect(syncAutoIncidents).not.toHaveBeenCalled();
    expect(tasks).toHaveLength(1);
    await tasks[0]();
    expect(syncAutoIncidents).toHaveBeenCalledWith(expect.anything(), ORG);
  });

  it("without one, it runs inline (Slack and other callers keep their behaviour)", async () => {
    await attest(seed());
    expect(syncAutoIncidents).toHaveBeenCalledTimes(1);
  });
});

describe("syncAutoIncidents bursts", () => {
  const { syncAutoIncidents: realSync } = jest.requireActual("@/lib/autoIncidents") as typeof import("@/lib/autoIncidents");
  const db = { from: () => { throw new Error("unused"); } };
  beforeEach(() => {
    aggregations = 0;
    aggregationGate = new Promise<void>(r => { releaseAggregation = r; });
  });

  it("calls made before a run starts share it: one aggregation sees all their changes", async () => {
    releaseAggregation();
    const calls = Array.from({ length: 10 }, () => realSync(db as never, "org-same-tick"));
    expect(new Set(calls).size).toBe(1);
    await Promise.all(calls);
    expect(aggregations).toBe(1);
  });

  it("calls made while a run is going share the one queued behind it: two aggregations, not ten", async () => {
    const first = realSync(db as never, "org-burst");
    await new Promise(r => setTimeout(r, 0));
    expect(aggregations).toBe(1);   // started, and held
    const later = Array.from({ length: 9 }, () => realSync(db as never, "org-burst"));
    expect(new Set(later).size).toBe(1);
    expect(later[0]).not.toBe(first);
    releaseAggregation();
    await Promise.all([first, ...later]);
    expect(aggregations).toBe(2);
  });

  it("a call after the queued run has started gets a run of its own (the started one could miss its change)", async () => {
    releaseAggregation();
    await realSync(db as never, "org-seq");
    await realSync(db as never, "org-seq");
    expect(aggregations).toBe(2);
  });
});
