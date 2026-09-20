import type { SupabaseClient } from "@supabase/supabase-js";

jest.mock("@/lib/repoViolations", () => ({ hasOpenRepoViolations: jest.fn().mockResolvedValue(true) }));
jest.mock("@/lib/audit", () => ({ writeAuditLog: jest.fn().mockResolvedValue(undefined) }));
jest.mock("@/lib/cache", () => ({
  cacheDel: jest.fn().mockResolvedValue(undefined),
  cacheKeys: { dashboard: (orgId: string, days: number) => `dash:${orgId}:${days}` },
}));
jest.mock("@/lib/autoIncidents", () => ({ syncAutoIncidents: jest.fn().mockResolvedValue(undefined) }));
jest.mock("@/lib/github", () => ({
  getInstallationToken: jest.fn(),
  updateCheckRun: jest.fn(),
}));

import { performAttestation } from "@/lib/attestation";
import { getInstallationToken, updateCheckRun } from "@/lib/github";

const mockGetInstallationToken = getInstallationToken as jest.MockedFunction<typeof getInstallationToken>;
const mockUpdateCheckRun = updateCheckRun as jest.MockedFunction<typeof updateCheckRun>;

interface ReadResult { data: unknown; count?: number | null }
interface MockDbConfig { reads: Record<string, ReadResult[]> }

function makeMockDb(config: MockDbConfig) {
  const readIdx: Record<string, number> = {};
  const updates: Array<{ table: string; payload: Record<string, unknown> }> = [];
  const inserts: Array<{ table: string; payload: Record<string, unknown> }> = [];

  function nextRead(table: string): ReadResult {
    const q = config.reads[table] ?? [];
    const i = readIdx[table] ?? 0;
    readIdx[table] = i + 1;
    return q[i] ?? { data: null };
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  function makeChain(table: string, isWrite: boolean, writeResult?: any): any {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const self: any = {
      select: () => makeChain(table, isWrite, writeResult),
      eq: () => self,
      neq: () => self,
      in: () => self,
      order: () => self,
      limit: () => self,
      insert: (payload: Record<string, unknown>) => {
        inserts.push({ table, payload });
        return makeChain(table, true, { data: { id: "new-attestation-id", created_at: "2026-01-01T00:00:00.000Z" }, error: null });
      },
      update: (payload: Record<string, unknown>) => {
        updates.push({ table, payload });
        return makeChain(table, true, { data: null, error: null });
      },
      single: () => Promise.resolve(isWrite ? writeResult : nextRead(table)),
      maybeSingle: () => Promise.resolve(isWrite ? writeResult : nextRead(table)),
      then: (resolve: (v: unknown) => void) => resolve(isWrite ? (writeResult ?? { data: null, error: null }) : nextRead(table)),
    };
    return self;
  }

  return {
    db: { from: (table: string) => makeChain(table, false) } as unknown as SupabaseClient,
    updates, inserts,
  };
}

const BASE_PARAMS = {
  org_id: "org-1", user_id: "user-1", scan_id: "scan-1",
  file_path: "src/app.ts", reviewer_email: "reviewer@acme.com",
};

function baseReads(overrides: Partial<MockDbConfig["reads"]> = {}): MockDbConfig["reads"] {
  return {
    scans: [
      { data: { id: "scan-1", repo_full_name: "acme/repo", overall_risk: "HIGH", check_run_id: 555, installation_id: 42 } },
      { data: [{ id: "scan-1" }] }, // repoScans lookup
    ],
    scan_files: [{ data: { risk_score: "CRITICAL" } }],
    attestations: [{ data: null }], // no existing attestation -- goes through insert
    violations: [{ data: null, count: 0 }], // no remaining CRITICAL/HIGH
    ...overrides,
  };
}

describe("attestation.performAttestation", () => {
  beforeEach(() => {
    mockGetInstallationToken.mockReset();
    mockUpdateCheckRun.mockReset();
  });

  it("returns scan_not_found when the scan doesn't belong to the org", async () => {
    const { db } = makeMockDb({ reads: { scans: [{ data: null }] } });
    const result = await performAttestation(db, BASE_PARAMS);
    expect(result).toEqual({ ok: false, reason: "scan_not_found" });
  });

  it("flips scan_files.attested and resolves violations for a normal attestation", async () => {
    mockGetInstallationToken.mockResolvedValue({ token: "tok", expires_at: "" });
    mockUpdateCheckRun.mockResolvedValue(undefined);
    const { db, updates } = makeMockDb({ reads: baseReads() });

    const result = await performAttestation(db, BASE_PARAMS);

    expect(result.ok).toBe(true);
    expect(updates.some(u => u.table === "scan_files" && u.payload.attested === true)).toBe(true);
    expect(updates.some(u => u.table === "violations" && u.payload.status === "resolved")).toBe(true);
  });

  it("clears check_run_sync_error when the GitHub check-run update succeeds", async () => {
    mockGetInstallationToken.mockResolvedValue({ token: "tok", expires_at: "" });
    mockUpdateCheckRun.mockResolvedValue(undefined);
    const { db, updates } = makeMockDb({ reads: baseReads() });

    await performAttestation(db, BASE_PARAMS);

    expect(mockUpdateCheckRun).toHaveBeenCalledTimes(1);
    const scansSyncUpdate = updates.find(u => u.table === "scans" && "check_run_sync_error" in u.payload);
    expect(scansSyncUpdate?.payload.check_run_sync_error).toBeNull();
  });

  it("retries updateCheckRun once, and succeeding on the retry clears the error (not persisted)", async () => {
    mockGetInstallationToken.mockResolvedValue({ token: "tok", expires_at: "" });
    mockUpdateCheckRun.mockRejectedValueOnce(new Error("rate limited")).mockResolvedValueOnce(undefined);
    const { db, updates } = makeMockDb({ reads: baseReads() });

    await performAttestation(db, BASE_PARAMS);

    expect(mockUpdateCheckRun).toHaveBeenCalledTimes(2); // first failed, retried once
    const scansSyncUpdate = updates.find(u => u.table === "scans" && "check_run_sync_error" in u.payload);
    expect(scansSyncUpdate?.payload.check_run_sync_error).toBeNull();
  });

  it("persists check_run_sync_error after both the initial attempt and the retry fail", async () => {
    mockGetInstallationToken.mockResolvedValue({ token: "tok", expires_at: "" });
    mockUpdateCheckRun.mockRejectedValue(new Error("installation token revoked"));
    const { db, updates } = makeMockDb({ reads: baseReads() });

    const result = await performAttestation(db, BASE_PARAMS);

    expect(result.ok).toBe(true); // attestation itself still succeeds -- the GitHub sync is best-effort
    expect(mockUpdateCheckRun).toHaveBeenCalledTimes(2); // initial attempt + one retry, then gives up
    const scansSyncUpdate = updates.find(u => u.table === "scans" && "check_run_sync_error" in u.payload);
    expect(scansSyncUpdate?.payload.check_run_sync_error).toContain("installation token revoked");
  });

  it("does not attempt a check-run sync when the scan has no check_run_id (not a GitHub PR scan)", async () => {
    const { db, updates } = makeMockDb({
      reads: baseReads({
        scans: [
          { data: { id: "scan-1", repo_full_name: "acme/repo", overall_risk: "HIGH", check_run_id: null, installation_id: null } },
          { data: [{ id: "scan-1" }] },
        ],
      }),
    });

    const result = await performAttestation(db, BASE_PARAMS);

    expect(result.ok).toBe(true);
    expect(mockUpdateCheckRun).not.toHaveBeenCalled();
    expect(updates.some(u => u.table === "scans" && "check_run_sync_error" in u.payload)).toBe(false);
  });

  it("returns the existing attestation instead of inserting a duplicate on a repeat call", async () => {
    mockGetInstallationToken.mockResolvedValue({ token: "tok", expires_at: "" });
    mockUpdateCheckRun.mockResolvedValue(undefined);
    const { db, inserts } = makeMockDb({
      reads: baseReads({
        attestations: [{ data: { id: "existing-attestation-id", created_at: "2025-06-01T00:00:00.000Z" } }],
      }),
    });

    const result = await performAttestation(db, BASE_PARAMS);

    expect(result).toMatchObject({ ok: true, attestation_id: "existing-attestation-id" });
    expect(inserts.some(i => i.table === "attestations")).toBe(false);
  });
});
