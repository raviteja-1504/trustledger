/**
 * @jest-environment node
 *
 * What one sign-off covers (lib/attestation.ts): the file's CONTENT, in every scan of the repo where it is
 * byte-identical. Attesting through an older scan's link reaches the newer scan whose check and alert wait on it,
 * and another PR's DIFFERENT version of the file keeps its violation (it used to be resolved by any attestation of
 * that path in the repo, without anyone reviewing it).
 */
import { fakeSupabase } from "../helpers/fakeSupabase";

jest.mock("@/lib/audit", () => ({ writeAuditLog: jest.fn(async () => {}) }));
jest.mock("@/lib/cache", () => ({ cacheDel: async () => {}, cacheKeys: { dashboard: () => "d" } }));
jest.mock("@/lib/autoIncidents", () => ({ syncAutoIncidents: async () => {} }));
jest.mock("@/lib/repoViolations", () => ({ hasOpenRepoViolations: async () => true }));
jest.mock("@/lib/scanner", () => ({ buildAttestationHash: () => "hash" }));
jest.mock("@/lib/github", () => ({ getInstallationToken: jest.fn(async () => ({ token: "t" })), updateCheckRun: jest.fn(async () => {}) }));

import { performAttestation } from "@/lib/attestation";
import { ALL_PERMISSIONS } from "@/lib/permissions";
import { updateCheckRun } from "@/lib/github";

const ORG = "org-1";
// PR #1 pushed twice (s1 then s2, auth.ts unchanged); PR #2 (s3) has a different auth.ts.
function seed() {
  return fakeSupabase({
    scans: [
      { id: "s1", org_id: ORG, repo_full_name: "acme/api", pr_number: 1, check_run_id: 11, installation_id: 7, created_at: "2026-10-01T00:00:00Z" },
      { id: "s2", org_id: ORG, repo_full_name: "acme/api", pr_number: 1, check_run_id: 12, installation_id: 7, created_at: "2026-10-02T00:00:00Z" },
      { id: "s3", org_id: ORG, repo_full_name: "acme/api", pr_number: 2, check_run_id: 13, installation_id: 7, created_at: "2026-10-03T00:00:00Z" },
    ],
    scan_files: [
      { scan_id: "s1", org_id: ORG, file_path: "auth.ts", risk_score: "CRITICAL", content_hash: "A" },
      { scan_id: "s2", org_id: ORG, file_path: "auth.ts", risk_score: "CRITICAL", content_hash: "A" },
      { scan_id: "s3", org_id: ORG, file_path: "auth.ts", risk_score: "CRITICAL", content_hash: "B" },
    ],
    attestations: [],
    violations: ["s1", "s2", "s3"].map(s => ({ id: `v-${s}`, org_id: ORG, scan_id: s, file_path: "auth.ts", risk_score: "CRITICAL", status: "open" })),
    alerts: ["s1", "s2", "s3"].map(s => ({ id: `a-${s}`, org_id: ORG, scan_id: s, repo: "acme/api", alert_type: "policy", status: "firing" })),
  });
}
const rows = (db: ReturnType<typeof fakeSupabase>, t: string) => (db.client.from(t) as unknown as { rows: Record<string, unknown>[] }).rows;

beforeEach(() => jest.clearAllMocks());

it("attesting through the older scan's link covers the newer scan of the same content: its check, alert and violation", async () => {
  const db = seed();
  const res = await performAttestation(db.client as never, {
    org_id: ORG, user_id: "u1", scan_id: "s1", file_path: "auth.ts", reviewer_email: "rev@a.test", permissions: ALL_PERMISSIONS,
  });
  expect(res.ok).toBe(true);
  // s2 got the sign-off too, marked as carried from this attestation
  expect(rows(db, "attestations").map(a => a.scan_id).sort()).toEqual(["s1", "s2"]);
  expect(rows(db, "attestations").find(a => a.scan_id === "s2")).toMatchObject({ reviewer_email: "rev@a.test", payload_hash: expect.stringMatching(/^inherited:/) });
  expect(rows(db, "violations").filter(v => v.status === "resolved").map(v => v.scan_id).sort()).toEqual(["s1", "s2"]);
  expect(rows(db, "alerts").filter(a => a.status === "resolved").map(a => a.scan_id).sort()).toEqual(["s1", "s2"]);
  // both checks of PR #1 unblock
  expect((updateCheckRun as jest.Mock).mock.calls.map(c => c[3]).sort()).toEqual([11, 12]);
});

it("another PR's different version of the file keeps its violation, alert and blocked check", async () => {
  const db = seed();
  await performAttestation(db.client as never, {
    org_id: ORG, user_id: "u1", scan_id: "s2", file_path: "auth.ts", reviewer_email: "rev@a.test", permissions: ALL_PERMISSIONS,
  });
  expect(rows(db, "violations").find(v => v.scan_id === "s3")?.status).toBe("open");
  expect(rows(db, "alerts").find(a => a.scan_id === "s3")?.status).toBe("firing");
  expect(rows(db, "attestations").some(a => a.scan_id === "s3")).toBe(false);
  expect((updateCheckRun as jest.Mock).mock.calls.map(c => c[3])).not.toContain(13);
});

it("a scan still waiting on another file keeps its alert and check", async () => {
  const db = seed();
  rows(db, "violations").push({ id: "v-other", org_id: ORG, scan_id: "s2", file_path: "db.ts", risk_score: "HIGH", status: "open" });
  await performAttestation(db.client as never, {
    org_id: ORG, user_id: "u1", scan_id: "s1", file_path: "auth.ts", reviewer_email: "rev@a.test", permissions: ALL_PERMISSIONS,
  });
  expect(rows(db, "alerts").find(a => a.scan_id === "s2")?.status).toBe("firing");
  expect((updateCheckRun as jest.Mock).mock.calls.map(c => c[3])).toEqual([11]);
});
