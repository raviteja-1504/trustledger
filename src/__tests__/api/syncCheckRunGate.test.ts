/**
 * @jest-environment node
 *
 * POST /api/sync-check-run follows the org's merge gate (lib/mergeGate.ts): with "Block HIGH" off, the check
 * turns green once the CRITICAL files are signed off -- and the HIGH files nobody reviewed are NOT marked resolved.
 */
import { NextRequest } from "next/server";
import { fakeSupabase } from "../helpers/fakeSupabase";

let db: ReturnType<typeof fakeSupabase>;
jest.mock("@/lib/supabase", () => ({ createServiceClient: () => db.client }));
jest.mock("@/app/api/_middleware", () => ({
  ...jest.requireActual("@/app/api/_middleware"),
  verifyApiKey: async () => ({ org_id: "org-1", user_id: "u1", role: "admin" }),
}));
jest.mock("@/lib/github", () => ({ getInstallationToken: jest.fn(async () => ({ token: "t" })), updateCheckRun: jest.fn(async () => {}) }));

import { POST } from "@/app/api/sync-check-run/route";
import { updateCheckRun } from "@/lib/github";

const ORG = "org-1";
const rows = (t: string) => (db.client.from(t) as unknown as { rows: Record<string, unknown>[] }).rows;
const sync = async () => (await POST(new NextRequest(new URL("/api/sync-check-run", "https://app.example"), { method: "POST", body: JSON.stringify({ scan_id: "s1" }) }))).json();

function seed(blockHigh: boolean) {
  db = fakeSupabase({
    organizations: [{ id: ORG, block_on_critical: true, block_on_high: blockHigh }],
    scans: [{ id: "s1", org_id: ORG, repo_full_name: "acme/api", check_run_id: 11, installation_id: 7 }],
    scan_files: [
      { id: "f1", scan_id: "s1", org_id: ORG, file_path: "auth.ts", risk_score: "CRITICAL" },
      { id: "f2", scan_id: "s1", org_id: ORG, file_path: "util.ts", risk_score: "HIGH" },
    ],
    attestations: [{ id: "a1", org_id: ORG, scan_id: "s1", file_path: "auth.ts", risk_score: "CRITICAL" }],
    violations: [
      { id: "v1", org_id: ORG, scan_id: "s1", file_path: "auth.ts", risk_score: "CRITICAL", status: "open" },
      { id: "v2", org_id: ORG, scan_id: "s1", file_path: "util.ts", risk_score: "HIGH", status: "open" },
    ],
  });
}

beforeEach(() => jest.clearAllMocks());

it("with \"Block HIGH\" off: green once the CRITICAL file is signed off; the unreviewed HIGH file stays open", async () => {
  seed(false);
  expect(await sync()).toMatchObject({ synced: true, conclusion: "success" });
  expect((updateCheckRun as jest.Mock).mock.calls[0][4]).toMatchObject({ conclusion: "success" });
  expect(rows("violations").find(v => v.id === "v2")?.status).toBe("open");
  expect(rows("violations").find(v => v.id === "v1")?.status).toBe("resolved");
});

it("with it on: the unattested HIGH file still holds the check", async () => {
  seed(true);
  expect(await sync()).toMatchObject({ synced: false, reason: "files_pending", attested: 1, total: 2 });
  expect(updateCheckRun).not.toHaveBeenCalled();
  expect(rows("violations").every(v => v.status === "open")).toBe(true);
});
