/**
 * @jest-environment node
 *
 * A rescan (POST /api/scans/:id/rescan) and a dashboard "scan this PR" (POST /api/scans/pr) create scans, so they count
 * against the plan's monthly scans like a webhook scan does -- and are refused once those are used.
 */
import { NextRequest } from "next/server";
import { fakeSupabase } from "../helpers/fakeSupabase";

const enqueueScan = jest.fn(async () => {});
const createCheckRun = jest.fn(async () => ({ id: 1 }));
let fake: ReturnType<typeof fakeSupabase>;

jest.mock("@/lib/supabase", () => ({ createServiceClient: () => fake.client }));
jest.mock("@/app/api/_middleware", () => ({
  verifyApiKey: async () => ({ org_id: "o1", user_id: "u1", actor_email: "a@x.io", role: "admin" }),
  requirePermission: async () => null,
}));
jest.mock("@/lib/queue", () => ({ enqueueScan: (...a: unknown[]) => (enqueueScan as unknown as (...x: unknown[]) => unknown)(...a) }));
jest.mock("@/lib/github", () => ({
  getInstallationToken: async () => ({ token: "t" }),
  getPullRequest: async () => ({ head_sha: "newsha", additions: 1, deletions: 1, commits: 1, changed_files: 1, created_at: "2026-11-01T00:00:00Z" }),
  getPRHeadSha: async () => "newsha",
  createCheckRun: (...a: unknown[]) => (createCheckRun as unknown as (...x: unknown[]) => unknown)(...a),
}));
jest.mock("@/lib/connectedRepo", () => ({
  resolveConnectedRepo: async () => ({ ok: true, installationId: 9, owner: "acme", name: "web", repo: "acme/web" }),
}));
jest.mock("@/lib/audit", () => ({ writeAuditLog: async () => {} }));
jest.mock("@/lib/opsEvents", () => ({ recordEvent: async () => {} }));

import { POST as rescan } from "@/app/api/scans/[id]/rescan/route";
import { POST as scanPr } from "@/app/api/scans/pr/route";

const old = new Date(Date.now() - 3 * 3600_000).toISOString();
const thisMonth = () => {
  const d = new Date(); return new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), 1, 0, 0, 1)).toISOString();
};
const scanRow = (id: string, created_at: string) => ({
  id, org_id: "o1", repo_full_name: "acme/web", pr_number: 5, commit_sha: "oldsha", branch: "main", pr_author: "x", installation_id: 9, created_at,
});
const seed = (used: number) => {
  // `used` scans this month (all but the first are a bit older than the PR's latest, which is more than a minute ago)
  const rows = Array.from({ length: used }, (_, i) => scanRow(`s${i}`, i === 0 ? old : thisMonth()));
  fake = fakeSupabase({ organizations: [{ id: "o1", plan: "free" }], scans: rows, repositories: [] });
};
const callRescan = () => rescan(new NextRequest("https://app.example/api/scans/s0/rescan", { method: "POST" }), { params: Promise.resolve({ id: "s0" }) });
const callPr = () => scanPr(new NextRequest("https://app.example/api/scans/pr", { method: "POST", body: JSON.stringify({ repo: "acme/web", pr_number: 5, force: true }) }));

beforeEach(() => { jest.clearAllMocks(); });

describe.each([["rescan", callRescan], ["scan this PR", callPr]] as const)("%s", (_name, call) => {
  it("is refused once the monthly scans are used, and queues nothing", async () => {
    seed(3);
    const res = await call();
    expect(res.status).toBe(403);
    const body = await res.json();
    expect(body.error).toBe("plan_limit_scans");
    expect(body.message).toMatch(/3 of 3 scans/);
    expect(enqueueScan).not.toHaveBeenCalled();
    expect(createCheckRun).not.toHaveBeenCalled();
  });

  it("is refused past the limit too (4 of 3)", async () => {
    seed(4);
    expect((await call()).status).toBe(403);
    expect(enqueueScan).not.toHaveBeenCalled();
  });

  it("still works while scans remain", async () => {
    seed(2);
    const res = await call();
    expect(res.status).toBe(200);
    expect(enqueueScan).toHaveBeenCalledTimes(1);
  });
});
