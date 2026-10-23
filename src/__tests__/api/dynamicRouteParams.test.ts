/**
 * @jest-environment node
 *
 * Next 16 passes a dynamic route's `params` as a Promise. These handlers had no tests before the upgrade;
 * each must await params and act on the right record (and only within the caller's org).
 */
import { NextRequest } from "next/server";
import { fakeSupabase } from "../helpers/fakeSupabase";
import { hashScimToken } from "@/lib/scimAuth";

const SCIM_TOKEN = "tl_scim_test-token-for-org-1";

let db: ReturnType<typeof fakeSupabase>;
jest.mock("@/lib/supabase", () => ({ createServiceClient: () => db.client }));
jest.mock("@/app/api/_middleware", () => ({
  ...jest.requireActual("@/app/api/_middleware"),
  verifyApiKey: async () => ({ org_id: "org-1", user_id: "u-admin", actor_email: "a@acme.test", role: "admin" }),
}));
jest.mock("@/lib/audit", () => ({ writeAuditLog: jest.fn(async () => {}) }));
jest.mock("@/lib/opsEvents", () => ({ recordEvent: jest.fn(async () => {}) }));
jest.mock("@/lib/queue", () => ({ enqueueScan: jest.fn(async () => ({ queued: true })) }));
jest.mock("@/lib/github", () => ({ getInstallationToken: jest.fn(), getPRHeadSha: jest.fn(), getPullRequest: jest.fn(), createCheckRun: jest.fn() }));

import { POST as rescanPOST } from "@/app/api/scans/[id]/rescan/route";
import { GET as scimGET, PATCH as scimPATCH, DELETE as scimDELETE } from "@/app/api/scim/v2/Users/[id]/route";

const rows = (t: string) => (db.client.from(t) as unknown as { rows: Record<string, unknown>[] }).rows;
const req = (url: string, method = "GET", body?: unknown, headers: Record<string, string> = {}) =>
  new NextRequest(new URL(url, "https://app.example"), { method, headers, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
const ctx = (id: string) => ({ params: Promise.resolve({ id }) });

beforeEach(() => {
  db = fakeSupabase({
    scans: [
      { id: "s-api", org_id: "org-1", repo_full_name: "acme/api", pr_number: null, installation_id: null, created_at: "2026-01-01T00:00:00Z" },
      { id: "s-other", org_id: "org-2", repo_full_name: "x/y", pr_number: 4, installation_id: 9, created_at: "2026-01-01T00:00:00Z" },
    ],
    org_members: [
      { org_id: "org-1", user_id: "u-1", email: "one@acme.test", name: "One", role: "developer" },
      { org_id: "org-2", user_id: "u-2", email: "two@other.test", name: "Two", role: "developer" },
    ],
    scim_tokens: [{ org_id: "org-1", token_hash: hashScimToken(SCIM_TOKEN), token_prefix: "tl_scim_test-t" }],
  });
});

describe("POST /api/scans/[id]/rescan", () => {
  it("reads the scan id from the awaited params", async () => {
    // a scan submitted through the API (no GitHub App) can't be rescanned -- proves the right record was loaded
    const res = await rescanPOST(req("/api/scans/s-api/rescan", "POST"), ctx("s-api"));
    expect(res.status).toBe(409);
    expect((await res.json()).error).toBe("rescan_unavailable");
  });

  it("another org's scan id is not found", async () => {
    expect((await rescanPOST(req("/api/scans/s-other/rescan", "POST"), ctx("s-other"))).status).toBe(404);
  });

  describe("a GitHub PR's rescan", () => {
    const github = jest.requireMock("@/lib/github") as Record<string, jest.Mock>;
    const { enqueueScan } = jest.requireMock("@/lib/queue") as { enqueueScan: jest.Mock };
    beforeEach(() => {
      jest.clearAllMocks();
      rows("scans").push({ id: "s-gh", org_id: "org-1", repo_full_name: "acme/juice", pr_number: 1, installation_id: 7, commit_sha: "old", branch: "main", pr_author: "dev", created_at: "2026-01-01T00:00:00Z" });
      github.getInstallationToken.mockResolvedValue({ token: "t" });
      github.createCheckRun.mockResolvedValue({ id: 99 });
      github.getPRHeadSha.mockResolvedValue("head-from-sha");
    });

    it("carries the PR's size and commits, as a webhook scan does (PR behaviour / author baseline read them)", async () => {
      github.getPullRequest.mockResolvedValue({ head_sha: "head-1", additions: 37146, deletions: 0, commits: 1, changed_files: 470, created_at: "2026-10-23T14:00:00Z" });
      expect((await rescanPOST(req("/api/scans/s-gh/rescan", "POST"), ctx("s-gh"))).status).toBe(200);
      expect(enqueueScan).toHaveBeenCalledWith(expect.objectContaining({
        head_sha: "head-1", force: true, action: "rescan", check_run_id: 99,
        pr_additions: 37146, pr_deletions: 0, pr_commits: 1, pr_changed_files: 470, pr_created_at: "2026-10-23T14:00:00Z",
      }));
    });

    it("if GitHub can't return the PR, still rescans the head it can find, without invented sizes", async () => {
      github.getPullRequest.mockRejectedValue(new Error("502"));
      expect((await rescanPOST(req("/api/scans/s-gh/rescan", "POST"), ctx("s-gh"))).status).toBe(200);
      const job = enqueueScan.mock.calls[0][0];
      expect(job.head_sha).toBe("head-from-sha");
      expect(job).not.toHaveProperty("pr_additions");
    });
  });
});

describe("/api/scim/v2/Users/[id]", () => {
  const auth = { Authorization: `Bearer ${SCIM_TOKEN}` };

  it("GET returns the user named in params, in the SCIM org only", async () => {
    const res = await scimGET(req("/api/scim/v2/Users/u-1", "GET", undefined, auth), ctx("u-1"));
    expect(res.status).toBe(200);
    expect(await res.json()).toMatchObject({ id: "u-1", userName: "one@acme.test" });
    expect((await scimGET(req("/api/scim/v2/Users/u-2", "GET", undefined, auth), ctx("u-2"))).status).toBe(404);
  });

  it("PATCH active=false and DELETE de-provision that user only", async () => {
    const off = { Operations: [{ op: "replace", path: "active", value: false }] };
    expect((await scimPATCH(req("/api/scim/v2/Users/u-1", "PATCH", off, auth), ctx("u-1"))).status).toBe(204);
    expect(rows("org_members").map(m => m.user_id)).toEqual(["u-2"]);
    expect((await scimDELETE(req("/api/scim/v2/Users/u-2", "DELETE", undefined, auth), ctx("u-2"))).status).toBe(204);
    expect(rows("org_members").map(m => m.user_id)).toEqual(["u-2"]);   // other org untouched
  });

  it("refuses a wrong SCIM token", async () => {
    expect((await scimGET(req("/api/scim/v2/Users/u-1", "GET", undefined, { Authorization: "Bearer nope" }), ctx("u-1"))).status).toBe(401);
  });
});
