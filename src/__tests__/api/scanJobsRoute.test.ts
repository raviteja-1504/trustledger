/**
 * @jest-environment node
 *
 * GET/POST /api/scan-jobs: the organisation sees its own queue and the reasons for failures, and can replay a failed job -- the
 * original job, once, within the plan's allowance.
 */
import { NextRequest } from "next/server";
import { fakeSupabase } from "../helpers/fakeSupabase";

let db: ReturnType<typeof fakeSupabase>;
let auth: { org_id: string; user_id?: string; role?: string; error?: string };
let allowed: { allowed: boolean; reason?: string; title?: string; summary?: string };
const requeueJob = jest.fn(async (_j: unknown) => {});

jest.mock("@/lib/supabase", () => ({ createServiceClient: () => db.client }));
jest.mock("@/app/api/_middleware", () => ({
  verifyApiKey: async () => auth,
  requirePermission: async (a: { role?: string }) => (a.role === "developer_readonly" ? "insufficient_permissions" : null),
}));
jest.mock("@/lib/planGate", () => ({ checkScanAllowed: async () => allowed }));
jest.mock("@/lib/queue", () => ({ requeueJob: (j: unknown) => requeueJob(j), ScanNotQueuedError: class extends Error {} }));

import { GET, POST } from "@/app/api/scan-jobs/route";

const now = () => new Date().toISOString();
const row = (id: string, org: string, status: string, extra: Record<string, unknown> = {}) => ({
  id, org_id: org, dedupe_key: id, repo_full_name: "acme/app", pr_number: 1, head_sha: "abcdef0", action: "opened", forced: false, status, attempts: 1, max_attempts: 4,
  last_error: null, result: null, scan_id: null, created_at: now(), updated_at: now(), finished_at: null, started_at: null,
  job: { org_id: org, installation_id: 7, repo_full_name: "acme/app", pr_number: 1, head_sha: "abcdef0", check_run_id: 42, delivery_id: "orig", action: "opened", branch: "main", pr_author: null, before_sha: null }, ...extra,
});
const call = (method: string, body?: unknown) => (method === "GET" ? GET : POST)(new NextRequest("https://app.example/api/scan-jobs", { method, ...(body === undefined ? {} : { body: JSON.stringify(body) }) }));
const stored = (id: string) => (db.tables.scan_jobs as Array<Record<string, unknown>>).find(r => r.id === id)!;

beforeEach(() => {
  requeueJob.mockClear();
  auth = { org_id: "org-1", user_id: "u1", role: "admin" };
  allowed = { allowed: true };
  db = fakeSupabase({
    scan_jobs: [
      row("ok-1", "org-1", "succeeded"), row("dead-1", "org-1", "dead", { last_error: "scan_failed: The scan could not be completed.", attempts: 4 }),
      row("fail-1", "org-1", "failed", { last_error: "files_unreadable" }), row("run-1", "org-1", "running"),
      row("theirs", "org-2", "dead", { last_error: "other org's secret reason" }),
    ],
  });
});

describe("GET", () => {
  it("shows this organisation's counts and the jobs that need attention, with reasons", async () => {
    const body = await (await call("GET")).json();
    expect(body.set_up).toBe(true);
    expect(body.counts).toEqual({ queued: 0, running: 1, succeeded: 1, failed: 1, dead: 1 });
    expect(body.attention.map((j: { id: string }) => j.id).sort()).toEqual(["dead-1", "fail-1"]);
    expect(body.attention.find((j: { id: string }) => j.id === "dead-1").last_error).toBe("scan_failed: The scan could not be completed.");
  });

  it("never shows another organisation's jobs, and never sends the stored payload", async () => {
    const text = JSON.stringify(await (await call("GET")).json());
    expect(text).not.toContain("other org's secret reason");
    expect(text).not.toContain("check_run_id");
    expect(text).not.toContain("installation_id");
  });

  it("needs a signed-in member", async () => {
    auth = { org_id: "", error: "missing_credentials" };
    expect((await call("GET")).status).toBe(401);
  });
});

describe("POST (replay)", () => {
  it("queues the ORIGINAL job again with fresh attempts", async () => {
    const res = await call("POST", { id: "dead-1" });
    expect(res.status).toBe(200);
    expect(requeueJob).toHaveBeenCalledTimes(1);
    expect(requeueJob.mock.calls[0][0]).toMatchObject({ job_id: "dead-1", check_run_id: 42, delivery_id: "orig", head_sha: "abcdef0" });
    expect(stored("dead-1")).toMatchObject({ status: "queued", attempts: 0, last_error: null });
  });

  it("a failed job (waiting for the queue's retry) can be replayed too", async () => {
    expect((await call("POST", { id: "fail-1" })).status).toBe(200);
  });

  it.each(["ok-1", "run-1"])("%s (finished or running) cannot be replayed: it would only be a duplicate", async (id) => {
    const res = await call("POST", { id });
    expect(res.status).toBe(409);
    expect((await res.json()).error).toBe("job_not_replayable");
    expect(requeueJob).not.toHaveBeenCalled();
  });

  it("replaying twice in a row queues it once", async () => {
    await call("POST", { id: "dead-1" });
    expect((await call("POST", { id: "dead-1" })).status).toBe(409);
    expect(requeueJob).toHaveBeenCalledTimes(1);
  });

  it("another organisation's job is not found, and untouched", async () => {
    expect((await call("POST", { id: "theirs" })).status).toBe(404);
    expect(stored("theirs").status).toBe("dead");
    expect(requeueJob).not.toHaveBeenCalled();
  });

  it("needs the permission to start scans", async () => {
    auth = { org_id: "org-1", user_id: "u2", role: "developer_readonly" };
    expect((await call("POST", { id: "dead-1" })).status).toBe(403);
    expect(requeueJob).not.toHaveBeenCalled();
  });

  it("is refused when the plan's scans are used up, like any other scan", async () => {
    allowed = { allowed: false, reason: "scans", title: "Plan limit reached: 3 of 3 scans used this month", summary: "…" };
    const res = await call("POST", { id: "dead-1" });
    expect(res.status).toBe(403);
    expect((await res.json()).error).toBe("plan_limit_scans");
    expect(stored("dead-1").status).toBe("dead");
    expect(requeueJob).not.toHaveBeenCalled();
  });

  it("an id is required", async () => {
    expect((await call("POST", {})).status).toBe(400);
  });
});
