/**
 * @jest-environment node
 *
 * Task 10, GitHub pipeline reliability: what happens between "GitHub delivered it" and "the scan is queued".
 *   - a delivery whose handling failed is retried by GitHub with the same GUID: it must be processed, not dropped;
 *   - a scan that could not be queued must not leave the check run spinning on "in_progress";
 *   - the queue's direct fallback must report a scan that did not run instead of pretending it was queued.
 */
import crypto from "crypto";
import { NextRequest } from "next/server";
import { fakeSupabase } from "../helpers/fakeSupabase";

let db = fakeSupabase({});
let failDbOnce = false;
jest.mock("@/lib/supabase", () => ({
  createServiceClient: () => {
    if (failDbOnce) { failDbOnce = false; throw new Error("database unavailable"); }
    return db.client;
  },
}));
jest.mock("@vercel/functions", () => ({ waitUntil: (p: Promise<unknown>) => { void p; } }));
const createCheckRun = jest.fn(async () => ({ id: 99 }));
const updateCheckRun = jest.fn(async () => undefined);
jest.mock("@/lib/github", () => ({
  ...jest.requireActual("@/lib/github"),
  getInstallationToken: async () => ({ token: "t" }),
  createCheckRun: (...a: unknown[]) => createCheckRun(...(a as [])),
  updateCheckRun: (...a: unknown[]) => updateCheckRun(...(a as [])),
}));
const enqueueScan = jest.fn(async (..._a: unknown[]) => undefined);
jest.mock("@/lib/queue", () => ({ enqueueScan: (...a: unknown[]) => enqueueScan(...a) }));
const recordEvent = jest.fn();
jest.mock("@/lib/opsEvents", () => ({ recordEvent: (...a: unknown[]) => recordEvent(...a) }));
jest.mock("@/lib/rateLimit", () => ({ ...jest.requireActual("@/lib/rateLimit"), checkRateLimit: async () => ({ success: true, headers: {} }) }));

import { POST } from "@/app/api/webhook/github/route";

const SECRET = "test-webhook-secret-reliability";
const raw = JSON.stringify({
  action: "opened", installation: { id: 4242 }, repository: { full_name: "acme/app" },
  pull_request: { number: 7, head: { sha: "abc123", ref: "feat" }, user: { login: "dev" }, additions: 1, deletions: 0, commits: 1, changed_files: 1, created_at: "2026-11-11T00:00:00Z" },
});
const send = async (guid: string) => {
  const sig = "sha256=" + crypto.createHmac("sha256", SECRET).update(raw).digest("hex");
  const res = await POST(new NextRequest(new URL("/api/webhook/github", "https://app.example"), { method: "POST", body: raw, headers: { "x-hub-signature-256": sig, "x-github-event": "pull_request", "x-github-delivery": guid } }));
  return { status: res.status, body: await res.json() as Record<string, unknown> };
};
const settle = () => new Promise(r => setTimeout(r, 20));

beforeEach(() => {
  process.env.GITHUB_WEBHOOK_SECRET = SECRET;
  failDbOnce = false;
  for (const m of [createCheckRun, updateCheckRun, enqueueScan, recordEvent]) m.mockClear();
  enqueueScan.mockImplementation(async () => undefined);
  db = fakeSupabase({ organizations: [{ id: "org-1", github_org: "acme" }], webhook_deliveries: [] });
});

describe("a delivery whose handling failed", () => {
  it("is processed when GitHub redelivers it with the same GUID", async () => {
    failDbOnce = true;
    await expect(send("retry-guid-1")).rejects.toThrow("database unavailable");
    const retry = await send("retry-guid-1");
    expect(retry.body).toMatchObject({ ok: true, queued: true });
    expect(retry.body.reason).toBeUndefined();
  });

  it("a delivery that succeeded is still dropped when repeated", async () => {
    expect((await send("ok-guid-1")).body).toMatchObject({ queued: true });
    expect((await send("ok-guid-1")).body).toMatchObject({ skipped: true, reason: "duplicate_delivery" });
  });

  it("a request with a bad signature cannot clear a real delivery's GUID", async () => {
    expect((await send("sig-guid-1")).body).toMatchObject({ queued: true });
    const forged = await POST(new NextRequest(new URL("/api/webhook/github", "https://app.example"), { method: "POST", body: raw, headers: { "x-hub-signature-256": "sha256=00", "x-github-event": "pull_request", "x-github-delivery": "sig-guid-1" } }));
    expect(forged.status).toBe(401);
    expect((await send("sig-guid-1")).body).toMatchObject({ skipped: true, reason: "duplicate_delivery" });
  });
});

describe("a scan that could not be queued", () => {
  it("closes the in-progress check run as neutral, telling the user to re-run", async () => {
    enqueueScan.mockRejectedValueOnce(new Error("qstash down"));
    expect((await send("enq-guid-1")).body).toMatchObject({ queued: true, check_run_id: 99 });
    await settle();
    expect(updateCheckRun).toHaveBeenCalledTimes(1);
    expect(updateCheckRun).toHaveBeenCalledWith("t", "acme", "app", 99, expect.objectContaining({
      status: "completed", conclusion: "neutral", output: expect.objectContaining({ title: "Scan could not be started" }),
    }));
    expect(recordEvent).toHaveBeenCalledWith(expect.objectContaining({ kind: "scan.enqueue_failed" }));
  });

  it("leaves the check run alone when the worker itself ran and reported its failure", async () => {
    enqueueScan.mockRejectedValueOnce(Object.assign(new Error("scan-worker answered 503"), { workerResponded: true }));
    await send("enq-guid-2");
    await settle();
    expect(updateCheckRun).not.toHaveBeenCalled();
    expect(recordEvent).toHaveBeenCalledWith(expect.objectContaining({ kind: "scan.enqueue_failed" }));
  });
});

describe("the queue's direct fallback", () => {
  const realFetch = global.fetch;
  afterEach(() => { global.fetch = realFetch; delete process.env.QSTASH_TOKEN; delete process.env.INTERNAL_SECRET; });
  const job = { org_id: "org-1", installation_id: 1, repo_full_name: "acme/app", pr_number: 7, head_sha: "abc", branch: "feat", pr_author: "dev", before_sha: null, action: "opened", check_run_id: 99, delivery_id: null };
  const real = () => jest.requireActual("@/lib/queue") as typeof import("@/lib/queue");

  it("reports a worker failure instead of pretending the scan was queued", async () => {
    process.env.INTERNAL_SECRET = "s3cret"; process.env.NEXT_PUBLIC_APP_URL = "https://app.example";
    global.fetch = jest.fn(async () => new Response(JSON.stringify({ error: "boom" }), { status: 500 })) as typeof fetch;
    await expect(real().enqueueScan(job)).rejects.toMatchObject({ name: "ScanNotQueuedError", workerResponded: true });
  });

  it("reports that nothing ran when no secret is available in production", async () => {
    const env = process.env as Record<string, string | undefined>;
    const was = env.NODE_ENV; env.NODE_ENV = "production"; delete env.INTERNAL_SECRET;
    try { await expect(real().enqueueScan(job)).rejects.toMatchObject({ name: "ScanNotQueuedError", workerResponded: false }); }
    finally { env.NODE_ENV = was; }
  });

  it("resolves when the worker accepts the job", async () => {
    process.env.INTERNAL_SECRET = "s3cret";
    global.fetch = jest.fn(async () => new Response(JSON.stringify({ ok: true }), { status: 200 })) as typeof fetch;
    await expect(real().enqueueScan(job)).resolves.toBeUndefined();
  });
});
