/**
 * @jest-environment node
 *
 * The GitHub App is public: anyone can install it. A pull request from an installation that no TrustLedger organisation
 * has claimed must not get a check run or a comment, and must not queue a scan.
 */
import crypto from "crypto";
import { NextRequest } from "next/server";
import { fakeSupabase } from "../helpers/fakeSupabase";

let db = fakeSupabase({});
jest.mock("@/lib/supabase", () => ({ createServiceClient: () => db.client }));
jest.mock("@vercel/functions", () => ({ waitUntil: (p: Promise<unknown>) => { void p; } }));
const createCheckRun = jest.fn(async () => ({ id: 99 }));
const getInstallationToken = jest.fn(async () => ({ token: "t" }));
jest.mock("@/lib/github", () => ({
  ...jest.requireActual("@/lib/github"),
  getInstallationToken: (...a: unknown[]) => getInstallationToken(...(a as [])),
  createCheckRun: (...a: unknown[]) => createCheckRun(...(a as [])),
}));
const enqueueScan = jest.fn(async () => undefined);
jest.mock("@/lib/queue", () => ({ enqueueScan: (...a: unknown[]) => enqueueScan(...(a as [])) }));
const recordEvent = jest.fn();
jest.mock("@/lib/opsEvents", () => ({ recordEvent: (...a: unknown[]) => recordEvent(...a) }));
jest.mock("@/lib/rateLimit", () => ({ ...jest.requireActual("@/lib/rateLimit"), checkRateLimit: async () => ({ success: true, headers: {} }) }));

import { POST } from "@/app/api/webhook/github/route";

const SECRET = "test-webhook-secret";
const body = (owner: string) => JSON.stringify({
  action: "opened", installation: { id: 4242 },
  repository: { full_name: `${owner}/app` },
  pull_request: { number: 7, head: { sha: "abc123", ref: "feat" }, user: { login: "dev" }, additions: 1, deletions: 0, commits: 1, changed_files: 1, created_at: "2026-11-11T00:00:00Z" },
});
const send = async (raw: string) => {
  const sig = "sha256=" + crypto.createHmac("sha256", SECRET).update(raw).digest("hex");
  const res = await POST(new NextRequest(new URL("/api/webhook/github", "https://app.example"), { method: "POST", body: raw, headers: { "x-hub-signature-256": sig, "x-github-event": "pull_request", "x-github-delivery": "d-1" } }));
  return { status: res.status, body: await res.json() as Record<string, unknown> };
};

beforeEach(() => {
  process.env.GITHUB_WEBHOOK_SECRET = SECRET;
  createCheckRun.mockClear(); getInstallationToken.mockClear(); enqueueScan.mockClear(); recordEvent.mockClear();
  db = fakeSupabase({ organizations: [{ id: "org-1", github_org: "acme" }], webhook_deliveries: [] });
});

describe("GitHub webhook: pull_request from an installation nobody has claimed", () => {
  it("is ignored: no check run, no scan, no comment; the event is recorded", async () => {
    const r = await send(body("stranger-corp"));
    expect(r.status).toBe(200);
    expect(r.body).toMatchObject({ ok: true, skipped: true, reason: "installation_not_linked" });
    expect(getInstallationToken).not.toHaveBeenCalled();
    expect(createCheckRun).not.toHaveBeenCalled();
    expect(enqueueScan).not.toHaveBeenCalled();
    expect(recordEvent).toHaveBeenCalledWith(expect.objectContaining({ kind: "webhook.ignored" }));
  });

  it("a linked organisation is still scanned: check run created and the scan queued", async () => {
    const r = await send(body("acme"));
    expect(r.body).toMatchObject({ ok: true, queued: true, check_run_id: 99 });
    expect(createCheckRun).toHaveBeenCalledTimes(1);
    await Promise.resolve();
    expect(enqueueScan).toHaveBeenCalledTimes(1);
    expect(enqueueScan).toHaveBeenCalledWith(expect.objectContaining({ org_id: "org-1", repo_full_name: "acme/app", pr_number: 7 }));
  });
});
