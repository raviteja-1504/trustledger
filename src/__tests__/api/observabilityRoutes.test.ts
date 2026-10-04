/**
 * @jest-environment node
 *
 * Trace lookup API, the daily pipeline-health job, and the GitHub webhook's trace propagation.
 */
import { NextRequest } from "next/server";
import { fakeSupabase } from "../helpers/fakeSupabase";

let db: ReturnType<typeof fakeSupabase>;
let role = "admin";
jest.mock("@/lib/supabase", () => ({ createServiceClient: () => db.client }));
jest.mock("@/app/api/_middleware", () => ({
  ...jest.requireActual("@/app/api/_middleware"),
  verifyApiKey: async () => ({ org_id: ORG, user_id: "u1", role }),
}));
jest.mock("@/lib/serverErrors", () => ({ reportServerError: jest.fn() }));
const enqueued: Array<Record<string, unknown>> = [];
jest.mock("@/lib/queue", () => ({ enqueueScan: async (job: Record<string, unknown>) => { enqueued.push(job); } }));
const pending: Promise<unknown>[] = [];
jest.mock("@vercel/functions", () => ({ waitUntil: (p: Promise<unknown>) => { pending.push(p); } }));
jest.mock("@/lib/rateLimit", () => ({ checkRateLimit: async () => ({ success: true, headers: {} }), RATE_LIMITS: { webhook: {} } }));
jest.mock("@/lib/github", () => ({
  verifyWebhookSignature: () => true,
  getInstallationToken: async () => ({ token: "t" }),
  createCheckRun: async () => ({ id: 555 }),
  updateCheckRun: async () => ({}),
}));

const ORG = "11111111-1111-1111-1111-111111111111";
const SCAN = "22222222-2222-2222-2222-222222222222";
const minsAgo = (m: number) => new Date(Date.now() - m * 60_000).toISOString();
const rows = (t: string) => (db.client.from(t) as unknown as { rows: Record<string, unknown>[] }).rows;
const ev = (trace: string, kind: string, mins: number, extra: Record<string, unknown> = {}) =>
  ({ id: Math.floor(Math.random() * 1e9), org_id: ORG, trace_id: trace, kind, level: kind.endsWith("failed") ? "error" : "info", message: null, scan_id: null, delivery_id: null, repo: "o/api", pr_number: 7, ref_id: null, duration_ms: null, data: {}, created_at: minsAgo(mins), ...extra });

import { GET as traceGet } from "@/app/api/ops/trace/route";
import { GET as cronGet } from "@/app/api/cron/pipeline-health/route";
import { POST as webhookPost } from "@/app/api/webhook/github/route";

beforeEach(() => { role = "admin"; enqueued.length = 0; pending.length = 0; });

describe("GET /api/ops/trace", () => {
  const seed = () => {
    db = fakeSupabase({
      ops_events: [
        ev("ok-trace", "webhook.received", 30), ev("ok-trace", "scan.queued", 30), ev("ok-trace", "scan.started", 29),
        ev("ok-trace", "scan.completed", 28, { scan_id: SCAN }),
        ev("stuck-trace", "scan.queued", 40, { pr_number: 9 }),
        ev("err-trace", "api.error", 5, { ref_id: "3f9a1c22", repo: null, pr_number: null }),
        { ...ev("foreign", "scan.queued", 50), org_id: "99999999-9999-9999-9999-999999999999" },
      ],
      webhook_deliveries: [],
    });
  };
  const get = (q = "") => traceGet(new NextRequest(new URL(`/api/ops/trace${q ? `?q=${encodeURIComponent(q)}` : ""}`, "https://app.example")));

  it("lists recent traces with a status, plus pipeline health — this org only", async () => {
    seed();
    const body = await (await get()).json();
    const byId = Object.fromEntries(body.traces.map((t: { trace_id: string; status: string }) => [t.trace_id, t.status]));
    expect(byId).toEqual({ "ok-trace": "completed", "stuck-trace": "stuck", "err-trace": "error" });
    expect(body.health.stuck_scans.map((s: { trace_id: string }) => s.trace_id)).toEqual(["stuck-trace"]);
  });

  it("finds a trace by error reference, by PR and by scan id — returning the whole timeline", async () => {
    seed();
    expect((await (await get("3f9a1c22")).json()).traces.map((t: { trace_id: string }) => t.trace_id)).toEqual(["err-trace"]);
    const byPr = (await (await get("o/api#7")).json()).traces.find((t: { trace_id: string }) => t.trace_id === "ok-trace");
    expect(byPr.events.map((e: { kind: string }) => e.kind)).toEqual(["webhook.received", "scan.queued", "scan.started", "scan.completed"]);
    expect((await (await get(SCAN)).json()).traces[0]).toMatchObject({ trace_id: "ok-trace", scan_id: SCAN });
  });

  it("rejects a malformed query and non-reviewers", async () => {
    seed();
    expect((await get("not a valid query!")).status).toBe(400);
    role = "developer";
    expect((await get()).status).toBe(403);
  });
});

describe("daily pipeline-health job", () => {
  const run = (auth = `Bearer ${process.env.CRON_SECRET}`) => cronGet(new NextRequest(new URL("/api/cron/pipeline-health", "https://app.example"), { headers: { authorization: auth } }));
  beforeAll(() => { process.env.CRON_SECRET = "cron-test-secret"; });

  it("raises one pipeline alert per org per day, and purges events older than 30 days", async () => {
    db = fakeSupabase({
      organizations: [{ id: ORG }],
      ops_events: [ev("stuck-trace", "scan.queued", 40), ev("ancient", "scan.completed", 31 * 24 * 60)],
      webhook_deliveries: [], alerts: [],
    });
    expect((await run("Bearer nope")).status).toBe(401);
    expect(await (await run()).json()).toMatchObject({ alerts_raised: 1 });
    expect(rows("alerts")[0]).toMatchObject({ org_id: ORG, alert_type: "pipeline", status: "firing", title: "Scan pipeline: 1 scan stuck" });
    expect(rows("ops_events").some(e => e.trace_id === "ancient")).toBe(false);
    expect(await (await run()).json()).toMatchObject({ alerts_raised: 0 });     // already alerted today
  });
});

describe("GitHub webhook tracing", () => {
  it("uses GitHub's delivery id as the trace id, records the steps and hands the trace to the worker", async () => {
    db = fakeSupabase({ organizations: [{ id: ORG, github_org: "o" }], webhook_deliveries: [], ops_events: [] });
    const payload = { action: "opened", installation: { id: 42 }, repository: { full_name: "o/api" },
      pull_request: { number: 7, head: { sha: "abc123", ref: "feat" }, user: { login: "ana" } } };
    const res = await webhookPost(new NextRequest(new URL("/api/webhook/github", "https://app.example"), {
      method: "POST", body: JSON.stringify(payload),
      headers: { "x-github-event": "pull_request", "x-github-delivery": "0f0e7a5c-1111-4000-8000-abcdefabcdef", "x-hub-signature-256": "sha256=x" },
    }));
    expect(res.status).toBe(200);
    await Promise.all(pending);
    expect(enqueued[0]).toMatchObject({ trace_id: "0f0e7a5c-1111-4000-8000-abcdefabcdef", repo_full_name: "o/api", pr_number: 7 });
    const kinds = rows("ops_events").map(e => [e.kind, e.trace_id, e.org_id, e.repo, e.pr_number]);
    expect(kinds).toEqual([
      ["webhook.received", "0f0e7a5c-1111-4000-8000-abcdefabcdef", ORG, "o/api", 7],
      ["scan.queued", "0f0e7a5c-1111-4000-8000-abcdefabcdef", ORG, "o/api", 7],
    ]);
  });
});
