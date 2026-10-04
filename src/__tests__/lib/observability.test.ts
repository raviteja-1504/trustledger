/**
 * @jest-environment node
 *
 * Observability: trace context, log redaction, ops events, safeError's references, Sentry scrubbing, pipeline health.
 */
import { fakeSupabase } from "../helpers/fakeSupabase";

let db: ReturnType<typeof fakeSupabase>;
jest.mock("@/lib/supabase", () => ({ createServiceClient: () => db.client }));
const sentryReports: Array<{ err: unknown; ctx: Record<string, unknown> }> = [];
jest.mock("@/lib/serverErrors", () => ({ reportServerError: (err: unknown, ctx: Record<string, unknown>) => sentryReports.push({ err, ctx }) }));

import { logger, redact } from "@/lib/logger";
import { runWithTrace, annotateTrace, adoptTraceId, currentTrace, traceIdFrom } from "@/lib/trace";
import { recordEvent } from "@/lib/opsEvents";
import { safeError } from "@/lib/errors";
import { scrubEvent } from "@/lib/sentryScrub";
import { pipelineHealth } from "@/lib/pipelineHealth";

const rows = (t: string) => (db.client.from(t) as unknown as { rows: Record<string, unknown>[] }).rows;
const ORG = "11111111-1111-1111-1111-111111111111";
const SCAN = "22222222-2222-2222-2222-222222222222";

let out: string[];
beforeEach(() => {
  db = fakeSupabase({ ops_events: [] });
  sentryReports.length = 0;
  out = [];
  jest.spyOn(process.stdout, "write").mockImplementation(((s: string) => { out.push(String(s)); return true; }) as never);
  jest.spyOn(process.stderr, "write").mockImplementation(((s: string) => { out.push(String(s)); return true; }) as never);
  jest.spyOn(console, "log").mockImplementation((...a: unknown[]) => { out.push(a.join(" ")); });
  jest.spyOn(console, "warn").mockImplementation((...a: unknown[]) => { out.push(a.join(" ")); });
  jest.spyOn(console, "error").mockImplementation((...a: unknown[]) => { out.push(a.join(" ")); });
});
afterEach(() => jest.restoreAllMocks());

describe("logger", () => {
  it("never writes secrets — by key name or by token shape", () => {
    expect(redact({ authorization: "Bearer x", nested: { github_token: "y", api_key: "z" }, ok: "fine" }))
      .toEqual({ authorization: "[redacted]", nested: { github_token: "[redacted]", api_key: "[redacted]" }, ok: "fine" });
    const leaked = "failed with ghp_abcdefghijklmnopqrstuvwxyz0123 and tl_live_0123456789abcdef0123";
    expect(redact(leaked)).toBe("failed with [redacted] and [redacted]");
    logger.error("token ghs_abcdefghijklmnopqrstuvwx1234 rejected", { password: "hunter2" });
    expect(out.join("\n")).not.toMatch(/ghs_abcdef|hunter2/);
  });

  it("stamps the active trace on every line", () => {
    runWithTrace({ trace_id: "trace-abc-123", org_id: ORG }, () => {
      annotateTrace({ repo: "o/api", pr_number: 7 });
      logger.info("inside");
    });
    logger.info("outside");
    const inside = out.find(l => l.includes("inside"))!;
    expect(inside).toContain("trace-abc-123");
    expect(inside).toContain("o/api");
    expect(out.find(l => l.includes("outside"))).not.toContain("trace-abc-123");
  });
});

describe("trace context", () => {
  it("keeps a sane incoming request id, replaces anything else, and can adopt a queued job's id", () => {
    expect(traceIdFrom("abcd1234efgh")).toBe("abcd1234efgh");
    expect(traceIdFrom("bad id with spaces")).toMatch(/^[0-9a-f]{16}$/);
    expect(traceIdFrom(null)).toMatch(/^[0-9a-f]{16}$/);
    runWithTrace({ trace_id: "worker-local-id" }, () => {
      adoptTraceId("0f0e7a5c-1111-4000-8000-abcdefabcdef");
      expect(currentTrace()!.trace_id).toBe("0f0e7a5c-1111-4000-8000-abcdefabcdef");
    });
  });
});

describe("ops events", () => {
  it("record the step with the active trace's fields, redacted", async () => {
    await runWithTrace({ trace_id: "t-1-abcdef", org_id: ORG, repo: "o/api", pr_number: 7 }, async () => {
      annotateTrace({ scan_id: SCAN });
      await recordEvent({ kind: "scan.failed", message: "boom", duration_ms: 1234.4, data: { token: "secret", files: 3 } });
    });
    expect(rows("ops_events")[0]).toMatchObject({
      trace_id: "t-1-abcdef", kind: "scan.failed", level: "error", org_id: ORG, scan_id: SCAN, repo: "o/api", pr_number: 7,
      duration_ms: 1234, data: { token: "[redacted]", files: 3 },
    });
  });

  it("never break the caller when storage fails", async () => {
    db = { writes: [], client: { from: () => { throw new Error("db down"); } } } as never;
    await expect(recordEvent({ kind: "scan.started" })).resolves.toBeUndefined();
  });
});

describe("safeError", () => {
  it("returns a reference, records it on the timeline and reports server faults to Sentry", async () => {
    const res = await runWithTrace({ trace_id: "req-1234abcd", org_id: ORG }, async () => {
      const r = safeError(new Error("relation scans does not exist"), { code: "scan_lookup_failed", message: "Try again." });
      await new Promise(resolve => setImmediate(resolve));
      return r;
    });
    const body = await res.json();
    expect(res.headers.get("X-Ref-Id")).toBe(body.ref_id);
    expect(res.headers.get("X-Trace-Id")).toBe("req-1234abcd");
    expect(rows("ops_events")[0]).toMatchObject({ kind: "api.error", ref_id: body.ref_id, trace_id: "req-1234abcd", org_id: ORG });
    expect(sentryReports[0].ctx).toMatchObject({ code: "scan_lookup_failed", ref_id: body.ref_id });
  });

  it("client errors (4xx) are recorded but not sent to Sentry", async () => {
    safeError(new Error("bad input"), { code: "invalid", message: "No.", status: 400 });
    await new Promise(resolve => setImmediate(resolve));
    expect(rows("ops_events")).toHaveLength(1);
    expect(sentryReports).toHaveLength(0);
  });
});

describe("Sentry scrubbing", () => {
  it("strips who, cookies, auth headers, request bodies, emails and tokens", () => {
    const ev = scrubEvent({
      user: { id: "u1", email: "ana@acme.dev", ip_address: "1.2.3.4" },
      request: { headers: { authorization: "Bearer x", cookie: "sb=1", "user-agent": "UA" }, cookies: { sb: "1" }, data: "const secret = 1", url: "https://app/x?email=ana@acme.dev" },
      message: "failed for ana@acme.dev with ghp_abcdefghijklmnopqrstuvwxyz0123",
      exception: { values: [{ value: "token tl_live_0123456789abcdef0123 invalid" }] },
      extra: { password: "p", note: "bob@acme.dev" },
    });
    expect(ev.user).toEqual({ id: "u1" });
    expect(ev.request).toEqual({ headers: { "user-agent": "UA" }, url: "https://app/x?email=[email]" });
    expect(ev.message).toBe("failed for [email] with [redacted]");
    expect(ev.exception!.values![0].value).toBe("token [redacted] invalid");
    expect(ev.extra).toEqual({ password: "[redacted]", note: "[email]" });
  });
});

describe("pipeline health", () => {
  const minsAgo = (m: number) => new Date(Date.now() - m * 60_000).toISOString();
  it("finds scans queued 15+ minutes ago that never finished, and webhooks never processed", async () => {
    db = fakeSupabase({
      ops_events: [
        { org_id: ORG, trace_id: "stuck", kind: "scan.queued", repo: "o/api", pr_number: 7, created_at: minsAgo(40) },
        { org_id: ORG, trace_id: "done", kind: "scan.queued", repo: "o/api", pr_number: 8, created_at: minsAgo(50) },
        { org_id: ORG, trace_id: "done", kind: "scan.completed", repo: "o/api", pr_number: 8, created_at: minsAgo(49) },
        { org_id: ORG, trace_id: "fresh", kind: "scan.queued", repo: "o/api", pr_number: 9, created_at: minsAgo(3) },
        { org_id: ORG, trace_id: "bad", kind: "scan.queued", repo: "o/web", pr_number: 1, created_at: minsAgo(30) },
        { org_id: ORG, trace_id: "bad", kind: "scan.failed", repo: "o/web", pr_number: 1, created_at: minsAgo(29) },
        { org_id: ORG, trace_id: "r", kind: "api.error", created_at: minsAgo(5) },
        { org_id: "other-org", trace_id: "x", kind: "scan.queued", created_at: minsAgo(90) },
      ],
      webhook_deliveries: [
        { id: "d-old", org_id: ORG, repo_full_name: "o/api", event_type: "pull_request.opened", processed: false, created_at: minsAgo(30), error: null },
        { id: "d-new", org_id: ORG, repo_full_name: "o/api", event_type: "pull_request.opened", processed: false, created_at: minsAgo(2), error: null },
        { id: "d-ok", org_id: ORG, repo_full_name: "o/api", event_type: "pull_request.opened", processed: true, created_at: minsAgo(30), error: null },
      ],
    });
    const h = await pipelineHealth(db.client as never, ORG);
    expect(h.stuck_scans.map(s => s.trace_id)).toEqual(["stuck"]);
    expect(h.undelivered_webhooks.map(w => w.id)).toEqual(["d-old"]);
    expect(h).toMatchObject({ failed_scans_24h: 1, api_errors_24h: 1, completed_scans_24h: 1, events_available: true });
  });
});
