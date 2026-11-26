/**
 * @jest-environment node
 *
 * Outbound webhook retries: a failed delivery is stored with its original event and retried on the documented
 * schedule (5 min, 15 min, 1 h, 6 h, 24 h), re-sending that same event, and is abandoned after the 5th failed retry.
 */
import { NextRequest } from "next/server";
import { fakeSupabase } from "../helpers/fakeSupabase";
import { nextRetryAt, RETRY_DELAYS_MS } from "@/lib/webhookRetry";

const sent: Array<{ url: string; body: string }> = [];
let respond: () => { ok: boolean; status: number } = () => ({ ok: false, status: 500 });
jest.mock("@/lib/safeFetch", () => ({
  safeFetch: async (url: string, init: { body: string }) => { sent.push({ url, body: init.body }); return respond(); },
}));

let fake: ReturnType<typeof fakeSupabase>;
jest.mock("@/lib/supabase", () => ({ createServiceClient: () => fake.client }));

import { GET } from "@/app/api/cron/webhook-retry/route";
import { fireOrgWebhooks } from "@/lib/outboundWebhook";

const MIN = 60_000;
const event = { id: "evt-1", type: "violation.opened", created_at: "2026-11-27T00:00:00.000Z", org_id: "o1", data: { n: 7 } };
const hook = { id: "h1", org_id: "o1", url: "https://hooks.example.com/in", secret: "s", events: ["violation.opened"], enabled: true };
const failedRow = (over: Record<string, unknown> = {}) => ({
  id: "f1", webhook_id: "h1", org_id: "o1", event_id: "evt-1", event_type: "violation.opened", payload: event,
  retry_count: 0, next_retry_at: new Date(Date.now() - MIN).toISOString(), permanently_failed: false, ...over,
});
const run = () => GET(new NextRequest("https://app.example/api/cron/webhook-retry", { headers: { authorization: "Bearer topsecret" } }));
const rows = () => fake.tables.webhook_failed_deliveries;

beforeEach(() => {
  process.env.CRON_SECRET = "topsecret";
  sent.length = 0;
  respond = () => ({ ok: false, status: 500 });
  fake = fakeSupabase({ webhook_configs: [{ ...hook }], webhook_failed_deliveries: [failedRow()], webhook_delivery_log: [] });
});

describe("schedule", () => {
  it("is 5m, 15m, 1h, 6h, 24h, then nothing", () => {
    const now = new Date("2026-11-27T00:00:00Z");
    expect([0, 1, 2, 3, 4].map(n => nextRetryAt(n, now)!.getTime() - now.getTime())).toEqual([5 * MIN, 15 * MIN, 60 * MIN, 360 * MIN, 1440 * MIN]);
    expect(nextRetryAt(5, now)).toBeNull();
    expect(RETRY_DELAYS_MS).toHaveLength(5);
  });
});

describe("retry job", () => {
  it("re-sends the original event, not a generic ping", async () => {
    await run();
    expect(sent).toHaveLength(1);
    expect(JSON.parse(sent[0].body)).toEqual(event);
  });

  it("removes the record when the retry succeeds", async () => {
    respond = () => ({ ok: true, status: 200 });
    const res = await (await run()).json();
    expect(res).toMatchObject({ retried: 1, succeeded: 1 });
    expect(rows()).toHaveLength(0);
  });

  it("schedules the next retry on the backoff after a failure", async () => {
    const before = Date.now();
    await run();
    const r = rows()[0] as { retry_count: number; next_retry_at: string; permanently_failed: boolean };
    expect(r.retry_count).toBe(1);
    expect(r.permanently_failed).toBe(false);
    const wait = new Date(r.next_retry_at).getTime() - before;
    expect(wait).toBeGreaterThan(14 * MIN);
    expect(wait).toBeLessThan(16 * MIN);
  });

  it("gives up after the 5th failed retry and never sends it again", async () => {
    rows()[0] = failedRow({ retry_count: 4 });
    await run();
    const r = rows()[0] as { retry_count: number; next_retry_at: string | null; permanently_failed: boolean };
    expect(r).toMatchObject({ retry_count: 5, next_retry_at: null, permanently_failed: true });
    sent.length = 0;
    await run();
    expect(sent).toHaveLength(0);
  });

  it("leaves deliveries that are not due yet alone", async () => {
    rows()[0] = failedRow({ next_retry_at: new Date(Date.now() + 10 * MIN).toISOString() });
    await run();
    expect(sent).toHaveLength(0);
  });

  it("abandons a delivery whose webhook was disabled", async () => {
    (fake.tables.webhook_configs[0] as { enabled: boolean }).enabled = false;
    await run();
    expect(sent).toHaveLength(0);
    expect(rows()[0]).toMatchObject({ permanently_failed: true });
  });

  it("does not retry a delivery another run has claimed", async () => {
    // the first run claims the row by pushing next_retry_at out; a second, overlapping read of the stale value finds nothing to claim
    await run();
    sent.length = 0;
    await run();
    expect(sent).toHaveLength(0);
  });
});

describe("recording failures", () => {
  it("keeps a failed first delivery, with its payload, for retry", async () => {
    fake = fakeSupabase({ organizations: [{ id: "o1" }], webhook_configs: [{ ...hook }], webhook_failed_deliveries: [] });
    await fireOrgWebhooks(fake.client, "o1", { type: "violation.opened", data: { n: 7 } });
    expect(rows()).toHaveLength(1);
    const r = rows()[0] as { payload: { data: unknown; id: string }; event_id: string; retry_count: number; webhook_id: string };
    expect(r.webhook_id).toBe("h1");
    expect(r.payload.data).toEqual({ n: 7 });
    expect(r.event_id).toBe(r.payload.id);
    expect(r.retry_count).toBe(0);
  });

  it("stores nothing when the delivery succeeds", async () => {
    respond = () => ({ ok: true, status: 200 });
    fake = fakeSupabase({ organizations: [{ id: "o1" }], webhook_configs: [{ ...hook }], webhook_failed_deliveries: [] });
    await fireOrgWebhooks(fake.client, "o1", { type: "violation.opened", data: {} });
    expect(rows()).toHaveLength(0);
  });

  it("does not queue a delivery to a blocked URL", async () => {
    fake = fakeSupabase({ organizations: [{ id: "o1" }], webhook_configs: [{ ...hook, url: "http://127.0.0.1/x" }], webhook_failed_deliveries: [] });
    await fireOrgWebhooks(fake.client, "o1", { type: "violation.opened", data: {} });
    expect(rows()).toHaveLength(0);
  });
});
