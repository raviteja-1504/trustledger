/**
 * @jest-environment node
 *
 * Operator alerts: sent only when a webhook is configured, only to a public https address, at most once per kind and organisation
 * per window, never throwing, and never carrying customer data.
 */
const safeFetch = jest.fn();
jest.mock("@/lib/safeFetch", () => ({ safeFetch: (...a: unknown[]) => safeFetch(...a) }));
jest.mock("@/lib/logger", () => ({ logger: { error: jest.fn(), warn: jest.fn(), info: jest.fn() } }));

import { notifyOps, opsAlertText, resetOpsAlertState } from "@/lib/opsAlert";

const URL_ENV = "https://hooks.example.com/services/T0/B0/xyz";
const T0 = Date.parse("2026-11-29T12:00:00Z");
const sentText = (i = 0) => JSON.parse((safeFetch.mock.calls[i][1] as { body: string }).body).text as string;

beforeEach(() => { resetOpsAlertState(); safeFetch.mockReset(); safeFetch.mockResolvedValue({ ok: true, status: 200 }); process.env.OPS_ALERT_WEBHOOK_URL = URL_ENV; });
afterAll(() => { delete process.env.OPS_ALERT_WEBHOOK_URL; });

describe("notifyOps", () => {
  it("does nothing, and says so, without a webhook configured", async () => {
    delete process.env.OPS_ALERT_WEBHOOK_URL;
    expect(await notifyOps("scan_job_dead", { org_id: "o1" }, T0)).toBe(false);
    expect(safeFetch).not.toHaveBeenCalled();
  });

  it("posts a Slack-compatible message with the severity, a fixed sentence and the opaque ids", async () => {
    expect(await notifyOps("scan_job_dead", { org_id: "11111111-1111-4111-8111-111111111111", job_id: "j-9", attempts: 4 }, T0)).toBe(true);
    expect(safeFetch).toHaveBeenCalledTimes(1);
    expect(safeFetch.mock.calls[0][0]).toBe(URL_ENV);
    expect(sentText()).toBe("[P2] TrustLedger: A scan job ran out of attempts and needs replaying (org_id=11111111-1111-4111-8111-111111111111, job_id=j-9, attempts=4)");
  });

  it("audit failures are P1", () => {
    expect(opsAlertText("audit_write_failed", { org_id: "o", event_type: "api_key_created" })).toMatch(/^\[P1\]/);
  });

  it("never puts customer data in a message, whatever it is given", async () => {
    await notifyOps("integration_gave_up", {
      org_id: "o1", webhook_id: "w1", repo: "acme/secret-repo", email: "ceo@acme.com", payload: { token: "ghp_abc" }, url: "https://hooks.acme.com/in?token=s3cret", error: "boom at /src/auth.ts", count: { nested: 1 },
    }, T0);
    const text = sentText();
    for (const leaked of ["acme/secret-repo", "ceo@acme.com", "ghp_abc", "s3cret", "auth.ts", "boom"]) expect(text).not.toContain(leaked);
    expect(text).toContain("org_id=o1");
    expect(text).toContain("webhook_id=w1");
  });

  it("sends the same alert for the same organisation only once per window, but another organisation or kind separately", async () => {
    await notifyOps("scan_job_dead", { org_id: "o1" }, T0);
    expect(await notifyOps("scan_job_dead", { org_id: "o1" }, T0 + 60_000)).toBe(false);
    await notifyOps("scan_job_dead", { org_id: "o2" }, T0 + 60_000);
    await notifyOps("audit_write_failed", { org_id: "o1" }, T0 + 60_000);
    expect(safeFetch).toHaveBeenCalledTimes(3);
    // after the window it is sent again
    expect(await notifyOps("scan_job_dead", { org_id: "o1" }, T0 + 16 * 60_000)).toBe(true);
  });

  it("a flood is capped: at most 20 distinct alerts per window per instance", async () => {
    for (let i = 0; i < 40; i++) await notifyOps("scan_job_dead", { org_id: `o${i}` }, T0);
    expect(safeFetch).toHaveBeenCalledTimes(20);
  });

  it("never throws: a refused address, a network error or a non-2xx just return false", async () => {
    safeFetch.mockRejectedValueOnce(new Error("blocked: private address"));
    expect(await notifyOps("queue_delayed", {}, T0)).toBe(false);
    resetOpsAlertState();
    safeFetch.mockResolvedValueOnce({ ok: false, status: 500 });
    expect(await notifyOps("queue_delayed", {}, T0)).toBe(false);
  });

  it("goes through the guarded fetch with a short timeout (an address pointing inside the network is refused there)", async () => {
    await notifyOps("database_unavailable", {}, T0);
    expect(safeFetch.mock.calls[0][1]).toMatchObject({ method: "POST", timeoutMs: 4000 });
  });
});
