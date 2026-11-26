/**
 * @jest-environment node
 *
 * The server fetches webhook / alert URLs that users type in. Found by the engine's own self-scan once it understood
 * Fetch-API request bodies: the test-webhook endpoint could be pointed at cloud metadata or localhost.
 *
 * Three layers: isPublicHttpUrl vets the URL's host name (here); the callers send only through safeFetch and treat what
 * comes back correctly (here, with safeFetch mocked); safeFetch itself vets the address the connection really goes to and
 * never follows a redirect (lib/safeFetch.test.ts, against real servers).
 */
import { isPublicHttpUrl } from "@/lib/outboundUrl";
import { deliverWebhook } from "@/lib/outboundWebhook";
import { sendSlackAlert, sendTeamsAlert, type AlertPayload } from "@/lib/alertDelivery";
import { safeFetch, OutboundBlockedError } from "@/lib/safeFetch";

jest.mock("@/lib/safeFetch", () => {
  const actual = jest.requireActual("@/lib/safeFetch");
  return { ...actual, safeFetch: jest.fn() };
});
const safeFetchMock = safeFetch as jest.MockedFunction<typeof safeFetch>;
const reply = (status: number) => ({ ok: status >= 200 && status < 300, status }) as unknown as Response;

describe("isPublicHttpUrl", () => {
  it.each([
    "https://hooks.slack.com/services/T000/B000/XXXX", "https://example.com/webhook", "http://hooks.example.org:8080/x",
    "https://outlook.office.com/webhook/abc", "https://8.8.8.8/hook", "https://[2606:4700:4700::1111]/hook",
  ])("allows %s", u => expect(isPublicHttpUrl(u)).toBe(true));

  it.each([
    "http://169.254.169.254/latest/meta-data/", "http://localhost:6379", "http://127.0.0.1/admin", "http://10.0.0.5/", "http://172.16.0.1/",
    "http://172.31.255.255/", "http://192.168.1.1/", "http://100.64.0.1/", "http://0.0.0.0/", "http://[::1]/", "http://[fd00::1]/", "http://[fe80::1]/",
    "http://[::ffff:10.0.0.1]/", "http://2130706433/", "http://0x7f.0.0.1/", "http://intranet/", "http://db.internal/", "http://printer.local/",
    "http://metadata.google.internal/computeMetadata/v1/", "file:///etc/passwd", "ftp://example.com/x", "gopher://example.com/", "not a url", "",
    "https://user:pass@example.com/", "http://LOCALHOST/", "http://localhost./",
  ])("refuses %s", u => expect(isPublicHttpUrl(u)).toBe(false));

  it("does not take a public look-alike for a private range", () => {
    expect(isPublicHttpUrl("http://172.15.0.1/")).toBe(true);   // just outside 172.16/12
    expect(isPublicHttpUrl("http://172.32.0.1/")).toBe(true);
    expect(isPublicHttpUrl("http://100.63.0.1/")).toBe(true);   // just outside CGNAT
  });
});

describe("delivery refuses private destinations without making a request", () => {
  beforeEach(() => { safeFetchMock.mockReset(); safeFetchMock.mockResolvedValue(reply(200)); });
  const alert: AlertPayload = { alert_id: "a1", severity: "P1", title: "t", body: "b", org_name: "Acme", app_url: "https://app.example.com" };
  const event = { id: "e1", type: "scan.completed", created_at: "2026-11-12T00:00:00Z", data: {} } as unknown as Parameters<typeof deliverWebhook>[1];

  it("a webhook to cloud metadata is not sent, and says why", async () => {
    const r = await deliverWebhook({ url: "http://169.254.169.254/latest/meta-data/", events: ["scan.completed"], enabled: true } as Parameters<typeof deliverWebhook>[0], event);
    expect(safeFetchMock).not.toHaveBeenCalled();
    expect(r).toMatchObject({ success: false, error: "webhook_url_not_allowed" });
  });
  it("a webhook to a public host is sent, through safeFetch", async () => {
    const r = await deliverWebhook({ url: "https://hooks.example.com/x", events: ["scan.completed"], enabled: true } as Parameters<typeof deliverWebhook>[0], event);
    expect(safeFetchMock).toHaveBeenCalledTimes(1);
    expect(safeFetchMock.mock.calls[0][0]).toBe("https://hooks.example.com/x");
    expect(safeFetchMock.mock.calls[0][1]).toMatchObject({ method: "POST", headers: expect.objectContaining({ "X-TrustLedger-Event": "scan.completed" }) });
    expect(r.success).toBe(true);
  });
  it("Slack and Teams alerts to a private URL are not sent", async () => {
    expect(await sendSlackAlert("http://localhost:8080/hook", alert)).toBe(false);
    expect(await sendTeamsAlert("http://10.1.2.3/hook", alert)).toBe(false);
    expect(safeFetchMock).not.toHaveBeenCalled();
  });
});

describe("what the callers do with the answer", () => {
  beforeEach(() => safeFetchMock.mockReset());
  const alert: AlertPayload = { alert_id: "a1", severity: "P1", title: "t", body: "b", org_name: "Acme", app_url: "https://app.example.com" };
  const event = { id: "e1", type: "scan.completed", created_at: "2026-11-12T00:00:00Z", data: {} } as unknown as Parameters<typeof deliverWebhook>[1];
  const hook = { url: "https://hooks.example.com/x", events: ["scan.completed"], enabled: true } as Parameters<typeof deliverWebhook>[0];

  it("a 302 reply (a redirect safeFetch did not follow) is a failed delivery, not a success", async () => {
    safeFetchMock.mockResolvedValue(reply(302));
    expect(await deliverWebhook(hook, event)).toMatchObject({ success: false, status_code: 302 });
    expect(await sendSlackAlert("https://hooks.example.com/slack", alert)).toBe(false);
    expect(await sendTeamsAlert("https://hooks.example.com/teams", alert)).toBe(false);
  });

  it("an address that resolves to a private range is reported as a failed delivery, never thrown", async () => {
    safeFetchMock.mockRejectedValue(new OutboundBlockedError("address_not_allowed", "hooks.example.com resolves to a private address (10.0.0.9), so the request was not sent"));
    expect(await deliverWebhook(hook, event)).toMatchObject({ success: false, status_code: null, error: expect.stringContaining("private address") });
    expect(await sendSlackAlert("https://hooks.example.com/slack", alert)).toBe(false);
    expect(await sendTeamsAlert("https://hooks.example.com/teams", alert)).toBe(false);
  });

  it("a 2xx reply is a success", async () => {
    safeFetchMock.mockResolvedValue(reply(204));
    expect(await deliverWebhook(hook, event)).toMatchObject({ success: true, status_code: 204 });
    expect(await sendSlackAlert("https://hooks.example.com/slack", alert)).toBe(true);
    expect(await sendTeamsAlert("https://hooks.example.com/teams", alert)).toBe(true);
  });
});
