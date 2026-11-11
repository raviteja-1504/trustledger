/**
 * @jest-environment node
 *
 * verifyInstallationAccess: the id in the install callback's URL is trusted only if GitHub says the person who approved the
 * install (identified by the one-time code) can access that installation. Fails closed.
 */
import { verifyInstallationAccess } from "@/lib/githubUserAuth";

const fetchMock = jest.fn();
const json = (body: unknown, ok = true) => ({ ok, status: ok ? 200 : 401, json: async () => body });
beforeEach(() => {
  process.env.GITHUB_APP_CLIENT_ID = "Iv1.test"; process.env.GITHUB_APP_CLIENT_SECRET = "secret\r";
  fetchMock.mockReset(); (global as unknown as { fetch: unknown }).fetch = fetchMock;
});
const happy = (ids: number[]) => fetchMock.mockImplementation(async (url: string) =>
  url.includes("login/oauth/access_token") ? json({ access_token: "ghu_x" }) : json({ installations: ids.map(id => ({ id })) }));

describe("verifyInstallationAccess", () => {
  it("ok when the installation is in the person's list; the code is exchanged with the app's client id and secret", async () => {
    happy([1, 777]);
    expect(await verifyInstallationAccess("code1", 777)).toEqual({ ok: true });
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("https://github.com/login/oauth/access_token");
    expect(JSON.parse(init.body)).toEqual({ client_id: "Iv1.test", client_secret: "secret", code: "code1" });
    expect(fetchMock.mock.calls[1][1].headers.Authorization).toBe("Bearer ghu_x");
  });

  it("someone else's installation id is refused", async () => {
    happy([1, 2]);
    expect(await verifyInstallationAccess("code1", 999)).toEqual({ ok: false, reason: "not_accessible" });
  });

  it("finds an installation on a later page", async () => {
    let page = 0;
    fetchMock.mockImplementation(async (url: string) => {
      if (url.includes("access_token")) return json({ access_token: "t" });
      page++;
      return json({ installations: page === 1 ? Array.from({ length: 100 }, (_, i) => ({ id: i + 1 })) : [{ id: 4242 }] });
    });
    expect(await verifyInstallationAccess("c", 4242)).toEqual({ ok: true });
  });

  it("no code, missing credentials, a bad id: refused without calling GitHub", async () => {
    expect(await verifyInstallationAccess(null, 5)).toEqual({ ok: false, reason: "no_code" });
    expect(await verifyInstallationAccess("c", NaN)).toEqual({ ok: false, reason: "not_accessible" });
    delete process.env.GITHUB_APP_CLIENT_SECRET;
    expect(await verifyInstallationAccess("c", 5)).toEqual({ ok: false, reason: "not_configured" });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("a rejected or errored code exchange, or a failed lookup, is not verified", async () => {
    fetchMock.mockResolvedValue(json({ error: "bad_verification_code" }));            // 200 but no token
    expect(await verifyInstallationAccess("c", 5)).toEqual({ ok: false, reason: "exchange_failed" });
    fetchMock.mockResolvedValue(json({}, false));
    expect(await verifyInstallationAccess("c", 5)).toEqual({ ok: false, reason: "exchange_failed" });
    fetchMock.mockRejectedValue(new Error("network"));
    expect(await verifyInstallationAccess("c", 5)).toEqual({ ok: false, reason: "exchange_failed" });
    fetchMock.mockImplementation(async (url: string) => url.includes("access_token") ? json({ access_token: "t" }) : json({}, false));
    expect(await verifyInstallationAccess("c", 5)).toEqual({ ok: false, reason: "lookup_failed" });
  });
});
