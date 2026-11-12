/**
 * @jest-environment node
 *
 * SSO is switched off for now. With it off, the check that runs on EVERY authenticated API request (is this organisation enforcing SSO?)
 * reads nothing: it used to cost a Redis command per request, the largest share of the project's commands.
 */
const cached = jest.fn(async (_k: string, _t: number, fn: () => Promise<unknown>) => fn());
jest.mock("@/lib/cache", () => ({ cached: (...a: [string, number, () => Promise<unknown>]) => cached(...a), cacheDel: jest.fn(async () => {}) }));

import { ssoEnforcement, ssoEnabled } from "@/lib/ssoMembership";

const from = jest.fn(() => { throw new Error("the database must not be read"); });
const db = { from } as unknown as Parameters<typeof ssoEnforcement>[0];
const saved = process.env.ENABLE_SSO;
afterEach(() => { if (saved === undefined) delete process.env.ENABLE_SSO; else process.env.ENABLE_SSO = saved; jest.clearAllMocks(); });

describe("SSO off (the default)", () => {
  it("is off unless ENABLE_SSO is exactly true", () => {
    delete process.env.ENABLE_SSO; expect(ssoEnabled()).toBe(false);
    process.env.ENABLE_SSO = "1"; expect(ssoEnabled()).toBe(false);
    process.env.ENABLE_SSO = "false"; expect(ssoEnabled()).toBe(false);
    process.env.ENABLE_SSO = "true"; expect(ssoEnabled()).toBe(true);
  });

  it("enforcement is never required, and neither the cache nor the database is touched", async () => {
    delete process.env.ENABLE_SSO;
    expect(await ssoEnforcement(db, "org-1")).toEqual({ enforce: false, provider_id: null });
    expect(cached).not.toHaveBeenCalled();
    expect(from).not.toHaveBeenCalled();
  });

  it("switched on, it reads (through the cache) as before", async () => {
    process.env.ENABLE_SSO = "true";
    const maybeSingle = async () => ({ data: { enforce_sso: true, provider_id: "idp-1" }, error: null });
    const chain = { select: () => chain, eq: () => chain, maybeSingle };
    const live = { from: () => chain } as unknown as Parameters<typeof ssoEnforcement>[0];
    expect(await ssoEnforcement(live, "org-1")).toEqual({ enforce: true, provider_id: "idp-1" });
    expect(cached).toHaveBeenCalledTimes(1);
  });
});
