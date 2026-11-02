/**
 * @jest-environment node
 *
 * The status bar's API check (lib/apiHealth.ts): a slow or failed answer is retried before the API is called
 * offline, the viewer's own lost connection is told apart, and an offline API is re-checked soon.
 */
import fs from "fs";
import path from "path";
import { HEALTH_TIMEOUT_MS, RECHECK_OFFLINE_MS, RECHECK_ONLINE_MS, probeApi, recheckAfter } from "@/lib/apiHealth";

const answers = (...oks: Array<boolean | "throw">) => {
  const calls: Array<{ url: string; cache: string }> = [];
  const fetch = jest.fn(async (url: string, init: { cache: RequestCache }) => {
    calls.push({ url, cache: init.cache });
    const next = oks.shift();
    if (next === "throw") throw new Error("timeout");
    return { ok: !!next };
  });
  return { fetch, calls };
};
const noWait = async () => {};

describe("probeApi", () => {
  it("one good answer: online, without a retry", async () => {
    const { fetch, calls } = answers(true);
    expect(await probeApi({ fetch, wait: noWait, isOnline: () => true })).toBe("online");
    expect(calls).toEqual([{ url: "/healthz", cache: "no-store" }]);
  });

  it("a timeout (a cold start) followed by a good answer is online, not offline", async () => {
    const { fetch } = answers("throw", true);
    expect(await probeApi({ fetch, wait: noWait, isOnline: () => true })).toBe("online");
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it("offline only after the retry fails too", async () => {
    expect(await probeApi({ ...answers(false, false), wait: noWait, isOnline: () => true })).toBe("offline");
    expect(await probeApi({ ...answers("throw", "throw"), wait: noWait, isOnline: () => true })).toBe("offline");
  });

  it("the viewer's own connection being down is not 'API offline'", async () => {
    const { fetch } = answers();
    expect(await probeApi({ fetch, wait: noWait, isOnline: () => false })).toBe("no-network");
    expect(fetch).not.toHaveBeenCalled();
  });

  it("allows a cold start: the time limit is well above the old 3 seconds", () => {
    expect(HEALTH_TIMEOUT_MS).toBeGreaterThanOrEqual(8000);
  });

  it("re-checks soon while offline, rarely while online", () => {
    expect(recheckAfter("online")).toBe(RECHECK_ONLINE_MS);
    expect(recheckAfter("offline")).toBe(RECHECK_OFFLINE_MS);
    expect(recheckAfter("no-network")).toBe(RECHECK_OFFLINE_MS);
    expect(RECHECK_OFFLINE_MS).toBeLessThan(RECHECK_ONLINE_MS / 5);
  });
});

describe("server start-up", () => {
  it("doesn't load the scan engines on every function's cold start (the scan routes wait for them themselves)", () => {
    const src = fs.readFileSync(path.join(__dirname, "../../instrumentation.ts"), "utf8");
    expect(src).not.toMatch(/import\(["']\.\/lib\/astTaint/);
    expect(src).not.toMatch(/warm\w*TaintEngine\(/);
  });

  it("every scanning route waits for the engines before scanning", () => {
    for (const route of ["app/api/scan-worker/route.ts", "app/api/scans/route.ts", "app/api/scans/[id]/route.ts", "app/api/webhook/gitlab/route.ts", "app/api/webhook/bitbucket/route.ts"]) {
      expect(fs.readFileSync(path.join(__dirname, "../../", route), "utf8")).toMatch(/await ensureTaintEngines\(/);
    }
  });
});
