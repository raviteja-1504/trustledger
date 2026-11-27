/**
 * @jest-environment node
 *
 * P0.3: a production deployment with missing configuration fails, it does not run. The service client used to fall back to a stub
 * that answers every query with "no data, no error" (so writes "succeeded" and reads were empty) or to the anon key.
 */
import { NextRequest } from "next/server";

// the real client needs a WebSocket implementation Node 18 lacks; only its construction matters here
jest.mock("@supabase/supabase-js", () => ({ createClient: () => ({ from: () => ({}), auth: {} }) }));

const KEYS = ["NODE_ENV", "VERCEL_ENV", "VERCEL", "NEXT_PUBLIC_SKIP_AUTH", "NEXT_PUBLIC_SUPABASE_URL", "NEXT_PUBLIC_SUPABASE_ANON_KEY", "SUPABASE_SERVICE_ROLE_KEY", "TRUSTED_PROXY_HOPS"] as const;
const saved: Record<string, string | undefined> = {};
const env = process.env as Record<string, string | undefined>;
const set = (vals: Partial<Record<(typeof KEYS)[number], string>>) => { for (const k of KEYS) delete env[k]; for (const [k, v] of Object.entries(vals)) env[k] = v; };
beforeEach(() => { for (const k of KEYS) saved[k] = env[k]; jest.resetModules(); });
afterEach(() => { for (const k of KEYS) { if (saved[k] === undefined) delete env[k]; else env[k] = saved[k]; } });

const load = async () => (await import("@/lib/supabase")).createServiceClient;
const CONFIGURED = { NEXT_PUBLIC_SUPABASE_URL: "https://abc.supabase.co", NEXT_PUBLIC_SUPABASE_ANON_KEY: "anon" };

describe("createServiceClient", () => {
  it("throws in production when Supabase is not configured (no stub that reports success)", async () => {
    set({ NODE_ENV: "production" });
    expect((await load())).toThrow(/supabase_not_configured/);
  });

  it("throws in production when only the service key is missing (no silent anon-key fallback)", async () => {
    set({ NODE_ENV: "production", ...CONFIGURED });
    expect((await load())).toThrow(/supabase_service_key_missing/);
  });

  it("also throws when VERCEL_ENV says production, and the demo switch changes nothing", async () => {
    set({ NODE_ENV: "test", VERCEL_ENV: "production", NEXT_PUBLIC_SKIP_AUTH: "true" });
    expect((await load())).toThrow(/supabase_not_configured/);
  });

  it("works in production with full configuration", async () => {
    set({ NODE_ENV: "production", ...CONFIGURED, SUPABASE_SERVICE_ROLE_KEY: "service" });
    expect(typeof (await load())().from).toBe("function");
  });

  it("outside production the stub still serves local development and the demo", async () => {
    set({ NODE_ENV: "development", NEXT_PUBLIC_SKIP_AUTH: "true" });
    const client = (await load())();
    expect(await (client.from("scans").select("*") as unknown as PromiseLike<{ data: unknown; error: unknown }>)).toMatchObject({ data: null, error: null });
  });

  it("outside production a missing service key only warns", async () => {
    set({ NODE_ENV: "test", ...CONFIGURED });
    const warn = jest.spyOn(console, "error").mockImplementation(() => {});
    expect(() => (jest.requireActual("@/lib/supabase") as { createServiceClient: () => unknown }).createServiceClient()).not.toThrow();
    warn.mockRestore();
  });
});

describe("the demo scan's rate limit uses the trusted client address", () => {
  const checkRateLimit = jest.fn(async (_ip: string) => ({ success: false, headers: {} }));

  const callWith = async (headers: Record<string, string>) => {
    jest.resetModules();
    jest.doMock("@/lib/rateLimit", () => ({ checkRateLimit: (ip: string) => checkRateLimit(ip) }));
    const { POST } = await import("@/app/api/demo/scan/route");
    await POST(new NextRequest("https://app.example/api/demo/scan", { method: "POST", headers, body: "{}" }));
    return checkRateLimit.mock.calls[checkRateLimit.mock.calls.length - 1][0];
  };

  it("a client-written x-real-ip or left-most x-forwarded-for does not choose the key", async () => {
    set({ NODE_ENV: "test" });
    const ip = await callWith({ "x-real-ip": "6.6.6.6", "x-forwarded-for": "7.7.7.7, 203.0.113.9" });
    expect(ip).toBe("203.0.113.9");                       // the entry the proxy appended, not what the caller wrote
  });

  it("on Vercel it is the platform's own address", async () => {
    set({ NODE_ENV: "test", VERCEL: "1" });
    expect(await callWith({ "x-vercel-forwarded-for": "198.51.100.4", "x-forwarded-for": "7.7.7.7" })).toBe("198.51.100.4");
  });
});
