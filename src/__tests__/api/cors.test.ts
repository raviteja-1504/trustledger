/**
 * @jest-environment node
 *
 * API CORS: default-deny allowlist, preflights answered before auth, no wildcard.
 */
import { NextRequest } from "next/server";

const ENV = ["NODE_ENV", "NEXT_PUBLIC_SKIP_AUTH", "NEXT_PUBLIC_SUPABASE_URL", "NEXT_PUBLIC_SUPABASE_ANON_KEY", "NEXT_PUBLIC_APP_URL", "API_CORS_ALLOWED_ORIGINS"];
const saved: Record<string, string | undefined> = {};
const env = process.env as Record<string, string | undefined>;
beforeEach(() => {
  for (const k of ENV) saved[k] = env[k];
  env.NEXT_PUBLIC_SKIP_AUTH = "false"; env.NEXT_PUBLIC_SUPABASE_URL = "https://abc.supabase.co"; env.NEXT_PUBLIC_SUPABASE_ANON_KEY = "anon";
  env.NEXT_PUBLIC_APP_URL = "https://app.trustledger.dev/"; env.API_CORS_ALLOWED_ORIGINS = "https://ci.partner.io, https://tools.example.com";
  jest.resetModules();
});
afterEach(() => { for (const k of ENV) { if (saved[k] === undefined) delete env[k]; else env[k] = saved[k]; } });

const call = async (method: string, origin?: string, path = "/api/scans") => {
  const { middleware } = await import("@/middleware");
  return middleware(new NextRequest(new URL(path, "https://app.trustledger.dev"), { method, headers: origin ? { origin } : {} }));
};

describe("preflight", () => {
  it.each(["https://app.trustledger.dev", "https://ci.partner.io", "https://tools.example.com"])("answers %s with 204 and CORS headers", async origin => {
    const res = await call("OPTIONS", origin);
    expect(res.status).toBe(204);
    expect(res.headers.get("access-control-allow-origin")).toBe(origin);
    expect(res.headers.get("access-control-allow-methods")).toContain("POST");
    expect(res.headers.get("access-control-allow-headers")).toContain("X-TrustLedger-Key");
    expect(res.headers.get("vary")).toContain("Origin");
    expect(res.headers.get("access-control-allow-credentials")).toBeNull();
  });

  it("refuses an origin that is not allowed, with no CORS headers", async () => {
    const res = await call("OPTIONS", "https://evil.example");
    expect(res.status).toBe(403);
    expect(res.headers.get("access-control-allow-origin")).toBeNull();
  });

  it("refuses a preflight with no Origin", async () => {
    expect((await call("OPTIONS")).status).toBe(403);
  });

  it("is answered without credentials, even on a path that needs auth", async () => {
    expect((await call("OPTIONS", "https://ci.partner.io", "/api/orgs/delete")).status).toBe(204);
  });

  it("does not treat a look-alike origin as allowed", async () => {
    expect((await call("OPTIONS", "https://app.trustledger.dev.evil.example")).status).toBe(403);
    expect((await call("OPTIONS", "http://app.trustledger.dev")).status).toBe(403);
  });
});

describe("actual requests", () => {
  it("echo an allowed origin, never a wildcard", async () => {
    const res = await call("POST", "https://ci.partner.io");
    expect(res.headers.get("access-control-allow-origin")).toBe("https://ci.partner.io");
    expect(res.headers.get("vary")).toContain("Origin");
  });

  it("get no CORS headers for a disallowed origin", async () => {
    const res = await call("POST", "https://evil.example");
    expect(res.headers.get("access-control-allow-origin")).toBeNull();
    expect(res.headers.get("vary")).toContain("Origin");
  });

  it("are unaffected without an Origin header (server-to-server)", async () => {
    const res = await call("POST");
    expect(res.headers.get("access-control-allow-origin")).toBeNull();
  });

  it("also apply to middleware error responses (413)", async () => {
    const { middleware } = await import("@/middleware");
    const res = await middleware(new NextRequest("https://app.trustledger.dev/api/scans", {
      method: "POST", headers: { origin: "https://ci.partner.io", "content-length": String(50 * 1024 * 1024) },
    }));
    expect(res.status).toBe(413);
    expect(res.headers.get("access-control-allow-origin")).toBe("https://ci.partner.io");
  });

  it("never emit * (also in production)", async () => {
    env.NODE_ENV = "production";
    delete env.API_CORS_ALLOWED_ORIGINS; delete env.NEXT_PUBLIC_APP_URL;
    const res = await call("POST", "https://anyone.example");
    expect(res.headers.get("access-control-allow-origin")).toBeNull();
  });

  it("leave non-API pages alone", async () => {
    const res = await call("GET", "https://ci.partner.io", "/login");
    expect(res.headers.get("access-control-allow-origin")).toBeNull();
  });
});
