/**
 * @jest-environment node
 *
 * An API key's IP allowlist is the authenticated key's own, and the client IP is not taken from the
 * left-most (client-written) X-Forwarded-For entry.
 */
import { NextRequest } from "next/server";
import crypto from "crypto";

const sha = (s: string) => crypto.createHash("sha256").update(s).digest("hex");

interface KeyRow { org_id: string; expires_at: null; revoked: boolean; ip_allowlist: string[] | null }
const keys: Record<string, KeyRow> = {};

jest.mock("@/lib/supabase", () => ({
  createServiceClient: () => ({
    from: (table: string) => {
      if (table !== "api_keys") throw new Error("unexpected table " + table);
      let hash = "";
      const q = {
        select: () => q,
        eq: (_c: string, v: string) => { hash = v; return q; },
        limit: () => q,
        // the old lookup (by org, no key_hash) would pick an arbitrary key -- model that as the first row
        single: async () => ({ data: hash ? keys[hash] ?? null : Object.values(keys)[0] ?? null }),
        update: () => ({ eq: () => ({ then: () => {} }) }),
      };
      return q;
    },
  }),
}));

const ENV = ["VERCEL", "TRUSTED_PROXY_HOPS", "NEXT_PUBLIC_SKIP_AUTH"] as const;
const saved: Record<string, string | undefined> = {};
const env = process.env as Record<string, string | undefined>;
beforeEach(() => {
  for (const k of ENV) { saved[k] = env[k]; delete env[k]; }
  for (const k of Object.keys(keys)) delete keys[k];
});
afterEach(() => { for (const k of ENV) { if (saved[k] === undefined) delete env[k]; else env[k] = saved[k]; } });

const call = async (apiKey: string, headers: Record<string, string>) => {
  const { verifyApiKey } = await import("@/app/api/_middleware");
  return verifyApiKey(new NextRequest("https://app.example/api/x", { headers: { "x-trustledger-key": apiKey, ...headers } }));
};

describe("getClientIp", () => {
  const h = (o: Record<string, string>) => new Headers(o);
  it("uses the proxy-appended (right-most) X-Forwarded-For entry, not the client-written left one", async () => {
    const { getClientIp } = await import("@/lib/clientIp");
    expect(getClientIp(h({ "x-forwarded-for": "6.6.6.6, 203.0.113.9" }))).toBe("203.0.113.9");
  });
  it("honours TRUSTED_PROXY_HOPS", async () => {
    env.TRUSTED_PROXY_HOPS = "2";
    const { getClientIp } = await import("@/lib/clientIp");
    expect(getClientIp(h({ "x-forwarded-for": "6.6.6.6, 203.0.113.9, 10.0.0.1" }))).toBe("203.0.113.9");
  });
  it("prefers platform headers on Vercel", async () => {
    env.VERCEL = "1";
    const { getClientIp } = await import("@/lib/clientIp");
    expect(getClientIp(h({ "x-vercel-forwarded-for": "198.51.100.4", "x-forwarded-for": "6.6.6.6" }))).toBe("198.51.100.4");
  });
  it("falls back to x-real-ip then unknown", async () => {
    const { getClientIp } = await import("@/lib/clientIp");
    expect(getClientIp(h({ "x-real-ip": "192.0.2.1" }))).toBe("192.0.2.1");
    expect(getClientIp(h({}))).toBe("unknown");
  });
});

describe("API key IP allowlist", () => {
  it("applies the allowlist of the key that authenticated, not another key of the org", async () => {
    // the unrestricted key is first, so a lookup by org would wrongly pick it and let the restricted key through
    keys[sha("open")]       = { org_id: "o1", expires_at: null, revoked: false, ip_allowlist: null };
    keys[sha("restricted")] = { org_id: "o1", expires_at: null, revoked: false, ip_allowlist: ["203.0.113.9"] };

    const blocked = await call("restricted", { "x-forwarded-for": "198.51.100.77" });
    expect(blocked.org_id).toBe("");
    expect(blocked.error).toMatch(/^ip_not_allowed/);

    expect((await call("restricted", { "x-forwarded-for": "203.0.113.9" })).org_id).toBe("o1");
    expect((await call("open", { "x-forwarded-for": "198.51.100.77" })).org_id).toBe("o1");
  });

  it("a spoofed left-most X-Forwarded-For entry does not get past the allowlist", async () => {
    keys[sha("restricted")] = { org_id: "o1", expires_at: null, revoked: false, ip_allowlist: ["203.0.113.9"] };
    const res = await call("restricted", { "x-forwarded-for": "203.0.113.9, 198.51.100.77" });
    expect(res.error).toMatch(/^ip_not_allowed: 198\.51\.100\.77/);
  });

  it("a key with a wildcard allowlist admits anyone", async () => {
    keys[sha("any")] = { org_id: "o1", expires_at: null, revoked: false, ip_allowlist: ["*"] };
    expect((await call("any", { "x-forwarded-for": "198.51.100.77" })).org_id).toBe("o1");
  });
});
