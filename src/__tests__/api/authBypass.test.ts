/**
 * @jest-environment node
 *
 * NEXT_PUBLIC_SKIP_AUTH is a demo switch. In a production runtime it must never open anything, and the edge
 * middleware must fail closed when Supabase is not configured there.
 */
import { NextRequest } from "next/server";

const ENV_KEYS = ["NODE_ENV", "VERCEL_ENV", "NEXT_PUBLIC_SKIP_AUTH", "NEXT_PUBLIC_SUPABASE_URL", "NEXT_PUBLIC_SUPABASE_ANON_KEY"] as const;
const saved: Record<string, string | undefined> = {};
const env = process.env as Record<string, string | undefined>;

function setEnv(vals: Partial<Record<(typeof ENV_KEYS)[number], string | undefined>>) {
  for (const k of ENV_KEYS) delete env[k];
  for (const [k, v] of Object.entries(vals)) if (v !== undefined) env[k] = v;
}

beforeEach(() => { for (const k of ENV_KEYS) saved[k] = env[k]; jest.resetModules(); });
afterEach(() => { for (const k of ENV_KEYS) { if (saved[k] === undefined) delete env[k]; else env[k] = saved[k]; } });

jest.mock("@/lib/supabase", () => ({
  createServiceClient: () => ({
    auth: { getUser: async () => ({ data: { user: null }, error: { message: "bad" } }) },
    from: () => { throw new Error("db must not be reached"); },
  }),
}));

describe("authBypassEnabled", () => {
  it.each([
    [{ NODE_ENV: "test", NEXT_PUBLIC_SKIP_AUTH: "true" }, true],
    [{ NODE_ENV: "development", NEXT_PUBLIC_SKIP_AUTH: "true" }, true],
    [{ NODE_ENV: "production", NEXT_PUBLIC_SKIP_AUTH: "true" }, false],
    [{ NODE_ENV: "test", VERCEL_ENV: "production", NEXT_PUBLIC_SKIP_AUTH: "true" }, false],
    [{ NODE_ENV: "test", NEXT_PUBLIC_SKIP_AUTH: "false" }, false],
    [{ NODE_ENV: "test" }, false],
  ] as const)("%j -> %s", async (vals, expected) => {
    setEnv(vals);
    const { authBypassEnabled } = await import("@/lib/authBypass");
    expect(authBypassEnabled()).toBe(expected);
  });
});

describe("verifyApiKey", () => {
  const req = () => new NextRequest("https://app.example/api/x");

  it("grants the demo identity outside production", async () => {
    setEnv({ NODE_ENV: "test", NEXT_PUBLIC_SKIP_AUTH: "true" });
    const { verifyApiKey } = await import("@/app/api/_middleware");
    expect((await verifyApiKey(req())).org_id).toBe("demo");
  });

  it("still demands credentials in production even with the switch on", async () => {
    setEnv({ NODE_ENV: "production", NEXT_PUBLIC_SKIP_AUTH: "true" });
    const { verifyApiKey } = await import("@/app/api/_middleware");
    const res = await verifyApiKey(req());
    expect(res.org_id).toBe("");
    expect(res.error).toBe("missing_credentials");
  });
});

describe("permissionResolver", () => {
  const subject = { org_id: "org-1" };

  it("grants everything outside production with the switch on", async () => {
    setEnv({ NODE_ENV: "test", NEXT_PUBLIC_SKIP_AUTH: "true" });
    const { permissionsFor } = await import("@/lib/permissionResolver");
    const { ALL_PERMISSIONS } = await import("@/lib/permissions");
    expect(await permissionsFor({ ...subject })).toEqual(ALL_PERMISSIONS);
  });

  it("does not in production", async () => {
    setEnv({ NODE_ENV: "production", NEXT_PUBLIC_SKIP_AUTH: "true" });
    const { permissionsFor } = await import("@/lib/permissionResolver");
    const { ALL_PERMISSIONS } = await import("@/lib/permissions");
    expect(await permissionsFor({ ...subject })).not.toEqual(ALL_PERMISSIONS);
  });
});

describe("edge middleware", () => {
  const get = async (path = "/dashboard") => {
    const { middleware } = await import("@/middleware");
    return middleware(new NextRequest(new URL(path, "https://app.example")));
  };

  it("production + SKIP_AUTH still sends signed-out visitors to /login", async () => {
    setEnv({ NODE_ENV: "production", NEXT_PUBLIC_SKIP_AUTH: "true", NEXT_PUBLIC_SUPABASE_URL: "https://abc.supabase.co", NEXT_PUBLIC_SUPABASE_ANON_KEY: "anon" });
    const res = await get();
    expect(res.status).toBe(307);
    expect(res.headers.get("location")).toContain("/login");
  });

  it("production without Supabase configuration fails closed", async () => {
    setEnv({ NODE_ENV: "production" });
    const res = await get();
    expect(res.status).toBe(503);
    expect(await res.json()).toEqual({ error: "auth_not_configured" });
  });

  it("VERCEL_ENV=production without Supabase configuration fails closed", async () => {
    setEnv({ NODE_ENV: "test", VERCEL_ENV: "production" });
    expect((await get()).status).toBe(503);
  });

  it("non-production demo mode passes through", async () => {
    setEnv({ NODE_ENV: "test", NEXT_PUBLIC_SKIP_AUTH: "true" });
    expect((await get()).status).toBe(200);
  });

  it("non-production without Supabase configuration still passes (local dev)", async () => {
    setEnv({ NODE_ENV: "test" });
    expect((await get()).status).toBe(200);
  });
});
