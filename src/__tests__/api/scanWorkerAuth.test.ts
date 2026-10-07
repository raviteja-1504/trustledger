/**
 * @jest-environment node
 *
 * /api/scan-worker must not accept a forged job. The direct-call secret used to default to "dev" when
 * INTERNAL_SECRET was unset -- in production that let anyone post a job naming any installation, repo and org.
 */
import { NextRequest } from "next/server";

jest.mock("@/lib/supabase", () => ({ createServiceClient: () => { throw new Error("past-auth"); } }));

import { POST } from "@/app/api/scan-worker/route";
import { enqueueScan } from "@/lib/queue";
import { internalSecret } from "@/lib/internalSecret";

const ENV_KEYS = ["INTERNAL_SECRET", "VERCEL_ENV", "QSTASH_CURRENT_SIGNING_KEY", "QSTASH_NEXT_SIGNING_KEY", "QSTASH_TOKEN", "NEXT_PUBLIC_APP_URL"] as const;
const saved: Record<string, string | undefined> = {};
beforeEach(() => { for (const k of ENV_KEYS) { saved[k] = process.env[k]; delete process.env[k]; } });
afterEach(() => { for (const k of ENV_KEYS) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; } });

const JOB = { org_id: "attacker-org", installation_id: 1, repo_full_name: "victim/private", pr_number: 1, head_sha: "abc", branch: "main",
  pr_author: null, before_sha: null, action: "opened", check_run_id: null, delivery_id: null };
/** 401 when refused; anything else (here the mocked DB throwing "past-auth") means the request got through. */
const outcome = (headers: Record<string, string>) =>
  POST(new NextRequest(new URL("https://app.example/api/scan-worker"), { method: "POST", headers, body: JSON.stringify(JOB) }))
    .then(r => r.status, e => String(e instanceof Error ? e.message : e));

describe("internalSecret", () => {
  it("is INTERNAL_SECRET when set (BOM/whitespace stripped)", () => {
    process.env.INTERNAL_SECRET = "\uFEFF s3cret-value \n";
    expect(internalSecret()).toBe("s3cret-value");
    process.env.VERCEL_ENV = "production";
    expect(internalSecret()).toBe("s3cret-value");
  });
  it("falls back to 'dev' only outside production", () => {
    expect(internalSecret()).toBe("dev");
    process.env.VERCEL_ENV = "production";
    expect(internalSecret()).toBeNull();
    process.env.INTERNAL_SECRET = "   ";
    expect(internalSecret()).toBeNull();
  });
});

describe("/api/scan-worker authentication", () => {
  it("production without INTERNAL_SECRET: the 'dev' header (or none) is refused", async () => {
    process.env.VERCEL_ENV = "production";
    expect(await outcome({ "x-internal-secret": "dev" })).toBe(401);
    expect(await outcome({ "x-internal-secret": "" })).toBe(401);
    expect(await outcome({})).toBe(401);
  });

  it("with INTERNAL_SECRET set: only that exact value gets through", async () => {
    process.env.VERCEL_ENV = "production";
    process.env.INTERNAL_SECRET = "a-long-random-secret";
    expect(await outcome({ "x-internal-secret": "dev" })).toBe(401);
    expect(await outcome({ "x-internal-secret": "a-long-random-secre" })).toBe(401);
    expect(await outcome({ "x-internal-secret": "a-long-random-secret" })).toBe("past-auth");
  });

  it("local dev keeps working with the 'dev' value", async () => {
    expect(await outcome({ "x-internal-secret": "dev" })).toBe("past-auth");
    expect(await outcome({ "x-internal-secret": "nope" })).toBe(401);
  });
});

describe("queue direct-call fallback", () => {
  const realFetch = global.fetch;
  let calls: { url: string; secret: string | null }[] = [];
  beforeEach(() => {
    calls = [];
    process.env.NEXT_PUBLIC_APP_URL = "https://app.example";
    global.fetch = (async (url: string, init?: RequestInit) => {
      calls.push({ url, secret: new Headers(init?.headers).get("x-internal-secret") });
      return new Response("{}", { status: 200 });
    }) as typeof fetch;
  });
  afterEach(() => { global.fetch = realFetch; });

  it("in production without INTERNAL_SECRET it sends nothing (never the 'dev' value)", async () => {
    process.env.VERCEL_ENV = "production";
    await enqueueScan(JOB);
    expect(calls).toEqual([]);
  });

  it("sends the configured secret", async () => {
    process.env.VERCEL_ENV = "production";
    process.env.INTERNAL_SECRET = "a-long-random-secret";
    await enqueueScan(JOB);
    expect(calls).toEqual([{ url: "https://app.example/api/scan-worker", secret: "a-long-random-secret" }]);
  });
});
