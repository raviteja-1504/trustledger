/**
 * @jest-environment node
 *
 * /healthz says why the database check failed -- by error code only (it's public); the message goes to the logs.
 */
let dbError: { code?: string; message?: string } | null = null;
jest.mock("@/lib/supabase", () => ({
  createServiceClient: () => ({ from: () => ({ select: () => ({ limit: async () => ({ data: [], error: dbError }) }) }) }),
}));
const mockCacheCalls = { sets: 0, gets: 0 };
jest.mock("@/lib/cache", () => {
  const store = new Map<string, unknown>();
  return {
    cacheGet: async (k: string) => { mockCacheCalls.gets++; return store.get(k) ?? null; },
    cacheSet: async (k: string, v: unknown) => { mockCacheCalls.sets++; store.set(k, v); },
    cacheBackend: async () => "redis",
  };
});
const logError = jest.fn();
jest.mock("@/lib/logger", () => ({ logger: { error: (...a: unknown[]) => logError(...a), info: jest.fn(), warn: jest.fn() } }));

import { GET } from "@/app/healthz/route";

beforeEach(() => { process.env.NEXT_PUBLIC_SUPABASE_URL = "https://abcdefghijklmnopqrst.supabase.co"; dbError = null; logError.mockClear(); });

it("reports ok when the query works", async () => {
  const body = await (await GET()).json();
  expect(body.services.database).toMatchObject({ status: "ok" });
});

it("reports the error code publicly and the message only in the logs", async () => {
  dbError = { code: "42501", message: "permission denied for table organizations (internal detail)" };
  const body = await (await GET()).json();
  expect(body.services.database).toMatchObject({ status: "degraded", detail: "query failed (42501)" });
  expect(JSON.stringify(body)).not.toContain("internal detail");
  expect(logError).toHaveBeenCalledWith("healthz_db_query_failed", expect.objectContaining({ code: "42501", detail: expect.stringContaining("permission denied") }));
});

it("probes the cache once, not on every call: a status bar or a bot calling /healthz does not cost Redis commands", async () => {
  const before = { ...mockCacheCalls };
  for (let i = 0; i < 25; i++) await GET();
  // the first call of this file already probed it; 25 more calls add nothing
  expect(mockCacheCalls.sets - before.sets).toBe(0);
  expect(mockCacheCalls.gets - before.gets).toBe(0);
  const body = await (await GET()).json();
  expect(body.services.cache).toMatchObject({ status: "ok", detail: "redis" });
});
