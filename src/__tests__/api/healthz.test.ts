/**
 * @jest-environment node
 *
 * /healthz says why the database check failed -- by error code only (it's public); the message goes to the logs.
 */
let dbError: { code?: string; message?: string } | null = null;
jest.mock("@/lib/supabase", () => ({
  createServiceClient: () => ({ from: () => ({ select: () => ({ limit: async () => ({ data: [], error: dbError }) }) }) }),
}));
jest.mock("@/lib/cache", () => {
  const store = new Map<string, unknown>();
  return { cacheGet: async (k: string) => store.get(k) ?? null, cacheSet: async (k: string, v: unknown) => { store.set(k, v); } };
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
