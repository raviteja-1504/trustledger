/**
 * @jest-environment node
 *
 * GET /api/report/change-register: validates the period, returns the register as JSON (with a reproducible sample
 * when a seed is given) or CSV, and a loader failure is a 500 without the data.
 */
import { NextRequest } from "next/server";

let permission: string | null = null;
jest.mock("@/app/api/_middleware", () => ({ verifyApiKey: async () => ({ org_id: "org-1", user_id: "u1" }), requirePermission: async () => permission }));
jest.mock("@/lib/rateLimit", () => ({ checkRateLimit: async () => ({ success: true, headers: {} }), RATE_LIMITS: { report: {} } }));
jest.mock("@/lib/supabase", () => ({ createServiceClient: () => ({}) }));
jest.mock("@/lib/serverErrors", () => ({ reportServerError: () => {} }));
jest.mock("@/lib/logger", () => {
  const actual = jest.requireActual("@/lib/logger");
  return { ...actual, logger: { ...actual.logger, error: () => {} } };
});
const loaded: Array<[string, string, string]> = [];
let loaderFails = false;
jest.mock("@/lib/changeRegisterLoader", () => ({
  loadChangeRegister: async (_db: unknown, org: string, start: string, end: string) => {
    loaded.push([org, start, end]);
    if (loaderFails) throw new Error("GitHub down");
    const { buildRegister } = jest.requireActual("@/lib/changeRegister");
    return buildRegister({
      period_start: start, period_end: end,
      pulls: Array.from({ length: 10 }, (_, i) => ({ repo: "acme/api", number: i + 1, title: `PR ${i + 1}`, author: "alice",
        merged_at: `2026-10-${String(i + 10)}T12:00:00Z`, merged_by: "carol", head_sha: `sha${i}`, url: `u${i}` })),
      reviews: new Map(), scans: [], riskyFiles: [], signoffs: [], coverage: [{ repo: "acme/api", read: true, pulls: 10 }],
    });
  },
}));

import { GET } from "@/app/api/report/change-register/route";
import { drawSample } from "@/lib/changeRegister";

const get = (qs: string) => GET(new NextRequest(new URL(`/api/report/change-register?${qs}`, "https://app.example")));
const PERIOD = "period_start=2026-10-01&period_end=2026-10-31T23:59:59Z";

beforeEach(() => { permission = null; loaderFails = false; loaded.length = 0; });

describe("GET /api/report/change-register", () => {
  it("returns the register for the caller's organisation and period", async () => {
    const res = await get(PERIOD);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(loaded).toEqual([["org-1", "2026-10-01T00:00:00.000Z", "2026-10-31T23:59:59.000Z"]]);
    expect(body.summary.merged).toBe(10);
    expect(body.sample).toBeNull();
    expect(res.headers.get("cache-control")).toContain("no-store");
  });

  it("a seed draws the same sample anyone can re-draw from the register", async () => {
    const body = await (await get(`${PERIOD}&sample_seed=audit-2026&sample_size=4`)).json();
    expect(body.sample.seed).toBe("audit-2026");
    expect(body.sample.rows).toHaveLength(4);
    expect(body.sample.rows).toEqual(drawSample(body.rows, 4, "audit-2026"));
  });

  it("CSV: one line per pull request, as an attachment", async () => {
    const res = await get(`${PERIOD}&format=csv`);
    expect(res.headers.get("content-type")).toMatch(/^text\/csv/);
    expect(res.headers.get("content-disposition")).toContain("trustledger-change-register-2026-10-01-2026-10-31.csv");
    expect((await res.text()).trim().split("\n")).toHaveLength(11);
  });

  it.each([
    ["no period", ""],
    ["end before start", "period_start=2026-10-31&period_end=2026-10-01"],
    ["not a date", "period_start=yesterday&period_end=2026-10-01"],
  ])("%s → 400", async (_, qs) => {
    expect((await get(qs)).status).toBe(400);
    expect(loaded).toHaveLength(0);
  });

  it("a period over 400 days → 400", async () => {
    const res = await get("period_start=2025-01-01&period_end=2026-10-01");
    expect(res.status).toBe(400);
    expect((await res.json()).error).toBe("period_too_long");
  });

  it("without the report permission → 403", async () => {
    permission = "forbidden";
    expect((await get(PERIOD)).status).toBe(403);
    expect(loaded).toHaveLength(0);
  });

  it("a loader failure is a 500 without register data", async () => {
    loaderFails = true;
    const res = await get(PERIOD);
    expect(res.status).toBe(500);
    const body = await res.json();
    expect(body.error).toBe("change_register_failed");
    expect(body.rows).toBeUndefined();
  });
});
