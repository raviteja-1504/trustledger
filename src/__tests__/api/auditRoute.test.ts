/**
 * @jest-environment node
 *
 * /api/audit: filters (period, type, actor), per-type counts for the period, stored hashes; POST verifies.
 */
import { NextRequest } from "next/server";
import { fakeSupabase } from "../helpers/fakeSupabase";

let db: ReturnType<typeof fakeSupabase>;
jest.mock("@/lib/supabase", () => ({ createServiceClient: () => db.client }));
jest.mock("@/app/api/_middleware", () => ({ verifyApiKey: async () => ({ org_id: "org-1", role: "admin" }), requirePermission: async () => null }));

import { GET, POST } from "@/app/api/audit/route";
import { writeAuditLog } from "@/lib/audit";

const get = async (q = "") => {
  const res = await GET(new NextRequest(new URL(`/api/audit${q}`, "https://app.example")));
  return { status: res.status, body: await res.json() as Record<string, any> };   // eslint-disable-line @typescript-eslint/no-explicit-any
};
const entry = (id: number, type: string, at: string, actor = "ada@x", org = "org-1") =>
  ({ id, org_id: org, event_type: type, actor_email: actor, resource_type: null, resource_id: null, payload: {}, prev_hash: null, entry_hash: `h${id}`, created_at: at });

beforeEach(() => {
  db = fakeSupabase({ audit_log: [
    entry(1, "user_login", "2026-09-01T00:00:00Z"), entry(2, "scan_complete", "2026-10-02T00:00:00Z", "system"),
    entry(3, "attestation", "2026-10-03T00:00:00Z"), entry(4, "attestation", "2026-10-04T00:00:00Z", "bob@x"),
    entry(5, "user_login", "2026-10-05T00:00:00Z", "ada@x", "org-2"),
  ] });
});

describe("GET /api/audit", () => {
  it("newest first, with stored hashes, a total and per-type counts", async () => {
    const { body } = await get();
    expect(body.events.map((e: { id: number }) => e.id)).toEqual([4, 3, 2, 1]);
    expect(body.events[0].entry_hash).toBe("h4");
    expect(body.total).toBe(4);
    expect(body.counts).toEqual({ attestation: 2, scan_complete: 1, user_login: 1 });
    expect(body.period_total).toBe(4);
  });

  it("filters by period, type and actor; counts follow the period only", async () => {
    const { body } = await get("?since=2026-10-01&until=2026-10-31&type=attestation,user_login&actor=ada@x");
    expect(body.events.map((e: { id: number }) => e.id)).toEqual([3]);
    expect(body.total).toBe(1);
    expect(body.counts).toEqual({ attestation: 2, scan_complete: 1 });
    expect(body.period).toEqual({ start: "2026-10-01T00:00:00.000Z", end: "2026-10-31T23:59:59.999Z" });
  });

  it("pages, caps the page size, and refuses bad filters", async () => {
    expect((await get("?limit=2&page=1")).body.events.map((e: { id: number }) => e.id)).toEqual([2, 1]);
    expect((await get("?limit=99999")).body.limit).toBe(500);
    expect((await get("?since=last-week")).status).toBe(400);
    expect((await get("?type=DROP TABLE")).status).toBe(400);
  });
});

describe("POST /api/audit", () => {
  it("verifies what writeAuditLog stored", async () => {
    db = fakeSupabase({ audit_log: [] });
    await writeAuditLog(db.client as never, { org_id: "org-1", event_type: "user_login", actor_email: "ada@x", payload: { b: 1, a: 2 } });
    await writeAuditLog(db.client as never, { org_id: "org-1", event_type: "attestation", actor_email: null, payload: { file_path: "x.ts" } });
    const res = await POST(new NextRequest(new URL("/api/audit", "https://app.example"), { method: "POST" }));
    expect(await res.json()).toMatchObject({ valid: true, total: 2, verified: 2, legacy: 0 });
  });
});
