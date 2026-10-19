/**
 * @jest-environment node
 *
 * /api/violation-status: a PATCH writes only the fields it was sent (a status change keeps the note, assignee and
 * escalation), and GET returns every override, past the 1000-row response cap.
 */
import { NextRequest } from "next/server";

const upserts: Record<string, unknown>[] = [];
let rows: { violation_id: string; status: string }[] = [];
const ranges: [number, number][] = [];

jest.mock("@/app/api/_middleware", () => ({
  verifyApiKey: async () => ({ org_id: "org-1", user_id: "u1", actor_email: null }),
  requirePermission: async () => null,
}));
jest.mock("@/lib/autoIncidents", () => ({ syncAutoIncidents: async () => {} }));
jest.mock("@/lib/audit", () => ({ writeAuditLog: async () => {} }));
jest.mock("@/lib/supabase", () => ({
  createServiceClient: () => ({
    from: () => {
      const q = {
        select: () => q, eq: () => q, order: () => q,
        range: async (a: number, b: number) => { ranges.push([a, b]); return { data: rows.slice(a, b + 1), error: null }; },
        upsert: async (row: Record<string, unknown>) => { upserts.push(row); return { error: null }; },
      };
      return q;
    },
  }),
}));

import { GET, PATCH } from "@/app/api/violation-status/route";

const patch = (body: unknown) => PATCH(new NextRequest(new URL("/api/violation-status", "https://app.example"), { method: "PATCH", body: JSON.stringify(body), headers: { "content-type": "application/json" } }));

beforeEach(() => { upserts.length = 0; ranges.length = 0; rows = []; });

describe("PATCH /api/violation-status", () => {
  it("a status change sends no note / assignee / escalation, so the stored ones are kept", async () => {
    expect((await patch({ violation_id: "high::s1::a.ts", status: "resolved" })).status).toBe(200);
    expect(upserts[0]).toMatchObject({ org_id: "org-1", violation_id: "high::s1::a.ts", status: "resolved" });
    expect(upserts[0]).not.toHaveProperty("note");
    expect(upserts[0]).not.toHaveProperty("assigned_email");
    expect(upserts[0]).not.toHaveProperty("escalated");
  });

  it("fields that are sent are written; an empty string clears", async () => {
    await patch({ violation_id: "v", status: "open", note: "vendor fix pending", assigned_email: "a@b.io", escalated: true });
    expect(upserts[0]).toMatchObject({ note: "vendor fix pending", assigned_email: "a@b.io", escalated: true });
    await patch({ violation_id: "v", status: "open", note: "", assigned_email: "", escalated: false });
    expect(upserts[1]).toMatchObject({ note: null, assigned_email: null, escalated: false });
  });

  it("a malformed assignee is rejected", async () => {
    expect((await patch({ violation_id: "v", status: "open", assigned_email: "nope" })).status).toBe(400);
    expect(upserts).toHaveLength(0);
  });
});

describe("GET /api/violation-status", () => {
  it("pages past 1000 rows", async () => {
    rows = Array.from({ length: 2300 }, (_, i) => ({ violation_id: `v${i}`, status: "resolved" }));
    const res = await GET(new NextRequest(new URL("/api/violation-status", "https://app.example")));
    const body = await res.json() as { overrides: Record<string, unknown> };
    expect(Object.keys(body.overrides)).toHaveLength(2300);
    expect(ranges).toEqual([[0, 999], [1000, 1999], [2000, 2999]]);
    expect(res.headers.get("Cache-Control")).toBe("private, no-store");
  });

  it("exactly one full page → one more (empty) read, then stops", async () => {
    rows = Array.from({ length: 1000 }, (_, i) => ({ violation_id: `v${i}`, status: "open" }));
    await GET(new NextRequest(new URL("/api/violation-status", "https://app.example")));
    expect(ranges).toEqual([[0, 999], [1000, 1999]]);
  });
});
