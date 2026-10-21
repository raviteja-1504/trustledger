/**
 * @jest-environment node
 *
 * /api/violation-status: a PATCH writes only the fields it was sent (a status change keeps the note, assignee and
 * escalation), assigns only members of the organisation, and records assignment / escalation / resolution in the
 * audit trail once each; GET returns every override, past the 1000-row response cap, with each file's repository.
 */
import { NextRequest } from "next/server";

const upserts: Record<string, unknown>[] = [];
let rows: { violation_id: string; status: string; assigned_email?: string | null; updated_at?: string }[] = [];
const ranges: [number, number][] = [];
const audits: Array<{ event_type: string; payload: Record<string, unknown> }> = [];
const MEMBERS = new Set(["a@b.io", "rev@b.io"]);
let before: Record<string, unknown> | null = null;
let scanRepos: Array<{ id: string; repo_full_name: string }> = [];

jest.mock("@/app/api/_middleware", () => ({
  verifyApiKey: async () => ({ org_id: "org-1", user_id: "u1", actor_email: "lead@b.io" }),
  requirePermission: async () => null,
}));
jest.mock("@/lib/autoIncidents", () => ({ syncAutoIncidents: async () => {} }));
jest.mock("@/lib/audit", () => ({ writeAuditLog: async (_db: unknown, e: { event_type: string; payload: Record<string, unknown> }) => { audits.push(e); } }));
jest.mock("@/lib/supabase", () => ({
  createServiceClient: () => ({
    from: (table: string) => {
      const eqs: Record<string, unknown> = {};
      const q = {
        select: () => q, order: () => q,
        eq: (c: string, v: unknown) => { eqs[c] = v; return q; },
        in: () => q,
        range: async (a: number, b: number) => { ranges.push([a, b]); return { data: rows.slice(a, b + 1), error: null }; },
        maybeSingle: async () => table === "org_members"
          ? { data: MEMBERS.has(String(eqs.email)) ? { id: "m" } : null }
          : { data: before },
        upsert: async (row: Record<string, unknown>) => { upserts.push(row); return { error: null }; },
        then: (res: (v: unknown) => unknown) => Promise.resolve({ data: table === "scans" ? scanRepos : [], error: null }).then(res),
      };
      return q;
    },
  }),
}));

import { GET, PATCH } from "@/app/api/violation-status/route";

const patch = (body: unknown) => PATCH(new NextRequest(new URL("/api/violation-status", "https://app.example"), { method: "PATCH", body: JSON.stringify(body), headers: { "content-type": "application/json" } }));
const SCAN = "11111111-1111-4111-8111-111111111111";

beforeEach(() => { upserts.length = 0; ranges.length = 0; audits.length = 0; rows = []; before = null; scanRepos = []; });

describe("PATCH /api/violation-status", () => {
  it("a status change sends no note / assignee / escalation, so the stored ones are kept", async () => {
    expect((await patch({ violation_id: "high::s1::a.ts", status: "resolved" })).status).toBe(200);
    expect(upserts[0]).toMatchObject({ org_id: "org-1", violation_id: "high::s1::a.ts", status: "resolved" });
    expect(upserts[0]).not.toHaveProperty("note");
    expect(upserts[0]).not.toHaveProperty("assigned_email");
    expect(upserts[0]).not.toHaveProperty("escalated");
  });

  it("fields that are sent are written; an empty string clears", async () => {
    await patch({ violation_id: "v", status: "open", note: "vendor fix pending", assigned_email: "A@b.io", escalated: true });
    expect(upserts[0]).toMatchObject({ note: "vendor fix pending", assigned_email: "a@b.io", escalated: true });
    await patch({ violation_id: "v", status: "open", note: "", assigned_email: "", escalated: false });
    expect(upserts[1]).toMatchObject({ note: null, assigned_email: null, escalated: false });
  });

  it("a malformed assignee, or someone outside the organisation, is rejected", async () => {
    expect((await patch({ violation_id: "v", status: "open", assigned_email: "nope" })).status).toBe(400);
    const res = await patch({ violation_id: "v", status: "open", assigned_email: "stranger@else.io" });
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ error: "not_a_member" });
    expect(upserts).toHaveLength(0);
  });

  it("records assignment, escalation and resolution in the audit trail -- each only when it changes, naming the file", async () => {
    await patch({ violation_id: `crit::${SCAN}::src/auth.ts`, status: "open", assigned_email: "rev@b.io" });
    expect(audits).toEqual([{ event_type: "violation_assigned", payload: { scan_id: SCAN, file_path: "src/auth.ts", assigned_email: "rev@b.io" }, org_id: "org-1",
      actor_id: "u1", actor_email: "lead@b.io", resource_type: "violation", resource_id: `crit::${SCAN}::src/auth.ts` }]);

    // the same assignee again, and an already-resolved item saved again: nothing new to record
    audits.length = 0;
    before = { status: "resolved", assigned_email: "rev@b.io", escalated: false };
    await patch({ violation_id: `crit::${SCAN}::src/auth.ts`, status: "resolved", assigned_email: "rev@b.io" });
    expect(audits).toEqual([]);

    before = { status: "open", assigned_email: "rev@b.io", escalated: false };
    await patch({ violation_id: `crit::${SCAN}::src/auth.ts`, status: "resolved", escalated: true, assigned_email: "" });
    const detail = (a: typeof audits[number]) =>
      a.event_type === "violation_assigned" ? a.payload.assigned_email : a.event_type === "violation_escalated" ? a.payload.escalated : a.payload.status;
    expect(audits.map(a => [a.event_type, detail(a)])).toEqual([
      ["violation_resolved", "resolved"], ["violation_assigned", null], ["violation_escalated", true],
    ]);
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

  it("each file's override names its repository, so an assignee can follow the file to a newer push", async () => {
    rows = [{ violation_id: `high::${SCAN}::a.ts`, status: "open", assigned_email: "rev@b.io" }, { violation_id: "deploy::blocked", status: "open" }];
    scanRepos = [{ id: SCAN, repo_full_name: "acme/api" }];
    const body = await (await GET(new NextRequest(new URL("/api/violation-status", "https://app.example")))).json() as { overrides: Record<string, { repo?: string }> };
    expect(body.overrides[`high::${SCAN}::a.ts`].repo).toBe("acme/api");
    expect(body.overrides["deploy::blocked"].repo).toBeUndefined();
  });
});
