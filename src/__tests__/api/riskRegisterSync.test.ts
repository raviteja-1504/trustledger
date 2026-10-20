/**
 * @jest-environment node
 *
 * POST /api/risk-register/sync: records derived risks without an ON CONFLICT upsert (the partial unique index
 * can't serve one, so every sync used to fail), changes only metadata, reopens what the sync itself closed, and
 * never overrides a person's decision.
 */
import { NextRequest } from "next/server";

type Row = Record<string, unknown>;
let rows: Row[] = [];
let failInsert = false;
const audit: unknown[] = [];

jest.mock("@/app/api/_middleware", () => ({
  verifyApiKey: async () => ({ org_id: "org-1", user_id: "u1" }),
  requirePermission: async () => null,
}));
jest.mock("@/lib/audit", () => ({ writeAuditLog: async (_db: unknown, e: unknown) => { audit.push(e); } }));
jest.mock("@/lib/supabase", () => ({
  createServiceClient: () => ({
    from: () => {
      const filters: Array<(r: Row) => boolean> = [];
      let op: { kind: "update"; patch: Row } | null = null;
      const q = {
        select: () => q,
        eq: (c: string, v: unknown) => { filters.push(r => r[c] === v); return q; },
        neq: (c: string, v: unknown) => { filters.push(r => r[c] !== v); return q; },
        in: (c: string, vs: unknown[]) => { filters.push(r => vs.includes(r[c])); return q; },
        not: (c: string) => { filters.push(r => r[c] != null); return q; },
        update: (patch: Row) => { op = { kind: "update", patch }; return q; },
        insert: async (list: Row[]) => {
          if (failInsert) return { error: { message: "boom" } };
          for (const r of list) rows.push({ status: "open", updated_by: null, description: null, repo: null, related_cve: null, related_cwe: null, related_link: null, ...r });
          return { error: null };
        },
        then: (res: (v: unknown) => unknown) => {
          const hit = rows.filter(r => filters.every(f => f(r)));
          if (op) for (const r of hit) Object.assign(r, op.patch);
          return Promise.resolve({ data: hit.map(r => ({ ...r })), error: null }).then(res);
        },
      };
      return q;
    },
  }),
}));

import { POST } from "@/app/api/risk-register/sync/route";

const sync = async (risks: unknown) => {
  const res = await POST(new NextRequest(new URL("/api/risk-register/sync", "https://app.example"), { method: "POST", body: JSON.stringify({ risks }), headers: { "content-type": "application/json" } }));
  return { status: res.status, body: await res.json() as Record<string, number> };
};
const risk = (id: string, o: Row = {}) => ({ id, title: `Risk ${id}`, category: "ai-code", likelihood: 4, impact: 4, ...o });
const byId = (id: string) => rows.find(r => r.external_id === id)!;

beforeEach(() => { rows = []; failInsert = false; audit.length = 0; });

describe("risk register sync", () => {
  it("first sync inserts every derived risk as an open, auto-derived row for the org", async () => {
    const { status, body } = await sync([risk("DR-A", { repo: "acme/api", related_cwe: "CWE-89 — SQL Injection" }), risk("DR-B")]);
    expect(status).toBe(200);
    expect(body).toMatchObject({ synced: 2, inserted: 2, updated: 0, closed: 0 });
    expect(byId("DR-A")).toMatchObject({ org_id: "org-1", auto_derived: true, status: "open", repo: "acme/api", related_cwe: "CWE-89 — SQL Injection", likelihood: 4 });
  });

  it("a second identical sync changes nothing; changed metadata updates only that row, never workflow fields", async () => {
    await sync([risk("DR-A"), risk("DR-B")]);
    Object.assign(byId("DR-A"), { owner_email: "lead@acme.test", status: "mitigating", updated_by: "u9", notes: ["n"] });
    expect((await sync([risk("DR-A"), risk("DR-B")])).body).toMatchObject({ inserted: 0, updated: 0, closed: 0 });
    expect((await sync([risk("DR-A", { title: "Risk A (3 files)" }), risk("DR-B")])).body).toMatchObject({ updated: 1 });
    expect(byId("DR-A")).toMatchObject({ title: "Risk A (3 files)", owner_email: "lead@acme.test", status: "mitigating", notes: ["n"] });
  });

  it("a risk no longer derived is closed by the system; derived again, it is reopened", async () => {
    await sync([risk("DR-A"), risk("DR-B")]);
    expect((await sync([risk("DR-A")])).body).toMatchObject({ closed: 1 });
    expect(byId("DR-B")).toMatchObject({ status: "closed", updated_by: null });
    expect((await sync([risk("DR-A"), risk("DR-B")])).body).toMatchObject({ reopened: 1, inserted: 0 });
    expect(byId("DR-B").status).toBe("open");
    expect(audit).toHaveLength(2);
  });

  it("a risk a person worked on, then closed by the system when it went away, reopens when it comes back", async () => {
    await sync([risk("DR-A"), risk("DR-B")]);
    Object.assign(byId("DR-B"), { status: "mitigating", updated_by: "u-person" });
    await sync([risk("DR-A")]);
    expect(byId("DR-B")).toMatchObject({ status: "closed", updated_by: null });
    await sync([risk("DR-A"), risk("DR-B")]);
    expect(byId("DR-B").status).toBe("open");
  });

  it("a risk a person closed stays closed, even while it is still derived", async () => {
    await sync([risk("DR-A")]);
    Object.assign(byId("DR-A"), { status: "closed", updated_by: "u-person" });
    expect((await sync([risk("DR-A")])).body).toMatchObject({ reopened: 0 });
    expect(byId("DR-A").status).toBe("closed");
  });

  it("manual risks and other orgs' rows are never touched", async () => {
    rows.push({ org_id: "org-1", external_id: "DR-A", auto_derived: false, status: "open", title: "Mine", category: "access", likelihood: 2, impact: 2, updated_by: "u1" });
    rows.push({ org_id: "org-2", external_id: "DR-Z", auto_derived: true, status: "open", title: "Theirs", category: "ai-code", likelihood: 2, impact: 2, updated_by: null });
    const { body } = await sync([risk("DR-A", { title: "Derived" })]);
    expect(body).toMatchObject({ inserted: 0, updated: 0, closed: 0 });
    expect(rows.find(r => r.external_id === "DR-A")!.title).toBe("Mine");
    expect(rows.find(r => r.external_id === "DR-Z")!.status).toBe("open");
  });

  it("repeated ids are written once; risks the table would reject are skipped, not fatal", async () => {
    const { body } = await sync([
      risk("DR-A", { title: "first" }), risk("DR-A", { title: "second" }),
      risk("DR-BAD1", { likelihood: 7 }), risk("DR-BAD2", { category: "made-up" }), risk("DR-BAD3", { title: "  " }), { title: "no id", category: "ai-code", likelihood: 1, impact: 1 },
    ]);
    expect(body).toMatchObject({ synced: 1, inserted: 1, skipped: 4 });
    expect(rows).toHaveLength(1);
    expect(byId("DR-A").title).toBe("second");
  });

  it("an empty batch closes every open derived risk", async () => {
    await sync([risk("DR-A"), risk("DR-B")]);
    expect((await sync([])).body).toMatchObject({ closed: 2 });
  });

  it("bad requests and database failures are reported", async () => {
    expect((await sync("nope")).status).toBe(400);
    expect((await sync(Array.from({ length: 501 }, (_, i) => risk(`DR-${i}`)))).status).toBe(400);
    failInsert = true;
    expect((await sync([risk("DR-A")])).status).toBeGreaterThanOrEqual(500);
  });
});
