/**
 * @jest-environment node
 *
 * PATCH /api/risk-register/state: only workflow fields with valid values reach the table. The page used to send
 * `owner` (the table column is `owner_email`), so every owner change was rejected by the database.
 */
import { NextRequest } from "next/server";
import { fakeSupabase } from "../helpers/fakeSupabase";
import { riskPatchToDb } from "@/lib/riskRegister";

let db: ReturnType<typeof fakeSupabase>;
jest.mock("@/lib/supabase", () => ({ createServiceClient: () => db.client }));
jest.mock("@/lib/audit", () => ({ writeAuditLog: async () => undefined }));
jest.mock("@/app/api/_middleware", () => ({ verifyApiKey: async () => ({ org_id: "org-1", user_id: "u1" }), requirePermission: async () => null }));

import { PATCH } from "@/app/api/risk-register/state/route";

const patch = async (p: unknown, external_id = "DR-1") => {
  const res = await PATCH(new NextRequest("https://app.example/api/risk-register/state", { method: "PATCH", body: JSON.stringify({ external_id, patch: p }) }));
  return { res, body: await res.json() as { error?: string; risk?: Record<string, unknown> } };
};
beforeEach(() => {
  db = fakeSupabase({ risk_register: [{ org_id: "org-1", external_id: "DR-1", auto_derived: true, title: "T", status: "open", owner_email: null, notes: [] }] });
});

describe("PATCH /api/risk-register/state", () => {
  it("saves valid workflow fields", async () => {
    const { res, body } = await patch({ status: "mitigating", owner_email: "ana@example.com", due_date: "2026-12-01", notes: ["a"], residual_likelihood: 2 });
    expect(res.status).toBe(200);
    expect(body.risk).toMatchObject({ status: "mitigating", owner_email: "ana@example.com", due_date: "2026-12-01", residual_likelihood: 2 });
  });
  it("clears an owner and a due date", async () => {
    const { body } = await patch({ owner_email: null, due_date: null });
    expect(body.risk).toMatchObject({ owner_email: null, due_date: null });
  });
  it.each([
    ["an unknown column such as 'owner'", { owner: "ana@example.com" }],
    ["a status that does not exist", { status: "done" }],
    ["a treatment that does not exist", { treatment: "ignore" }],
    ["a residual score out of range", { residual_impact: 9 }],
    ["a malformed due date", { due_date: "next week" }],
    ["notes that are not text", { notes: [1] }],
    ["an empty patch", {}],
    ["a column that is never hand-set (title)", { title: "x" }],
  ])("rejects %s without writing", async (_name, p) => {
    const before = db.writes.length;
    const { res, body } = await patch(p);
    expect(res.status).toBe(400);
    expect(body.error).toBe("invalid_patch");
    expect(db.writes.length).toBe(before);
  });
});

describe("riskPatchToDb", () => {
  it("maps the page's owner to the owner_email column; 'unassigned' clears it", () => {
    expect(riskPatchToDb({ owner: "ana@example.com" })).toEqual({ owner_email: "ana@example.com" });
    expect(riskPatchToDb({ owner: "unassigned" })).toEqual({ owner_email: null });
  });
  it("an empty due date clears it; identified_at is never written", () => {
    expect(riskPatchToDb({ due_date: "" })).toEqual({ due_date: null });
    expect(riskPatchToDb({ identified_at: "2026-01-01", status: "closed" })).toEqual({ status: "closed" });
  });
});
