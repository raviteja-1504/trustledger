/**
 * @jest-environment node
 *
 * POST /api/audit/forks: an admin records that the audit chain's forks were reviewed -- inside the chain, only when forks are
 * the chain's only problem, and never as a way to hide tampering.
 */
import { NextRequest } from "next/server";
import { fakeSupabase } from "../helpers/fakeSupabase";
import { auditEntryHashV2, checkAuditChain, loadAuditRows } from "@/lib/audit";

let db: ReturnType<typeof fakeSupabase>;
let auth: { org_id: string; user_id?: string; actor_email?: string; role?: string; error?: string };
jest.mock("@/lib/supabase", () => ({ createServiceClient: () => db.client }));
jest.mock("@/app/api/_middleware", () => ({
  verifyApiKey: async () => auth,
  requireRole: (a: { role?: string }) => (a.role === "admin" ? null : "insufficient_permissions"),
  requirePermission: async () => null,
}));
import { POST } from "@/app/api/audit/forks/route";

const ORG = "org-1";
const T0 = Date.parse("2026-11-01T00:00:00.000Z");
const mk = (id: number, prev: string | null, over: Record<string, unknown> = {}) => {
  const created_at = new Date(T0 + id * 60_000).toISOString();
  const f = { event_type: "user_login", actor_id: "u", actor_email: "a@x.dev", resource_type: "session", resource_id: `s${id}`, payload: { id }, ...over };
  return { id, org_id: ORG, ...f, prev_hash: prev, created_at, entry_hash: auditEntryHashV2({ ...f, prev_hash: prev, org_id: ORG, created_at } as never) };
};
/** 1 -> 2, and 3 forks off 1. */
const forked = () => { const a = mk(1, null), b = mk(2, a.entry_hash), c = mk(3, a.entry_hash); return [a, b, c]; };
const call = (body: unknown = {}) => POST(new NextRequest("https://app.example/api/audit/forks", { method: "POST", body: JSON.stringify(body) }));
const log = () => db.tables.audit_log as Array<Record<string, unknown>>;

beforeEach(() => { auth = { org_id: ORG, user_id: "u-admin", actor_email: "admin@acme.dev", role: "admin" }; });

it("records the reviewed forks in the chain, and the chain then verifies", async () => {
  db = fakeSupabase({ audit_log: forked() });
  const res = await call({ note: "double sign-in" });
  expect(res.status).toBe(200);
  expect(await res.json()).toEqual({ ok: true, reviewed: 1 });
  const entry = log()[3];
  expect(entry).toMatchObject({ event_type: "audit_forks_reviewed", actor_email: "admin@acme.dev", payload: { fork_entry_ids: [3], count: 1, note: "double sign-in" } });
  log().forEach((r, i) => { r.id ??= i + 1; });                 // the in-memory database does not assign ids; a real one does
  const { rows } = await loadAuditRows(db.client as never, ORG);
  expect(checkAuditChain(rows)).toMatchObject({ status: "VALID", valid: true, reviewed_forks: 1 });
});

it("is admin only", async () => {
  db = fakeSupabase({ audit_log: forked() });
  auth = { org_id: ORG, user_id: "u", role: "developer" };
  expect((await call()).status).toBe(403);
  expect(log()).toHaveLength(3);
});

it("a clean log needs no review: nothing is written", async () => {
  const a = mk(1, null);
  db = fakeSupabase({ audit_log: [a, mk(2, a.entry_hash)] });
  expect(await (await call()).json()).toEqual({ ok: true, reviewed: 0 });
  expect(log()).toHaveLength(2);
});

it("refuses to mark a chain with other damage as reviewed", async () => {
  const rows = forked();
  rows[1] = { ...rows[1], resource_id: "tampered" };            // a changed entry as well as the fork
  db = fakeSupabase({ audit_log: rows });
  const res = await call();
  expect(res.status).toBe(409);
  expect((await res.json()).error).toBe("chain_not_reviewable");
  expect(log()).toHaveLength(3);
});

it("writes nothing when the log cannot be read in full", async () => {
  db = fakeSupabase({ audit_log: forked() }, { maxRows: 2 });    // the server shortens pages: 2 of 3 entries come back
  const res = await call();
  expect(res.status).toBe(503);
  expect(log()).toHaveLength(3);
});

it("does not report success if the review entry itself cannot be written", async () => {
  db = fakeSupabase({ audit_log: forked() });
  const real = db.client.from;
  db.client.from = ((table: string) => {
    const q = real(table) as unknown as { insert: (p: unknown) => unknown };
    if (table === "audit_log") q.insert = () => Promise.resolve({ error: { code: "42501", message: "permission denied" } });
    return q;
  }) as typeof db.client.from;
  expect((await call()).status).toBe(500);
});
