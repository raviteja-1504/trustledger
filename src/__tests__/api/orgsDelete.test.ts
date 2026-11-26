/**
 * @jest-environment node
 *
 * POST /api/orgs/delete: audit first, one database call, never a success response when it did not complete.
 */
import { NextRequest } from "next/server";

const rpc = jest.fn();
const fromSpy = jest.fn();
const writeAuditLog = jest.fn();
const cacheDel = jest.fn(async () => {});

jest.mock("@/lib/supabase", () => ({
  createServiceClient: () => ({
    rpc: (...a: unknown[]) => rpc(...a),
    from: (...a: unknown[]) => { fromSpy(...a); throw new Error("the route must not delete row by row"); },
  }),
}));
jest.mock("@/lib/audit", () => ({ writeAuditLog: (...a: unknown[]) => writeAuditLog(...a) }));
jest.mock("@/lib/cache", () => ({ cacheDel: (...a: unknown[]) => (cacheDel as unknown as (...x: unknown[]) => unknown)(...a), cacheKeys: { dashboard: () => "d", dependencies: () => "p" } }));
jest.mock("@/lib/logger", () => ({ logger: { error: jest.fn(), warn: jest.fn(), info: jest.fn() } }));
let auth: { org_id: string; role?: string; user_id?: string; actor_email?: string; error?: string };
jest.mock("@/app/api/_middleware", () => ({
  verifyApiKey: async () => auth,
  requireRole: (a: { role?: string }) => (a.role === "admin" ? null : "insufficient_permissions"),
}));

import { POST } from "@/app/api/orgs/delete/route";
const call = () => POST(new NextRequest("https://app.example/api/orgs/delete", { method: "POST" }));

beforeEach(() => {
  jest.clearAllMocks();
  auth = { org_id: "org-1", role: "admin", user_id: "u1", actor_email: "a@x.io" };
  writeAuditLog.mockResolvedValue(undefined);
  rpc.mockResolvedValue({ data: null, error: null });
});

it("records the request, deletes through the function, records completion and succeeds", async () => {
  const res = await call();
  expect(res.status).toBe(200);
  expect(await res.json()).toEqual({ ok: true });
  expect(rpc).toHaveBeenCalledWith("delete_org_cascade", { target_org_id: "org-1" });
  expect(writeAuditLog.mock.calls.map(c => c[1].event_type)).toEqual(["org_deletion_requested", "org_deleted"]);
  expect(writeAuditLog.mock.calls[0][2]).toEqual({ strict: true });
  expect(writeAuditLog.mock.invocationCallOrder[0]).toBeLessThan(rpc.mock.invocationCallOrder[0]);
  expect(fromSpy).not.toHaveBeenCalled();
});

it("does not delete anything when the audit entry cannot be written", async () => {
  writeAuditLog.mockRejectedValueOnce(new Error("audit_write_failed: boom"));
  const res = await call();
  expect(res.status).toBe(500);
  expect(rpc).not.toHaveBeenCalled();
});

it("reports a missing database function as an error, with no fallback deletes", async () => {
  rpc.mockResolvedValue({ data: null, error: { code: "PGRST202", message: "Could not find the function public.delete_org_cascade" } });
  const res = await call();
  expect(res.status).toBe(500);
  expect(await res.json()).toEqual({ error: "org_delete_unavailable" });
  expect(fromSpy).not.toHaveBeenCalled();
  expect(cacheDel).not.toHaveBeenCalled();
});

it("reports a failed deletion as an error, not ok:true", async () => {
  rpc.mockResolvedValue({ data: null, error: { code: "P0001", message: "org_delete_blocked: scans" } });
  const res = await call();
  expect(res.status).toBe(500);
  expect(await res.json()).toEqual({ error: "org_delete_failed" });
  expect(writeAuditLog).toHaveBeenCalledTimes(1);
});

it("still succeeds if only the completion audit entry fails (the deletion already happened)", async () => {
  writeAuditLog.mockResolvedValueOnce(undefined).mockRejectedValueOnce(new Error("audit_write_failed"));
  expect((await call()).status).toBe(200);
});

it("is admin only", async () => {
  auth = { org_id: "org-1", role: "developer" };
  expect((await call()).status).toBe(403);
  expect(rpc).not.toHaveBeenCalled();
});
