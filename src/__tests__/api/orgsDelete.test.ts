/**
 * @jest-environment node
 *
 * Organisation deletion workflow (app/api/orgs/delete): request -> waiting period -> explicit execution, with a step-up
 * (authenticator code, or a recent sign-in), a cancellation window, and an explicit job status. A failed run changes nothing
 * and can be repeated or cancelled.
 */
import { NextRequest } from "next/server";
import { fakeSupabase } from "../helpers/fakeSupabase";
import { generateTOTP } from "@/lib/totp";

let db: ReturnType<typeof fakeSupabase>;
let auditBroken = false;
let auth: { org_id: string; role?: string; user_id?: string; actor_email?: string; error?: string };
const rpc = jest.fn();

jest.mock("@/lib/supabase", () => ({ createServiceClient: () => wrapped() }));
jest.mock("@/lib/cache", () => ({ cacheDel: async () => {}, cacheKeys: { dashboard: () => "d", dependencies: () => "p" } }));
jest.mock("@/lib/rateLimit", () => ({ checkRateLimit: async () => ({ success: true, headers: {} }) }));
jest.mock("@/app/api/_middleware", () => ({
  verifyApiKey: async () => auth,
  requireRole: (a: { role?: string }) => (a.role === "admin" ? null : "insufficient_permissions"),
  requirePermission: async () => null,
}));

function wrapped() {
  const client = db.client as unknown as { from: (t: string) => Record<string, unknown> };
  return {
    ...client,
    rpc: (...a: unknown[]) => rpc(...a),
    from: (table: string) => {
      const q = client.from(table);
      if (table === "audit_log" && auditBroken) q.insert = () => Promise.resolve({ error: { code: "42501", message: "permission denied" } });
      return q;
    },
  };
}

import { GET, POST } from "@/app/api/orgs/delete/route";

const SLUG = "acme";
const SECRET = "JBSWY3DPEHPK3PXP";
const rows = (t: string) => db.tables[t] as Array<Record<string, unknown>>;
const events = () => rows("audit_log").map(r => r.event_type);
const open = () => rows("org_deletion_requests")[0] as { status: string; execute_after: string; error: string | null } | undefined;

/** A token whose amr says the person signed in `agoMs` ago. */
const token = (agoMs: number) => {
  const b64 = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
  return `${b64({ alg: "none" })}.${b64({ session_id: "s", amr: [{ method: "password", timestamp: Math.floor((Date.now() - agoMs) / 1000) }] })}.sig`;
};
const call = (body: unknown, bearer: string | null = token(60_000)) => POST(new NextRequest("https://app.example/api/orgs/delete", {
  method: "POST", body: JSON.stringify(body), headers: bearer ? { Authorization: `Bearer ${bearer}` } : {},
}));
const getReq = () => GET(new NextRequest("https://app.example/api/orgs/delete"));

beforeEach(() => {
  jest.clearAllMocks();
  auditBroken = false;
  process.env.ORG_DELETION_DELAY_HOURS = "2";
  auth = { org_id: "org-1", role: "admin", user_id: "u1", actor_email: "a@acme.io" };
  rpc.mockResolvedValue({ data: null, error: null });
  db = fakeSupabase({
    audit_log: [], org_deletion_requests: [], user_2fa: [],
    organizations: [{ id: "org-1", name: "Acme", slug: SLUG }],
    org_members: [{ org_id: "org-1", user_id: "u1" }, { org_id: "org-1", user_id: "u2" }],
    scans: [{ id: "s1", org_id: "org-1" }], repositories: [], violations: [], secret_findings: [], incidents: [], api_keys: [], webhook_configs: [], evidence_log: [],
    attestations: [{ id: "a1", org_id: "org-1" }], audit_checkpoints: [],
  });
});
afterAll(() => { delete process.env.ORG_DELETION_DELAY_HOURS; });

describe("preview", () => {
  it("shows what is deleted and what is kept, the exports to take first, and the delay", async () => {
    const res = await getReq();
    const body = await res.json();
    expect(body.organization).toEqual({ name: "Acme", slug: SLUG });
    expect(body.preview.deleted.find((d: { key: string }) => d.key === "members").count).toBe(2);
    expect(body.preview.deleted.find((d: { key: string }) => d.key === "scans").count).toBe(1);
    expect(body.preview.retained.find((d: { key: string }) => d.key === "attestations").count).toBe(1);
    expect(body.preview.exports.length).toBeGreaterThan(0);
    expect(body).toMatchObject({ request: null, delay_hours: 2, step_up: "recent_signin" });
  });

  it("is admin only", async () => {
    auth = { org_id: "org-1", role: "developer", user_id: "u9" };
    expect((await getReq()).status).toBe(403);
  });
});

describe("requesting", () => {
  it("starts the waiting period, records the request and keeps what would be deleted as shown", async () => {
    const res = await call({ action: "request", confirm: SLUG });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body).toMatchObject({ ok: true, status: "pending", delay_hours: 2 });
    expect(Date.parse(body.execute_after) - Date.now()).toBeGreaterThan(1.9 * 3600_000);
    expect(open()).toMatchObject({ status: "pending" });
    expect(events()).toEqual(["org_deletion_requested"]);
    expect(rpc).not.toHaveBeenCalled();
  });

  it("needs the organisation's name typed exactly", async () => {
    for (const confirm of [undefined, "", "Acme", "acme ", "other"]) {
      const res = await call({ action: "request", confirm });
      expect(res.status).toBe(400);
    }
    expect(rows("org_deletion_requests")).toHaveLength(0);
  });

  it("needs a recent sign-in when two-factor is off", async () => {
    const res = await call({ action: "request", confirm: SLUG }, token(30 * 60_000));
    expect(res.status).toBe(401);
    expect((await res.json()).error).toBe("reauth_required");
    expect((await call({ action: "request", confirm: SLUG }, "not-a-jwt")).status).toBe(401);
    expect(rows("org_deletion_requests")).toHaveLength(0);
  });

  it("an API key cannot request a deletion", async () => {
    auth = { org_id: "org-1", role: "admin" };                         // no user: an org API key
    const res = await call({ action: "request", confirm: SLUG }, null);
    expect(res.status).toBe(403);
    expect((await res.json()).error).toBe("session_required");
  });

  it("with two-factor on, needs a current authenticator code (a recent sign-in is not enough)", async () => {
    rows("user_2fa").push({ user_id: "u1", enabled: true, secret: SECRET });
    expect(((await (await getReq()).json()) as { step_up: string }).step_up).toBe("totp");
    const none = await call({ action: "request", confirm: SLUG });
    expect(none.status).toBe(401);
    expect((await none.json()).error).toBe("mfa_code_required");
    const wrong = await call({ action: "request", confirm: SLUG, code: "000000" });
    expect((await wrong.json()).error).toBe("invalid_code");
    const ok = await call({ action: "request", confirm: SLUG, code: generateTOTP(SECRET) });
    expect(ok.status).toBe(200);
  });

  it("only one open request per organisation", async () => {
    await call({ action: "request", confirm: SLUG });
    const again = await call({ action: "request", confirm: SLUG });
    expect(again.status).toBe(409);
    expect(rows("org_deletion_requests")).toHaveLength(1);
  });

  it("is withdrawn if the request cannot be recorded", async () => {
    auditBroken = true;
    const res = await call({ action: "request", confirm: SLUG });
    expect(res.status).toBe(500);
    expect(rows("org_deletion_requests")).toHaveLength(0);
  });
});

describe("executing", () => {
  const request = async () => { await call({ action: "request", confirm: SLUG }); };
  const elapse = () => { rows("org_deletion_requests")[0].execute_after = new Date(Date.now() - 1000).toISOString(); };

  it("is refused during the waiting period, and nothing is deleted", async () => {
    await request();
    const res = await call({ action: "execute", confirm: SLUG });
    expect(res.status).toBe(409);
    expect(await res.json()).toMatchObject({ error: "waiting_period" });
    expect(rpc).not.toHaveBeenCalled();
    expect(open()!.status).toBe("pending");
  });

  it("after the waiting period: records the start, deletes in one call, records completion", async () => {
    await request(); elapse();
    const res = await call({ action: "execute", confirm: SLUG });
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true, status: "completed" });
    expect(rpc).toHaveBeenCalledWith("delete_org_cascade", { target_org_id: "org-1" });
    expect(events()).toEqual(["org_deletion_requested", "org_deletion_started", "org_deleted"]);
    expect(open()!.status).toBe("completed");
  });

  it("needs the name and a step-up again", async () => {
    await request(); elapse();
    expect((await call({ action: "execute", confirm: "nope" })).status).toBe(400);
    const stale = await call({ action: "execute", confirm: SLUG }, token(60 * 60_000));
    expect(stale.status).toBe(401);
    expect(rpc).not.toHaveBeenCalled();
    expect(open()!.status).toBe("pending");
  });

  it("deletes nothing, and goes back to pending, when the start cannot be recorded", async () => {
    await request(); elapse();
    auditBroken = true;
    const res = await call({ action: "execute", confirm: SLUG });
    expect(res.status).toBe(500);
    expect(rpc).not.toHaveBeenCalled();
    expect(open()!.status).toBe("pending");
  });

  it("a failed run changes nothing, is marked failed with the reason, and can be run again", async () => {
    await request(); elapse();
    rpc.mockResolvedValueOnce({ data: null, error: { code: "P0001", message: "org_delete_blocked: scans" } });
    const res = await call({ action: "execute", confirm: SLUG });
    expect(res.status).toBe(500);
    expect(await res.json()).toMatchObject({ error: "org_delete_failed", request_status: "failed" });
    expect(open()).toMatchObject({ status: "failed", error: "org_delete_blocked: scans" });
    expect(events()).not.toContain("org_deleted");

    const retry = await call({ action: "execute", confirm: SLUG });
    expect(retry.status).toBe(200);
    expect(open()!.status).toBe("completed");
    expect(rpc).toHaveBeenCalledTimes(2);
  });

  it("a missing database function is reported, not hidden", async () => {
    await request(); elapse();
    rpc.mockResolvedValueOnce({ data: null, error: { code: "PGRST202", message: "Could not find the function public.delete_org_cascade" } });
    const res = await call({ action: "execute", confirm: SLUG });
    expect((await res.json()).error).toBe("org_delete_unavailable");
    expect(open()!.status).toBe("failed");
  });

  it("only one execution at a time", async () => {
    await request(); elapse();
    open()!.status = "executing";
    const res = await call({ action: "execute", confirm: SLUG });
    expect(res.status).toBe(409);
    expect(rpc).not.toHaveBeenCalled();
  });

  it("without a request there is nothing to execute", async () => {
    expect((await call({ action: "execute", confirm: SLUG })).status).toBe(404);
    expect(rpc).not.toHaveBeenCalled();
  });
});

describe("cancelling", () => {
  it("stops a pending request, records it, and then nothing can be executed", async () => {
    await call({ action: "request", confirm: SLUG });
    const res = await call({ action: "cancel" }, token(3 * 3600_000));          // no step-up needed to cancel
    expect(res.status).toBe(200);
    expect(open()).toMatchObject({ status: "cancelled" });
    expect(events()).toEqual(["org_deletion_requested", "org_deletion_cancelled"]);
    expect((await call({ action: "execute", confirm: SLUG })).status).toBe(404);
    expect(rpc).not.toHaveBeenCalled();
  });

  it("can also drop a failed run", async () => {
    await call({ action: "request", confirm: SLUG });
    open()!.status = "failed";
    expect((await call({ action: "cancel" })).status).toBe(200);
    expect(open()!.status).toBe("cancelled");
  });

  it("cannot cancel a deletion that is running", async () => {
    await call({ action: "request", confirm: SLUG });
    open()!.status = "executing";
    expect((await call({ action: "cancel" })).status).toBe(409);
    expect(open()!.status).toBe("executing");
  });

  it("a new request can be made after a cancellation", async () => {
    await call({ action: "request", confirm: SLUG });
    await call({ action: "cancel" });
    expect((await call({ action: "request", confirm: SLUG })).status).toBe(200);
  });

  it("is admin only", async () => {
    await call({ action: "request", confirm: SLUG });
    auth = { org_id: "org-1", role: "developer", user_id: "u9" };
    expect((await call({ action: "cancel" })).status).toBe(403);
    expect(open()!.status).toBe("pending");
  });
});

it("a body with no action does nothing (the old one-call deletion is gone)", async () => {
  const res = await call({});
  expect(res.status).toBe(400);
  expect(await res.json()).toMatchObject({ error: "action_required" });
  expect(rpc).not.toHaveBeenCalled();
});
