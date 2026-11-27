/**
 * @jest-environment node
 *
 * SCIM changes who has access, so provisioning and deprovisioning are audit-logged -- and when the entry cannot be written,
 * a new member is undone while a removal stays in force (and is recorded when the IdP retries).
 */
import { NextRequest } from "next/server";
import { fakeSupabase } from "../helpers/fakeSupabase";
import { hashScimToken } from "@/lib/scimAuth";

let db: ReturnType<typeof fakeSupabase>;
let auditBroken = false;
const TOKEN = "tl_scim_test-token-0123456789012345678901234567890";

jest.mock("@/lib/supabase", () => ({ createServiceClient: () => wrapped() }));
function wrapped() {
  const client = db.client as unknown as { from: (t: string) => Record<string, unknown> };
  return {
    ...client,
    from: (table: string) => {
      const q = client.from(table);
      if (table === "audit_log" && auditBroken) q.insert = () => Promise.resolve({ error: { code: "42501", message: "permission denied" } });
      return q;
    },
    auth: { admin: { createUser: async ({ email }: { email: string }) => ({ data: { user: { id: `auth-${email}` } }, error: null }) } },
  };
}

import { POST as provision } from "@/app/api/scim/v2/Users/route";
import { DELETE as deprovisionDelete, PATCH as deprovisionPatch } from "@/app/api/scim/v2/Users/[id]/route";

const rows = (t: string) => db.tables[t] as Array<Record<string, unknown>>;
const events = () => rows("audit_log").map(r => r.event_type);
const call = (url: string, method: string, body?: unknown) =>
  new NextRequest(new URL(url, "https://app.example"), { method, headers: { Authorization: `Bearer ${TOKEN}` }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
const ctx = (id: string) => ({ params: Promise.resolve({ id }) });

beforeEach(() => {
  auditBroken = false;
  db = fakeSupabase({
    audit_log: [],
    scim_tokens: [{ org_id: "org-1", token_hash: hashScimToken(TOKEN), token_prefix: TOKEN.slice(0, 14), created_at: "2026-11-01T00:00:00Z", last_used_at: null }],
    org_members: [{ org_id: "org-1", user_id: "u-1", email: "one@acme.com", name: "One", role: "developer" }],
    sso_domains: [{ org_id: "org-1", domain: "acme.com", verification_token: "t", verified_at: "2026-10-01T00:00:00Z" }],
  });
});

describe("provisioning", () => {
  it("is recorded as user_added by scim", async () => {
    const res = await provision(call("/api/scim/v2/Users", "POST", { userName: "new@acme.com" }));
    expect(res.status).toBe(201);
    expect(rows("audit_log")).toEqual([expect.objectContaining({ event_type: "user_added", actor_email: "scim", payload: { via: "scim", email: "new@acme.com", role: "developer" } })]);
  });

  it("is undone, and fails, when it cannot be recorded", async () => {
    auditBroken = true;
    const res = await provision(call("/api/scim/v2/Users", "POST", { userName: "new@acme.com" }));
    expect(res.status).toBe(500);
    expect(rows("org_members").some(m => m.email === "new@acme.com")).toBe(false);
  });
});

describe("deprovisioning", () => {
  it.each([
    ["DELETE", () => deprovisionDelete(call("/api/scim/v2/Users/u-1", "DELETE"), ctx("u-1"))],
    ["PATCH active=false", () => deprovisionPatch(call("/api/scim/v2/Users/u-1", "PATCH", { Operations: [{ op: "replace", path: "active", value: false }] }), ctx("u-1"))],
  ])("%s removes the member and records user_removed with their email", async (_n, run) => {
    expect((await run()).status).toBe(204);
    expect(rows("org_members")).toHaveLength(0);
    expect(rows("audit_log")).toEqual([expect.objectContaining({ event_type: "user_removed", actor_email: "scim", payload: { via: "scim", email: "one@acme.com", already_absent: false } })]);
  });

  it("access stays revoked when the entry cannot be written; the IdP is told it failed, and its retry records it", async () => {
    auditBroken = true;
    const first = await deprovisionDelete(call("/api/scim/v2/Users/u-1", "DELETE"), ctx("u-1"));
    expect(first.status).toBe(500);
    expect(rows("org_members")).toHaveLength(0);                      // the safe direction
    auditBroken = false;
    const retry = await deprovisionDelete(call("/api/scim/v2/Users/u-1", "DELETE"), ctx("u-1"));
    expect(retry.status).toBe(204);
    expect(events()).toEqual(["user_removed"]);
    expect(rows("audit_log")[0].payload).toMatchObject({ already_absent: true });
  });
});
