/**
 * @jest-environment node
 *
 * P0.4: when a REQUIRED audit entry cannot be written, the action is reported as failed (never a success), and is undone where
 * it can be -- or, for irreversible actions, never starts. These drive real routes with an audit_log that refuses inserts.
 */
import { NextRequest } from "next/server";
import { fakeSupabase } from "../helpers/fakeSupabase";

let db: ReturnType<typeof fakeSupabase>;
let auditBroken = false;
const removed: string[] = [];

jest.mock("@/lib/supabase", () => ({ createServiceClient: () => wrapped() }));
jest.mock("@/lib/rateLimit", () => ({ checkRateLimit: async () => ({ success: true, headers: {} }), RATE_LIMITS: { keyCreate: {} } }));
jest.mock("@/lib/cache", () => ({ cacheDel: async () => {}, cacheKeys: { dashboard: () => "d", dependencies: () => "p" } }));
jest.mock("@/app/api/_middleware", () => ({
  verifyApiKey: async () => ({ org_id: "org-1", user_id: "u-admin", actor_email: "admin@acme.dev", role: "admin" }),
  requirePermission: async () => null,
  requireRole: () => null,
  permissionsFor: async () => ({}),
}));

/** The in-memory database, except that inserts into audit_log fail while `auditBroken`. */
function wrapped() {
  const client = db.client as unknown as { from: (t: string) => Record<string, unknown>; storage?: unknown };
  return {
    ...client,
    from: (table: string) => {
      const q = client.from(table);
      if (table === "audit_log" && auditBroken) {
        const real = q.insert as (p: unknown) => unknown;
        q.insert = () => Promise.resolve({ error: { code: "42501", message: "permission denied" } });
        void real;
      }
      return q;
    },
    storage: { from: () => ({ remove: async (paths: string[]) => { removed.push(...paths); return { error: null }; } }) },
  };
}

import { POST as createKey, DELETE as revokeKey } from "@/app/api/keys/route";
import { PATCH as toggleRepo } from "@/app/api/repos/route";
import { DELETE as purge } from "@/app/api/retention/route";
import { DELETE as deleteFile } from "@/app/api/storage/route";
import { PATCH as patchSettings } from "@/app/api/settings/route";

const json = (body: unknown) => ({ method: "POST", body: JSON.stringify(body), headers: { "content-type": "application/json" } });
const table = (name: string) => db.tables[name] as Array<Record<string, unknown>>;
const auditEvents = () => table("audit_log").map(r => r.event_type);

beforeEach(() => {
  auditBroken = false; removed.length = 0;
  db = fakeSupabase({
    audit_log: [], api_keys: [], organizations: [{ id: "org-1", name: "Acme", retention_policy: null }], scans: [], violations: [], secret_findings: [], incidents: [], alerts: [],
    repositories: [{ id: "r1", org_id: "org-1", repo_full_name: "acme/web", is_active: true }],
  });
});

describe("API keys", () => {
  it("creating a key records it and returns the key once", async () => {
    const res = await createKey(new NextRequest("https://app.example/api/keys", json({ name: "ci" })));
    expect(res.status).toBe(200);
    expect((await res.json()).raw_key).toMatch(/^tl_live_/);
    expect(auditEvents()).toEqual(["api_key_created"]);
  });

  it("a key whose creation cannot be recorded is removed, never returned, and the request fails", async () => {
    auditBroken = true;
    const res = await createKey(new NextRequest("https://app.example/api/keys", json({ name: "ci" })));
    expect(res.status).toBe(500);
    const body = await res.json();
    expect(body).toMatchObject({ error: "audit_unavailable", action_completed: false });
    expect(body.raw_key).toBeUndefined();
    expect(table("api_keys")).toHaveLength(0);
  });

  it("a revocation that cannot be recorded stays in force, and is reported as failed to record", async () => {
    table("api_keys").push({ id: "k1", org_id: "org-1", name: "ci", revoked: false });
    auditBroken = true;
    const res = await revokeKey(new NextRequest("https://app.example/api/keys", { method: "DELETE", body: JSON.stringify({ id: "k1" }) }));
    expect(res.status).toBe(500);
    expect(await res.json()).toMatchObject({ error: "audit_unavailable", action_completed: true });
    expect(table("api_keys")[0].revoked).toBe(true);                 // the safe direction is kept
  });
});

describe("repository switch-off", () => {
  const call = (is_active: boolean) => toggleRepo(new NextRequest("https://app.example/api/repos", { method: "PATCH", body: JSON.stringify({ id: "r1", is_active }) }));

  it("is recorded when it works", async () => {
    expect((await call(false)).status).toBe(200);
    expect(auditEvents()).toEqual(["repo_disabled"]);
    expect(table("repositories")[0].is_active).toBe(false);
  });

  it("is undone when it cannot be recorded", async () => {
    auditBroken = true;
    const res = await call(false);
    expect(res.status).toBe(500);
    expect(await res.json()).toMatchObject({ error: "audit_unavailable", action_completed: false });
    expect(table("repositories")[0].is_active).toBe(true);
  });
});

describe("irreversible deletions are recorded BEFORE they happen", () => {
  it("storage: the file is not deleted when the request cannot be recorded", async () => {
    auditBroken = true;
    const res = await deleteFile(new NextRequest("https://app.example/api/storage?path=reports/a.pdf", { method: "DELETE" }));
    expect(res.status).toBe(500);
    expect(removed).toEqual([]);
  });

  it("storage: the file is deleted, with the request recorded first, when auditing works", async () => {
    const res = await deleteFile(new NextRequest("https://app.example/api/storage?path=reports/a.pdf", { method: "DELETE" }));
    expect(res.status).toBe(200);
    expect(removed).toHaveLength(1);
    expect(auditEvents()).toEqual(["evidence_deleted"]);
  });

  it("retention: nothing is purged when the request cannot be recorded", async () => {
    table("scans").push({ id: "s1", org_id: "org-1", created_at: "2020-01-01T00:00:00Z" });
    auditBroken = true;
    const res = await purge(new NextRequest("https://app.example/api/retention?scope=scans&before=2021-01-01T00:00:00Z", { method: "DELETE" }));
    expect(res.status).toBe(500);
    expect(await res.json()).toMatchObject({ error: "audit_unavailable" });
    expect(table("scans")).toHaveLength(1);
  });
});

describe("organisation settings", () => {
  it("a settings change that cannot be recorded is reported as failed", async () => {
    auditBroken = true;
    const res = await patchSettings(new NextRequest("https://app.example/api/settings", { method: "PATCH", body: JSON.stringify({ name: "Renamed" }) }));
    expect(res.status).toBe(500);
    expect(await res.json()).toMatchObject({ error: "audit_unavailable" });
  });
});
