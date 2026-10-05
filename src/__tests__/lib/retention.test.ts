/**
 * @jest-environment node
 *
 * Data retention: the stored policy, what automatic enforcement deletes (old, closed, unattested -- this org
 * only) and what it never touches, the daily cron, and the API.
 */
import { NextRequest } from "next/server";
import { fakeSupabase } from "../helpers/fakeSupabase";

let db: ReturnType<typeof fakeSupabase>;
let role = "admin";
jest.mock("@/lib/supabase", () => ({ createServiceClient: () => db.client }));
const audit = jest.fn(async (..._a: unknown[]) => {});
jest.mock("@/lib/audit", () => ({ writeAuditLog: (...a: unknown[]) => audit(...a) }));
jest.mock("@/app/api/_middleware", () => ({
  ...jest.requireActual("@/app/api/_middleware"),
  verifyApiKey: async () => ({ org_id: "org-1", user_id: "u1", actor_email: "a@acme.test", role }),
}));
jest.mock("@/lib/pipelineHealth", () => ({ pipelineHealth: async () => ({ stuck_scans: [], undelivered_webhooks: [] }) }));
jest.mock("@/lib/opsEvents", () => ({ recordEvent: jest.fn(async () => {}) }));

import { RETENTION_DEFAULTS, enforceRetention, normalizeRetention } from "@/lib/retention";
import { GET as cronGET } from "@/app/api/cron/pipeline-health/route";
import { GET as retGET, PATCH as retPATCH, DELETE as retDELETE } from "@/app/api/retention/route";

const NOW = Date.parse("2026-10-05T00:00:00Z");
const daysAgo = (d: number) => new Date(NOW - d * 86_400_000).toISOString();
const rows = (t: string) => (db.client.from(t) as unknown as { rows: Record<string, unknown>[] }).rows;
const ids = (t: string) => rows(t).map(r => r.id).sort();
const req = (url: string, method = "GET", body?: unknown, headers: Record<string, string> = {}) =>
  new NextRequest(new URL(url, "https://app.example"), { method, headers, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });

function world(policy: unknown = { ...RETENTION_DEFAULTS, auto_enforce: true }) {
  db = fakeSupabase({
    organizations: [{ id: "org-1", retention_policy: policy }, { id: "org-2", retention_policy: { ...RETENTION_DEFAULTS, auto_enforce: false } }],
    scans: [
      { id: "s-old-attested", org_id: "org-1", created_at: daysAgo(500) },
      { id: "s-old",          org_id: "org-1", created_at: daysAgo(500) },
      { id: "s-new",          org_id: "org-1", created_at: daysAgo(10) },
      { id: "s-other-org",    org_id: "org-2", created_at: daysAgo(900) },
    ],
    attestations: [{ id: "a1", org_id: "org-1", scan_id: "s-old-attested" }],
    violations: [
      { id: "v-of-old-scan",  org_id: "org-1", scan_id: "s-old", status: "open",     created_at: daysAgo(500) },
      { id: "v-old-resolved", org_id: "org-1", scan_id: "s-new", status: "resolved", created_at: daysAgo(400) },
      { id: "v-old-open",     org_id: "org-1", scan_id: "s-new", status: "open",     created_at: daysAgo(400) },
      { id: "v-new-resolved", org_id: "org-1", scan_id: "s-new", status: "resolved", created_at: daysAgo(5) },
      { id: "v-other-org",    org_id: "org-2", scan_id: "s-other-org", status: "resolved", created_at: daysAgo(900) },
    ],
    secret_findings: [],
    alerts: [
      { id: "al-old-resolved", org_id: "org-1", status: "resolved", created_at: daysAgo(400) },
      { id: "al-old-firing",   org_id: "org-1", status: "firing",   created_at: daysAgo(400) },
    ],
    incidents: [
      { id: "i-old-resolved", org_id: "org-1", status: "resolved", created_at: daysAgo(3000) },
      { id: "i-old-active",   org_id: "org-1", status: "active",   created_at: daysAgo(3000) },
    ],
    audit_log: [{ id: 1, org_id: "org-1", created_at: daysAgo(4000) }],
    ops_events: [],
  });
}

beforeEach(() => { jest.clearAllMocks(); role = "admin"; world(); process.env.CRON_SECRET = "cron-test"; });

describe("policy", () => {
  it("fills defaults, clamps to bounds, drops unknown keys, and is off unless chosen", () => {
    const p = normalizeRetention({ scans_days: 5, violations_days: 99999, audit_log_days: 100, bogus: 1 });
    expect(p).toMatchObject({ scans_days: 30, violations_days: 2555, audit_log_days: 365, incidents_days: 2555, auto_enforce: false });
    expect("bogus" in p).toBe(false);
    expect(normalizeRetention(null)).toEqual(RETENTION_DEFAULTS);
  });
});

describe("automatic enforcement", () => {
  it("deletes old closed records and old unattested scans -- nothing open, attested, recent, other-org, or audit", async () => {
    const r = await enforceRetention(db.client as never, "org-1", normalizeRetention({ ...RETENTION_DEFAULTS, auto_enforce: true }), NOW);
    expect(ids("scans")).toEqual(["s-new", "s-old-attested", "s-other-org"]);
    // the old scan's own violation goes with it; standalone old ones only when closed
    expect(ids("violations")).toEqual(["v-new-resolved", "v-old-open", "v-other-org"]);
    expect(ids("alerts")).toEqual(["al-old-firing"]);
    expect(ids("incidents")).toEqual(["i-old-active"]);
    expect(rows("audit_log")).toHaveLength(1);
    expect(rows("attestations")).toHaveLength(1);
    expect(r).toMatchObject({ attested_scans_kept: 1, failed: [] });
    expect(r.deleted).toMatchObject({ scans: 1, violations: 1, alerts: 1, incidents: 1 });
  });

  it("the daily cron applies it only for orgs that switched it on, and records the run", async () => {
    const res = await cronGET(req("/api/cron/pipeline-health", "GET", undefined, { authorization: "Bearer cron-test" }));
    expect(await res.json()).toMatchObject({ ok: true, retention_orgs: 1 });
    expect(ids("scans")).toContain("s-other-org");          // org-2 has it off
    expect(ids("scans")).not.toContain("s-old");            // org-1 has it on
    const stored = rows("organizations").find(o => o.id === "org-1")!.retention_policy as Record<string, unknown>;
    expect(stored).toMatchObject({ auto_enforce: true, last_result: expect.objectContaining({ attested_scans_kept: 1 }) });
    expect(audit).toHaveBeenCalledWith(expect.anything(), expect.objectContaining({ org_id: "org-1", resource_type: "data_deletion", payload: expect.objectContaining({ automatic: true }) }));
  });

  it("with it off, the cron deletes nothing", async () => {
    world({ ...RETENTION_DEFAULTS, auto_enforce: false });
    await cronGET(req("/api/cron/pipeline-health", "GET", undefined, { authorization: "Bearer cron-test" }));
    expect(ids("scans")).toHaveLength(4);
    expect(ids("violations")).toHaveLength(5);
  });
});

describe("/api/retention", () => {
  it("GET returns the stored policy; PATCH saves a clamped one (and can't forge the last run)", async () => {
    world({ ...RETENTION_DEFAULTS, scans_days: 180 });
    expect((await (await retGET(req("/api/retention"))).json()).policy).toMatchObject({ scans_days: 180, auto_enforce: false });
    const res = await retPATCH(req("/api/retention", "PATCH", { scans_days: 10, auto_enforce: true, last_result: { at: "x", deleted: {}, attested_scans_kept: 0, failed: [] } }));
    expect(res.status).toBe(200);
    const stored = rows("organizations").find(o => o.id === "org-1")!.retention_policy as Record<string, unknown>;
    expect(stored).toMatchObject({ scans_days: 30, auto_enforce: true });
    expect(stored.last_result ?? null).toBeNull();
  });

  it("changing it needs the policies permission", async () => {
    role = "developer";
    expect((await retPATCH(req("/api/retention", "PATCH", { auto_enforce: true }))).status).toBe(403);
    expect((rows("organizations")[0].retention_policy as Record<string, unknown>).scans_days).toBe(365);
  });

  it("a manual delete is explicit, so it includes open records -- but never attested scans or other orgs", async () => {
    const res = await retDELETE(req(`/api/retention?scope=all&before=${encodeURIComponent(daysAgo(300))}`, "DELETE"));
    const body = await res.json();
    expect(body.skipped.scans).toMatch(/1 attested/);
    expect(ids("scans")).toEqual(["s-new", "s-old-attested", "s-other-org"]);
    expect(ids("violations")).toEqual(["v-new-resolved", "v-other-org"]);
    expect(ids("alerts")).toEqual([]);
  });
});
