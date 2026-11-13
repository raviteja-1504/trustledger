/**
 * @jest-environment node
 *
 * Does the REST API work, start to finish? A signed-in admin creates an API key (POST /api/keys), then a CI job uses ONLY that key to submit a
 * scan (POST /api/scans with X-TrustLedger-Key), exactly as the getting-started guide describes. The real authentication, permission checks,
 * validation, scanner and storage code run; only the database, the session lookup and a few side effects are faked.
 */
import { NextRequest } from "next/server";
import { fakeSupabase } from "../helpers/fakeSupabase";

let db: ReturnType<typeof fakeSupabase>;
const session = { id: "u1", email: "admin@acme.dev" };
jest.mock("@/lib/supabase", () => ({
  createServiceClient: () => ({
    ...db.client,
    auth: { getUser: async (token: string) => token === "session-token" ? { data: { user: session }, error: null } : { data: { user: null }, error: { message: "bad" } } },
  }),
}));
jest.mock("@/lib/jwt", () => ({ getJwtSessionId: () => null, getJwtSsoProviderId: () => null }));
jest.mock("@/lib/ssoMembership", () => ({ ...jest.requireActual("@/lib/ssoMembership"), ssoEnforcement: async () => ({ enforce: false, provider_id: null }) }));
jest.mock("@/lib/engineWarmup", () => ({ ensureTaintEngines: async () => undefined }));
jest.mock("@/lib/audit", () => ({ writeAuditLog: async () => undefined }));
jest.mock("@/lib/autoIncidents", () => ({ syncAutoIncidents: async () => undefined }));
// the rate limiter is memory-backed and lives across tests (10 keys an hour would trip after a few of them); it has its own tests
jest.mock("@/lib/rateLimit", () => ({ ...jest.requireActual("@/lib/rateLimit"), checkRateLimit: async () => ({ success: true, headers: {} }) }));

import { POST as createKey, GET as listKeys, DELETE as revokeKey } from "@/app/api/keys/route";
import { POST as submitScan, GET as listScans } from "@/app/api/scans/route";

const url = (p: string) => new URL(p, "https://app.example");
const asSession = { Authorization: "Bearer session-token", "Content-Type": "application/json" };
const asKey = (key: string) => ({ "X-TrustLedger-Key": key, "Content-Type": "application/json" });

const VULNERABLE = `const express = require("express");\nconst app = express();\napp.get("/user", (req, res) => {\n  db.query("SELECT * FROM users WHERE id = " + req.query.id);\n});\n`;
const scanBody = (over: Record<string, unknown> = {}) => JSON.stringify({
  repo: "acme/api", pr_number: 482, commit_sha: "abc123def456", branch: "main",
  files: [{ path: "src/routes.js", content: VULNERABLE }], ...over,
});

beforeEach(() => {
  process.env.NEXT_PUBLIC_SKIP_AUTH = "false";
  db = fakeSupabase({
    org_members: [{ org_id: "org-1", user_id: "u1", role: "admin", email: "admin@acme.dev", active_session_id: null }],
    user_2fa: [], api_keys: [], repositories: [], scans: [], scan_files: [], violations: [], secret_findings: [],
  });
});

let keySeq = 0;
async function newKey(name = "ci") {
  const res = await createKey(new NextRequest(url("/api/keys"), { method: "POST", headers: asSession, body: JSON.stringify({ name }) }));
  const body = await res.json() as { id: string; raw_key: string; key_prefix: string };
  // the real database generates the row's id; the fake one does not
  const id = `key-${++keySeq}`;
  await db.client.from("api_keys").update({ id }).eq("name", name);
  return { res, body: { ...body, id } };
}

describe("creating an API key", () => {
  it("a signed-in admin gets a tl_live_ key, shown once; only its hash is stored", async () => {
    const { res, body } = await newKey();
    expect(res.status).toBe(200);
    expect(body.raw_key).toMatch(/^tl_live_[0-9a-f]{40}$/);
    const stored = (await db.client.from("api_keys").select("*")) as unknown as { data: Array<Record<string, unknown>> };
    expect(stored.data).toHaveLength(1);
    expect(JSON.stringify(stored.data[0])).not.toContain(body.raw_key);
    expect(stored.data[0]).toMatchObject({ org_id: "org-1", name: "ci" });
  });

  it("a request with no credentials is refused", async () => {
    const res = await createKey(new NextRequest(url("/api/keys"), { method: "POST", body: JSON.stringify({ name: "x" }) }));
    expect(res.status).toBe(401);
  });
});

describe("submitting a scan with only the key", () => {
  it("works: the scanner runs, the scan and its files are stored under the key's organisation, and the findings come back", async () => {
    const { body: key } = await newKey();
    const res = await submitScan(new NextRequest(url("/api/scans"), { method: "POST", headers: asKey(key.raw_key), body: scanBody() }));
    expect(res.status).toBe(200);
    const out = await res.json() as { scan_id: string; repo: string; file_count: number; overall_risk: string; files: Array<{ file_path: string; risk_indicators: string[] }> };
    expect(out).toMatchObject({ repo: "acme/api", file_count: 1 });
    expect(out.files[0].file_path).toBe("src/routes.js");
    expect(out.files[0].risk_indicators).toContain("sql-injection");
    expect(["HIGH", "CRITICAL"]).toContain(out.overall_risk);

    const scans = (await db.client.from("scans").select("*")) as unknown as { data: Array<Record<string, unknown>> };
    expect(scans.data).toHaveLength(1);
    expect(scans.data[0]).toMatchObject({ id: out.scan_id, org_id: "org-1", repo_full_name: "acme/api", pr_number: 482 });
    const files = (await db.client.from("scan_files").select("*")) as unknown as { data: Array<Record<string, unknown>> };
    expect(files.data).toHaveLength(1);
    expect(files.data[0]).toMatchObject({ scan_id: out.scan_id, org_id: "org-1", file_path: "src/routes.js" });
    const viol = (await db.client.from("violations").select("*")) as unknown as { data: unknown[] };
    expect(viol.data.length).toBeGreaterThan(0);          // a high-risk file opens a violation to attest
  });

  it("the same key can read the scans back", async () => {
    const { body: key } = await newKey();
    await submitScan(new NextRequest(url("/api/scans"), { method: "POST", headers: asKey(key.raw_key), body: scanBody() }));
    // a connected repository is active by default in the real database
    await db.client.from("repositories").update({ is_active: true }).eq("org_id", "org-1");
    const res = await listScans(new NextRequest(url("/api/scans"), { headers: asKey(key.raw_key) }));
    expect(res.status).toBe(200);
    expect((await res.json()).scans).toHaveLength(1);
  });

  it("refuses a made-up key, a missing key and a malformed request", async () => {
    const { body: key } = await newKey();
    expect((await submitScan(new NextRequest(url("/api/scans"), { method: "POST", headers: asKey("tl_live_" + "0".repeat(40)), body: scanBody() }))).status).toBe(401);
    expect((await submitScan(new NextRequest(url("/api/scans"), { method: "POST", headers: { "Content-Type": "application/json" }, body: scanBody() }))).status).toBe(401);
    const bad = await submitScan(new NextRequest(url("/api/scans"), { method: "POST", headers: asKey(key.raw_key), body: scanBody({ repo: "not-a-repo" }) }));
    expect(bad.status).toBe(400);
  });

  it("a revoked key stops working at once", async () => {
    const { body: key } = await newKey();
    expect((await submitScan(new NextRequest(url("/api/scans"), { method: "POST", headers: asKey(key.raw_key), body: scanBody() }))).status).toBe(200);
    const rev = await revokeKey(new NextRequest(url("/api/keys"), { method: "DELETE", headers: asSession, body: JSON.stringify({ id: key.id }) }));
    expect(rev.status).toBe(200);
    const res = await submitScan(new NextRequest(url("/api/scans"), { method: "POST", headers: asKey(key.raw_key), body: scanBody({ commit_sha: "deadbeef01" }) }));
    expect(res.status).toBe(401);
    expect(await res.json()).toMatchObject({ error: "invalid_api_key" });
  });

  it("an expired key is refused", async () => {
    const { body: key } = await newKey();
    await db.client.from("api_keys").update({ expires_at: "2020-01-01T00:00:00Z" }).eq("id", key.id);
    const res = await submitScan(new NextRequest(url("/api/scans"), { method: "POST", headers: asKey(key.raw_key), body: scanBody() }));
    expect(await res.json()).toMatchObject({ error: "api_key_expired" });
  });
});

describe("what a key may not do", () => {
  it("it cannot create or list API keys (management needs a signed-in person)", async () => {
    const { body: key } = await newKey();
    expect((await createKey(new NextRequest(url("/api/keys"), { method: "POST", headers: asKey(key.raw_key), body: JSON.stringify({ name: "escalate" }) }))).status).toBe(403);
    expect((await listKeys(new NextRequest(url("/api/keys"), { headers: asKey(key.raw_key) }))).status).toBe(403);
  });
});

describe("the plan's limits apply to the API too", () => {
  const used = (n: number, when = new Date().toISOString()) => db.client.from("scans").insert(Array.from({ length: n }, (_, i) => ({ id: `old-${when}-${i}`, org_id: "org-1", repo_full_name: "acme/api", created_at: when })));
  const submitWithKey = async (over: Record<string, unknown> = {}) => {
    const { body: key } = await newKey();
    return submitScan(new NextRequest(url("/api/scans"), { method: "POST", headers: asKey(key.raw_key), body: scanBody(over) }));
  };
  const scanCount = async () => ((await db.client.from("scans").select("id")) as unknown as { data: unknown[] }).data.length;

  it("the 4th scan of the month is refused, says why and how to get more, and stores nothing", async () => {
    await used(3);
    await db.client.from("repositories").insert({ org_id: "org-1", repo_full_name: "acme/api", is_active: true });
    const res = await submitWithKey();
    expect(res.status).toBe(403);
    const body = await res.json() as { error: string; message: string };
    expect(body.error).toBe("plan_limit_scans");
    expect(body.message).toMatch(/3 scans a month/);
    expect(body.message).toMatch(/Contact us to upgrade/);
    expect(await scanCount()).toBe(3);
  });

  it("scans from an earlier month do not count", async () => {
    await used(3, "2020-01-15T10:00:00Z");
    expect((await submitWithKey()).status).toBe(200);
  });

  it("a second repository is refused; the connected one still works", async () => {
    await db.client.from("repositories").insert({ org_id: "org-1", repo_full_name: "acme/api", is_active: true });
    const other = await submitWithKey({ repo: "acme/other" });
    expect(other.status).toBe(403);
    expect(await other.json()).toMatchObject({ error: "plan_limit_repos" });
    expect((await submitWithKey({ repo: "acme/api", commit_sha: "feedface01" })).status).toBe(200);
  });

  it("a signed-in person (the dashboard's New scan) is held to the same limits", async () => {
    await used(3);
    const res = await submitScan(new NextRequest(url("/api/scans"), { method: "POST", headers: asSession, body: scanBody() }));
    expect(res.status).toBe(403);
    expect(await res.json()).toMatchObject({ error: "plan_limit_scans" });
  });

  it("a scan submitted with a key is recorded as an API scan", async () => {
    expect((await submitWithKey()).status).toBe(200);
    const scans = (await db.client.from("scans").select("*")) as unknown as { data: Array<{ triggered_by: string }> };
    expect(scans.data[0].triggered_by).toBe("api");
  });
});

