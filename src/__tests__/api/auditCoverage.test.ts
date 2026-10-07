/**
 * @jest-environment node
 *
 * Audit-log coverage for the actions an enterprise reviewer asks about: sign-ins, repository changes, data
 * exports and evidence files. Runs the real routes and the real (hash-chained) audit writer against an
 * in-memory database, and reads back the audit_log rows they wrote.
 */
import { NextRequest } from "next/server";
import { fakeSupabase } from "../helpers/fakeSupabase";
import { generateTOTP, generateTOTPSecret } from "@/lib/totp";

let db: ReturnType<typeof fakeSupabase>;
const users: Record<string, Record<string, unknown>> = {};
jest.mock("@/lib/supabase", () => ({
  createServiceClient: () => ({
    ...db.client,
    auth: { getUser: async (token: string) => {
      const sub = JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString()).sub as string;
      return users[sub] ? { data: { user: users[sub] }, error: null } : { data: { user: null }, error: { message: "bad" } };
    } },
    storage: { from: () => ({
      upload: async () => ({ error: null }),
      remove: async () => ({ error: null }),
      createSignedUrl: async (p: string) => ({ data: { signedUrl: `https://signed/${p}` }, error: null }),
    }) },
  }),
}));
jest.mock("@/lib/rateLimit", () => ({ checkRateLimit: async () => ({ success: true, reset: 0, headers: {} }) }));
jest.mock("@/lib/cache", () => ({ cacheDel: async () => {}, cacheKeys: { dashboard: () => "d" }, cached: async (_k: string, _t: number, f: () => unknown) => f() }));
let caller: Record<string, unknown> = {};
jest.mock("@/app/api/_middleware", () => ({
  ...jest.requireActual("@/app/api/_middleware"),
  verifyApiKey: async () => caller,
}));
jest.mock("@/lib/github", () => ({
  getInstallationToken: async () => ({ token: "t" }),
  listInstallationRepos: async () => [{ full_name: "acme/new-one", default_branch: "main" }, { full_name: "acme/new-two", default_branch: "main" }, { full_name: "acme/existing", default_branch: "main" }],
}));

import { POST as bootstrap } from "@/app/api/auth/bootstrap/route";
import { POST as mfaVerify } from "@/app/api/auth/2fa/login/route";
import { POST as reposPOST, PATCH as reposPATCH } from "@/app/api/repos/route";
import { GET as exportGET } from "@/app/api/export/route";
import { GET as sarifGET } from "@/app/api/export/sarif/route";
import { GET as signedGET } from "@/app/api/export/signed/route";
import { POST as storagePOST, DELETE as storageDELETE } from "@/app/api/storage/route";

const ADMIN = { org_id: "org-1", user_id: "u-admin", actor_email: "admin@acme.dev", role: "admin" };
const DEV   = { org_id: "org-1", user_id: "u-dev", actor_email: "dev@acme.dev", role: "developer" };
const token = (sub: string, session: string) => `h.${Buffer.from(JSON.stringify({ sub, session_id: session })).toString("base64url")}.s`;
const rows = (t: string) => (db.client.from(t) as unknown as { rows: Record<string, unknown>[] }).rows;
const audit = (type?: string) => rows("audit_log").filter(r => !type || r.event_type === type);
const req = (url: string, init: { method?: string; body?: unknown; auth?: string } = {}) =>
  new NextRequest(new URL(url, "https://app.example"), {
    method: init.method ?? "GET",
    headers: init.auth ? { Authorization: `Bearer ${init.auth}`, "Content-Type": "application/json" } : {},
    ...(init.body === undefined ? {} : { body: init.body instanceof FormData ? init.body : JSON.stringify(init.body) }),
  });

const savedKey = process.env.EXPORT_SIGNING_KEY;
beforeEach(() => {
  for (const k of Object.keys(users)) delete users[k];
  caller = { ...ADMIN };
  process.env.EXPORT_SIGNING_KEY = "test-signing-key";
  db = fakeSupabase({
    organizations: [{ id: "org-1", name: "Acme", slug: "acme" }],
    org_members: [
      { id: "m1", org_id: "org-1", user_id: "u-admin", email: "admin@acme.dev", role: "admin", active_session_id: "old", custom_role_id: null },
      { id: "m2", org_id: "org-1", user_id: "u-dev", email: "dev@acme.dev", role: "developer", active_session_id: null, custom_role_id: null },
    ],
    user_2fa: [],
    audit_log: [],
    repositories: [{ id: "r1", org_id: "org-1", repo_full_name: "acme/existing", is_active: true, default_branch: "main" }],
    github_installations: [{ org_id: "org-1", installation_id: 7, github_org: "acme" }],
    violations: [{ id: "v1", org_id: "org-1", scan_id: "s1", file_path: "a.ts", risk_score: "HIGH", status: "open", created_at: "2026-10-01" }],
    scans: [{ id: "s1", org_id: "org-1", repo_full_name: "acme/existing" }],
    scan_files: [{ scan_id: "s1", file_path: "a.ts", indicators: [{ id: "sql-injection", severity: "critical", line: 3, label: "SQLi", detail: "d" }] }],
  });
});
afterAll(() => { if (savedKey === undefined) delete process.env.EXPORT_SIGNING_KEY; else process.env.EXPORT_SIGNING_KEY = savedKey; });

describe("sign-ins", () => {
  it("a new session writes one user_login; a repeated bootstrap for the same session does not", async () => {
    users["u-admin"] = { id: "u-admin", email: "admin@acme.dev", email_confirmed_at: "2026-10-01", app_metadata: { provider: "github" } };
    expect((await bootstrap(req("/api/auth/bootstrap", { method: "POST", body: {}, auth: token("u-admin", "s-new") }))).status).toBe(200);
    expect((await bootstrap(req("/api/auth/bootstrap", { method: "POST", body: {}, auth: token("u-admin", "s-new") }))).status).toBe(200);
    expect(audit("user_login")).toEqual([expect.objectContaining({
      org_id: "org-1", actor_id: "u-admin", actor_email: "admin@acme.dev", resource_id: "s-new",
      payload: { method: "github", mfa: false },
    })]);
    // a later sign-in is a new entry, chained to the previous one
    await bootstrap(req("/api/auth/bootstrap", { method: "POST", body: {}, auth: token("u-admin", "s-later") }));
    const logins = audit("user_login");
    expect(logins).toHaveLength(2);
    expect(logins[1].prev_hash).toBe(logins[0].entry_hash);
  });

  it("someone with no org gets no login entry", async () => {
    users.stranger = { id: "stranger", email: "x@y.dev", email_confirmed_at: "2026-10-01", app_metadata: { provider: "email" } };
    await bootstrap(req("/api/auth/bootstrap", { method: "POST", body: {}, auth: token("stranger", "s1") }));
    expect(audit()).toEqual([]);
  });

  it("with 2FA on, the login is written by the 2FA step (mfa: true), not by bootstrap", async () => {
    const secret = generateTOTPSecret();
    rows("user_2fa").push({ user_id: "u-admin", enabled: true, secret, backup_codes: [] });
    users["u-admin"] = { id: "u-admin", email: "admin@acme.dev", email_confirmed_at: "2026-10-01", app_metadata: { provider: "email" } };
    const pre = await (await bootstrap(req("/api/auth/bootstrap", { method: "POST", body: {}, auth: token("u-admin", "s2") }))).json();
    expect(pre.mfa_required).toBe(true);
    expect(audit("user_login")).toEqual([]);
    expect((await mfaVerify(req("/api/auth/2fa/login", { method: "POST", body: { code: generateTOTP(secret) }, auth: token("u-admin", "s2") }))).status).toBe(200);
    expect(audit("user_login")).toEqual([expect.objectContaining({
      actor_id: "u-admin", resource_id: "s2", payload: { method: "email", mfa: true, mfa_method: "totp" },
    })]);
    expect(audit("org_settings_changed")).toEqual([]);
  });
});

describe("repository changes", () => {
  it("import from GitHub records the repos it added (not ones already connected)", async () => {
    expect((await reposPOST(req("/api/repos?import=github", { method: "POST" }))).status).toBe(200);
    expect(audit("repo_connected")).toEqual([expect.objectContaining({
      actor_email: "admin@acme.dev", payload: { source: "github_import", count: 2, repos: ["acme/new-one", "acme/new-two"] },
    })]);
  });

  it("an import that adds nothing writes nothing", async () => {
    rows("repositories").push({ id: "r2", org_id: "org-1", repo_full_name: "acme/new-one" }, { id: "r3", org_id: "org-1", repo_full_name: "acme/new-two" });
    await reposPOST(req("/api/repos?import=github", { method: "POST" }));
    expect(audit()).toEqual([]);
  });

  it("adding one repo by name", async () => {
    expect((await reposPOST(req("/api/repos", { method: "POST", body: { repo_full_name: "acme/manual" } }))).status).toBe(200);
    expect(audit("repo_connected")).toEqual([expect.objectContaining({ resource_id: "acme/manual", payload: { source: "manual", repo: "acme/manual" } })]);
  });

  it("switching a repo off and on", async () => {
    await reposPATCH(req("/api/repos", { method: "PATCH", body: { id: "r1", is_active: false } }));
    await reposPATCH(req("/api/repos", { method: "PATCH", body: { id: "r1", is_active: true } }));
    expect(audit().map(r => [r.event_type, (r.payload as { repo: string }).repo])).toEqual([["repo_disabled", "acme/existing"], ["repo_enabled", "acme/existing"]]);
  });

  it("a refused or failed change writes nothing", async () => {
    caller = { ...DEV };
    expect((await reposPOST(req("/api/repos", { method: "POST", body: { repo_full_name: "acme/x" } }))).status).toBe(403);
    caller = { ...ADMIN };
    expect((await reposPATCH(req("/api/repos", { method: "PATCH", body: { id: "nope", is_active: false } }))).status).toBe(404);
    expect(audit()).toEqual([]);
  });
});

describe("data exports", () => {
  it("CSV/JSON export records type, format and row count", async () => {
    expect((await exportGET(req("/api/export?type=violations&format=csv"))).status).toBe(200);
    expect((await exportGET(req("/api/export?type=violations&format=json"))).status).toBe(200);
    expect(audit("data_exported").map(r => r.payload)).toEqual([
      { export_type: "violations", format: "csv", rows: 1 },
      { export_type: "violations", format: "json", rows: 1 },
    ]);
  });

  it("an invalid type or a refused caller writes nothing", async () => {
    expect((await exportGET(req("/api/export?type=nope"))).status).toBe(400);
    caller = { ...DEV };
    expect((await exportGET(req("/api/export?type=violations"))).status).toBe(403);
    expect(audit()).toEqual([]);
  });

  it("SARIF export", async () => {
    expect((await sarifGET(req("/api/export/sarif?scan_id=s1"))).status).toBe(200);
    expect(audit("data_exported")).toEqual([expect.objectContaining({
      resource_id: "s1", payload: { export_type: "sarif", format: "sarif", scan_id: "s1", repo: "acme/existing", findings: 1 },
    })]);
  });

  it("signed audit export now needs can_export_data (a developer was let through before), and is recorded", async () => {
    caller = { ...DEV };
    expect((await signedGET(req("/api/export/signed"))).status).toBe(403);
    caller = { ...ADMIN };
    const res = await signedGET(req("/api/export/signed"));
    expect(res.status).toBe(200);
    // the export it returned does not include its own entry
    expect((await res.json()).events).toEqual([]);
    expect(audit("data_exported")).toEqual([expect.objectContaining({ actor_email: "admin@acme.dev", payload: expect.objectContaining({ export_type: "audit_signed", format: "json", rows: 0 }) })]);
  });
});

describe("evidence files", () => {
  it("upload and delete are recorded under their own names (not attestation / report_generated)", async () => {
    const fd = new FormData();
    fd.set("file", new File(["x"], "soc2.pdf", { type: "application/pdf" }));
    fd.set("path", "CC6.1");
    expect((await storagePOST(req("/api/storage", { method: "POST", body: fd }))).status).toBe(200);
    expect((await storageDELETE(req("/api/storage?path=CC6.1/soc2.pdf", { method: "DELETE" }))).status).toBe(200);
    expect(audit().map(r => r.event_type)).toEqual(["evidence_uploaded", "evidence_deleted"]);
    expect(audit("attestation")).toEqual([]);
    expect(audit("report_generated")).toEqual([]);
  });
});
