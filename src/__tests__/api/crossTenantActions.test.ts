/**
 * @jest-environment node
 *
 * P0.2: ids and addresses in a request body are claims, not facts. An organisation cannot make the platform act with another
 * organisation's GitHub installation, link its records to another organisation's data, or change/delete another organisation's
 * webhook -- and the routes that rewrite its own configuration or data are recorded.
 */
import { NextRequest } from "next/server";
import { fakeSupabase } from "../helpers/fakeSupabase";

let db: ReturnType<typeof fakeSupabase>;
let auditBroken = false;
const tokenFor = jest.fn(async (_installationId: number) => ({ token: "t" }));
const githubCalls: Array<{ url: string; method: string }> = [];

jest.mock("@/lib/supabase", () => ({ createServiceClient: () => wrapped() }));
jest.mock("@/lib/cache", () => ({ cacheDel: async () => {}, cacheKeys: { dashboard: () => "d", dependencies: () => "p" } }));
jest.mock("@/lib/github", () => ({ ...jest.requireActual("@/lib/github"), getInstallationToken: (id: number) => tokenFor(id) }));
jest.mock("@/app/api/_middleware", () => ({
  verifyApiKey: async () => ({ org_id: "org-1", user_id: "u-admin", actor_email: "admin@one.dev", role: "admin" }),
  requirePermission: async () => null,
  requireRole: () => null,
}));

function wrapped() {
  const client = db.client as unknown as { from: (t: string) => Record<string, unknown> };
  return {
    ...client,
    from: (table: string) => {
      const q = client.from(table);
      if (table === "audit_log" && auditBroken) q.insert = () => Promise.resolve({ error: { code: "42501", message: "permission denied" } });
      return q;
    },
  };
}

import { POST as postComment } from "@/app/api/github-app/comment/route";
import { POST as recordEvidence } from "@/app/api/evidence/records/route";
import { POST as createHook, PATCH as patchHook, DELETE as deleteHook } from "@/app/api/webhooks/route";
import { POST as resetOrg } from "@/app/api/orgs/reset/route";

const rows = (t: string) => db.tables[t] as Array<Record<string, unknown>>;
const events = () => rows("audit_log").map(r => r.event_type);
const req = (url: string, method: string, body?: unknown) => new NextRequest(new URL(url, "https://app.example"), { method, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });

const realFetch = global.fetch;
beforeEach(() => {
  auditBroken = false; tokenFor.mockClear(); githubCalls.length = 0;
  global.fetch = (async (url: string, init?: RequestInit) => { githubCalls.push({ url: String(url), method: init?.method ?? "GET" }); return new Response("[]", { status: 200 }); }) as typeof fetch;
  db = fakeSupabase({
    audit_log: [],
    scans: [
      { id: "s-1", org_id: "org-1", repo_full_name: "one/app", pr_number: 7, overall_risk: "HIGH", total_ai_percentage: 0.1, installation_id: 111 },
      { id: "s-2", org_id: "org-2", repo_full_name: "two/app", pr_number: 9, overall_risk: "HIGH", total_ai_percentage: 0.1, installation_id: 222 },
      { id: "s-push", org_id: "org-1", repo_full_name: "one/app", pr_number: null, overall_risk: "LOW", total_ai_percentage: 0, installation_id: 111 },
    ],
    scan_files: [], attestations: [{ id: "a-1", org_id: "org-1", scan_id: "s-1", file_path: "x" }, { id: "a-2", org_id: "org-2", scan_id: "s-2", file_path: "y" }],
    repositories: [{ id: "r-1", org_id: "org-1", repo_full_name: "one/app" }, { id: "r-2", org_id: "org-2", repo_full_name: "two/app" }],
    github_installations: [{ id: "gi-1", org_id: "org-1", installation_id: 111 }, { id: "gi-2", org_id: "org-2", installation_id: 222 }],
    evidence_log: [],
    webhook_configs: [
      { id: "h-1", org_id: "org-1", url: "https://one.example/hook", events: ["scan.completed"], enabled: true },
      { id: "h-2", org_id: "org-2", url: "https://two.example/hook", events: ["scan.completed"], enabled: true },
    ],
    api_keys: [], violations: [], secret_findings: [], webhook_deliveries: [], organizations: [{ id: "org-1", onboarding_complete: true }],
  });
});
afterEach(() => { global.fetch = realFetch; });

describe("POST /api/github-app/comment", () => {
  const call = (body: Record<string, unknown>) => postComment(req("/api/github-app/comment", "POST", body));

  it("comments on the scan's own repository and pull request, with this organisation's installation", async () => {
    const res = await call({ scan_id: "s-1", repo: "one/app", pr_number: 7 });
    expect(res.status).toBe(200);
    expect(tokenFor).toHaveBeenCalledWith(111);
    expect(githubCalls.every(c => c.url.includes("/repos/one/app/issues/7/"))).toBe(true);
  });

  it("never uses another organisation's installation, however the body names it", async () => {
    const res = await call({ scan_id: "s-1", repo: "one/app", pr_number: 7, installation_id: 222 });
    expect(res.status).toBe(200);
    expect(tokenFor).toHaveBeenCalledTimes(1);
    expect(tokenFor).toHaveBeenCalledWith(111);                       // its own, not 222
  });

  it("with no installation of its own, a foreign installation id gets nothing: no token is ever requested for it", async () => {
    rows("github_installations").splice(0, 1);                         // org-1 has none
    (rows("scans")[0] as { installation_id: number | null }).installation_id = null;
    const res = await call({ scan_id: "s-1", repo: "one/app", pr_number: 7, installation_id: 222 });
    expect(res.status).toBe(422);
    expect(tokenFor).not.toHaveBeenCalled();
    expect(githubCalls).toEqual([]);
  });

  it("refuses a repository or pull request other than the scan's (no comment on someone else's PR)", async () => {
    for (const body of [{ repo: "two/app", pr_number: 7 }, { repo: "one/app", pr_number: 9 }, { repo: "victim/repo", pr_number: 1 }]) {
      const res = await call({ scan_id: "s-1", ...body });
      expect(res.status).toBe(400);
    }
    expect(tokenFor).not.toHaveBeenCalled();
    expect(githubCalls).toEqual([]);
  });

  it("another organisation's scan is not found", async () => {
    expect((await call({ scan_id: "s-2", repo: "two/app", pr_number: 9 })).status).toBe(404);
    expect(githubCalls).toEqual([]);
  });

  it("a scan with no pull request has nothing to comment on", async () => {
    expect((await call({ scan_id: "s-push", repo: "one/app", pr_number: 1 })).status).toBe(409);
    expect(githubCalls).toEqual([]);
  });
});

describe("POST /api/evidence/records cites only this organisation's data", () => {
  const record = (extra: Record<string, unknown>) => recordEvidence(req("/api/evidence/records", "POST", {
    framework: "soc2", control_id: "CC6.1", evidence_type: "security_scan", evidence_source: "manual", ...extra,
  }));

  it("accepts its own scan, attestation and repository", async () => {
    const res = await record({ scan_id: "s-1", attestation_id: "a-1", repository_id: "r-1" });
    expect([200, 201]).toContain(res.status);
    expect(rows("evidence_log")).toHaveLength(1);
  });

  it.each([
    ["scan_id", "s-2"], ["attestation_id", "a-2"], ["repository_id", "r-2"], ["scan_id", "does-not-exist"],
  ])("refuses %s=%s (another organisation's, or missing) and stores nothing", async (field, id) => {
    const res = await record({ [field]: id });
    expect(res.status).toBe(400);
    expect(await res.json()).toMatchObject({ error: "invalid_reference", field });
    expect(rows("evidence_log")).toHaveLength(0);
  });
});

describe("webhook configuration", () => {
  const body = { url: "https://hooks.one.example/in", events: ["scan.completed"] };

  it("creating an endpoint is recorded, with where it points and not its query string", async () => {
    const res = await createHook(req("/api/webhooks", "POST", { ...body, url: "https://hooks.one.example/in?token=SECRET" }));
    expect(res.status).toBe(200);
    expect(rows("audit_log")).toEqual([expect.objectContaining({ event_type: "org_settings_changed", resource_type: "webhook", payload: expect.objectContaining({ action: "created", endpoint: "https://hooks.one.example/in" }) })]);
    expect(JSON.stringify(rows("audit_log"))).not.toContain("SECRET");
  });

  it("an endpoint that cannot be recorded is not created", async () => {
    auditBroken = true;
    const res = await createHook(req("/api/webhooks", "POST", body));
    expect(res.status).toBe(500);
    expect(rows("webhook_configs").filter(h => h.org_id === "org-1")).toHaveLength(1);   // only the seeded one
  });

  it("editing cannot point an endpoint at a private address or plain http", async () => {
    for (const url of ["http://one.example/hook", "https://127.0.0.1/x", "https://169.254.169.254/latest", "https://localhost/x"]) {
      const res = await patchHook(req("/api/webhooks", "PATCH", { id: "h-1", url }));
      expect(res.status).toBe(400);
    }
    expect(rows("webhook_configs").find(h => h.id === "h-1")!.url).toBe("https://one.example/hook");
  });

  it("another organisation's webhook cannot be changed or deleted by its id", async () => {
    const patch = await patchHook(req("/api/webhooks", "PATCH", { id: "h-2", enabled: false }));
    expect(patch.status).toBe(404);
    const del = await deleteHook(req("/api/webhooks?id=h-2", "DELETE"));
    expect(del.status).toBe(404);
    expect(rows("webhook_configs").find(h => h.id === "h-2")).toMatchObject({ enabled: true, url: "https://two.example/hook" });
    expect(events()).toEqual([]);
  });

  it("changes and removals of its own are recorded", async () => {
    expect((await patchHook(req("/api/webhooks", "PATCH", { id: "h-1", enabled: false, secret: "s3cret" }))).status).toBe(200);
    expect((await deleteHook(req("/api/webhooks?id=h-1", "DELETE"))).status).toBe(200);
    expect(rows("audit_log").map(r => (r.payload as { action: string }).action)).toEqual(["updated", "deleted"]);
    expect(JSON.stringify(rows("audit_log"))).not.toContain("s3cret");
  });
});

describe("POST /api/orgs/reset", () => {
  it("is recorded before and after, and wipes only this organisation", async () => {
    rows("scans").push({ id: "s-3", org_id: "org-1" });
    const res = await resetOrg(req("/api/orgs/reset", "POST"));
    expect(res.status).toBe(200);
    expect(rows("audit_log").map(r => (r.payload as { phase: string }).phase)).toEqual(["requested", "completed"]);
    expect(rows("scans").every(s => s.org_id !== "org-1")).toBe(true);
    expect(rows("scans").some(s => s.org_id === "org-2")).toBe(true);
  });

  it("wipes nothing when the request cannot be recorded", async () => {
    auditBroken = true;
    const before = rows("scans").length;
    const res = await resetOrg(req("/api/orgs/reset", "POST"));
    expect(res.status).toBe(500);
    expect(rows("scans")).toHaveLength(before);
  });
});
