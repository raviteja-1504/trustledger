/**
 * @jest-environment node
 *
 * /api/shadow-ai: detections from stored scans, a server-side policy and triage (permission-checked and
 * audit-logged), developers limited to their own pull requests, and graceful behaviour before the migration.
 */
import { NextRequest } from "next/server";
import { fakeSupabase } from "../helpers/fakeSupabase";

let db: ReturnType<typeof fakeSupabase>;
jest.mock("@/lib/supabase", () => ({ createServiceClient: () => db.client }));
let caller: Record<string, unknown> = {};
jest.mock("@/app/api/_middleware", () => ({
  ...jest.requireActual("@/app/api/_middleware"),
  verifyApiKey: async () => caller,
}));

import { GET, PUT, PATCH } from "@/app/api/shadow-ai/route";

const ADMIN = { org_id: "org-1", user_id: "u-admin", actor_email: "admin@acme.dev", role: "admin" };
const REVIEWER = { org_id: "org-1", user_id: "u-rev", actor_email: "rev@acme.dev", role: "security_reviewer" };
const DEV = { org_id: "org-1", user_id: "u-dev", actor_email: "dev@acme.dev", role: "developer" };
const rows = (t: string) => (db.client.from(t) as unknown as { rows: Record<string, unknown>[] }).rows;
const req = (method: string, body?: unknown, q = "") =>
  new NextRequest(new URL(`/api/shadow-ai${q}`, "https://app.example"), { method, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
const recent = new Date(Date.now() - 2 * 86400_000).toISOString();
const old = new Date(Date.now() - 60 * 86400_000).toISOString();

beforeEach(() => {
  caller = { ...ADMIN };
  db = fakeSupabase({
    organizations: [{ id: "org-1", name: "Acme", ai_tool_policy: null }, { id: "org-2", name: "Other", ai_tool_policy: { allowed: ["cursor"] } }],
    org_members: [
      { id: "m1", org_id: "org-1", user_id: "u-admin", email: "admin@acme.dev", role: "admin", custom_role_id: null },
      { id: "m2", org_id: "org-1", user_id: "u-rev", email: "rev@acme.dev", role: "security_reviewer", custom_role_id: null },
      { id: "m3", org_id: "org-1", user_id: "u-dev", email: "dev@acme.dev", role: "developer", custom_role_id: null, github_login: "dev-own" },
    ],
    scans: [
      { id: "s1", org_id: "org-1", repo_full_name: "acme/app", pr_number: 1, pr_author: "dev-own", created_at: recent, ai_tooling: [{ tool: "Cursor", file: ".cursorrules", label: "Cursor AI agent rules file" }] },
      { id: "s2", org_id: "org-1", repo_full_name: "acme/app", pr_number: 2, pr_author: "someone-else", created_at: recent, ai_tooling: [{ tool: "claude", file: "commit:abc1234", label: "Claude co-author trailer on commit" }] },
      { id: "s3", org_id: "org-1", repo_full_name: "acme/app", pr_number: 3, pr_author: "dev-own", created_at: old, ai_tooling: [{ tool: "Windsurf", file: ".windsurfrules" }] },
      { id: "s9", org_id: "org-2", repo_full_name: "other/secret", pr_number: 1, pr_author: "x", created_at: recent, ai_tooling: [{ tool: "Devin", file: ".devin/x" }] },
    ],
    scan_files: [{ scan_id: "s2", org_id: "org-1", file_path: "src/a.ts", attribution: { model: "gemini", confidence: 0.9 } }],
    shadow_ai_triage: [],
    audit_log: [],
  });
});

describe("GET", () => {
  it("lists this org's detections in the window; no policy means nothing is a violation", async () => {
    const res = await GET(req("GET"));
    const body = await res.json();
    expect(res.status).toBe(200);
    expect(body.policy).toBeNull();
    const tools = body.detections.map((d: { tool: string }) => d.tool).sort();
    expect(tools).toEqual(["claude", "cursor", "gemini"]);                // windsurf is outside 30 days; org-2 excluded
    expect(body.detections.some((d: { violation: boolean }) => d.violation)).toBe(false);
    expect(body.summary.policy_configured).toBe(false);
  });

  it("with a policy, explicit unapproved evidence is a violation and the hint is not", async () => {
    rows("organizations")[0].ai_tool_policy = { allowed: ["claude"] };
    const body = await (await GET(req("GET"))).json();
    const by = (t: string) => body.detections.find((d: { tool: string }) => d.tool === t);
    expect(by("cursor")).toMatchObject({ violation: true, approval: "unapproved" });
    expect(by("claude")).toMatchObject({ violation: false, approval: "approved" });
    expect(by("gemini")).toMatchObject({ tier: "hint", violation: false });
    expect(body.summary.open_violations).toBe(1);
  });

  it("a wider window includes older scans", async () => {
    const body = await (await GET(req("GET", undefined, "?days=90"))).json();
    expect(body.detections.map((d: { tool: string }) => d.tool)).toContain("windsurf");
  });

  it("developers see only their own pull requests", async () => {
    caller = { ...DEV };
    const body = await (await GET(req("GET"))).json();
    expect(body.scope).toBe("own");
    expect(body.detections.map((d: { tool: string }) => d.tool)).toEqual(["cursor"]);
  });
});

describe("PUT policy", () => {
  it("saves a normalised policy and audit-logs the change", async () => {
    const res = await PUT(req("PUT", { allowed: ["claude", "not-a-tool", "github-copilot"] }));
    expect(res.status).toBe(200);
    expect((rows("organizations")[0].ai_tool_policy as { allowed: string[] }).allowed).toEqual(["github-copilot", "claude"]);
    expect(rows("organizations")[1].ai_tool_policy).toEqual({ allowed: ["cursor"] });   // other org untouched
    expect(rows("audit_log")).toEqual([expect.objectContaining({ event_type: "ai_tool_policy_changed", actor_email: "admin@acme.dev", payload: { allowed: ["github-copilot", "claude"], previous: null } })]);
  });

  it("needs can_manage_policies, and a list", async () => {
    caller = { ...REVIEWER };
    expect((await PUT(req("PUT", { allowed: [] }))).status).toBe(403);
    caller = { ...ADMIN };
    expect((await PUT(req("PUT", { allowed: "claude" }))).status).toBe(400);
    expect(rows("audit_log")).toEqual([]);
  });
});

describe("PATCH triage", () => {
  const key = "acme/app|cursor|.cursorrules";

  it("sets status and appends notes, audit-logged", async () => {
    caller = { ...REVIEWER };
    expect((await PATCH(req("PATCH", { key, status: "investigating", note: "Asked the team" }))).status).toBe(200);
    expect((await PATCH(req("PATCH", { key, note: "Removed in #12" }))).status).toBe(200);
    const t = rows("shadow_ai_triage").find(r => r.detection_key === key)!;
    expect(t).toMatchObject({ org_id: "org-1", status: "investigating" });
    expect((t.notes as Array<{ text: string; by: string }>).map(n => n.text)).toEqual(["Asked the team", "Removed in #12"]);
    expect(rows("audit_log").map(r => r.event_type)).toEqual(["shadow_ai_triaged", "shadow_ai_triaged"]);
    // the GET reflects it
    const body = await (await GET(req("GET"))).json();
    expect(body.detections.find((d: { key: string }) => d.key === key)).toMatchObject({ status: "investigating" });
  });

  it("validates input and needs can_resolve_violations", async () => {
    caller = { ...DEV };
    expect((await PATCH(req("PATCH", { key, status: "resolved" }))).status).toBe(403);
    caller = { ...REVIEWER };
    expect((await PATCH(req("PATCH", { key, status: "deleted" }))).status).toBe(400);
    expect((await PATCH(req("PATCH", { key: "no-pipes", status: "resolved" }))).status).toBe(400);
    expect((await PATCH(req("PATCH", { key }))).status).toBe(400);
    expect(rows("shadow_ai_triage")).toEqual([]);
  });
});

describe("before the migration", () => {
  it("GET still works; writes explain the migration is needed", async () => {
    const real = db.client.from.bind(db.client);
    // Simulate the missing column/table: those reads and writes error.
    (db.client as { from: (t: string) => unknown }).from = (t: string) => {
      const q: unknown = real(t);
      if (t === "shadow_ai_triage") return { select: () => ({ eq: async () => ({ data: null, error: { code: "42P01" } }) }), upsert: async () => ({ error: { code: "42P01" } }) };
      if (t === "organizations") return { select: () => ({ eq: () => ({ maybeSingle: async () => ({ data: null, error: { code: "42703" } }) }) }), update: () => ({ eq: async () => ({ error: { code: "42703" } }) }) };
      return q;
    };
    const body = await (await GET(req("GET"))).json();
    expect(body.detections.length).toBeGreaterThan(0);
    expect(body.policy).toBeNull();
    expect((await PUT(req("PUT", { allowed: ["claude"] }))).status).toBe(503);
    caller = { ...REVIEWER };
    expect((await PATCH(req("PATCH", { key: "acme/app|cursor|.cursorrules", status: "resolved" }))).status).toBe(503);
  });
});
