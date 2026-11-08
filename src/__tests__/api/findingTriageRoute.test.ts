/**
 * @jest-environment node
 *
 * /api/findings/triage: a decision is stored per (org, repo, fingerprint), written to the audit log, listed back,
 * and removed by reopening. Only roles that may resolve violations can write.
 */
import { NextRequest } from "next/server";
import { fakeSupabase } from "../helpers/fakeSupabase";

let db: ReturnType<typeof fakeSupabase>;
let role = "security_reviewer";
jest.mock("@/lib/supabase", () => ({ createServiceClient: () => db.client }));
jest.mock("@/app/api/_middleware", () => ({
  ...jest.requireActual("@/app/api/_middleware"),
  verifyApiKey: async () => ({ org_id: "org-1", user_id: "u1", role, actor_email: "rev@x.io" }),
}));

import { GET, POST, DELETE } from "@/app/api/findings/triage/route";

const FP = "fingerprint-0001";
const req = (method: string, body?: unknown, qs = "") => new NextRequest(new URL(`/api/findings/triage${qs}`, "https://app.example"), {
  method, ...(body ? { body: JSON.stringify(body), headers: { "content-type": "application/json" } } : {}),
});
const triageRows = () => (db.client.from("finding_triage") as unknown as { rows: Array<Record<string, unknown>> }).rows;
const auditRows = () => (db.client.from("audit_log") as unknown as { rows: Array<Record<string, unknown>> }).rows;
const accept = (over = {}) => ({ repo: "acme/shop", fingerprint: FP, rule_id: "sql-injection", file_path: "src/a.ts", status: "accepted", reason: "Behind the VPN", expires_in_days: 90, ...over });

beforeEach(() => {
  role = "security_reviewer";
  db = fakeSupabase({ finding_triage: [], audit_log: [] });
});

describe("POST: record a decision", () => {
  it("stores it for this org, repo and fingerprint, with who, why and when it expires", async () => {
    const res = await POST(req("POST", accept()));
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.ok).toBe(true);
    expect(body.decision).toMatchObject({ status: "accepted", reason: "Behind the VPN", set_by_email: "rev@x.io" });
    expect(triageRows()).toHaveLength(1);
    expect(triageRows()[0]).toMatchObject({ org_id: "org-1", repo_full_name: "acme/shop", fingerprint: FP, rule_id: "sql-injection", file_path: "src/a.ts", status: "accepted", reason: "Behind the VPN", set_by_email: "rev@x.io" });
    const days = (Date.parse(String(triageRows()[0].expires_at)) - Date.now()) / 86_400_000;
    expect(days).toBeGreaterThan(89.9);
    expect(days).toBeLessThan(90.1);
  });

  it("no expiry stores null", async () => {
    await POST(req("POST", accept({ expires_in_days: null })));
    expect(triageRows()[0].expires_at).toBeNull();
  });

  it("deciding the same finding again updates the one row instead of adding a second", async () => {
    await POST(req("POST", accept()));
    await POST(req("POST", accept({ status: "false_positive", reason: "validated enum" })));
    expect(triageRows()).toHaveLength(1);
    expect(triageRows()[0]).toMatchObject({ status: "false_positive", reason: "validated enum" });
  });

  it("another repo's decision on a same-fingerprint finding is a separate row", async () => {
    await POST(req("POST", accept()));
    await POST(req("POST", accept({ repo: "acme/other" })));
    expect(triageRows()).toHaveLength(2);
  });

  it("writes an audit entry saying who accepted what, and why", async () => {
    await POST(req("POST", accept()));
    expect(auditRows()).toHaveLength(1);
    expect(auditRows()[0]).toMatchObject({ event_type: "finding_triaged", org_id: "org-1", resource_id: FP, actor_email: "rev@x.io" });
    expect(auditRows()[0].payload).toMatchObject({ repo: "acme/shop", rule_id: "sql-injection", status: "accepted", reason: "Behind the VPN" });
  });

  it("refuses a missing or too-short reason, and a status that isn't a decision", async () => {
    expect((await POST(req("POST", accept({ reason: "ok" })))).status).toBe(400);
    expect((await POST(req("POST", accept({ status: "fixed" })))).status).toBe(400);
    expect(triageRows()).toHaveLength(0);
  });

  it("a viewer can't record one", async () => {
    role = "viewer";
    const res = await POST(req("POST", accept()));
    expect(res.status).toBe(403);
    expect(triageRows()).toHaveLength(0);
    expect(auditRows()).toHaveLength(0);
  });
});

describe("GET and DELETE", () => {
  it("GET lists a repo's decisions keyed by fingerprint, and only that repo's", async () => {
    await POST(req("POST", accept()));
    await POST(req("POST", accept({ repo: "acme/other", fingerprint: "fingerprint-0002" })));
    const res = await GET(req("GET", undefined, "?repo=acme/shop"));
    const { triage } = await res.json() as { triage: Record<string, { status: string; reason: string }> };
    expect(Object.keys(triage)).toEqual([FP]);
    expect(triage[FP]).toMatchObject({ status: "accepted", reason: "Behind the VPN" });
  });

  it("GET needs a repo", async () => {
    expect((await GET(req("GET"))).status).toBe(400);
  });

  it("reopening removes the decision and is audited; other findings keep theirs", async () => {
    await POST(req("POST", accept()));
    await POST(req("POST", accept({ fingerprint: "fingerprint-0002" })));
    const res = await DELETE(req("DELETE", { repo: "acme/shop", fingerprint: FP }));
    expect(res.status).toBe(200);
    expect(triageRows().map(r => r.fingerprint)).toEqual(["fingerprint-0002"]);
    expect(auditRows().map(r => r.event_type)).toEqual(["finding_triaged", "finding_triaged", "finding_reopened"]);
  });

  it("a viewer can't reopen", async () => {
    await POST(req("POST", accept()));
    role = "viewer";
    expect((await DELETE(req("DELETE", { repo: "acme/shop", fingerprint: FP }))).status).toBe(403);
    expect(triageRows()).toHaveLength(1);
  });
});
