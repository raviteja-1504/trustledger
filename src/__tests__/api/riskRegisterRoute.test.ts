/**
 * @jest-environment node
 *
 * GET /api/risk-register: the register derived on the server from the database, so it follows the real
 * attestations (the old page used a cached payload and disagreed with them), synced and merged in one request.
 */
import { NextRequest } from "next/server";
import { fakeSupabase } from "../helpers/fakeSupabase";

let db: ReturnType<typeof fakeSupabase>;
let canEdit = true;
jest.mock("@/lib/supabase", () => ({ createServiceClient: () => db.client }));
jest.mock("@/lib/audit", () => ({ writeAuditLog: async () => undefined }));
jest.mock("@/app/api/_middleware", () => ({
  verifyApiKey: async () => ({ org_id: "org-1", user_id: "u1" }),
  requirePermission: async () => (canEdit ? null : "forbidden"),
}));

import { GET } from "@/app/api/risk-register/route";

type Risk = { id: string; status: string; owner: string; title: string; auto_derived: boolean; repo?: string; notes: string[] };
type Body = { risks: Risk[]; basis: Record<string, number | string | null>; sync: Record<string, number> | null; syncError: string | null; capped: unknown; canEdit: boolean };
const get = async () => { const res = await GET(new NextRequest(new URL("/api/risk-register", "https://app.example"))); return { res, body: await res.json() as Body }; };

const file = (scan_id: string, file_path: string, risk_score: string, risk_indicators: string[] = [], ai = 0.6) =>
  ({ org_id: "org-1", scan_id, file_path, risk_score, risk_indicators, ai_percentage: ai });

function seed(over: { files?: unknown[]; attestations?: unknown[]; violations?: unknown[]; risk_register?: unknown[]; scans?: unknown[] } = {}) {
  db = fakeSupabase({
    repositories: [{ org_id: "org-1", repo_full_name: "o/api", is_active: true }, { org_id: "org-1", repo_full_name: "o/off", is_active: false }],
    scans: (over.scans ?? [
      { id: "a-old", org_id: "org-1", repo_full_name: "o/api", created_at: "2026-10-01T00:00:00Z" },
      { id: "a-new", org_id: "org-1", repo_full_name: "o/api", created_at: "2026-10-05T00:00:00Z" },
      { id: "x1", org_id: "org-1", repo_full_name: "o/off", created_at: "2026-10-06T00:00:00Z" },
    ]) as Record<string, unknown>[],
    scan_files: (over.files ?? [
      file("a-new", "src/a.ts", "CRITICAL", ["sql-injection"]), file("a-new", "src/b.ts", "HIGH"), file("a-new", "src/c.ts", "HIGH"),
      file("a-old", "src/gone.ts", "CRITICAL", ["hardcoded-secret"]), file("x1", "off.ts", "CRITICAL", ["hardcoded-secret"]),
    ]) as Record<string, unknown>[],
    attestations: (over.attestations ?? []).map(a => ({ org_id: "org-1", ...(a as object) })) as Record<string, unknown>[],
    violations: (over.violations ?? []).map(v => ({ org_id: "org-1", ...(v as object) })) as Record<string, unknown>[],
    risk_register: (over.risk_register ?? []) as Record<string, unknown>[],
  });
}
beforeEach(() => { canEdit = true; seed(); });

const byPrefix = (risks: Risk[], p: string) => risks.find(r => r.id.startsWith(p));

describe("GET /api/risk-register", () => {
  it("derives risks from the latest scan of each ACTIVE repository only", async () => {
    const { res, body } = await get();
    expect(res.headers.get("Cache-Control")).toBe("private, no-store");
    expect(byPrefix(body.risks, "DR-CRIT-UNATT-")?.title).toMatch(/1 CRITICAL file unattested in api/);
    expect(byPrefix(body.risks, "DR-HIGH-UNATT-")?.title).toMatch(/2 HIGH-risk files awaiting attestation in api/);
    expect(byPrefix(body.risks, "DR-SQL-INJECT-")).toBeDefined();
    expect(body.risks.some(r => r.id.includes("SECRETS"))).toBe(false);           // the old scan and the inactive repo are ignored
    expect(body.risks.every(r => r.repo === undefined || r.repo === "o/api")).toBe(true);
  });

  it("follows the real attestations: an attested file leaves the unattested risk", async () => {
    seed({ attestations: [{ scan_id: "a-new", file_path: "src/b.ts", risk_score: "HIGH" }] });
    const { body } = await get();
    expect(byPrefix(body.risks, "DR-HIGH-UNATT-")?.title).toMatch(/^1 HIGH-risk file awaiting/);
    expect(body.basis).toMatchObject({ highCriticalFiles: 3, attestedFiles: 1, waitingFiles: 2, repos: 1 });
  });

  it("when every file is attested, the file risks are gone and the sync closes the ones it had recorded", async () => {
    await get();                                                                    // first sync records them
    const stored = db.tables.risk_register.filter(r => r.auto_derived);
    expect(stored.length).toBeGreaterThan(0);
    for (const r of stored) { r.status ??= "open"; r.created_at ??= "2026-10-05T00:00:00Z"; r.notes ??= []; }   // column defaults, which the fake does not apply
    db.tables.attestations.push(
      { org_id: "org-1", scan_id: "a-new", file_path: "src/a.ts", risk_score: "CRITICAL" }, { org_id: "org-1", scan_id: "a-new", file_path: "src/b.ts", risk_score: "HIGH" }, { org_id: "org-1", scan_id: "a-new", file_path: "src/c.ts", risk_score: "HIGH" });
    const { body } = await get();
    expect(body.risks.filter(r => r.id.includes("UNATT") || r.id === "DR-DEPLOY-BLOCK").every(r => r.status === "closed")).toBe(true);   // none left open
    expect(body.sync).toMatchObject({ closed: expect.any(Number) });
    expect(body.sync!.closed).toBeGreaterThan(0);
    // ...and the closed ones stay in the register as history, closed, not vanished
    expect(db.tables.risk_register.filter(r => String(r.external_id).includes("UNATT")).every(r => r.status === "closed")).toBe(true);
    expect(body.risks.filter(r => r.id.includes("UNATT")).length).toBeGreaterThan(0);          // kept as closed history, not vanished
    expect(body.risks.filter(r => r.status === "closed").map(r => r.id).sort()).toEqual(
      db.tables.risk_register.filter(r => r.status === "closed" && r.auto_derived).map(r => String(r.external_id)).sort());
  });

  it("a file closed on the Violations page without an attestation is not 'awaiting attestation', and is not counted as attested", async () => {
    seed({ violations: [{ scan_id: "a-new", file_path: "src/c.ts", risk_score: "HIGH", status: "resolved" }, { scan_id: "a-new", file_path: "src/b.ts", risk_score: "HIGH", status: "open" }] });
    const { body } = await get();
    expect(byPrefix(body.risks, "DR-HIGH-UNATT-")?.title).toMatch(/^1 HIGH-risk file awaiting/);
    expect(body.basis).toMatchObject({ attestedFiles: 0, closedWithoutAttestation: 1, waitingFiles: 2 });
  });

  it("people's decisions survive the sync and are merged in", async () => {
    await get();
    const row = db.tables.risk_register.find(r => String(r.external_id).startsWith("DR-CRIT-UNATT-"))!;
    Object.assign(row, { owner_email: "ana@example.com", status: "mitigating", notes: ["checked"], updated_by: "u9" });
    const { body } = await get();
    const r = byPrefix(body.risks, "DR-CRIT-UNATT-")!;
    expect(r).toMatchObject({ owner: "ana@example.com", status: "mitigating", notes: ["checked"] });
  });

  it("includes manually added risks", async () => {
    seed({ risk_register: [{ org_id: "org-1", external_id: "MR-1", auto_derived: false, title: "Vendor risk", category: "compliance", likelihood: 3, impact: 3, status: "open", treatment: "accept", notes: [], created_at: "2026-10-01T00:00:00Z" }] });
    const { body } = await get();
    expect(body.risks.find(r => r.id === "MR-1")).toMatchObject({ title: "Vendor risk", auto_derived: false });
    expect(db.tables.risk_register.filter(r => r.external_id === "MR-1")).toHaveLength(1);       // never duplicated by the sync
  });

  it("a read-only role gets the live register without any write", async () => {
    canEdit = false;
    const before = db.writes.length;
    const { body } = await get();
    expect(body.canEdit).toBe(false);
    expect(body.sync).toBeNull();
    expect(db.writes.length).toBe(before);
    expect(byPrefix(body.risks, "DR-CRIT-UNATT-")).toBeDefined();
  });

  it("an empty organisation is an empty register, not an error", async () => {
    seed({ scans: [], files: [] });
    const { res, body } = await get();
    expect(res.status).toBe(200);
    expect(body.risks).toEqual([]);
    expect(body.basis).toMatchObject({ repos: 0, highCriticalFiles: 0 });
  });

  it("if recording fails the register is still returned, with a message", async () => {
    const orig = db.client.from.bind(db.client);
    (db.client as unknown as { from: (t: string) => unknown }).from = (t: string) => {
      const q = orig(t) as { insert: (...a: unknown[]) => unknown };
      if (t === "risk_register") q.insert = () => ({ then: (res: (v: unknown) => unknown) => Promise.resolve({ data: null, error: { message: "boom" } }).then(res) });
      return q;
    };
    const { res, body } = await get();
    expect(res.status).toBe(200);
    expect(body.syncError).toMatch(/couldn't be recorded/);
    expect(body.sync).toBeNull();
    expect(body.risks.length).toBeGreaterThan(0);
  });
});
