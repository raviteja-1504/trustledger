/**
 * @jest-environment node
 *
 * Task 12: control ownership, missing-evidence tracking and remediation status. Remediation is the existing
 * compliance_exceptions register; this joins it with coverage and owners and puts the result in the signed export.
 */
import crypto from "crypto";
import { NextRequest } from "next/server";
import { fakeSupabase } from "../helpers/fakeSupabase";
import { buildGapReport, gapsOf, isValidOwnerEmail, type RemediationItem } from "@/lib/controlTracking";
import { getFrameworkMapping, type ControlCoverageResult } from "@/lib/controlMapping";

const cov = (control_id: string, over: Partial<ControlCoverageResult> = {}): ControlCoverageResult => ({
  control_id, control_name: control_id, status: "missing", sufficient_alone: false,
  satisfied_types: [], missing_types: ["security_scan"], expired_types: [], freshness_days: null, ...over,
});
const item = (over: Partial<RemediationItem> = {}): RemediationItem => ({
  id: "x1", control_id: "C1", title: "Fix it", status: "open", owner_email: "a@acme.dev", due_date: "2026-12-31", risk_accepted: false, remediation: null, ...over,
});
const TODAY = "2026-11-26";

describe("gapsOf", () => {
  it("separates missing, unverified and expired evidence", () => {
    expect(gapsOf({ missing_types: ["security_scan", "pr_approval"], unverified_types: ["pr_approval"], expired_types: ["risk_assessment"] })).toEqual([
      { evidence_type: "security_scan", kind: "missing" },
      { evidence_type: "pr_approval", kind: "unverified" },
      { evidence_type: "risk_assessment", kind: "expired" },
    ]);
  });
  it("is empty when nothing is outstanding", () => {
    expect(gapsOf({ missing_types: [], expired_types: [] })).toEqual([]);
  });
});

describe("buildGapReport", () => {
  const owners = [{ control_id: "C1", owner_email: "a@acme.dev" }];

  it("flags a gap nobody has taken up, and a control with no owner", () => {
    const r = buildGapReport([cov("C1"), cov("C2")], owners, [], TODAY);
    expect(r.controls[0]).toMatchObject({ owner: "a@acme.dev", flags: ["gap_untracked"] });
    expect(r.controls[1]).toMatchObject({ owner: null, flags: ["no_owner", "gap_untracked"] });
    expect(r.summary).toEqual({ controls: 2, with_gaps: 2, unowned: 1, untracked_gaps: 2, overdue: 0, resolved_but_gap_remains: 0 });
  });

  it("a gap with an open or in-progress remediation item is tracked", () => {
    for (const status of ["open", "in-progress"]) {
      const c = buildGapReport([cov("C1")], owners, [item({ status })], TODAY).controls[0];
      expect(c.flags).toEqual([]);
      expect(c.remediations).toHaveLength(1);
    }
  });

  it("flags an open item that is past its due date", () => {
    const c = buildGapReport([cov("C1")], owners, [item({ due_date: "2026-11-01" })], TODAY).controls[0];
    expect(c.flags).toEqual(["remediation_overdue"]);
    expect(c.remediations[0].overdue).toBe(true);
    expect(buildGapReport([cov("C1")], owners, [item({ due_date: TODAY })], TODAY).controls[0].flags).toEqual([]);   // due today is not overdue
  });

  it("closing a remediation item does not close the gap: it is flagged until evidence is in", () => {
    const r = buildGapReport([cov("C1")], owners, [item({ status: "resolved" })], TODAY);
    expect(r.controls[0].flags).toEqual(["resolved_but_gap_remains"]);
    expect(r.summary).toMatchObject({ untracked_gaps: 1, resolved_but_gap_remains: 1 });
  });

  it("an accepted risk is a recorded response, even once its item is resolved, and is not hidden", () => {
    const c = buildGapReport([cov("C1")], owners, [item({ status: "resolved", risk_accepted: true })], TODAY).controls[0];
    expect(c.flags).toEqual(["risk_accepted"]);
  });

  it("a satisfied control with an old resolved item raises nothing", () => {
    const c = buildGapReport([cov("C1", { status: "satisfied", satisfied_types: ["security_scan"], missing_types: [] })], owners, [item({ status: "resolved" })], TODAY).controls[0];
    expect(c.flags).toEqual([]);
    expect(c.gaps).toEqual([]);
  });

  it("ignores another control's items and never calls a control sufficient on its own", () => {
    const r = buildGapReport([cov("C1")], owners, [item({ control_id: "C9" })], TODAY);
    expect(r.controls[0].remediations).toEqual([]);
    expect(r.controls.every(c => c.sufficient_alone === false)).toBe(true);
  });
});

describe("isValidOwnerEmail", () => {
  it.each([["a@acme.dev", true], ["no-at-sign", false], ["a b@acme.dev", false], ["", false], [undefined, false], [42, false], ["a@b", false]])("%p -> %p", (v, ok) => {
    expect(isValidOwnerEmail(v)).toBe(ok);
  });
});

// ── Routes ────────────────────────────────────────────────────────────────────────────────────────────────

const key = crypto.generateKeyPairSync("ed25519", { privateKeyEncoding: { type: "pkcs8", format: "pem" }, publicKeyEncoding: { type: "spki", format: "pem" } });
let db = fakeSupabase({});
let orgId = "org-1";
let allowWrite = true;
jest.mock("@/lib/supabase", () => ({ createServiceClient: () => db.client }));
jest.mock("@/app/api/_middleware", () => ({
  verifyApiKey: async () => ({ org_id: orgId, user_id: "u-1", actor_email: "lead@acme.dev", role: "admin" }),
  requirePermission: async () => (allowWrite ? null : "forbidden"),
}));

import { GET as getControls, PUT as putOwner, DELETE as deleteOwner } from "@/app/api/evidence/controls/route";
import { GET as getGaps } from "@/app/api/evidence/gaps/route";
import { POST as collect } from "@/app/api/evidence/records/route";
import { GET as exportEvidence } from "@/app/api/evidence/export/route";
// eslint-disable-next-line @typescript-eslint/no-var-requires
const verifier = require("../../../scripts/verify-evidence-export.cjs") as { verifyExport: (doc: unknown, key?: string) => { signature: string; problems: string[] } };

const req = (url: string, init?: { method?: string; body?: unknown }) =>
  new NextRequest(new URL(url, "http://localhost"), { method: init?.method, body: init?.body === undefined ? undefined : JSON.stringify(init.body) });
const put = (body: unknown) => putOwner(req("/api/evidence/controls", { method: "PUT", body }));
const json = async (res: Response) => ({ status: res.status, body: await res.json() as Record<string, any> });

beforeEach(() => {
  process.env.EXPORT_SIGNING_PRIVATE_KEY = key.privateKey as string;
  orgId = "org-1"; allowWrite = true;
  db = fakeSupabase({
    org_members: [{ org_id: "org-1", email: "Ana@Acme.dev" }, { org_id: "org-1", email: "bo@acme.dev" }, { org_id: "org-2", email: "eve@other.dev" }],
    control_owners: [], compliance_exceptions: [], evidence_log: [], audit_log: [],
  });
});

describe("control ownership routes", () => {
  it("assigns an owner who is a member (any capitalisation), and records the change with the previous owner", async () => {
    const first = await json(await put({ framework: "soc2", control_id: "CC8.1", owner_email: "ana@acme.dev" }));
    expect(first).toMatchObject({ status: 200, body: { ok: true, owner: "ana@acme.dev", previous_owner: null } });
    const second = await json(await put({ framework: "soc2", control_id: "CC8.1", owner_email: "bo@acme.dev" }));
    expect(second.body).toMatchObject({ owner: "bo@acme.dev", previous_owner: "ana@acme.dev" });
    expect(db.tables.control_owners).toHaveLength(1);                                          // one owner per control
    const audit = db.tables.audit_log.filter(r => (r as { resource_type: string }).resource_type === "control_owner");
    expect(audit).toHaveLength(2);
    expect((audit[1] as { payload: unknown }).payload).toMatchObject({ control_id: "CC8.1", owner: "bo@acme.dev", previous_owner: "ana@acme.dev" });
  });

  it("refuses an owner outside the organisation, a malformed email, and unknown frameworks or controls", async () => {
    expect((await json(await put({ framework: "soc2", control_id: "CC8.1", owner_email: "eve@other.dev" }))).body.error).toBe("owner_not_a_member");
    expect((await json(await put({ framework: "soc2", control_id: "CC8.1", owner_email: "nope" }))).body.error).toBe("invalid_owner_email");
    expect((await json(await put({ framework: "hipaa", control_id: "CC8.1", owner_email: "ana@acme.dev" }))).body.error).toBe("unknown_framework");
    expect((await json(await put({ framework: "soc2", control_id: "ZZ9", owner_email: "ana@acme.dev" }))).body.error).toBe("unknown_control_id");
    expect(db.tables.control_owners).toHaveLength(0);
  });

  it("needs the export permission to read ownership as well as to change it, and says nothing about who owns what without it", async () => {
    await put({ framework: "soc2", control_id: "CC8.1", owner_email: "ana@acme.dev" });       // an owner exists to leak
    allowWrite = false;
    expect((await json(await put({ framework: "soc2", control_id: "CC8.1", owner_email: "bo@acme.dev" }))).status).toBe(403);
    expect((await json(await deleteOwner(req("/api/evidence/controls?framework=soc2&control_id=CC8.1", { method: "DELETE" })))).status).toBe(403);
    const read = await getControls(req("/api/evidence/controls?framework=soc2"));
    expect(read.status).toBe(403);
    expect(JSON.stringify(await read.json())).not.toMatch(/ana@acme|owner|CC8\.1/);
    expect(db.tables.control_owners).toEqual([expect.objectContaining({ owner_email: "ana@acme.dev" })]);   // untouched
    allowWrite = true;
    expect((await json(await getControls(req("/api/evidence/controls?framework=soc2")))).status).toBe(200);
  });

  it("lists every control, owned or not, and never shows another organisation's owners", async () => {
    await put({ framework: "soc2", control_id: "CC8.1", owner_email: "ana@acme.dev" });
    orgId = "org-2";
    const other = await json(await getControls(req("/api/evidence/controls?framework=soc2")));
    expect(other.body.controls.every((c: { owner: string | null }) => c.owner === null)).toBe(true);
    orgId = "org-1";
    const mine = await json(await getControls(req("/api/evidence/controls?framework=soc2")));
    expect(mine.body.controls.find((c: { control_id: string }) => c.control_id === "CC8.1")).toMatchObject({ owner: "ana@acme.dev", assigned_by: "lead@acme.dev" });
    expect(mine.body.controls.map((c: { control_id: string }) => c.control_id)).toEqual(getFrameworkMapping("soc2")!.controls.map(c => c.control_id));
  });

  it("removes an owner, audited, and does nothing when there was none", async () => {
    await put({ framework: "soc2", control_id: "CC8.1", owner_email: "ana@acme.dev" });
    const del = await json(await deleteOwner(req("/api/evidence/controls?framework=soc2&control_id=CC8.1", { method: "DELETE" })));
    expect(del.body).toMatchObject({ ok: true, removed: true, previous_owner: "ana@acme.dev" });
    expect(db.tables.control_owners).toHaveLength(0);
    expect((await json(await deleteOwner(req("/api/evidence/controls?framework=soc2&control_id=CC8.1", { method: "DELETE" })))).body.removed).toBe(false);
  });
});

describe("gap report and signed export", () => {
  const evidence = (control_id: string, evidence_type: string) =>
    collect(req("/api/evidence/records", { method: "POST", body: { framework: "soc2", control_id, evidence_type, evidence_source: `src-${control_id}-${evidence_type}` } }));

  it("joins coverage, owners and the remediation register", async () => {
    await put({ framework: "soc2", control_id: "CC8.1", owner_email: "ana@acme.dev" });
    db.tables.compliance_exceptions.push(
      { id: "e1", org_id: "org-1", framework_id: "soc2", control_id: "CC8.1", title: "Collect PR approvals", status: "in-progress", owner_email: "ana@acme.dev", due_date: "2020-01-01", risk_accepted: false, remediation: "weekly export" },
      { id: "e2", org_id: "org-2", framework_id: "soc2", control_id: "CC6.1", title: "Another org's item", status: "open", owner_email: null, due_date: null, risk_accepted: false, remediation: null },
    );
    const { status, body } = await json(await getGaps(req("/api/evidence/gaps?framework=soc2")));
    expect(status).toBe(200);
    expect(body.mapping_version).toBeDefined();
    expect(body.scope_disclaimer).toMatch(/does not|not establish|not a/i);
    const cc81 = body.controls.find((c: { control_id: string }) => c.control_id === "CC8.1");
    expect(cc81).toMatchObject({ owner: "ana@acme.dev", sufficient_alone: false });
    expect(cc81.remediations).toEqual([expect.objectContaining({ id: "e1", overdue: true })]);
    expect(cc81.flags).toEqual(["remediation_overdue"]);
    const cc61 = body.controls.find((c: { control_id: string }) => c.control_id === "CC6.1");
    expect(cc61.remediations).toEqual([]);                                                   // org-2's item is not shown
    expect(cc61.flags).toEqual(expect.arrayContaining(["no_owner", "gap_untracked"]));
    expect(body.summary.unowned).toBe(body.summary.controls - 1);
  });

  it("evidence that was edited after collection reappears as an unverified gap", async () => {
    await evidence("CC8.1", "pr_approval");
    const before = (await json(await getGaps(req("/api/evidence/gaps?framework=soc2")))).body.controls.find((c: { control_id: string }) => c.control_id === "CC8.1");
    expect(before.gaps.map((g: { kind: string }) => g.kind)).not.toContain("unverified");
    (db.tables.evidence_log[0] as { file_url: string }).file_url = "https://evil.example";
    const after = (await json(await getGaps(req("/api/evidence/gaps?framework=soc2")))).body.controls.find((c: { control_id: string }) => c.control_id === "CC8.1");
    expect(after.gaps).toEqual(expect.arrayContaining([{ evidence_type: "pr_approval", kind: "unverified" }]));
  });

  it("rejects an unknown framework", async () => {
    expect((await json(await getGaps(req("/api/evidence/gaps?framework=hipaa")))).body.error).toBe("unknown_framework");
  });

  it("the gap report needs the export permission too: without it, no owners, no remediation items, no controls", async () => {
    await put({ framework: "soc2", control_id: "CC8.1", owner_email: "ana@acme.dev" });
    db.tables.compliance_exceptions.push({ id: "e1", org_id: "org-1", framework_id: "soc2", control_id: "CC8.1", title: "Secret remediation plan", status: "open", owner_email: "ana@acme.dev", due_date: null, risk_accepted: false, remediation: null });
    allowWrite = false;
    const denied = await json(await getGaps(req("/api/evidence/gaps?framework=soc2")));
    expect(denied.status).toBe(403);
    expect(JSON.stringify(denied.body)).not.toMatch(/ana@acme|Secret remediation|CC8\.1|controls/);
    allowWrite = true;
    expect((await json(await getGaps(req("/api/evidence/gaps?framework=soc2")))).status).toBe(200);
  });

  it("the signed export carries the gap report, and editing it breaks the signature", async () => {
    await put({ framework: "soc2", control_id: "CC8.1", owner_email: "ana@acme.dev" });
    await evidence("CC8.1", "pr_approval");
    const doc = JSON.parse(await (await exportEvidence(req("/api/evidence/export?framework=soc2"))).text());
    expect(doc.gap_report.controls.find((c: { control_id: string }) => c.control_id === "CC8.1")).toMatchObject({ owner: "ana@acme.dev", sufficient_alone: false });
    expect(doc.gap_report.summary.controls).toBe(doc.coverage.total_controls);
    expect(verifier.verifyExport(doc, key.publicKey as string)).toMatchObject({ signature: "valid", problems: [] });
    doc.gap_report.controls.find((c: { control_id: string }) => c.control_id === "CC8.1").owner = "someone@else.dev";
    expect(verifier.verifyExport(doc).signature).toBe("invalid");
    doc.gap_report.summary.unowned = 0;
    expect(verifier.verifyExport(doc).signature).toBe("invalid");
  });
});
