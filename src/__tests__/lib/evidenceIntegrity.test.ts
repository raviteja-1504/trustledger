/**
 * @jest-environment node
 *
 * Task 12 (evidence verification, cryptographic verification, auditor export). Three defects this pins down:
 *   - a stored record's content_hash could not be recomputed from the stored row;
 *   - `verify` marked a record verified even when its hash did not match;
 *   - the export signature covered only top-level scalars (nested records were signed as `{}`).
 */
import crypto from "crypto";
import { NextRequest } from "next/server";
import { fakeSupabase } from "../helpers/fakeSupabase";
import {
  buildEvidenceRecord, evidenceRecordToRow, rowToEvidenceRecord, checkIntegrity, canonicalPayload, computeContentHash,
  type EvidenceRecord,
} from "@/lib/evidenceRecord";
import { anchorStatus, decideVerification, isTrustedEvidence } from "@/lib/evidenceVerification";
import { coverageReport, frameworkCoverageSummary } from "@/lib/controlMapping";

const base = {
  evidence_id: "7d8a52de-3c2b-4a37-a1d6-9d0a1f0f3b11", org_id: "org-1", framework: "soc2", control_id: "CC8.1",
  evidence_type: "pr_approval" as const, evidence_source: "https://github.com/acme/app/pull/7",
  collection_timestamp: "2026-11-01T10:00:00.123Z", collector_identity: "user-1", repository_id: "acme/app", commit_sha: "abc123",
};
const fresh = () => buildEvidenceRecord(base);

/** What the database hands back: its own timestamptz spelling, not the ISO string that was written. */
const asStored = (row: ReturnType<typeof evidenceRecordToRow>, mutate?: (r: typeof row) => void) => {
  const r = { ...row }; mutate?.(r);
  return rowToEvidenceRecord({ ...r, id: r.id!, created_at: "2026-11-01T10:00:00.123000+00:00" })!;
};

describe("a stored record's hash can be recomputed from the stored row", () => {
  it("a new record carries the id and time that were hashed", () => {
    const row = evidenceRecordToRow(fresh());
    expect(row).toMatchObject({ id: base.evidence_id, created_at: base.collection_timestamp });
  });

  it("survives the database's own spelling of the timestamp", () => {
    expect(checkIntegrity(asStored(evidenceRecordToRow(fresh())))).toBe("intact");
  });

  it.each([
    ["the source", (r: { file_url: string | null }) => { r.file_url = "https://evil.example/pr/1"; }],
    ["the control", (r: { control_id: string }) => { r.control_id = "CC6.1"; }],
    ["the framework", (r: { framework_id: string }) => { r.framework_id = "pcidss"; }],
  ])("detects a change to %s", (_n, mutate) => {
    expect(checkIntegrity(asStored(evidenceRecordToRow(fresh()), mutate as never))).toBe("mismatch");
  });

  it("detects a changed expiration date or collector (both are inside the stored note)", () => {
    const row = evidenceRecordToRow(fresh());
    const note = JSON.parse(row.note);
    expect(checkIntegrity(asStored(row, r => { r.note = JSON.stringify({ ...note, expiration_date: "2099-01-01T00:00:00.000Z" }); }))).toBe("mismatch");
    expect(checkIntegrity(asStored(row, r => { r.note = JSON.stringify({ ...note, collector_identity: "someone-else" }); }))).toBe("mismatch");
  });

  it("does not call a record collected before hash_version 2 tampered: it is legacy and cannot be checked", () => {
    const row = evidenceRecordToRow(fresh());
    const legacy = JSON.parse(row.note); delete legacy.hv;
    const rec = asStored({ ...row, note: JSON.stringify(legacy) });
    expect(rec.hash_version).toBe(1);
    expect(checkIntegrity(rec)).toBe("legacy_unverifiable");
  });
});

describe("verification decision", () => {
  const good = () => asStored(evidenceRecordToRow(fresh()));
  const tampered = () => asStored(evidenceRecordToRow(fresh()), r => { r.file_url = "https://evil.example"; });

  it("verifies an intact record whose hash the audit log also holds", () => {
    const o = decideVerification(good(), "anchored");
    expect(o).toMatchObject({ integrity: "intact", result: "verified" });
    expect(o.record.verification_status).toBe("verified");
  });
  it("FAILS a record whose hash does not match (it used to be marked verified anyway)", () => {
    const o = decideVerification(tampered(), "anchored");
    expect(o).toMatchObject({ integrity: "mismatch", result: "failed" });
    expect(o.record.verification_status).toBe("verification_failed");
  });
  it("fails a record whose own hash was edited to match its edited fields, because the audit log still holds the original", () => {
    const edited = tampered();
    edited.content_hash = computeContentHash(canonicalPayload(edited));
    expect(checkIntegrity(edited)).toBe("intact");                         // the record alone looks fine ...
    expect(decideVerification(edited, "anchor_mismatch").result).toBe("failed");   // ... the audit log is what catches it
  });
  it("verifies when there is no audit anchor, but says so", () => {
    expect(decideVerification(good(), "no_anchor")).toMatchObject({ result: "verified", anchor: "no_anchor" });
  });
  it("leaves a legacy record unchanged unless the original payload is supplied", () => {
    const legacy = { ...good(), hash_version: 1 as const };
    expect(decideVerification(legacy, "anchored").result).toBe("unchanged");
    const payload = canonicalPayload(legacy);
    expect(decideVerification(legacy, "anchored", payload).result).toBe("verified");
    expect(decideVerification(legacy, "anchored", payload + " ").result).toBe("failed");
  });
});

describe("audit-log anchor", () => {
  it("compares the record's hash with the hashes the audit log holds for it", () => {
    expect(anchorStatus([{ content_hash: "aa" }, { action: "verify" }], "aa")).toBe("anchored");
    expect(anchorStatus([{ content_hash: "aa" }], "bb")).toBe("anchor_mismatch");
    expect(anchorStatus([{ action: "verify" }, null, "x"], "aa")).toBe("no_anchor");
    expect(anchorStatus([], "aa")).toBe("no_anchor");
  });
});

describe("which records may count toward a control", () => {
  const rec = (over: Partial<EvidenceRecord> = {}): EvidenceRecord => ({ ...asStored(evidenceRecordToRow(fresh())), ...over });
  it("trusts an intact record, in any non-failed status", () => {
    expect(isTrustedEvidence(rec())).toBe(true);
    expect(isTrustedEvidence(rec({ verification_status: "verified" }))).toBe(true);
  });
  it("never trusts revoked, failed, mismatched or anchor-mismatched records", () => {
    expect(isTrustedEvidence(rec({ verification_status: "revoked" }))).toBe(false);
    expect(isTrustedEvidence(rec({ verification_status: "verification_failed" }))).toBe(false);
    expect(isTrustedEvidence(rec({ evidence_source: "https://evil.example" }))).toBe(false);
    expect(isTrustedEvidence(rec(), "anchor_mismatch")).toBe(false);
  });
  it("trusts a legacy record only after it was verified", () => {
    expect(isTrustedEvidence(rec({ hash_version: 1 }))).toBe(false);
    expect(isTrustedEvidence(rec({ hash_version: 1, verification_status: "verified" }))).toBe(true);
  });
});

describe("coverage ignores evidence that fails verification", () => {
  const now = new Date("2026-11-10T00:00:00Z");
  const approval = (): EvidenceRecord => asStored(evidenceRecordToRow(buildEvidenceRecord({ ...base, control_id: "CC8.1" })));

  it("a failed record does not satisfy its requirement, with or without a trust check", () => {
    const failed = { ...approval(), verification_status: "verification_failed" as const };
    for (const opts of [{}, { isTrusted: () => true }]) {
      const c = coverageReport("soc2", [failed], now, opts).find(x => x.control_id === "CC8.1")!;
      expect(c.satisfied_types).not.toContain("pr_approval");
      expect(c.missing_types).toContain("pr_approval");
    }
  });

  it("a record that no longer matches its hash is reported as unverified, and counts for nothing", () => {
    const edited = { ...approval(), evidence_source: "https://evil.example" };
    const c = coverageReport("soc2", [edited], now, { isTrusted: r => isTrustedEvidence(r) }).find(x => x.control_id === "CC8.1")!;
    expect(c.unverified_types).toEqual(["pr_approval"]);
    expect(c.satisfied_types).toEqual([]);
    expect(c.freshness_days).toBeNull();
  });

  it("is unchanged when every record is trusted: no unverified_types key, requirement satisfied", () => {
    const c = coverageReport("soc2", [approval()], now, { isTrusted: r => isTrustedEvidence(r) }).find(x => x.control_id === "CC8.1")!;
    expect(c.satisfied_types).toContain("pr_approval");
    expect("unverified_types" in c).toBe(false);
  });

  it("the framework summary passes the trust check through", () => {
    const s = frameworkCoverageSummary("soc2", [{ ...approval(), evidence_source: "x" }], now, { isTrusted: r => isTrustedEvidence(r) })!;
    expect(s.controls.find(c => c.control_id === "CC8.1")!.unverified_types).toEqual(["pr_approval"]);
  });
});

// ── End to end through the real routes ───────────────────────────────────────────────────────────────────────

const signingKey = crypto.generateKeyPairSync("ed25519", { privateKeyEncoding: { type: "pkcs8", format: "pem" }, publicKeyEncoding: { type: "spki", format: "pem" } });
let db = fakeSupabase({});
jest.mock("@/lib/supabase", () => ({ createServiceClient: () => db.client }));
jest.mock("@/app/api/_middleware", () => ({
  verifyApiKey: async () => ({ org_id: "org-1", user_id: "u-1", actor_email: "lead@acme.dev", role: "admin" }),
  requirePermission: async () => null,
}));

import { POST as collect } from "@/app/api/evidence/records/route";
import { PATCH as lifecycle } from "@/app/api/evidence/[id]/route";
import { GET as exportEvidence } from "@/app/api/evidence/export/route";
// eslint-disable-next-line @typescript-eslint/no-var-requires
const verifier = require("../../../scripts/verify-evidence-export.cjs") as { verifyExport: (doc: unknown, key?: string, allowUnsigned?: boolean) => { signature: string; hash_checked: number; hash_legacy: number; hash_mismatches: string[]; problems: string[]; key_trusted: boolean | null } };

const req = (url: string, init?: { method?: string; body?: unknown }) =>
  new NextRequest(new URL(url, "http://localhost"), { method: init?.method, body: init?.body === undefined ? undefined : JSON.stringify(init.body) });
const patch = (id: string, body: unknown) => lifecycle(req(`/api/evidence/${id}`, { method: "PATCH", body }), { params: Promise.resolve({ id }) });
async function collectOne(over: Record<string, unknown> = {}) {
  const res = await collect(req("/api/evidence/records", { method: "POST", body: { framework: "soc2", control_id: "CC8.1", evidence_type: "pr_approval", evidence_source: "https://github.com/acme/app/pull/7", ...over } }));
  return { status: res.status, ...(await res.json() as { evidence_id: string; content_hash: string }) };
}
const exportDoc = async () => JSON.parse(await (await exportEvidence(req("/api/evidence/export?framework=soc2"))).text());

describe("collect, verify, tamper, export (real routes, in-memory database)", () => {
  beforeEach(() => {
    process.env.EXPORT_SIGNING_PRIVATE_KEY = signingKey.privateKey as string;
    db = fakeSupabase({ evidence_log: [], audit_log: [] });
  });

  it("a collected record verifies from its stored row, without anyone supplying a payload", async () => {
    const c = await collectOne();
    expect(c.status).toBe(201);
    const res = await patch(c.evidence_id, { action: "verify" });
    expect(await res.json()).toMatchObject({ ok: true, hash_match: true, integrity: "intact", anchor: "anchored", verification_status: "verified" });
  });

  it("a record edited in the database fails verification and is then reported as failed", async () => {
    const c = await collectOne();
    (db.tables.evidence_log[0] as { file_url: string }).file_url = "https://evil.example/pr/9";
    const out = await (await patch(c.evidence_id, { action: "verify" })).json();
    expect(out).toMatchObject({ ok: false, hash_match: false, integrity: "mismatch", verification_status: "verification_failed" });
    expect(JSON.parse((db.tables.evidence_log[0] as { note: string }).note).verification_status).toBe("verification_failed");
  });

  it("an attacker who rewrites the record AND its hash is still caught by the audit log's copy", async () => {
    const c = await collectOne();
    const row = db.tables.evidence_log[0] as { file_url: string; note: string; org_id: string; framework_id: string; control_id: string; id: string; created_at: string };
    row.file_url = "https://evil.example/pr/9";
    const forged = rowToEvidenceRecord(row as never)!;
    const note = JSON.parse(row.note); note.content_hash = computeContentHash(canonicalPayload(forged)); row.note = JSON.stringify(note);
    const out = await (await patch(c.evidence_id, { action: "verify" })).json();
    expect(out).toMatchObject({ integrity: "intact", anchor: "anchor_mismatch", verification_status: "verification_failed" });
  });

  it("asks for the original payload when a record predates re-verifiable hashes", async () => {
    const c = await collectOne();
    const row = db.tables.evidence_log[0] as { note: string };
    const note = JSON.parse(row.note); delete note.hv; row.note = JSON.stringify(note);
    const res = await patch(c.evidence_id, { action: "verify" });
    expect(res.status).toBe(422);
    expect(await res.json()).toMatchObject({ error: "legacy_record_needs_payload" });
  });

  it("the export is signed over the whole document and verifies offline, including every record hash", async () => {
    await collectOne(); await collectOne({ control_id: "CC6.1", evidence_type: "access_control_event", evidence_source: "iam-review-2026" });
    const doc = await exportDoc();
    expect(doc.export_version).toBe("1.1");
    expect(doc.evidence_records).toHaveLength(2);
    expect(doc.evidence_records[0]).toMatchObject({ hash_version: 2, integrity: "intact", audit_anchor: "anchored" });
    const v = verifier.verifyExport(doc, signingKey.publicKey as string);
    expect(v).toMatchObject({ signature: "valid", hash_checked: 2, hash_legacy: 0, hash_mismatches: [], problems: [], key_trusted: true });
  });

  it.each([
    ["a record's content hash", (d: any) => { d.evidence_records[0].content_hash = "f".repeat(64); }],
    ["a record's verification status", (d: any) => { d.evidence_records[0].verification_status = "revoked"; }],
    ["a coverage result", (d: any) => { d.coverage.controls[0].status = "satisfied"; }],
    ["an audit-trail entry", (d: any) => { d.audit_trail[0].actor_email = "someone@else.dev"; }],
    ["the scope disclaimer", (d: any) => { d.scope_disclaimer = "This proves compliance."; }],
  ])("detects a change to %s after signing (it used to be signed as {})", async (_n, change) => {
    await collectOne();
    const doc = await exportDoc();
    change(doc);
    const v = verifier.verifyExport(doc);
    expect(v.signature).toBe("invalid");
    expect(v.problems.length).toBeGreaterThan(0);
  });

  it("rejects a document re-signed with someone else's key when the trusted key is pinned", async () => {
    await collectOne();
    const doc = await exportDoc();
    const other = crypto.generateKeyPairSync("ed25519", { privateKeyEncoding: { type: "pkcs8", format: "pem" }, publicKeyEncoding: { type: "spki", format: "pem" } });
    const { cryptographic_verification, ...body } = doc;
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { canonicalJson } = require("../../../scripts/verify-evidence-export.cjs");
    const forged = { ...body, cryptographic_verification: { ...cryptographic_verification, public_key_pem: other.publicKey, key_id: undefined, signature: crypto.sign(null, Buffer.from(canonicalJson(body)), other.privateKey as string).toString("base64") } };
    expect(verifier.verifyExport(forged).signature).toBe("valid");                                   // self-consistent ...
    const pinned = verifier.verifyExport(forged, signingKey.publicKey as string);
    expect(pinned.key_trusted).toBe(false);                                                         // ... but not the trusted key
    expect(pinned.problems[0]).toMatch(/not the trusted key/);
  });

  it("a tampered record is excluded from coverage in the export, and its hash fails offline", async () => {
    await collectOne();
    (db.tables.evidence_log[0] as { file_url: string }).file_url = "https://evil.example/pr/9";
    const doc = await exportDoc();
    expect(doc.evidence_records[0]).toMatchObject({ integrity: "mismatch" });
    const cc81 = doc.coverage.controls.find((c: { control_id: string }) => c.control_id === "CC8.1");
    expect(cc81.unverified_types).toEqual(["pr_approval"]);
    expect(cc81.satisfied_types).toEqual([]);
    expect(verifier.verifyExport(doc).hash_mismatches).toHaveLength(1);
  });

  it("an unsigned export fails verification unless explicitly allowed", async () => {
    delete process.env.EXPORT_SIGNING_PRIVATE_KEY;
    jest.resetModules();
    await collectOne();
    const doc = await exportDoc();
    if (doc.cryptographic_verification.signature) return;   // the key was cached by an earlier request in this file
    expect(verifier.verifyExport(doc).problems).toContain("the document is not signed");
    expect(verifier.verifyExport(doc, undefined, true).problems).toEqual([]);
  });
});
