/**
 * @jest-environment node
 *
 * P0.5: partial or unreadable audit data is never reported as verified. A read error, a server that shortens pages, and a log
 * longer than one check reads each give an explicit INCOMPLETE status instead of a clean result.
 */
import { fakeSupabase } from "../helpers/fakeSupabase";
import { auditEntryHashV2, loadAuditRows, verifyAuditChain, MAX_AUDIT_ROWS } from "@/lib/audit";
import { createCheckpoint } from "@/lib/auditCheckpoint";
import { generateSigningKeyPair } from "@/lib/attestationSigning";

const ORG = "org-1";
const T0 = Date.parse("2026-11-01T00:00:00.000Z");

/** `n` v2 entries, stored as database rows. */
function rows(n: number): Array<Record<string, unknown>> {
  const out: Array<Record<string, unknown>> = [];
  let prev: string | null = null;
  for (let i = 1; i <= n; i++) {
    const created_at = new Date(T0 + i * 1000).toISOString();
    const f = { event_type: "scan_complete", actor_id: null, actor_email: "a@x.dev", resource_type: "scan", resource_id: `s${i}`, payload: { n: i } };
    const entry_hash: string = auditEntryHashV2({ ...f, prev_hash: prev, org_id: ORG, created_at });
    out.push({ id: i, org_id: ORG, ...f, prev_hash: prev, entry_hash, created_at });
    prev = entry_hash;
  }
  return out;
}
/** Cheap rows for tests that only count (the hashes are never reached). */
const bulk = (n: number) => Array.from({ length: n }, (_, i) => ({ id: i + 1, org_id: ORG, event_type: "x", actor_email: null, payload: {}, prev_hash: null, entry_hash: `h${i}`, created_at: "2026-11-01T00:00:00.000Z" }));

describe("loadAuditRows", () => {
  it("is complete when it holds the whole log, past the 1000-row page cap", async () => {
    const db = fakeSupabase({ audit_log: rows(2345) }, { maxRows: 1000 });
    const r = await loadAuditRows(db.client as never, ORG);
    expect(r).toMatchObject({ complete: true });
    expect(r.rows).toHaveLength(2345);
  });

  it("is NOT complete when the server shortens pages (a short page looks like the last one)", async () => {
    const db = fakeSupabase({ audit_log: rows(2345) }, { maxRows: 500 });
    const r = await loadAuditRows(db.client as never, ORG);
    expect(r).toMatchObject({ complete: false, reason: "count_mismatch" });
    expect(r.rows).toHaveLength(500);
  });

  it("is NOT complete when the log is longer than the limit, and says so", async () => {
    const db = fakeSupabase({ audit_log: bulk(2500) }, { maxRows: 1000 });
    const r = await loadAuditRows(db.client as never, ORG, { maxRows: 2000 });
    expect(r).toMatchObject({ complete: false, reason: "limit_reached" });
    expect(r.rows).toHaveLength(2000);
  });

  it("a log of exactly the limit is complete", async () => {
    const db = fakeSupabase({ audit_log: bulk(2000) }, { maxRows: 1000 });
    expect(await loadAuditRows(db.client as never, ORG, { maxRows: 2000 })).toMatchObject({ complete: true });
  });

  it("is NOT complete when a page read fails part-way", async () => {
    const db = fakeSupabase({ audit_log: bulk(2500) }, { maxRows: 1000, errorFor: (t, call) => (t === "audit_log" && call === 2 ? { message: "db down" } : null) });
    expect(await loadAuditRows(db.client as never, ORG)).toMatchObject({ complete: false, reason: "read_failed" });
  });

  it("is NOT complete when the row count cannot be read", async () => {
    const db = fakeSupabase({ audit_log: rows(5) }, { errorFor: (t, call) => (t === "audit_log" && call === 2 ? { message: "db down" } : null) });
    expect(await loadAuditRows(db.client as never, ORG)).toMatchObject({ complete: false, reason: "read_failed" });
  });

  it("ignores other organisations' entries when counting", async () => {
    const db = fakeSupabase({ audit_log: [...rows(5), ...bulk(3).map(r => ({ ...r, org_id: "other", id: r.id + 100 }))] });
    expect(await loadAuditRows(db.client as never, ORG)).toMatchObject({ complete: true });
  });
});

describe("verifyAuditChain", () => {
  it("a complete, clean log is VALID", async () => {
    const db = fakeSupabase({ audit_log: rows(30) });
    expect(await verifyAuditChain(db.client as never, ORG)).toMatchObject({ status: "VALID", valid: true, total: 30, verified: 30 });
  });

  it("a server that shortens pages gives INCOMPLETE, never VALID (the 500 rows it did read are clean)", async () => {
    const db = fakeSupabase({ audit_log: rows(1200) }, { maxRows: 500 });
    const r = await verifyAuditChain(db.client as never, ORG);
    expect(r).toMatchObject({ status: "INCOMPLETE", valid: false, verified: 0 });
  });

  it("a read error gives INCOMPLETE", async () => {
    const db = fakeSupabase({ audit_log: rows(30) }, { errorFor: (t, call) => (t === "audit_log" && call === 1 ? { message: "db down" } : null) });
    expect(await verifyAuditChain(db.client as never, ORG)).toMatchObject({ status: "INCOMPLETE", valid: false });
  });

  it("a log longer than the limit gives INCOMPLETE_LIMIT_REACHED, never VALID", async () => {
    const db = fakeSupabase({ audit_log: bulk(MAX_AUDIT_ROWS + 1) }, { maxRows: 1000 });
    const r = await verifyAuditChain(db.client as never, ORG);
    expect(r).toMatchObject({ status: "INCOMPLETE_LIMIT_REACHED", valid: false, verified: 0, total: MAX_AUDIT_ROWS });
  });
});

describe("checkpoints are not signed over a partial read", () => {
  it("createCheckpoint refuses when the log could not be read in full", async () => {
    const keys = generateSigningKeyPair();
    const saved = process.env.ATTESTATION_SIGNING_KEY;
    process.env.ATTESTATION_SIGNING_KEY = keys.privateKeyPem;
    try {
      const db = fakeSupabase({ audit_log: rows(1200), audit_checkpoints: [], signing_keys: [] }, { maxRows: 500 });
      expect(await createCheckpoint(db.client as never, ORG)).toEqual({ created: false, reason: "audit_unreadable" });
      expect(db.tables.audit_checkpoints).toHaveLength(0);
    } finally { if (saved === undefined) delete process.env.ATTESTATION_SIGNING_KEY; else process.env.ATTESTATION_SIGNING_KEY = saved; }
  });
});
