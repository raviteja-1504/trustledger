/**
 * @jest-environment node
 *
 * P0.1: audit hash v2 covers org, actor and resource; a fork is not a clean history; the writer cannot fork the chain.
 */
import { fakeSupabase } from "../helpers/fakeSupabase";
import {
  auditEntryHash, auditEntryHashV2, checkAuditChain, loadAuditRows, writeAuditLog, type ChainRow,
} from "@/lib/audit";
import { generateSigningKeyPair } from "@/lib/attestationSigning";
import { verifyCheckpointedChain, createCheckpoint } from "@/lib/auditCheckpoint";
// eslint-disable-next-line @typescript-eslint/no-var-requires
const bundleVerifier = require("../../../scripts/verify-audit-bundle.cjs") as { checkChain: (rows: unknown[], orgId: string) => { valid: boolean; reason?: string; broken_at?: number; forked?: boolean; fork_at?: number } };

jest.mock("@/lib/logger", () => ({ logger: { error: jest.fn(), warn: jest.fn(), info: jest.fn() } }));
// a failed audit write records an ops event and alerts the operator (lib/audit.ts); neither is the subject of these tests
jest.mock("@/lib/opsEvents", () => ({ recordEvent: jest.fn(async () => {}) }));
jest.mock("@/lib/opsAlert", () => ({ notifyOps: jest.fn(async () => false) }));

const ORG = "org-1";
const T0 = Date.parse("2026-11-01T00:00:00.000Z");

/** A chain of `n` entries, v2-hashed (the first `v1` of them v1), each carrying every field the hash covers. */
function chain(n: number, v1 = 0): ChainRow[] {
  const rows: ChainRow[] = [];
  let prev: string | null = null;
  for (let i = 1; i <= n; i++) {
    const created_at = new Date(T0 + i * 60_000).toISOString();
    const f = { event_type: "role_change", actor_id: `u${i}`, actor_email: `a${i}@x.dev`, resource_type: "member", resource_id: `m${i}`, payload: { n: i } };
    const entry_hash: string = i <= v1
      ? auditEntryHash(prev, f.event_type, f.actor_email, f.payload, created_at)
      : auditEntryHashV2({ ...f, prev_hash: prev, org_id: ORG, created_at });
    rows.push({ id: i, org_id: ORG, ...f, prev_hash: prev, entry_hash, created_at });
    prev = entry_hash;
  }
  return rows;
}

describe("hash v2 covers every identifying field", () => {
  it("a clean v2 chain verifies, every entry with its metadata covered", () => {
    expect(checkAuditChain(chain(5))).toMatchObject({ status: "VALID", valid: true, verified: 5, metadata_verified: 5, legacy: 0 });
  });

  it.each([
    ["org_id", (r: ChainRow) => { r.org_id = "org-2"; }],
    ["actor_id", (r: ChainRow) => { r.actor_id = "someone-else"; }],
    ["resource_type", (r: ChainRow) => { r.resource_type = "api_key"; }],
    ["resource_id", (r: ChainRow) => { r.resource_id = "m999"; }],
    ["actor_email", (r: ChainRow) => { r.actor_email = "evil@x.dev"; }],
    ["event_type", (r: ChainRow) => { r.event_type = "scan_complete"; }],
    ["payload", (r: ChainRow) => { r.payload = { n: 999 }; }],
    ["created_at", (r: ChainRow) => { r.created_at = new Date(T0 + 5).toISOString(); }],
  ])("changing %s is detected", (_field, tamper) => {
    const rows = chain(5);
    tamper(rows[2]);
    expect(checkAuditChain(rows)).toMatchObject({ status: "INVALID", valid: false, broken_at: 3, reason: "content_changed" });
  });

  it("nulling a metadata field is detected (null is not the same as a value)", () => {
    const rows = chain(4);
    rows[1].actor_id = null; rows[1].resource_id = null;
    expect(checkAuditChain(rows).valid).toBe(false);
  });

  it("changing prev_hash is detected as a broken link", () => {
    const rows = chain(4);
    rows[2].prev_hash = "0".repeat(64);
    expect(checkAuditChain(rows)).toMatchObject({ valid: false, reason: "missing_link" });
  });

  it("older v1 entries still verify (their metadata cannot be covered), and are counted apart", () => {
    expect(checkAuditChain(chain(6, 3))).toMatchObject({ status: "VALID", verified: 6, metadata_verified: 3 });
  });

  it("an entry cannot be re-hashed as v1 to make its metadata editable (downgrade)", () => {
    const rows = chain(4);
    const r = rows[3];
    r.resource_id = "forged";
    r.entry_hash = auditEntryHash(r.prev_hash, r.event_type, r.actor_email, r.payload, r.created_at);   // a valid v1 hash of the edited row
    expect(checkAuditChain(rows)).toMatchObject({ status: "INVALID", valid: false, reason: "downgraded", broken_at: 4 });
  });

  it("a v2 row with no org_id is not counted as verified (the loader always supplies it): it shows as unverified, never as checked", () => {
    const rows = chain(3).map(r => { const copy = { ...r }; delete copy.org_id; return copy as ChainRow; });
    expect(checkAuditChain(rows)).toMatchObject({ verified: 0, metadata_verified: 0, legacy: 3 });
  });

  it("v2 does not collide across field boundaries (fields are an array, not a joined string)", () => {
    const base = { prev_hash: null, org_id: ORG, event_type: "e", actor_id: null, actor_email: "a", payload: {}, created_at: "t" };
    expect(auditEntryHashV2({ ...base, resource_type: "x::y", resource_id: "z" })).not.toBe(auditEntryHashV2({ ...base, resource_type: "x", resource_id: "y::z" }));
  });
});

describe("a fork is not a clean history", () => {
  /** Entries 2 and 3 both claim entry 1 as parent. */
  function forked(): ChainRow[] {
    const rows = chain(3);
    const f = { event_type: "role_change", actor_id: "u", actor_email: "a@x.dev", resource_type: "member", resource_id: "m", payload: { branch: "b" } };
    const created_at = new Date(T0 + 4 * 60_000).toISOString();
    rows[2] = { id: 3, org_id: ORG, ...f, prev_hash: rows[0].entry_hash, created_at, entry_hash: auditEntryHashV2({ ...f, prev_hash: rows[0].entry_hash, org_id: ORG, created_at }) };
    return rows;
  }

  it("is FORK_DETECTED and not valid, naming where it starts", () => {
    expect(checkAuditChain(forked())).toMatchObject({ status: "FORK_DETECTED", valid: false, concurrent: 1, fork_at: 3 });
  });

  it("makes the checkpoint verification non-clean (CHAIN_FORKED), not VALID and not HISTORY_MODIFIED", () => {
    const v = verifyCheckpointedChain(ORG, forked(), [], []);
    expect(v.status).toBe("CHAIN_FORKED");
    expect(v.problems[0]).toMatchObject({ code: "chain_forked" });
  });

  it("checkpoint creation refuses to sign a forked chain", async () => {
    const keys = generateSigningKeyPair();
    const saved = process.env.ATTESTATION_SIGNING_KEY;
    process.env.ATTESTATION_SIGNING_KEY = keys.privateKeyPem;
    try {
      const db = fakeSupabase({ audit_log: forked().map(r => ({ ...r })), audit_checkpoints: [], signing_keys: [] });
      expect(await createCheckpoint(db.client as never, ORG)).toEqual({ created: false, reason: "verification_failed", status: "CHAIN_FORKED" });
      expect(db.tables.audit_checkpoints).toHaveLength(0);
    } finally { if (saved === undefined) delete process.env.ATTESTATION_SIGNING_KEY; else process.env.ATTESTATION_SIGNING_KEY = saved; }
  });

  it("the offline bundle verifier reports a fork too", () => {
    expect(bundleVerifier.checkChain(forked(), ORG)).toMatchObject({ valid: false, forked: true, fork_at: 3 });
  });
});

describe("offline bundle verifier matches the server on v2", () => {
  it("accepts a clean v2 chain and a mixed v1 -> v2 chain", () => {
    expect(bundleVerifier.checkChain(chain(5), ORG).valid).toBe(true);
    expect(bundleVerifier.checkChain(chain(6, 3), ORG).valid).toBe(true);
  });

  it("catches a change to each covered field, and a downgrade", () => {
    for (const edit of [(r: ChainRow) => { r.actor_id = "x"; }, (r: ChainRow) => { r.resource_type = "x"; }, (r: ChainRow) => { r.resource_id = "x"; }]) {
      const rows = chain(4); edit(rows[2]);
      expect(bundleVerifier.checkChain(rows, ORG)).toMatchObject({ valid: false, reason: "content_changed", broken_at: 3 });
    }
    const rows = chain(4); const r = rows[3]; r.resource_id = "forged";
    r.entry_hash = auditEntryHash(r.prev_hash, r.event_type, r.actor_email, r.payload, r.created_at);
    expect(bundleVerifier.checkChain(rows, ORG)).toMatchObject({ valid: false, reason: "downgraded" });
  });
});

describe("writeAuditLog", () => {
  const entry = { org_id: ORG, event_type: "member_role_changed" as const, actor_id: "u1", actor_email: "a@x.dev", resource_type: "member", resource_id: "m1", payload: { to: "admin" } };

  it("writes a v2 entry that the chain check recomputes, chained to the previous one", async () => {
    const db = fakeSupabase({ audit_log: [] });
    await writeAuditLog(db.client as never, entry);
    await writeAuditLog(db.client as never, { ...entry, resource_id: "m2" });
    const { rows } = await loadAuditRows(db.client as never, ORG);
    expect(rows).toHaveLength(2);
    expect(checkAuditChain(rows)).toMatchObject({ status: "VALID", verified: 2, metadata_verified: 2 });
  });

  type DbErr = { code: string; message: string } | null;
  /**
   * A client whose reads answer from `tails` in turn (the last one repeats), whose audit_log insert fails with
   * `insertErrors` in turn (null = succeeds), and which can fail its reads.
   */
  function scripted(opts: { insertErrors?: DbErr[]; readError?: boolean; tails?: Array<string | null> }) {
    const inserts: Array<Record<string, unknown>> = [];
    const tails = opts.tails ?? [null];
    let insertCall = 0, readCall = 0;
    const client = {
      from: () => ({
        select: () => {
          const q: Record<string, unknown> = {};
          q.eq = () => q;
          q.order = () => q;
          q.limit = async () => {
            const tail = tails[Math.min(readCall++, tails.length - 1)];
            return opts.readError ? { data: null, error: { message: "db down" } } : { data: tail ? [{ entry_hash: tail }] : [], error: null };
          };
          return q;
        },
        insert: async (row: Record<string, unknown>) => { inserts.push(row); return { error: opts.insertErrors?.[insertCall++] ?? null }; },
      }),
    };
    return { client, inserts };
  }

  it("retries after a unique-violation from a concurrent writer, appending after the NEW tail", async () => {
    // our read sees tail-1; another instance appends first (our insert is refused); the re-read sees tail-2
    const s = scripted({ tails: ["tail-1", "tail-2"], insertErrors: [{ code: "23505", message: "duplicate key" }, null] });
    await writeAuditLog(s.client as never, entry, { strict: true });
    expect(s.inserts.map(r => r.prev_hash)).toEqual(["tail-1", "tail-2"]);
  });

  it("does not append a genesis entry when the previous entry cannot be read (that would fork the chain)", async () => {
    const s = scripted({ readError: true });
    await writeAuditLog(s.client as never, entry);                       // best effort: no throw...
    expect(s.inserts).toHaveLength(0);                                   // ...but nothing was written
    await expect(writeAuditLog(s.client as never, entry, { strict: true })).rejects.toThrow(/audit_write_failed: read/);
  });

  it("gives up after repeated conflicts: strict callers get the failure, others do not throw", async () => {
    const conflict = { code: "23505", message: "duplicate key" };
    const s = scripted({ insertErrors: Array(10).fill(conflict) });
    await expect(writeAuditLog(s.client as never, entry, { strict: true })).rejects.toThrow(/audit_write_failed/);
    expect(s.inserts.length).toBeLessThanOrEqual(6);
    const lenient = scripted({ insertErrors: Array(10).fill(conflict) });
    await expect(writeAuditLog(lenient.client as never, entry)).resolves.toBeUndefined();
  });

  it("does not retry other insert errors", async () => {
    const s = scripted({ insertErrors: [{ code: "42501", message: "permission denied" }] });
    await expect(writeAuditLog(s.client as never, entry, { strict: true })).rejects.toThrow(/permission denied/);
    expect(s.inserts).toHaveLength(1);
  });
});

describe("one-child-per-parent migrations", () => {
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const fs = require("fs") as typeof import("fs");
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const path = require("path") as typeof import("path");
  const sql = (f: string) => fs.readFileSync(path.join(__dirname, "../../../supabase/migrations", f), "utf8");

  it("the new-entries index is partial, so an organisation's existing fork cannot block it", () => {
    const s = sql("20261128_audit_one_child_new_entries.sql");
    expect(s).toContain("CREATE UNIQUE INDEX audit_log_one_child_new_entries");
    expect(s).toContain("(COALESCE(prev_hash, ''GENESIS''))");
    expect(s).toContain("WHERE id > %s");
    expect(s).toContain("MAX(id)");
  });

  it("the full-table index skips rather than fails when a fork exists (so it is never relied on alone)", () => {
    expect(sql("20261128_audit_one_child_per_parent.sql")).toContain("EXCEPTION WHEN unique_violation");
  });
});

describe("recording that forks were reviewed", () => {
  /** A v2 chain: entries 1,2, then 3 which forks off entry 1. Optionally followed by a review entry. */
  function forkedChain(review?: { ids: number[]; at?: "end" | "before" }): ChainRow[] {
    const rows = chain(2);
    const mk = (id: number, prev: string | null, event_type: string, payload: unknown): ChainRow => {
      const created_at = new Date(T0 + id * 60_000).toISOString();
      const f = { event_type, actor_id: "u", actor_email: "a@x.dev", resource_type: "audit_log", resource_id: null as string | null, payload };
      return { id, org_id: ORG, ...f, prev_hash: prev, created_at, entry_hash: auditEntryHashV2({ ...f, prev_hash: prev, org_id: ORG, created_at }) };
    };
    rows.push(mk(3, rows[0].entry_hash, "user_login", { fork: true }));                       // shares entry 1 as its parent
    if (review) rows.push(mk(4, rows[2].entry_hash, "audit_forks_reviewed", { fork_entry_ids: review.ids }));
    return rows;
  }

  it("an unreviewed fork is not clean", () => {
    expect(checkAuditChain(forkedChain())).toMatchObject({ status: "FORK_DETECTED", valid: false, fork_ids: [3], unreviewed_forks: 1 });
  });

  it("once an entry later in the chain names it, the fork counts as reviewed and the log verifies", () => {
    expect(checkAuditChain(forkedChain({ ids: [3] }))).toMatchObject({ status: "VALID", valid: true, concurrent: 1, reviewed_forks: 1, unreviewed_forks: 0 });
  });

  it("a review does not cover a fork it did not name", () => {
    expect(checkAuditChain(forkedChain({ ids: [99] }))).toMatchObject({ status: "FORK_DETECTED", unreviewed_fork_ids: [3] });
    expect(checkAuditChain(forkedChain({ ids: [] }))).toMatchObject({ status: "FORK_DETECTED" });
  });

  it("a fork that happens AFTER the review is not covered by it", () => {
    const rows = forkedChain({ ids: [3] });
    // entry 5 forks off entry 3 (which already has entry 4 as a child)
    const created_at = new Date(T0 + 5 * 60_000).toISOString();
    const f = { event_type: "user_login", actor_id: "u", actor_email: "a@x.dev", resource_type: "session", resource_id: null as string | null, payload: { late: true } };
    rows.push({ id: 5, org_id: ORG, ...f, prev_hash: rows[2].entry_hash, created_at, entry_hash: auditEntryHashV2({ ...f, prev_hash: rows[2].entry_hash, org_id: ORG, created_at }) });
    expect(checkAuditChain(rows)).toMatchObject({ status: "FORK_DETECTED", reviewed_forks: 1, unreviewed_fork_ids: [5], fork_at: 5 });
  });

  it("a review entry cannot vouch for a fork that did not exist yet (it can only name entries before its own id)", () => {
    // review entry 4 names fork 3 and ALSO 5; entry 5 (written after the review) forks off entry 3
    const rows = forkedChain({ ids: [3, 5] });
    const created_at = new Date(T0 + 5 * 60_000).toISOString();
    const f = { event_type: "user_login", actor_id: "u", actor_email: "a@x.dev", resource_type: "session", resource_id: null as string | null, payload: { later: true } };
    rows.push({ id: 5, org_id: ORG, ...f, prev_hash: rows[2].entry_hash, created_at, entry_hash: auditEntryHashV2({ ...f, prev_hash: rows[2].entry_hash, org_id: ORG, created_at }) });
    expect(checkAuditChain(rows)).toMatchObject({ status: "FORK_DETECTED", reviewed_forks: 1, unreviewed_fork_ids: [5] });
  });

  it("changing a review entry's payload breaks its hash, so a review cannot be forged or edited", () => {
    const rows = forkedChain({ ids: [3] });
    rows[3].payload = { fork_entry_ids: [3, 7] };
    expect(checkAuditChain(rows)).toMatchObject({ status: "INVALID", valid: false, broken_at: 4 });
  });

  it("a review never hides tampering: a changed entry is still INVALID", () => {
    const rows = forkedChain({ ids: [3] });
    rows[1].resource_id = "x";
    expect(checkAuditChain(rows).valid).toBe(false);
  });

  it("checkpoint creation is allowed again after the review, and still refused without it", async () => {
    const keys = generateSigningKeyPair();
    const saved = process.env.ATTESTATION_SIGNING_KEY;
    process.env.ATTESTATION_SIGNING_KEY = keys.privateKeyPem;
    try {
      const blocked = fakeSupabase({ audit_log: forkedChain().map(r => ({ ...r })), audit_checkpoints: [], signing_keys: [] });
      expect(await createCheckpoint(blocked.client as never, ORG)).toMatchObject({ created: false, status: "CHAIN_FORKED" });
      const ok = fakeSupabase({ audit_log: forkedChain({ ids: [3] }).map(r => ({ ...r })), audit_checkpoints: [], signing_keys: [] });
      expect(await createCheckpoint(ok.client as never, ORG)).toMatchObject({ created: true });
    } finally { if (saved === undefined) delete process.env.ATTESTATION_SIGNING_KEY; else process.env.ATTESTATION_SIGNING_KEY = saved; }
  });

  it("the offline bundle verifier agrees", () => {
    expect(bundleVerifier.checkChain(forkedChain(), ORG)).toMatchObject({ valid: false, forked: true, fork_at: 3 });
    expect(bundleVerifier.checkChain(forkedChain({ ids: [3] }), ORG)).toMatchObject({ valid: true });
  });
});
