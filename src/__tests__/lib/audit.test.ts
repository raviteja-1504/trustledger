/**
 * Audit chain (lib/audit.ts): entries hash canonical JSON with their stored time, so they can be recomputed from
 * the row; verification checks every link and every recomputable entry, and doesn't call pre-fix entries tampered.
 */
import { auditEntryHash, canonicalJson, checkAuditChain, verifyAuditChain, writeAuditLog, type ChainRow, type VerificationStatus } from "@/lib/audit";
import { buildAuditHash } from "@/lib/scanner";
import type { SupabaseClient } from "@supabase/supabase-js";
import type { Database } from "@/types/supabase";

function chain(events: Array<{ event_type: string; actor_email: string | null; payload: Record<string, unknown> }>, start = 1): ChainRow[] {
  let prev: string | null = null;
  return events.map((e, i) => {
    const created_at = new Date(Date.UTC(2026, 0, i + 1, 10, 0, 0, 123)).toISOString();
    const entry_hash = auditEntryHash(prev, e.event_type, e.actor_email, e.payload, created_at);
    const row: ChainRow = { id: start + i, ...e, prev_hash: prev, entry_hash, created_at };
    prev = entry_hash;
    return row;
  });
}
const three = () => chain([
  { event_type: "scan_complete", actor_email: "a@b.com", payload: { scan_id: "s1", repo: "o/api" } },
  { event_type: "attestation",   actor_email: "a@b.com", payload: { file: "x.ts" } },
  { event_type: "merge_blocked", actor_email: null,      payload: { reason: "risk" } },
]);

describe("canonicalJson", () => {
  it("sorts keys at every level, so jsonb's key reordering doesn't change the text", () => {
    expect(canonicalJson({ b: 1, a: { d: [{ z: 1, y: 2 }], c: null } })).toBe('{"a":{"c":null,"d":[{"y":2,"z":1}]},"b":1}');
    expect(canonicalJson({ a: undefined, b: "x" })).toBe('{"b":"x"}');
    expect(canonicalJson([undefined, 1])).toBe("[null,1]");
    expect(canonicalJson("s")).toBe('"s"');
  });
});

describe("checkAuditChain", () => {
  it("an empty or untampered chain is valid, every entry verified", () => {
    expect(checkAuditChain([])).toMatchObject({ valid: true, status: "VALID", total: 0, verified: 0 });
    const r = checkAuditChain(three());
    expect(r).toMatchObject({ valid: true, status: "VALID", total: 3, verified: 3, legacy: 0, concurrent: 0, first_at: "2026-01-01T10:00:00.123Z", last_at: "2026-01-03T10:00:00.123Z" });
  });

  it("recomputes from the row as Postgres returns it: reordered keys, +00:00 timestamps", () => {
    const rows = three().map(r => ({ ...r, created_at: r.created_at.replace("Z", "+00:00"), payload: Object.fromEntries(Object.entries(r.payload as object).reverse()) }));
    expect(checkAuditChain(rows)).toMatchObject({ valid: true, verified: 3 });
  });

  it("a changed payload is detected at that entry — status INVALID", () => {
    const rows = three();
    rows[1].payload = { file: "x.ts", tampered: true };
    expect(checkAuditChain(rows)).toMatchObject({ valid: false, status: "INVALID", broken_at: 2, reason: "content_changed", verified: 1 });
  });

  it("a deleted entry breaks the next entry's link — status MISSING_RECORDS", () => {
    const rows = three();
    expect(checkAuditChain([rows[0], rows[2]])).toMatchObject({ valid: false, status: "MISSING_RECORDS", broken_at: 3, reason: "missing_link" });
  });

  it("entries written before the fix can't be recomputed: link-checked and counted, not called tampered", () => {
    // Legacy: hashed with insertion-order JSON and a time the database didn't store.
    let prev: string | null = null;
    const legacy: ChainRow[] = [1, 2].map(i => {
      const entry_hash = buildAuditHash(prev, "scan_complete", "a@b.com", JSON.stringify({ z: 1, a: i }), "2025-12-01T00:00:00.000Z");
      const row = { id: i, event_type: "scan_complete", actor_email: "a@b.com", payload: { a: i, z: 1 }, prev_hash: prev, entry_hash, created_at: "2025-12-01T00:00:00.004Z" };
      prev = entry_hash;
      return row;
    });
    const fresh = chain([{ event_type: "attestation", actor_email: "a@b.com", payload: { f: 1 } }], 3);
    fresh[0].prev_hash = prev;
    fresh[0].entry_hash = auditEntryHash(prev, "attestation", "a@b.com", { f: 1 }, fresh[0].created_at);
    expect(checkAuditChain([...legacy, ...fresh])).toMatchObject({ valid: true, total: 3, verified: 1, legacy: 2 });
    // ...but once entries are recomputable, a later unrecomputable one IS a change.
    const broken = [...legacy, ...fresh, { ...legacy[1], id: 4, prev_hash: fresh[0].entry_hash, entry_hash: "f".repeat(64) }];
    expect(checkAuditChain(broken)).toMatchObject({ valid: false, broken_at: 4, reason: "content_changed" });
  });

  it("two entries written at once that point at the same previous entry — status FORK_DETECTED", () => {
    const [a] = three();
    const b = { id: 2, event_type: "x", actor_email: null, payload: {}, prev_hash: a.entry_hash, created_at: "2026-02-01T00:00:00.000Z", entry_hash: "" };
    b.entry_hash = auditEntryHash(b.prev_hash, b.event_type, null, b.payload, b.created_at);
    const c = { ...b, id: 3, event_type: "y" };
    c.entry_hash = auditEntryHash(c.prev_hash, c.event_type, null, c.payload, c.created_at);
    const r = checkAuditChain([a, b, c]);
    expect(r).toMatchObject({ status: "FORK_DETECTED", valid: true, concurrent: 1, verified: 3 });
  });

  it("a first entry pointing at a hash that isn't there is a missing link", () => {
    const rows = three();
    rows[0] = { ...rows[0], prev_hash: "a".repeat(64) };
    expect(checkAuditChain(rows)).toMatchObject({ valid: false, broken_at: 1, reason: "missing_link" });
  });
});

describe("verifyAuditChain + writeAuditLog", () => {
  function memoryDb(maxRows = 1000) {
    const rows: ChainRow[] = [];
    const db = {
      from: () => {
        let insertRow: Record<string, unknown> | null = null;
        let window: [number, number] | null = null, desc = false, lim: number | null = null;
        const q = {
          select: () => q, eq: () => q,
          order: (_c: string, o?: { ascending?: boolean }) => { desc = o?.ascending === false; return q; },
          limit: (n: number) => { lim = n; return q; },
          range: (a: number, b: number) => { window = [a, b]; return q; },
          single: async () => ({ data: desc ? rows[rows.length - 1] ?? null : rows[0] ?? null }),
          insert: async (r: Record<string, unknown>) => { insertRow = r; rows.push({ id: rows.length + 1, ...r } as unknown as ChainRow); return { error: null }; },
          then: (res: (v: unknown) => unknown) => {
            let out = desc ? [...rows].reverse() : [...rows];
            if (window) out = out.slice(window[0], window[1] + 1);
            out = out.slice(0, Math.min(lim ?? Infinity, maxRows));
            void insertRow;
            return Promise.resolve({ data: out, error: null }).then(res);
          },
        };
        return q;
      },
    };
    return { db: db as unknown as SupabaseClient<Database>, rows };
  }

  it("what writeAuditLog stores verifies, past the 1000-row cap", async () => {
    const { db, rows } = memoryDb();
    for (let i = 0; i < 1203; i++) await writeAuditLog(db, { org_id: "o", event_type: "scan_complete", actor_email: i % 2 ? "a@b.com" : null, payload: { i, nested: { z: 1, a: [i] } } });
    expect(rows[0].created_at).toMatch(/Z$/);                 // the hashed time is stored
    const r = await verifyAuditChain(db, "o");
    expect(r).toMatchObject({ status: "VALID", valid: true, total: 1203, verified: 1203, legacy: 0 });
  });

  it("concurrent in-process writes for the same org are serialised — no fork", async () => {
    const { db, rows } = memoryDb();
    // Fire 20 writes for the same org simultaneously; the in-process lock must prevent forks.
    await Promise.all(Array.from({ length: 20 }, (_, i) =>
      writeAuditLog(db, { org_id: "org1", event_type: "scan_complete", actor_email: null, payload: { i } }),
    ));
    const r = await verifyAuditChain(db, "org1");
    expect(rows).toHaveLength(20);
    // No fork: every entry must have a unique prev_hash.
    const prevHashes = rows.map(r => r.prev_hash).filter(Boolean);
    expect(new Set(prevHashes).size).toBe(prevHashes.length);
    expect(r).toMatchObject({ status: "VALID", valid: true, total: 20, verified: 20, concurrent: 0 });
  });

  it("concurrent writes for different orgs are independent — both chains verify", async () => {
    // Use separate db instances per org so the simplified memoryDb doesn't cross-contaminate.
    const { db: dbA } = memoryDb();
    const { db: dbB } = memoryDb();
    await Promise.all([
      ...Array.from({ length: 5 }, (_, i) => writeAuditLog(dbA, { org_id: "orgA", event_type: "scan_complete", actor_email: null, payload: { i } })),
      ...Array.from({ length: 5 }, (_, i) => writeAuditLog(dbB, { org_id: "orgB", event_type: "attestation",   actor_email: null, payload: { i } })),
    ]);
    const [rA, rB] = await Promise.all([verifyAuditChain(dbA, "orgA"), verifyAuditChain(dbB, "orgB")]);
    expect(rA).toMatchObject({ status: "VALID", valid: true, total: 5 });
    expect(rB).toMatchObject({ status: "VALID", valid: true, total: 5 });
  });

  it("verifyAuditChain returns INCOMPLETE when a database error occurs mid-read", async () => {
    // Use synthetic rows (1000 entries) so a second read is triggered, then fail that second read.
    // We don't need valid hashes here — the error fires before checkAuditChain.
    const fakeRows: ChainRow[] = Array.from({ length: 1000 }, (_, i) => ({
      id: i + 1, event_type: "scan_complete", actor_email: null,
      payload: { i }, prev_hash: i === 0 ? null : `h${i - 1}`,
      entry_hash: `h${i}`, created_at: new Date(Date.UTC(2026, 0, i + 1)).toISOString(),
    }));
    let call = 0;
    const errorDb = {
      from: () => {
        const q: Record<string, unknown> = {};
        q.select = () => q; q.eq = () => q; q.order = () => q; q.range = () => q;
        q.then = (res: (v: unknown) => unknown) => {
          call++;
          if (call >= 2) return Promise.resolve({ data: null, error: { message: "db timeout" } }).then(res);
          return Promise.resolve({ data: fakeRows, error: null }).then(res);
        };
        return q;
      },
    };
    const r = await verifyAuditChain(errorDb as unknown as SupabaseClient<Database>, "org");
    expect(r.status).toBe("INCOMPLETE");
    expect(r.valid).toBe(false);
    expect(r.total).toBe(1000);
  });
});
