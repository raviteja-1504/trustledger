/**
 * Audit chain (lib/audit.ts): entries hash canonical JSON with their stored time, so they can be recomputed from
 * the row; verification checks every link and every recomputable entry, and doesn't call pre-fix entries tampered.
 */
import { auditEntryHash, canonicalJson, checkAuditChain, verifyAuditChain, writeAuditLog, type ChainRow } from "@/lib/audit";
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
    expect(checkAuditChain([])).toMatchObject({ valid: true, total: 0, verified: 0 });
    const r = checkAuditChain(three());
    expect(r).toMatchObject({ valid: true, total: 3, verified: 3, legacy: 0, concurrent: 0, first_at: "2026-01-01T10:00:00.123Z", last_at: "2026-01-03T10:00:00.123Z" });
  });

  it("recomputes from the row as Postgres returns it: reordered keys, +00:00 timestamps", () => {
    const rows = three().map(r => ({ ...r, created_at: r.created_at.replace("Z", "+00:00"), payload: Object.fromEntries(Object.entries(r.payload as object).reverse()) }));
    expect(checkAuditChain(rows)).toMatchObject({ valid: true, verified: 3 });
  });

  it("a changed payload is detected at that entry", () => {
    const rows = three();
    rows[1].payload = { file: "x.ts", tampered: true };
    expect(checkAuditChain(rows)).toMatchObject({ valid: false, broken_at: 2, reason: "content_changed", verified: 1 });
  });

  it("a deleted entry breaks the next entry's link", () => {
    const rows = three();
    expect(checkAuditChain([rows[0], rows[2]])).toMatchObject({ valid: false, broken_at: 3, reason: "missing_link" });
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

  it("two entries written at once that point at the same previous entry are counted, not failed", () => {
    const [a] = three();
    const b = { id: 2, event_type: "x", actor_email: null, payload: {}, prev_hash: a.entry_hash, created_at: "2026-02-01T00:00:00.000Z", entry_hash: "" };
    b.entry_hash = auditEntryHash(b.prev_hash, b.event_type, null, b.payload, b.created_at);
    const c = { ...b, id: 3, event_type: "y" };
    c.entry_hash = auditEntryHash(c.prev_hash, c.event_type, null, c.payload, c.created_at);
    expect(checkAuditChain([a, b, c])).toMatchObject({ valid: true, concurrent: 1, verified: 3 });
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
    expect(r).toMatchObject({ valid: true, total: 1203, verified: 1203, legacy: 0 });
  });
});
