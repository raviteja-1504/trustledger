import { verifyAuditChain } from "@/lib/audit";
import { buildAuditHash } from "@/lib/scanner";
import type { SupabaseClient } from "@supabase/supabase-js";
import type { Database } from "@/types/supabase";

type Row = {
  id: number; event_type: string; actor_email: string | null;
  payload: unknown; prev_hash: string | null; entry_hash: string; created_at: string;
};

function buildValidChain(events: Array<{ event_type: string; actor_email: string; payload: Record<string, unknown> }>): Row[] {
  let prevHash: string | null = null;
  return events.map((e, i) => {
    const created_at = new Date(2026, 0, i + 1).toISOString();
    const entry_hash = buildAuditHash(prevHash, e.event_type, e.actor_email, JSON.stringify(e.payload), created_at);
    const row: Row = { id: i + 1, event_type: e.event_type, actor_email: e.actor_email, payload: e.payload, prev_hash: prevHash, entry_hash, created_at };
    prevHash = entry_hash;
    return row;
  });
}

function dbReturning(rows: Row[]): SupabaseClient<Database> {
  return {
    from: () => ({
      select: () => ({
        eq: () => ({
          order: () => Promise.resolve({ data: rows }),
        }),
      }),
    }),
  } as unknown as SupabaseClient<Database>;
}

describe("verifyAuditChain", () => {
  it("reports valid for an empty log", async () => {
    const result = await verifyAuditChain(dbReturning([]), "org-1");
    expect(result).toEqual({ valid: true, total: 0 });
  });

  it("validates an untampered hash chain", async () => {
    const rows = buildValidChain([
      { event_type: "scan_complete", actor_email: "a@b.com", payload: { scan_id: "s1" } },
      { event_type: "attestation",   actor_email: "a@b.com", payload: { file: "x.ts" } },
      { event_type: "merge_blocked", actor_email: "system",  payload: { reason: "risk" } },
    ]);
    const result = await verifyAuditChain(dbReturning(rows), "org-1");
    expect(result).toEqual({ valid: true, total: 3 });
  });

  it("detects tampering with a single entry's payload", async () => {
    const rows = buildValidChain([
      { event_type: "scan_complete", actor_email: "a@b.com", payload: { scan_id: "s1" } },
      { event_type: "attestation",   actor_email: "a@b.com", payload: { file: "x.ts" } },
      { event_type: "merge_blocked", actor_email: "system",  payload: { reason: "risk" } },
    ]);
    // Simulate someone editing row 2's payload directly in the DB without
    // recomputing the hash — the whole point of the chain is to catch this.
    rows[1].payload = { file: "x.ts", tampered: true };

    const result = await verifyAuditChain(dbReturning(rows), "org-1");
    expect(result.valid).toBe(false);
    expect(result.broken_at).toBe(rows[1].id);
  });

  it("detects a deleted entry (chain gap breaks the next entry's prev_hash link)", async () => {
    const rows = buildValidChain([
      { event_type: "scan_complete", actor_email: "a@b.com", payload: { scan_id: "s1" } },
      { event_type: "attestation",   actor_email: "a@b.com", payload: { file: "x.ts" } },
      { event_type: "merge_blocked", actor_email: "system",  payload: { reason: "risk" } },
    ]);
    // Remove the middle row entirely, as an attacker deleting an inconvenient
    // audit entry from the table would — the remaining rows no longer chain.
    const withGap = [rows[0], rows[2]];

    const result = await verifyAuditChain(dbReturning(withGap), "org-1");
    expect(result.valid).toBe(false);
    expect(result.broken_at).toBe(rows[2].id);
  });
});
