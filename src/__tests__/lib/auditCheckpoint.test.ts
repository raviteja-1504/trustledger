/**
 * @jest-environment node
 *
 * Task 11: signed audit checkpoints. Truncation of the newest entries is invisible to the hash chain alone;
 * these tests show the checkpoints catch it, along with modified history, forged or reordered checkpoints,
 * and that key rotation / revocation behave.
 */
import { fakeSupabase } from "../helpers/fakeSupabase";
import { auditEntryHash, type ChainRow } from "@/lib/audit";
import { generateSigningKeyPair } from "@/lib/attestationSigning";
import {
  buildCheckpointPayload, signCheckpoint, verifyCheckpointSignature, verifyCheckpointedChain, createCheckpoint,
  verifyOrgCheckpoints, exportAuditBundle, type CheckpointKey, type SignedCheckpoint,
} from "@/lib/auditCheckpoint";

const ORG = "org-1";
const T0 = Date.parse("2026-11-01T00:00:00.000Z");

function chain(n: number, tamper?: (rows: ChainRow[]) => void): ChainRow[] {
  const rows: ChainRow[] = [];
  let prev: string | null = null;
  for (let i = 1; i <= n; i++) {
    const at = new Date(T0 + i * 60_000).toISOString();
    const payload = { n: i };
    const hash = auditEntryHash(prev, "scan_complete", "a@x.dev", payload, at);
    rows.push({ id: i, event_type: "scan_complete", actor_email: "a@x.dev", payload, prev_hash: prev, entry_hash: hash, created_at: at });
    prev = hash;
  }
  tamper?.(rows);
  return rows;
}

const keyA = generateSigningKeyPair();
const keyB = generateSigningKeyPair();
const kA = (status: CheckpointKey["status"] = "active"): CheckpointKey => ({ id: "key-a", public_key_pem: keyA.publicKeyPem, status });
const kB = (status: CheckpointKey["status"] = "active"): CheckpointKey => ({ id: "key-b", public_key_pem: keyB.publicKeyPem, status });

function checkpoints(rows: ChainRow[], counts: number[], opts: { key?: "a" | "b"; keys?: Array<"a" | "b"> } = {}): SignedCheckpoint[] {
  const out: SignedCheckpoint[] = [];
  counts.forEach((count, i) => {
    const which = opts.keys?.[i] ?? opts.key ?? "a";
    const prev = out[out.length - 1] ?? null;
    const payload = buildCheckpointPayload(ORG, rows.slice(0, count), i + 1, prev?.payload_hash ?? null, which === "a" ? "key-a" : "key-b", new Date(T0 + 3_600_000 * (i + 1)));
    out.push(signCheckpoint(payload, which === "a" ? keyA.privateKeyPem : keyB.privateKeyPem));
  });
  return out;
}

describe("checkpoint signatures", () => {
  const rows = chain(5);
  const [cp] = checkpoints(rows, [5]);

  it("verifies under the signing key's public half and nothing else", () => {
    expect(verifyCheckpointSignature(cp, keyA.publicKeyPem)).toBe(true);
    expect(verifyCheckpointSignature(cp, keyB.publicKeyPem)).toBe(false);
  });
  it("fails when the payload is edited, even if the hash is recomputed by the editor but not re-signed", () => {
    const edited = { ...cp, payload: { ...cp.payload, entry_count: 3 } };
    expect(verifyCheckpointSignature(edited, keyA.publicKeyPem)).toBe(false);
  });
  it("fails on garbage instead of throwing", () => {
    expect(verifyCheckpointSignature({ ...cp, signature: "!!!" }, keyA.publicKeyPem)).toBe(false);
    expect(verifyCheckpointSignature(cp, "not a key")).toBe(false);
  });
});

describe("verifying a chain against its checkpoints", () => {
  it("is VALID for an untouched chain, and counts entries added since the last checkpoint", () => {
    const rows = chain(8);
    const v = verifyCheckpointedChain(ORG, rows, checkpoints(rows, [3, 6]), [kA()]);
    expect(v).toMatchObject({ status: "VALID", checkpoints: 2, latest_sequence: 2, unanchored_entries: 2 });
  });

  it("says NO_CHECKPOINTS rather than VALID when there is nothing to compare against", () => {
    const v = verifyCheckpointedChain(ORG, chain(4), [], [kA()]);
    expect(v.status).toBe("NO_CHECKPOINTS");
    expect(v.unanchored_entries).toBe(4);
  });

  it("detects truncation the hash chain cannot see", () => {
    const full = chain(10);
    const cps = checkpoints(full, [4, 10]);
    const truncated = full.slice(0, 7);                       // newest three deleted: still links and recomputes
    expect(verifyCheckpointedChain(ORG, truncated, [], [kA()]).chain.valid).toBe(true);
    const v = verifyCheckpointedChain(ORG, truncated, cps, [kA()]);
    expect(v.status).toBe("TRUNCATED");
    expect(v.problems).toEqual([expect.objectContaining({ sequence: 2, code: "truncated" })]);
  });

  it("detects a committed entry that was replaced by an entry that still hashes correctly (rewritten tail)", () => {
    const full = chain(6);
    const cps = checkpoints(full, [6]);
    const rewritten = chain(6, rows => {                        // an attacker re-chains the last entry with other content
      const r = rows[5], at = r.created_at, payload = { n: 99 };
      r.payload = payload; r.entry_hash = auditEntryHash(r.prev_hash, r.event_type, r.actor_email, payload, at);
    });
    expect(verifyCheckpointedChain(ORG, rewritten, [], [kA()]).chain.valid).toBe(true);
    expect(verifyCheckpointedChain(ORG, rewritten, cps, [kA()]).status).toBe("HISTORY_MODIFIED");
  });

  it("detects a modified historical record (chain content no longer recomputes)", () => {
    const full = chain(6);
    const cps = checkpoints(full, [6]);
    const modified = chain(6, rows => { rows[2].payload = { n: "edited" }; });
    expect(verifyCheckpointedChain(ORG, modified, cps, [kA()]).status).toBe("HISTORY_MODIFIED");
  });

  it("detects a deleted entry in the middle", () => {
    const full = chain(6);
    const cps = checkpoints(full, [6]);
    const v = verifyCheckpointedChain(ORG, full.filter(r => r.id !== 3), cps, [kA()]);
    expect(["TRUNCATED", "HISTORY_MODIFIED"]).toContain(v.status);
  });

  it("flags a forged checkpoint (signed with a key that is not the registered one)", () => {
    const rows = chain(5);
    const forged = checkpoints(rows, [5], { key: "b" }).map(c => ({ ...c, payload: { ...c.payload, key_id: "key-a" } }));
    const v = verifyCheckpointedChain(ORG, rows, forged, [kA()]);
    expect(v.status).toBe("CHECKPOINT_INVALID");
  });

  it("flags a deleted checkpoint (gap in the sequence) and a broken link", () => {
    const rows = chain(9);
    const [c1, c2, c3] = checkpoints(rows, [3, 6, 9]);
    expect(verifyCheckpointedChain(ORG, rows, [c1, c3], [kA()]).problems.map(p => p.code)).toEqual(expect.arrayContaining(["sequence_gap", "link_broken"]));
    expect(verifyCheckpointedChain(ORG, rows, [c2, c3], [kA()]).status).toBe("CHECKPOINT_INVALID");   // the first one is missing
  });

  it("flags a checkpoint that records fewer entries than the one before it", () => {
    const rows = chain(9);
    const [c1] = checkpoints(rows, [6]);
    const payload = buildCheckpointPayload(ORG, rows.slice(0, 3), 2, c1.payload_hash, "key-a", new Date(T0 + 7_200_000));
    const back = signCheckpoint(payload, keyA.privateKeyPem);
    expect(verifyCheckpointedChain(ORG, rows, [c1, back], [kA()]).problems.map(p => p.code)).toContain("went_backwards");
  });

  it("rejects another organisation's checkpoints", () => {
    const rows = chain(4);
    const v = verifyCheckpointedChain("org-2", rows, checkpoints(rows, [4]), [kA()]);
    expect(v.status).toBe("CHECKPOINT_INVALID");
  });
});

describe("key rotation and revocation", () => {
  const rows = chain(8);
  // checkpoint 1 signed by the old key, 2 by the new one
  const cps = checkpoints(rows, [3, 8], { keys: ["a", "b"] });

  it("old checkpoints stay verifiable after their key is retired", () => {
    expect(verifyCheckpointedChain(ORG, rows, cps, [kA("retired"), kB()]).status).toBe("VALID");
  });
  it("a revoked key makes its checkpoints untrusted, not valid", () => {
    const v = verifyCheckpointedChain(ORG, rows, cps, [kA("revoked"), kB()]);
    expect(v.status).toBe("KEY_UNTRUSTED");
    expect(v.problems[0]).toMatchObject({ sequence: 1, code: "key_revoked" });
  });
  it("a checkpoint whose key cannot be found is untrusted", () => {
    expect(verifyCheckpointedChain(ORG, rows, cps, [kB()]).status).toBe("KEY_UNTRUSTED");
  });
  it("truncation outranks an untrusted key in the reported status", () => {
    expect(verifyCheckpointedChain(ORG, rows.slice(0, 5), cps, [kA("revoked"), kB()]).status).toBe("TRUNCATED");
  });
});

describe("createCheckpoint (database-backed)", () => {
  const realEnv = { ...process.env };
  afterEach(() => { process.env = { ...realEnv }; });

  function setup(n: number) {
    process.env.ATTESTATION_SIGNING_KEY = keyA.privateKeyPem;
    delete process.env.AUDIT_CHECKPOINT_SINK_URL;
    return fakeSupabase({ audit_log: chain(n).map(r => ({ ...r, org_id: ORG })), audit_checkpoints: [], signing_keys: [] });
  }
  const table = (db: ReturnType<typeof fakeSupabase>, name: string) => db.tables[name] as Array<Record<string, unknown>>;

  it("signs and stores a checkpoint that verifies, and chains the next one to it", async () => {
    const db = setup(5);
    const first = await createCheckpoint(db.client as never, ORG, new Date(T0 + 1_000_000));
    expect(first).toMatchObject({ created: true, external: "not_configured" });
    expect(table(db, "audit_checkpoints")).toHaveLength(1);
    // two more entries, then a second checkpoint
    const extra = chain(7).slice(5).map(r => ({ ...r, org_id: ORG }));
    table(db, "audit_log").push(...extra);
    const second = await createCheckpoint(db.client as never, ORG, new Date(T0 + 2_000_000));
    expect(second.created).toBe(true);
    const v = await verifyOrgCheckpoints(db.client as never, ORG);
    expect(v).toMatchObject({ status: "VALID", checkpoints: 2, latest_sequence: 2, unanchored_entries: 0 });
  });

  it("does nothing when the chain has not changed", async () => {
    const db = setup(3);
    await createCheckpoint(db.client as never, ORG);
    expect(await createCheckpoint(db.client as never, ORG)).toEqual({ created: false, reason: "unchanged" });
    expect(table(db, "audit_checkpoints")).toHaveLength(1);
  });

  it("refuses to sign after the chain was truncated, instead of blessing the shorter chain", async () => {
    const db = setup(6);
    await createCheckpoint(db.client as never, ORG);
    db.tables.audit_log.splice(4);                                  // delete the newest entries
    expect(await createCheckpoint(db.client as never, ORG)).toEqual({ created: false, reason: "verification_failed", status: "TRUNCATED" });
    expect((await verifyOrgCheckpoints(db.client as never, ORG)).status).toBe("TRUNCATED");
    expect(table(db, "audit_checkpoints")).toHaveLength(1);
  });

  it("refuses to sign a chain that is already broken", async () => {
    const db = setup(5);
    (db.tables.audit_log[2] as { payload: unknown }).payload = { n: "edited" };
    expect(await createCheckpoint(db.client as never, ORG)).toMatchObject({ created: false, reason: "verification_failed", status: "HISTORY_MODIFIED" });
  });

  it("reports no signing key and an empty log without creating anything", async () => {
    const db = setup(2);
    delete process.env.ATTESTATION_SIGNING_KEY;
    expect(await createCheckpoint(db.client as never, ORG)).toEqual({ created: false, reason: "no_signing_key" });
    process.env.ATTESTATION_SIGNING_KEY = keyA.privateKeyPem;
    expect(await createCheckpoint(fakeSupabase({ audit_log: [], audit_checkpoints: [], signing_keys: [] }).client as never, ORG)).toEqual({ created: false, reason: "no_entries" });
  });

  it("pushes the checkpoint to the external sink when one is configured, and never follows redirects", async () => {
    const db = setup(3);
    process.env.AUDIT_CHECKPOINT_SINK_URL = "https://sink.example.com/checkpoints";
    process.env.AUDIT_CHECKPOINT_SINK_TOKEN = "tok";
    const realFetch = global.fetch;
    const fetchMock = jest.fn(async () => new Response("ok", { status: 200 }));
    global.fetch = fetchMock as unknown as typeof fetch;
    try {
      const r = await createCheckpoint(db.client as never, ORG);
      expect(r).toMatchObject({ created: true, external: "delivered" });
      const [url, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
      expect(url).toBe("https://sink.example.com/checkpoints");
      expect(init).toMatchObject({ method: "POST", redirect: "manual" });
      expect((init.headers as Record<string, string>).Authorization).toBe("Bearer tok");
      const body = JSON.parse(init.body as string);
      expect(verifyCheckpointSignature(body.checkpoint, body.public_key.public_key_pem)).toBe(true);
    } finally { global.fetch = realFetch; }
  });

  it("a failing or private sink is reported, not thrown, and the checkpoint is still recorded", async () => {
    const db = setup(3);
    process.env.AUDIT_CHECKPOINT_SINK_URL = "http://127.0.0.1/hook";
    const r = await createCheckpoint(db.client as never, ORG);
    expect(r).toMatchObject({ created: true, external: "failed" });
    expect(table(db, "audit_checkpoints")).toHaveLength(1);
  });

  it("exports a bundle that verifies on its own", async () => {
    const db = setup(4);
    await createCheckpoint(db.client as never, ORG);
    const bundle = await exportAuditBundle(db.client as never, ORG);
    expect(bundle).toMatchObject({ format: "trustledger.audit-bundle", version: 1, org_id: ORG });
    expect(verifyCheckpointedChain(bundle.org_id, bundle.entries, bundle.checkpoints, bundle.keys).status).toBe("VALID");
  });
});
