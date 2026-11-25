/**
 * @jest-environment node
 *
 * scripts/verify-audit-bundle.cjs is the independent verifier: it shares no code with the app. These tests keep it
 * in lockstep with lib/auditCheckpoint.ts (same scenarios, same verdicts) and exercise the real command line.
 */
import fs from "fs";
import os from "os";
import path from "path";
import { spawnSync } from "child_process";
import { auditEntryHash, type ChainRow } from "@/lib/audit";
import { generateSigningKeyPair } from "@/lib/attestationSigning";
import {
  buildCheckpointPayload, signCheckpoint, verifyCheckpointedChain, type CheckpointKey, type SignedCheckpoint, type AuditBundle,
} from "@/lib/auditCheckpoint";

// eslint-disable-next-line @typescript-eslint/no-var-requires
const script = require("../../../scripts/verify-audit-bundle.cjs") as {
  verify: (org: string, rows: ChainRow[], cps: SignedCheckpoint[], keys: CheckpointKey[]) => { status: string; problems: Array<{ code: string }>; unanchored_entries: number };
};
const SCRIPT = path.join(__dirname, "../../../scripts/verify-audit-bundle.cjs");

const ORG = "org-1";
const T0 = Date.parse("2026-11-01T00:00:00.000Z");
const key = generateSigningKeyPair();
const otherKey = generateSigningKeyPair();
const keyRow = (status: CheckpointKey["status"] = "active"): CheckpointKey => ({ id: "key-1", public_key_pem: key.publicKeyPem, status });

function chain(n: number, edit?: (rows: ChainRow[]) => void): ChainRow[] {
  const rows: ChainRow[] = [];
  let prev: string | null = null;
  for (let i = 1; i <= n; i++) {
    const at = new Date(T0 + i * 60_000).toISOString();
    const payload = { n: i, nested: { b: 2, a: [1, null, "x"] } };
    const h = auditEntryHash(prev, "attestation", i % 2 ? "a@x.dev" : null, payload, at);
    rows.push({ id: i * 2, event_type: "attestation", actor_email: i % 2 ? "a@x.dev" : null, payload, prev_hash: prev, entry_hash: h, created_at: at });
    prev = h;
  }
  edit?.(rows);
  return rows;
}
function cps(rows: ChainRow[], counts: number[], priv = key.privateKeyPem): SignedCheckpoint[] {
  const out: SignedCheckpoint[] = [];
  counts.forEach((c, i) => out.push(signCheckpoint(buildCheckpointPayload(ORG, rows.slice(0, c), i + 1, out[i - 1]?.payload_hash ?? null, "key-1", new Date(T0 + 3_600_000 * (i + 1))), priv)));
  return out;
}

const full = chain(9);
const scenarios: Array<[string, ChainRow[], SignedCheckpoint[], CheckpointKey[]]> = [
  ["valid", full, cps(full, [3, 9]), [keyRow()]],
  ["valid with unanchored tail", full, cps(full, [3, 6]), [keyRow()]],
  ["no checkpoints", full, [], [keyRow()]],
  ["truncated", full.slice(0, 5), cps(full, [3, 9]), [keyRow()]],
  ["rewritten tail", chain(9, r => { r[8].payload = { n: "x" }; r[8].entry_hash = auditEntryHash(r[8].prev_hash, r[8].event_type, r[8].actor_email, r[8].payload, r[8].created_at); }), cps(full, [9]), [keyRow()]],
  ["modified middle", chain(9, r => { r[4].payload = { n: "edited" }; }), cps(full, [9]), [keyRow()]],
  ["forged signature", full, cps(full, [9], otherKey.privateKeyPem), [keyRow()]],
  ["checkpoint gap", full, cps(full, [3, 6, 9]).filter(c => c.payload.sequence !== 2), [keyRow()]],
  ["revoked key", full, cps(full, [9]), [keyRow("revoked")]],
  ["retired key", full, cps(full, [9]), [keyRow("retired")]],
  ["unknown key", full, cps(full, [9]), []],
];

describe("the standalone verifier agrees with the library", () => {
  it.each(scenarios)("%s", (_name, rows, checkpoints, keys) => {
    const lib = verifyCheckpointedChain(ORG, rows, checkpoints, keys);
    const out = script.verify(ORG, rows, checkpoints, keys);
    expect(out.status).toBe(lib.status);
    expect(out.problems.map(p => p.code).sort()).toEqual(lib.problems.map(p => p.code).sort());
    expect(out.unanchored_entries).toBe(lib.unanchored_entries);
  });
});

describe("command line", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "audit-bundle-"));
  afterAll(() => fs.rmSync(dir, { recursive: true, force: true }));
  const write = (name: string, v: unknown) => { const f = path.join(dir, name); fs.writeFileSync(f, JSON.stringify(v)); return f; };
  const bundle = (rows: ChainRow[], checkpoints: SignedCheckpoint[], keys = [keyRow()]): AuditBundle =>
    ({ format: "trustledger.audit-bundle", version: 1, org_id: ORG, exported_at: new Date(T0).toISOString(), checkpoints, keys, entries: rows });
  const run = (...args: string[]) => {
    const r = spawnSync(process.execPath, [SCRIPT, ...args], { encoding: "utf8" });
    return { code: r.status, out: r.stdout ? JSON.parse(r.stdout) : null, err: r.stderr };
  };

  it("exits 0 and says VALID for an intact bundle", () => {
    const r = run(write("ok.json", bundle(full, cps(full, [4, 9]))));
    expect(r.code).toBe(0);
    expect(r.out).toMatchObject({ status: "VALID", checkpoints: 2, entries: 9, unanchored_entries: 0, keys_source: "bundle" });
  });

  it("exits 1 for a truncated chain", () => {
    const r = run(write("trunc.json", bundle(full.slice(0, 6), cps(full, [9]))));
    expect(r.code).toBe(1);
    expect(r.out.status).toBe("TRUNCATED");
  });

  it("catches a rewrite of the database only when checked against checkpoints held elsewhere", () => {
    // An attacker with database access deletes the newest entries AND the checkpoints that covered them.
    const honest = cps(full, [4, 9]);
    const tampered = bundle(full.slice(0, 4), cps(full, [4]));
    expect(run(write("tampered.json", tampered)).out.status).toBe("VALID");                   // self-consistent: nothing to see
    const external = run(write("tampered2.json", tampered), "--checkpoints", write("external.json", honest.map(c => ({ checkpoint: c }))));
    expect(external.code).toBe(1);
    expect(external.out).toMatchObject({ status: "TRUNCATED", checkpoints_source: "external (--checkpoints)" });
  });

  it("with keys pinned out of band, a bundle that swapped in its own key is rejected", () => {
    const attackerRows = full;
    const forged = cps(attackerRows, [9], otherKey.privateKeyPem);
    const swapped = bundle(attackerRows, forged, [{ id: "key-1", public_key_pem: otherKey.publicKeyPem, status: "active" }]);
    const file = write("swapped.json", swapped);
    expect(run(file).out.status).toBe("VALID");                                                 // trusts the bundle's own key
    const pinned = run(file, "--keys", write("pinned.json", [keyRow()]));
    expect(pinned.code).toBe(1);
    expect(pinned.out).toMatchObject({ status: "CHECKPOINT_INVALID", keys_source: "pinned (--keys)" });
  });

  it("exits 2 with a message for bad usage", () => {
    expect(run().code).toBe(2);
    expect(run(write("notabundle.json", { hello: 1 })).code).toBe(2);
    expect(run(path.join(dir, "missing.json")).code).toBe(2);
  });
});
