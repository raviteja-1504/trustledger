/**
 * Signed audit checkpoints (Task 11): independently verifiable evidence that the audit chain has not been
 * truncated or rewritten.
 *
 * A hash chain alone cannot show that its NEWEST entries were deleted: what is left still links and recomputes.
 * A checkpoint is a signed statement made earlier: "this org's chain held `entry_count` entries, the last with
 * hash H". Verification fails when fewer entries remain (TRUNCATED) or when entry number `entry_count` is no
 * longer H (HISTORY_MODIFIED). Checkpoints chain to each other through prev_checkpoint_hash, so deleting or
 * reordering one is visible too.
 *
 * What this does and does not guarantee:
 *  - Verification needs only the public key and the data (scripts/verify-audit-bundle.cjs uses nothing else).
 *  - The checkpoints table is append-only by database rule, but whoever owns the database can drop the rules and
 *    delete checkpoints together with audit rows. A rewrite is only detectable against checkpoints held somewhere
 *    that person cannot change: the external sink (AUDIT_CHECKPOINT_SINK_URL) or an export kept elsewhere. This
 *    module does not make storage immutable and must not be described as doing so.
 *  - Entries written after the newest checkpoint are not covered (reported as unanchored_entries).
 *  - Key rotation: a retired key still verifies its old checkpoints. A revoked key's checkpoints are untrusted.
 */
import crypto from "crypto";
import type { SupabaseClient } from "@supabase/supabase-js";
import { canonicalJson, checkAuditChain, loadAuditRows, type ChainRow, type ChainVerification } from "./audit";
import { ensureSigningKey } from "./attestationSigning";
import { isPublicHttpUrl } from "./outboundUrl";

export const CHECKPOINT_SCHEMA_VERSION = 1 as const;

export interface CheckpointPayload {
  schema_version:       typeof CHECKPOINT_SCHEMA_VERSION;
  org_id:               string;
  /** 1, 2, 3 ... per org, no gaps. */
  sequence:             number;
  /** Number of audit entries the chain held (counted in id order). */
  entry_count:          number;
  last_entry_id:        number;
  last_entry_hash:      string;
  first_entry_hash:     string;
  prev_checkpoint_hash: string | null;
  created_at:           string;
  /** signing_keys row that signed this checkpoint. */
  key_id:               string;
}

export interface SignedCheckpoint {
  payload:      CheckpointPayload;
  /** sha256 hex of canonicalJson(payload). */
  payload_hash: string;
  /** base64 Ed25519 signature over payload_hash (its UTF-8 bytes). */
  signature:    string;
}

export interface CheckpointKey {
  id:             string;
  public_key_pem: string;
  status:         "active" | "retired" | "revoked";
}

export function checkpointHash(payload: CheckpointPayload): string {
  return crypto.createHash("sha256").update(canonicalJson(payload)).digest("hex");
}

export function signCheckpoint(payload: CheckpointPayload, privateKeyPem: string): SignedCheckpoint {
  const payload_hash = checkpointHash(payload);
  const signature = crypto.sign(null, Buffer.from(payload_hash, "utf8"), { key: privateKeyPem, format: "pem" }).toString("base64");
  return { payload, payload_hash, signature };
}

/** True only if the stored hash matches the payload AND the signature is valid for it under this public key. */
export function verifyCheckpointSignature(cp: SignedCheckpoint, publicKeyPem: string): boolean {
  try {
    if (checkpointHash(cp.payload) !== cp.payload_hash) return false;
    return crypto.verify(null, Buffer.from(cp.payload_hash, "utf8"), { key: publicKeyPem, format: "pem" }, Buffer.from(cp.signature, "base64"));
  } catch {
    return false;
  }
}

export function buildCheckpointPayload(
  orgId: string, rows: readonly ChainRow[], sequence: number, prevCheckpointHash: string | null, keyId: string, now: Date,
): CheckpointPayload {
  const last = rows[rows.length - 1];
  return {
    schema_version: CHECKPOINT_SCHEMA_VERSION, org_id: orgId, sequence,
    entry_count: rows.length, last_entry_id: last.id, last_entry_hash: last.entry_hash, first_entry_hash: rows[0].entry_hash,
    prev_checkpoint_hash: prevCheckpointHash, created_at: now.toISOString(), key_id: keyId,
  };
}

// ── Verification (pure: usable on a database read or on an exported bundle) ───────────────────────────────

export type CheckpointStatus =
  | "VALID"              // every checkpoint verifies and the chain still contains what each one committed to
  | "NO_CHECKPOINTS"     // nothing to compare against: the chain's own links are all that was checked
  | "TRUNCATED"          // fewer entries remain than a checkpoint recorded
  | "HISTORY_MODIFIED"   // a committed entry changed, or the chain itself no longer verifies
  | "CHECKPOINT_INVALID" // bad signature or hash, a gap or reorder in the checkpoint sequence, or the wrong org
  | "KEY_UNTRUSTED";     // signed by a revoked key, or by a key that is not available to verify with

export interface CheckpointProblem { sequence: number | null; code: string; detail: string }

export interface CheckpointVerification {
  status:             CheckpointStatus;
  checkpoints:        number;
  latest_sequence:    number | null;
  latest_at:          string | null;
  /** Entries newer than the latest checkpoint: intact as far as the chain goes, but not yet anchored. */
  unanchored_entries: number;
  chain:              ChainVerification;
  problems:           CheckpointProblem[];
}

export function verifyCheckpointedChain(
  orgId: string, rows: readonly ChainRow[], checkpoints: readonly SignedCheckpoint[], keys: readonly CheckpointKey[],
): CheckpointVerification {
  const chain = checkAuditChain(rows);
  const problems: CheckpointProblem[] = [];
  const keyById = new Map(keys.map(k => [k.id, k]));
  const sorted = [...checkpoints].sort((a, b) => a.payload.sequence - b.payload.sequence);
  const flags = { invalid: false, untrusted: false, truncated: false, modified: !chain.valid };
  if (!chain.valid) problems.push({ sequence: null, code: "chain_" + (chain.reason ?? "invalid"), detail: `audit chain failed at entry ${chain.broken_at ?? "?"}` });

  let prev: SignedCheckpoint | null = null;
  for (const cp of sorted) {
    const p = cp.payload, seq = p.sequence;
    if (p.org_id !== orgId) { flags.invalid = true; problems.push({ sequence: seq, code: "wrong_org", detail: "checkpoint belongs to another organisation" }); continue; }
    const key = keyById.get(p.key_id);
    if (!key) { flags.untrusted = true; problems.push({ sequence: seq, code: "key_unavailable", detail: `no public key for ${p.key_id}` }); }
    else if (key.status === "revoked") { flags.untrusted = true; problems.push({ sequence: seq, code: "key_revoked", detail: `signing key ${key.id} was revoked` }); }
    else if (!verifyCheckpointSignature(cp, key.public_key_pem)) { flags.invalid = true; problems.push({ sequence: seq, code: "bad_signature", detail: "signature or payload hash does not verify" }); }

    const expectedSeq = prev ? prev.payload.sequence + 1 : 1;
    if (seq !== expectedSeq) { flags.invalid = true; problems.push({ sequence: seq, code: "sequence_gap", detail: `expected sequence ${expectedSeq}` }); }
    if ((prev?.payload_hash ?? null) !== p.prev_checkpoint_hash) { flags.invalid = true; problems.push({ sequence: seq, code: "link_broken", detail: "does not chain to the previous checkpoint" }); }
    if (prev && (p.entry_count < prev.payload.entry_count || p.last_entry_id < prev.payload.last_entry_id)) {
      flags.invalid = true; problems.push({ sequence: seq, code: "went_backwards", detail: "records fewer entries than the checkpoint before it" });
    }

    if (rows.length < p.entry_count) {
      flags.truncated = true;
      problems.push({ sequence: seq, code: "truncated", detail: `chain holds ${rows.length} entries, checkpoint recorded ${p.entry_count}` });
    } else {
      const at = rows[p.entry_count - 1];
      if (at.id !== p.last_entry_id || at.entry_hash !== p.last_entry_hash || rows[0].entry_hash !== p.first_entry_hash) {
        flags.modified = true;
        problems.push({ sequence: seq, code: "history_modified", detail: `entry ${p.entry_count} no longer matches what was committed` });
      }
    }
    prev = cp;
  }

  const status: CheckpointStatus =
    flags.invalid ? "CHECKPOINT_INVALID"
    : flags.truncated ? "TRUNCATED"
    : flags.modified ? "HISTORY_MODIFIED"
    : flags.untrusted ? "KEY_UNTRUSTED"
    : sorted.length === 0 ? "NO_CHECKPOINTS" : "VALID";
  const latest = sorted[sorted.length - 1]?.payload ?? null;
  return {
    status, checkpoints: sorted.length, latest_sequence: latest?.sequence ?? null, latest_at: latest?.created_at ?? null,
    unanchored_entries: latest ? Math.max(0, rows.length - latest.entry_count) : rows.length, chain, problems,
  };
}

// ── Database-backed operations ─────────────────────────────────────────────────────────────────────────────

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Db = SupabaseClient<any>;

interface CheckpointRow { sequence: number; payload: CheckpointPayload; payload_hash: string; signature: string }
const toSigned = (r: CheckpointRow): SignedCheckpoint => ({ payload: r.payload, payload_hash: r.payload_hash, signature: r.signature });

export async function loadCheckpoints(db: Db, orgId: string): Promise<SignedCheckpoint[]> {
  const out: SignedCheckpoint[] = [];
  for (let from = 0; from < 100_000; from += 1000) {
    const { data, error } = await db.from("audit_checkpoints").select("sequence, payload, payload_hash, signature")
      .eq("org_id", orgId).order("sequence", { ascending: true }).range(from, from + 999) as { data: CheckpointRow[] | null; error: unknown };
    if (error) throw error;
    out.push(...(data ?? []).map(toSigned));
    if (!data || data.length < 1000) break;
  }
  return out;
}

/** Public keys for the given ids, retired and revoked ones included (old checkpoints must stay verifiable). */
export async function loadCheckpointKeys(db: Db, keyIds: readonly string[]): Promise<CheckpointKey[]> {
  const ids = [...new Set(keyIds)];
  if (ids.length === 0) return [];
  const { data, error } = await db.from("signing_keys").select("id, public_key_pem, status").in("id", ids) as { data: CheckpointKey[] | null; error: unknown };
  if (error) throw error;
  return data ?? [];
}

/** Load everything and verify. Throws if the database cannot be read, so a failed read is never reported as "valid". */
export async function verifyOrgCheckpoints(db: Db, orgId: string): Promise<CheckpointVerification> {
  const { rows, complete } = await loadAuditRows(db, orgId);
  if (!complete) throw new Error("audit_unreadable");
  const checkpoints = await loadCheckpoints(db, orgId);
  const keys = await loadCheckpointKeys(db, checkpoints.map(c => c.payload.key_id));
  return verifyCheckpointedChain(orgId, rows, checkpoints, keys);
}

export type CreateCheckpointResult =
  | { created: true; checkpoint: SignedCheckpoint; external: "delivered" | "failed" | "not_configured" }
  | { created: false; reason: "no_signing_key" | "no_entries" | "unchanged" | "audit_unreadable" | "verification_failed" | "conflict"; status?: CheckpointStatus };

/**
 * Record a checkpoint of the org's audit chain now, unless nothing changed since the last one. Refuses to sign when
 * the chain or the earlier checkpoints already fail verification: a new signature must not bless a broken state.
 */
export async function createCheckpoint(db: Db, orgId: string, now = new Date()): Promise<CreateCheckpointResult> {
  const key = await ensureSigningKey(db);
  if (!key) return { created: false, reason: "no_signing_key" };
  const { rows, complete } = await loadAuditRows(db, orgId);
  if (!complete) return { created: false, reason: "audit_unreadable" };
  if (rows.length === 0) return { created: false, reason: "no_entries" };

  const existing = await loadCheckpoints(db, orgId);
  const keys = await loadCheckpointKeys(db, existing.map(c => c.payload.key_id));
  const before = verifyCheckpointedChain(orgId, rows, existing, keys);
  if (before.status !== "VALID" && before.status !== "NO_CHECKPOINTS") return { created: false, reason: "verification_failed", status: before.status };
  if (before.status === "VALID" && before.unanchored_entries === 0) return { created: false, reason: "unchanged" };

  const last = existing[existing.length - 1];
  const payload = buildCheckpointPayload(orgId, rows, (last?.payload.sequence ?? 0) + 1, last?.payload_hash ?? null, key.id, now);
  const signed = signCheckpoint(payload, key.privateKeyPem);
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const { error } = await (db.from("audit_checkpoints") as any).insert({
    org_id: orgId, sequence: payload.sequence, entry_count: payload.entry_count, last_entry_id: payload.last_entry_id,
    payload, payload_hash: signed.payload_hash, signature: signed.signature, key_id: key.id, created_at: payload.created_at,
  });
  if (error) return { created: false, reason: "conflict" };   // a concurrent run took this sequence number
  const external = await publishCheckpoint(signed, await publicKeyOf(db, key.id));
  return { created: true, checkpoint: signed, external };
}

async function publicKeyOf(db: Db, keyId: string): Promise<CheckpointKey | null> {
  return (await loadCheckpointKeys(db, [keyId]))[0] ?? null;
}

/**
 * Push a signed checkpoint to the operator's external store (AUDIT_CHECKPOINT_SINK_URL, optional bearer token in
 * AUDIT_CHECKPOINT_SINK_TOKEN). The store is what makes a database-level rewrite detectable: use one the database
 * owner cannot change (write-once / object-lock storage behind the endpoint). Best-effort: a failure is reported,
 * never thrown, and the checkpoint remains recorded in the database.
 */
export async function publishCheckpoint(cp: SignedCheckpoint, key: CheckpointKey | null): Promise<"delivered" | "failed" | "not_configured"> {
  const url = (process.env.AUDIT_CHECKPOINT_SINK_URL ?? "").trim();
  if (!url) return "not_configured";
  if (!isPublicHttpUrl(url)) return "failed";
  const token = (process.env.AUDIT_CHECKPOINT_SINK_TOKEN ?? "").trim();
  try {
    const res = await fetch(url, {
      method: "POST",
      redirect: "manual",   // never follow a redirect off the vetted public URL (see outboundUrl.ts)
      headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) },
      body: JSON.stringify({ type: "trustledger.audit_checkpoint", checkpoint: cp, public_key: key }),
    });
    return res.ok ? "delivered" : "failed";
  } catch {
    return "failed";
  }
}

export interface AuditBundle {
  format:      "trustledger.audit-bundle";
  version:     1;
  org_id:      string;
  exported_at: string;
  checkpoints: SignedCheckpoint[];
  keys:        CheckpointKey[];
  entries:     ChainRow[];
}

/** Everything an outside party needs to verify the org's audit chain without trusting this application. */
export async function exportAuditBundle(db: Db, orgId: string, now = new Date()): Promise<AuditBundle> {
  const { rows, complete } = await loadAuditRows(db, orgId);
  if (!complete) throw new Error("audit_unreadable");
  const checkpoints = await loadCheckpoints(db, orgId);
  const keys = await loadCheckpointKeys(db, checkpoints.map(c => c.payload.key_id));
  return { format: "trustledger.audit-bundle", version: 1, org_id: orgId, exported_at: now.toISOString(), checkpoints, keys, entries: rows };
}
