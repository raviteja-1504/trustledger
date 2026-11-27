#!/usr/bin/env node
/**
 * Independent verifier for a TrustLedger audit bundle (GET /api/audit/checkpoints?bundle=1).
 *
 * Uses only Node's built-in crypto. It shares no code with the application, so a bundle can be checked without
 * trusting it. Usage:
 *
 *   node scripts/verify-audit-bundle.cjs bundle.json [--keys keys.json] [--checkpoints external.json]
 *
 *   --keys         public keys you obtained from TrustLedger out of band: [{ "id", "public_key_pem", "status" }].
 *                  Without it the keys inside the bundle are used, which only proves the bundle is self-consistent:
 *                  whoever could edit the bundle could swap the keys too.
 *   --checkpoints  checkpoints you stored outside TrustLedger's database (the external sink, or an earlier export):
 *                  a list of { payload, payload_hash, signature } (or sink bodies with a "checkpoint" field).
 *                  They replace the bundle's own, which is what detects a rewrite of the database itself.
 *
 * Exit code 0 only for status VALID; 1 for any finding; 2 for bad usage. The output is JSON.
 * Checkpoints cover the chain only up to their entry_count: newer entries are reported as unanchored.
 */
"use strict";
const crypto = require("crypto");
const fs = require("fs");

function canonicalJson(v) {
  if (v === null || typeof v !== "object") return JSON.stringify(v) === undefined ? "null" : JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(x => (x === undefined ? "null" : canonicalJson(x))).join(",") + "]";
  return "{" + Object.keys(v).filter(k => v[k] !== undefined).sort().map(k => JSON.stringify(k) + ":" + canonicalJson(v[k])).join(",") + "}";
}
const sha256 = s => crypto.createHash("sha256").update(s).digest("hex");
const entryHash = (prev, type, actor, payload, iso) =>
  sha256(`${prev == null ? "GENESIS" : prev}::${type}::${actor == null ? "system" : actor}::${canonicalJson(payload == null ? {} : payload)}::${iso}`);

// Hash v2 (src/lib/audit.ts auditEntryHashV2): also covers org_id, actor_id, resource_type and resource_id. A "" resource
// (how a CSV writes null) is null.
const nul = v => (v == null || v === "" ? null : v);
const entryHashV2 = (r, orgId, iso) => sha256("tl-audit-v2:" + canonicalJson([
  nul(r.prev_hash), orgId, r.event_type, nul(r.actor_id), r.actor_email == null ? "system" : r.actor_email,
  nul(r.resource_type), nul(r.resource_id), r.payload == null ? {} : r.payload, iso,
]));

function checkChain(rows, orgId) {
  const seen = new Set(), parents = new Set(), forkIds = [], forkSet = new Set(), reviewedSet = new Set();
  let recomputable = false, seenV2 = false;
  for (let i = 0; i < rows.length; i++) {
    const r = rows[i];
    if (i > 0 || r.prev_hash != null) {
      if (r.prev_hash == null || !seen.has(r.prev_hash)) return { valid: false, broken_at: r.id, reason: "missing_link" };
    }
    if (r.prev_hash != null) { if (parents.has(r.prev_hash)) { forkIds.push(r.id); forkSet.add(r.id); } parents.add(r.prev_hash); }
    const at = Number.isNaN(Date.parse(r.created_at)) ? r.created_at : new Date(r.created_at).toISOString();
    if (orgId != null && entryHashV2(r, orgId, at) === r.entry_hash) { recomputable = true; seenV2 = true; }
    else if (entryHash(r.prev_hash, r.event_type, r.actor_email, r.payload, at) === r.entry_hash) {
      if (seenV2) return { valid: false, broken_at: r.id, reason: "downgraded" };   // old format after the new one: re-hashed to hide a change
      recomputable = true;
    }
    else if (recomputable) return { valid: false, broken_at: r.id, reason: "content_changed" };
    // An "audit_forks_reviewed" entry covers the forks it names that came BEFORE it.
    if (r.event_type === "audit_forks_reviewed" && r.payload && Array.isArray(r.payload.fork_entry_ids)) {
      for (const id of r.payload.fork_entry_ids) if (typeof id === "number" && id < r.id && forkSet.has(id)) reviewedSet.add(id);
    }
    seen.add(r.entry_hash);
  }
  const unreviewed = forkIds.filter(id => !reviewedSet.has(id));
  return unreviewed.length === 0 ? { valid: true, reviewed_forks: forkIds.length } : { valid: false, forked: true, fork_at: unreviewed[0], unreviewed_forks: unreviewed.length };
}

function signatureOk(cp, pem) {
  try {
    if (sha256(canonicalJson(cp.payload)) !== cp.payload_hash) return false;
    return crypto.verify(null, Buffer.from(cp.payload_hash, "utf8"), { key: pem, format: "pem" }, Buffer.from(cp.signature, "base64"));
  } catch { return false; }
}

function verify(orgId, rows, checkpoints, keys) {
  const chain = checkChain(rows, orgId);
  const problems = [];
  const keyById = new Map(keys.map(k => [k.id, k]));
  const sorted = [...checkpoints].sort((a, b) => a.payload.sequence - b.payload.sequence);
  const flag = { invalid: false, untrusted: false, truncated: false, modified: !chain.valid && !chain.forked, forked: !!chain.forked };
  if (chain.forked) problems.push({ sequence: null, code: "chain_forked", detail: "an audit entry shares its parent with an earlier one, from entry " + chain.fork_at });
  else if (!chain.valid) problems.push({ sequence: null, code: "chain_" + chain.reason, detail: "audit chain failed at entry " + chain.broken_at });
  let prev = null;
  for (const cp of sorted) {
    const p = cp.payload, seq = p.sequence;
    if (p.org_id !== orgId) { flag.invalid = true; problems.push({ sequence: seq, code: "wrong_org", detail: "checkpoint belongs to another organisation" }); continue; }
    const key = keyById.get(p.key_id);
    if (!key) { flag.untrusted = true; problems.push({ sequence: seq, code: "key_unavailable", detail: "no public key for " + p.key_id }); }
    else if (key.status === "revoked") { flag.untrusted = true; problems.push({ sequence: seq, code: "key_revoked", detail: "signing key " + key.id + " was revoked" }); }
    else if (!signatureOk(cp, key.public_key_pem)) { flag.invalid = true; problems.push({ sequence: seq, code: "bad_signature", detail: "signature or payload hash does not verify" }); }
    const expected = prev ? prev.payload.sequence + 1 : 1;
    if (seq !== expected) { flag.invalid = true; problems.push({ sequence: seq, code: "sequence_gap", detail: "expected sequence " + expected }); }
    if ((prev ? prev.payload_hash : null) !== p.prev_checkpoint_hash) { flag.invalid = true; problems.push({ sequence: seq, code: "link_broken", detail: "does not chain to the previous checkpoint" }); }
    if (prev && (p.entry_count < prev.payload.entry_count || p.last_entry_id < prev.payload.last_entry_id)) {
      flag.invalid = true; problems.push({ sequence: seq, code: "went_backwards", detail: "records fewer entries than the checkpoint before it" });
    }
    if (rows.length < p.entry_count) {
      flag.truncated = true;
      problems.push({ sequence: seq, code: "truncated", detail: "chain holds " + rows.length + " entries, checkpoint recorded " + p.entry_count });
    } else {
      const at = rows[p.entry_count - 1];
      if (at.id !== p.last_entry_id || at.entry_hash !== p.last_entry_hash || rows[0].entry_hash !== p.first_entry_hash) {
        flag.modified = true;
        problems.push({ sequence: seq, code: "history_modified", detail: "entry " + p.entry_count + " no longer matches what was committed" });
      }
    }
    prev = cp;
  }
  const status = flag.invalid ? "CHECKPOINT_INVALID" : flag.truncated ? "TRUNCATED" : flag.modified ? "HISTORY_MODIFIED"
    : flag.forked ? "CHAIN_FORKED" : flag.untrusted ? "KEY_UNTRUSTED" : sorted.length === 0 ? "NO_CHECKPOINTS" : "VALID";
  const latest = sorted.length ? sorted[sorted.length - 1].payload : null;
  return {
    status, entries: rows.length, checkpoints: sorted.length, latest_sequence: latest ? latest.sequence : null,
    unanchored_entries: latest ? Math.max(0, rows.length - latest.entry_count) : rows.length, problems,
  };
}

function main(argv) {
  const args = argv.slice(2);
  const opt = name => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined; };
  const file = args.find((a, i) => !a.startsWith("--") && (i === 0 || !args[i - 1].startsWith("--")));
  if (!file) { console.error("usage: verify-audit-bundle.cjs bundle.json [--keys keys.json] [--checkpoints external.json]"); return 2; }
  const read = f => JSON.parse(fs.readFileSync(f, "utf8"));
  let bundle;
  try { bundle = read(file); } catch (e) { console.error("cannot read bundle: " + e.message); return 2; }
  if (!bundle || bundle.format !== "trustledger.audit-bundle" || bundle.version !== 1) { console.error("not a TrustLedger audit bundle (version 1)"); return 2; }
  let keys = bundle.keys, checkpoints = bundle.checkpoints;
  try {
    if (opt("--keys")) keys = read(opt("--keys"));
    if (opt("--checkpoints")) checkpoints = read(opt("--checkpoints")).map(c => (c && c.checkpoint ? c.checkpoint : c));
  } catch (e) { console.error("cannot read option file: " + e.message); return 2; }
  const result = verify(bundle.org_id, bundle.entries, checkpoints, keys);
  result.keys_source = opt("--keys") ? "pinned (--keys)" : "bundle";
  result.checkpoints_source = opt("--checkpoints") ? "external (--checkpoints)" : "bundle";
  console.log(JSON.stringify(result, null, 2));
  return result.status === "VALID" ? 0 : 1;
}

if (require.main === module) process.exit(main(process.argv));
module.exports = { verify, checkChain, canonicalJson };
