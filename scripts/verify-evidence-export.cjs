#!/usr/bin/env node
/**
 * Offline verifier for a TrustLedger compliance evidence export (GET /api/evidence/export).
 * Node's built-in crypto only; no network, no TrustLedger code.
 *
 *   node scripts/verify-evidence-export.cjs export.json [trusted-public-key.pem] [--allow-unsigned]
 *
 * It checks two things:
 *   1. the Ed25519 signature covers the whole document (everything except `cryptographic_verification`), so no
 *      record, coverage entry or audit-trail row can be changed after signing;
 *   2. for every record with hash_version 2, its content_hash recomputes from the fields printed next to it.
 *
 * Trust: a document carries its own public key, which proves nothing by itself (a forger signs with their own).
 * Pass the key you obtained from <your-domain>/.well-known/trustledger-export-signing-key as the second argument;
 * the document is rejected if it was signed with a different key.
 *
 * What it does NOT establish: that the evidence is genuine, or that any control is met. It shows the export is
 * intact and was issued by the holder of the key. Records with hash_version 1 cannot be re-derived and are only counted.
 *
 * Exit code 0 = everything checked passed; 1 = a check failed; 2 = usage or parse error.
 */
"use strict";
const crypto = require("crypto");
const fs = require("fs");

function canonicalJson(v) {
  if (v === null || typeof v !== "object") return JSON.stringify(v) === undefined ? "null" : JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(x => (x === undefined ? "null" : canonicalJson(x))).join(",") + "]";
  return "{" + Object.keys(v).filter(k => v[k] !== undefined).sort().map(k => JSON.stringify(k) + ":" + canonicalJson(v[k])).join(",") + "}";
}
const keyId = pem => crypto.createHash("sha256").update(crypto.createPublicKey(pem).export({ type: "spki", format: "der" })).digest("hex").slice(0, 16);

/** Must match canonicalPayload() in src/lib/evidenceRecord.ts. */
function recordHash(orgId, framework, r) {
  const stable = {
    evidence_id: r.evidence_id, org_id: orgId, framework, control_id: r.control_id, evidence_type: r.evidence_type,
    evidence_source: r.evidence_source, collection_timestamp: r.collection_timestamp,
    collector_identity: r.collector_identity, expiration_date: r.expiration_date,
  };
  for (const k of ["repository_id", "commit_sha", "scan_id", "attestation_id"]) if (r[k]) stable[k] = r[k];
  const ordered = {};
  for (const k of Object.keys(stable).sort()) ordered[k] = stable[k];
  return crypto.createHash("sha256").update(JSON.stringify(ordered), "utf8").digest("hex");
}

function verifyExport(doc, trustedPem, allowUnsigned) {
  const problems = [];
  const sig = doc.cryptographic_verification;
  const result = { signature: "none", key_id: null, key_trusted: null, records: 0, hash_checked: 0, hash_legacy: 0, hash_mismatches: [], problems };

  if (!sig || !sig.signature) {
    result.signature = "missing";
    if (!allowUnsigned) problems.push("the document is not signed");
  } else if (sig.algorithm !== "Ed25519") {
    result.signature = "unsupported";
    problems.push(`signature algorithm is "${sig.algorithm}", not Ed25519`);
  } else {
    const { cryptographic_verification, ...signed } = doc;
    try {
      const embeddedId = keyId(sig.public_key_pem);
      result.key_id = embeddedId;
      if (sig.key_id && sig.key_id !== embeddedId) problems.push("the signature's key_id does not match its own public key");
      if (trustedPem) {
        result.key_trusted = keyId(trustedPem) === embeddedId;
        if (!result.key_trusted) problems.push(`signed with key ${embeddedId}, which is not the trusted key ${keyId(trustedPem)}`);
      }
      const ok = crypto.verify(null, Buffer.from(canonicalJson(signed), "utf8"), crypto.createPublicKey(sig.public_key_pem), Buffer.from(sig.signature, "base64"));
      result.signature = ok ? "valid" : "invalid";
      if (!ok) problems.push("the signature does not match the document: it was changed after signing, or the signature is invalid");
    } catch (e) {
      result.signature = "invalid";
      problems.push("the signature or public key could not be read: " + e.message);
    }
  }

  const framework = doc.framework && doc.framework.id;
  for (const r of doc.evidence_records || []) {
    result.records++;
    if (r.hash_version === 2) {
      result.hash_checked++;
      if (recordHash(doc.org_id, framework, r) !== r.content_hash) result.hash_mismatches.push(r.evidence_id);
    } else result.hash_legacy++;
  }
  if (result.hash_mismatches.length) problems.push(`${result.hash_mismatches.length} record(s) whose content_hash does not recompute from their fields`);
  return result;
}

function main(argv) {
  const args = argv.slice(2).filter(a => a !== "--allow-unsigned");
  const allowUnsigned = argv.includes("--allow-unsigned");
  const [file, keyFile] = args;
  if (!file) { console.error("usage: verify-evidence-export.cjs export.json [trusted-public-key.pem] [--allow-unsigned]"); return 2; }
  let doc, trustedPem;
  try { doc = JSON.parse(fs.readFileSync(file, "utf8")); } catch (e) { console.error("cannot read export: " + e.message); return 2; }
  if (!doc || !Array.isArray(doc.evidence_records) || !doc.framework) { console.error("not a TrustLedger evidence export"); return 2; }
  if (keyFile) { try { trustedPem = fs.readFileSync(keyFile, "utf8"); keyId(trustedPem); } catch (e) { console.error("cannot read trusted key: " + e.message); return 2; } }
  const result = verifyExport(doc, trustedPem, allowUnsigned);
  result.note = "This shows the export is intact and who signed it. It does not show the evidence is genuine or that any control is met.";
  if (result.signature === "valid" && !trustedPem) result.note += " The signing key was NOT checked against a trusted copy: pass the key published at /.well-known/trustledger-export-signing-key.";
  console.log(JSON.stringify(result, null, 2));
  return result.problems.length === 0 ? 0 : 1;
}

if (require.main === module) process.exit(main(process.argv));
module.exports = { verifyExport, recordHash, canonicalJson };
