#!/usr/bin/env node
/**
 * Offline verifier for a TrustLedger signed document (Trust Record, or a signed audit-log export in JSON form).
 * Pure Node, no dependencies, no network needed.
 *
 *   node verify-trust-record.mjs <document.json> [trusted-public-key.pem]
 *
 * Without a key file, it self-verifies the signature and prints the key id for you to compare, by eye, against
 * the key published at <your-domain>/.well-known/trustledger-export-signing-key.
 * With a trusted-public-key.pem (recommended), it ALSO requires the document's key to match that file, so a
 * document signed with a stranger's key is rejected.
 *
 * Exit code 0 = verified, 1 = failed or key mismatch, 2 = usage/parse error.
 */
import { readFileSync } from "node:fs";
import { createPublicKey, createHash, verify } from "node:crypto";

/** Canonical JSON: object keys sorted at every level, no whitespace. Must match src/lib/trustRecord.ts. */
function canonical(v) {
  if (v === null || typeof v !== "object") return JSON.stringify(v) ?? "null";
  if (Array.isArray(v)) return "[" + v.map(canonical).join(",") + "]";
  return "{" + Object.keys(v).filter(k => v[k] !== undefined).sort().map(k => JSON.stringify(k) + ":" + canonical(v[k])).join(",") + "}";
}
function keyId(pem) {
  const der = createPublicKey(pem).export({ type: "spki", format: "der" });
  return createHash("sha256").update(der).digest("hex").slice(0, 16);
}
function fail(msg, code = 1) { console.error("FAILED: " + msg); process.exit(code); }

const [docPath, trustedKeyPath] = process.argv.slice(2);
if (!docPath) { console.error("Usage: node verify-trust-record.mjs <document.json> [trusted-public-key.pem]"); process.exit(2); }

let doc;
try { doc = JSON.parse(readFileSync(docPath, "utf8")); } catch (e) { fail("could not read or parse " + docPath + ": " + e.message, 2); }

// A Trust Record is { record, signature }; a signed audit export puts the same fields under `integrity`.
const sig = doc.signature ?? doc.integrity;
const signedObject = doc.record ?? (doc.integrity ? { ...doc } : null);
if (!sig) fail("no signature found in the document", 2);
const algo = sig.algorithm ?? sig.signature_algo;

if (algo !== "Ed25519") {
  fail(`signature algorithm is "${algo}", not Ed25519. HMAC-SHA256 documents can only be checked by the issuing server (they use a shared secret).`, 2);
}

// For a Trust Record we sign `record`; for an audit export we sign a fixed field object. Only the Trust Record
// is self-contained enough to re-canonicalise offline here.
if (!doc.record) fail("this looks like an audit-log export; re-canonicalising its signed content offline is not supported by this script. Verify it on the issuing server, or use the Trust Record.", 2);

const message = Buffer.from(canonical(doc.record), "utf8");
const signature = Buffer.from(sig.value ?? "", "base64");
const pem = sig.public_key_pem;
if (!pem) fail("the signature has no embedded public_key_pem", 2);

const embeddedId = keyId(pem);
if (sig.key_id && sig.key_id !== embeddedId) fail(`the signature's key_id (${sig.key_id}) does not match its own public key (${embeddedId}) -- the document is inconsistent.`);

if (trustedKeyPath) {
  let trustedPem;
  try { trustedPem = readFileSync(trustedKeyPath, "utf8"); } catch (e) { fail("could not read trusted key " + trustedKeyPath + ": " + e.message, 2); }
  if (keyId(trustedPem) !== embeddedId) fail(`the document was signed with key ${embeddedId}, which is NOT the trusted key ${keyId(trustedPem)}. Rejected.`);
}

const ok = (() => { try { return verify(null, message, createPublicKey(pem), signature); } catch { return false; } })();
if (!ok) fail("the signature does not match the document content -- it was changed after signing, or the signature is invalid.");

console.log("VERIFIED: the document's `record` is intact and signed with Ed25519 key " + embeddedId + ".");
if (!trustedKeyPath) console.log("Next: confirm key " + embeddedId + " is the one published at <your-domain>/.well-known/trustledger-export-signing-key (or re-run with that key file).");
process.exit(0);
