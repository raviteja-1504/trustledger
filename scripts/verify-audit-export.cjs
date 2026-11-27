#!/usr/bin/env node
/**
 * Offline verifier for a TrustLedger signed audit-log export (GET /api/export/signed), CSV or JSON.
 * Node's built-in crypto only: no network, no TrustLedger code.
 *
 *   node scripts/verify-audit-export.cjs <export.csv|export.json> [trusted-public-key.pem] [--hmac-key <secret>]
 *
 * What it checks:
 *   1. the signature covers the file (CSV: every byte above the "# --- signature ---" line; JSON: the signed object);
 *   2. the number of events matches the count the export declares, so nothing was dropped or added;
 *   3. every entry's hash recomputes from the values in the file, and each entry links to an earlier one.
 *      The first entry's predecessor is outside the exported period, so its link cannot be checked here.
 *
 * Trust: a file carries its own public key, which proves nothing by itself (a forger signs with their own key and embeds
 * it). Pass the key you obtained from <your-domain>/.well-known/trustledger-export-signing-key as the second argument;
 * the file is rejected if it was signed with a different key. An HMAC-signed export (the legacy scheme) can only be
 * checked by someone who holds the shared secret: pass it with --hmac-key.
 *
 * What it does NOT establish: that the events are the whole story of the organisation (an export is one period), or
 * that the hash chain outside the period is intact. It shows this file is exactly what TrustLedger signed.
 *
 * Exit code 0 = everything checked passed; 1 = a check failed; 2 = usage or parse error.
 */
"use strict";
const crypto = require("crypto");
const fs = require("fs");

const MARKER = "# --- signature ---";
const CSV_HEADER_V1 = ["id", "event_type", "actor_email", "resource_type", "resource_id", "payload", "prev_hash", "entry_hash", "created_at"];
const CSV_HEADER = [...CSV_HEADER_V1, "actor_id"];   // trustledger-audit-csv/2 adds actor_id (covered by hash v2)

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
const keyIdOfPem = pem => sha256(crypto.createPublicKey(pem).export({ type: "spki", format: "der" })).slice(0, 16);
const pemFromSpkiBase64 = b64 => "-----BEGIN PUBLIC KEY-----\n" + (b64.match(/.{1,64}/g) || []).join("\n") + "\n-----END PUBLIC KEY-----\n";

/** RFC 4180 parser (quoted cells, doubled quotes, line breaks inside quotes). Mirrors src/lib/csv.ts parseCsv. */
function parseCsv(text) {
  const out = []; let row = [], cell = "", quoted = false, i = 0, any = false;
  while (i < text.length) {
    const c = text[i];
    if (quoted) {
      if (c === '"') { if (text[i + 1] === '"') { cell += '"'; i += 2; continue; } quoted = false; i++; continue; }
      cell += c; i++; continue;
    }
    if (c === '"' && cell === "") { quoted = true; any = true; i++; continue; }
    if (c === ",") { row.push(cell); cell = ""; any = true; i++; continue; }
    if (c === "\r" || c === "\n") { if (c === "\r" && text[i + 1] === "\n") i++; row.push(cell); out.push(row); row = []; cell = ""; any = false; i++; continue; }
    cell += c; any = true; i++;
  }
  if (any || cell !== "" || row.length) { row.push(cell); out.push(row); }
  return out;
}
/** Undo the formula-injection apostrophe the CSV writer adds (src/lib/csv.ts csvUnneutralize). */
const unneutralize = s => (s.startsWith("'") ? s.slice(1) : s);

/** Signature check over `signed` (a string). `sig` = { algo, value, pem?, keyId? }. */
function checkSignature(signed, sig, trustedPem, hmacKey, problems, out) {
  out.signature_algo = sig.algo;
  if (sig.algo === "Ed25519") {
    let pem = sig.pem;
    if (!pem && trustedPem) pem = trustedPem;
    if (!pem) { out.signature = "unverifiable"; problems.push("the file carries no public key and none was supplied"); return; }
    try {
      const embeddedId = keyIdOfPem(pem);
      out.key_id = embeddedId;
      if (sig.keyId && sig.keyId !== embeddedId) problems.push("the file's key id does not match its own public key");
      if (trustedPem) {
        out.key_trusted = keyIdOfPem(trustedPem) === embeddedId;
        if (!out.key_trusted) problems.push(`signed with key ${embeddedId}, which is not the trusted key ${keyIdOfPem(trustedPem)}`);
      }
      const ok = crypto.verify(null, Buffer.from(signed, "utf8"), crypto.createPublicKey(pem), Buffer.from(sig.value, "base64"));
      out.signature = ok ? "valid" : "invalid";
      if (!ok) problems.push("the signature does not match the file: it was changed after signing, or the signature is not TrustLedger's");
    } catch (e) { out.signature = "invalid"; problems.push("the signature or public key could not be read: " + e.message); }
  } else if (sig.algo === "HMAC-SHA256") {
    if (!hmacKey) { out.signature = "unverifiable"; problems.push("signed with a shared secret (HMAC-SHA256): it cannot be verified independently. Pass the secret with --hmac-key, or ask for an Ed25519-signed export."); return; }
    const expected = crypto.createHmac("sha256", hmacKey).update(signed).digest("hex");
    const ok = expected.length === String(sig.value).length && crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(String(sig.value)));
    out.signature = ok ? "valid" : "invalid";
    if (!ok) problems.push("the HMAC does not match the file: it was changed after signing, or the secret is wrong");
  } else { out.signature = "unsupported"; problems.push(`unknown signature algorithm "${sig.algo}"`); }
}

/** Entry hashes recompute and entries link. `rows` = [{id,event_type,actor_email,payload,prev_hash,entry_hash,created_at}]. */
function checkRows(rows, problems, out, orgId) {
  const seen = new Set(), parents = new Set(); let recomputable = false, seenV2 = false, legacy = 0, verified = 0, metadata = 0, forkAt = null;
  out.rows = { checked: rows.length, verified: 0, metadata_verified: 0, legacy: 0, broken_at: null, fork_at: null };
  for (let i = 0; i < rows.length; i++) {
    const r = rows[i];
    if (i > 0 && (r.prev_hash == null || !seen.has(r.prev_hash))) {
      problems.push(`entry ${r.id} does not link to an earlier entry in this export: an entry may have been removed`);
      out.rows.broken_at = r.id; break;
    }
    if (r.prev_hash != null) { if (parents.has(r.prev_hash) && forkAt == null) forkAt = r.id; parents.add(r.prev_hash); }
    const at = Number.isNaN(Date.parse(r.created_at)) ? r.created_at : new Date(r.created_at).toISOString();
    if (orgId != null && entryHashV2(r, orgId, at) === r.entry_hash) { recomputable = true; seenV2 = true; verified++; metadata++; }
    else if (entryHash(r.prev_hash, r.event_type, r.actor_email, r.payload, at) === r.entry_hash) {
      if (seenV2) { problems.push(`entry ${r.id} is in the old hash format after entries in the new one: it may have been re-hashed to hide a change`); out.rows.broken_at = r.id; break; }
      recomputable = true; verified++;
    }
    else if (!recomputable) legacy++;
    else { problems.push(`entry ${r.id}: its contents no longer match its hash`); out.rows.broken_at = r.id; break; }
    seen.add(r.entry_hash);
  }
  out.rows.verified = verified; out.rows.legacy = legacy; out.rows.metadata_verified = metadata; out.rows.fork_at = forkAt;
  if (forkAt != null) problems.push(`the history has a fork: entry ${forkAt} shares its previous entry with an earlier one, so this is not a clean history`);
}

function verifyJson(text, trustedPem, hmacKey) {
  const problems = [], out = { kind: "json", problems };
  const doc = JSON.parse(text);
  const i = doc && doc.integrity, m = doc && doc.metadata;
  if (!i || !m || !Array.isArray(doc.events)) throw new Error("not a TrustLedger audit export (needs metadata, integrity and events)");
  const declared = m.event_count;
  out.events = doc.events.length; out.events_declared = declared;
  if (declared !== doc.events.length) problems.push(`the export declares ${declared} events but contains ${doc.events.length}`);
  const signed = JSON.stringify({ org_id: m.org_id, period_start: m.period_start, period_end: m.period_end, exported_at: m.exported_at, event_count: declared, chain_valid: i.chain_valid, events: doc.events });
  checkSignature(signed, { algo: i.signature_algo, value: i.signature, pem: i.public_key_pem, keyId: i.key_id }, trustedPem, hmacKey, problems, out);
  checkRows(doc.events.map(e => ({ ...e, payload: e.payload })), problems, out, m.org_id);
  out.chain_valid_claimed = i.chain_valid;
  return out;
}

function verifyCsv(text, trustedPem, hmacKey) {
  const problems = [], out = { kind: "csv", problems };
  let at = text.lastIndexOf(MARKER + "\n");
  if (at < 0) { const crlf = text.lastIndexOf(MARKER + "\r\n"); if (crlf >= 0) at = crlf; }
  if (at < 0 || (at > 0 && text[at - 1] !== "\n")) throw new Error(`not a signed TrustLedger audit CSV: no "${MARKER}" line`);
  let signed = text.slice(0, at);
  const footer = text.slice(at).split(/\r?\n/);
  const field = prefix => { const l = footer.find(x => x.startsWith(prefix)); return l ? l.slice(prefix.length).trim() : null; };
  const sigLine = footer.find(l => /^# Signature \([^)]+\): /.test(l));
  if (!sigLine) throw new Error("the signature block has no signature line");
  const sm = /^# Signature \(([^)]+)\): (.*)$/.exec(sigLine);
  const spki = field("# Public key (SPKI, base64): ");
  const sig = { algo: sm[1], value: sm[2].trim(), pem: spki ? pemFromSpkiBase64(spki) : null, keyId: field("# Public key id: ") };
  // The signed bytes are exactly what is above the marker, LF-terminated. A quoted cell may legitimately contain CRLF, so the
  // file is checked as written first. Only if that fails and the file has CRLF is it re-checked after converting them to LF
  // (a file re-saved on Windows), and then it says so.
  const attempt = text => { const p = [], o = {}; checkSignature(text, sig, trustedPem, hmacKey, p, o); return { p, o }; };
  let chosen = attempt(signed);
  if (chosen.o.signature === "invalid" && signed.includes("\r\n")) {
    const alt = attempt(signed.replace(/\r\n/g, "\n"));
    if (alt.o.signature === "valid") {
      signed = signed.replace(/\r\n/g, "\n");
      chosen = alt;
      chosen.o.note = "The file has CRLF line endings; it was verified after converting them back to the LF endings it was signed with.";
    }
  }
  Object.assign(out, chosen.o);
  problems.push(...chosen.p);

  const lines = signed.split("\n");
  const declaredLine = lines.find(l => l.startsWith("# Events: "));
  const declared = declaredLine ? Number(declaredLine.slice("# Events: ".length)) : NaN;
  const header = signed.indexOf(CSV_HEADER.join(",") + "\n") >= 0 ? CSV_HEADER : CSV_HEADER_V1;
  const dataStart = signed.indexOf(header.join(",") + "\n");
  const orgLine = lines.find(l => l.startsWith("# Org id: "));
  const csvOrgId = orgLine ? orgLine.slice("# Org id: ".length).trim() : null;
  if (dataStart < 0) { problems.push("the column header row is missing or not the expected one"); return out; }
  const records = parseCsv(signed.slice(dataStart)).filter(r => !(r.length === 1 && r[0] === ""));
  const body = records.slice(1);
  const rows = body.map(r => ({
    id: Number(r[0]), event_type: r[1], actor_email: r[2] === "" ? null : unneutralize(r[2]), resource_type: r[3], resource_id: r[4], actor_id: header.length > 9 ? (r[9] === "" ? null : r[9]) : null,
    payload: (() => { try { return JSON.parse(r[5]); } catch { return undefined; } })(), prev_hash: r[6] === "" ? null : r[6], entry_hash: r[7], created_at: r[8],
  }));
  out.events = rows.length; out.events_declared = Number.isNaN(declared) ? null : declared;
  if (records.some(r => r.length !== header.length)) problems.push("a row does not have the expected number of columns");
  if (Number.isNaN(declared)) problems.push('the signed header has no "# Events:" count');
  else if (declared !== rows.length) problems.push(`the export declares ${declared} events but contains ${rows.length}`);
  if (rows.some(r => r.payload === undefined)) problems.push("an entry's payload is not valid JSON");
  else checkRows(rows, problems, out, csvOrgId);
  const claim = lines.find(l => l.startsWith("# Chain integrity: "));
  out.chain_integrity_claimed = claim ? claim.slice("# Chain integrity: ".length) : null;
  return out;
}

function main(argv) {
  const args = argv.slice(2);
  let hmacKey = process.env.EXPORT_SIGNING_KEY || null;
  const k = args.indexOf("--hmac-key");
  if (k >= 0) { hmacKey = args[k + 1]; args.splice(k, 2); }
  const [file, keyFile] = args;
  if (!file) { console.error("usage: verify-audit-export.cjs <export.csv|export.json> [trusted-public-key.pem] [--hmac-key <secret>]"); return 2; }
  let text, trustedPem = null;
  try { text = fs.readFileSync(file, "utf8"); } catch (e) { console.error("cannot read the export: " + e.message); return 2; }
  if (keyFile) { try { trustedPem = fs.readFileSync(keyFile, "utf8"); keyIdOfPem(trustedPem); } catch (e) { console.error("cannot read the trusted key: " + e.message); return 2; } }
  let result;
  try { result = text.trimStart().startsWith("{") ? verifyJson(text, trustedPem, hmacKey) : verifyCsv(text, trustedPem, hmacKey); }
  catch (e) { console.error(e.message); return 2; }
  if (result.signature === "valid" && !trustedPem && result.signature_algo === "Ed25519") {
    result.warning = "The signing key was NOT checked against a trusted copy: pass the key published at /.well-known/trustledger-export-signing-key.";
  }
  result.note = (result.note ? result.note + " " : "") + "This shows the file is exactly what TrustLedger signed. It is one period of the log, not proof about entries outside it.";
  console.log(JSON.stringify(result, null, 2));
  return result.problems.length === 0 && result.signature === "valid" ? 0 : 1;
}

if (require.main === module) process.exit(main(process.argv));
module.exports = { verifyCsv, verifyJson, parseCsv, entryHash };
