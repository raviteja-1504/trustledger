/**
 * Verifies a TrustLedger evidence file -- a signed report's evidence record, or a Trust Record: `{ record, signature }`
 * -- with Web Crypto, so the /verify page checks it in the browser and the file is never uploaded.
 *
 * The signature is checked against the key PUBLISHED at /.well-known/trustledger-export-signing-key, never the key
 * the file carries (a forger could sign with their own key and embed it). For a report it also re-checks what the
 * signature implies an auditor can rely on: the record's SHA-256 (printed in the PDF), each change-register row's own
 * hash, and that the auditor sample re-draws from its seed. Same steps as scripts/verify-trust-record.mjs.
 *
 * Client-safe: pure apart from the injected SubtleCrypto.
 */
import { canonicalJson } from "@/lib/canonicalJson";
import { drawSample, pullKey, type RegisterRow } from "@/lib/changeRegisterShared";

export interface PublishedKey { key_id: string; public_key_pem: string }
export interface VerifyStep { label: string; ok: boolean | null; detail: string }
export interface VerifyResult {
  /** verified: every check passed; failed: something doesn't match; unverifiable: it can't be checked here. */
  verdict: "verified" | "failed" | "unverifiable";
  steps: VerifyStep[];
  record_sha256: string | null;
  /** The report's id and period when it is a report, for the reader to match against the PDF. */
  report?: { id: string; framework: string; period_start: string; period_end: string };
}

const hex = (buf: ArrayBuffer) => [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, "0")).join("");
const utf8 = (s: string) => new TextEncoder().encode(s);
const b64 = (s: string) => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const pemToDer = (pem: string) => b64(pem.replace(/-----(BEGIN|END) PUBLIC KEY-----/g, "").replace(/\s+/g, ""));

async function sha256Hex(subtle: SubtleCrypto, data: BufferSource): Promise<string> {
  return hex(await subtle.digest("SHA-256", data));
}

/** A public key's id: the first 16 hex characters of SHA-256 over its DER (SPKI) bytes (lib/exportSigning.ts keyId). */
export async function keyIdOf(subtle: SubtleCrypto, pem: string): Promise<string> {
  return (await sha256Hex(subtle, pemToDer(pem))).slice(0, 16);
}

type Doc = { record?: unknown; signature?: Record<string, unknown> };

export async function verifyEvidence(input: unknown, published: PublishedKey | null, subtle: SubtleCrypto): Promise<VerifyResult> {
  const steps: VerifyStep[] = [];
  const done = (record_sha256: string | null, report?: VerifyResult["report"]): VerifyResult => ({
    verdict: steps.some(s => s.ok === false) ? "failed" : steps.some(s => s.ok === null) ? "unverifiable" : "verified",
    steps, record_sha256, ...(report ? { report } : {}),
  });

  const doc = (input && typeof input === "object" ? input : {}) as Doc;
  if (!doc.record || typeof doc.record !== "object" || !doc.signature || typeof doc.signature !== "object") {
    steps.push({ label: "Evidence file", ok: false, detail: "This isn't a TrustLedger evidence file: it needs a `record` and a `signature`." });
    return done(null);
  }
  const record = doc.record as Record<string, unknown>;
  const sig = doc.signature;
  const canonical = utf8(canonicalJson(record));
  const recordSha = await sha256Hex(subtle, canonical);
  const report = typeof record.report_id === "string"
    ? { id: record.report_id, framework: String(record.framework ?? ""), period_start: String(record.period_start ?? ""), period_end: String(record.period_end ?? "") }
    : undefined;

  // the SHA-256 the PDF prints is the record's
  if (typeof sig.record_sha256 === "string") {
    steps.push(sig.record_sha256 === recordSha
      ? { label: "Record fingerprint", ok: true, detail: `SHA-256 ${recordSha}: compare it with the one printed in the PDF.` }
      : { label: "Record fingerprint", ok: false, detail: `The record's SHA-256 is ${recordSha}, but the signature says ${sig.record_sha256}: the record was changed.` });
  }

  if (sig.algorithm !== "Ed25519") {
    steps.push({ label: "Signature", ok: null, detail: `Signed with ${String(sig.algorithm)}, a shared secret only the issuing server holds: it can't be verified independently. Ask for a report signed with Ed25519.` });
    return done(recordSha, report);
  }
  if (!published) {
    steps.push({ label: "Published key", ok: null, detail: "This deployment publishes no signing key, so there is nothing to verify against." });
    return done(recordSha, report);
  }
  if (sig.key_id !== published.key_id) {
    steps.push({ label: "Signing key", ok: false, detail: `Signed with key ${String(sig.key_id)}, not the published key ${published.key_id}.` });
    return done(recordSha, report);
  }
  if (typeof sig.public_key_pem === "string" && await keyIdOf(subtle, sig.public_key_pem) !== published.key_id) {
    steps.push({ label: "Signing key", ok: false, detail: "The key carried in the file doesn't match its own key id: the file is inconsistent." });
    return done(recordSha, report);
  }
  steps.push({ label: "Signing key", ok: true, detail: `Key ${published.key_id}, as published at /.well-known/trustledger-export-signing-key.` });

  let valid: boolean;
  try {
    const key = await subtle.importKey("spki", pemToDer(published.public_key_pem), { name: "Ed25519" }, false, ["verify"]);
    valid = await subtle.verify({ name: "Ed25519" }, key, b64(String(sig.value ?? "")), canonical);
  } catch {
    steps.push({ label: "Signature", ok: null, detail: "This browser can't check Ed25519 signatures. Use a current browser, or run scripts/verify-trust-record.mjs." });
    return done(recordSha, report);
  }
  steps.push(valid
    ? { label: "Signature", ok: true, detail: "Valid: the record is exactly what TrustLedger signed." }
    : { label: "Signature", ok: false, detail: "Invalid: the record was changed after signing, or the signature isn't TrustLedger's." });

  // the change register inside a report: every row's own hash, and the sample re-drawn from its seed
  const cr = record.change_register as { rows?: RegisterRow[]; sample?: { seed: string; size: number; picked: Array<{ repo: string; number: number }> } } | undefined;
  if (cr?.rows) {
    let bad = 0;
    for (const row of cr.rows) {
      const { row_sha256, ...rest } = row;
      if (await sha256Hex(subtle, utf8(canonicalJson(rest))) !== row_sha256) bad++;
    }
    steps.push(bad === 0
      ? { label: "Change register rows", ok: true, detail: `All ${cr.rows.length} rows match their own SHA-256, so each CSV row can be checked on its own.` }
      : { label: "Change register rows", ok: false, detail: `${bad} of ${cr.rows.length} rows don't match their SHA-256.` });
    if (cr.sample) {
      const redrawn = drawSample(cr.rows, cr.sample.size, cr.sample.seed).map(r => pullKey(r.repo, r.number));
      const picked = cr.sample.picked.map(p => pullKey(p.repo, p.number));
      steps.push(redrawn.join() === picked.join()
        ? { label: "Auditor sample", ok: true, detail: `Re-drawn from seed ${cr.sample.seed}: the same ${picked.length} pull requests.` }
        : { label: "Auditor sample", ok: false, detail: `Re-drawing from seed ${cr.sample.seed} gives different pull requests.` });
    }
  }
  return done(recordSha, report);
}
