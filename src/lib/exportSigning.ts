/**
 * Public-key signing for exported evidence (Trust Records, signed audit-log exports).
 *
 * Why: the older scheme signs with HMAC-SHA256 and a shared secret (EXPORT_SIGNING_KEY). Anyone verifying a
 * document needs that secret, so an outside auditor can't check it independently without being trusted with a
 * key that could also FORGE documents. Ed25519 fixes this: the server signs with a private key it alone holds,
 * and anyone verifies with the public key, which reveals nothing and can be published openly.
 *
 * Set EXPORT_SIGNING_PRIVATE_KEY to a PEM-encoded Ed25519 private key (PKCS#8). Generate one with:
 *   openssl genpkey -algorithm ed25519 -out tl_export_key.pem
 * Keep it server-only. The matching public key is derived from it and served at
 *   /.well-known/trustledger-export-signing-key   (JSON: algorithm, key_id, public_key_pem)
 * so auditors and the offline verifier (scripts/verify-trust-record.mjs) can fetch it.
 *
 * Trust model: a signed document carries its own public key for convenience, but a verifier must NOT trust that
 * key on its own -- a forger could sign with their own key and embed it. Trust comes from matching the
 * document's key_id against the key published at the official URL. keyIdMatches()/checkAgainstTrustedKey() below
 * enforce that; verifyEd25519() only proves "signed by whoever owns this public key".
 *
 * Server-only (node:crypto). Never import into client code.
 */
import crypto from "crypto";

export const EXPORT_SIG_ALGO = "Ed25519";

export interface PublicKeyInfo {
  algorithm: typeof EXPORT_SIG_ALGO;
  key_id: string;
  public_key_pem: string;
}

export interface Ed25519Signature {
  algorithm: typeof EXPORT_SIG_ALGO;
  /** base64 of the 64-byte Ed25519 signature over the canonical bytes. */
  value: string;
  /** Short id of the signing public key (keyId of public_key_pem). */
  key_id: string;
  /** The signing public key, so a document is self-describing. NEVER trusted on its own -- see keyIdMatches. */
  public_key_pem: string;
  /** Exactly what was signed, so a verifier reconstructs the same bytes. */
  signed_content: string;
}

let cachedPrivate: crypto.KeyObject | null | undefined;

/** The configured Ed25519 private key, or null when EXPORT_SIGNING_PRIVATE_KEY is unset or not an Ed25519 key. */
export function exportPrivateKey(): crypto.KeyObject | null {
  if (cachedPrivate !== undefined) return cachedPrivate;
  const pem = (process.env.EXPORT_SIGNING_PRIVATE_KEY ?? "").trim();
  if (!pem) return (cachedPrivate = null);
  try {
    const key = crypto.createPrivateKey(pem);
    cachedPrivate = key.asymmetricKeyType === "ed25519" ? key : null;
    if (!cachedPrivate) console.warn("[exportSigning] EXPORT_SIGNING_PRIVATE_KEY is set but is not an Ed25519 key -- public-key signing is off.");
  } catch {
    console.warn("[exportSigning] EXPORT_SIGNING_PRIVATE_KEY is set but could not be parsed as a PEM private key -- public-key signing is off.");
    cachedPrivate = null;
  }
  return cachedPrivate;
}

/** Test-only: forget the memoised key after changing the env var. */
export function _resetExportKeyCache(): void { cachedPrivate = undefined; }

/** A public key's id: first 16 hex chars of SHA-256 over its DER (SPKI) bytes. Stable across PEM whitespace. */
export function keyId(publicKey: crypto.KeyObject): string {
  const der = publicKey.export({ type: "spki", format: "der" });
  return crypto.createHash("sha256").update(der).digest("hex").slice(0, 16);
}

/** keyId computed from a PEM public key, or null when the PEM can't be parsed. */
export function keyIdFromPem(pem: string): string | null {
  try { return keyId(crypto.createPublicKey(pem)); } catch { return null; }
}

/** The public half of the configured signing key, or null when none is configured. */
export function exportPublicKey(): PublicKeyInfo | null {
  const priv = exportPrivateKey();
  if (!priv) return null;
  const pub = crypto.createPublicKey(priv);
  return { algorithm: EXPORT_SIG_ALGO, key_id: keyId(pub), public_key_pem: pub.export({ type: "spki", format: "pem" }) as string };
}

/** Sign canonical bytes with the configured Ed25519 key, or null when no private key is set. */
export function signEd25519(canonical: string, signedContentNote: string): Ed25519Signature | null {
  const priv = exportPrivateKey();
  if (!priv) return null;
  const pub = crypto.createPublicKey(priv);
  const value = crypto.sign(null, Buffer.from(canonical, "utf8"), priv).toString("base64");
  return {
    algorithm: EXPORT_SIG_ALGO,
    value,
    key_id: keyId(pub),
    public_key_pem: pub.export({ type: "spki", format: "pem" }) as string,
    signed_content: signedContentNote,
  };
}

/** Does the signature's public key (by key_id and by bytes) match this trusted public key? Guards against a
 * document that is validly self-signed with a key that isn't ours. */
export function keyIdMatches(sig: { key_id?: unknown; public_key_pem?: unknown }, trustedPublicPem: string): boolean {
  const trustedId = keyIdFromPem(trustedPublicPem);
  const embeddedId = typeof sig.public_key_pem === "string" ? keyIdFromPem(sig.public_key_pem) : null;
  // The embedded PEM must actually hash to the key_id it claims, AND that id must be our trusted key's id.
  return !!trustedId && !!embeddedId && embeddedId === trustedId && sig.key_id === trustedId;
}

/** Verify an Ed25519 signature over `canonical` using the key embedded in the signature. Proves the document was
 * signed by whoever owns that key; pair with keyIdMatches to prove it is OUR key. */
export function verifyEd25519(canonical: string, sig: { value?: unknown; public_key_pem?: unknown }): boolean {
  if (typeof sig.value !== "string" || typeof sig.public_key_pem !== "string") return false;
  let signature: Buffer, pub: crypto.KeyObject;
  try {
    signature = Buffer.from(sig.value, "base64");
    if (signature.length !== 64) return false;
    pub = crypto.createPublicKey(sig.public_key_pem);
    if (pub.asymmetricKeyType !== "ed25519") return false;
  } catch { return false; }
  try { return crypto.verify(null, Buffer.from(canonical, "utf8"), pub, signature); } catch { return false; }
}
