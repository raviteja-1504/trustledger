/**
 * Field-level protection for secrets stored in the database (on top of Supabase's disk encryption):
 *
 *   - Secrets the server must read back (2FA TOTP secrets) are sealed with AES-256-GCM under
 *     DATA_ENCRYPTION_KEY (32 bytes, as 64 hex chars or base64): stored as `enc:v1:<base64 iv|tag|ciphertext>`.
 *   - One-time codes the server only has to recognise (2FA backup codes) are stored as salted scrypt hashes:
 *     `scrypt:<base64 salt>:<base64 hash>`.
 *
 * Rows written before this existed hold the plain value; it is still accepted (openSecret returns it as-is,
 * matchBackupCode compares it in constant time) and needsUpgrade() tells the caller to rewrite it.
 * Without DATA_ENCRYPTION_KEY, sealSecret stores the plain value (and warns once) rather than break 2FA
 * set-up; a sealed value then can't be opened, so the key must not be removed or changed once it is in use.
 */
import crypto from "crypto";
import { promisify } from "util";

const scrypt = promisify(crypto.scrypt) as (pw: crypto.BinaryLike, salt: crypto.BinaryLike, keylen: number, opts: crypto.ScryptOptions) => Promise<Buffer>;

const SEALED = "enc:v1:";
const HASHED = "scrypt:";
const SCRYPT_OPTS: crypto.ScryptOptions = { N: 1 << 14, r: 8, p: 1 };

let warned = false;
function warnOnce(msg: string) {
  if (warned) return;
  warned = true;
  console.warn(`[secretBox] ${msg}`);
}

/** The configured 32-byte key, or null when DATA_ENCRYPTION_KEY is unset or malformed. */
export function encryptionKey(): Buffer | null {
  const raw = process.env.DATA_ENCRYPTION_KEY?.trim();
  if (!raw) return null;
  const key = /^[0-9a-fA-F]{64}$/.test(raw) ? Buffer.from(raw, "hex") : Buffer.from(raw, "base64");
  if (key.length !== 32) {
    warnOnce("DATA_ENCRYPTION_KEY is set but is not 32 bytes (64 hex chars or base64) -- secrets are stored unencrypted.");
    return null;
  }
  return key;
}

export const isSealed = (v: string | null | undefined): boolean => !!v && v.startsWith(SEALED);
export const isHashedCode = (v: string | null | undefined): boolean => !!v && v.startsWith(HASHED);

/** Seal a secret for storage. Returns the plain value when no key is configured. */
export function sealSecret(plain: string): string {
  const key = encryptionKey();
  if (!key) {
    warnOnce("DATA_ENCRYPTION_KEY is not set -- 2FA secrets are stored unencrypted.");
    return plain;
  }
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([cipher.update(plain, "utf8"), cipher.final()]);
  return SEALED + Buffer.concat([iv, cipher.getAuthTag(), ct]).toString("base64");
}

/** The plain secret from a stored value (legacy plain values pass through); null when it can't be opened. */
export function openSecret(stored: string | null | undefined): string | null {
  if (!stored) return null;
  if (!isSealed(stored)) return stored;
  const key = encryptionKey();
  if (!key) return null;
  try {
    const buf = Buffer.from(stored.slice(SEALED.length), "base64");
    if (buf.length < 29) return null;
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, buf.subarray(0, 12));
    decipher.setAuthTag(buf.subarray(12, 28));
    return Buffer.concat([decipher.update(buf.subarray(28)), decipher.final()]).toString("utf8");
  } catch {
    return null;
  }
}

const normCode = (code: string) => code.replace(/\s/g, "").toUpperCase();

/** A salted scrypt hash of a backup code, for storage. */
export async function hashBackupCode(code: string): Promise<string> {
  const salt = crypto.randomBytes(16);
  const hash = await scrypt(normCode(code), salt, 32, SCRYPT_OPTS);
  return `${HASHED}${salt.toString("base64")}:${hash.toString("base64")}`;
}

async function codeMatches(stored: string, code: string): Promise<boolean> {
  if (!isHashedCode(stored)) {
    const a = Buffer.from(normCode(stored)), b = Buffer.from(code);
    return a.length === b.length && crypto.timingSafeEqual(a, b);
  }
  const [salt, hash] = stored.slice(HASHED.length).split(":");
  if (!salt || !hash) return false;
  const want = Buffer.from(hash, "base64");
  const got = await scrypt(code, Buffer.from(salt, "base64"), want.length || 32, SCRYPT_OPTS);
  return want.length === got.length && crypto.timingSafeEqual(want, got);
}

/** Index of the stored backup code (hashed or legacy plain) that `code` matches, or -1. */
export async function matchBackupCode(stored: readonly string[] | null | undefined, code: string): Promise<number> {
  const c = normCode(code);
  if (!c) return -1;
  const list = stored ?? [];
  for (let i = 0; i < list.length; i++) if (await codeMatches(list[i], c)) return i;
  return -1;
}

/** Stored values still in a legacy plain form that should be rewritten now (secret only once a key exists). */
export function needsUpgrade(secret: string | null | undefined, codes: readonly string[] | null | undefined): { secret: boolean; codes: boolean } {
  return {
    secret: !!secret && !isSealed(secret) && encryptionKey() !== null,
    codes:  (codes ?? []).some(c => !isHashedCode(c)),
  };
}
