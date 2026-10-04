/**
 * TOTP (RFC 6238, HMAC-SHA1, 6 digits, 30 s) — shared by 2FA setup/disable and the sign-in 2FA step.
 * Compatible with Google Authenticator, Authy, 1Password, etc.
 */
import crypto from "crypto";

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function base32Decode(encoded: string): Buffer {
  const cleaned = encoded.replace(/=+$/, "").toUpperCase();
  let bits = "";
  for (const c of cleaned) {
    const idx = ALPHABET.indexOf(c);
    if (idx === -1) continue;
    bits += idx.toString(2).padStart(5, "0");
  }
  const bytes: number[] = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(bytes);
}

export function base32Encode(buf: Buffer): string {
  let bits = "";
  Array.from(buf).forEach(byte => { bits += byte.toString(2).padStart(8, "0"); });
  while (bits.length % 5 !== 0) bits += "0";
  let out = "";
  for (let i = 0; i < bits.length; i += 5) out += ALPHABET[parseInt(bits.slice(i, i + 5), 2)];
  while (out.length % 8 !== 0) out += "=";
  return out;
}

export function generateTOTPSecret(): string {
  return base32Encode(crypto.randomBytes(20));
}

/** The code for the 30-second step containing unix time `t` (seconds; defaults to now). */
export function generateTOTP(secret: string, t?: number): string {
  const counter = Math.floor((t ?? Date.now() / 1000) / 30);
  const key = base32Decode(secret);
  const msg = Buffer.alloc(8);
  msg.writeBigInt64BE(BigInt(counter), 0);
  const hmac = crypto.createHmac("sha1", key).update(msg).digest();
  const offset = hmac[19] & 0x0f;
  const code = ((hmac[offset] & 0x7f) << 24 | hmac[offset + 1] << 16 | hmac[offset + 2] << 8 | hmac[offset + 3]) % 1_000_000;
  return code.toString().padStart(6, "0");
}

/** True when `code` matches the current step or one step either side (clock drift). */
export function verifyTOTP(secret: string, code: string, window = 1): boolean {
  const now = Math.floor(Date.now() / 1000);
  const clean = code.replace(/\s/g, "");
  for (let i = -window; i <= window; i++) {
    if (generateTOTP(secret, now + i * 30) === clean) return true;
  }
  return false;
}

export function buildOtpAuthUri(secret: string, email: string, issuer: string): string {
  const params = new URLSearchParams({ secret, issuer, algorithm: "SHA1", digits: "6", period: "30" });
  return `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(email)}?${params.toString()}`;
}
