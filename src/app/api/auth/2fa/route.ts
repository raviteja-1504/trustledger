/**
 * TOTP Two-Factor Authentication
 * Uses HMAC-SHA1 Time-based One-Time Passwords (RFC 6238).
 * Compatible with Google Authenticator, Authy, 1Password, etc.
 *
 * POST /api/auth/2fa?action=setup    → generate secret + QR code data
 * POST /api/auth/2fa?action=verify   → verify TOTP code + enable 2FA
 * POST /api/auth/2fa?action=disable  → disable 2FA (requires code)
 * GET  /api/auth/2fa                 → check 2FA status
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { verifyApiKey } from "../../_middleware";
import crypto from "crypto";
import { writeAuditLog } from "@/lib/audit";
import { checkRateLimit } from "@/lib/rateLimit";

// ── TOTP implementation (no dependencies — pure stdlib) ──────────────────────

function base32Decode(encoded: string): Buffer {
  const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const cleaned  = encoded.replace(/=+$/, "").toUpperCase();
  let bits = "";
  for (const c of cleaned) {
    const idx = ALPHABET.indexOf(c);
    if (idx === -1) continue;
    bits += idx.toString(2).padStart(5, "0");
  }
  const bytes: number[] = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }
  return Buffer.from(bytes);
}

function base32Encode(buf: Buffer): string {
  const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  Array.from(buf).forEach(byte => { bits += byte.toString(2).padStart(8, "0"); });
  while (bits.length % 5 !== 0) bits += "0";
  let out = "";
  for (let i = 0; i < bits.length; i += 5) out += ALPHABET[parseInt(bits.slice(i, i + 5), 2)];
  while (out.length % 8 !== 0) out += "=";
  return out;
}

function generateTOTPSecret(): string {
  return base32Encode(crypto.randomBytes(20));
}

function generateTOTP(secret: string, t?: number): string {
  const counter = Math.floor((t ?? Date.now() / 1000) / 30);
  const key     = base32Decode(secret);
  const msg     = Buffer.alloc(8);
  msg.writeBigInt64BE(BigInt(counter), 0);
  const hmac = crypto.createHmac("sha1", key).update(msg).digest();
  const offset= hmac[19] & 0x0f;
  const code  = ((hmac[offset] & 0x7f) << 24 |
                  hmac[offset+1] << 16 |
                  hmac[offset+2] << 8  |
                  hmac[offset+3]) % 1_000_000;
  return code.toString().padStart(6, "0");
}

function verifyTOTP(secret: string, code: string, window = 1): boolean {
  const now = Math.floor(Date.now() / 1000);
  for (let i = -window; i <= window; i++) {
    if (generateTOTP(secret, now + i * 30) === code.replace(/\s/g, "")) return true;
  }
  return false;
}

function buildOtpAuthUri(secret: string, email: string, issuer: string): string {
  const params = new URLSearchParams({
    secret,
    issuer,
    algorithm: "SHA1",
    digits:    "6",
    period:    "30",
  });
  return `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(email)}?${params.toString()}`;
}

// ── DB helpers ────────────────────────────────────────────────────────────────

async function get2FARecord(db: ReturnType<typeof createServiceClient>, userId: string) {
  const { data } = await db
    .from("user_2fa")
    .select("enabled, secret, backup_codes")
    .eq("user_id", userId)
    .single() as { data: { enabled: boolean; secret: string | null; backup_codes: string[] | null } | null };
  return data;
}

// ── Route ─────────────────────────────────────────────────────────────────────

export async function GET(req: NextRequest) {
  const { user_id, org_id, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });
  if (!user_id) return NextResponse.json({ error: "user_required" }, { status: 400 });

  const db     = createServiceClient();
  const record = await get2FARecord(db, user_id);

  return NextResponse.json({
    enabled:       record?.enabled ?? false,
    setup_pending: !!(record?.secret && !record.enabled),
  });
}

export async function POST(req: NextRequest) {
  const { user_id, org_id, actor_email, error } = await verifyApiKey(req);
  if (error) return NextResponse.json({ error }, { status: 401 });
  if (!user_id) return NextResponse.json({ error: "user_required" }, { status: 400 });

  const url    = new URL(req.url);
  const action = url.searchParams.get("action");
  const body   = await req.json().catch(() => ({})) as { code?: string };
  const db     = createServiceClient();

  if (action === "setup") {
    // Generate new secret
    const secret = generateTOTPSecret();
    const issuer = "TrustLedger";

    // Upsert pending 2FA record (not enabled until verified)
    await db.from("user_2fa").upsert({
      user_id, secret, enabled: false, backup_codes: [],
    }, { onConflict: "user_id" });

    const otpUri = buildOtpAuthUri(secret, actor_email ?? user_id, issuer);

    // Return secret + OTP URI (client renders QR from URI)
    return NextResponse.json({
      secret,
      otp_uri: otpUri,
      issuer,
      digits:  6,
      period:  30,
      note:    "Scan the QR code with your authenticator app, then verify with /api/auth/2fa?action=verify",
    });
  }

  if (action === "verify" || action === "disable") {
    // Rate-limit TOTP attempts per user: 10 attempts per 15 minutes
    const rl = await checkRateLimit(user_id, { limit: 10, windowMs: 15 * 60_000, prefix: "2fa" });
    if (!rl.success) {
      return NextResponse.json(
        { error: "too_many_attempts", retry_after: Math.ceil((rl.reset - Date.now()) / 1000) },
        { status: 429, headers: rl.headers },
      );
    }
  }

  if (action === "verify") {
    if (!body.code) return NextResponse.json({ error: "code required" }, { status: 400 });

    const record = await get2FARecord(db, user_id);
    if (!record?.secret) return NextResponse.json({ error: "no_setup_pending" }, { status: 400 });
    if (record.enabled)  return NextResponse.json({ error: "already_enabled"  }, { status: 400 });

    if (!verifyTOTP(record.secret, body.code)) {
      return NextResponse.json({ error: "invalid_code" }, { status: 400 });
    }

    // Generate backup codes
    const backupCodes = Array.from({ length: 8 }, () =>
      crypto.randomBytes(4).toString("hex").toUpperCase(),
    );

    await db.from("user_2fa").update({ enabled: true, backup_codes: backupCodes }).eq("user_id", user_id);

    await writeAuditLog(db, {
      org_id,
      event_type:    "org_settings_changed",
      actor_id:      user_id,
      actor_email:   actor_email ?? null,
      resource_type: "2fa",
      resource_id:   user_id,
      payload:       { action: "2fa_enabled" },
    });

    return NextResponse.json({
      ok:           true,
      backup_codes: backupCodes,
      note:         "Save these backup codes in a safe place. They can only be shown once.",
    });
  }

  if (action === "disable") {
    if (!body.code) return NextResponse.json({ error: "code required" }, { status: 400 });

    const record = await get2FARecord(db, user_id);
    if (!record?.enabled) return NextResponse.json({ error: "not_enabled" }, { status: 400 });

    // Check TOTP code or backup code
    const validTotp   = verifyTOTP(record.secret!, body.code);
    const validBackup = record.backup_codes?.includes(body.code.toUpperCase());

    if (!validTotp && !validBackup) {
      return NextResponse.json({ error: "invalid_code" }, { status: 400 });
    }

    await db.from("user_2fa").update({ enabled: false, secret: null, backup_codes: [] }).eq("user_id", user_id);

    await writeAuditLog(db, {
      org_id,
      event_type:    "org_settings_changed",
      actor_id:      user_id,
      actor_email:   actor_email ?? null,
      resource_type: "2fa",
      resource_id:   user_id,
      payload:       { action: "2fa_disabled" },
    });

    return NextResponse.json({ ok: true });
  }

  return NextResponse.json({ error: "unknown_action" }, { status: 400 });
}
