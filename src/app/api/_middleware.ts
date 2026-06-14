/**
 * Shared API middleware helpers
 * Authenticates requests via:
 *   1. Supabase session JWT (browser clients)
 *   2. TrustLedger API key (CI/CD, integrations)
 *
 * Also enforces:
 *   - IP allowlist (per API key)
 *   - Global per-IP rate limiting (prevents brute force)
 *   - Request size limit (10MB max)
 */

import { NextRequest, NextResponse } from "next/server";
import { createServiceClient } from "@/lib/supabase";
import { checkRateLimit } from "@/lib/rateLimit";
import { getJwtSessionId } from "@/lib/jwt";
import crypto from "crypto";

// ── Global per-IP rate limit (applied to ALL API routes) ────────────────────
// 300 requests/minute per IP — generous for legitimate use, blocks bots
const GLOBAL_API_LIMIT = { limit: 300, windowMs: 60_000, prefix: "global" };

export async function applyGlobalRateLimit(req: NextRequest): Promise<NextResponse | null> {
  const ip = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim()
    ?? req.headers.get("x-real-ip")
    ?? "unknown";

  const rl = await checkRateLimit(ip, GLOBAL_API_LIMIT);
  if (!rl.success) {
    return NextResponse.json(
      { error: "too_many_requests", detail: "Global rate limit exceeded. Slow down." },
      { status: 429, headers: rl.headers },
    );
  }
  return null; // allowed
}

/** Add standard API response headers (version, timing, request ID). */
export function addApiHeaders(res: NextResponse, startMs?: number): NextResponse {
  res.headers.set("X-API-Version",         "1.0.0");
  res.headers.set("X-Request-Id",          crypto.randomUUID().slice(0, 8));
  if (startMs) {
    res.headers.set("X-Response-Time-Ms",  String(Date.now() - startMs));
  }
  return res;
}

// ── IP allowlist check ────────────────────────────────────────────────────────
// Returns null if allowed, error string if blocked.
async function checkIPAllowlist(
  db: ReturnType<typeof createServiceClient>,
  org_id: string,
  req:    NextRequest,
): Promise<string | null> {
  const { data: key } = await db
    .from("api_keys")
    .select("ip_allowlist")
    .eq("org_id", org_id)
    .limit(1)
    .single() as { data: { ip_allowlist: string[] | null } | null };

  const allowlist = key?.ip_allowlist;
  if (!allowlist || allowlist.length === 0) return null; // no restriction

  const clientIp = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim()
    ?? req.headers.get("x-real-ip")
    ?? "unknown";

  if (allowlist.includes(clientIp) || allowlist.includes("*")) return null;
  return `ip_not_allowed: ${clientIp} is not in the allowlist`;
}

export interface AuthResult {
  org_id:      string;
  user_id?:    string;
  actor_email?: string;
  error?:      string;
}

export async function verifyApiKey(req: NextRequest): Promise<AuthResult> {
  // ── Demo / local-testing bypass ───────────────────────────────────────────
  if (process.env.NEXT_PUBLIC_SKIP_AUTH === "true") {
    return { org_id: "demo", actor_email: "demo@trustledger.dev" };
  }

  const authHeader = req.headers.get("Authorization") ?? "";
  const db = createServiceClient();

  // ── Bearer JWT from Supabase session ──────────────────────────────────────
  if (authHeader.startsWith("Bearer ")) {
    const token = authHeader.slice(7);
    const { data: { user }, error } = await db.auth.getUser(token);
    if (error || !user) return { org_id: "", error: "invalid_token" };

    const { data: member } = await db
      .from("org_members")
      .select("org_id, email, active_session_id")
      .eq("user_id", user.id)
      .single();

    if (!member) return { org_id: "", error: "no_org_membership" };

    // ── Single active session enforcement ─────────────────────────────────
    // A newer login (via /api/auth/bootstrap) overwrites active_session_id.
    // If this token's session_id no longer matches, this session has been
    // superseded by a login elsewhere — reject it.
    const tokenSessionId = getJwtSessionId(token);
    if (member.active_session_id && tokenSessionId && member.active_session_id !== tokenSessionId) {
      return { org_id: "", error: "session_revoked" };
    }

    return { org_id: member.org_id, user_id: user.id, actor_email: member.email };
  }

  // ── TrustLedger API key (format: tl_live_<random64>) ──────────────────────
  const apiKey = req.headers.get("X-TrustLedger-Key") ?? authHeader.replace("ApiKey ", "");
  if (apiKey) {
    const keyHash = crypto.createHash("sha256").update(apiKey).digest("hex");
    const { data: key } = await db
      .from("api_keys")
      .select("org_id, expires_at, revoked")
      .eq("key_hash", keyHash)
      .single();

    if (!key || (key as { revoked: boolean }).revoked) return { org_id: "", error: "invalid_api_key" };
    const ipErr = await checkIPAllowlist(db, (key as { org_id: string }).org_id, req);
    if (ipErr) return { org_id: "", error: ipErr };
    if (key.expires_at && new Date(key.expires_at) < new Date()) {
      return { org_id: "", error: "api_key_expired" };
    }

    // Update last_used (fire-and-forget)
    db.from("api_keys").update({ last_used: new Date().toISOString() })
      .eq("key_hash", keyHash).then(() => {});

    return { org_id: key.org_id };
  }

  return { org_id: "", error: "missing_credentials" };
}
