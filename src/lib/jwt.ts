// Lightweight JWT payload decoder. Does NOT verify the signature — only use
// this on tokens that have already been verified elsewhere (e.g. via
// supabase.auth.getUser()), to read additional claims like `session_id`.

function base64UrlDecode(input: string): string {
  const padded = input.replace(/-/g, "+").replace(/_/g, "/");
  const pad = padded.length % 4 === 0 ? "" : "=".repeat(4 - (padded.length % 4));
  if (typeof Buffer !== "undefined") {
    return Buffer.from(padded + pad, "base64").toString("utf8");
  }
  return atob(padded + pad);
}

export function decodeJwtPayload(token: string): Record<string, unknown> | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  try {
    return JSON.parse(base64UrlDecode(parts[1]));
  } catch {
    return null;
  }
}

/** The SSO provider id if this session was established through SAML SSO (amr[0] = sso/saml), else null. */
export function getJwtSsoProviderId(token: string): string | null {
  const amr = decodeJwtPayload(token)?.amr;
  if (!Array.isArray(amr)) return null;
  const sso = amr.find(e => e && typeof e === "object" && (e as { method?: unknown }).method === "sso/saml") as { provider?: unknown } | undefined;
  return sso && typeof sso.provider === "string" ? sso.provider : null;
}

export function getJwtSessionId(token: string): string | null {
  const payload = decodeJwtPayload(token);
  const sessionId = payload?.session_id;
  return typeof sessionId === "string" ? sessionId : null;
}
