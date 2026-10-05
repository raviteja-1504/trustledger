/**
 * Small pure helpers for the sign-in / sign-up / password-reset flows (kept separate so they're testable
 * without React or Supabase).
 */

/** Messages for the login page's ?error= codes. Anything else gets GENERIC — the param is never echoed,
 *  so a crafted link can't put its own text on the sign-in page. */
export const LOGIN_ERROR_MESSAGES: Record<string, string> = {
  session_timeout:    "You were signed out after 30 minutes of inactivity.",
  session_revoked:    "You were signed out because your account signed in somewhere else.",
  pkce_lost:          "Your sign-in attempt expired. Please try again.",
  missing_code:       "GitHub didn't complete the sign-in. Please try again.",
  access_denied:      "GitHub sign-in was cancelled or not authorised. Please try again.",
  auth_failed:        "Sign-in failed. Please try again.",
  not_signed_in:      "Please sign in first, then try again.",
  invalid_session:    "Your session has expired. Please sign in again.",
  link_expired:       "That email link has expired or was already used. Request a new one below.",
  link_other_browser: "That email link has to be opened in the same browser you requested it from. Request a new one here, or open the link in that browser.",
  link_invalid:       "That email link isn't valid any more. Request a new one below.",
  sso_required:        "Your organisation requires single sign-on. Use “Sign in with SSO” with your work email.",
  sso_no_provider:     "Single sign-on isn't set up for that email domain. Sign in another way, or ask your admin.",
  sso_not_configured:  "Your organisation's single sign-on was removed or changed. Ask your admin, then try again.",
  sso_domain_mismatch: "Your identity provider signed you in with an email outside your organisation's verified domains. Ask your admin to check the SSO setup.",
  sso_other_org:       "That SSO account already belongs to a different TrustLedger organisation.",
  sso_not_invited:     "Your organisation doesn't add new SSO users automatically. Ask an admin to invite you, then sign in with SSO again.",
  sso_failed:          "Single sign-on didn't complete. Please try again.",
};
export const GENERIC_LOGIN_ERROR = "Sign-in didn't complete. Please try again.";

export function loginErrorMessage(code: string | null | undefined): string | null {
  if (!code) return null;
  return LOGIN_ERROR_MESSAGES[code] ?? GENERIC_LOGIN_ERROR;
}

/** The domain "Sign in with SSO" looks up for a work email ("Ann@Acme.com " → "acme.com"); null if it isn't one. */
export function ssoDomainOf(email: string): string | null {
  const m = /^[^@\s]+@([a-z0-9.-]+\.[a-z]{2,63})$/i.exec(email.trim());
  return m ? m[1].toLowerCase().replace(/\.$/, "") : null;
}

/** Codes whose fix is "request a new email link" — the login page opens the Forgot Password tab for them. */
export const LINK_ERROR_CODES = new Set(["link_expired", "link_other_browser", "link_invalid"]);

/** Where to go after signing in: a same-site path only (never another site, never back to /login). */
export function safeNextPath(next: string | null | undefined, fallback = "/dashboard"): string {
  if (!next || !next.startsWith("/") || next.startsWith("//") || next.includes("\\")) return fallback;
  if (/[\u0000-\u001f\u007f]/.test(next)) return fallback;
  if (next === "/login" || next.startsWith("/login?") || next.startsWith("/auth/")) return fallback;
  return next;
}

/**
 * Maps the error Supabase reports when it couldn't complete an emailed link (confirm sign-up, password
 * reset) to a login error code. `url` is the address the link landed on (Supabase puts its own errors in
 * the URL: #error=access_denied&error_code=otp_expired…).
 */
export function authLinkErrorCode(error: unknown, url: string): string | null {
  if (!error) return null;
  const e = error as { name?: string; message?: string; details?: { code?: string } };
  if (e.name === "AuthPKCECodeVerifierMissingError" || /code verifier/i.test(e.message ?? "")) return "link_other_browser";
  if (e.details?.code === "otp_expired" || /error_code=otp_expired/.test(url) || /expired/i.test(e.message ?? "")) return "link_expired";
  return "link_invalid";
}

/** True when the URL carries an emailed-link / OAuth result Supabase will try to consume. */
export function hasAuthCallbackParams(search: string, hash: string): boolean {
  return /(?:^|[?&#])(code|error_code|error_description|access_token)=/.test(`${search}&${hash}`);
}

/** Full-page navigation (so middleware re-runs with fresh cookies). A function so tests can observe it. */
export function fullPageNavigate(url: string): void {
  window.location.assign(url);
}

/** Like fullPageNavigate, but replaces the current history entry (used to leave a spent emailed link). */
export function fullPageReplace(url: string): void {
  window.location.replace(url);
}
