/**
 * What may reach PostHog: no emails or names, and no customer data in URLs. Paths are reduced to their route
 * pattern (/repo/acme/payments-api → /repo/[...slug]) and query strings / fragments are dropped, because they
 * carry repository names, PR numbers, file paths and sign-in parameters.
 *
 * Applied to every event through posthog.init({ sanitize_properties }) in analytics.ts, so PostHog's own
 * automatic properties ($current_url, $pathname, $referrer, ...) are covered too, not just our events.
 */

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Route pattern for an app path; unknown deep paths keep only their first segment. */
export function templatePath(path: string): string {
  const clean = (path.split(/[?#]/)[0] || "/").replace(/\/+$/, "") || "/";
  const segs = clean.split("/").filter(Boolean);
  if (segs.length === 0) return "/";
  if (segs[0] === "repo") return "/repo/[...slug]";
  if (segs[0] === "pr" && segs.length > 1) return "/pr/[id]";
  // any id-like segment (uuid, number, long hex) is a record reference
  return "/" + segs.map(s => (UUID.test(s) || /^\d+$/.test(s) || /^[0-9a-f]{16,}$/i.test(s)) ? "[id]" : s).join("/");
}

/** A URL reduced to origin + route pattern (no query, no fragment). Non-URLs become "". */
export function scrubUrl(value: string): string {
  try {
    const u = new URL(value);
    return `${u.origin}${templatePath(u.pathname)}`;
  } catch {
    return value.startsWith("/") ? templatePath(value) : "";
  }
}

function originOf(value: string): string {
  try { return new URL(value).origin; } catch { return ""; }
}

const EMAIL =/[^\s@"'<>]+@[^\s@"'<>]+\.[a-z]{2,}/gi;
const URL_KEY = /(url|referrer|pathname|href|host_?path)$/i;

/** Every event's properties, before they leave the browser. */
export function sanitizeAnalyticsProperties(props: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(props)) {
    if (/^\$?(email|name|user_email|github_login)$/i.test(k)) continue;
    if (typeof v !== "string") { out[k] = v; continue; }
    // A referrer is someone else's page (e.g. the customer's GitHub PR): keep only which site it was.
    if (/referr/i.test(k)) out[k] = originOf(v);
    else if (k === "page" || URL_KEY.test(k)) out[k] = /^https?:\/\//.test(v) ? scrubUrl(v) : v.startsWith("/") ? templatePath(v) : scrubUrl(v);
    else out[k] = v.replace(EMAIL, "[email]");
  }
  return out;
}

/** The only person properties sent: opaque ids and the role -- never email, name or org name. */
export function identityProperties(profile: { org_id?: string | null; role?: string | null }): Record<string, string> {
  const p: Record<string, string> = {};
  if (profile.org_id) p.org_id = profile.org_id;
  if (profile.role) p.role = profile.role;
  return p;
}
