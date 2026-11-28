/**
 * Roles pushed by an identity provider over SCIM (the standard `roles` attribute -- Okta and Entra map a group to it).
 *
 * Only roles below admin can be granted this way: making someone an admin is decided inside TrustLedger, by an admin, never by
 * whoever manages the IdP's groups or holds the SCIM token. An unknown role is rejected rather than ignored, so a typo in the
 * IdP's mapping shows up as an error there instead of quietly giving everyone "developer".
 */
export const SCIM_GRANTABLE_ROLES = ["developer", "security_reviewer"] as const;
export type ScimRole = typeof SCIM_GRANTABLE_ROLES[number];

export type ScimRoleResult = { ok: true; role: ScimRole | null } | { ok: false; detail: string };

/** The role asked for by a SCIM `roles` value: an array of {value, primary?}, a bare string, or empty/absent (= no role given). */
export function parseScimRoles(value: unknown): ScimRoleResult {
  if (value === undefined || value === null) return { ok: true, role: null };
  const items = Array.isArray(value) ? value : [value];
  const names = items
    .map(i => (typeof i === "string" ? i : (i && typeof i === "object" ? { v: (i as { value?: unknown }).value, p: (i as { primary?: unknown }).primary === true } : null)))
    .filter(i => i !== null)
    .map(i => (typeof i === "string" ? { v: i, p: false } : i as { v: unknown; p: boolean }));
  if (names.length === 0) return { ok: true, role: null };
  const chosen = names.find(n => n.p) ?? names[0];
  const role = typeof chosen.v === "string" ? chosen.v.trim().toLowerCase() : "";
  if (role === "admin" || role === "platform_admin") {
    return { ok: false, detail: "Admin cannot be granted through SCIM: make someone an admin in TrustLedger (Settings > Team)." };
  }
  if (!(SCIM_GRANTABLE_ROLES as readonly string[]).includes(role)) {
    return { ok: false, detail: `Unknown role "${String(chosen.v).slice(0, 40)}". Use one of: ${SCIM_GRANTABLE_ROLES.join(", ")}.` };
  }
  return { ok: true, role: role as ScimRole };
}
