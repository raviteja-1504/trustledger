/**
 * Roles an org admin may give a member. Deliberately excludes "platform_admin": that role reads every
 * organisation's data (api/admin, api/orgs), so it must never be reachable through an org's own team
 * management -- it is granted only by hand in the database.
 */
export const ASSIGNABLE_ROLES = ["developer", "security_reviewer", "admin"] as const;
export type AssignableRole = typeof ASSIGNABLE_ROLES[number];

export function isAssignableRole(role: unknown): role is AssignableRole {
  return typeof role === "string" && (ASSIGNABLE_ROLES as readonly string[]).includes(role);
}
