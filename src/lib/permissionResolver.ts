/**
 * Server-side permission resolution (see lib/permissions.ts for the model). requirePermission() is what
 * API routes call; it is re-exported from app/api/_middleware.ts next to requireRole().
 */
import { createServiceClient } from "@/lib/supabase";
import { logger } from "@/lib/logger";
import {
  ALL_PERMISSIONS, API_KEY_PERMISSIONS, NO_PERMISSIONS, PERMISSION_KEYS, builtinPermissions, permissionsFromRow,
  type PermissionKey, type Permissions,
} from "@/lib/permissions";

/** Who is asking -- the subset of the API auth result this needs. No user_id means an org API key. */
export interface PermissionSubject {
  org_id:   string;
  user_id?: string;
  role?:    string;
}

type DbError = { code?: string; message?: string } | null;

/** Postgres "undefined column": a database that predates migration 005 has no custom roles at all. */
function isMissingColumn(err: DbError): boolean {
  return !!err && (err.code === "42703" || /custom_role_id/.test(err.message ?? ""));
}

async function loadPermissions(subject: PermissionSubject): Promise<Permissions> {
  if (process.env.NEXT_PUBLIC_SKIP_AUTH === "true") return ALL_PERMISSIONS;
  if (!subject.org_id) return NO_PERMISSIONS;
  if (!subject.user_id) return API_KEY_PERMISSIONS;
  const base = builtinPermissions(subject.role);
  if (subject.role === "platform_admin") return base;

  const db = createServiceClient();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const { data: member, error } = await (db.from("org_members") as any)
    .select("custom_role_id").eq("org_id", subject.org_id).eq("user_id", subject.user_id).maybeSingle() as
    { data: { custom_role_id?: string | null } | null; error: DbError };
  if (error) {
    if (isMissingColumn(error)) return base;
    // A custom role can be narrower than the built-in one, so an unreadable assignment must not widen access.
    logger.error("Permission lookup failed", { event: "permissions_lookup_failed", org_id: subject.org_id, error: error.message });
    return NO_PERMISSIONS;
  }
  if (!member?.custom_role_id) return base;

  const { data: custom, error: roleErr } = await db
    .from("custom_roles").select("*").eq("id", member.custom_role_id).eq("org_id", subject.org_id).maybeSingle();
  if (roleErr || !custom) {
    logger.error("Custom role lookup failed", { event: "permissions_lookup_failed", org_id: subject.org_id, error: roleErr?.message ?? "custom_role_not_found" });
    return NO_PERMISSIONS;
  }
  return permissionsFromRow(custom as Partial<Record<PermissionKey, unknown>>);
}

const cache = new WeakMap<object, Promise<Permissions>>();

/** The caller's effective permissions (built-in role, replaced by an assigned custom role). Loaded on first
 * use and memoised per auth object, so routes that never ask pay nothing. */
export function permissionsFor(subject: PermissionSubject): Promise<Permissions> {
  let p = cache.get(subject);
  if (!p) { p = loadPermissions(subject); cache.set(subject, p); }
  return p;
}

/** "insufficient_permissions" unless the caller holds every listed permission; null if allowed. */
export async function requirePermission(subject: PermissionSubject, ...keys: PermissionKey[]): Promise<string | null> {
  const perms = await permissionsFor(subject);
  return keys.every(k => perms[k]) ? null : "insufficient_permissions";
}

/** Permissions of the org member with this email (Slack commands know only the person's email); null if
 * the email isn't a member of the org. */
export async function permissionsForMemberEmail(orgId: string, email: string): Promise<{ user_id: string | null; permissions: Permissions } | null> {
  const db = createServiceClient();
  const { data: member } = await db
    .from("org_members").select("user_id, role").eq("org_id", orgId).eq("email", email).maybeSingle() as
    { data: { user_id: string | null; role: string } | null };
  if (!member) return null;
  // A pending invite (no user yet) has no custom role either; its built-in role applies.
  const permissions = member.user_id
    ? await permissionsFor({ org_id: orgId, user_id: member.user_id, role: member.role })
    : builtinPermissions(member.role);
  return { user_id: member.user_id, permissions };
}

/** Stops a team manager handing out more than they hold: only a built-in admin (or platform admin) may make
 * someone admin -- admin also covers API keys and org deletion, which no flag grants -- and any other
 * role or custom role is grantable only if every permission it carries is one the caller has.
 * Returns an error code, or null if allowed. */
export async function checkGrantable(
  subject: PermissionSubject,
  target: { role?: string | null; permissions?: Permissions },
): Promise<string | null> {
  const isAdmin = subject.role === "admin" || subject.role === "platform_admin";
  if (target.role === "admin" && !isAdmin) return "cannot_grant_admin";
  if (isAdmin) return null;
  const mine = await permissionsFor(subject);
  const wanted = target.permissions ?? (target.role ? builtinPermissions(target.role) : null);
  if (wanted && PERMISSION_KEYS.some(k => wanted[k] && !mine[k])) return "cannot_grant_more_than_own_permissions";
  return null;
}
