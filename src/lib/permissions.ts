/**
 * Effective permissions -- what a caller may do, enforced server-side by requirePermission()
 * (app/api/_middleware.ts) and mirrored to the UI through /api/me.
 *
 * A member's permissions come from their built-in role (BUILTIN_PERMISSIONS). If an admin assigns them a
 * custom role (custom_roles, org_members.custom_role_id), the custom role's flags REPLACE the built-in set
 * entirely -- the same rule as get_user_permissions() in migration 005. The built-in role still decides
 * the few admin-only operations that have no flag (API keys, org deletion, org settings).
 *
 * Pure and dependency-free so client components can import it too.
 */

export const PERMISSION_KEYS = [
  "can_attest_critical",
  "can_attest_high",
  "can_attest_medium",
  "can_resolve_violations",
  "can_manage_incidents",
  "can_view_secrets",
  "can_export_data",
  "can_manage_policies",
  "can_manage_team",
  "can_manage_integrations",
  "can_view_audit_log",
  "can_trigger_scans",
  "can_create_reports",
  "can_manage_billing",
] as const;

export type PermissionKey = typeof PERMISSION_KEYS[number];
export type Permissions = Record<PermissionKey, boolean>;

export const PERMISSION_LABELS: Record<PermissionKey, { label: string; detail: string }> = {
  can_attest_critical:     { label: "Attest CRITICAL files",   detail: "Sign off CRITICAL-risk files" },
  can_attest_high:         { label: "Attest HIGH files",       detail: "Sign off HIGH-risk files" },
  can_attest_medium:       { label: "Attest MEDIUM/LOW files", detail: "Sign off lower-risk files" },
  can_resolve_violations:  { label: "Triage findings",         detail: "Resolve violations, triage findings, accept exceptions" },
  can_manage_incidents:    { label: "Manage incidents",        detail: "Open, update and close incidents" },
  can_view_secrets:        { label: "View secrets",            detail: "See detected secrets and change their status" },
  can_export_data:         { label: "Export data",             detail: "CSV/SARIF exports, evidence packages, full data export" },
  can_manage_policies:     { label: "Manage policies",         detail: "Rules, compliance and audit settings, data retention" },
  can_manage_team:         { label: "Manage team",             detail: "Invite and remove members, change roles" },
  can_manage_integrations: { label: "Manage integrations",     detail: "Repositories, API keys, outbound webhooks" },
  can_view_audit_log:      { label: "View audit log",          detail: "Read the tamper-evident audit trail" },
  can_trigger_scans:       { label: "Run scans",               detail: "Start and re-run PR scans" },
  can_create_reports:      { label: "Create reports",          detail: "Generate compliance reports" },
  can_manage_billing:      { label: "Manage billing",          detail: "Change plan and payment details" },
};

const all = (v: boolean): Permissions => Object.fromEntries(PERMISSION_KEYS.map(k => [k, v])) as Permissions;
const only = (...keys: PermissionKey[]): Permissions => ({ ...all(false), ...Object.fromEntries(keys.map(k => [k, true])) });

/** Built-in roles. Developer keeps what it could already do (view, scan, report, see secrets from its own
 * PRs, read the audit log); attesting, triage and every management action need a reviewer or admin. */
export const BUILTIN_PERMISSIONS: Record<"admin" | "security_reviewer" | "developer", Permissions> = {
  admin: all(true),
  security_reviewer: only(
    "can_attest_critical", "can_attest_high", "can_attest_medium", "can_resolve_violations",
    "can_manage_incidents", "can_view_secrets", "can_export_data", "can_view_audit_log",
    "can_trigger_scans", "can_create_reports",
  ),
  developer: only("can_view_secrets", "can_view_audit_log", "can_trigger_scans", "can_create_reports"),
};

/** Org API keys (CI, Zapier): automation, never a human sign-off -- no attesting, no management. */
export const API_KEY_PERMISSIONS: Permissions = only(
  "can_resolve_violations", "can_manage_incidents", "can_trigger_scans", "can_create_reports",
);

export const ALL_PERMISSIONS: Permissions = all(true);
export const NO_PERMISSIONS: Permissions = all(false);

/** A custom_roles row (or any object with the flag columns) → a complete permission set; a missing flag is false. */
export function permissionsFromRow(row: Partial<Record<PermissionKey, unknown>>): Permissions {
  return Object.fromEntries(PERMISSION_KEYS.map(k => [k, row[k] === true])) as Permissions;
}

/** Built-in role → permissions. Unknown roles get developer's set; platform_admin gets everything. */
export function builtinPermissions(role: string | null | undefined): Permissions {
  if (role === "platform_admin") return ALL_PERMISSIONS;
  return BUILTIN_PERMISSIONS[(role ?? "developer") as keyof typeof BUILTIN_PERMISSIONS] ?? BUILTIN_PERMISSIONS.developer;
}

/** The flag that allows attesting a file of the given risk score. */
export function attestPermissionFor(risk: string | null | undefined): PermissionKey {
  const r = (risk ?? "").toUpperCase();
  return r === "CRITICAL" ? "can_attest_critical" : r === "HIGH" ? "can_attest_high" : "can_attest_medium";
}

export function canAttestAny(p: Permissions): boolean {
  return p.can_attest_critical || p.can_attest_high || p.can_attest_medium;
}
