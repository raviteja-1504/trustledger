/**
 * @jest-environment node
 *
 * The permission model (lib/permissions.ts) and how a caller's effective permissions are resolved
 * (lib/permissionResolver.ts): built-in role, replaced by an assigned custom role.
 */
import { fakeSupabase } from "../helpers/fakeSupabase";

let db: ReturnType<typeof fakeSupabase>;
let failMemberRead: { code?: string; message: string } | null = null;
jest.mock("@/lib/supabase", () => ({
  createServiceClient: () => ({
    from: (t: string) => {
      const q = db.client.from(t);
      if (t === "org_members" && failMemberRead) {
        const err = failMemberRead;
        return { select: () => ({ eq: () => ({ eq: () => ({ maybeSingle: async () => ({ data: null, error: err }) }) }) }) };
      }
      return q;
    },
  }),
}));
jest.mock("@/lib/logger", () => ({ logger: { error: jest.fn(), info: jest.fn(), warn: jest.fn() } }));

import {
  ALL_PERMISSIONS, API_KEY_PERMISSIONS, BUILTIN_PERMISSIONS, NO_PERMISSIONS, PERMISSION_KEYS,
  attestPermissionFor, builtinPermissions, canAttestAny, permissionsFromRow,
} from "@/lib/permissions";
import { checkGrantable, permissionsFor, permissionsForMemberEmail, requirePermission } from "@/lib/permissionResolver";

const JUNIOR = { id: "cr-junior", org_id: "org-1", name: "Junior reviewer", can_attest_high: true, can_attest_medium: true, can_trigger_scans: true };
const OTHER_ORG_ROLE = { id: "cr-foreign", org_id: "org-2", name: "Foreign", ...Object.fromEntries(PERMISSION_KEYS.map(k => [k, true])) };

beforeEach(() => {
  failMemberRead = null;
  delete process.env.NEXT_PUBLIC_SKIP_AUTH;
  db = fakeSupabase({
    org_members: [
      { org_id: "org-1", user_id: "u-admin", email: "admin@a.test", role: "admin", custom_role_id: null },
      { org_id: "org-1", user_id: "u-dev", email: "dev@a.test", role: "developer", custom_role_id: null },
      { org_id: "org-1", user_id: "u-junior", email: "junior@a.test", role: "developer", custom_role_id: "cr-junior" },
      { org_id: "org-1", user_id: "u-sneaky", email: "sneaky@a.test", role: "developer", custom_role_id: "cr-foreign" },
      { org_id: "org-1", user_id: null, email: "pending@a.test", role: "security_reviewer" },
    ],
    custom_roles: [JUNIOR, OTHER_ORG_ROLE],
  });
});

describe("permission model", () => {
  it("built-in roles: admin everything; reviewer attests and triages but doesn't manage; developer can't attest or triage", () => {
    expect(BUILTIN_PERMISSIONS.admin).toEqual(ALL_PERMISSIONS);
    const rev = BUILTIN_PERMISSIONS.security_reviewer;
    expect(rev.can_attest_critical && rev.can_resolve_violations && rev.can_export_data).toBe(true);
    expect(rev.can_manage_team || rev.can_manage_integrations || rev.can_manage_billing || rev.can_manage_policies).toBe(false);
    const dev = BUILTIN_PERMISSIONS.developer;
    expect(canAttestAny(dev) || dev.can_resolve_violations || dev.can_export_data || dev.can_manage_incidents).toBe(false);
    expect(dev.can_trigger_scans && dev.can_view_secrets).toBe(true);
  });

  it("unknown roles get developer's set; platform_admin everything", () => {
    expect(builtinPermissions("owner")).toEqual(BUILTIN_PERMISSIONS.developer);
    expect(builtinPermissions(undefined)).toEqual(BUILTIN_PERMISSIONS.developer);
    expect(builtinPermissions("platform_admin")).toEqual(ALL_PERMISSIONS);
  });

  it("a custom_roles row becomes a complete set: missing or non-boolean flags are false", () => {
    const p = permissionsFromRow({ can_attest_high: true, can_view_secrets: "yes" as unknown as boolean });
    expect(p.can_attest_high).toBe(true);
    expect(p.can_view_secrets).toBe(false);
    expect(Object.keys(p).sort()).toEqual([...PERMISSION_KEYS].sort());
  });

  it("the attest flag follows the file's risk", () => {
    expect(attestPermissionFor("CRITICAL")).toBe("can_attest_critical");
    expect(attestPermissionFor("high")).toBe("can_attest_high");
    expect(attestPermissionFor("MEDIUM")).toBe("can_attest_medium");
    expect(attestPermissionFor(undefined)).toBe("can_attest_medium");
  });

  it("API keys automate but never sign off or manage", () => {
    expect(canAttestAny(API_KEY_PERMISSIONS)).toBe(false);
    expect(API_KEY_PERMISSIONS.can_manage_team || API_KEY_PERMISSIONS.can_manage_integrations).toBe(false);
    expect(API_KEY_PERMISSIONS.can_trigger_scans).toBe(true);
  });
});

describe("resolving a caller's permissions", () => {
  it("a member without a custom role gets their built-in role", async () => {
    expect(await permissionsFor({ org_id: "org-1", user_id: "u-dev", role: "developer" })).toEqual(BUILTIN_PERMISSIONS.developer);
    expect(await permissionsFor({ org_id: "org-1", user_id: "u-admin", role: "admin" })).toEqual(ALL_PERMISSIONS);
  });

  it("an assigned custom role REPLACES the built-in set", async () => {
    const p = await permissionsFor({ org_id: "org-1", user_id: "u-junior", role: "developer" });
    expect(p).toEqual(permissionsFromRow(JUNIOR));
    expect(p.can_attest_high).toBe(true);        // granted beyond developer
    expect(p.can_view_secrets).toBe(false);      // taken away from developer
    expect(await requirePermission({ org_id: "org-1", user_id: "u-junior", role: "developer" }, "can_attest_critical")).toBe("insufficient_permissions");
  });

  it("a custom role id that belongs to another org grants nothing", async () => {
    expect(await permissionsFor({ org_id: "org-1", user_id: "u-sneaky", role: "developer" })).toEqual(NO_PERMISSIONS);
  });

  it("API keys, demo mode, missing org", async () => {
    expect(await permissionsFor({ org_id: "org-1" })).toEqual(API_KEY_PERMISSIONS);
    expect(await permissionsFor({ org_id: "" })).toEqual(NO_PERMISSIONS);
    process.env.NEXT_PUBLIC_SKIP_AUTH = "true";
    expect(await permissionsFor({ org_id: "demo" })).toEqual(ALL_PERMISSIONS);
  });

  it("a database without the custom_role_id column falls back to built-in roles; any other read error fails closed", async () => {
    failMemberRead = { code: "42703", message: "column org_members.custom_role_id does not exist" };
    expect(await permissionsFor({ org_id: "org-1", user_id: "u-dev", role: "security_reviewer" })).toEqual(BUILTIN_PERMISSIONS.security_reviewer);
    failMemberRead = { code: "57014", message: "canceling statement due to statement timeout" };
    expect(await permissionsFor({ org_id: "org-1", user_id: "u-dev", role: "security_reviewer" })).toEqual(NO_PERMISSIONS);
  });

  it("is resolved once per request (auth object)", async () => {
    const auth = { org_id: "org-1", user_id: "u-junior", role: "developer" };
    const spy = jest.spyOn(db.client, "from");
    await permissionsFor(auth); await requirePermission(auth, "can_attest_high"); await permissionsFor(auth);
    expect(spy.mock.calls.filter(c => c[0] === "org_members")).toHaveLength(1);
  });

  it("Slack: looks the member up by email in this org only", async () => {
    expect(await permissionsForMemberEmail("org-1", "junior@a.test")).toEqual({ user_id: "u-junior", permissions: permissionsFromRow(JUNIOR) });
    expect(await permissionsForMemberEmail("org-1", "pending@a.test")).toEqual({ user_id: null, permissions: BUILTIN_PERMISSIONS.security_reviewer });
    expect(await permissionsForMemberEmail("org-2", "junior@a.test")).toBeNull();
  });
});

describe("checkGrantable: nobody hands out more than they hold", () => {
  const admin  = { org_id: "org-1", user_id: "u-admin", role: "admin" };
  const junior = { org_id: "org-1", user_id: "u-junior", role: "developer" };

  it("admins may grant anything", async () => {
    expect(await checkGrantable(admin, { role: "admin" })).toBeNull();
    expect(await checkGrantable(admin, { permissions: ALL_PERMISSIONS })).toBeNull();
  });

  it("only an admin may make someone admin", async () => {
    expect(await checkGrantable(junior, { role: "admin" })).toBe("cannot_grant_admin");
  });

  it("a non-admin may grant only roles within their own permissions", async () => {
    expect(await checkGrantable(junior, { role: "security_reviewer" })).toBe("cannot_grant_more_than_own_permissions");
    expect(await checkGrantable(junior, { permissions: permissionsFromRow({ can_attest_high: true }) })).toBeNull();
    expect(await checkGrantable(junior, { permissions: permissionsFromRow({ can_attest_critical: true }) })).toBe("cannot_grant_more_than_own_permissions");
  });
});
